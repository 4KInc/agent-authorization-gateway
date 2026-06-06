"""FastAPI service for the Isolator Agent.

Endpoints:
  POST /isolate           Trigger isolation analysis and containment
  GET  /isolation-records List isolation records
  GET  /isolator-keys     Publishes the Isolator's Ed25519 public key
  GET  /health            Liveness probe

The Isolator is the ONLY agent that takes automated enforcement actions.
When triggered by a HIGH/CRITICAL incident, it:
1. Analyzes the incident using Gemini 2.5 Pro
2. Identifies the rogue agent(s)
3. Revokes their registration (removes public key from registry)
4. Produces a signed isolation record documenting the containment
"""

from __future__ import annotations

import json
import logging
import os
from contextlib import asynccontextmanager

import httpx
from fastapi import FastAPI, Query, Request

try:
    import google.cloud.logging as _cloud_logging
    _cloud_logging.Client().setup_logging(log_level=logging.INFO)
except Exception:
    logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

_state: dict = {}

GATEWAY_URL = os.environ.get("GATEWAY_URL", "https://agent-auth-gateway-1031148889398.us-central1.run.app")


def _load_config() -> dict:
    local = os.environ.get("ISOLATOR_LOCAL_CONFIG", "")
    if local:
        return json.loads(local)
    from google.cloud import secretmanager
    project_id = os.environ.get("GCP_PROJECT_ID", os.environ.get("GOOGLE_CLOUD_PROJECT", ""))
    client = secretmanager.SecretManagerServiceClient()
    name = f"projects/{project_id}/secrets/gateway-isolator-config/versions/latest"
    resp = client.access_secret_version(request={"name": name})
    return json.loads(resp.payload.data.decode())


@asynccontextmanager
async def lifespan(app: FastAPI):
    cfg = _load_config()
    project_id = os.environ.get("GCP_PROJECT_ID", os.environ.get("GOOGLE_CLOUD_PROJECT", ""))

    from google.cloud import firestore
    from .isolator_signing_key import load as load_isolator_key

    _state["db"] = firestore.Client(project=project_id)
    _state["model"] = cfg.get("model", "gemini-2.5-pro")
    _state["default_tenant"] = cfg.get("default_tenant", "default")

    load_isolator_key()
    logger.info("Isolator service ready. model=%s", _state["model"])

    # Initialize A2A executor with Firestore client
    try:
        _a2a_executor._db = _state["db"]
    except Exception:
        pass

    yield


app = FastAPI(title="Isolator Agent", lifespan=lifespan)

# Mount A2A routes (agent card at /.well-known/agent.json)
try:
    from a2a.server.request_handlers import DefaultRequestHandlerV2
    from a2a.server.tasks import InMemoryTaskStore
    from a2a.server.routes import create_agent_card_routes, create_jsonrpc_routes, create_rest_routes
    from a2a.server.routes.fastapi_routes import add_a2a_routes_to_fastapi
    from .a2a_server import create_agent_card
    from .a2a_executor import IsolatorA2AExecutor

    _a2a_executor = IsolatorA2AExecutor()
    _a2a_card = create_agent_card()
    _a2a_handler = DefaultRequestHandlerV2(
        agent_executor=_a2a_executor,
        task_store=InMemoryTaskStore(),
        agent_card=_a2a_card,
    )
    add_a2a_routes_to_fastapi(
        app,
        agent_card_routes=create_agent_card_routes(_a2a_card),
        jsonrpc_routes=create_jsonrpc_routes(_a2a_handler, rpc_url="/a2a"),
        rest_routes=create_rest_routes(_a2a_handler),
    )
    logger.info("A2A routes mounted on Isolator REST service")
except Exception as e:
    logger.warning("A2A routes not mounted (non-fatal): %s", e)


@app.get("/health")
def health():
    return {"ok": True, "service": "agent-isolator"}


@app.get("/isolator-keys")
def isolator_keys():
    from .isolator_signing_key import load as load_isolator_key
    key = load_isolator_key()
    return {
        "keys": [{
            "kid": key.kid,
            "kty": "OKP",
            "crv": "Ed25519",
            "x": key.public_key_b64url(),
        }]
    }


@app.post("/isolate")
async def isolate(request: Request):
    """Analyze an incident and execute containment actions.

    Accepts either a Pub/Sub push message or a direct JSON body with:
    - tenant: tenant identifier
    - incident: the full incident report body
    - OR trigger.incident_id: ID of an incident to fetch
    """
    from .isolator_agent import build_isolator_agent, run_isolation_analysis
    from .isolation_writer import write_isolation_record

    body = await request.json()
    tenant = body.get("tenant", _state["default_tenant"])
    incident = body.get("incident")

    # If no incident body provided, try to fetch by ID
    if not incident and body.get("trigger", {}).get("incident_id"):
        incident_id = body["trigger"]["incident_id"]
        db = _state["db"]
        doc = db.collection("tenants").document(tenant) \
            .collection("incident_reports").document(incident_id).get()
        if doc.exists:
            incident = doc.to_dict()
        else:
            return {"error": f"Incident {incident_id} not found"}

    if not incident:
        return {"error": "No incident provided. Include 'incident' body or 'trigger.incident_id'."}

    # Check severity threshold — only act on HIGH or CRITICAL
    incident_body = incident.get("body", incident)
    severity = incident_body.get("severity", "INFO")
    if severity not in ("HIGH", "CRITICAL"):
        return {
            "action": "SKIPPED",
            "reason": f"Severity {severity} below isolation threshold (HIGH/CRITICAL required)",
            "incident_severity": severity,
        }

    logger.info("Isolation triggered: severity=%s tenant=%s", severity, tenant)

    # Run Gemini analysis
    model = _state["model"]
    agent = build_isolator_agent(model=model)
    analysis = run_isolation_analysis(agent, incident_body)

    if analysis is None:
        return {"error": "Isolator agent produced no output"}

    # Execute containment actions
    db = _state["db"]
    actions_taken = []

    for action in analysis.get("containment_actions", []):
        agent_id = action.get("agent_id")
        action_type = action.get("action", "MONITOR_ONLY")

        if action_type == "REVOKE_REGISTRATION" and agent_id:
            # Revoke the agent's registration via the Gateway API
            try:
                headers = {}
                try:
                    from google.oauth2 import id_token as google_id_token
                    from google.auth.transport.requests import GRequest
                    from urllib.parse import urlparse
                    parsed = urlparse(GATEWAY_URL)
                    audience = f"{parsed.scheme}://{parsed.netloc}"
                    token = google_id_token.fetch_id_token(GRequest(), audience)
                    headers["Authorization"] = f"Bearer {token}"
                except Exception:
                    pass

                async with httpx.AsyncClient(timeout=10) as client:
                    resp = await client.delete(
                        f"{GATEWAY_URL}/agents/{agent_id}",
                        headers=headers,
                    )
                    if resp.status_code in (200, 204):
                        actions_taken.append({
                            "agent_id": agent_id,
                            "action": "REVOKE_REGISTRATION",
                            "status": "executed",
                            "rationale": action.get("rationale", ""),
                        })
                        logger.info("ISOLATED: revoked agent %s", agent_id)
                    elif resp.status_code == 404:
                        actions_taken.append({
                            "agent_id": agent_id,
                            "action": "REVOKE_REGISTRATION",
                            "status": "agent_not_found",
                            "rationale": action.get("rationale", ""),
                        })
                    else:
                        actions_taken.append({
                            "agent_id": agent_id,
                            "action": "REVOKE_REGISTRATION",
                            "status": f"failed_{resp.status_code}",
                            "rationale": action.get("rationale", ""),
                        })
            except Exception as e:
                actions_taken.append({
                    "agent_id": agent_id,
                    "action": "REVOKE_REGISTRATION",
                    "status": f"error: {e}",
                    "rationale": action.get("rationale", ""),
                })

        elif action_type == "RATE_LIMIT_ZERO":
            actions_taken.append({
                "agent_id": agent_id,
                "action": "RATE_LIMIT_ZERO",
                "status": "recommended",
                "rationale": action.get("rationale", ""),
                "note": "Rate limit changes require manual policy update",
            })

        elif action_type == "MONITOR_ONLY":
            actions_taken.append({
                "agent_id": agent_id,
                "action": "MONITOR_ONLY",
                "status": "flagged",
                "rationale": action.get("rationale", ""),
            })

    # Write signed isolation record
    target_agent = analysis.get("agent_id", "unknown")
    envelope = write_isolation_record(
        db=db,
        tenant=tenant,
        agent_id=target_agent,
        trigger={
            "type": "INCIDENT_REPORT",
            "incident_id": incident_body.get("incident_id", "unknown"),
            "severity": severity,
        },
        actions_taken=actions_taken,
        reason=analysis.get("summary", "Rogue agent detected"),
        severity=severity,
        evidence_references={
            "incident_id": incident_body.get("incident_id"),
            "audit_reports": incident_body.get("evidence_references", {}).get("audit_reports", []),
            "receipts": incident_body.get("evidence_references", {}).get("receipts", []),
        },
    )

    isolation_id = envelope["body"]["isolation_id"]
    logger.info("Isolation record created: id=%s agent=%s actions=%d",
                isolation_id, target_agent, len(actions_taken))

    return {
        "isolation_id": isolation_id,
        "agent_id": target_agent,
        "severity": severity,
        "actions_taken": actions_taken,
        "summary": analysis.get("summary", ""),
    }


@app.get("/isolation-records")
def isolation_records(
    tenant: str = Query(...),
    limit: int = Query(20, le=100),
):
    db = _state["db"]
    collection = db.collection("tenants").document(tenant).collection("isolation_records")
    records = []
    for doc in collection.stream():
        records.append(doc.to_dict())

    records.sort(
        key=lambda r: r.get("body", {}).get("isolated_at", ""),
        reverse=True,
    )
    return {"isolation_records": records[:limit]}
