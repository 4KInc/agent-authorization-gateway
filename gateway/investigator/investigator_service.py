"""FastAPI service for the Investigation Agent.

Endpoints:
  POST /investigate         Pub/Sub push or manual trigger
  GET  /incidents           Returns recent incident reports
  GET  /investigator-keys   Publishes the Investigator's Ed25519 public key
  GET  /health              Liveness probe
"""

from __future__ import annotations

import base64
import json
import logging
import os
from contextlib import asynccontextmanager

from fastapi import FastAPI, Query, Request

try:
    import google.cloud.logging as _cloud_logging
    _cloud_logging.Client().setup_logging(log_level=logging.INFO)
except Exception:
    logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

_state: dict = {}


def _load_config() -> dict:
    local = os.environ.get("INVESTIGATOR_LOCAL_CONFIG", "")
    if local:
        return json.loads(local)
    from google.cloud import secretmanager
    project_id = os.environ.get("GCP_PROJECT_ID", os.environ.get("GOOGLE_CLOUD_PROJECT", ""))
    client = secretmanager.SecretManagerServiceClient()
    name = f"projects/{project_id}/secrets/gateway-investigator-config/versions/latest"
    resp = client.access_secret_version(request={"name": name})
    return json.loads(resp.payload.data.decode())


@asynccontextmanager
async def lifespan(app: FastAPI):
    cfg = _load_config()
    project_id = os.environ.get("GCP_PROJECT_ID", os.environ.get("GOOGLE_CLOUD_PROJECT", ""))

    from google.cloud import firestore
    from .investigator_signing_key import load as load_investigator_key

    _state["db"] = firestore.Client(project=project_id)
    _state["model"] = cfg.get("model", "gemini-2.5-pro")
    _state["default_tenant"] = cfg.get("default_tenant", "default")

    load_investigator_key()
    logger.info("Investigator service ready. model=%s", _state["model"])

    try:
        _a2a_executor._db = _state["db"]
    except Exception:
        pass

    yield


app = FastAPI(title="Investigation Agent", lifespan=lifespan)

# Mount A2A routes
try:
    from a2a.server.request_handlers import DefaultRequestHandlerV2
    from a2a.server.tasks import InMemoryTaskStore
    from a2a.server.routes import create_agent_card_routes, create_jsonrpc_routes, create_rest_routes
    from a2a.server.routes.fastapi_routes import add_a2a_routes_to_fastapi
    from .a2a_server import create_agent_card
    from .a2a_executor import InvestigatorA2AExecutor

    _a2a_executor = InvestigatorA2AExecutor()
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
    logger.info("A2A routes mounted on Investigator REST service")
except Exception as e:
    logger.warning("A2A routes not mounted (non-fatal): %s", e)


@app.get("/health")
def health():
    return {"ok": True, "service": "incident-investigator"}


@app.get("/investigator-keys")
def investigator_keys():
    from .investigator_signing_key import load as load_investigator_key
    key = load_investigator_key()
    return {
        "keys": [{
            "kid": key.kid,
            "kty": "OKP",
            "crv": "Ed25519",
            "x": key.public_key_b64url(),
        }]
    }


@app.post("/investigate")
async def investigate(request: Request):
    from .investigator_agent import build_investigator_agent, run_investigation
    from .incident_writer import write_incident_report

    body = await request.json()

    # Handle Pub/Sub push format: {message: {data: base64(...), ...}}
    if "message" in body:
        raw = body["message"].get("data", "")
        try:
            decoded = json.loads(base64.b64decode(raw).decode())
        except Exception:
            decoded = {}
        tenant = decoded.get("tenant", _state["default_tenant"])
        trigger = {
            "type": "AUDIT_CONFLICT",
            "trigger_id": decoded.get("audit_id", "unknown"),
        }
    else:
        tenant = body.get("tenant", _state["default_tenant"])
        trigger = body.get("trigger", {})

    trigger_type = trigger.get("type", "MANUAL")
    trigger_id = trigger.get("trigger_id", "unknown")

    logger.info("Investigation triggered: type=%s id=%s tenant=%s",
                trigger_type, trigger_id, tenant)

    db = _state["db"]
    model = _state["model"]

    try:
        agent = build_investigator_agent(db, tenant, model=model)
        narrative = run_investigation(agent, trigger)

        if narrative is None:
            logger.error("Investigator agent returned no result")
            return {"error": "Agent produced no output", "trigger": trigger}

        envelope = write_incident_report(db, tenant, trigger, narrative)
        incident_id = envelope["body"]["incident_id"]
        severity = envelope["body"]["severity"]

        logger.info("Incident report created: id=%s severity=%s tenant=%s",
                    incident_id, severity, tenant)

        # Notify Isolator on HIGH/CRITICAL incidents
        isolator_result = None
        if severity in ("HIGH", "CRITICAL"):
            import httpx
            isolator_url = os.environ.get("ISOLATOR_URL", "https://agent-auth-isolator-1031148889398.us-central1.run.app")
            try:
                headers = {}
                try:
                    from google.oauth2 import id_token as google_id_token
                    from google.auth.transport.requests import Request
                    from urllib.parse import urlparse
                    parsed = urlparse(isolator_url)
                    audience = f"{parsed.scheme}://{parsed.netloc}"
                    token = google_id_token.fetch_id_token(Request(), audience)
                    headers["Authorization"] = f"Bearer {token}"
                except Exception:
                    pass
                async with httpx.AsyncClient(timeout=120) as client:
                    resp = await client.post(
                        f"{isolator_url}/isolate",
                        json={"tenant": tenant, "incident": envelope},
                        headers=headers,
                    )
                    isolator_result = resp.json() if resp.status_code == 200 else {"error": resp.status_code}
                    logger.info("Isolator notified: %s", isolator_result)
            except Exception as e:
                logger.warning("Isolator notification failed: %s", e)
                isolator_result = {"error": str(e)}

        return {
            "incident_id": incident_id,
            "severity": severity,
            "tenant": tenant,
            "trigger": trigger,
            "isolator_triggered": severity in ("HIGH", "CRITICAL"),
            "isolator_result": isolator_result,
        }

    except Exception:
        logger.exception("Investigation failed for trigger %s", trigger)
        return {"error": "Investigation failed", "trigger": trigger}


@app.get("/incidents")
def incidents(
    tenant: str = Query(...),
    limit: int = Query(20, le=100),
):
    db = _state["db"]
    collection = db.collection("tenants").document(tenant).collection("incident_reports")
    reports = []
    for doc in collection.stream():
        reports.append(doc.to_dict())

    reports.sort(
        key=lambda r: r.get("body", {}).get("created_at", ""),
        reverse=True,
    )
    return {"incidents": reports[:limit]}
