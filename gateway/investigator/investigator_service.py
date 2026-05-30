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
    yield


app = FastAPI(title="Investigation Agent", lifespan=lifespan)


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
        return {
            "incident_id": incident_id,
            "severity": severity,
            "tenant": tenant,
            "trigger": trigger,
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
