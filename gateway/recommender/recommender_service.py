"""FastAPI service for the Policy Recommendation Agent.

Endpoints:
  POST /recommend-tick    Invoked by Cloud Scheduler every hour
  GET  /proposals         Returns recent policy proposals
  GET  /recommender-keys  Publishes the Recommender's Ed25519 public key
  GET  /health            Liveness probe
"""

from __future__ import annotations

import json
import logging
import os
from contextlib import asynccontextmanager

from fastapi import FastAPI, Query

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

_state: dict = {}


def _load_config() -> dict:
    local = os.environ.get("RECOMMENDER_LOCAL_CONFIG", "")
    if local:
        return json.loads(local)
    from google.cloud import secretmanager
    project_id = os.environ.get("GCP_PROJECT_ID", os.environ.get("GOOGLE_CLOUD_PROJECT", ""))
    client = secretmanager.SecretManagerServiceClient()
    name = f"projects/{project_id}/secrets/gateway-recommender-config/versions/latest"
    resp = client.access_secret_version(request={"name": name})
    return json.loads(resp.payload.data.decode())


@asynccontextmanager
async def lifespan(app: FastAPI):
    cfg = _load_config()
    project_id = os.environ.get("GCP_PROJECT_ID", os.environ.get("GOOGLE_CLOUD_PROJECT", ""))

    from google.cloud import firestore
    from .recommender_signing_key import load as load_recommender_key

    _state["db"] = firestore.Client(project=project_id)
    _state["model"] = cfg.get("model", "gemini-2.5-pro")
    _state["default_tenant"] = cfg.get("default_tenant", "default")

    load_recommender_key()
    logger.info("Recommender service ready. model=%s", _state["model"])
    yield


app = FastAPI(title="Policy Recommendation Agent", lifespan=lifespan)


@app.get("/health")
def health():
    return {"ok": True, "service": "policy-recommender"}


@app.get("/recommender-keys")
def recommender_keys():
    from .recommender_signing_key import load as load_recommender_key
    key = load_recommender_key()
    return {
        "keys": [{
            "kid": key.kid,
            "kty": "OKP",
            "crv": "Ed25519",
            "x": key.public_key_b64url(),
        }]
    }


@app.post("/recommend-tick")
def recommend_tick():
    from .recommender_agent import build_recommender_agent, run_recommender
    from .proposal_writer import write_proposal
    from ..auditor.receipt_reader import list_tenants

    db = _state["db"]
    model = _state["model"]

    tenants = list_tenants(db)
    if not tenants:
        tenants = [_state["default_tenant"]]

    summary = {"tenants_processed": 0, "proposals_created": 0, "errors": 0}

    for tenant in tenants:
        try:
            agent = build_recommender_agent(db, tenant, model=model)
            raw_proposals = run_recommender(agent)
            logger.info("Tenant %s: agent returned %d proposals", tenant, len(raw_proposals))

            for raw in raw_proposals:
                try:
                    envelope = write_proposal(db, tenant, raw)
                    summary["proposals_created"] += 1
                    logger.info(
                        "Wrote proposal %s for tenant %s (confidence=%s)",
                        envelope["body"]["proposal_id"], tenant,
                        envelope["body"]["confidence"],
                    )
                except Exception:
                    logger.exception("Failed to write proposal for tenant %s", tenant)
                    summary["errors"] += 1

            summary["tenants_processed"] += 1
        except Exception:
            logger.exception("Recommender failed for tenant %s", tenant)
            summary["errors"] += 1

    logger.info("recommend-tick summary: %s", summary)
    return summary


@app.get("/proposals")
def proposals(
    tenant: str = Query(...),
    limit: int = Query(20, le=100),
):
    from .audit_reader import fetch_recent_proposals
    db = _state["db"]
    recent = fetch_recent_proposals(db, tenant, days_back=30)
    return {"proposals": recent[:limit]}
