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

    # Initialize A2A executor with the shared Firestore client
    if _a2a_executor is not None:
        _a2a_executor._db = _state["db"]
        logger.info("A2A executor connected to Firestore")

    logger.info("Recommender service ready. model=%s", _state["model"])
    yield


# Create A2A executor at module level so routes can reference it;
# its _db is set later in the lifespan when Firestore is ready.
_a2a_executor = None
try:
    from .a2a_server import create_agent_card
    from .a2a_executor import RecommenderA2AExecutor
    _a2a_executor = RecommenderA2AExecutor()
except ImportError:
    pass

app = FastAPI(title="Policy Recommendation Agent", lifespan=lifespan)

if _a2a_executor is not None:
    from a2a.server.request_handlers import DefaultRequestHandlerV2
    from a2a.server.tasks import InMemoryTaskStore
    from a2a.server.routes import create_agent_card_routes, create_jsonrpc_routes, create_rest_routes
    from a2a.server.routes.fastapi_routes import add_a2a_routes_to_fastapi

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
    logger.info("A2A routes mounted on Recommender REST service")


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


@app.post("/analyze-patterns")
def analyze_patterns(body: dict = {}):
    """On-demand pattern analysis — same as recommend-tick but for a specific tenant."""
    from .recommender_agent import build_recommender_agent, run_recommender

    tenant = body.get("tenant", _state["default_tenant"])
    window_hours = body.get("window_hours", 24)

    db = _state["db"]
    model = _state["model"]

    try:
        agent = build_recommender_agent(db, tenant, model=model)
        raw_proposals = run_recommender(agent)
        return {
            "tenant": tenant,
            "window_hours": window_hours,
            "proposals_found": len(raw_proposals),
            "proposals": raw_proposals,
        }
    except Exception as e:
        logger.exception("On-demand analysis failed for tenant %s", tenant)
        return {"error": str(e), "tenant": tenant}


@app.get("/proposals")
def proposals(
    tenant: str = Query(...),
    limit: int = Query(20, le=100),
):
    from .audit_reader import fetch_recent_proposals
    db = _state["db"]
    recent = fetch_recent_proposals(db, tenant, days_back=30)
    return {"proposals": recent[:limit]}
