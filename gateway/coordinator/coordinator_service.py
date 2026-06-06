"""FastAPI service for the Discovery Coordinator.

Endpoints:
  POST /discover          Register a new A2A agent by its agent card URL
  POST /scan              Scan a list of candidate URLs for A2A agents
  GET  /directory         List all known agents
  POST /route-question    AI-powered capability matching
  GET  /coordinator-keys  Publishes the Coordinator's Ed25519 public key
  GET  /health            Liveness probe
"""

from __future__ import annotations

import json
import logging
import os
from contextlib import asynccontextmanager
from typing import List, Optional

from fastapi import FastAPI, Query
from pydantic import BaseModel

try:
    import google.cloud.logging as _cloud_logging
    _cloud_logging.Client().setup_logging(log_level=logging.INFO)
except Exception:
    logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

_state: dict = {}


def _load_config() -> dict:
    local = os.environ.get("COORDINATOR_LOCAL_CONFIG", "")
    if local:
        return json.loads(local)
    from google.cloud import secretmanager
    project_id = os.environ.get("GCP_PROJECT_ID", os.environ.get("GOOGLE_CLOUD_PROJECT", ""))
    client = secretmanager.SecretManagerServiceClient()
    name = f"projects/{project_id}/secrets/gateway-coordinator-config/versions/latest"
    resp = client.access_secret_version(request={"name": name})
    return json.loads(resp.payload.data.decode())


@asynccontextmanager
async def lifespan(app: FastAPI):
    cfg = _load_config()
    project_id = os.environ.get("GCP_PROJECT_ID", os.environ.get("GOOGLE_CLOUD_PROJECT", ""))

    from google.cloud import firestore
    from .coordinator_signing_key import load as load_coordinator_key

    _state["db"] = firestore.Client(project=project_id)
    _state["model"] = cfg.get("model", "gemini-2.5-pro")
    _state["default_tenant"] = cfg.get("default_tenant", "default")

    load_coordinator_key()
    logger.info("Discovery Coordinator ready. model=%s", _state["model"])

    try:
        _a2a_executor._db = _state["db"]
    except Exception:
        pass

    yield


app = FastAPI(title="Discovery Coordinator", lifespan=lifespan)

# Mount A2A routes
try:
    from a2a.server.request_handlers import DefaultRequestHandlerV2
    from a2a.server.tasks import InMemoryTaskStore
    from a2a.server.routes import create_agent_card_routes, create_jsonrpc_routes, create_rest_routes
    from a2a.server.routes.fastapi_routes import add_a2a_routes_to_fastapi
    from .a2a_server import create_agent_card
    from .a2a_executor import CoordinatorA2AExecutor

    _a2a_executor = CoordinatorA2AExecutor()
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
    logger.info("A2A routes mounted on Coordinator REST service")
except Exception as e:
    logger.warning("A2A routes not mounted (non-fatal): %s", e)


# ── Request models ──────────────────────────────────────────────

class DiscoverRequest(BaseModel):
    agent_card_url: str
    introducer: Optional[str] = None

class ScanRequest(BaseModel):
    urls: List[str]

class RouteQuestionRequest(BaseModel):
    question: str


# ── Endpoints ───────────────────────────────────────────────────

@app.get("/health")
def health():
    return {"ok": True, "service": "discovery-coordinator"}


@app.get("/coordinator-keys")
def coordinator_keys():
    from .coordinator_signing_key import load as load_coordinator_key
    key = load_coordinator_key()
    return {
        "keys": [{
            "kid": key.kid,
            "kty": "OKP",
            "crv": "Ed25519",
            "x": key.public_key_b64url(),
        }]
    }


@app.post("/discover")
def discover(req: DiscoverRequest):
    from .a2a_discovery import discover_agent
    from .routing_agent import assess_capabilities
    from .directory import upsert_entry

    db = _state["db"]
    model = _state["model"]

    entry = discover_agent(
        agent_card_url=req.agent_card_url,
        introducer=req.introducer,
        discovery_method="manual" if not req.introducer else "registration",
    )

    # Use Gemini to assess capabilities if the card was fetched successfully
    if entry.get("agent_card"):
        try:
            entry["ai_assessed_capabilities"] = assess_capabilities(
                entry["agent_card"], model=model
            )
        except Exception as e:
            logger.warning("Capability assessment failed: %s", e)
            entry["ai_assessed_capabilities"] = entry["agent_card"].get("description", "")

    upsert_entry(db, entry)

    return {
        "status": "registered",
        "agent_card_url": entry["agent_card_url"],
        "trust_level": entry["trust_level"],
        "health_status": entry["health_status"],
        "ai_assessed_capabilities": entry["ai_assessed_capabilities"],
    }


@app.post("/scan")
def scan(req: ScanRequest):
    from .a2a_discovery import discover_agent
    from .routing_agent import assess_capabilities
    from .directory import upsert_entry

    db = _state["db"]
    model = _state["model"]
    results = []

    for url in req.urls:
        try:
            entry = discover_agent(
                agent_card_url=url,
                discovery_method="scan",
            )
            if entry.get("agent_card"):
                try:
                    entry["ai_assessed_capabilities"] = assess_capabilities(
                        entry["agent_card"], model=model
                    )
                except Exception:
                    entry["ai_assessed_capabilities"] = entry["agent_card"].get("description", "")
            upsert_entry(db, entry)
            results.append({
                "url": url,
                "status": "registered",
                "trust_level": entry["trust_level"],
                "health_status": entry["health_status"],
            })
        except Exception as e:
            logger.warning("Scan failed for %s: %s", url, e)
            results.append({"url": url, "status": "error", "detail": str(e)})

    return {"scanned": len(req.urls), "results": results}


@app.get("/directory")
def directory():
    from .directory import list_entries
    try:
        db = _state["db"]
        entries = list_entries(db)
        return {"agents": entries, "count": len(entries)}
    except Exception as e:
        logger.exception("Directory query failed")
        return {"agents": [], "count": 0, "error": str(e)}


@app.post("/route-question")
def route_question(req: RouteQuestionRequest):
    from .routing_agent import build_routing_agent, run_routing

    try:
        db = _state["db"]
        model = _state["model"]

        agent = build_routing_agent(db, model=model)
        result = run_routing(agent, req.question)

        return result
    except Exception as e:
        logger.exception("Route question failed")
        return {"matches": [], "error": str(e), "no_match_explanation": f"Routing temporarily unavailable: {e}"}
