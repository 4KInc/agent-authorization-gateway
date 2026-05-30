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
    yield


app = FastAPI(title="Discovery Coordinator", lifespan=lifespan)


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
    db = _state["db"]
    entries = list_entries(db)
    return {"agents": entries, "count": len(entries)}


@app.post("/route-question")
def route_question(req: RouteQuestionRequest):
    from .routing_agent import build_routing_agent, run_routing

    db = _state["db"]
    model = _state["model"]

    agent = build_routing_agent(db, model=model)
    result = run_routing(agent, req.question)

    return result
