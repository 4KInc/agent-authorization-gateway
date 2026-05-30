"""FastAPI service for the Policy Auditor.

Endpoints:
  POST /audit-tick    Invoked by Cloud Scheduler every 60s
  GET  /audit-keys    Publishes the Auditor's Ed25519 public key
  GET  /audit-reports  Returns recent audit reports
  GET  /health        Liveness probe
"""

from __future__ import annotations

import json
import logging
import os
from contextlib import asynccontextmanager
from typing import Optional

from fastapi import FastAPI, Query, HTTPException

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

_state: dict = {}


def _load_config() -> dict:
    local = os.environ.get("AUDITOR_LOCAL_CONFIG", "")
    if local:
        return json.loads(local)
    from google.cloud import secretmanager
    project_id = os.environ.get("GCP_PROJECT_ID", os.environ.get("GOOGLE_CLOUD_PROJECT", ""))
    client = secretmanager.SecretManagerServiceClient()
    name = f"projects/{project_id}/secrets/gateway-auditor-config/versions/latest"
    resp = client.access_secret_version(request={"name": name})
    return json.loads(resp.payload.data.decode())


@asynccontextmanager
async def lifespan(app: FastAPI):
    cfg = _load_config()
    project_id = os.environ.get("GCP_PROJECT_ID", os.environ.get("GOOGLE_CLOUD_PROJECT", ""))

    from google.cloud import firestore
    from .compliance_search import ComplianceSearcher
    from .auditor_agent import build_auditor_agent
    from .audit_signing_key import load as load_auditor_key

    _state["db"] = firestore.Client(project=project_id)
    _state["searcher"] = ComplianceSearcher(
        project_id=project_id,
        data_store_id=cfg["data_store_id"],
        location=cfg.get("data_store_location", "global"),
        engine_id=cfg.get("engine_id"),
    )
    _state["agent"] = build_auditor_agent(
        _state["searcher"],
        model=cfg.get("model", "gemini-2.5-pro"),
    )
    _state["max_per_tick"] = int(os.environ.get("MAX_PER_TICK", "10"))

    # Pub/Sub publisher for CONFLICT notifications to the Investigator
    _state["pubsub_publisher"] = None
    _state["conflict_topic"] = None
    if project_id:
        try:
            from google.cloud import pubsub_v1
            _state["pubsub_publisher"] = pubsub_v1.PublisherClient()
            _state["conflict_topic"] = f"projects/{project_id}/topics/auditor-conflicts"
            logger.info("Pub/Sub publisher ready: topic=%s", _state["conflict_topic"])
        except Exception:
            logger.warning("Pub/Sub publisher init failed; CONFLICT notifications disabled")

    load_auditor_key()

    # Initialize A2A executor with the shared Firestore client
    if _a2a_executor is not None:
        _a2a_executor._db = _state["db"]
        logger.info("A2A executor connected to Firestore")

    logger.info("Auditor service ready. data_store=%s model=%s",
                cfg["data_store_id"], cfg.get("model"))
    yield


# Create A2A executor at module level so routes can reference it;
# its _db is set later in the lifespan when Firestore is ready.
_a2a_executor = None
try:
    from .a2a_server import create_agent_card
    from .a2a_executor import AuditorA2AExecutor
    _a2a_executor = AuditorA2AExecutor()
except ImportError:
    pass

app = FastAPI(title="Policy Auditor Agent", lifespan=lifespan)

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
    logger.info("A2A routes mounted on Auditor REST service")


@app.get("/health")
def health():
    return {"ok": True, "service": "policy-auditor"}


@app.get("/audit-keys")
def audit_keys():
    from .audit_signing_key import load as load_auditor_key
    key = load_auditor_key()
    return {
        "keys": [{
            "kid": key.kid,
            "kty": "OKP",
            "crv": "Ed25519",
            "x": key.public_key_b64url(),
        }]
    }


@app.post("/audit-tick")
def audit_tick():
    from .receipt_reader import ReceiptReader, list_tenants
    from .auditor_agent import audit_receipt
    from .report_writer import write_audit_report

    db = _state["db"]
    agent = _state["agent"]
    max_per_tick = _state["max_per_tick"]

    tenants = list_tenants(db)
    reader = ReceiptReader(db)

    summary = {
        "audited": 0, "skipped": 0, "errors": 0,
        "by_verdict": {"ALIGNED": 0, "CONFLICT": 0,
                       "INSUFFICIENT_EVIDENCE": 0, "ERROR": 0},
    }

    for tenant in tenants:
        try:
            receipts = reader.fetch_unaudited(tenant, max_per_tick)
        except Exception as e:
            logger.exception("Failed to fetch receipts for tenant %s", tenant)
            summary["errors"] += 1
            continue

        logger.info("Tenant %s: %d unaudited receipts", tenant, len(receipts))

        for receipt in receipts:
            seq = receipt.get("seq", "?")
            decision = receipt.get("decision", "?")
            try:
                verdict, rationale, citations = audit_receipt(agent, receipt)
                envelope = write_audit_report(
                    db=db, tenant=tenant, receipt=receipt,
                    verdict=verdict, rationale=rationale, citations=citations,
                )
                reader.set_checkpoint(tenant, int(seq))
                summary["audited"] += 1
                summary["by_verdict"][verdict] = summary["by_verdict"].get(verdict, 0) + 1
                logger.info("Audited seq=%s decision=%s verdict=%s", seq, decision, verdict)

                # Notify Investigator on CONFLICT verdicts
                if verdict == "CONFLICT" and _state.get("pubsub_publisher"):
                    try:
                        audit_id = envelope["body"]["audit_id"]
                        msg = json.dumps({"tenant": tenant, "audit_id": audit_id}).encode()
                        _state["pubsub_publisher"].publish(_state["conflict_topic"], msg)
                        logger.info("Published CONFLICT to Pub/Sub: audit_id=%s", audit_id)
                    except Exception:
                        logger.exception("Failed to publish CONFLICT to Pub/Sub")
            except Exception:
                logger.exception("Audit failed for tenant=%s seq=%s", tenant, seq)
                summary["errors"] += 1

    logger.info("audit-tick summary: %s", summary)
    return summary


@app.post("/audit-receipt")
def audit_single_receipt(body: dict = {}):
    """On-demand audit of a single receipt by seq number."""
    from .receipt_reader import ReceiptReader
    from .auditor_agent import audit_receipt
    from .report_writer import write_audit_report

    tenant = body.get("tenant", "default")
    receipt_seq = body.get("receipt_seq")
    if receipt_seq is None:
        raise HTTPException(400, "receipt_seq is required")

    db = _state["db"]
    agent = _state["agent"]
    reader = ReceiptReader(db)

    # Find the specific receipt
    all_receipts = reader.fetch_unaudited(tenant, max_batch=9999)
    # Also check already-audited receipts
    collection = db.collection("tenants").document(tenant).collection("receipts")
    target = None
    for doc in collection.stream():
        data = doc.to_dict()
        b = data.get("body", {})
        try:
            if int(b.get("seq", -1)) == int(receipt_seq):
                flat = {**b}
                meta = data.get("_meta", {})
                flat.update(meta)
                flat["receipt_hash"] = data.get("receipt_hash", "")
                target = flat
                break
        except (ValueError, TypeError):
            continue

    if target is None:
        raise HTTPException(404, f"Receipt seq={receipt_seq} not found for tenant={tenant}")

    try:
        verdict, rationale, citations = audit_receipt(agent, target)
        envelope = write_audit_report(
            db=db, tenant=tenant, receipt=target,
            verdict=verdict, rationale=rationale, citations=citations,
        )
        return envelope
    except Exception as e:
        logger.exception("On-demand audit failed for seq=%s", receipt_seq)
        raise HTTPException(500, f"Audit failed: {e}")


@app.get("/audit-reports")
def audit_reports(
    tenant: str = Query(...),
    since_seq: int = Query(0),
    limit: int = Query(50, le=200),
):
    db = _state["db"]
    reports = []
    collection = db.collection("tenants").document(tenant).collection("audit_reports")
    for doc in collection.stream():
        data = doc.to_dict()
        body = data.get("body", {})
        if body.get("receipt_seq", 0) > since_seq:
            reports.append(data)

    reports.sort(key=lambda r: r.get("body", {}).get("receipt_seq", 0))
    return {"reports": reports[:limit]}
