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
    )
    _state["agent"] = build_auditor_agent(
        _state["searcher"],
        model=cfg.get("model", "gemini-2.5-pro"),
    )
    _state["max_per_tick"] = int(os.environ.get("MAX_PER_TICK", "10"))

    load_auditor_key()
    logger.info("Auditor service ready. data_store=%s model=%s",
                cfg["data_store_id"], cfg.get("model"))
    yield


app = FastAPI(title="Policy Auditor Agent", lifespan=lifespan)


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
                write_audit_report(
                    db=db, tenant=tenant, receipt=receipt,
                    verdict=verdict, rationale=rationale, citations=citations,
                )
                reader.set_checkpoint(tenant, int(seq))
                summary["audited"] += 1
                summary["by_verdict"][verdict] = summary["by_verdict"].get(verdict, 0) + 1
                logger.info("Audited seq=%s decision=%s verdict=%s", seq, decision, verdict)
            except Exception:
                logger.exception("Audit failed for tenant=%s seq=%s", tenant, seq)
                summary["errors"] += 1

    logger.info("audit-tick summary: %s", summary)
    return summary


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
