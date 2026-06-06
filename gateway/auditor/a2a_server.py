"""A2A Server for the Policy Auditor Agent."""
from __future__ import annotations

import logging
import os

from fastapi import FastAPI

logger = logging.getLogger(__name__)


def create_agent_card():
    """Build the Policy Auditor's A2A agent card."""
    from a2a.types import AgentCard, AgentSkill, AgentCapabilities, AgentProvider, AgentInterface

    url = os.environ.get("A2A_BASE_URL", "http://localhost:8080")

    card = AgentCard(
        name="Policy Auditor Agent",
        description=(
            "RAG-powered compliance auditor that reads authorization receipts "
            "and evaluates each decision against compliance frameworks (SOC2, NIST, ISO 27001). "
            "Produces signed audit reports with ALIGNED / CONFLICT / INSUFFICIENT_EVIDENCE verdicts."
        ),
        supported_interfaces=[
            AgentInterface(url=url, protocol_version="1.0"),
        ],
        version="0.1.0",
        capabilities=AgentCapabilities(streaming=False),
        default_input_modes=["text"],
        default_output_modes=["text"],
        skills=[
            AgentSkill(
                id="query_audits",
                name="Query Audit Reports",
                description=(
                    "List audit reports for a tenant, optionally filtering by "
                    "minimum receipt_seq and/or verdict."
                ),
                tags=["audit", "compliance", "firestore"],
                examples=[
                    '{"skill":"query_audits","input":{"tenant":"hackathon-demo","since_seq":0,"verdict_filter":"CONFLICT","limit":20}}'
                ],
            ),
            AgentSkill(
                id="audit_receipt",
                name="Audit a Single Receipt",
                description=(
                    "Fetch a specific audit report by audit_id from Firestore."
                ),
                tags=["audit", "receipt"],
                examples=[
                    '{"skill":"audit_receipt","input":{"tenant":"hackathon-demo","audit_id":"aud-abc123"}}'
                ],
            ),
            AgentSkill(
                id="explain_verdict",
                name="Explain Verdict",
                description=(
                    "Return the full audit report envelope including rationale "
                    "and citations for a given audit_id."
                ),
                tags=["audit", "explain", "rationale"],
                examples=[
                    '{"skill":"explain_verdict","input":{"tenant":"hackathon-demo","audit_id":"aud-abc123"}}'
                ],
            ),
        ],
        provider=AgentProvider(
            organization="4K Inc (BlockIntel)",
            url="https://github.com/4KInc/agent-authorization-gateway",
        ),
    )
    return card


def create_app() -> FastAPI:
    """Create the A2A-enabled FastAPI application for the Policy Auditor."""
    from contextlib import asynccontextmanager

    from a2a.server.request_handlers import DefaultRequestHandlerV2
    from a2a.server.tasks import InMemoryTaskStore
    from a2a.server.routes import (
        create_agent_card_routes,
        create_jsonrpc_routes,
        create_rest_routes,
    )
    from a2a.server.routes.fastapi_routes import add_a2a_routes_to_fastapi

    from .a2a_executor import AuditorA2AExecutor

    _state: dict = {}
    executor = AuditorA2AExecutor()

    @asynccontextmanager
    async def lifespan(a):
        logging.basicConfig(level=logging.INFO)
        project_id = os.environ.get("GCP_PROJECT_ID", os.environ.get("GOOGLE_CLOUD_PROJECT", ""))
        from google.cloud import firestore
        _state["db"] = firestore.Client(project=project_id)
        executor._db = _state["db"]
        logger.info("Policy Auditor A2A server ready")
        yield

    app = FastAPI(title="Policy Auditor Agent — A2A", lifespan=lifespan)

    agent_card = create_agent_card()
    task_store = InMemoryTaskStore()

    handler = DefaultRequestHandlerV2(
        agent_executor=executor,
        task_store=task_store,
        agent_card=agent_card,
    )

    add_a2a_routes_to_fastapi(
        app,
        agent_card_routes=create_agent_card_routes(agent_card),
        jsonrpc_routes=create_jsonrpc_routes(handler, rpc_url="/"),
        rest_routes=create_rest_routes(handler),
    )

    @app.get("/health")
    def health():
        return {"ok": True, "service": "auditor-a2a"}

    return app


app = create_app()
