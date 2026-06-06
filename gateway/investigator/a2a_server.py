"""A2A Server for the Investigation Agent."""
from __future__ import annotations

import logging
import os

from fastapi import FastAPI

logger = logging.getLogger(__name__)


def create_agent_card():
    """Build the Investigation Agent's A2A agent card."""
    from a2a.types import AgentCard, AgentSkill, AgentCapabilities, AgentProvider, AgentInterface

    url = os.environ.get("A2A_BASE_URL", "http://localhost:8080")

    card = AgentCard(
        name="Investigation Agent",
        description=(
            "LLM-powered incident investigator triggered by CONFLICT audit verdicts. "
            "Analyses receipt chains, identifies root causes, and produces signed "
            "incident report envelopes with severity classification."
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
                id="query_incidents",
                name="Query Incident Reports",
                description=(
                    "List incident reports for a tenant, optionally filtering by "
                    "minimum severity level."
                ),
                tags=["incidents", "investigation", "firestore"],
                examples=[
                    '{"skill":"query_incidents","input":{"tenant":"hackathon-demo","severity":"HIGH","limit":20}}'
                ],
            ),
            AgentSkill(
                id="explain_incident",
                name="Explain Incident",
                description=(
                    "Return the full incident report envelope — narrative, severity, "
                    "trigger, and evidence — for a given incident_id."
                ),
                tags=["incidents", "explain", "narrative"],
                examples=[
                    '{"skill":"explain_incident","input":{"tenant":"hackathon-demo","incident_id":"inc-abc123"}}'
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
    """Create the A2A-enabled FastAPI application for the Investigation Agent."""
    from contextlib import asynccontextmanager

    from a2a.server.request_handlers import DefaultRequestHandlerV2
    from a2a.server.tasks import InMemoryTaskStore
    from a2a.server.routes import (
        create_agent_card_routes,
        create_jsonrpc_routes,
        create_rest_routes,
    )
    from a2a.server.routes.fastapi_routes import add_a2a_routes_to_fastapi

    from .a2a_executor import InvestigatorA2AExecutor

    _state: dict = {}
    executor = InvestigatorA2AExecutor()

    @asynccontextmanager
    async def lifespan(a):
        logging.basicConfig(level=logging.INFO)
        project_id = os.environ.get("GCP_PROJECT_ID", os.environ.get("GOOGLE_CLOUD_PROJECT", ""))
        from google.cloud import firestore
        _state["db"] = firestore.Client(project=project_id)
        executor._db = _state["db"]
        logger.info("Investigation Agent A2A server ready")
        yield

    app = FastAPI(title="Investigation Agent — A2A", lifespan=lifespan)

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
        return {"ok": True, "service": "investigator-a2a"}

    return app


app = create_app()
