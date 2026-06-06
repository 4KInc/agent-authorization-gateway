"""A2A Server for the Policy Recommendation Agent."""
from __future__ import annotations

import logging
import os

from fastapi import FastAPI

logger = logging.getLogger(__name__)


def create_agent_card():
    """Build the Policy Recommender's A2A agent card."""
    from a2a.types import AgentCard, AgentSkill, AgentCapabilities, AgentProvider, AgentInterface

    url = os.environ.get("A2A_BASE_URL", "http://localhost:8080")

    card = AgentCard(
        name="Policy Recommendation Agent",
        description=(
            "LLM-powered policy advisor that analyses audit reports and proposes "
            "concrete policy changes to reduce CONFLICT verdicts. Produces signed "
            "policy proposal envelopes stored in Firestore."
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
                id="query_proposals",
                name="Query Policy Proposals",
                description=(
                    "List recent policy proposals for a tenant from Firestore."
                ),
                tags=["policy", "proposals", "firestore"],
                examples=[
                    '{"skill":"query_proposals","input":{"tenant":"hackathon-demo","limit":20}}'
                ],
            ),
            AgentSkill(
                id="explain_proposal",
                name="Explain Proposal",
                description=(
                    "Return the full proposal envelope — rationale, confidence, "
                    "and proposed rule changes — for a given proposal_id."
                ),
                tags=["policy", "explain", "rationale"],
                examples=[
                    '{"skill":"explain_proposal","input":{"tenant":"hackathon-demo","proposal_id":"prop-abc123"}}'
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
    """Create the A2A-enabled FastAPI application for the Policy Recommender."""
    from contextlib import asynccontextmanager

    from a2a.server.request_handlers import DefaultRequestHandlerV2
    from a2a.server.tasks import InMemoryTaskStore
    from a2a.server.routes import (
        create_agent_card_routes,
        create_jsonrpc_routes,
        create_rest_routes,
    )
    from a2a.server.routes.fastapi_routes import add_a2a_routes_to_fastapi

    from .a2a_executor import RecommenderA2AExecutor

    _state: dict = {}
    executor = RecommenderA2AExecutor()

    @asynccontextmanager
    async def lifespan(a):
        logging.basicConfig(level=logging.INFO)
        project_id = os.environ.get("GCP_PROJECT_ID", os.environ.get("GOOGLE_CLOUD_PROJECT", ""))
        from google.cloud import firestore
        _state["db"] = firestore.Client(project=project_id)
        executor._db = _state["db"]
        logger.info("Policy Recommender A2A server ready")
        yield

    app = FastAPI(title="Policy Recommendation Agent — A2A", lifespan=lifespan)

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
        return {"ok": True, "service": "recommender-a2a"}

    return app


app = create_app()
