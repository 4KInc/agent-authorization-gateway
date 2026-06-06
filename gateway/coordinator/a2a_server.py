"""A2A Server for the Discovery Coordinator Agent."""
from __future__ import annotations

import logging
import os

from fastapi import FastAPI

logger = logging.getLogger(__name__)


def create_agent_card():
    """Build the Discovery Coordinator's A2A agent card."""
    from a2a.types import AgentCard, AgentSkill, AgentCapabilities, AgentProvider, AgentInterface

    url = os.environ.get("A2A_BASE_URL", "http://localhost:8080")

    card = AgentCard(
        name="Discovery Coordinator Agent",
        description=(
            "AI-powered agent registry and capability router. Maintains a Firestore "
            "directory of known A2A agents, uses Gemini to assess capabilities, and "
            "routes natural-language questions to the best-matched agent."
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
                id="route_capability",
                name="Route Capability",
                description=(
                    "Given a natural-language question, return the best-matched "
                    "agent from the directory along with its endpoint URL."
                ),
                tags=["routing", "discovery", "capability-matching"],
                examples=[
                    '{"skill":"route_capability","input":{"question":"Which agent can verify authorization receipts?"}}'
                ],
            ),
            AgentSkill(
                id="list_known_agents",
                name="List Known Agents",
                description="Return all registered agents from the Firestore directory.",
                tags=["discovery", "directory"],
                examples=[
                    '{"skill":"list_known_agents","input":{}}'
                ],
            ),
            AgentSkill(
                id="register_known_agent",
                name="Register Agent",
                description=(
                    "Register a new A2A agent by fetching its agent card from the "
                    "provided URL and storing it in the directory."
                ),
                tags=["discovery", "registration"],
                examples=[
                    '{"skill":"register_known_agent","input":{"agent_card_url":"https://my-agent.example.com/.well-known/agent.json","introducer":"operator"}}'
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
    """Create the A2A-enabled FastAPI application for the Discovery Coordinator."""
    from contextlib import asynccontextmanager

    from a2a.server.request_handlers import DefaultRequestHandlerV2
    from a2a.server.tasks import InMemoryTaskStore
    from a2a.server.routes import (
        create_agent_card_routes,
        create_jsonrpc_routes,
        create_rest_routes,
    )
    from a2a.server.routes.fastapi_routes import add_a2a_routes_to_fastapi

    from .a2a_executor import CoordinatorA2AExecutor

    _state: dict = {}
    executor = CoordinatorA2AExecutor()

    @asynccontextmanager
    async def lifespan(a):
        logging.basicConfig(level=logging.INFO)
        project_id = os.environ.get("GCP_PROJECT_ID", os.environ.get("GOOGLE_CLOUD_PROJECT", ""))
        from google.cloud import firestore
        _state["db"] = firestore.Client(project=project_id)
        executor._db = _state["db"]
        logger.info("Discovery Coordinator A2A server ready")
        yield

    app = FastAPI(title="Discovery Coordinator Agent — A2A", lifespan=lifespan)

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
        return {"ok": True, "service": "coordinator-a2a"}

    return app


app = create_app()
