"""A2A Server — exposes the Agent Authorization Gateway via A2A protocol.

Uses the official a2a-sdk to create a standards-compliant A2A server with:
- Agent card at /.well-known/agent.json
- JSON-RPC and REST message endpoints
- Task management
"""

from __future__ import annotations

import logging
import os

from fastapi import FastAPI

logger = logging.getLogger(__name__)


def create_agent_card():
    """Build the gateway's A2A agent card."""
    from a2a.types import AgentCard, AgentSkill, AgentCapabilities, AgentProvider, AgentInterface

    url = os.environ.get("A2A_BASE_URL", "http://localhost:8080")

    card = AgentCard(
        name="Agent Authorization Gateway",
        description=(
            "Cryptographic policy enforcement for AI agent actions. "
            "Issues Ed25519-signed, hash-chained authorization receipts. "
            "Every decision is independently verifiable."
        ),
        supported_interfaces=[
            AgentInterface(url=url, protocol_version="1.0"),
        ],
        version="0.4.0",
        capabilities=AgentCapabilities(streaming=False),
        default_input_modes=["text"],
        default_output_modes=["text"],
        skills=[
            AgentSkill(
                id="authorize_action",
                name="Authorize Action",
                description=(
                    "Issue a short-lived Ed25519 token authorizing a specific "
                    "action by a registered agent. Requires a DPoP proof."
                ),
                tags=["authorization", "dpop", "ed25519"],
                examples=[
                    '{"skill":"authorize_action","input":{"agent_id":"worker-01","action":"read","resource":"staging-db","agent_proof":"<jwt>"}}'
                ],
            ),
            AgentSkill(
                id="verify_receipt",
                name="Verify Receipt",
                description=(
                    "Verify the cryptographic integrity of a receipt including "
                    "signature and chain linkage."
                ),
                tags=["verification", "audit"],
                examples=['{"skill":"verify_receipt","input":{"receipt_seq":"1"}}'],
            ),
            AgentSkill(
                id="get_public_key",
                name="Get Public Key",
                description="Return the gateway's Ed25519 public key in JWK format.",
                tags=["keys", "verification"],
                examples=['{"skill":"get_public_key","input":{}}'],
            ),
            AgentSkill(
                id="get_chain_summary",
                name="Get Chain Summary",
                description="Return receipt chain statistics including Merkle root.",
                tags=["audit", "merkle"],
                examples=['{"skill":"get_chain_summary","input":{}}'],
            ),
        ],
        provider=AgentProvider(
            organization="4K Inc (BlockIntel)",
            url="https://github.com/4KInc/agent-authorization-gateway",
        ),
    )
    return card


def create_app() -> FastAPI:
    """Create the A2A-enabled FastAPI application."""
    from contextlib import asynccontextmanager

    from a2a.server.request_handlers import DefaultRequestHandlerV2
    from a2a.server.tasks import InMemoryTaskStore
    from a2a.server.routes import (
        create_agent_card_routes,
        create_jsonrpc_routes,
        create_rest_routes,
    )
    from a2a.server.routes.fastapi_routes import add_a2a_routes_to_fastapi

    from gateway.gateway_service import GatewayService
    from .executor import GatewayA2AExecutor

    _state: dict = {}
    executor = GatewayA2AExecutor()

    @asynccontextmanager
    async def lifespan(a):
        import logging
        logging.basicConfig(level=logging.INFO)
        try:
            from gateway.startup_check import run_signing_key_self_check
            run_signing_key_self_check()
        except Exception as e:
            logger.warning(f"Startup self-check: {e}")

        gateway = GatewayService(tenant="hackathon-demo")
        _state["gateway"] = gateway
        executor._gw = gateway
        logger.info(f"A2A server ready. kid={gateway._kid}")
        yield

    app = FastAPI(
        title="Agent Authorization Gateway — A2A",
        lifespan=lifespan,
    )

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
        return {"ok": True, "service": "gateway-a2a", "protocol": "a2a-1.0"}

    return app


app = create_app()
