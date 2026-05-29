"""Local development helper only.

Runs REST + MCP in one process for convenience when iterating against a local
resource without Firestore. NOT used in any deployed service — production runs
REST and MCP as separate Cloud Run services that share keys via Firestore
(see gateway/api.py /keys handler and serve_mcp.py _publish_key_to_shared_store).

This ensures tokens issued via MCP are verifiable via REST /keys (same signing key).

Usage:
    python serve_combined.py                    # REST on 8080, MCP on 8090
    REST_PORT=8080 MCP_PORT=8090 python serve_combined.py
"""

import asyncio
import logging
import os
import sys

import uvicorn

logger = logging.getLogger("gateway.combined")
logging.basicConfig(
    level=logging.INFO,
    format='{"time":"%(asctime)s","level":"%(levelname)s","logger":"%(name)s","msg":"%(message)s"}',
)

# Validate MCP auth config before importing anything heavy
MCP_AUTH_MODE = os.environ.get("MCP_AUTH_MODE", "bearer").lower()
MCP_AUTH_TOKEN = os.environ.get("MCP_AUTH_TOKEN", "")
GATEWAY_DEV_MODE = os.environ.get("GATEWAY_DEV_MODE", "").lower() == "true"

if MCP_AUTH_MODE == "none" and not GATEWAY_DEV_MODE:
    logger.fatal("FATAL: MCP_AUTH_MODE=none requires GATEWAY_DEV_MODE=true")
    sys.exit(1)
if MCP_AUTH_MODE == "bearer" and not MCP_AUTH_TOKEN:
    logger.fatal("FATAL: MCP_AUTH_MODE=bearer requires MCP_AUTH_TOKEN")
    sys.exit(1)

# Import and wire up shared gateway instance
from gateway.gateway_service import GatewayService
from gateway.store import create_store

# Create ONE shared GatewayService
_shared_gateway = GatewayService(tenant="hackathon-demo")
_shared_store = create_store()

# Patch the REST API to use the shared instance
import gateway.api as api_mod
api_mod._gateway = _shared_gateway
api_mod._store = _shared_store

# Patch the MCP server to use the shared instance
import gateway.mcp_server as mcp_mod
mcp_mod._gateway = _shared_gateway
mcp_mod._store = _shared_store

# Build the apps
from gateway.api import api_app
from gateway.mcp_server import mcp

rest_port = int(os.environ.get("REST_PORT", "8080"))
mcp_port = int(os.environ.get("MCP_PORT", "8090"))

# MCP app with transport auth middleware
mcp_app = mcp.streamable_http_app()

if MCP_AUTH_MODE != "none":
    from serve_mcp import MCPTransportAuthMiddleware
    mcp_app.add_middleware(MCPTransportAuthMiddleware)

logger.info(f"Combined server: REST on :{rest_port}, MCP on :{mcp_port}")
logger.info(f"MCP auth: {MCP_AUTH_MODE}, dev_mode={GATEWAY_DEV_MODE}")
logger.info(f"Shared gateway kid: {_shared_gateway._kid}")


async def main():
    rest_config = uvicorn.Config(api_app, host="0.0.0.0", port=rest_port, log_level="info")
    mcp_config = uvicorn.Config(mcp_app, host="0.0.0.0", port=mcp_port, log_level="info")

    rest_server = uvicorn.Server(rest_config)
    mcp_server = uvicorn.Server(mcp_config)

    await asyncio.gather(rest_server.serve(), mcp_server.serve())


if __name__ == "__main__":
    print(f"Agent Authorization Gateway — Combined Server")
    print(f"REST API: http://0.0.0.0:{rest_port}")
    print(f"MCP:      http://0.0.0.0:{mcp_port}/mcp")
    print(f"MCP auth: {MCP_AUTH_MODE}")
    print()
    asyncio.run(main())
