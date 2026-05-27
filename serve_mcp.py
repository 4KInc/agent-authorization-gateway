"""Run the Gateway MCP server standalone.

Usage:
    python serve_mcp.py              # Runs on port 8090 (or PORT env var)

The MCP server exposes gateway tools (authorize_action, verify_receipt, etc.)
so any MCP-compatible agent can connect and use them.
"""

import os

import uvicorn

from gateway.mcp_server import mcp

if __name__ == "__main__":
    port = int(os.environ.get("PORT", "8090"))
    host = "0.0.0.0"

    # Get the Starlette ASGI app from FastMCP
    app = mcp.streamable_http_app()

    print(f"Agent Authorization Gateway — MCP Server")
    print(f"Listening on {host}:{port}")
    print(f"MCP endpoint: http://{host}:{port}/mcp")
    print()

    uvicorn.run(app, host=host, port=port)
