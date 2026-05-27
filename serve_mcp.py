"""Run the Gateway MCP server standalone.

Usage:
    python serve_mcp.py              # Runs on port 8090
    python serve_mcp.py --port 9090  # Custom port

The MCP server exposes gateway tools (authorize_action, verify_receipt, etc.)
so any MCP-compatible agent can connect and use them.
"""

import os
import sys

# Must set env vars BEFORE importing FastMCP (it reads them at class init)
port = os.environ.get("PORT", "8090")
os.environ["FASTMCP_PORT"] = port
os.environ["FASTMCP_HOST"] = "0.0.0.0"

from gateway.mcp_server import mcp

if __name__ == "__main__":
    print(f"Agent Authorization Gateway — MCP Server")
    print(f"Listening on 0.0.0.0:{port}")
    print(f"MCP endpoint: http://0.0.0.0:{port}/mcp")
    print()

    mcp.run(transport="streamable-http")
