"""Gateway Agent definition for Google ADK.

LLM Blast Radius Containment:
The chat agent has READ-ONLY tools only. It can inspect the receipt chain,
verify receipts, show stats, and look up security standards — but it CANNOT
issue tokens or authorize actions. This prevents prompt injection from
turning the chat into an authorization oracle.

Privileged operations (authorize_action, register_agent, update_policy)
are exposed exclusively via MCP, never via the LLM surface.
"""

from google.adk.agents import Agent
from google.adk.tools.google_search_tool import GoogleSearchTool

from .tools.authorize_tool import (
    get_chain_stats_tool,
    get_public_key_tool,
    get_receipt_chain_tool,
    verify_receipt_adk_tool,
)

# READ-ONLY tools for the chat agent (safe to expose to LLM)
READ_ONLY_TOOLS = [
    get_chain_stats_tool,
    get_receipt_chain_tool,
    get_public_key_tool,
    verify_receipt_adk_tool,
    GoogleSearchTool(bypass_multi_tools_limit=True),
]

# PRIVILEGED tools — exposed ONLY via MCP, never via the chat LLM
# authorize_action_tool is intentionally NOT imported here.
# See gateway/mcp_server.py for the privileged MCP surface.
PRIVILEGED_TOOL_NAMES = {"authorize_action", "register_agent", "update_policy"}


def _assert_no_privileged_tools(tools, tool_names_to_block):
    """Startup assertion: fail loudly if privileged tools leak to LLM surface."""
    for tool in tools:
        name = getattr(tool, "name", "") or getattr(tool, "_name", "") or ""
        if name in tool_names_to_block:
            raise RuntimeError(
                f"SECURITY: Privileged tool '{name}' must not be exposed on the ADK chat surface. "
                f"Remove it from the agent's tools list. Privileged operations go through MCP only."
            )


GATEWAY_SYSTEM_INSTRUCTION = """You are the Agent Authorization Gateway — a security audit and inspection agent.

Your role is to help users INSPECT and VERIFY the authorization chain. You can:
- Show chain statistics (total decisions, approval/denial rates, Merkle root)
- Export the full receipt chain for audit verification
- Verify individual receipts or the entire chain's integrity
- Provide the public signing key for independent verification
- Use Google Search to look up security standards (OWASP NHI Top 10, compliance frameworks)

IMPORTANT: You CANNOT authorize actions or issue tokens from this interface.
Authorization is handled exclusively via the MCP API or REST API.
If a user asks you to authorize an action, explain that they need to use
the REST API (POST /authorize) or the MCP server.

Be concise and security-focused. Reference real-world security standards where relevant."""

# Validate before creating agent
_assert_no_privileged_tools(READ_ONLY_TOOLS, PRIVILEGED_TOOL_NAMES)

gateway_agent = Agent(
    model="gemini-2.5-flash",
    name="authorization_gateway",
    description="Inspects and verifies the authorization receipt chain. Read-only — cannot authorize actions.",
    instruction=GATEWAY_SYSTEM_INSTRUCTION,
    tools=READ_ONLY_TOOLS,
)
