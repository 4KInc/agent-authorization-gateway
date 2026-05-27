"""Worker Agent — a data analytics agent that requests authorization via MCP.

This agent demonstrates the full authorize → execute flow using MCP:
1. User asks for data
2. Worker calls authorize_action via MCP (Gateway's MCP server)
3. Gateway evaluates policy, signs receipt, returns token
4. Worker executes the action using the scoped token
5. Worker returns results to user

The MCP connection means the Worker and Gateway are decoupled —
they can run as separate services, and any MCP-compatible agent
framework can connect to the Gateway.
"""

import os

from google.adk.agents import Agent
from google.adk.tools import McpToolset
from google.adk.tools.mcp_tool import StreamableHTTPConnectionParams

from .tools import query_database_tool, search_analytics_tool, list_datasets_tool, write_data_tool

# MCP connection to the Gateway's authorization tools
GATEWAY_MCP_URL = os.environ.get(
    "GATEWAY_MCP_URL",
    "http://localhost:8090/mcp",
)

gateway_mcp_toolset = McpToolset(
    connection_params=StreamableHTTPConnectionParams(
        url=GATEWAY_MCP_URL,
        timeout=10.0,
    ),
    # Only import the authorization tool — the worker doesn't need stats/chain/keys
    tool_filter=["authorize_action"],
)

WORKER_SYSTEM_INSTRUCTION = """You are a Data Analytics Worker Agent. Your job is to help users analyze data by querying databases and accessing resources.

CRITICAL SECURITY REQUIREMENT:
Before performing ANY data operation, you MUST first call authorize_action to get authorization from the Gateway.

Your workflow for every data request:
1. Determine what action you need (read, query, search, list, analyze)
2. Call authorize_action with:
   - agent_id: "worker-analytics-01"
   - action: description of what you're doing (e.g., "read records", "search analytics")
   - resource: the target resource (e.g., "staging-database", "staging-analytics-api")
   - parameters: any relevant parameters as a JSON string
3. If decision is "approve":
   - Take the token from the response
   - Call the appropriate data tool (query_database, search_analytics, list_datasets, or write_data) with the token
   - Present the results to the user
4. If decision is "deny":
   - Tell the user the action was blocked
   - Explain the reason codes
   - Suggest compliant alternatives (e.g., use staging instead of production)
   - NOTE: "write" actions will be denied by Gateway policy — this is expected behavior demonstrating the enforcement boundary

RULES:
- NEVER skip authorization — every data access needs a token
- NEVER ignore a deny — blocked means blocked
- ALWAYS pass the authorization token to data tools
- If the user asks about security, chain stats, or receipts, tell them to ask the Gateway Agent directly

Your agent_id is: worker-analytics-01"""

worker_agent = Agent(
    model="gemini-2.5-flash",
    name="worker_analytics",
    description="A data analytics agent that queries databases and APIs. Always requests authorization from the Gateway via MCP before accessing any resource. Use this agent when the user wants to read data, run queries, search analytics, or list datasets.",
    instruction=WORKER_SYSTEM_INSTRUCTION,
    tools=[
        gateway_mcp_toolset,
        query_database_tool,
        search_analytics_tool,
        list_datasets_tool,
        write_data_tool,
    ],
)
