"""Worker Agent — a data analytics agent that requests authorization before acting.

This agent demonstrates the full authorize → execute flow:
1. User asks for data
2. Worker calls authorize_action (via Gateway sub-agent transfer)
3. Gateway evaluates policy, signs receipt, returns token
4. Worker executes the action using the scoped token
5. Worker returns results to user

In the multi-agent architecture, the user talks to the Orchestrator,
which delegates to either the Worker or the Gateway based on intent.
"""

from google.adk.agents import Agent

from gateway.tools.authorize_tool import authorize_action_tool
from .tools import query_database_tool, search_analytics_tool, list_datasets_tool

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
   - Call the appropriate data tool (query_database, search_analytics, or list_datasets) with the token
   - Present the results to the user
4. If decision is "deny":
   - Tell the user the action was blocked
   - Explain the reason codes
   - Suggest compliant alternatives (e.g., use staging instead of production)

RULES:
- NEVER skip authorization — every data access needs a token
- NEVER ignore a deny — blocked means blocked
- ALWAYS pass the authorization token to data tools
- If the user asks about security, chain stats, or receipts, tell them to ask the Gateway Agent directly

Your agent_id is: worker-analytics-01"""

worker_agent = Agent(
    model="gemini-2.5-flash",
    name="worker_analytics",
    description="A data analytics agent that queries databases and APIs. Always requests authorization from the Gateway before accessing any resource. Use this agent when the user wants to read data, run queries, search analytics, or list datasets.",
    instruction=WORKER_SYSTEM_INSTRUCTION,
    tools=[
        authorize_action_tool,
        query_database_tool,
        search_analytics_tool,
        list_datasets_tool,
    ],
)
