"""Worker agent tools — simulated data operations that require authorization.

These tools simulate real database/API operations. In production, each would
validate the scoped authorization token before executing. Here they demonstrate
the authorize → execute flow.
"""

from __future__ import annotations

import json
import time
import hashlib

from google.adk.tools import FunctionTool


def query_database(
    resource: str,
    query: str,
    authorization_token: str = "",
) -> dict:
    """Query a database after receiving authorization from the Gateway.

    IMPORTANT: You must call authorize_action FIRST and pass the token here.

    Args:
        resource: The database resource to query (e.g., "staging-database").
        query: The query to execute (e.g., "SELECT * FROM events LIMIT 10").
        authorization_token: The 60-second scoped token from the Gateway.

    Returns:
        Query results (simulated) or an error if unauthorized.
    """
    if not authorization_token:
        return {
            "error": "UNAUTHORIZED",
            "message": "No authorization token provided. Call authorize_action first.",
        }

    # Simulate token validation (in production, verify JWT signature + expiry)
    if not authorization_token.startswith("ey"):
        return {
            "error": "INVALID_TOKEN",
            "message": "Token format is invalid.",
        }

    # Simulated query results
    return {
        "status": "success",
        "resource": resource,
        "query": query,
        "token_used": authorization_token[:20] + "...",
        "results": [
            {"id": 1, "event": "page_view", "user": "user_42", "ts": "2026-05-27T10:00:00Z"},
            {"id": 2, "event": "click", "user": "user_17", "ts": "2026-05-27T10:01:23Z"},
            {"id": 3, "event": "purchase", "user": "user_42", "ts": "2026-05-27T10:05:00Z"},
        ],
        "count": 3,
        "executed_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }


def search_analytics(
    resource: str,
    search_query: str,
    authorization_token: str = "",
) -> dict:
    """Search analytics data after receiving authorization from the Gateway.

    Args:
        resource: The analytics resource to search.
        search_query: The search criteria (e.g., "conversion_rate > 0.05").
        authorization_token: The 60-second scoped token from the Gateway.

    Returns:
        Search results (simulated) or an error if unauthorized.
    """
    if not authorization_token:
        return {
            "error": "UNAUTHORIZED",
            "message": "No authorization token provided. Call authorize_action first.",
        }

    return {
        "status": "success",
        "resource": resource,
        "search_query": search_query,
        "token_used": authorization_token[:20] + "...",
        "results": [
            {"metric": "conversion_rate", "value": 0.073, "segment": "organic", "period": "2026-05"},
            {"metric": "conversion_rate", "value": 0.061, "segment": "paid", "period": "2026-05"},
        ],
        "count": 2,
        "executed_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }


def list_datasets(
    resource: str,
    authorization_token: str = "",
) -> dict:
    """List available datasets in a database after receiving authorization.

    Args:
        resource: The database resource to list datasets from.
        authorization_token: The 60-second scoped token from the Gateway.

    Returns:
        List of available datasets or an error if unauthorized.
    """
    if not authorization_token:
        return {
            "error": "UNAUTHORIZED",
            "message": "No authorization token provided. Call authorize_action first.",
        }

    return {
        "status": "success",
        "resource": resource,
        "token_used": authorization_token[:20] + "...",
        "datasets": [
            {"name": "analytics_events", "rows": 1_250_000, "last_updated": "2026-05-27"},
            {"name": "user_sessions", "rows": 340_000, "last_updated": "2026-05-26"},
            {"name": "conversion_funnel", "rows": 89_000, "last_updated": "2026-05-27"},
            {"name": "revenue_daily", "rows": 2_190, "last_updated": "2026-05-27"},
        ],
        "count": 4,
        "executed_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }


# Export as ADK FunctionTools
query_database_tool = FunctionTool(query_database)
search_analytics_tool = FunctionTool(search_analytics)
list_datasets_tool = FunctionTool(list_datasets)
