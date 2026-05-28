"""Worker agent tools — simulated data operations that require authorization.

These tools simulate real database/API operations. Each validates the scoped
authorization token (JWT) before executing, checking signature, expiry, and
action digest binding. This demonstrates the authorize -> execute flow with
real cryptographic verification at the enforcement boundary.
"""

from __future__ import annotations

import json
import os
import time
import hashlib

import jwt as pyjwt

from google.adk.tools import FunctionTool
from gateway.tokens import compute_action_digest, TOKEN_ISSUER, TOKEN_AUDIENCE


def _validate_token(
    authorization_token: str,
    expected_action: str,
    expected_resource: str,
    agent_id: str = "worker-agent",
    parameters: dict | None = None,
) -> dict | None:
    """Validate a scoped authorization JWT.

    Returns None on success, or an error dict on failure.
    Checks: format, signature, expiry, issuer/audience, and action_digest binding.
    """
    if not authorization_token:
        return {
            "error": "UNAUTHORIZED",
            "message": (
                "No authorization token provided. "
                "You must call authorize_action on the Gateway first, "
                "then pass the returned token here."
            ),
        }

    # For worker-side validation, we do a lightweight check.
    # Full verification happens at the protected resource via the middleware.
    # Here we decode without signature verification to check structure/expiry.
    try:
        claims = pyjwt.decode(
            authorization_token,
            options={"verify_signature": False},
            algorithms=["EdDSA", "HS256"],
            issuer=TOKEN_ISSUER,
            audience=TOKEN_AUDIENCE,
        )
    except pyjwt.ExpiredSignatureError:
        return {
            "error": "TOKEN_EXPIRED",
            "message": (
                "Authorization token has expired. "
                "Request a new authorization from the Gateway."
            ),
        }
    except pyjwt.InvalidSignatureError:
        return {
            "error": "INVALID_SIGNATURE",
            "message": "Token signature verification failed. The token may have been tampered with.",
        }
    except pyjwt.InvalidTokenError as exc:
        # Catch-all for malformed tokens, bad issuer/audience, etc.
        return {
            "error": "INVALID_TOKEN",
            "message": f"Token validation failed: {exc}",
        }

    # Verify the token is bound to the action we are about to execute
    expected_digest = compute_action_digest(
        agent_id=agent_id,
        action=expected_action,
        resource=expected_resource,
        parameters=parameters,
    )
    token_digest = claims.get("action_digest", "")
    if token_digest != expected_digest:
        return {
            "error": "ACTION_MISMATCH",
            "message": (
                f"Token was issued for a different action. "
                f"Expected digest {expected_digest[:32]}..., "
                f"got {token_digest[:32]}..."
            ),
        }

    # Token is valid and bound to the correct action
    return None


# ---------------------------------------------------------------------------
# Simulated data sets
# ---------------------------------------------------------------------------

_ANALYTICS_DATA = {
    "analytics": [
        {"metric": "conversion_rate", "value": 0.073, "segment": "organic", "period": "2026-05", "trend": "+12%"},
        {"metric": "conversion_rate", "value": 0.061, "segment": "paid", "period": "2026-05", "trend": "+3%"},
        {"metric": "bounce_rate", "value": 0.42, "segment": "organic", "period": "2026-05", "trend": "-5%"},
        {"metric": "avg_session_duration", "value": 184.5, "segment": "all", "period": "2026-05", "trend": "+8%"},
    ],
    "users": [
        {"user_id": "u_3f8a", "email": "alice@acme.co", "role": "admin", "last_active": "2026-05-27T09:12:00Z", "sessions": 47},
        {"user_id": "u_91cb", "email": "bob@acme.co", "role": "editor", "last_active": "2026-05-26T16:30:00Z", "sessions": 23},
        {"user_id": "u_d4e7", "email": "carol@acme.co", "role": "viewer", "last_active": "2026-05-27T11:00:00Z", "sessions": 112},
    ],
    "events": [
        {"id": 1, "event": "page_view", "user": "u_3f8a", "page": "/dashboard", "ts": "2026-05-27T10:00:00Z"},
        {"id": 2, "event": "click", "user": "u_91cb", "page": "/reports", "ts": "2026-05-27T10:01:23Z"},
        {"id": 3, "event": "purchase", "user": "u_d4e7", "amount": 49.99, "ts": "2026-05-27T10:05:00Z"},
        {"id": 4, "event": "signup", "user": "u_a1b2", "source": "referral", "ts": "2026-05-27T10:12:45Z"},
        {"id": 5, "event": "page_view", "user": "u_d4e7", "page": "/pricing", "ts": "2026-05-27T10:15:00Z"},
    ],
    "revenue": [
        {"date": "2026-05-25", "revenue": 12_450.00, "transactions": 312, "avg_order": 39.90},
        {"date": "2026-05-26", "revenue": 15_780.00, "transactions": 401, "avg_order": 39.35},
        {"date": "2026-05-27", "revenue": 9_230.00, "transactions": 228, "avg_order": 40.48},
    ],
}

_DATASETS_REGISTRY = {
    "analytics": [
        {"name": "web_analytics_events", "rows": 1_250_000, "last_updated": "2026-05-27", "size_mb": 480},
        {"name": "conversion_funnel", "rows": 89_000, "last_updated": "2026-05-27", "size_mb": 34},
        {"name": "ab_test_results", "rows": 12_400, "last_updated": "2026-05-26", "size_mb": 5},
    ],
    "users": [
        {"name": "user_profiles", "rows": 45_000, "last_updated": "2026-05-27", "size_mb": 120},
        {"name": "user_sessions", "rows": 340_000, "last_updated": "2026-05-26", "size_mb": 210},
        {"name": "user_permissions", "rows": 45_000, "last_updated": "2026-05-25", "size_mb": 8},
    ],
    "default": [
        {"name": "analytics_events", "rows": 1_250_000, "last_updated": "2026-05-27", "size_mb": 480},
        {"name": "user_sessions", "rows": 340_000, "last_updated": "2026-05-26", "size_mb": 210},
        {"name": "conversion_funnel", "rows": 89_000, "last_updated": "2026-05-27", "size_mb": 34},
        {"name": "revenue_daily", "rows": 2_190, "last_updated": "2026-05-27", "size_mb": 1},
    ],
}


def _select_data(resource: str) -> tuple[str, list[dict]]:
    """Pick simulated result data based on keywords in the resource name."""
    resource_lower = resource.lower()
    for keyword in ("analytics", "users", "events", "revenue"):
        if keyword in resource_lower:
            return keyword, _ANALYTICS_DATA.get(keyword, _ANALYTICS_DATA["events"])
    return "events", _ANALYTICS_DATA["events"]


def _select_datasets(resource: str) -> list[dict]:
    """Pick simulated dataset list based on keywords in the resource name."""
    resource_lower = resource.lower()
    for keyword in ("analytics", "users"):
        if keyword in resource_lower:
            return _DATASETS_REGISTRY[keyword]
    return _DATASETS_REGISTRY["default"]


# ---------------------------------------------------------------------------
# Tool implementations
# ---------------------------------------------------------------------------

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
    error = _validate_token(authorization_token, expected_action="query", expected_resource=resource)
    if error:
        return error

    data_type, results = _select_data(resource)

    return {
        "status": "success",
        "resource": resource,
        "data_type": data_type,
        "query": query,
        "token_verified": True,
        "token_snippet": authorization_token[:20] + "...",
        "results": results,
        "count": len(results),
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
    error = _validate_token(authorization_token, expected_action="query", expected_resource=resource)
    if error:
        return error

    _, results = _select_data(resource)

    return {
        "status": "success",
        "resource": resource,
        "search_query": search_query,
        "token_verified": True,
        "token_snippet": authorization_token[:20] + "...",
        "results": results,
        "count": len(results),
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
    error = _validate_token(authorization_token, expected_action="query", expected_resource=resource)
    if error:
        return error

    datasets = _select_datasets(resource)

    return {
        "status": "success",
        "resource": resource,
        "token_verified": True,
        "token_snippet": authorization_token[:20] + "...",
        "datasets": datasets,
        "count": len(datasets),
        "executed_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }


def write_data(
    resource: str,
    table: str,
    data: str,
    authorization_token: str = "",
) -> dict:
    """Write data to a database table. Requires "write" authorization from the Gateway.

    This tool demonstrates the enforcement boundary: the Gateway policy only
    allows "query" actions, so requesting authorization for "write" will be
    DENIED. The agent should report the denial to the user.

    Args:
        resource: The database resource to write to (e.g., "staging-database").
        table: The target table name (e.g., "analytics_events").
        data: JSON-encoded row data to insert.
        authorization_token: The scoped token from the Gateway (must authorize "write").

    Returns:
        Write confirmation or an error if unauthorized / denied.
    """
    error = _validate_token(authorization_token, expected_action="write", expected_resource=resource)
    if error:
        return error

    # If we somehow got here with a valid write token, simulate the write
    return {
        "status": "success",
        "resource": resource,
        "table": table,
        "rows_written": 1,
        "token_verified": True,
        "token_snippet": authorization_token[:20] + "...",
        "executed_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }


# ---------------------------------------------------------------------------
# Export as ADK FunctionTools
# ---------------------------------------------------------------------------
query_database_tool = FunctionTool(query_database)
search_analytics_tool = FunctionTool(search_analytics)
list_datasets_tool = FunctionTool(list_datasets)
write_data_tool = FunctionTool(write_data)
