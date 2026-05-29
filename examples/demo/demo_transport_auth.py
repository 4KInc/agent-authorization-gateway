#!/usr/bin/env python3
"""Demo: Transport Auth — proves the MCP server rejects anonymous callers.

Requires the MCP server running in bearer mode (MCP_AUTH_MODE=bearer).
The correct bearer token is read from MCP_AUTH_TOKEN env var.

Three attacks:
  A1. No credentials at all → 401 UNAUTHORIZED
  A2. Wrong bearer token   → 401 INVALID_TOKEN
  A3. Correct bearer + no DPoP proof → identity layer rejects with NO_PROOF

Exit code 0 if all attacks are rejected, 1 if any succeeds (regression).
"""

import json
import os
import sys

import httpx

MCP_URL = os.environ.get("MCP_URL", "http://localhost:8090/mcp")
MCP_AUTH_TOKEN = os.environ.get("MCP_AUTH_TOKEN", "")

# JSON-RPC initialize request (what any MCP client sends first)
JSONRPC_INIT = {
    "jsonrpc": "2.0",
    "method": "initialize",
    "params": {
        "protocolVersion": "2024-11-05",
        "capabilities": {},
        "clientInfo": {"name": "rogue-client", "version": "0.0.1"},
    },
    "id": 1,
}

# JSON-RPC tool call — authorize_action with no DPoP proof
JSONRPC_AUTHORIZE = {
    "jsonrpc": "2.0",
    "method": "tools/call",
    "params": {
        "name": "authorize_action",
        "arguments": {
            "agent_id": "anonymous-attacker",
            "action": "query",
            "resource": "staging-database",
            "agent_proof": "",
        },
    },
    "id": 2,
}


def run():
    print("=" * 60)
    print("  TRANSPORT AUTH DEMO — MCP Bearer Mode")
    print("=" * 60)
    print(f"  MCP URL: {MCP_URL}")
    print(f"  Auth mode: bearer")
    print()

    results = []

    with httpx.Client(timeout=10) as client:
        # --- A1: Anonymous (no Authorization header) ---
        print("[A1] Attack: Anonymous MCP request (no credentials)")
        resp = client.post(MCP_URL, json=JSONRPC_INIT)
        status = resp.status_code
        body = _safe_json(resp)
        error_code = body.get("error", "") if isinstance(body, dict) else ""
        blocked = status == 401 and error_code == "UNAUTHORIZED"
        results.append(("Anonymous", "401 UNAUTHORIZED", f"{status} {error_code}", blocked))
        print(f"     Expected: 401 UNAUTHORIZED")
        print(f"     Actual:   {status} {error_code}")
        print(f"     Result:   {'REJECTED (no token minted)' if blocked else 'FAILED — ANONYMOUS ACCESS ALLOWED!'}")

        # --- A2: Wrong bearer token ---
        print()
        print("[A2] Attack: Wrong bearer token")
        resp = client.post(
            MCP_URL,
            json=JSONRPC_INIT,
            headers={"Authorization": "Bearer wrong-token-12345"},
        )
        status = resp.status_code
        body = _safe_json(resp)
        error_code = body.get("error", "") if isinstance(body, dict) else ""
        blocked = status == 401 and error_code == "INVALID_TOKEN"
        results.append(("Wrong bearer", "401 INVALID_TOKEN", f"{status} {error_code}", blocked))
        print(f"     Expected: 401 INVALID_TOKEN")
        print(f"     Actual:   {status} {error_code}")
        print(f"     Result:   {'REJECTED' if blocked else 'FAILED — WRONG TOKEN ACCEPTED!'}")

    # --- A3: Correct bearer + no DPoP proof (uses proper MCP client) ---
    print()
    print("[A3] Attack: Correct bearer, no DPoP proof (empty agent_proof)")
    import asyncio
    a3_result = asyncio.run(_test_a3_no_dpop())
    results.append(a3_result)

    # --- Summary ---
    print()
    print("=" * 60)
    print("  TRANSPORT AUTH RESULTS")
    print("=" * 60)
    print(f"  {'Attack':<22} {'Expected':<22} {'Actual':<22} {'Status'}")
    print(f"  {'-'*22} {'-'*22} {'-'*22} {'-'*8}")
    all_blocked = True
    for attack, expected, actual, blocked in results:
        s = "BLOCKED" if blocked else "FAIL"
        if not blocked:
            all_blocked = False
        print(f"  {attack:<22} {expected:<22} {actual:<22} {s}")

    print()
    if all_blocked:
        print("  ALL TRANSPORT ATTACKS REJECTED — no anonymous token issuance possible")
    else:
        print("  SOME ATTACKS SUCCEEDED — TRANSPORT AUTH IS BROKEN!")
    print("=" * 60)

    return 0 if all_blocked else 1


async def _test_a3_no_dpop():
    """A3: Connect with correct bearer via proper MCP client, call authorize with no proof."""
    from mcp.client.streamable_http import streamablehttp_client
    from mcp import ClientSession
    import json as _json

    try:
        async with streamablehttp_client(
            MCP_URL,
            headers={"Authorization": f"Bearer {MCP_AUTH_TOKEN}"},
        ) as (r, w, _):
            async with ClientSession(r, w) as session:
                await session.initialize()
                result = await session.call_tool("authorize_action", {
                    "agent_id": "anonymous-attacker",
                    "action": "query",
                    "resource": "staging-database",
                    "agent_proof": "",
                })
                text = result.content[0].text if result.content else ""
                parsed = _json.loads(text) if text else {}
                no_proof = parsed.get("error") == "NO_PROOF"
                if no_proof:
                    print("     Transport: PASSED (valid bearer)")
                    print("     Identity:  REJECTED (NO_PROOF — DPoP required)")
                    print("     Result:    BLOCKED at identity layer")
                    return ("Bearer + no DPoP", "NO_PROOF", "NO_PROOF", True)
                else:
                    print(f"     Unexpected response: {parsed}")
                    if parsed.get("decision") and parsed.get("token"):
                        print("     CRITICAL: TOKEN ISSUED WITHOUT DPoP — EXPLOIT REGRESSION!")
                    print("     Result:    FAILED")
                    return ("Bearer + no DPoP", "NO_PROOF", str(parsed)[:40], False)
    except Exception as e:
        print(f"     Exception: {type(e).__name__}: {str(e)[:150]}")
        print("     Result:    FAILED (connection error, not a clean NO_PROOF rejection)")
        return ("Bearer + no DPoP", "NO_PROOF", f"Exception: {type(e).__name__}", False)


def _safe_json(resp):
    try:
        return resp.json()
    except Exception:
        return resp.text


def _truncate(s, n):
    return s[:n] + "..." if len(s) > n else s


def _extract_no_proof(body):
    """Check if the response contains a NO_PROOF error anywhere in the JSON-RPC result."""
    if isinstance(body, dict):
        # Direct error
        if "NO_PROOF" in str(body.get("error", "")):
            return True
        if "NO_PROOF" in str(body.get("detail", "")):
            return True
        # JSON-RPC result wrapping tool output
        result = body.get("result", {})
        if isinstance(result, dict):
            content = result.get("content", [])
            if isinstance(content, list):
                for item in content:
                    text = item.get("text", "") if isinstance(item, dict) else ""
                    if "NO_PROOF" in text:
                        return True
    if isinstance(body, str) and "NO_PROOF" in body:
        return True
    return False


if __name__ == "__main__":
    sys.exit(run())
