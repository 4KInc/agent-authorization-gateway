"""Run the Gateway MCP server standalone with transport authentication.

Usage:
    python serve_mcp.py              # Runs on port 8090 (or PORT env var)

Environment variables:
    MCP_AUTH_MODE     = "bearer" | "iam" | "none"  (default: "bearer")
    MCP_AUTH_TOKEN    = shared secret for bearer mode
    GATEWAY_DEV_MODE  = "true" to allow MCP_AUTH_MODE=none (NEVER in production)

The MCP server exposes gateway tools (authorize_action, verify_receipt, etc.)
so any MCP-compatible agent can connect and use them.

Transport auth is the first layer; DPoP identity verification inside
authorize_action is the second layer. Both are required for token issuance.
"""

import logging
import os
import sys

import uvicorn
from starlette.applications import Starlette
from starlette.middleware import Middleware
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse

logger = logging.getLogger("gateway.mcp_transport")
logging.basicConfig(
    level=logging.INFO,
    format='{"time":"%(asctime)s","level":"%(levelname)s","logger":"%(name)s","msg":"%(message)s"}',
)

# --- Auth configuration ---

MCP_AUTH_MODE = os.environ.get("MCP_AUTH_MODE", "bearer").lower()
MCP_AUTH_TOKEN = os.environ.get("MCP_AUTH_TOKEN", "")
GATEWAY_DEV_MODE = os.environ.get("GATEWAY_DEV_MODE", "").lower() == "true"

# Anonymous endpoints that don't require transport auth (Phase 3)
ANONYMOUS_PATHS = frozenset()  # /keys is on the REST API, not MCP — all MCP tools require auth


def _validate_config():
    """Startup assertion: refuse to start open without dev mode."""
    if MCP_AUTH_MODE == "none" and not GATEWAY_DEV_MODE:
        logger.fatal(
            "FATAL: MCP_AUTH_MODE=none is only allowed when GATEWAY_DEV_MODE=true. "
            "An open MCP server must not be deployed. "
            "Set MCP_AUTH_MODE=bearer with MCP_AUTH_TOKEN, or MCP_AUTH_MODE=iam for production."
        )
        sys.exit(1)

    if MCP_AUTH_MODE == "bearer" and not MCP_AUTH_TOKEN:
        logger.fatal(
            "FATAL: MCP_AUTH_MODE=bearer requires MCP_AUTH_TOKEN to be set. "
            "Generate one with: python -c \"import secrets; print(secrets.token_urlsafe(32))\""
        )
        sys.exit(1)

    if MCP_AUTH_MODE == "none" and GATEWAY_DEV_MODE:
        logger.warning("MCP transport auth DISABLED (dev mode). Do NOT deploy this configuration.")

    if MCP_AUTH_MODE not in ("bearer", "iam", "none"):
        logger.fatal(f"FATAL: MCP_AUTH_MODE must be 'bearer', 'iam', or 'none', got '{MCP_AUTH_MODE}'")
        sys.exit(1)

    allowed_hosts = os.environ.get("MCP_ALLOWED_HOSTS", "")
    logger.info(
        f"MCP server starting: auth_mode={MCP_AUTH_MODE}, "
        f"dev_mode={GATEWAY_DEV_MODE}, dns_rebinding=on, "
        f"allowed_hosts=localhost+[{allowed_hosts or 'none'}]"
    )


def _verify_google_id_token(token: str) -> bool:
    """Verify a Google-signed ID token (for MCP_AUTH_MODE=iam).

    In production, use google-auth library to verify:
    - Signature against Google's public keys
    - Audience matches this service's URL
    - Token is not expired

    TODO: Replace this stub with google.oauth2.id_token.verify_oauth2_token()
    when deploying with Cloud Run IAM.
    """
    try:
        from google.oauth2 import id_token as google_id_token
        from google.auth.transport import requests as google_requests

        audience = os.environ.get("MCP_IAM_AUDIENCE", "")
        if not audience:
            logger.error("MCP_AUTH_MODE=iam requires MCP_IAM_AUDIENCE (service URL)")
            return False

        claims = google_id_token.verify_oauth2_token(
            token, google_requests.Request(), audience
        )
        logger.info(f"IAM token verified: sub={claims.get('sub')} email={claims.get('email')}")
        return True
    except ImportError:
        logger.error("google-auth not installed; IAM mode requires: pip install google-auth")
        return False
    except Exception as e:
        logger.warning(f"IAM token verification failed: {e}")
        return False


class MCPTransportAuthMiddleware(BaseHTTPMiddleware):
    """Middleware that enforces transport authentication on all MCP requests."""

    async def dispatch(self, request: Request, call_next):
        if MCP_AUTH_MODE == "none":
            return await call_next(request)

        # Extract Bearer token from Authorization header
        auth_header = request.headers.get("authorization", "")
        if not auth_header.startswith("Bearer "):
            return JSONResponse(
                status_code=401,
                content={"error": "UNAUTHORIZED", "detail": "Missing Authorization: Bearer <token> header"},
                headers={"WWW-Authenticate": "Bearer"},
            )

        token = auth_header[7:]  # strip "Bearer "

        if MCP_AUTH_MODE == "bearer":
            if token != MCP_AUTH_TOKEN:
                logger.warning(f"MCP transport: invalid bearer token from {request.client.host if request.client else '?'}")
                return JSONResponse(
                    status_code=401,
                    content={"error": "INVALID_TOKEN", "detail": "Invalid bearer token"},
                    headers={"WWW-Authenticate": "Bearer"},
                )

        elif MCP_AUTH_MODE == "iam":
            if not _verify_google_id_token(token):
                return JSONResponse(
                    status_code=401,
                    content={"error": "INVALID_TOKEN", "detail": "Invalid Google ID token"},
                    headers={"WWW-Authenticate": "Bearer"},
                )

        return await call_next(request)


async def _resume_chain_from_firestore():
    """Resume the in-memory receipt chain from the Firestore-stored max seq.

    This prevents seq from restarting at 1 on each cold start.
    """
    try:
        from gateway.mcp_server import _get_gateway, _get_store
        gateway = _get_gateway()
        store = _get_store()
        stored_chain = await store.get_chain(gateway.tenant)
        if stored_chain:
            last = stored_chain[-1]
            last_seq = int(last.get("body", {}).get("seq", 0))
            last_hash = last.get("receipt_hash", "")
            if last_seq > 0 and last_hash:
                gateway._receipt_chain._seq = last_seq
                gateway._receipt_chain._prev_receipt_hash = last_hash
                logger.info(f"Resumed chain at seq={last_seq}, prev_hash={last_hash[:24]}...")
    except Exception as e:
        logger.warning(f"Chain resume (non-fatal): {e}")


# _publish_key_to_shared_store() REMOVED 2026-05-28.
# Per-instance key publishing was a workaround that didn't survive redeploys.
# All services now load the SAME shared key from Secret Manager.
# The Firestore "keys" collection is no longer written to.


if __name__ == "__main__":
    _validate_config()

    from contextlib import asynccontextmanager
    from gateway.mcp_server import mcp, _get_store, _get_gateway

    port = int(os.environ.get("PORT", "8090"))
    host = "0.0.0.0"

    # Get the Starlette ASGI app from FastMCP then wrap with auth middleware
    app = mcp.streamable_http_app()
    app.add_middleware(MCPTransportAuthMiddleware)

    # Store the original lifespan so we can chain ours
    _original_lifespan = app.router.lifespan_context

    @asynccontextmanager
    async def _lifespan(a):
        # Force-recreate the store on THIS event loop (fixes the closed-loop bug)
        import gateway.mcp_server as _mcp_mod
        from gateway.store import create_store
        _mcp_mod._store = create_store()

        # Resume chain from Firestore (on the uvicorn event loop)
        await _resume_chain_from_firestore()

        # Startup self-check: verify signing key roundtrip
        try:
            from gateway.startup_check import run_signing_key_self_check, check_chain_kid_consistency
            run_signing_key_self_check()
            gw = _get_gateway()
            store = _mcp_mod._store
            await check_chain_kid_consistency(store, gw.tenant, gw._kid)
        except Exception as e:
            logger.warning(f"Startup self-check (non-fatal): {e}")

        # Chain to FastMCP's own lifespan
        async with _original_lifespan(a) as state:
            yield state

    app.router.lifespan_context = _lifespan

    print(f"Agent Authorization Gateway — MCP Server")
    print(f"Listening on {host}:{port}")
    print(f"MCP endpoint: http://{host}:{port}/mcp")
    print(f"Transport auth: {MCP_AUTH_MODE}")
    print()

    uvicorn.run(app, host=host, port=port)
