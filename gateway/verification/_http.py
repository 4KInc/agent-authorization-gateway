"""Shared HTTP probes used by multiple verifiers.

Three auth strategies:
1. GCP identity tokens (Cloud Run service-to-service)
2. GCP access tokens (Google APIs: GCS, Pub/Sub, Cloud Functions, etc.)
3. Caller-supplied credentials (AWS SigV4, Azure SAS, bearer tokens, etc.)
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import logging
from datetime import datetime, timezone
from urllib.parse import urlparse, quote

import httpx

from .base import VerificationResult

logger = logging.getLogger("gateway.verification")


# ── GCP auth ──────────────────────────────────────────────────────────

async def _get_gcp_identity_headers(url: str) -> dict[str, str]:
    """Get a GCP identity token for Cloud Run service-to-service auth."""
    try:
        from google.oauth2 import id_token as google_id_token
        from google.auth.transport.requests import Request

        parsed = urlparse(url)
        audience = f"{parsed.scheme}://{parsed.netloc}"
        token = google_id_token.fetch_id_token(Request(), audience)
        return {"Authorization": f"Bearer {token}"}
    except Exception:
        return {}


def _get_gcp_access_token() -> str | None:
    """Get a GCP access token from Application Default Credentials."""
    try:
        import google.auth
        import google.auth.transport.requests

        credentials, _ = google.auth.default()
        credentials.refresh(google.auth.transport.requests.Request())
        return credentials.token
    except Exception:
        return None


# ── AWS SigV4 (minimal, for HEAD/GET existence checks only) ──────────

def _sign_aws_v4(
    method: str,
    url: str,
    region: str,
    service: str,
    access_key: str,
    secret_key: str,
    session_token: str | None = None,
) -> dict[str, str]:
    """Produce AWS Signature V4 headers for a simple GET/HEAD request.

    Minimal implementation sufficient for existence-check API calls
    (no body, no complex query strings). Not a full SigV4 library.
    """
    now = datetime.now(timezone.utc)
    datestamp = now.strftime("%Y%m%d")
    amzdate = now.strftime("%Y%m%dT%H%M%SZ")

    parsed = urlparse(url)
    host = parsed.hostname
    canonical_uri = quote(parsed.path or "/", safe="/")
    canonical_querystring = parsed.query or ""

    headers_to_sign = {"host": host, "x-amz-date": amzdate}
    if session_token:
        headers_to_sign["x-amz-security-token"] = session_token

    signed_headers = ";".join(sorted(headers_to_sign))
    canonical_headers = "".join(f"{k}:{v}\n" for k, v in sorted(headers_to_sign.items()))

    payload_hash = hashlib.sha256(b"").hexdigest()

    canonical_request = "\n".join([
        method.upper(), canonical_uri, canonical_querystring,
        canonical_headers, signed_headers, payload_hash,
    ])

    credential_scope = f"{datestamp}/{region}/{service}/aws4_request"
    string_to_sign = "\n".join([
        "AWS4-HMAC-SHA256", amzdate, credential_scope,
        hashlib.sha256(canonical_request.encode()).hexdigest(),
    ])

    def _hmac_sha256(key: bytes, msg: str) -> bytes:
        return hmac.new(key, msg.encode(), hashlib.sha256).digest()

    signing_key = _hmac_sha256(
        _hmac_sha256(
            _hmac_sha256(
                _hmac_sha256(f"AWS4{secret_key}".encode(), datestamp),
                region,
            ),
            service,
        ),
        "aws4_request",
    )
    signature = hmac.new(signing_key, string_to_sign.encode(), hashlib.sha256).hexdigest()

    auth_header = (
        f"AWS4-HMAC-SHA256 Credential={access_key}/{credential_scope}, "
        f"SignedHeaders={signed_headers}, Signature={signature}"
    )

    result = {
        "Authorization": auth_header,
        "x-amz-date": amzdate,
        "x-amz-content-sha256": payload_hash,
    }
    if session_token:
        result["x-amz-security-token"] = session_token
    return result


# ── Generic probes ────────────────────────────────────────────────────

async def probe_url(
    url: str,
    resource_label: str,
    method: str = "GET",
    accept_statuses: set[int] | None = None,
) -> VerificationResult:
    """Probe a URL (with optional GCP identity token)."""
    if accept_statuses is None:
        accept_statuses = {200}
    try:
        headers = await _get_gcp_identity_headers(url)
        async with httpx.AsyncClient(timeout=5.0) as client:
            resp = await client.request(method, url, headers=headers)
            if resp.status_code in accept_statuses:
                return VerificationResult(
                    status="verified",
                    reason=f"{resource_label} endpoint returned {resp.status_code}",
                    details={"url": url, "status_code": resp.status_code},
                )
            return VerificationResult(
                status="failed",
                reason=f"{resource_label} endpoint returned {resp.status_code}",
                details={"url": url, "status_code": resp.status_code},
            )
    except httpx.TimeoutException:
        return VerificationResult(
            status="failed",
            reason=f"{resource_label} endpoint timed out (>5s)",
            details={"url": url},
        )
    except Exception as e:
        return VerificationResult(
            status="failed",
            reason=f"{resource_label} probe error: {type(e).__name__}: {e}",
            details={"url": url},
        )


async def probe_gcp_api(
    api_url: str,
    resource_label: str,
    accept_statuses: set[int] | None = None,
) -> VerificationResult:
    """Probe a Google API using Application Default Credentials."""
    if accept_statuses is None:
        accept_statuses = {200}

    access_token = _get_gcp_access_token()
    if not access_token:
        return VerificationResult(
            status="failed",
            reason=f"No GCP credentials available to probe {resource_label}",
            details={"url": api_url},
        )

    try:
        headers = {"Authorization": f"Bearer {access_token}"}
        async with httpx.AsyncClient(timeout=5.0) as client:
            resp = await client.get(api_url, headers=headers)
            if resp.status_code in accept_statuses:
                return VerificationResult(
                    status="verified",
                    reason=f"{resource_label} exists (API returned {resp.status_code})",
                    details={"url": api_url, "status_code": resp.status_code},
                )
            if resp.status_code == 404:
                return VerificationResult(
                    status="failed",
                    reason=f"{resource_label} not found (API returned 404)",
                    details={"url": api_url, "status_code": 404},
                )
            return VerificationResult(
                status="failed",
                reason=f"{resource_label} probe returned {resp.status_code}",
                details={"url": api_url, "status_code": resp.status_code},
            )
    except httpx.TimeoutException:
        return VerificationResult(
            status="failed", reason=f"{resource_label} API timed out (>5s)",
            details={"url": api_url},
        )
    except Exception as e:
        return VerificationResult(
            status="failed",
            reason=f"{resource_label} API probe error: {type(e).__name__}: {e}",
            details={"url": api_url},
        )


async def probe_aws_api(
    url: str,
    resource_label: str,
    region: str,
    service: str,
    creds: dict,
    method: str = "GET",
    accept_statuses: set[int] | None = None,
) -> VerificationResult:
    """Probe an AWS API using caller-supplied credentials.

    Args:
        creds: dict with "aws_access_key_id", "aws_secret_access_key",
               and optionally "aws_session_token".
    """
    if accept_statuses is None:
        accept_statuses = {200}

    access_key = creds.get("aws_access_key_id", "")
    secret_key = creds.get("aws_secret_access_key", "")
    if not access_key or not secret_key:
        return VerificationResult(
            status="failed",
            reason=f"AWS credentials missing (need aws_access_key_id + aws_secret_access_key) to probe {resource_label}",
        )

    try:
        auth_headers = _sign_aws_v4(
            method=method, url=url, region=region, service=service,
            access_key=access_key, secret_key=secret_key,
            session_token=creds.get("aws_session_token"),
        )
        async with httpx.AsyncClient(timeout=5.0) as client:
            resp = await client.request(method, url, headers=auth_headers)
            if resp.status_code in accept_statuses:
                return VerificationResult(
                    status="verified",
                    reason=f"{resource_label} exists (AWS API returned {resp.status_code})",
                    details={"status_code": resp.status_code},
                )
            if resp.status_code == 404 or resp.status_code == 403:
                return VerificationResult(
                    status="failed",
                    reason=f"{resource_label} not found or access denied (AWS API returned {resp.status_code})",
                    details={"status_code": resp.status_code},
                )
            return VerificationResult(
                status="failed",
                reason=f"{resource_label} probe returned {resp.status_code}",
                details={"status_code": resp.status_code},
            )
    except httpx.TimeoutException:
        return VerificationResult(
            status="failed", reason=f"{resource_label} AWS API timed out (>5s)",
        )
    except Exception as e:
        return VerificationResult(
            status="failed",
            reason=f"{resource_label} AWS probe error: {type(e).__name__}: {e}",
        )


async def probe_with_bearer(
    url: str,
    resource_label: str,
    token: str,
    method: str = "GET",
    accept_statuses: set[int] | None = None,
) -> VerificationResult:
    """Probe a URL using a caller-supplied bearer token.

    Works for Azure (SAS tokens via query string or Bearer header),
    RabbitMQ management API, or any token-authenticated endpoint.
    """
    if accept_statuses is None:
        accept_statuses = {200}

    try:
        headers = {"Authorization": f"Bearer {token}"}
        async with httpx.AsyncClient(timeout=5.0) as client:
            resp = await client.request(method, url, headers=headers)
            if resp.status_code in accept_statuses:
                return VerificationResult(
                    status="verified",
                    reason=f"{resource_label} exists (returned {resp.status_code})",
                    details={"status_code": resp.status_code},
                )
            return VerificationResult(
                status="failed",
                reason=f"{resource_label} returned {resp.status_code}",
                details={"status_code": resp.status_code},
            )
    except httpx.TimeoutException:
        return VerificationResult(
            status="failed", reason=f"{resource_label} timed out (>5s)",
        )
    except Exception as e:
        return VerificationResult(
            status="failed",
            reason=f"{resource_label} probe error (basic_auth): {type(e).__name__}: {e}",
        )


async def probe_tcp(
    host: str,
    port: int,
    resource_label: str,
    timeout: float = 5.0,
) -> VerificationResult:
    """Test TCP connectivity to a host:port.

    Proves the server process is listening. Does not authenticate or
    send any application-layer data.
    """
    try:
        _, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port),
            timeout=timeout,
        )
        writer.close()
        await writer.wait_closed()
        return VerificationResult(
            status="verified",
            reason=f"{resource_label} is reachable at {host}:{port} (TCP handshake succeeded)",
            details={"host": host, "port": port},
        )
    except asyncio.TimeoutError:
        return VerificationResult(
            status="failed",
            reason=f"{resource_label} at {host}:{port} timed out (>{timeout}s)",
            details={"host": host, "port": port},
        )
    except ConnectionRefusedError:
        return VerificationResult(
            status="failed",
            reason=f"{resource_label} at {host}:{port} refused connection",
            details={"host": host, "port": port},
        )
    except OSError as e:
        return VerificationResult(
            status="failed",
            reason=f"{resource_label} at {host}:{port} unreachable: {e}",
            details={"host": host, "port": port},
        )


async def probe_url_unauthenticated(
    url: str,
    resource_label: str,
    method: str = "HEAD",
) -> VerificationResult:
    """Probe a URL without any authentication.

    Any HTTP response (including 401, 403) proves the endpoint exists.
    Only DNS failures, timeouts, and connection errors count as "failed".
    """
    try:
        async with httpx.AsyncClient(timeout=5.0, follow_redirects=False) as client:
            resp = await client.request(method, url)
            return VerificationResult(
                status="verified",
                reason=f"{resource_label} is reachable (returned {resp.status_code})",
                details={"url": url, "status_code": resp.status_code},
            )
    except httpx.TimeoutException:
        return VerificationResult(
            status="failed",
            reason=f"{resource_label} at {url} timed out (>5s)",
            details={"url": url},
        )
    except Exception as e:
        return VerificationResult(
            status="failed",
            reason=f"{resource_label} at {url} unreachable: {type(e).__name__}: {e}",
            details={"url": url},
        )


def parse_connection_string(conn_str: str) -> tuple[str, int] | None:
    """Extract host and port from a database connection string.

    Supports: postgresql://, mysql://, mongodb://, redis://, host:port
    """
    try:
        parsed = urlparse(conn_str)
        if parsed.hostname:
            port = parsed.port
            if port is None:
                defaults = {
                    "postgresql": 5432, "postgres": 5432,
                    "mysql": 3306, "mariadb": 3306,
                    "mongodb": 27017, "mongodb+srv": 27017,
                    "redis": 6379, "rediss": 6379,
                }
                port = defaults.get(parsed.scheme, 0)
            if port > 0:
                return (parsed.hostname, port)
        if ":" in conn_str and "/" not in conn_str:
            parts = conn_str.rsplit(":", 1)
            return (parts[0], int(parts[1]))
    except Exception:
        pass
    return None


async def probe_with_basic_auth(
    url: str,
    resource_label: str,
    username: str,
    password: str,
    method: str = "GET",
    accept_statuses: set[int] | None = None,
) -> VerificationResult:
    """Probe a URL using HTTP Basic Auth (e.g. RabbitMQ management API)."""
    if accept_statuses is None:
        accept_statuses = {200}

    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            resp = await client.request(method, url, auth=(username, password))
            if resp.status_code in accept_statuses:
                return VerificationResult(
                    status="verified",
                    reason=f"{resource_label} exists (returned {resp.status_code})",
                    details={"status_code": resp.status_code},
                )
            return VerificationResult(
                status="failed",
                reason=f"{resource_label} returned {resp.status_code}",
                details={"status_code": resp.status_code},
            )
    except httpx.TimeoutException:
        return VerificationResult(
            status="failed", reason=f"{resource_label} timed out (>5s)",
        )
    except Exception as e:
        return VerificationResult(
            status="failed",
            reason=f"{resource_label} probe error: {type(e).__name__}: {e}",
        )
