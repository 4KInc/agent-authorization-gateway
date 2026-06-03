"""Continuous attestation — periodic re-verification of agent liveness.

After registration, agents are periodically re-challenged to prove they
are still alive and still control their private key. This closes the gap
between one-time registration verification and ongoing trust.

State machine (graduated):
  LIVE        — last challenge succeeded
  WARNING     — 1 consecutive failure (logged, receipts flagged)
  STALE       — 2 consecutive failures (new authorizations denied)
  SUSPENDED   — 3+ consecutive failures (full lockout, admin notified)
  UNKNOWN     — no liveness data (agent registered without live_challenge_url)

Checks happen two ways:
  1. Lazy: on authorize, if liveness_verified_at is older than the interval
  2. Scheduled: background sweep re-challenges all registered agents
"""

from __future__ import annotations

import base64
import json
import logging
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum

logger = logging.getLogger("gateway.liveness")

# Default attestation interval: 60 minutes
DEFAULT_ATTESTATION_INTERVAL = 3600
# Max history entries per agent
MAX_HISTORY_ENTRIES = 20


class LivenessState(str, Enum):
    LIVE = "LIVE"
    WARNING = "WARNING"
    STALE = "STALE"
    SUSPENDED = "SUSPENDED"
    UNKNOWN = "UNKNOWN"


@dataclass
class LivenessRecord:
    """Rolling liveness state for one agent."""
    agent_id: str
    state: LivenessState = LivenessState.UNKNOWN
    consecutive_failures: int = 0
    total_checks: int = 0
    total_successes: int = 0
    total_failures: int = 0
    liveness_verified_at: float | None = None
    last_check_at: float | None = None
    last_failure_reason: str | None = None
    live_challenge_url: str | None = None
    history: list[dict] = field(default_factory=list)

    def record_success(self) -> None:
        self.consecutive_failures = 0
        self.total_checks += 1
        self.total_successes += 1
        self.liveness_verified_at = time.time()
        self.last_check_at = time.time()
        self.last_failure_reason = None
        self.state = LivenessState.LIVE
        self._append_history("success", None)

    def record_failure(self, reason: str) -> None:
        self.consecutive_failures += 1
        self.total_checks += 1
        self.total_failures += 1
        self.last_check_at = time.time()
        self.last_failure_reason = reason
        if self.consecutive_failures >= 3:
            self.state = LivenessState.SUSPENDED
        elif self.consecutive_failures == 2:
            self.state = LivenessState.STALE
        elif self.consecutive_failures == 1:
            self.state = LivenessState.WARNING

        self._append_history("failure", reason)

    def _append_history(self, outcome: str, reason: str | None) -> None:
        entry = {
            "timestamp": time.time(),
            "outcome": outcome,
            "state_after": self.state.value,
        }
        if reason:
            entry["reason"] = reason
        self.history.append(entry)
        if len(self.history) > MAX_HISTORY_ENTRIES:
            self.history = self.history[-MAX_HISTORY_ENTRIES:]

    def is_stale(self, interval: int = DEFAULT_ATTESTATION_INTERVAL) -> bool:
        """True if liveness has never been verified or is older than interval."""
        if self.liveness_verified_at is None:
            return True
        return (time.time() - self.liveness_verified_at) > interval

    def should_deny_authorization(self) -> bool:
        """True if liveness state is too degraded for new authorizations."""
        return self.state in (LivenessState.STALE, LivenessState.SUSPENDED)

    def to_dict(self) -> dict:
        return {
            "agent_id": self.agent_id,
            "state": self.state.value,
            "consecutive_failures": self.consecutive_failures,
            "total_checks": self.total_checks,
            "total_successes": self.total_successes,
            "total_failures": self.total_failures,
            "liveness_verified_at": (
                datetime.fromtimestamp(self.liveness_verified_at, tz=timezone.utc).isoformat()
                if self.liveness_verified_at else None
            ),
            "last_check_at": (
                datetime.fromtimestamp(self.last_check_at, tz=timezone.utc).isoformat()
                if self.last_check_at else None
            ),
            "last_failure_reason": self.last_failure_reason,
            "live_challenge_url": self.live_challenge_url,
            "history": self.history[-10:],  # Return last 10 for API responses
        }


class LivenessManager:
    """Manages continuous attestation for all registered agents."""

    def __init__(self, attestation_interval: int = DEFAULT_ATTESTATION_INTERVAL):
        self._records: dict[str, LivenessRecord] = {}
        self.attestation_interval = attestation_interval

    def get_or_create(self, agent_id: str, live_challenge_url: str | None = None) -> LivenessRecord:
        record = self._records.get(agent_id)
        if record is None:
            record = LivenessRecord(agent_id=agent_id, live_challenge_url=live_challenge_url)
            self._records[agent_id] = record
        if live_challenge_url and record.live_challenge_url != live_challenge_url:
            record.live_challenge_url = live_challenge_url
        return record

    def get(self, agent_id: str) -> LivenessRecord | None:
        return self._records.get(agent_id)

    def remove(self, agent_id: str) -> None:
        self._records.pop(agent_id, None)

    def list_all(self) -> list[LivenessRecord]:
        return list(self._records.values())

    def agents_needing_check(self) -> list[LivenessRecord]:
        """Return agents whose liveness is stale and have a challenge URL."""
        return [
            r for r in self._records.values()
            if r.live_challenge_url and r.is_stale(self.attestation_interval)
        ]

    async def check_agent(
        self,
        agent_id: str,
        declared_jwk: dict,
        tenant_id: str,
    ) -> LivenessRecord:
        """Run a liveness challenge against a single agent. Updates state."""
        record = self.get(agent_id)
        if record is None:
            raise ValueError(f"No liveness record for agent '{agent_id}'")
        if not record.live_challenge_url:
            return record  # Nothing to check

        result = await _run_liveness_challenge(
            record.live_challenge_url, declared_jwk, agent_id, tenant_id,
        )

        if result["status"] == "verified":
            record.record_success()
            logger.info(
                "Liveness check PASSED: agent=%s state=%s",
                agent_id, record.state.value,
            )
        else:
            record.record_failure(result.get("reason", "unknown"))
            logger.warning(
                "Liveness check FAILED: agent=%s state=%s consecutive=%d reason=%s",
                agent_id, record.state.value,
                record.consecutive_failures, result.get("reason"),
            )
        return record

    async def sweep(
        self,
        registry,  # AgentRegistry
        tenant_id: str,
    ) -> dict:
        """Re-challenge all agents that need checking. Returns summary."""
        import base64
        needs_check = self.agents_needing_check()
        checked = 0
        passed = 0
        failed = 0

        for record in needs_check:
            agent = registry.get(record.agent_id)
            if agent is None:
                continue
            # Reconstruct JWK from the registered public key
            pub_bytes = agent.public_key.public_bytes_raw()
            jwk = {
                "kty": "OKP",
                "crv": "Ed25519",
                "x": base64.urlsafe_b64encode(pub_bytes).rstrip(b"=").decode(),
            }
            await self.check_agent(record.agent_id, jwk, tenant_id)
            checked += 1
            if record.state == LivenessState.LIVE:
                passed += 1
            else:
                failed += 1

        return {
            "checked": checked,
            "passed": passed,
            "failed": failed,
            "total_registered": len(self._records),
        }


async def _run_liveness_challenge(
    live_challenge_url: str,
    declared_jwk: dict,
    agent_id: str,
    tenant_id: str,
) -> dict:
    """POST a fresh nonce to the agent's callback URL and verify signature.

    This is the same protocol as the registration live challenge, extracted
    so it can be reused for continuous attestation.
    """
    import secrets as _secrets
    import httpx

    nonce = base64.urlsafe_b64encode(_secrets.token_bytes(32)).rstrip(b"=").decode()
    challenge_id = base64.urlsafe_b64encode(_secrets.token_bytes(16)).rstrip(b"=").decode()
    iat = int(time.time())

    challenge_payload = {
        "v": "1",
        "type": "agent_liveness_challenge",
        "tenant_id": tenant_id,
        "agent_id": agent_id,
        "nonce": nonce,
        "challenge_id": challenge_id,
        "iat": iat,
    }

    try:
        headers = {}
        try:
            from google.oauth2 import id_token as google_id_token
            from google.auth.transport.requests import Request
            from urllib.parse import urlparse
            parsed = urlparse(live_challenge_url)
            audience = f"{parsed.scheme}://{parsed.netloc}"
            token = google_id_token.fetch_id_token(Request(), audience)
            headers["Authorization"] = f"Bearer {token}"
        except Exception:
            pass
        async with httpx.AsyncClient(timeout=5.0) as client:
            resp = await client.post(live_challenge_url, json=challenge_payload, headers=headers)
            if resp.status_code != 200:
                return {"status": "failed", "reason": f"callback returned {resp.status_code}"}
            response_data = resp.json()
    except httpx.TimeoutException:
        return {"status": "failed", "reason": "callback timeout (>5s)"}
    except Exception as e:
        return {"status": "failed", "reason": f"callback error: {type(e).__name__}: {e}"}

    signature_b64 = response_data.get("signature")
    if not signature_b64:
        return {"status": "failed", "reason": "callback response missing 'signature' field"}

    canonical_bytes = json.dumps(challenge_payload, separators=(",", ":"), sort_keys=True).encode("utf-8")

    try:
        sig_padded = signature_b64 + "=" * (-len(signature_b64) % 4)
        signature = base64.urlsafe_b64decode(sig_padded)
    except Exception as e:
        return {"status": "failed", "reason": f"signature decode error: {e}"}

    x_b64 = declared_jwk.get("x", "")
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        from cryptography.exceptions import InvalidSignature
        x_padded = x_b64 + "=" * (-len(x_b64) % 4)
        pub_bytes = base64.urlsafe_b64decode(x_padded)
        pub_key = Ed25519PublicKey.from_public_bytes(pub_bytes)
        pub_key.verify(signature, canonical_bytes)
        return {"status": "verified", "reason": "signed challenge response verified"}
    except InvalidSignature:
        return {"status": "failed", "reason": "signature does not verify against the registered public key"}
    except Exception as e:
        return {"status": "failed", "reason": f"verification error: {e}"}
