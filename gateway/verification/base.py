"""Base class and registry for resource verifiers.

Verification statuses:
- "verified"      — live probe confirmed the resource exists
- "metadata_only" — caller provided metadata but no live probe was performed;
                     the gateway is recording what was declared, not confirming it
- "failed"        — live probe ran but the resource could not be reached
- "skipped"       — no reachability_url and no metadata provided
"""

from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass, field

logger = logging.getLogger("gateway.verification")


@dataclass
class VerificationResult:
    """Outcome of a resource existence verification probe."""

    status: str  # "verified", "metadata_only", "failed", "skipped"
    reason: str
    details: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        d = {"status": self.status, "reason": self.reason}
        if self.details:
            d["details"] = self.details
        return d


class ResourceVerifier(ABC):
    """Base class for type-specific resource verification.

    Each subclass knows how to probe one category of resource to confirm
    it exists and is reachable. Probes are read-only and non-destructive.

    Status semantics:
    - Return "verified" ONLY when a live probe succeeded (HTTP response,
      API call, etc.).
    - Return "metadata_only" when the caller provided descriptive metadata
      but no live probe was possible. This is honest: we recorded what
      was declared but did not confirm it.
    - Return "failed" when a live probe was attempted and failed.
    - Return "skipped" when nothing was provided at all.
    """

    @property
    @abstractmethod
    def resource_type(self) -> str:
        """The resource type string this verifier handles (e.g. 'db')."""

    @property
    @abstractmethod
    def required_metadata_fields(self) -> list[str]:
        """Metadata fields required for verification (empty = URL-only)."""

    @abstractmethod
    async def verify(self, reachability_url: str | None, metadata: dict | None) -> VerificationResult:
        """Probe the resource and return a VerificationResult."""


# ── Verifier registry ────────────────────────────────────────────────

_VERIFIERS: dict[str, ResourceVerifier] = {}


def register_verifier(verifier: ResourceVerifier) -> None:
    """Register a verifier instance for a resource type."""
    _VERIFIERS[verifier.resource_type] = verifier
    logger.debug("Registered verifier for resource type: %s", verifier.resource_type)


def get_verifier(resource_type: str) -> ResourceVerifier | None:
    """Look up the verifier for a resource type. Returns None if unknown."""
    return _VERIFIERS.get(resource_type)


def list_resource_types() -> list[str]:
    """Return all registered resource type strings."""
    return sorted(_VERIFIERS.keys())
