"""Resource verification — type-specific existence probes.

Each resource type has a verifier that knows how to confirm the resource
exists and is reachable. The registry dispatches to the correct verifier
based on the resource_type field.

Verifiers are non-destructive and read-only. They confirm existence,
never modify the target resource.
"""

from .base import ResourceVerifier, VerificationResult, get_verifier, list_resource_types

# Import type modules to trigger register_verifier() calls
from . import db  # noqa: F401
from . import api  # noqa: F401
from . import storage  # noqa: F401
from . import queue  # noqa: F401
from . import function  # noqa: F401

__all__ = ["ResourceVerifier", "VerificationResult", "get_verifier", "list_resource_types"]
