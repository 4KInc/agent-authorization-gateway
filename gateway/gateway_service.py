"""Core gateway service — orchestrates policy evaluation, receipt signing, and token issuance.

This is the main entry point that the ADK agent tool calls.

SECURITY: DPoP identity verification is enforced HERE, in the single
chokepoint. All surfaces (MCP, REST, ADK) call this method; none of
them can bypass proof verification.
"""

from __future__ import annotations

import base64
import hashlib
import logging
import os
import secrets
from dataclasses import dataclass

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .canonical import canonicalize
from .identity import AgentRegistry, verify_agent_proof
from .merkle import compute_batch_root
from .policy import EvaluationResult, Policy, PolicyEngine, create_demo_policy, get_active_policy
from .receipts import Receipt, ReceiptChain
from .resources import ResourceRegistry
from .tokens import compute_action_digest, issue_token

logger = logging.getLogger("gateway.service")


@dataclass
class AuthorizationResponse:
    """Response from the gateway for an authorization request."""
    decision: str
    reason_codes: list[str]
    token: str | None
    receipt: dict
    action_digest: str
    receipt_hash: str


class GatewayService:
    """Agent Authorization Gateway — core service.

    Evaluates agent action intents against a security policy,
    signs cryptographic receipts for every decision, and issues
    scoped authorization tokens for approved actions.

    Tokens are signed with Ed25519 (EdDSA) — resources verify using
    only the public key. No shared secrets.

    SECURITY: authorize() requires a valid DPoP proof from a registered
    agent. Absence of proof is a hard rejection (NO_PROOF).
    """

    def __init__(
        self,
        tenant: str = "default",
        policy: Policy | None = None,
        registry: AgentRegistry | None = None,
        resource_registry: ResourceRegistry | None = None,
        private_key: Ed25519PrivateKey | None = None,
        kid: str | None = None,
    ):
        self.tenant = tenant
        self.policy = policy or get_active_policy()
        self._policy_engine = PolicyEngine(self.policy)
        self._resource_registry = resource_registry or ResourceRegistry(tenant_id=tenant)
        if registry:
            self._registry = registry
        else:
            firestore_db = None
            if os.environ.get("FIRESTORE_ENABLED", "").lower() == "true":
                try:
                    from google.cloud import firestore as _fs
                    firestore_db = _fs.Client(project=os.environ.get("GOOGLE_CLOUD_PROJECT"))
                except Exception:
                    pass
            self._registry = AgentRegistry(tenant=tenant, firestore_db=firestore_db)

        # Signing keypair: prefer explicitly provided (from Secret Manager),
        # fall back to loading from signing_key module, final fallback to
        # ephemeral generation (tests only).
        if private_key and kid:
            self._private_key = private_key
            self._kid = kid
        else:
            try:
                from .signing_key import load_signing_key
                self._kid, self._private_key = load_signing_key()
            except Exception:
                # Tests may not have Secret Manager configured
                self._private_key = Ed25519PrivateKey.generate()
                self._kid = f"gateway-{tenant}-{secrets.token_hex(4)}"
                logger.warning(f"Using ephemeral signing key (kid={self._kid}) — tests only")

        # Receipt chain
        self._receipt_chain = ReceiptChain(
            tenant=tenant,
            private_key=self._private_key,
            kid=self._kid,
        )

    def authorize(
        self,
        agent_id: str,
        action: str,
        resource: str,
        agent_proof: str,
        parameters: dict | None = None,
        delegation_context: dict | None = None,
    ) -> AuthorizationResponse:
        """Evaluate an agent's intended action and return an authorization decision.

        SECURITY: agent_proof is REQUIRED. Calls without a valid DPoP proof
        are rejected before policy evaluation or token issuance.

        This is the primary entry point. For every call:
        0. Verifies DPoP agent identity proof (MANDATORY)
        1. Computes action digest (SHA-256 of canonicalized intent)
        2. Evaluates intent against policy rules
        3. If approved, generates a token jti
        4. Signs a cryptographic receipt (includes token jti for approve, null for deny)
        5. Issues a 60-second Ed25519-signed token (approvals only)
        6. Returns the decision, receipt, and token

        Raises ValueError with specific code on proof failure:
        - NO_PROOF: no agent_proof provided
        - UNREGISTERED_AGENT: agent not in registry
        - INVALID_PROOF_SIGNATURE: proof signed with wrong key
        - PROOF_EXPIRED: proof older than 30 seconds
        - PROOF_REPLAY: proof JTI already used
        - PROOF_ACTION_MISMATCH: proof action != request action
        - PROOF_RESOURCE_MISMATCH: proof resource != request resource
        - PROOF_DIGEST_MISMATCH: proof action_digest != computed digest
        """
        # Step 0: MANDATORY DPoP identity verification
        if not agent_proof:
            raise ValueError("NO_PROOF: agent_proof is required for every authorization request")

        # Compute action digest early so we can verify proof binding
        action_digest = compute_action_digest(agent_id, action, resource, parameters)

        # Verify proof (raises ValueError with specific code on failure)
        verified_agent = verify_agent_proof(
            proof=agent_proof,
            registry=self._registry,
            expected_agent_id=agent_id,
            expected_action=action,
            expected_resource=resource,
            expected_action_digest=action_digest,
        )
        logger.info(f"DPoP verified: agent={verified_agent.agent_id} kid={verified_agent.kid}")

        # Step 1a: Check resource registration (if strict mode)
        resource_registration_id = None
        if self._resource_registry.is_registered_and_active(resource):
            resource_registration_id = resource

        if self.policy.require_resource_registration and resource_registration_id is None:
            # Strict mode: unregistered resource is denied before policy evaluation
            import uuid
            receipt = self._receipt_chain.sign_decision(
                request_digest=action_digest,
                policy_version=self.policy.policy_hash(),
                decision="deny",
                reasons=["RESOURCE_NOT_REGISTERED"],
                resource_registration_id=None,
                delegation_context=delegation_context,
            )
            return AuthorizationResponse(
                decision="deny",
                reason_codes=["RESOURCE_NOT_REGISTERED"],
                token=None,
                receipt=receipt.envelope_dict(),
                action_digest=action_digest,
                receipt_hash=receipt.receipt_hash,
            )

        # Step 1b: Evaluate policy
        result = self._policy_engine.evaluate(agent_id, action, resource, parameters)

        # Step 2: Generate token jti (single source of truth for approvals)
        import uuid
        token = None
        token_jti = str(uuid.uuid4()) if result.decision == "approve" else None

        # Step 3: Sign receipt (includes token_jti, resource_registration_id, and delegation_context binding)
        receipt = self._receipt_chain.sign_decision(
            request_digest=action_digest,
            policy_version=self.policy.policy_hash(),
            decision=result.decision,
            reasons=result.reason_codes,
            token_jti=token_jti,
            resource_registration_id=resource_registration_id,
            delegation_context=delegation_context,
        )

        # Step 4: Issue token once with the real receipt_hash and the same jti
        if result.decision == "approve":
            token, _ = issue_token(
                private_key=self._private_key,
                agent_id=agent_id,
                action=action,
                resource=resource,
                action_digest=action_digest,
                decision=result.decision,
                receipt_hash=receipt.receipt_hash,
                tenant=self.tenant,
                receipt_jti=token_jti,
            )

        return AuthorizationResponse(
            decision=result.decision,
            reason_codes=result.reason_codes,
            token=token,
            receipt=receipt.envelope_dict(),
            action_digest=action_digest,
            receipt_hash=receipt.receipt_hash,
        )

    def get_receipt_chain(self) -> list[dict]:
        """Return all receipts in the chain as dicts."""
        return [r.envelope_dict() for r in self._receipt_chain.get_receipts()]

    def get_merkle_root(self) -> str | None:
        """Compute and return the current Merkle batch root."""
        hashes = self._receipt_chain.get_receipt_hashes()
        if not hashes:
            return None
        return compute_batch_root(hashes)

    def get_chain_stats(self) -> dict:
        """Return chain statistics."""
        receipts = self._receipt_chain.get_receipts()
        approvals = sum(1 for r in receipts if r.decision == "approve")
        denials = sum(1 for r in receipts if r.decision == "deny")
        return {
            "tenant": self.tenant,
            "total_receipts": len(receipts),
            "approvals": approvals,
            "denials": denials,
            "merkle_root": self.get_merkle_root(),
            "policy_version": self.policy.policy_hash(),
        }

    def get_public_key_jwk(self) -> dict:
        """Return the signing public key as a JWK."""
        pub_bytes = self._private_key.public_key().public_bytes_raw()
        x_b64url = base64.urlsafe_b64encode(pub_bytes).rstrip(b"=").decode("ascii")
        return {
            "kty": "OKP",
            "crv": "Ed25519",
            "kid": self._kid,
            "use": "sig",
            "alg": "EdDSA",
            "x": x_b64url,
        }
