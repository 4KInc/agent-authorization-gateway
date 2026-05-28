"""Core gateway service — orchestrates policy evaluation, receipt signing, and token issuance.

This is the main entry point that the ADK agent tool calls.
"""

from __future__ import annotations

import base64
import hashlib
import os
import secrets
from dataclasses import dataclass

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .canonical import canonicalize
from .merkle import compute_batch_root
from .policy import EvaluationResult, Policy, PolicyEngine, create_demo_policy
from .receipts import Receipt, ReceiptChain
from .tokens import compute_action_digest, issue_token


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
    """

    def __init__(
        self,
        tenant: str = "default",
        policy: Policy | None = None,
    ):
        self.tenant = tenant
        self.policy = policy or create_demo_policy()
        self._policy_engine = PolicyEngine(self.policy)

        # Generate signing keypair (used for both receipts and tokens)
        self._private_key = Ed25519PrivateKey.generate()
        self._kid = f"gateway-{tenant}-{secrets.token_hex(4)}"

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
        parameters: dict | None = None,
    ) -> AuthorizationResponse:
        """Evaluate an agent's intended action and return an authorization decision.

        This is the primary entry point. For every call:
        1. Computes action digest (SHA-256 of canonicalized intent)
        2. Evaluates intent against policy rules
        3. If approved, generates a token jti
        4. Signs a cryptographic receipt (includes token jti for approve, null for deny)
        5. Issues a 60-second Ed25519-signed token (approvals only)
        6. Returns the decision, receipt, and token
        """
        # Step 1: Compute action digest
        action_digest = compute_action_digest(agent_id, action, resource, parameters)

        # Step 2: Evaluate policy
        result = self._policy_engine.evaluate(agent_id, action, resource, parameters)

        # Step 3: Issue token first to get jti (only for approvals)
        token = None
        token_jti = None
        if result.decision == "approve":
            token, token_jti = issue_token(
                private_key=self._private_key,
                agent_id=agent_id,
                action=action,
                resource=resource,
                action_digest=action_digest,
                decision=result.decision,
                receipt_hash="pending",  # will be updated
                tenant=self.tenant,
            )

        # Step 4: Sign receipt (includes token_jti binding)
        receipt = self._receipt_chain.sign_decision(
            request_digest=action_digest,
            policy_version=self.policy.policy_hash(),
            decision=result.decision,
            reasons=result.reason_codes,
            token_jti=token_jti,
        )

        # Step 5: Re-issue token with actual receipt_hash (now known)
        if result.decision == "approve":
            token, token_jti = issue_token(
                private_key=self._private_key,
                agent_id=agent_id,
                action=action,
                resource=resource,
                action_digest=action_digest,
                decision=result.decision,
                receipt_hash=receipt.receipt_hash,
                tenant=self.tenant,
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
