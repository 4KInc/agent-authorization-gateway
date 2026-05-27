"""Receipt signing and chain management.

Implements the Receipt Chain Verification Protocol v0.1:
- 7-field canonical JSON receipt body
- Ed25519 signature
- SHA-256 hash chain with prev_receipt linkage
"""

from __future__ import annotations

import hashlib
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from .canonical import canonicalize

GENESIS_PREV_RECEIPT = "sha256:" + "0" * 64


@dataclass
class Receipt:
    """An immutable signed decision receipt."""

    v: str
    tenant: str
    seq: str
    ts: str
    request_digest: str
    policy_version: str
    decision: str
    reasons: list[str]
    prev_receipt: str

    # Computed after signing
    receipt_hash: str = ""
    signature: str = ""
    kid: str = ""

    def body_dict(self) -> dict:
        return {
            "v": self.v,
            "tenant": self.tenant,
            "seq": self.seq,
            "ts": self.ts,
            "request_digest": self.request_digest,
            "policy_version": self.policy_version,
            "decision": self.decision,
            "reasons": self.reasons,
            "prev_receipt": self.prev_receipt,
        }

    def envelope_dict(self) -> dict:
        return {
            "body": self.body_dict(),
            "sig": {
                "alg": "EdDSA",
                "kid": self.kid,
                "value": self.signature,
            },
            "receipt_hash": self.receipt_hash,
        }


class ReceiptChain:
    """Manages a per-tenant receipt chain with signing."""

    def __init__(self, tenant: str, private_key: Ed25519PrivateKey, kid: str):
        self.tenant = tenant
        self._private_key = private_key
        self._kid = kid
        self._seq = 0
        self._prev_receipt_hash = GENESIS_PREV_RECEIPT
        self._receipts: list[Receipt] = []

    @property
    def public_key(self) -> Ed25519PublicKey:
        return self._private_key.public_key()

    def sign_decision(
        self,
        request_digest: str,
        policy_version: str,
        decision: str,
        reasons: list[str],
    ) -> Receipt:
        """Create and sign a new receipt, advancing the chain."""
        self._seq += 1
        ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.") + \
            f"{datetime.now(timezone.utc).microsecond // 1000:03d}Z"

        receipt = Receipt(
            v="1",
            tenant=self.tenant,
            seq=str(self._seq),
            ts=ts,
            request_digest=request_digest,
            policy_version=policy_version,
            decision=decision,
            reasons=reasons,
            prev_receipt=self._prev_receipt_hash,
        )

        # Canonicalize and hash
        body_bytes = canonicalize(receipt.body_dict())
        receipt_hash = "sha256:" + hashlib.sha256(body_bytes).hexdigest()
        receipt.receipt_hash = receipt_hash

        # Sign
        import base64
        sig_bytes = self._private_key.sign(body_bytes)
        receipt.signature = base64.urlsafe_b64encode(sig_bytes).rstrip(b"=").decode("ascii")
        receipt.kid = self._kid

        # Advance chain
        self._prev_receipt_hash = receipt_hash
        self._receipts.append(receipt)

        return receipt

    def get_receipts(self) -> list[Receipt]:
        return list(self._receipts)

    def get_receipt_hashes(self) -> list[str]:
        """Return receipt hashes in order (without sha256: prefix) for Merkle tree."""
        return [r.receipt_hash.removeprefix("sha256:") for r in self._receipts]
