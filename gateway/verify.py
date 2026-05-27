"""Receipt verification — independent verification of receipt integrity.

Recomputes the canonical hash and verifies the Ed25519 signature
without access to the gateway's private key. Any auditor can use this.
"""

from __future__ import annotations

import base64
import hashlib
from dataclasses import dataclass, field

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .canonical import canonicalize

GENESIS_PREV_RECEIPT = "sha256:" + "0" * 64


@dataclass
class VerificationResult:
    receipt_integrity: str = "INCONCLUSIVE"  # PASS | FAIL | INCONCLUSIVE
    chain_validity: str = "INCONCLUSIVE"
    errors: list[dict] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "receipt_integrity": self.receipt_integrity,
            "chain_validity": self.chain_validity,
            "errors": self.errors,
        }


def verify_receipt(envelope: dict, public_key_jwk: dict) -> VerificationResult:
    """Verify a single receipt envelope against a public key.

    Checks:
    1. Receipt body canonicalizes correctly
    2. Receipt hash matches SHA-256 of canonical body
    3. Ed25519 signature is valid
    4. kid matches the provided key
    """
    result = VerificationResult()

    body = envelope.get("body")
    sig = envelope.get("sig")
    claimed_hash = envelope.get("receipt_hash")

    if not body or not sig:
        result.receipt_integrity = "FAIL"
        result.errors.append({"code": "MISSING_FIELDS", "message": "Envelope missing body or sig"})
        return result

    # Check kid match
    if sig.get("kid") != public_key_jwk.get("kid"):
        result.receipt_integrity = "FAIL"
        result.errors.append({
            "code": "KID_MISMATCH",
            "message": f"Receipt kid '{sig.get('kid')}' does not match key kid '{public_key_jwk.get('kid')}'",
        })
        return result

    # Check algorithm
    if sig.get("alg") != "EdDSA":
        result.receipt_integrity = "FAIL"
        result.errors.append({"code": "UNSUPPORTED_ALGORITHM", "message": f"Expected EdDSA, got {sig.get('alg')}"})
        return result

    # Canonicalize and hash
    try:
        body_bytes = canonicalize(body)
    except Exception as e:
        result.receipt_integrity = "FAIL"
        result.errors.append({"code": "CANONICALIZATION_FAILED", "message": str(e)})
        return result

    computed_hash = "sha256:" + hashlib.sha256(body_bytes).hexdigest()

    if claimed_hash and computed_hash != claimed_hash:
        result.receipt_integrity = "FAIL"
        result.errors.append({
            "code": "RECEIPT_HASH_MISMATCH",
            "message": f"Computed {computed_hash}, claimed {claimed_hash}",
        })
        return result

    # Verify Ed25519 signature
    try:
        x_bytes = _base64url_decode(public_key_jwk["x"])
        public_key = Ed25519PublicKey.from_public_bytes(x_bytes)
        sig_bytes = _base64url_decode(sig["value"])
        public_key.verify(sig_bytes, body_bytes)
    except InvalidSignature:
        result.receipt_integrity = "FAIL"
        result.errors.append({"code": "SIGNATURE_INVALID", "message": "Ed25519 signature verification failed"})
        return result
    except Exception as e:
        result.receipt_integrity = "FAIL"
        result.errors.append({"code": "SIGNATURE_ERROR", "message": str(e)})
        return result

    result.receipt_integrity = "PASS"
    return result


def verify_chain(envelopes: list[dict], public_key_jwk: dict) -> VerificationResult:
    """Verify a sequence of receipt envelopes.

    Checks everything verify_receipt checks, plus:
    1. Sequence numbers are monotonic and dense (1, 2, 3, ...)
    2. prev_receipt links are correct (hash chain integrity)
    3. First receipt points to genesis
    """
    result = VerificationResult()

    if not envelopes:
        result.receipt_integrity = "INCONCLUSIVE"
        result.chain_validity = "INCONCLUSIVE"
        result.errors.append({"code": "EMPTY_CHAIN", "message": "No receipts to verify"})
        return result

    expected_prev = GENESIS_PREV_RECEIPT
    expected_seq = 1

    for i, envelope in enumerate(envelopes):
        # Verify individual receipt
        single = verify_receipt(envelope, public_key_jwk)
        if single.receipt_integrity == "FAIL":
            result.receipt_integrity = "FAIL"
            result.errors.extend(single.errors)
            return result

        body = envelope["body"]

        # Check sequence
        actual_seq = int(body["seq"])
        if actual_seq != expected_seq:
            result.chain_validity = "FAIL"
            result.errors.append({
                "code": "SEQUENCE_GAP",
                "message": f"Expected seq {expected_seq}, got {actual_seq} at position {i}",
            })
            return result

        # Check prev_receipt link
        actual_prev = body["prev_receipt"]
        if actual_prev != expected_prev:
            result.chain_validity = "FAIL"
            result.errors.append({
                "code": "CHAIN_BREAK",
                "message": f"Receipt #{actual_seq} prev_receipt mismatch: expected {expected_prev[-16:]}, got {actual_prev[-16:]}",
            })
            return result

        # Advance
        expected_prev = envelope["receipt_hash"]
        expected_seq += 1

    result.receipt_integrity = "PASS"
    result.chain_validity = "PASS"
    return result


def _base64url_decode(s: str) -> bytes:
    s = s.replace("-", "+").replace("_", "/")
    padding = 4 - len(s) % 4
    if padding != 4:
        s += "=" * padding
    return base64.b64decode(s)
