"""Startup self-check — verifies signing key consistency before serving traffic.

Called from each gateway service's ASGI lifespan after load_signing_key().
Catches kid drift, key corruption, and Secret Manager disagreements.

Hard failures are LOUD LOGGING, not crashes — failing startup would brick
cold starts on transient Secret Manager hiccups.
"""

from __future__ import annotations

import base64
import logging
import secrets

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

logger = logging.getLogger("gateway.startup_check")


def run_signing_key_self_check():
    """Sign a test payload and verify it against the published JWK.

    Proves: the loaded private key and the JWK from get_public_jwk() are
    the same keypair, with the same kid.
    """
    from .signing_key import load_signing_key, get_public_jwk

    try:
        kid, priv = load_signing_key()
    except Exception as e:
        logger.error("STARTUP SELF-CHECK FAILED: could not load signing key: %s", e)
        return

    jwk = get_public_jwk()
    if jwk["kid"] != kid:
        logger.error(
            "STARTUP SELF-CHECK FAILED: loaded kid=%s but get_public_jwk "
            "returned kid=%s — keys are out of sync", kid, jwk["kid"]
        )
        return

    # Reconstruct public key from the JWK and verify a test signature
    test_payload = secrets.token_bytes(32)
    signature = priv.sign(test_payload)

    x_b64 = jwk["x"]
    padding = 4 - len(x_b64) % 4
    if padding != 4:
        x_b64 += "=" * padding
    pub = Ed25519PublicKey.from_public_bytes(base64.urlsafe_b64decode(x_b64))

    try:
        pub.verify(signature, test_payload)
        logger.info(
            "STARTUP SELF-CHECK PASSED: kid=%s, sign+verify roundtrip OK.", kid
        )
    except Exception as e:
        logger.error(
            "STARTUP SELF-CHECK FAILED: signature verification roundtrip "
            "failed for kid=%s: %s", kid, e
        )


async def check_chain_kid_consistency(store, tenant: str, expected_kid: str):
    """Check latest receipt in chain matches the loaded kid.

    Warning (not crash) if the chain has receipts from a different key.
    After the Secret Manager migration + chain reset, this should never fire.
    """
    try:
        chain = await store.get_chain(tenant)
        if chain:
            last = chain[-1]
            last_kid = last.get("sig", {}).get("kid", "")
            if last_kid and last_kid != expected_kid:
                logger.warning(
                    "CHAIN KID WARNING: latest receipt (seq=%s) signed with "
                    "kid=%s but loaded key is kid=%s — chain contains receipts "
                    "from a different key.",
                    last.get("body", {}).get("seq", "?"), last_kid, expected_kid
                )
            elif chain:
                logger.info(
                    "Chain kid consistency OK: %d receipts, latest kid=%s matches loaded key.",
                    len(chain), expected_kid
                )
    except Exception as e:
        logger.warning("Chain kid check skipped: %s", e)
