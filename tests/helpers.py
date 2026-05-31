"""Shared test helpers for creating registered gateways and proofs."""

import base64

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from gateway.gateway_service import GatewayService
from gateway.identity import AgentRegistry, create_agent_proof


def make_jwk(private_key: Ed25519PrivateKey) -> dict:
    pub_bytes = private_key.public_key().public_bytes_raw()
    x = base64.urlsafe_b64encode(pub_bytes).rstrip(b"=").decode()
    return {"kty": "OKP", "crv": "Ed25519", "x": x}


def make_registered_gateway(
    tenant: str = "test-tenant",
    agent_id: str = "test-agent-01",
) -> tuple[GatewayService, Ed25519PrivateKey, str]:
    """Create a GatewayService with a pre-registered agent.

    Returns (gateway, agent_private_key, agent_id).
    """
    registry = AgentRegistry()
    agent_key = Ed25519PrivateKey.generate()
    jwk = make_jwk(agent_key)
    registry.register(agent_id, jwk)
    gw = GatewayService(tenant=tenant, registry=registry)
    return gw, agent_key, agent_id


def register_agent_with_pop(client, agent_id: str, private_key: Ed25519PrivateKey) -> dict:
    """Register an agent via the API with proof of possession."""
    import time as _time
    from gateway.identity import build_registration_message
    from gateway.api import _get_gateway

    jwk = make_jwk(private_key)
    tenant = _get_gateway().tenant

    ch_resp = client.post("/agents/register-challenge", json={"agent_id": agent_id})
    assert ch_resp.status_code == 200, f"Challenge failed: {ch_resp.text}"
    ch = ch_resp.json()

    iat = int(_time.time())
    message = build_registration_message(tenant, agent_id, jwk, ch["nonce"], ch["challenge_id"], iat)
    sig = private_key.sign(message)
    sig_b64 = base64.urlsafe_b64encode(sig).rstrip(b"=").decode()

    resp = client.post("/agents/register", json={
        "agent_id": agent_id,
        "public_key": jwk,
        "proof": {"nonce": ch["nonce"], "challenge_id": ch["challenge_id"], "signature": sig_b64, "iat": iat},
    })
    assert resp.status_code == 200, f"Register failed: {resp.text}"
    return resp.json()


def authorized_call(
    gw: GatewayService,
    agent_key: Ed25519PrivateKey,
    agent_id: str,
    action: str,
    resource: str,
    parameters: dict | None = None,
):
    """Call gw.authorize() with a valid DPoP proof. Convenience for tests."""
    proof = create_agent_proof(agent_key, agent_id, action, resource)
    return gw.authorize(
        agent_id=agent_id,
        action=action,
        resource=resource,
        parameters=parameters,
        agent_proof=proof,
    )
