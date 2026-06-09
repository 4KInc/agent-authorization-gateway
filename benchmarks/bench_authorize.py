"""Benchmark: authorize() hot-path latency.

Runs 1000 authorize() calls against an in-memory GatewayService
(no Firestore, no GCS, no HTTP) and reports p50/p95/p99/min/max/mean.

Usage:
    python -m benchmarks.bench_authorize
"""

from __future__ import annotations

import statistics
import time

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from gateway.gateway_service import GatewayService
from gateway.identity import AgentRegistry, create_agent_proof
from gateway.policy import Policy, PolicyRule
from gateway.tokens import compute_action_digest

ITERATIONS = 1000
AGENT_ID = "bench-agent"
ACTION = "read"
RESOURCE = "staging/benchmark-db"


def _setup() -> tuple[GatewayService, Ed25519PrivateKey]:
    """Create an in-memory GatewayService and register a test agent."""
    agent_key = Ed25519PrivateKey.generate()
    gateway_key = Ed25519PrivateKey.generate()

    registry = AgentRegistry(tenant="bench")

    # Build JWK from the agent's public key
    import base64
    pub_bytes = agent_key.public_key().public_bytes_raw()
    x_b64 = base64.urlsafe_b64encode(pub_bytes).rstrip(b"=").decode("ascii")
    jwk = {"kty": "OKP", "crv": "Ed25519", "x": x_b64}

    registry.register(AGENT_ID, jwk)

    # Policy with allowlist and resource scope but no rate limit,
    # so the benchmark can run 1000 iterations without throttling.
    policy = Policy(
        version="bench-1",
        rules=[
            PolicyRule(
                id="allowed_actions",
                type="allowlist",
                config={"allowed_actions": ["read", "query", "list"]},
            ),
            PolicyRule(
                id="resource_scope",
                type="resource_scope",
                config={
                    "allowed_resources": ["staging", "dev", "sandbox"],
                    "denied_resources": ["production", "prod"],
                },
            ),
        ],
    )

    svc = GatewayService(
        tenant="bench",
        policy=policy,
        registry=registry,
        private_key=gateway_key,
        kid="bench-gateway-key",
    )
    return svc, agent_key


def _run_benchmark(svc: GatewayService, agent_key: Ed25519PrivateKey) -> list[int]:
    """Run ITERATIONS authorize() calls, return list of latencies in nanoseconds."""
    latencies_ns: list[int] = []

    for _ in range(ITERATIONS):
        # Create a fresh DPoP proof for each call (as a real agent would)
        proof = create_agent_proof(
            private_key=agent_key,
            agent_id=AGENT_ID,
            action=ACTION,
            resource=RESOURCE,
        )

        t0 = time.perf_counter_ns()
        resp = svc.authorize(
            agent_id=AGENT_ID,
            action=ACTION,
            resource=RESOURCE,
            agent_proof=proof,
        )
        t1 = time.perf_counter_ns()

        assert resp.decision == "approve", f"unexpected decision: {resp.decision}"
        latencies_ns.append(t1 - t0)

    return latencies_ns


def _print_results(latencies_ns: list[int]) -> None:
    """Print a formatted table of latency statistics."""
    us = [ns / 1000.0 for ns in latencies_ns]
    us_sorted = sorted(us)

    def percentile(data: list[float], p: float) -> float:
        k = (len(data) - 1) * (p / 100.0)
        f = int(k)
        c = f + 1
        if c >= len(data):
            return data[f]
        return data[f] + (k - f) * (data[c] - data[f])

    p50 = percentile(us_sorted, 50)
    p95 = percentile(us_sorted, 95)
    p99 = percentile(us_sorted, 99)
    mn = us_sorted[0]
    mx = us_sorted[-1]
    avg = statistics.mean(us)

    print()
    print(f"  authorize() latency — {len(us)} iterations")
    print(f"  {'─' * 38}")
    print(f"  {'Metric':<12} {'Value':>12}  {'Unit'}")
    print(f"  {'─' * 38}")
    print(f"  {'min':<12} {mn:>12.1f}  us")
    print(f"  {'p50':<12} {p50:>12.1f}  us")
    print(f"  {'p95':<12} {p95:>12.1f}  us")
    print(f"  {'p99':<12} {p99:>12.1f}  us")
    print(f"  {'max':<12} {mx:>12.1f}  us")
    print(f"  {'mean':<12} {avg:>12.1f}  us")
    print(f"  {'─' * 38}")
    print()


def main() -> None:
    print("Setting up in-memory GatewayService ...")
    svc, agent_key = _setup()

    print(f"Running {ITERATIONS} authorize() calls ...")
    latencies = _run_benchmark(svc, agent_key)

    _print_results(latencies)


if __name__ == "__main__":
    main()
