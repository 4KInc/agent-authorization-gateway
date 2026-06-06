# Agent Authorization Gateway

An open protocol and reference implementation for cryptographic proof of every AI agent action.

**Google for Startups AI Agents Challenge — Track 1: Build (Net-New Agents)**

## The Problem

AI agents are the fastest-growing category of Non-Human Identity (NHI). OWASP's NHI Top 10 identifies overprivileged NHIs and long-lived secrets as critical risks. Today, when an agent calls a cloud API, accesses a database, or invokes a tool:

- No policy evaluation before the action executes
- No cryptographic proof that authorization occurred
- No tamper-evident audit trail independent of the agent itself
- No way to revoke access if the agent drifts from its intent

If an agent is compromised or hallucinates a dangerous action, existing frameworks have no enforcement boundary — the agent's credentials work regardless.

## What's Different

| Dimension | Typical agent auth | This project |
|-----------|-------------------|--------------|
| **Enforcement** | Advisory — policy returns a decision, nothing prevents bypass | Mandatory — no Ed25519 token = resource rejects the request |
| **Audit trail** | Append-only logs (mutable by operator) | Ed25519-signed receipts, hash-chained, Merkle-anchored to Base L2 mainnet |
| **Token model** | Long-lived API keys or OAuth tokens | 60-second, single-use, action-bound Ed25519 JWTs |
| **Agent identity** | Self-declared agent_id string | DPoP-style proof of possession (challenge-response + Ed25519 keypair per agent) |
| **Verification** | Trust the auth server | Anyone with the public key can verify independently |
| **Multi-agent** | Single enforcement point | 6-agent system: enforce, audit, recommend, investigate, coordinate, isolate |

### vs. Related Projects

| | Agent Authorization Gateway | [agentgateway](https://github.com/agentgateway/agentgateway) | [better-auth agent-auth](https://github.com/better-auth/agent-auth-protocol) |
|---|---|---|---|
| Per-action signed receipts | Yes (Ed25519) | No | No |
| Hash-chained audit trail | Yes | No | No |
| Merkle anchoring | Yes (Base L2 mainnet) | No | No |
| Independent verification | Yes (public key only) | No | No |
| Token format | Ed25519 JWT (60s, action-bound) | — | Bearer token |
| Agent identity binding | DPoP-style proof of possession | — | — |
| Open protocol spec | Yes ([docs/protocol.md](docs/protocol.md)) | No | Draft |

## Architecture

[![Architecture Diagram](docs/architecture.svg)](docs/architecture.svg)

> Note: The SVG diagram above reflects an earlier state of the system (3 Cloud Run services). The current deployment has 11+ services and 6 agents; the diagram may need regeneration.

```
                          MCP / REST / A2A
 ┌─────────────────┐    (+ DPoP proof)     ┌──────────────────────────────────────┐
 │  Worker Agent   │ ─────────────────────>│  Gateway (Deterministic — no LLM     │
 │  (ADK/LangChain │  1. challenge-response │  in trust path)                      │
 │   /CrewAI/any)  │     registration       │                                      │
 │                 │  2. sign DPoP proof    │  Agent Registry  (PoP, Firestore)    │
 │  Ed25519 keypair│  3. declare intent     │  Policy Engine   (YAML/Firestore)    │
 │  per agent      │ <─────────────────── │  Receipt Signer  (Ed25519 + chain)   │
 │                 │  4. Ed25519 token      │  Token Issuer    (60s, single-use)   │
 └────────┬────────┘     + signed receipt  │  Action Registry (Firestore)         │
          │               (token_jti bound) │  Resource Registry (Firestore)       │
          │  5. use token                   │  Anchor Scheduler (Base L2, async)   │
          v                                └─────────────┬────────────────────────┘
 ┌─────────────────┐                                     │
 │ Protected       │  verify Ed25519 sig,                │ signed receipts
 │ Resource        │  action_digest, JTI                 v
 │                 │  replay, expiry       ┌─────────────────────────────────────┐
 └─────────────────┘                       │ AI Agent Cluster (Gemini 2.5 Pro)   │
                                           │                                     │
                                           │  Auditor     RAG over compliance    │
                                           │              PDFs (OWASP, NIST)     │
                                           │  Recommender pattern analysis +     │
                                           │              policy proposals        │
                                           │  Investigator incident reports +    │
                                           │              timeline synthesis      │
                                           │  Coordinator A2A discovery +        │
                                           │              capability routing      │
                                           │  Isolator    automated containment  │
                                           │              (HIGH/CRITICAL only)   │
                                           └─────────────────────────────────────┘

 Cloud Run Services (10 total):
 ┌──────────────┐ ┌──────────────┐ ┌──────────────┐ ┌──────────────┐ ┌──────────────┐
 │ REST API     │ │ MCP Server   │ │ ADK Chat     │ │ A2A Gateway  │ │ Resource     │
 │ (/docs)      │ │ (30 tools)   │ │ (read-only   │ │              │ │              │
 │              │ │              │ │  blast radius│ │              │ │              │
 └──────────────┘ └──────────────┘ └──────────────┘ └──────────────┘ └──────────────┘
 ┌──────────────┐ ┌──────────────┐ ┌──────────────┐ ┌──────────────┐ ┌──────────────┐
 │ Auditor      │ │ Recommender  │ │ Investigator │ │ Coordinator  │ │ Demo UI      │
 └──────────────┘ └──────────────┘ └──────────────┘ └──────────────┘ └──────────────┘
```

> **Note:** Gemini/ADK provides the conversational and analytical surfaces (Auditor, Recommender, Investigator, Coordinator, Isolator); policy evaluation, receipt signing, and token issuance are deterministic and run independent of the model.

## Six Agents

| Agent | Role | LLM in trust path? |
|-------|------|--------------------|
| **Gateway** | Policy enforcement, token issuance, receipt signing, Merkle anchoring | No — deterministic Python |
| **Auditor** | RAG compliance audit over OWASP NHI Top 10, NIST AI RMF, NIST SP 800-53 | Yes — Gemini 2.5 Pro |
| **Recommender** | Pattern analysis across audit history, policy change proposals | Yes — Gemini 2.5 Pro |
| **Investigator** | Evidence gathering, incident report synthesis with timeline | Yes — Gemini 2.5 Pro |
| **Coordinator** | A2A agent discovery, capability routing across the agent directory | Yes — Gemini 2.5 Pro |
| **Isolator** | Automated containment on HIGH/CRITICAL incidents (revoke, rate-limit) | Yes — Gemini 2.5 Pro |

The Isolator is the only agent that takes automated enforcement actions. All other AI agents produce signed reports for human review.

## Three Protocol Surfaces

| Surface | Description |
|---------|-------------|
| **REST** | OpenAPI (Swagger at `/docs`). Primary surface for registration, authorization, and chain inspection. |
| **MCP** | 30 tools namespaced as `gateway_*`, `auditor_*`, `recommender_*`, `investigator_*`, `coordinator_*`, `actions_*`, `resources_*`, `agents_*`. Compatible with ADK, LangChain, CrewAI, and any MCP client. |
| **A2A** | A2A agent cards at `/.well-known/agent-card.json` on each service. Coordinator maintains a directory of 5 live Gate agents + 3 synthetic demo agents. |

## The Receipt Chain Verification Protocol

Every authorization decision produces a signed receipt:

```json
{
  "body": {
    "v": "1", "tenant": "hackathon-demo", "seq": "4",
    "ts": "2026-05-28T00:23:52Z",
    "request_digest": "sha256:ff39ad...",
    "policy_version": "sha256:d59a1e...",
    "decision": "approve", "reasons": [],
    "prev_receipt": "sha256:c8e4bb...",
    "token_jti": "1b77f364-..."
  },
  "sig": { "alg": "EdDSA", "kid": "gateway-...", "value": "HIEMRy..." },
  "receipt_hash": "sha256:89ff1e..."
}
```

Each receipt links to the previous via `prev_receipt`, forming an unbroken hash chain from genesis. Receipts are batched into a Merkle tree (RFC 6962) and anchored to Base L2 mainnet (chain ID 8453) via a background scheduler — every 10 receipts or 1 hour, whichever comes first.

**First anchor tx:** [`0xee723953...`](https://basescan.org/tx/0xee723953b317846af8cc1654ce493975730da8e5ffcbdb07de9c5806e8ad21d1) — Block 46641063, Base mainnet.

Anyone can verify an anchor without trusting the gateway:

```python
from web3 import Web3
w3 = Web3(Web3.HTTPProvider("https://mainnet.base.org"))
tx = w3.eth.get_transaction("0x<tx_hash>")
assert tx.input.hex()[2:] == "<merkle_root_hex>"
```

Full specification: [docs/protocol.md](docs/protocol.md)

## Agent Registration (Proof of Possession)

Registration requires a challenge-response flow — the agent must prove it holds the private key before the gateway records the public key:

```
1. POST /agents/register-challenge  →  { "challenge": "<nonce>", "challenge_id": "..." }
2. Sign challenge with agent's Ed25519 private key
3. POST /agents/register  →  { "agent_id": "...", "kid": "agent-..." }
```

Self-declared agent IDs without proof of possession are rejected.

## Quick Start

```bash
git clone https://github.com/4KInc/agent-authorization-gateway.git
cd agent-authorization-gateway
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
cp .env.example .env  # add GOOGLE_API_KEY for AI agents
```

### Run locally

```bash
python serve.py           # REST API → http://localhost:8080/docs

# MCP server requires transport auth (bearer token or IAM)
export MCP_AUTH_MODE=bearer
export MCP_AUTH_TOKEN=$(python -c "import secrets; print(secrets.token_urlsafe(32))")
python serve_mcp.py       # MCP server → http://localhost:8090/mcp

adk web authorization_gateway  # ADK chat → http://localhost:8000
```

> **Note:** The MCP server requires authentication. `GET /keys` on the REST API is the only anonymous endpoint. All MCP tools require a valid `Authorization: Bearer <token>` header, and `gateway_authorize_action` additionally requires a DPoP agent identity proof. See [SECURITY.md](SECURITY.md).

### Run tests

```bash
pytest tests/ -v   # 309 tests
```

### Run the full demo

```bash
./examples/demo/run_demo.sh   # Gateway + Resource + Compliant Worker + Rogue Worker + Tamper Demo
```

### Deploy to Cloud Run

#### Set up the shared signing key (one-time per project)

All gateway services load a single Ed25519 signing key from Secret Manager at startup. Create it once per GCP project:

```bash
python -c "
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization
import json, secrets
k = Ed25519PrivateKey.generate()
pem = k.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption()
).decode()
kid = 'gateway-' + secrets.token_hex(4)
print(json.dumps({'kid': kid, 'private_pem': pem}))
" > /tmp/signing-key.json

gcloud secrets create gateway-signing-key --replication-policy=automatic
gcloud secrets versions add gateway-signing-key --data-file=/tmp/signing-key.json
rm /tmp/signing-key.json   # delete after upload

gcloud secrets add-iam-policy-binding gateway-signing-key \
  --member="serviceAccount:<runtime-sa>" \
  --role="roles/secretmanager.secretAccessor"
```

See [SECURITY.md](SECURITY.md) for the full key architecture rationale.

#### Deploy the services

```bash
gcloud builds submit --tag us-central1-docker.pkg.dev/PROJECT/repo/image:latest

# REST API (/keys is anonymous; /authorize requires DPoP proof)
gcloud run deploy agent-auth-gateway --image ... --allow-unauthenticated \
  --set-env-vars="FIRESTORE_ENABLED=true,GOOGLE_CLOUD_PROJECT=PROJECT,ANCHOR_TO_BASE=true"

# MCP server (transport auth via Secret Manager — recommended)
# First, store the token in Secret Manager (one-time):
#   MCP_TOKEN=$(python -c "import secrets; print(secrets.token_urlsafe(32))")
#   echo -n "$MCP_TOKEN" | gcloud secrets create mcp-auth-token --data-file=-
gcloud run deploy agent-auth-gateway-mcp --image ... --allow-unauthenticated \
  --set-env-vars="FIRESTORE_ENABLED=true,GOOGLE_CLOUD_PROJECT=PROJECT,MCP_AUTH_MODE=bearer" \
  --set-secrets="MCP_AUTH_TOKEN=mcp-auth-token:latest"
```

> **Security note:** Use `--set-secrets` (not `--set-env-vars`) for `MCP_AUTH_TOKEN` so the value is not visible in Cloud Run revision metadata. Use `MCP_AUTH_MODE=iam` with `--no-allow-unauthenticated` for production MCP deployments. The REST API's `/authorize` endpoint enforces DPoP proof at the application layer regardless of Cloud Run IAM settings.

## Demo

The demo proves three things:

1. **Compliant Worker:** Registers identity (challenge-response) → authorizes via MCP → uses token → action succeeds → token replay blocked
2. **Rogue Worker:** 4+ attacks (no token, invalid signature, expired token, wrong-action token) → all blocked with specific error codes
3. **Tamper Detection:** Modify a stored receipt → chain verification detects the exact receipt and field

Run `./examples/demo/run_demo.sh` to see the full demo locally.

## Live URLs

| Service | URL |
|---------|-----|
| **Interactive Demo UI** | **https://agent-auth-demo-ui-1031148889398.us-central1.run.app** |
| REST API (Swagger at /docs) | https://agent-auth-gateway-1031148889398.us-central1.run.app |
| MCP Server | https://agent-auth-gateway-mcp-1031148889398.us-central1.run.app/mcp |
| ADK Chat Agent | https://agent-auth-gateway-adk-1031148889398.us-central1.run.app |
| A2A Gateway | https://agent-auth-gateway-a2a-1031148889398.us-central1.run.app |
| Auditor | https://agent-auth-gateway-auditor-1031148889398.us-central1.run.app |
| Recommender | https://agent-auth-gateway-recommender-1031148889398.us-central1.run.app |
| Investigator | https://agent-auth-investigator-1031148889398.us-central1.run.app |
| Coordinator | https://agent-auth-gateway-coordinator-1031148889398.us-central1.run.app |
| Protected Resource | https://agent-auth-gateway-resource-1031148889398.us-central1.run.app |

> **MCP auth:** The MCP server requires `Authorization: Bearer <token>`. A demo bearer token is shared with the submission; production deployments use `MCP_AUTH_MODE=iam` with Cloud Run IAM. See [SECURITY.md](SECURITY.md).

## Positioning Against Adjacent Products

The "AI agent governance" space is new enough that the comparison terrain is not yet settled. Several established product categories have surface similarities to Gate but address fundamentally different problems.

### vs Auth0, Okta, and traditional identity providers

Auth0, Okta, and similar identity providers solve human authentication and human-to-application authorization. Their domain is users logging in to applications, the SSO flow, the OAuth dance, multi-factor enrollment, and the lifecycle of human identities.

Gate is in a different domain. It does not authenticate humans. It does not manage SSO. It does not issue session tokens for web applications. What Gate does is produce cryptographic evidence of authorization decisions made about AI agent actions: did this agent attempt to perform this action on this resource, was the attempt approved or denied, and what is the signed proof of that decision.

The two categories are complementary, not competitive. A typical deployment has Okta handling who can access the operator dashboard for Gate itself, and Gate handling what AI agents are authorized to do through the deployed system.

### vs Vanta, Drata, and compliance automation platforms

Vanta and Drata automate the gathering and presentation of evidence that controls exist and are operating: SOC 2 Type II evidence, ISO 27001 control attestation, HIPAA technical safeguards. They prove that a control was implemented.

Gate proves something different. Gate proves that a specific decision happened at a specific moment by a specific deterministic policy engine. The output is not "we have an access control policy" but rather "this exact request was denied at 14:32 UTC on this date, here is the Ed25519 signature, here are the NIST and OWASP citations the audit pipeline produced for that decision, and the entire chain is hash-linked back to genesis."

The two are complementary in production. A regulated enterprise running both gets Vanta proving controls exist and Gate proving decisions happened.

### vs Aembit, SPIFFE, and workload identity systems

Aembit and SPIFFE/SPIRE establish cryptographic identity for workloads: this microservice is verifiably this thing, here is its short-lived credential, here is the policy for service-to-service trust. Gate's DPoP proof of possession mechanism is in the same family of primitives, but Gate's primary contribution is not workload identity issuance — it is decision evidence for AI agent actions specifically.

AI agents are different from long-running services: they make decisions through non-deterministic reasoning, they invoke variable tools across sessions, and their action history is itself the thing regulators want to audit. Gate is built for that audit story. A serious enterprise deployment could run Aembit for service-to-service trust and Gate for agent action accountability.

### vs model-level safety work (Anthropic, OpenAI, others)

Frontier model laboratories invest in training-time safety: constitutional AI, RLHF, refusal training, red-teaming. This produces models that are less likely to take harmful actions when given the choice.

Gate operates one layer down. Even well-aligned models can be invoked through ambiguous tool calls, can be prompt-injected through poisoned inputs, and can act in ways their operators did not anticipate. Authorization at the infrastructure layer is a defense in depth that does not depend on the model's training being perfect. The Gateway is deterministic. The policy is code. The receipts are signed.

Model-level safety reduces the probability of harmful intent. Infrastructure-level enforcement reduces the consequences when intent is wrong. Both are needed.

## Build vs Buy

Every engineering leader considering Gate asks whether to just build it internally.

### The substrate that is "easy" to build

A team comfortable with cryptographic primitives can produce in roughly 2-4 engineering-weeks: an Ed25519 signing service, a hash-chained append-only log of decisions, a JCS canonicalization helper, a DPoP proof verification module, and basic policy evaluation against an allowlist. These are well-documented primitives.

### The infrastructure that is harder

Where most internal builds stall: the signed-artifact pipeline beyond authorization decisions. Producing audit reports against compliance frameworks (NIST, OWASP, ISO) requires a RAG corpus, prompt engineering that avoids hallucination, retrieval that produces verbatim citations not paraphrased summaries, and a non-deterministic-model failure mode that is acceptable to auditors. This requires roughly 2-3 months of focused work and ongoing investment to keep the corpus current.

Multi-agent coordination through A2A and MCP protocols, with consistent signing identities, proper kid management, and a unified tool surface, is another 1-2 months for someone who already knows MCP.

### The operational and compliance investment

The audit-ready story requires more than code. Customer-facing deployment documentation, SOC 2 control mappings, compliance corpus maintenance, vulnerability disclosure processes, independent security audits, and ongoing standards-tracking are continuous investments. A realistic internal build of a comparable system requires a dedicated team of 2-4 engineers for 6-9 months to reach feature parity with Gate's v0.5.

### When building makes sense

Building internally is the right choice when the authorization domain is highly specialized, the compliance frameworks of interest are niche enough that no commercial offering will cover them, or the cryptographic accountability layer is itself the product.

### When buying makes sense

Buying makes sense when the company's AI agent deployment is one component of a larger product, standard compliance frameworks cover the audit requirements, time-to-deployment matters more than perfect fit, or the team is small enough that 2-4 engineers on a 6-9 month build represents a meaningful opportunity cost.

## Open Protocol, Commercial Deployment

Gate's protocol is fully documented and unencumbered. The receipt format, the DPoP proof structure, the agent registration challenge-response, the A2A card extensions, and the live challenge verification are all specified in this repository. Anyone can implement a compatible client or server.

The reference implementation in this repository is licensed Apache-2.0. The signing key formats are standard JWK. The cryptographic primitives are Ed25519 and SHA-256. No proprietary algorithms, no required dependency on BlockIntel-hosted infrastructure, no token-redemption service to call out to.

What BlockIntel offers commercially is the deployed system, the maintained compliance corpus, the operational support, and the ongoing engineering investment in the v0.6 and v1.0 roadmap items. Customers who prefer to self-host can do so under Apache-2.0; customers who prefer a managed deployment work with BlockIntel directly. The protocol stays open regardless.

## Security Model

See [SECURITY.md](SECURITY.md) for the full threat model, including:
- Threats the Gateway defends against
- Threats it explicitly does NOT defend against
- Trust assumptions for tamper-evidence
- LLM blast radius containment (chat agent has read-only tools; enforcement is deterministic)
- Cryptographic choices table

## Documentation

| Document | Description |
|----------|-------------|
| [SECURITY.md](SECURITY.md) | Threat model and security boundaries |
| [docs/protocol.md](docs/protocol.md) | Receipt Chain Verification Protocol v0.5 (incl. on-chain anchoring, PoP registration) |
| [docs/policy.md](docs/policy.md) | Policy engine: rule types, YAML/Firestore loading, examples |
| [docs/system-guide.md](docs/system-guide.md) | Comprehensive system guide: onboarding, policy, resources, multi-agent ecosystem |
| [docs/marketplace/ARCHITECTURE.md](docs/marketplace/ARCHITECTURE.md) | Architecture deep-dive: 6 agents, 11 services, data flow, persistence |
| [docs/marketplace/A2A_INTENTS.md](docs/marketplace/A2A_INTENTS.md) | A2A protocol intents: skills, schemas, authentication across all agents |
| [docs/marketplace/MCP_TOOLS.md](docs/marketplace/MCP_TOOLS.md) | MCP tool reference: 30 tools with input/output schemas |
| [NAMING.md](NAMING.md) | Disambiguation from agentgateway project |

## Built With

- [Google ADK](https://github.com/google/adk-python) 2.1 — multi-agent orchestration (Auditor, Recommender, Investigator, Coordinator, Isolator)
- [Gemini 2.5 Pro](https://ai.google.dev/) — agent reasoning + RAG (not in the authorization trust path)
- [MCP](https://modelcontextprotocol.io/) — framework-agnostic tool integration (30 tools)
- [A2A](https://google.github.io/A2A/) — agent-to-agent discovery and capability routing
- [Cloud Run](https://cloud.google.com/run) — serverless deployment (11 services)
- [Cloud Firestore](https://cloud.google.com/firestore) — receipt chain, agent registry, action/resource registry persistence
- [Base L2](https://base.org/) — on-chain Merkle root anchoring (mainnet, chain ID 8453)
- Ed25519 / SHA-256 / RFC 8785 / RFC 6962 — cryptographic foundations

## License

Apache-2.0
