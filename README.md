# Agent Authorization Gateway

Cryptographic policy enforcement for AI agent actions. Every privileged action gets a policy check and a tamper-evident receipt. No standing credentials. No blind trust.

**Google for Startups AI Agents Challenge — Track 1: Build (Net-New Agents)**

## The Problem

AI agents are the fastest-growing category of Non-Human Identity (NHI). When an agent calls a cloud API, accesses a database, or invokes a tool, there is:

- No policy evaluation before the action executes
- No cryptographic proof that authorization occurred
- No tamper-evident audit trail independent of the agent itself
- No way to revoke access mid-action if the agent drifts from its intent

## What It Does

The Agent Authorization Gateway sits between AI agents and privileged resources. For every action:

1. **Intercepts** the action intent (via MCP tool call)
2. **Evaluates** it against a configurable security policy
3. **Signs** a cryptographic receipt with Ed25519 (approve or deny)
4. **Issues** a 60-second scoped authorization token (if approved)
5. **Links** the receipt into a tamper-evident hash chain with Merkle anchoring

## Architecture

```
┌──────────────┐     MCP Tool Call      ┌───────────────────┐
│              │    (declared intent)    │                   │
│  Worker Agent│ ────────────────────>   │  Authorization    │
│  (ADK)       │                        │  Gateway Agent    │
│              │ <────────────────────  │  (Gemini + ADK)   │
│              │   60s scoped token     │                   │
└──────┬───────┘   + signed receipt     └─────────┬─────────┘
       │                                          │
       │  (uses scoped token)                     │
       v                                          v
┌──────────────┐                        ┌─────────────────┐
│  Protected   │                        │  Receipt Chain  │
│  Resource    │                        │  Store          │
│  (DB, API)   │                        │  (Firestore)    │
└──────────────┘                        └─────────────────┘
```

### Component Breakdown

| Component | Technology | Purpose |
|-----------|-----------|---------|
| Orchestrator | Google ADK | Routes between Worker and Gateway sub-agents |
| Gateway Agent | ADK + Gemini 2.5 Flash | Receives intents, evaluates policy, signs receipts |
| Worker Agent | ADK + MCP client | Declares intents, receives tokens, executes actions |
| Policy Engine | Python (deterministic) | Evaluates action against allowlist, resource scope, rate limits |
| Receipt Signer | Ed25519 (cryptography lib) | Signs 7-field canonical JSON receipts |
| Token Issuer | PyJWT (HS256) | Issues 60-second scoped tokens bound to action digest |
| MCP Server | FastMCP (mcp SDK) | Exposes gateway tools for any MCP-compatible agent |
| Receipt Store | Cloud Firestore | Persists receipt chain with hash linkage |
| Dashboard | FastAPI + HTML/JS | Interactive UI for authorization, verification, and audit |

## Quick Start

### Prerequisites

- Python 3.11+
- Google Cloud account (for Cloud Run deployment)
- `GOOGLE_API_KEY` for Gemini (ADK agent only)

### Local Setup

```bash
# Clone the repo
git clone https://github.com/heart1in/agent-authorization-gateway.git
cd agent-authorization-gateway

# Create virtual environment
python -m venv .venv
source .venv/bin/activate

# Install dependencies
pip install -e ".[dev]"

# Copy environment variables
cp .env.example .env
# Edit .env and add your GOOGLE_API_KEY
```

### Run Locally

```bash
# Option 1: REST API + Dashboard (no API key needed)
python serve.py
# Open http://localhost:8080

# Option 2: MCP Server (no API key needed)
python serve_mcp.py
# MCP endpoint at http://localhost:8090/mcp

# Option 3: ADK Chat Agent (requires GOOGLE_API_KEY)
adk web authorization_gateway
# Open http://localhost:8000

# Option 4: Run the demo script
python demo.py
```

### Run Tests

```bash
pytest tests/ -v
```

### Deploy to Cloud Run

```bash
# Build and push container
gcloud builds submit --tag us-central1-docker.pkg.dev/YOUR_PROJECT/agent-auth-gateway/agent-auth-gateway:latest

# Deploy REST API + Dashboard
gcloud run deploy agent-auth-gateway \
  --image us-central1-docker.pkg.dev/YOUR_PROJECT/agent-auth-gateway/agent-auth-gateway:latest \
  --region us-central1 --allow-unauthenticated \
  --set-env-vars="FIRESTORE_ENABLED=true,GOOGLE_CLOUD_PROJECT=YOUR_PROJECT"

# Deploy MCP Server
gcloud run deploy agent-auth-gateway-mcp \
  --image us-central1-docker.pkg.dev/YOUR_PROJECT/agent-auth-gateway/agent-auth-gateway:latest \
  --region us-central1 --allow-unauthenticated \
  --command="python" --args="serve_mcp.py" \
  --set-env-vars="FIRESTORE_ENABLED=true,GOOGLE_CLOUD_PROJECT=YOUR_PROJECT,FASTMCP_PORT=8080,FASTMCP_HOST=0.0.0.0"

# Deploy ADK Chat Agent
gcloud run deploy agent-auth-gateway-adk \
  --image us-central1-docker.pkg.dev/YOUR_PROJECT/agent-auth-gateway/agent-auth-gateway:latest \
  --region us-central1 --allow-unauthenticated \
  --command="python" --args="serve_adk.py" \
  --set-env-vars="FIRESTORE_ENABLED=true,GOOGLE_CLOUD_PROJECT=YOUR_PROJECT,GOOGLE_API_KEY=YOUR_KEY"
```

## Live Demo

| Service | URL |
|---------|-----|
| REST API + Dashboard | https://agent-auth-gateway-1031148889398.us-central1.run.app |
| ADK Chat Agent | https://agent-auth-gateway-adk-1031148889398.us-central1.run.app |

## API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/` | Interactive dashboard UI |
| `GET` | `/health` | Health check |
| `POST` | `/authorize` | Authorize an agent action |
| `POST` | `/verify-receipt` | Verify a single receipt signature |
| `POST` | `/verify-chain` | Verify full chain integrity |
| `GET` | `/chain` | Get the full receipt chain |
| `GET` | `/stats` | Chain statistics |
| `GET` | `/keys` | Public signing key (JWK) |
| `GET` | `/docs` | Swagger API documentation |

## MCP Tools

The gateway exposes these tools via MCP for any compatible agent:

| Tool | Description |
|------|-------------|
| `authorize_action` | Evaluate an action against security policy |
| `get_chain_stats` | Get receipt chain statistics |
| `get_receipt_chain` | Get full chain for audit |
| `get_public_key` | Get Ed25519 signing key (JWK) |
| `verify_receipt` | Verify a receipt's cryptographic integrity |

## How It's Different

- **Not just logging — enforcement.** No token = no action. The worker agent cannot bypass the Gateway.
- **Not just tokens — receipts.** Every decision is signed, hash-chained, and Merkle-anchored. The audit trail is cryptographically tamper-evident.
- **Framework-agnostic via MCP.** Any agent framework (ADK, LangChain, CrewAI) can use the Gateway as an MCP tool. No vendor lock-in.
- **Protocol, not just product.** The Receipt Chain Verification Protocol is an open specification with RFC references, designed for independent verification.

## Project Structure

```
agent-authorization-gateway/
├── gateway/                    # Core gateway package
│   ├── gateway_service.py      # Main service orchestrating policy + signing
│   ├── policy.py               # Policy evaluation engine (3 rule types)
│   ├── receipts.py             # Receipt signing and chain management
│   ├── verify.py               # Independent receipt verification
│   ├── canonical.py            # Deterministic JSON canonicalization
│   ├── merkle.py               # Merkle tree construction
│   ├── tokens.py               # JWT token issuance
│   ├── store.py                # Firestore + in-memory persistence
│   ├── api.py                  # FastAPI REST endpoints + dashboard
│   ├── mcp_server.py           # MCP server (FastMCP)
│   ├── agent.py                # ADK Gateway agent definition
│   ├── orchestrator.py         # ADK Orchestrator (multi-agent)
│   ├── dashboard.html          # Interactive dashboard UI
│   └── tools/
│       └── authorize_tool.py   # ADK FunctionTool wrappers
├── worker/                     # Worker agent package
│   ├── agent.py                # ADK Worker agent (MCP client)
│   └── tools.py                # Simulated data operations
├── authorization_gateway/      # ADK entry point
│   └── agent.py                # Exports root_agent for ADK
├── tests/                      # Test suite
│   └── test_gateway.py         # Comprehensive gateway tests
├── serve.py                    # REST API entry point
├── serve_adk.py                # ADK agent entry point
├── serve_mcp.py                # MCP server entry point
├── demo.py                     # Demo script
├── Dockerfile                  # Multi-mode container
└── pyproject.toml              # Dependencies
```

## Built With

- [Google ADK](https://github.com/google/adk-python) (Agent Development Kit) 2.1
- [Gemini 2.5 Flash](https://ai.google.dev/) — agent reasoning
- [MCP](https://modelcontextprotocol.io/) (Model Context Protocol) — tool integration
- [Cloud Run](https://cloud.google.com/run) — serverless deployment
- [Cloud Firestore](https://cloud.google.com/firestore) — receipt persistence
- Ed25519 signatures, SHA-256 hash chains, RFC 6962 Merkle trees
- Receipt Chain Verification Protocol v0.1

## License

Apache-2.0
