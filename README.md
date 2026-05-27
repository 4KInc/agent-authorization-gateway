# Agent Authorization Gateway

Cryptographic policy enforcement for AI agent actions. Every privileged action gets a policy check and a tamper-evident receipt. No standing credentials. No blind trust.

**Google for Startups AI Agents Challenge — Track 1: Build**

## What It Does

When an AI agent attempts a privileged action (database query, API call, cloud resource access), the Gateway Agent:

1. Intercepts the action intent
2. Evaluates it against a security policy
3. Signs a cryptographic receipt (approve or deny)
4. Issues a 60-second scoped authorization token (if approved)
5. Links the receipt into a tamper-evident hash chain

## Quick Start

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"

# Run the demo (no API key needed)
python demo.py

# Run with ADK web UI (requires GOOGLE_API_KEY)
adk web main:agent
```

## Architecture

```
Worker Agent → authorize_action (MCP tool) → Gateway Agent
                                              ├── Policy evaluation
                                              ├── Receipt signing (Ed25519)
                                              ├── Token issuance (60s JWT)
                                              └── Merkle anchoring
```

## Built With

- Google ADK (Agent Development Kit)
- Gemini 2.0 Flash
- Receipt Chain Verification Protocol v0.1
- Ed25519 signatures, SHA-256 hash chains, RFC 6962 Merkle trees
- Cloud Run (deployment)

## License

Apache-2.0
