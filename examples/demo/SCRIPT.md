# Demo Script — 3 Minutes

Record with Loom or OBS. Share screen showing terminal + dashboard side-by-side.

## Scene 1: The Problem (30 seconds)

> "Today, when an AI agent accesses a cloud database or calls an API, it uses standing credentials with no policy check. If the agent is compromised or hallucinates a dangerous action, nothing stops it. There's no enforcement boundary and no audit trail."

Show: a simple `curl` to the Protected Resource with no token → 401 NO_TOKEN.

## Scene 2: The Gateway in Action (90 seconds)

> "The Agent Authorization Gateway adds cryptographic enforcement. Every action requires pre-execution policy evaluation and a short-lived Ed25519 token."

**Live demo steps:**

1. Show the dashboard at the Gateway URL. Point out: healthy status, policy rules visible.

2. **Authorize an approved action:** Click "Read DB" scenario → Authorize.
   - Show the green APPROVE banner with reason codes
   - Show the 60-second token was issued
   - Show the receipt hash and policy version

3. **Authorize a denied action:** Click "Rogue Delete" scenario → Authorize.
   - Show the red DENY banner
   - Show reason codes: ACTION_NOT_ALLOWED, RESOURCE_OUT_OF_SCOPE
   - Show no token was issued
   - Point out: "The denial itself is signed and recorded. The audit trail captures everything."

4. **Show the Audit Log:** Click Audit Log tab.
   - Show both decisions with timestamps, agents, actions, resources
   - Click "View" on a receipt to show the signed envelope

5. **Verify the chain:** Click Verify Chain → Verify Full Chain.
   - Show "Chain verified — N receipts checked, 0 failures"

## Scene 3: The Rogue Worker (45 seconds)

> "What happens when an agent tries to bypass the Gateway?"

Show terminal running `demo_rogue_worker.py` output (pre-recorded or live):

```
Attack                    Expected               Actual                 Status
No token                  401 NO_TOKEN            401 NO_TOKEN           BLOCKED
Self-forged token         401 INVALID_SIGNATURE   401 INVALID_SIGNATURE  BLOCKED
Expired token             401 EXPIRED             401 EXPIRED            BLOCKED
Wrong-action token        401 WRONG_ACTION        401 WRONG_ACTION       BLOCKED

Overall: ALL ATTACKS BLOCKED
```

> "Four different attack vectors. All blocked at the Protected Resource using only the Gateway's public key. No shared secrets needed."

## Scene 4: Business Case + Close (15 seconds)

> "The NHI market is $9.45 billion. OWASP just published the NHI Top 10. 42% of machine identities have privileged access. Every enterprise deploying AI agents needs an authorization boundary that produces cryptographic proof. That's what we built — with Google ADK, MCP, Gemini, and Cloud Run."

Show the architecture diagram briefly.
