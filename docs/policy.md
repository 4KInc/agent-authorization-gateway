# Policy Engine

The Agent Authorization Gateway uses a **deterministic Python policy engine** — no external dependencies, no IAM ramp-up, fully auditable.

## Why Deterministic Python (Not Cedar, OPA, or Rego)

| Concern | Our approach | Cedar/OPA/Rego |
|---------|-------------|----------------|
| **Auditability** | Policy logic is Python — readable by any developer, testable with pytest | Requires learning a DSL; harder to debug |
| **Performance** | In-process evaluation, ~0.1ms per decision | External process or sidecar, network overhead |
| **Dependencies** | Zero — standard library only | Requires runtime (Cedar agent, OPA sidecar) |
| **Receipt binding** | Policy hash is computed inline and embedded in every receipt | Would need a bridge to inject hash into receipt |
| **Correctness** | 101+ tests including edge cases | Depends on the quality of the external engine's test suite |

**Roadmap:** A `CedarPolicyEngine` implementation behind `POLICY_ENGINE=python|cedar` is planned for production. The three rule types below map cleanly to Cedar's `permit/forbid` with conditions.

## Rule Types

### 1. Action Allowlist (`type: "allowlist"`)

Controls which actions agents are permitted to perform.

```json
{
  "id": "allowed_actions",
  "type": "allowlist",
  "config": {
    "allowed_actions": ["read", "query", "list", "get", "search", "analyze"]
  }
}
```

**Behavior:** The action string is checked against each allowed action using **substring match** (case-insensitive). If the action contains any of the allowed strings, it passes. An empty `allowed_actions` list permits all actions.

**Examples:**
- `"read"` matches `"read"`, `"read_customer"`, `"read records"` → **PASS**
- `"delete"` with the above list → **FAIL** (`ACTION_NOT_ALLOWED:allowed_actions`)
- `"write"` → **FAIL**

### 2. Resource Scope (`type: "resource_scope"`)

Controls which resources agents can access.

```json
{
  "id": "resource_scope",
  "type": "resource_scope",
  "config": {
    "allowed_resources": ["staging", "dev", "sandbox", "test"],
    "denied_resources": ["production", "prod", "master-key", "admin"]
  }
}
```

**Behavior:** Deny list is checked first (substring match, case-insensitive). If the resource matches any denied pattern, it fails. Then the allow list is checked — the resource must match at least one allowed pattern.

**Examples:**
- `"staging-database"` → matches `"staging"` → **PASS**
- `"production-db"` → matches `"production"` in deny list → **FAIL** (`RESOURCE_OUT_OF_SCOPE:resource_scope`)
- `"unknown-service"` → no match in allow list → **FAIL**

### 3. Rate Limit (`type: "rate_limit"`)

Limits the number of actions per agent per time window.

```json
{
  "id": "rate_limit",
  "type": "rate_limit",
  "config": {
    "max_actions": 10,
    "window_seconds": 60
  }
}
```

**Behavior:** Each agent has a separate counter. When an agent exceeds `max_actions` within `window_seconds`, subsequent requests are denied until the window rolls over. Counters are persisted to Firestore across restarts.

**Example:** Agent "worker-01" makes 10 requests in 45 seconds → 11th request → **FAIL** (`RATE_LIMIT_EXCEEDED:rate_limit`)

## Adding a New Policy

### Via the REST API

```bash
# View current policy
curl https://your-gateway/policy

# Update policy
curl -X PUT https://your-gateway/policy \
  -H "Content-Type: application/json" \
  -d '{
    "version": "2",
    "rules": [
      {"id": "strict_read_only", "type": "allowlist", "config": {"allowed_actions": ["read", "list"]}},
      {"id": "staging_only", "type": "resource_scope", "config": {"allowed_resources": ["staging"]}}
    ]
  }'
```

### Via the Dashboard

1. Navigate to the **Policy** tab
2. Click **Edit Policy**
3. Modify rules inline or click **+ Add Rule**
4. Click **Save Policy** — changes take effect immediately

### Via JSON File Upload

1. Create a policy JSON file (see `examples/policy-*.json` for templates)
2. In the Dashboard → Policy tab → Click **Upload JSON**
3. Select your file — the policy is applied immediately

## How Policies Bind to Receipts

Every receipt's `body.policy_version` field contains the **SHA-256 hash of the policy** that was in effect when the decision was made. This hash is computed from the canonicalized policy JSON (RFC 8785), making it deterministic and reproducible.

```
Receipt body:
  policy_version: "sha256:d59a1e4171e6c60b1dc0964748d484f5..."
```

This binding means:
- You can prove which policy was in effect for any decision
- If the policy changes, subsequent receipts reference the new hash
- The chain captures the full policy history implicitly

## Failure Modes

| Failure | Behavior | Receipt |
|---------|----------|---------|
| Policy file corrupted | Falls back to last known good policy from Firestore | References last good policy hash |
| Policy returns no rules | All actions approved (empty rule set = no restrictions) | policy_version reflects empty policy |
| Ambiguous result | Not possible — every rule returns PASS or FAIL; any FAIL = DENY | Receipt captures all reason codes |
| Firestore unavailable | Uses in-memory policy (demo default) | References in-memory policy hash |
| Policy update mid-chain | New policy hash appears in subsequent receipts | Chain remains valid — policy changes are captured, not rejected |

## Dry Run

Use `POST /authorize/dry-run` to test policy decisions without creating receipts or advancing the chain. This is useful for validating policy changes before applying them.
