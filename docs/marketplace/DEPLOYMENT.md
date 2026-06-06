# Deployment

## Overview

Gate deploys as a constellation of Cloud Run services in a single GCP project. All services are fully managed — no customer-managed VMs, no Kubernetes cluster operations, no persistent compute. Each service scales to zero when idle and scales up automatically under load.

The deployment comprises 11 Cloud Run services, 1 Pub/Sub topic with 1 push subscription, 2 Cloud Scheduler jobs, 6 Secret Manager secrets (minimum), 1 Firestore database, and 1 Vertex AI Search data store.

## Deployment Topology Decisions

Before deploying, decide on these architectural questions:

### Single Gate instance vs multiple

Recommendation: one Gate deployment per customer organization. Multiple business units within an organization should share a single Gate instance with tenant isolation (one tenant per business unit or per environment).

### Tenant scoping

Common patterns:

- **Tenant-per-environment:** `acme-prod`, `acme-staging`, `acme-dev`. Recommended for most deployments.
- **Tenant-per-business-unit:** `acme-finance`, `acme-hr`, `acme-ops`. Useful when different business units have independent compliance reporting requirements.
- **Tenant-per-application:** Fine-grained but operationally heavier. Use only if applications have materially different retention or governance requirements.

### Shared GCP project vs dedicated

Recommendation: dedicated GCP project for production Gate deployments. This gives clean IAM boundaries, separate billing visibility, and isolated quotas. Pre-production deployments can share a project.

### Region

Current support: single region (`us-central1` default). Multi-region replication for Firestore is supported by GCP natively but is a v1.0 roadmap item for Gate. Customers requiring multi-region today should deploy independent Gate instances per region.

## Prerequisites

- GCP project with billing enabled
- APIs enabled:
  - Cloud Run (`run.googleapis.com`)
  - Cloud Firestore (`firestore.googleapis.com`)
  - Vertex AI / Discovery Engine (`discoveryengine.googleapis.com`)
  - Secret Manager (`secretmanager.googleapis.com`)
  - Cloud Pub/Sub (`pubsub.googleapis.com`)
  - Cloud Scheduler (`cloudscheduler.googleapis.com`)
  - Cloud Build (`cloudbuild.googleapis.com`)
  - Artifact Registry (`artifactregistry.googleapis.com`)
  - Cloud Logging (`logging.googleapis.com`)
  - Google AI API (`generativelanguage.googleapis.com`)
- `gcloud` CLI installed and authenticated
- Docker (for local builds) or Cloud Build (for remote builds)

Enable all APIs at once:

```bash
gcloud services enable \
  run.googleapis.com \
  firestore.googleapis.com \
  discoveryengine.googleapis.com \
  secretmanager.googleapis.com \
  pubsub.googleapis.com \
  cloudscheduler.googleapis.com \
  cloudbuild.googleapis.com \
  artifactregistry.googleapis.com \
  logging.googleapis.com \
  generativelanguage.googleapis.com
```

## Service Inventory

All services deploy to `us-central1` (configurable). Current deployed state:

| Service Name | Purpose | Image Source | Memory | Cloud Run Service |
|---|---|---|---|---|
| agent-auth-gateway | REST API (authorization chokepoint) | `gateway/` (main Dockerfile) | 512Mi | `agent-auth-gateway` |
| agent-auth-gateway-mcp | MCP server (tool-based access) | `serve_mcp.py` | 512Mi | `agent-auth-gateway-mcp` |
| agent-auth-gateway-adk | ADK chat agent | `authorization_gateway/` | 512Mi | `agent-auth-gateway-adk` |
| agent-auth-gateway-a2a | A2A protocol surface | `gateway/a2a/` | 512Mi | `agent-auth-gateway-a2a` |
| agent-auth-gateway-resource | Protected resource (demo) | `gateway/` (resource endpoint) | 256Mi | `agent-auth-gateway-resource` |
| agent-auth-gateway-auditor | Policy Auditor agent | `gateway/auditor/Dockerfile` | 1Gi | `agent-auth-gateway-auditor` |
| agent-auth-gateway-recommender | Policy Recommender agent | `gateway/recommender/Dockerfile` | 1Gi | `agent-auth-gateway-recommender` |
| agent-auth-investigator | Incident Investigator agent | `gateway/investigator/Dockerfile` | 1Gi | `agent-auth-investigator` |
| agent-auth-gateway-coordinator | Discovery Coordinator | `gateway/coordinator/Dockerfile` | 1Gi | `agent-auth-gateway-coordinator` |
| agent-auth-isolator | Incident Isolator agent | `gateway/isolator/Dockerfile` | 1Gi | `agent-auth-isolator` |
| agent-auth-demo-ui | Interactive demo dashboard | `independent-agent/` | 512Mi | `agent-auth-demo-ui` |

All services use `--min-instances=0` (scale-to-zero) and `--max-instances=10` by default.

## IAM

Each service should have a dedicated service account in production. The minimum required IAM roles per service:

### Gateway services (REST, MCP, ADK, A2A, Resource)

| Role | Purpose |
|---|---|
| `roles/datastore.user` | Read/write receipts, metadata, agent registry |
| `roles/secretmanager.secretAccessor` | Load signing key from Secret Manager |

### Auditor

| Role | Purpose |
|---|---|
| `roles/datastore.user` | Read receipts, write audit reports, manage checkpoint |
| `roles/secretmanager.secretAccessor` | Load auditor signing key and config |
| `roles/discoveryengine.viewer` | Query Vertex AI Search data store |
| `roles/pubsub.publisher` | Publish CONFLICT verdicts to `auditor-conflicts` topic |

### Recommender

| Role | Purpose |
|---|---|
| `roles/datastore.user` | Read audit reports, write proposals |
| `roles/secretmanager.secretAccessor` | Load recommender signing key and config |

### Investigator

| Role | Purpose |
|---|---|
| `roles/datastore.user` | Read receipts, audit reports, registrations; write incidents |
| `roles/secretmanager.secretAccessor` | Load investigator signing key and config |

### Coordinator

| Role | Purpose |
|---|---|
| `roles/datastore.user` | Read/write agent directory entries |
| `roles/secretmanager.secretAccessor` | Load coordinator signing key and config |

### Scheduler

Cloud Scheduler requires a service account with `roles/run.invoker` on the target services (Auditor and Recommender).

## Secrets

Create the following Secret Manager secrets before deploying:

### Signing Keys

Each agent requires an Ed25519 signing key. Generate and store them:

```bash
# Generate a key (example for gateway)
python3 -c "
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, NoEncryption
import json, hashlib, base64

key = Ed25519PrivateKey.generate()
pem = key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()).decode()
pub = key.public_key().public_bytes_raw()
kid_hash = hashlib.sha256(pub).hexdigest()[:8]
kid = f'gateway-{kid_hash}'

payload = json.dumps({'kid': kid, 'private_pem': pem})
print(payload)
"

# Store in Secret Manager
echo '<JSON_OUTPUT>' | gcloud secrets create gateway-signing-key --data-file=-
```

**Secret format** (JSON, as expected by `gateway/signing_key.py`):

```json
{
  "kid": "gateway-<8-char-hash>",
  "private_pem": "-----BEGIN PRIVATE KEY-----\n...\n-----END PRIVATE KEY-----\n"
}
```

| Secret Name | Used By | Format |
|---|---|---|
| `gateway-signing-key` | Gateway (all surfaces) | `{kid, private_pem}` |
| `gateway-auditor-signing-key` | Auditor | `{kid, private_pem}` |
| `gateway-recommender-signing-key` | Recommender | `{kid, private_pem}` |
| `gateway-investigator-signing-key` | Investigator | `{kid, private_pem}` |
| `gateway-coordinator-signing-key` | Coordinator | `{kid, private_pem}` |

### Configuration Secrets

Agent-specific configuration (non-sensitive but centralized in Secret Manager for convenience):

| Secret Name | Used By | Format |
|---|---|---|
| `gateway-auditor-config` | Auditor | `{data_store_id, engine_id, data_store_location, model}` |
| `gateway-recommender-config` | Recommender | `{model, default_tenant}` |
| `gateway-investigator-config` | Investigator | `{model, default_tenant}` |
| `gateway-coordinator-config` | Coordinator | `{model, default_tenant}` |

**Example auditor config:**

```json
{
  "data_store_id": "compliance-docs-v3",
  "engine_id": "compliance-search-engine",
  "data_store_location": "global",
  "model": "gemini-2.5-pro"
}
```

## Pub/Sub

Create the topic and push subscription:

```bash
# Topic
gcloud pubsub topics create auditor-conflicts

# Push subscription (delivers to Investigator)
gcloud pubsub subscriptions create auditor-conflicts-push \
  --topic=auditor-conflicts \
  --push-endpoint="https://<INVESTIGATOR_URL>/investigate" \
  --ack-deadline=300
```

The Auditor publishes a JSON message `{"tenant": "<tenant_id>", "audit_id": "<audit_id>"}` to the topic when it produces a CONFLICT verdict. The Investigator's `/investigate` endpoint handles the Pub/Sub push wrapper format (`{message: {data: <base64>}}`).

## Cloud Scheduler

Create scheduled jobs for the Auditor and Recommender:

```bash
# Auditor tick — every 5 minutes
gcloud scheduler jobs create http auditor-tick \
  --location=us-central1 \
  --schedule="*/5 * * * *" \
  --uri="https://<AUDITOR_URL>/audit-tick" \
  --http-method=POST \
  --oidc-service-account-email=<SCHEDULER_SA>@<PROJECT>.iam.gserviceaccount.com \
  --oidc-token-audience="https://<AUDITOR_URL>"

# Recommender tick — hourly
gcloud scheduler jobs create http recommender-tick \
  --location=us-central1 \
  --schedule="0 * * * *" \
  --uri="https://<RECOMMENDER_URL>/recommend-tick" \
  --http-method=POST \
  --oidc-service-account-email=<SCHEDULER_SA>@<PROJECT>.iam.gserviceaccount.com \
  --oidc-token-audience="https://<RECOMMENDER_URL>"
```

## Vertex AI Search

The Auditor requires a Discovery Engine data store with the compliance corpus.

### Data Store Setup

1. Create an unstructured data store in the Google Cloud Console under Discovery Engine.
2. Upload the following public compliance documents as PDFs:
   - [OWASP Non-Human Identity Top 10 (2025)](https://owasp.org/www-project-non-human-identities-top-10/)
   - [NIST AI RMF 1.0](https://www.nist.gov/artificial-intelligence/ai-risk-management-framework)
   - [NIST SP 800-53 Rev 5](https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final)
3. Create a search engine with `SEARCH_TIER_ENTERPRISE` (required for extractive answers).
4. Note the `data_store_id` and `engine_id` for the auditor config secret.

Gate does not redistribute these documents. Customers must download and upload them to their own Vertex AI Search data store.

## Build and Deploy

Each service has its own Dockerfile. Build and deploy using Cloud Build:

```bash
PROJECT_ID=$(gcloud config get-value project)
REGION=us-central1

# Gateway (REST)
gcloud builds submit --tag gcr.io/$PROJECT_ID/agent-auth-gateway .
gcloud run deploy agent-auth-gateway \
  --image gcr.io/$PROJECT_ID/agent-auth-gateway \
  --region $REGION \
  --memory 512Mi \
  --set-env-vars GOOGLE_CLOUD_PROJECT=$PROJECT_ID,FIRESTORE_ENABLED=true,TENANT_ID=default \
  --allow-unauthenticated

# Auditor
gcloud builds submit --tag gcr.io/$PROJECT_ID/agent-auth-gateway-auditor gateway/auditor/
gcloud run deploy agent-auth-gateway-auditor \
  --image gcr.io/$PROJECT_ID/agent-auth-gateway-auditor \
  --region $REGION \
  --memory 1Gi \
  --timeout 300 \
  --set-env-vars GCP_PROJECT_ID=$PROJECT_ID,GOOGLE_CLOUD_PROJECT=$PROJECT_ID,GOOGLE_GENAI_USE_VERTEXAI=TRUE,GOOGLE_CLOUD_LOCATION=us-central1

# Recommender
gcloud builds submit --tag gcr.io/$PROJECT_ID/agent-auth-gateway-recommender gateway/recommender/
gcloud run deploy agent-auth-gateway-recommender \
  --image gcr.io/$PROJECT_ID/agent-auth-gateway-recommender \
  --region $REGION \
  --memory 1Gi \
  --timeout 300 \
  --set-env-vars GCP_PROJECT_ID=$PROJECT_ID,GOOGLE_CLOUD_PROJECT=$PROJECT_ID,GOOGLE_GENAI_USE_VERTEXAI=TRUE,GOOGLE_CLOUD_LOCATION=us-central1

# Investigator
gcloud builds submit --tag gcr.io/$PROJECT_ID/agent-auth-investigator gateway/investigator/
gcloud run deploy agent-auth-investigator \
  --image gcr.io/$PROJECT_ID/agent-auth-investigator \
  --region $REGION \
  --memory 1Gi \
  --timeout 300 \
  --set-env-vars GCP_PROJECT_ID=$PROJECT_ID,GOOGLE_CLOUD_PROJECT=$PROJECT_ID,GOOGLE_GENAI_USE_VERTEXAI=TRUE,GOOGLE_CLOUD_LOCATION=us-central1

# Coordinator
gcloud builds submit --tag gcr.io/$PROJECT_ID/agent-auth-gateway-coordinator gateway/coordinator/
gcloud run deploy agent-auth-gateway-coordinator \
  --image gcr.io/$PROJECT_ID/agent-auth-gateway-coordinator \
  --region $REGION \
  --memory 1Gi \
  --set-env-vars GCP_PROJECT_ID=$PROJECT_ID,GOOGLE_CLOUD_PROJECT=$PROJECT_ID,GOOGLE_GENAI_USE_VERTEXAI=TRUE,GOOGLE_CLOUD_LOCATION=us-central1
```

Each AI agent service requires `roles/aiplatform.user` on its service account for Vertex AI Model Garden access.

## Environment Variables

| Variable | Services | Description |
|---|---|---|
| `GOOGLE_CLOUD_PROJECT` | All | GCP project ID |
| `FIRESTORE_ENABLED` | Gateway | Set to `true` to enable Firestore persistence |
| `TENANT_ID` | Gateway | Default tenant identifier |
| `MCP_AUTH_MODE` | MCP server | `bearer`, `iam`, or `none` |
| `MCP_BEARER_TOKEN` | MCP server | Static bearer token for MCP transport auth |
| `MCP_ALLOWED_HOSTS` | MCP server | Comma-separated hostnames for DNS rebinding protection |
| `GATEWAY_DEV_MODE` | MCP server | Must be `true` if `MCP_AUTH_MODE=none` |
| `GCP_PROJECT_ID` | AI agents | GCP project ID (used by agent services) |
| `GOOGLE_GENAI_USE_VERTEXAI` | AI agents | Set to `TRUE` to route Gemini calls through Vertex AI Model Garden |
| `GOOGLE_CLOUD_LOCATION` | AI agents | Vertex AI region (e.g., `us-central1`) |
| `ANCHOR_TO_BASE` | Gateway (REST) | Set to `true` to enable Base L2 Merkle anchoring |
| `MAX_PER_TICK` | Auditor | Max receipts per audit tick (default: 10) |
| `POLICY_YAML_PATH` | Gateway | Path to a YAML policy file to load at startup (overrides built-in demo policy; see docs/policy.md) |
| `CONTINUOUS_ATTESTATION` | Gateway | Set to `false` to disable background liveness sweep (default: enabled) |
| `ATTESTATION_INTERVAL` | Gateway | Seconds between liveness re-challenges (default: 3600) |
| `HOT_PATH_MODE` | Gateway | `sync` (blocking Firestore, default) or `async` (evidence buffer with 1s flush) |
| `A2A_BASE_URL` | AI agents (Auditor, Recommender, Investigator, Coordinator, Isolator) | Base URL of the service's own A2A endpoint, used to populate the agent card `url` field |

## Production Lockdown Checklist

The reference deployment uses `--allow-unauthenticated` on all Cloud Run services for evaluator access. This is appropriate for hackathon submission and design partnership demos. Production deployments must lock down the IAM boundary.

### 1. Remove public access from all services

```bash
PROJECT_ID=<your-project-id>
REGION=us-central1

for SVC in agent-auth-gateway agent-auth-gateway-auditor \
  agent-auth-gateway-recommender agent-auth-investigator \
  agent-auth-gateway-coordinator agent-auth-isolator \
  agent-auth-gateway-mcp agent-auth-demo-ui agent-auth-adk-chat; do
  gcloud run services update $SVC \
    --no-allow-unauthenticated \
    --region $REGION --project $PROJECT_ID
done
```

### 2. Grant inter-service invoker rights

Each service account receives `roles/run.invoker` only on the services it needs to call:

```bash
# Isolator -> Gateway (quarantine DELETE calls)
gcloud run services add-iam-policy-binding agent-auth-gateway \
  --member="serviceAccount:isolator-sa@${PROJECT_ID}.iam.gserviceaccount.com" \
  --role="roles/run.invoker" \
  --region $REGION --project $PROJECT_ID

# Investigator -> Gateway (read receipts, agent registrations)
gcloud run services add-iam-policy-binding agent-auth-gateway \
  --member="serviceAccount:investigator-sa@${PROJECT_ID}.iam.gserviceaccount.com" \
  --role="roles/run.invoker" \
  --region $REGION --project $PROJECT_ID

# Investigator -> Isolator (trigger containment on HIGH/CRITICAL)
gcloud run services add-iam-policy-binding agent-auth-isolator \
  --member="serviceAccount:investigator-sa@${PROJECT_ID}.iam.gserviceaccount.com" \
  --role="roles/run.invoker" \
  --region $REGION --project $PROJECT_ID

# Cloud Scheduler -> Auditor and Recommender (periodic ticks)
gcloud run services add-iam-policy-binding agent-auth-gateway-auditor \
  --member="serviceAccount:scheduler-sa@${PROJECT_ID}.iam.gserviceaccount.com" \
  --role="roles/run.invoker" \
  --region $REGION --project $PROJECT_ID

gcloud run services add-iam-policy-binding agent-auth-gateway-recommender \
  --member="serviceAccount:scheduler-sa@${PROJECT_ID}.iam.gserviceaccount.com" \
  --role="roles/run.invoker" \
  --region $REGION --project $PROJECT_ID
```

### 3. Restrict dashboard access to admin users

```bash
# Grant access to specific admin users via IAP or direct IAM
gcloud run services add-iam-policy-binding agent-auth-demo-ui \
  --member="user:admin@yourcompany.com" \
  --role="roles/run.invoker" \
  --region $REGION --project $PROJECT_ID
```

For organizations using Identity-Aware Proxy (IAP), configure IAP on the dashboard service instead of direct IAM bindings.

### 4. Enable Data Access audit logs

In the Cloud Console, enable Data Access audit logs for:
- Cloud Firestore (read/write operations on receipt and registry collections)
- Secret Manager (key access events)
- Cloud Run (inter-service invocation records)

These logs provide the evidence trail that a security reviewer or compliance auditor needs to verify that the IAM boundary is operating as documented.

### 5. Apply customer-managed encryption keys (recommended for regulated workloads)

Configure CMEK on Firestore and Secret Manager. Gate's application code is CMEK-transparent; no code changes required. See Google's [CMEK documentation](https://cloud.google.com/kms/docs/cmek) for the specific commands.

### 6. Configure VPC Service Controls (recommended for regulated workloads)

Add Gate's services to a VPC-SC perimeter. Vertex AI Model Garden inference inherits the perimeter automatically when accessed via the Vertex AI endpoint in the same project. Base L2 anchoring (if enabled) requires an egress rule for the Base RPC endpoint.

### 7. Verify the lockdown

```bash
# Unauthenticated call should fail after lockdown
curl -s -o /dev/null -w "%{http_code}" \
  https://agent-auth-gateway-<hash>.run.app/keys
# Expected: 403

# Authenticated call should succeed
curl -s -o /dev/null -w "%{http_code}" \
  -H "Authorization: Bearer $(gcloud auth print-identity-token)" \
  https://agent-auth-gateway-<hash>.run.app/keys
# Expected: 200
```

After the checklist, every Cloud Run service requires either a user IAM grant (for admin access) or a service account IAM grant (for inter-service calls). Public access is eliminated. A v0.6 release will ship a `deploy-production.sh` script that applies this checklist by default, with `--evaluator-mode` as an explicit opt-out for demo scenarios.

## Verification

Post-deployment smoke test:

```bash
# Health checks — all should return {"ok": true}
for svc in agent-auth-gateway agent-auth-gateway-auditor \
  agent-auth-gateway-recommender agent-auth-investigator \
  agent-auth-gateway-coordinator; do
  URL=$(gcloud run services describe $svc --region us-central1 --format="value(status.url)")
  echo -n "$svc: "
  curl -s "$URL/health" | python3 -c "import sys,json; print(json.load(sys.stdin))"
done

# Verify signing keys are loaded
curl -s $(gcloud run services describe agent-auth-gateway --region us-central1 --format="value(status.url)")/keys
curl -s $(gcloud run services describe agent-auth-gateway-auditor --region us-central1 --format="value(status.url)")/audit-keys

# Test authorization flow
python3 -c "
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
import httpx, base64, json
GATEWAY_URL = '$(gcloud run services describe agent-auth-gateway --region us-central1 --format=\"value(status.url)\")'
key = Ed25519PrivateKey.generate()
pub = key.public_key().public_bytes_raw()
x = base64.urlsafe_b64encode(pub).rstrip(b'=').decode()
jwk = {'kty': 'OKP', 'crv': 'Ed25519', 'x': x}
c = httpx.Client(timeout=30)
import time
ch = c.post(f'{GATEWAY_URL}/agents/register-challenge', json={'agent_id': 'smoke-test'}).json()
iat = int(time.time())
msg = json.dumps({'v':'1','tenant_id':'hackathon-demo','agent_id':'smoke-test','public_key':jwk,'nonce':ch['nonce'],'challenge_id':ch['challenge_id'],'iat':iat}, separators=(',',':'), sort_keys=True).encode()
sig = base64.urlsafe_b64encode(key.sign(msg)).rstrip(b'=').decode()
print('Register:', c.post(f'{GATEWAY_URL}/agents/register', json={'agent_id': 'smoke-test', 'public_key': jwk, 'proof': {'nonce': ch['nonce'], 'challenge_id': ch['challenge_id'], 'signature': sig, 'iat': iat}}).status_code)
"
```

## Cost Estimates

Rough order-of-magnitude at modest scale (1,000–10,000 daily authorization decisions):

| Service | Estimated Monthly Cost |
|---|---|
| Cloud Run (11 services, scale-to-zero) | $50–200 |
| Cloud Firestore | $20–100 |
| Vertex AI Search (Enterprise tier) | $200–2,000 |
| Gemini 2.5 Pro (AI agent model calls) | $100–500 |
| Secret Manager, Pub/Sub, Scheduler | <$20 |
| **Total** | **$400–3,500** |

Costs scale primarily with audit volume (Gemini API calls) and Vertex AI Search query volume. Vertex AI Search Enterprise tier pricing is roughly $1–4 per 1,000 queries with regional capacity fees; customers running >100,000 audits per month should price against current Vertex AI Search rates rather than the estimate above. The Gateway itself is lightweight — authorization decisions are deterministic and do not invoke models. Customers should validate these estimates against their own usage projections.

## Monitoring

Default metrics available in Cloud Monitoring:

- **Cloud Run:** Request count, latency (p50/p95/p99), instance count, memory/CPU utilization per service
- **Firestore:** Read/write operation counts, document sizes
- **Pub/Sub:** Message publish rate, push delivery latency, undelivered message count
- **Gemini API:** Token consumption, request count, latency

### Recommended Alerts

| Alert | Condition | Severity |
|---|---|---|
| Auditor tick failure | Any non-200 response from Cloud Scheduler to `/audit-tick` | High |
| Pub/Sub message age | Undelivered messages older than 5 minutes in `auditor-conflicts-push` | Medium |
| Firestore write errors | Gateway receipts write failure rate > 0% | Critical |
| Gateway 5xx rate | Error rate > 1% over 5 minutes | High |
| Secret Manager access failure | Any failed `access_secret_version` call | Critical |
| Model API errors | Gemini API error rate > 10% for any AI agent | Medium |
