# Policy Auditor Agent — GCP Setup Guide

Manual steps required before deploying the Auditor service. These create GCP resources that cannot be provisioned from code alone.

**Project ID:** `quick-catcher-470218-b0` (adjust if different)

## 1. Create GCS bucket for compliance documents

```bash
gsutil mb -l us-central1 gs://quick-catcher-470218-b0-auditor-compliance-docs
```

## 2. Upload compliance PDFs

Download these real compliance documents and upload to the bucket:

- **OWASP Non-Human Identities Top 10 (2025)**
  https://owasp.org/www-project-non-human-identities-top-10/
  (Download the PDF from the project page)

- **NIST AI Risk Management Framework (AI RMF 1.0)**
  https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.100-1.pdf

- **SOC2 Trust Services Criteria**
  https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria-with-revised-points-of-focus-2022

```bash
gsutil cp *.pdf gs://quick-catcher-470218-b0-auditor-compliance-docs/
```

## 3. Create Discovery Engine Data Store

In Google Cloud Console:
1. Navigate to **Agent Builder** (or Vertex AI Search)
2. Create a new **Data Store**:
   - Source: Cloud Storage
   - Type: Unstructured Data
   - Source: `gs://quick-catcher-470218-b0-auditor-compliance-docs/*`
   - Parsing: Default
   - Region: `global`
3. Wait for indexing to complete (5-30 minutes)
4. Note the **data_store_id** (resource ID, not display name)

## 4. Create Secret Manager secrets

### Auditor config
```bash
cat > /tmp/auditor-config.json << 'EOF'
{
  "data_store_id": "<DATA_STORE_ID_FROM_STEP_3>",
  "data_store_location": "global",
  "model": "gemini-2.5-pro",
  "audit_tick_seconds": 60
}
EOF

gcloud secrets create gateway-auditor-config \
  --replication-policy=automatic \
  --project=quick-catcher-470218-b0

gcloud secrets versions add gateway-auditor-config \
  --data-file=/tmp/auditor-config.json

rm /tmp/auditor-config.json
```

### Auditor signing key (separate from gateway)
```bash
python -c "
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization
import base64, json, secrets

k = Ed25519PrivateKey.generate()
priv = k.private_bytes(
    encoding=serialization.Encoding.Raw,
    format=serialization.PrivateFormat.Raw,
    encryption_algorithm=serialization.NoEncryption())
pub = k.public_key().public_bytes(
    encoding=serialization.Encoding.Raw,
    format=serialization.PublicFormat.Raw)
kid = 'auditor-' + secrets.token_hex(4)
print(json.dumps({
    'kid': kid,
    'private_key': base64.b64encode(priv).decode(),
    'public_key': base64.b64encode(pub).decode()
}))
" > /tmp/auditor-key.json

gcloud secrets create gateway-auditor-signing-key \
  --replication-policy=automatic \
  --project=quick-catcher-470218-b0

gcloud secrets versions add gateway-auditor-signing-key \
  --data-file=/tmp/auditor-key.json

rm /tmp/auditor-key.json
```

## 5. Grant IAM roles

```bash
PROJECT=quick-catcher-470218-b0
SA=1031148889398-compute@developer.gserviceaccount.com

# Secret Manager access for the two new secrets
gcloud secrets add-iam-policy-binding gateway-auditor-config \
  --member="serviceAccount:$SA" \
  --role="roles/secretmanager.secretAccessor" \
  --project=$PROJECT

gcloud secrets add-iam-policy-binding gateway-auditor-signing-key \
  --member="serviceAccount:$SA" \
  --role="roles/secretmanager.secretAccessor" \
  --project=$PROJECT

# Discovery Engine search access
gcloud projects add-iam-policy-binding $PROJECT \
  --member="serviceAccount:$SA" \
  --role="roles/discoveryengine.viewer"

# Vertex AI (Gemini) access
gcloud projects add-iam-policy-binding $PROJECT \
  --member="serviceAccount:$SA" \
  --role="roles/aiplatform.user"
```

## 6. Deploy the Auditor (after code is written)

```bash
gcloud builds submit gateway/auditor \
  --tag us-central1-docker.pkg.dev/$PROJECT/agent-auth-gateway/auditor:v0.1

gcloud run deploy agent-auth-gateway-auditor \
  --image us-central1-docker.pkg.dev/$PROJECT/agent-auth-gateway/auditor:v0.1 \
  --region us-central1 \
  --set-env-vars="GCP_PROJECT_ID=$PROJECT" \
  --max-instances=1 \
  --min-instances=0 \
  --memory=2Gi \
  --cpu=1 \
  --timeout=300 \
  --no-allow-unauthenticated
```

## 7. Create Cloud Scheduler job

```bash
AUDITOR_URL=$(gcloud run services describe agent-auth-gateway-auditor \
  --region us-central1 --format="value(status.url)")

gcloud scheduler jobs create http auditor-tick \
  --location=us-central1 \
  --schedule="* * * * *" \
  --uri="$AUDITOR_URL/audit-tick" \
  --http-method=POST \
  --oidc-service-account-email=$SA \
  --oidc-token-audience="$AUDITOR_URL"
```

## 8. Verify

```bash
# Health check
curl -H "Authorization: Bearer $(gcloud auth print-identity-token \
  --audiences=$AUDITOR_URL)" "$AUDITOR_URL/health"

# Auditor public key
curl -H "Authorization: Bearer $(gcloud auth print-identity-token \
  --audiences=$AUDITOR_URL)" "$AUDITOR_URL/audit-keys"

# Manual tick
curl -X POST -H "Authorization: Bearer $(gcloud auth print-identity-token \
  --audiences=$AUDITOR_URL)" "$AUDITOR_URL/audit-tick"
```
