"""MCP Server — exposes the Gateway as an MCP tool server.

Any agent framework (ADK, LangChain, CrewAI) can connect to this server
using the Model Context Protocol to authorize actions, verify receipts,
inspect the receipt chain, query audit reports, trigger investigations,
analyze policy patterns, and route capabilities across the multi-agent system.

Run standalone:
    python -m gateway.mcp_server

Or mount alongside the REST API (see serve.py).
"""

from __future__ import annotations

import json
import logging
import os

import httpx
from mcp.server.fastmcp import FastMCP
from mcp.server.transport_security import TransportSecuritySettings

from .gateway_service import GatewayService
from .store import create_store

logger = logging.getLogger(__name__)

# --- Singleton gateway + store ---
_gateway: GatewayService | None = None
_store = None


def _get_gateway() -> GatewayService:
    global _gateway
    if _gateway is None:
        _gateway = GatewayService(tenant="hackathon-demo")
    return _gateway


def _get_store():
    global _store
    if _store is None:
        _store = create_store()
    return _store


# --- Agent service URLs (set via env vars at deploy time) ---
AUDITOR_REST_URL = os.environ.get("AUDITOR_REST_URL", "")
RECOMMENDER_REST_URL = os.environ.get("RECOMMENDER_REST_URL", "")
INVESTIGATOR_REST_URL = os.environ.get("INVESTIGATOR_REST_URL", "")
COORDINATOR_REST_URL = os.environ.get("COORDINATOR_REST_URL", "")
GATEWAY_REST_URL = os.environ.get("GATEWAY_REST_URL", "")


# --- Service-to-service HTTP helper ---
def _get_identity_token(audience: str) -> str:
    """Mint a Google ID token for Cloud Run service-to-service auth."""
    try:
        from google.oauth2 import id_token as google_id_token
        from google.auth.transport.requests import Request
        return google_id_token.fetch_id_token(Request(), audience)
    except Exception:
        return ""


async def _call_agent(
    base_url: str,
    method: str,
    path: str,
    json_body: dict | None = None,
    params: dict | None = None,
    timeout: int = 120,
) -> dict:
    """Make an authenticated HTTP call to an AI agent service."""
    if not base_url:
        return {"error": "SERVICE_NOT_CONFIGURED", "detail": f"No URL configured for this agent service"}
    headers = {}
    token = _get_identity_token(base_url)
    if token:
        headers["Authorization"] = f"Bearer {token}"
    async with httpx.AsyncClient(timeout=timeout) as client:
        response = await client.request(
            method,
            f"{base_url}{path}",
            headers=headers,
            json=json_body,
            params=params,
        )
        response.raise_for_status()
        return response.json()


# --- MCP Server ---
mcp = FastMCP(
    "Agent Authorization Gateway",
    instructions=(
        "This MCP server provides cryptographic policy enforcement for AI agent actions, "
        "plus compliance auditing, policy recommendations, incident investigation, and "
        "capability routing across a multi-agent system. "
        "Tools are namespaced by agent: gateway_*, auditor_*, recommender_*, "
        "investigator_*, coordinator_*. "
        "Use gateway_authorize_action before performing any privileged operation. "
        "Every decision (approve or deny) produces a signed, hash-chained receipt."
    ),
    transport_security=TransportSecuritySettings(
        enable_dns_rebinding_protection=True,
        allowed_hosts=(
            ["127.0.0.1:*", "localhost:*", "[::1]:*"]
            + [h.strip() for h in os.environ.get("MCP_ALLOWED_HOSTS", "").split(",") if h.strip()]
        ),
    ),
)


# ============================================================================
# GATEWAY TOOLS (existing, in-process — unchanged behavior)
# ============================================================================

@mcp.tool()
async def gateway_authorize_action(
    agent_id: str,
    action: str,
    resource: str,
    agent_proof: str,
    parameters: str = "{}",
) -> str:
    """Evaluate an AI agent's intended action against a security policy.

    Returns an authorization decision (approve/deny) with a cryptographic
    receipt and, if approved, a 60-second scoped authorization token.

    SECURITY: agent_proof is REQUIRED. Calls without a valid DPoP proof
    signed by a registered agent key are rejected before policy evaluation.

    Args:
        agent_id: Unique identifier of the requesting agent.
        action: Human-readable description of the intended action.
        resource: Target resource (database, API endpoint, cloud service).
        agent_proof: DPoP-style proof JWT signed by the agent's Ed25519 private key.
        parameters: JSON string of action-specific parameters (optional).
    """
    params = None
    if parameters and parameters.strip():
        try:
            params = json.loads(parameters)
        except json.JSONDecodeError:
            params = {"raw": parameters}

    gateway = _get_gateway()
    store = _get_store()

    try:
        response = gateway.authorize(
            agent_id=agent_id,
            action=action,
            resource=resource,
            parameters=params,
            agent_proof=agent_proof,
        )
    except ValueError as e:
        error_code = str(e).split(":")[0] if ":" in str(e) else "IDENTITY_ERROR"
        return json.dumps({"error": error_code, "detail": str(e)})

    enriched = {
        **response.receipt,
        "_meta": {
            "agent_id": agent_id,
            "action": action,
            "resource": resource,
            "parameters": params,
        },
    }
    try:
        await store.save_receipt(gateway.tenant, enriched)
        await store.save_stats(gateway.tenant, gateway.get_chain_stats())
    except Exception:
        logger.exception("RECEIPT_PERSIST_FAILED: receipt not saved — token withheld")
        return json.dumps({
            "error": "RECEIPT_PERSIST_FAILED",
            "detail": "Authorization succeeded but the receipt could not be persisted. "
                      "Token withheld to prevent authorization without audit trail.",
        })

    return json.dumps({
        "decision": response.decision,
        "reason_codes": response.reason_codes,
        "token": response.token,
        "receipt_hash": response.receipt_hash,
        "action_digest": response.action_digest,
    })


@mcp.tool()
def gateway_get_chain_stats() -> str:
    """Get statistics about the current receipt chain.

    Returns total receipts, approval/denial counts, Merkle root, and policy version.
    """
    return json.dumps(_get_gateway().get_chain_stats())


@mcp.tool()
def gateway_get_receipt_chain() -> str:
    """Get the full receipt chain for audit/verification.

    Returns all signed receipts in sequence order with hash chain linkage.
    """
    return json.dumps(_get_gateway().get_receipt_chain())


@mcp.tool()
def gateway_get_public_key() -> str:
    """Get the gateway's Ed25519 signing public key as a JWK.

    Any verifier can use this key to independently verify receipt signatures.
    """
    return json.dumps(_get_gateway().get_public_key_jwk())


@mcp.tool()
def gateway_verify_receipt(receipt_json: str) -> str:
    """Verify a receipt's cryptographic integrity and signature.

    Takes a receipt envelope as a JSON string and verifies:
    1. The canonical hash matches the claimed receipt_hash
    2. The Ed25519 signature is valid
    3. The receipt was not tampered with after signing

    Args:
        receipt_json: JSON string of the receipt envelope (body + sig + receipt_hash).
    """
    from .verify import verify_receipt as _verify

    try:
        envelope = json.loads(receipt_json)
    except json.JSONDecodeError:
        return json.dumps({"receipt_integrity": "FAIL", "errors": [{"code": "INVALID_JSON"}]})

    gateway = _get_gateway()
    chain = gateway.get_receipt_chain()
    result = _verify(envelope, gateway.get_public_key_jwk(), chain=chain)
    return json.dumps(result.to_dict())


# gateway_register_agent REMOVED — registration is an admin operation that
# requires proof of possession, enforced only via the REST API endpoint
# POST /agents/register-challenge + POST /agents/register. The MCP bearer
# token authenticates the transport but not the caller's identity; allowing
# register_agent here would bypass PoP.


# ============================================================================
# BACKWARD COMPATIBILITY ALIASES
# Existing MCP clients may call the old tool names (without gateway_ prefix).
# Register the same functions under the original names so they keep working.
# ============================================================================

@mcp.tool()
async def authorize_action(
    agent_id: str, action: str, resource: str, agent_proof: str, parameters: str = "{}",
) -> str:
    """(Alias for gateway_authorize_action) Evaluate an AI agent's intended action against a security policy.

    Returns an authorization decision (approve/deny) with a cryptographic receipt and, if approved,
    a 60-second scoped authorization token. Requires a valid DPoP proof.

    Args:
        agent_id: Unique identifier of the requesting agent.
        action: Human-readable description of the intended action.
        resource: Target resource (database, API endpoint, cloud service).
        agent_proof: DPoP-style proof JWT signed by the agent's Ed25519 private key.
        parameters: JSON string of action-specific parameters (optional).
    """
    return await gateway_authorize_action(agent_id, action, resource, agent_proof, parameters)


@mcp.tool()
def get_chain_stats() -> str:
    """(Alias for gateway_get_chain_stats) Get receipt chain statistics."""
    return gateway_get_chain_stats()


@mcp.tool()
def get_receipt_chain() -> str:
    """(Alias for gateway_get_receipt_chain) Get the full receipt chain."""
    return gateway_get_receipt_chain()


@mcp.tool()
def get_public_key() -> str:
    """(Alias for gateway_get_public_key) Get the gateway's signing public key."""
    return gateway_get_public_key()


@mcp.tool()
def verify_receipt(receipt_json: str) -> str:
    """(Alias for gateway_verify_receipt) Verify a receipt's cryptographic integrity.

    Args:
        receipt_json: JSON string of the receipt envelope (body + sig + receipt_hash).
    """
    return gateway_verify_receipt(receipt_json)


# register_agent alias REMOVED — see gateway_register_agent removal note above.


# ============================================================================
# AUDITOR TOOLS (new — HTTP calls to the Auditor service)
# ============================================================================

@mcp.tool()
async def auditor_query_audits(
    tenant: str = "default",
    since_seq: int = 0,
    limit: int = 50,
) -> str:
    """Query compliance audit reports for a tenant. Each report contains a verdict
    (ALIGNED, CONFLICT, INSUFFICIENT_EVIDENCE, or ERROR), a rationale, and verbatim
    citations from OWASP NHI Top 10, NIST AI RMF, and NIST SP 800-53.

    Use this to review the compliance posture of recent authorization decisions,
    find CONFLICT verdicts that may require attention, or gather evidence for
    an investigation. Reports are sorted by receipt sequence number.

    Args:
        tenant: Tenant identifier (default: "default").
        since_seq: Only return reports for receipts with seq > this value.
        limit: Maximum number of reports to return (max 200).
    """
    result = await _call_agent(
        AUDITOR_REST_URL, "GET", "/audit-reports",
        params={"tenant": tenant, "since_seq": since_seq, "limit": min(limit, 200)},
    )
    return json.dumps(result, default=str)


@mcp.tool()
async def auditor_audit_receipt(tenant: str, receipt_seq: int) -> str:
    """Trigger an on-demand compliance audit of a specific authorization receipt.
    The Auditor queries OWASP NHI Top 10, NIST AI RMF, and NIST SP 800-53 via RAG,
    then uses Gemini 2.5 Pro to reason about whether the authorization decision
    aligns with compliance guidance.

    Returns a signed audit report with verdict (ALIGNED, CONFLICT,
    INSUFFICIENT_EVIDENCE), rationale, and verbatim citations. Use this when you
    need to assess whether a specific authorization decision is compliant, or when
    triggering a fresh audit because a prior verdict seems wrong.

    Note: this invokes Gemini and may take 10-30 seconds. Each audit is
    independently signed and timestamped. Results may vary across runs due to
    model non-determinism.

    Args:
        tenant: Tenant identifier.
        receipt_seq: Sequence number of the receipt to audit.
    """
    result = await _call_agent(
        AUDITOR_REST_URL, "POST", "/audit-receipt",
        json_body={"tenant": tenant, "receipt_seq": receipt_seq},
        timeout=120,
    )
    return json.dumps(result, default=str)


@mcp.tool()
async def auditor_explain_verdict(tenant: str, audit_id: str) -> str:
    """Retrieve a specific audit report by its ID and return the full rationale
    and compliance citations. Use this after auditor_query_audits returns a
    verdict you want to understand in detail — the query endpoint returns the
    full report, but this tool fetches a specific one by ID.

    The response includes the signed audit envelope with body (verdict, rationale,
    citations, receipt_seq, receipt_hash, auditor_kid) and Ed25519 signature.

    Args:
        tenant: Tenant identifier.
        audit_id: UUID of the audit report to retrieve.
    """
    result = await _call_agent(
        AUDITOR_REST_URL, "GET", "/audit-reports",
        params={"tenant": tenant, "since_seq": 0, "limit": 200},
    )
    reports = result.get("reports", [])
    for r in reports:
        if r.get("body", {}).get("audit_id") == audit_id:
            return json.dumps(r, default=str)
    return json.dumps({"error": "NOT_FOUND", "detail": f"Audit report {audit_id} not found for tenant {tenant}"})


# ============================================================================
# RECOMMENDER TOOLS (new — HTTP calls to the Recommender service)
# ============================================================================

@mcp.tool()
async def recommender_query_proposals(
    tenant: str = "default",
    limit: int = 20,
) -> str:
    """Query policy change proposals generated by the Recommender agent. Each proposal
    contains a trigger (the audit pattern that caused it), a proposed policy diff,
    a confidence level (HIGH/MEDIUM/LOW), rationale, and supporting compliance
    citations traced back to specific audit reports.

    Proposals are never auto-applied — they are recommendations for human review.
    Use this to see what policy changes the system is suggesting based on observed
    audit patterns (e.g., repeated CONFLICT verdicts, frequent denials).

    Args:
        tenant: Tenant identifier (default: "default").
        limit: Maximum number of proposals to return (max 100).
    """
    result = await _call_agent(
        RECOMMENDER_REST_URL, "GET", "/proposals",
        params={"tenant": tenant, "limit": min(limit, 100)},
    )
    return json.dumps(result, default=str)


@mcp.tool()
async def recommender_explain_proposal(tenant: str, proposal_id: str) -> str:
    """Retrieve a specific policy proposal by its ID and return the full rationale,
    policy diff, and supporting citations. Use this to understand why a specific
    policy change was proposed and what evidence supports it.

    Args:
        tenant: Tenant identifier.
        proposal_id: UUID of the policy proposal to retrieve.
    """
    result = await _call_agent(
        RECOMMENDER_REST_URL, "GET", "/proposals",
        params={"tenant": tenant, "limit": 100},
    )
    proposals = result.get("proposals", [])
    for p in proposals:
        if p.get("body", {}).get("proposal_id") == proposal_id:
            return json.dumps(p, default=str)
    return json.dumps({"error": "NOT_FOUND", "detail": f"Proposal {proposal_id} not found for tenant {tenant}"})


@mcp.tool()
async def recommender_analyze_patterns(
    tenant: str = "default",
    window_hours: int = 24,
) -> str:
    """Trigger an on-demand analysis of recent audit patterns to identify potential
    policy changes. The Recommender reads recent audit reports, groups them by
    pattern (verdict, action class, resource class, agent frequency), and produces
    concrete policy change proposals when patterns warrant human attention.

    This invokes Gemini 2.5 Pro and may take 30-60 seconds. Use this when you want
    a fresh analysis of current patterns rather than relying on the hourly scheduled
    run. Returns an array of raw proposals (possibly empty if no patterns warrant
    changes).

    Args:
        tenant: Tenant identifier (default: "default").
        window_hours: How many hours of audit history to analyze (default 24).
    """
    result = await _call_agent(
        RECOMMENDER_REST_URL, "POST", "/analyze-patterns",
        json_body={"tenant": tenant, "window_hours": window_hours},
        timeout=180,
    )
    return json.dumps(result, default=str)


# ============================================================================
# INVESTIGATOR TOOLS (new — HTTP calls to the Investigator service)
# ============================================================================

@mcp.tool()
async def investigator_query_incidents(
    tenant: str = "default",
    limit: int = 20,
) -> str:
    """Query incident reports generated by the Investigation Agent. Each report
    contains a severity (CRITICAL/HIGH/MEDIUM/LOW/INFO), an executive summary,
    a chronological timeline of events with evidence references, agents involved,
    compliance impact assessment, root cause hypothesis, and recommended actions.

    Incident reports are triggered by CONFLICT audit verdicts (via Pub/Sub) or
    manual investigation requests. Use this to review security events and
    understand their context.

    Args:
        tenant: Tenant identifier (default: "default").
        limit: Maximum number of incidents to return (max 100).
    """
    result = await _call_agent(
        INVESTIGATOR_REST_URL, "GET", "/incidents",
        params={"tenant": tenant, "limit": min(limit, 100)},
    )
    return json.dumps(result, default=str)


@mcp.tool()
async def investigator_investigate_conflict(
    tenant: str,
    audit_report_id: str,
) -> str:
    """Trigger an on-demand investigation of a specific CONFLICT audit report.
    The Investigator gathers evidence from receipts, audit reports, and agent
    registrations, then uses Gemini 2.5 Pro to synthesize a human-readable
    incident report with timeline, root cause hypothesis, and recommended actions.

    This invokes Gemini and may take 30-90 seconds. Use this when a CONFLICT
    verdict needs deeper analysis — the Investigator cross-references multiple
    data sources that no single agent has access to.

    The resulting incident report is signed with the Investigator's own Ed25519
    key and stored in Firestore.

    Args:
        tenant: Tenant identifier.
        audit_report_id: UUID of the CONFLICT audit report to investigate.
    """
    result = await _call_agent(
        INVESTIGATOR_REST_URL, "POST", "/investigate",
        json_body={
            "tenant": tenant,
            "trigger": {
                "type": "AUDIT_CONFLICT",
                "trigger_id": audit_report_id,
            },
        },
        timeout=180,
    )
    return json.dumps(result, default=str)


@mcp.tool()
async def investigator_explain_incident(tenant: str, incident_id: str) -> str:
    """Retrieve a specific incident report by its ID and return the full narrative,
    timeline, agents involved, compliance impact, root cause hypothesis, and
    recommended actions. Use this to get the complete details of a previously
    generated incident report.

    Args:
        tenant: Tenant identifier.
        incident_id: UUID of the incident report to retrieve.
    """
    result = await _call_agent(
        INVESTIGATOR_REST_URL, "GET", "/incidents",
        params={"tenant": tenant, "limit": 100},
    )
    incidents = result.get("incidents", [])
    for inc in incidents:
        if inc.get("body", {}).get("incident_id") == incident_id:
            return json.dumps(inc, default=str)
    return json.dumps({"error": "NOT_FOUND", "detail": f"Incident {incident_id} not found for tenant {tenant}"})


# ============================================================================
# COORDINATOR TOOLS (new — HTTP calls to the Coordinator service)
# ============================================================================

@mcp.tool()
async def coordinator_route_capability(question: str) -> str:
    """Route a natural-language question to the most capable agent in the directory.
    The Coordinator uses Gemini 2.5 Pro to match the question against registered
    agents' capabilities and returns the best match(es) with confidence scores
    and rationale.

    Use this when you need to find which agent can handle a specific task but
    don't know which one to call. The Coordinator does NOT execute the call —
    it only identifies the right agent. You then call that agent directly.

    Examples: "Authorize a database write for an AI agent" -> Gateway,
    "Verify a receipt's signature" -> Gateway,
    "Get compliance audit results" -> Auditor.

    Args:
        question: Natural-language description of what you need done.
    """
    result = await _call_agent(
        COORDINATOR_REST_URL, "POST", "/route-question",
        json_body={"question": question},
        timeout=60,
    )
    return json.dumps(result, default=str)


@mcp.tool()
async def coordinator_list_known_agents() -> str:
    """List all agents known to the Discovery Coordinator. Returns each agent's
    name, URL, trust level, health status, and AI-assessed capabilities.

    The directory includes both real deployed agents (Gateway, Auditor,
    Recommender, Investigator) and any agents registered via A2A discovery.

    Use this to understand the full agent ecosystem and what capabilities
    are available.
    """
    result = await _call_agent(
        COORDINATOR_REST_URL, "GET", "/directory",
    )
    return json.dumps(result, default=str)


@mcp.tool()
async def coordinator_register_known_agent(agent_card_url: str) -> str:
    """Register a new agent with the Discovery Coordinator by providing its
    A2A agent card URL. The Coordinator fetches the agent card, assesses its
    capabilities using Gemini, and adds it to the directory.

    Use this to expand the agent ecosystem by introducing new A2A-compatible
    agents. The agent card URL should serve a JSON agent card per the A2A spec.

    Args:
        agent_card_url: URL of the agent's A2A agent card (e.g. https://agent.example.com/.well-known/agent.json).
    """
    result = await _call_agent(
        COORDINATOR_REST_URL, "POST", "/discover",
        json_body={"agent_card_url": agent_card_url},
        timeout=60,
    )
    return json.dumps(result, default=str)


# ============================================================================
# ACTIONS REGISTRY TOOLS (HTTP calls to the Gateway REST API)
# ============================================================================

@mcp.tool()
async def actions_query_actions(include_revoked: bool = False, limit: int = 100) -> str:
    """Query the actions registry. Returns registered actions with their risk levels
    and approval requirements.

    Each action has:
    - action_id: canonical identifier (e.g., "read", "delete", "admin")
    - risk_level: low | medium | high | critical
    - requires_human_approval: whether the action needs human-in-the-loop approval

    Args:
        include_revoked: Include revoked actions in results.
        limit: Maximum number of actions to return.
    """
    result = await _call_agent(
        GATEWAY_REST_URL, "GET", "/actions",
        params={"include_revoked": str(include_revoked).lower(), "limit": limit},
    )
    return json.dumps(result, default=str)


@mcp.tool()
async def actions_get_action(action_id: str) -> str:
    """Get a specific registered action by ID, including its risk level,
    human-approval requirement, and metadata.

    Args:
        action_id: The action identifier to look up.
    """
    result = await _call_agent(
        GATEWAY_REST_URL, "GET", f"/actions/{action_id}",
    )
    return json.dumps(result, default=str)


@mcp.tool()
async def actions_register_action(
    action_id: str,
    display_name: str,
    risk_level: str,
    description: str = "",
    requires_human_approval: bool = False,
    metadata: str = "{}",
) -> str:
    """Register a new action in the actions registry.

    action_id: must match [a-zA-Z0-9._/-]{1,256}
    risk_level: one of "low", "medium", "high", "critical"
    requires_human_approval: if true, this action requires external
        human-in-the-loop approval (informational in v0.5)

    Args:
        action_id: Canonical action identifier.
        display_name: Human-readable name for dashboards.
        risk_level: One of low, medium, high, critical.
        description: Optional description of what this action does.
        requires_human_approval: Whether human approval is required.
        metadata: JSON string of additional key-value metadata.
    """
    if risk_level not in ("low", "medium", "high", "critical"):
        return json.dumps({"error": f"invalid risk_level: {risk_level}", "valid_values": ["low", "medium", "high", "critical"]})

    payload: dict = {
        "action_id": action_id,
        "display_name": display_name,
        "description": description,
        "risk_level": risk_level,
        "requires_human_approval": requires_human_approval,
    }
    if metadata and metadata.strip() and metadata.strip() != "{}":
        try:
            payload["metadata"] = json.loads(metadata)
        except json.JSONDecodeError:
            pass

    result = await _call_agent(
        GATEWAY_REST_URL, "POST", "/actions/register",
        json_body=payload,
    )
    return json.dumps(result, default=str)


# ============================================================================
# RESOURCE REGISTRY TOOLS (HTTP calls to the Gateway REST API)
# ============================================================================

@mcp.tool()
async def resources_query_resources(
    include_revoked: bool = False,
    limit: int = 100,
) -> str:
    """Query the resource registry. Returns registered resources with their
    type, owner, reachability status, and metadata.

    Each resource includes:
    - resource_id, display_name, description, owner
    - resource_type: "db" (v0.5; enum is extensible)
    - reachability_url, reachability_verification, reachability_verified_at
    - status: active | revoked

    Args:
        include_revoked: Include revoked resources in results.
        limit: Maximum number of resources to return.
    """
    result = await _call_agent(
        GATEWAY_REST_URL, "GET", "/resources",
        params={"include_revoked": str(include_revoked).lower(), "limit": limit},
    )
    return json.dumps(result, default=str)


@mcp.tool()
async def resources_get_resource(resource_id: str) -> str:
    """Get a specific registered resource by ID, including its type,
    reachability verification status, and full metadata.

    Args:
        resource_id: The resource identifier to look up.
    """
    result = await _call_agent(
        GATEWAY_REST_URL, "GET", f"/resources/{resource_id}",
    )
    return json.dumps(result, default=str)


@mcp.tool()
async def resources_register_resource(
    resource_id: str,
    display_name: str,
    resource_type: str,
    description: str = "",
    owner: str = "",
    reachability_url: str = "",
    metadata: str = "{}",
) -> str:
    """Register a new resource in the resource registry.

    resource_id: must match [a-zA-Z0-9._/-]{1,256}
    resource_type: must be "db" (v0.5 supports db only; enum is extensible)
    reachability_url: optional URL the Gateway will probe at registration
        time to verify the resource is reachable. Verification status is
        recorded but does not block registration.

    Args:
        resource_id: Canonical resource identifier.
        display_name: Human-readable name for dashboards.
        resource_type: One of: db.
        description: Optional description of this resource.
        owner: Team or person identifier.
        reachability_url: Optional URL for reachability verification.
        metadata: JSON string of additional key-value metadata.
    """
    if resource_type not in ("db",):
        return json.dumps({"error": f"invalid resource_type: {resource_type}", "valid_values": ["db"]})

    payload: dict = {
        "resource_id": resource_id,
        "display_name": display_name,
        "resource_type": resource_type,
        "description": description,
        "owner": owner,
    }
    if reachability_url:
        payload["reachability_url"] = reachability_url
    if metadata and metadata.strip() and metadata.strip() != "{}":
        try:
            payload["metadata"] = json.loads(metadata)
        except json.JSONDecodeError:
            pass

    result = await _call_agent(
        GATEWAY_REST_URL, "POST", "/resources/register",
        json_body=payload,
    )
    return json.dumps(result, default=str)


# ============================================================================
# AGENT REGISTRY QUERY TOOLS (HTTP calls to the Gateway REST API)
# Note: register_agent is deliberately excluded from MCP — PoP cannot
# be enforced over bearer-token transport. See removal note above.
# ============================================================================

@mcp.tool()
async def agents_query_agents(include_revoked: bool = False) -> str:
    """Query the agent registry. Returns registered agents with their key IDs,
    registration timestamps, and A2A card verification status.

    Each agent includes:
    - agent_id, kid, registered_at, registered_by, status
    - agent_card_url: URL of the agent's A2A card (if provided at registration)
    - agent_card_verification: verified | failed | skipped
    - agent_card_verified_at: timestamp of last verification

    Args:
        include_revoked: Include revoked agents in results.
    """
    result = await _call_agent(
        GATEWAY_REST_URL, "GET", "/agents",
        params={"include_revoked": str(include_revoked).lower()},
    )
    return json.dumps(result, default=str)


@mcp.tool()
async def agents_get_agent(agent_id: str) -> str:
    """Get a specific registered agent by ID, including its key ID,
    A2A card verification status, and registration details.

    Args:
        agent_id: The agent identifier to look up.
    """
    result = await _call_agent(
        GATEWAY_REST_URL, "GET", f"/agents/{agent_id}",
    )
    return json.dumps(result, default=str)


# --- Entry point ---
if __name__ == "__main__":
    import os
    os.environ.setdefault("FASTMCP_PORT", "8090")
    os.environ.setdefault("FASTMCP_HOST", "0.0.0.0")
    mcp.run(transport="streamable-http")
