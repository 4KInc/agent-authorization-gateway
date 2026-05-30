"""Fetch and validate A2A agent cards from /.well-known/agent.json endpoints.

Determines trust_level based on:
- Agent card schema validity
- TLS certificate validity (HTTPS required for TRUSTED)
- Domain alignment between card URL and card's declared interfaces
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Dict, Optional
from urllib.parse import urlparse

import httpx

logger = logging.getLogger(__name__)

REQUIRED_CARD_FIELDS = {"name", "description", "skills", "version"}


def _validate_agent_card(card: Dict) -> list[str]:
    """Return list of validation errors (empty = valid)."""
    errors = []
    for field in REQUIRED_CARD_FIELDS:
        if field not in card:
            errors.append(f"missing required field: {field}")
    if "skills" in card and not isinstance(card["skills"], list):
        errors.append("skills must be a list")
    return errors


def _check_domain_alignment(card_url: str, card: Dict) -> bool:
    """Check that the agent card's interfaces match the hosting domain."""
    card_domain = urlparse(card_url).hostname
    interfaces = card.get("supported_interfaces") or card.get("supportedInterfaces") or []
    if not interfaces:
        return True  # No interfaces declared, no mismatch possible
    for iface in interfaces:
        url = iface.get("url", "") if isinstance(iface, dict) else ""
        if url:
            iface_domain = urlparse(url).hostname
            if iface_domain and iface_domain != card_domain:
                return False
    return True


def _extract_skills(card: Dict) -> list[str]:
    """Extract skill names/ids from an agent card."""
    skills = card.get("skills", [])
    result = []
    for s in skills:
        if isinstance(s, dict):
            result.append(s.get("id") or s.get("name", "unknown"))
        elif isinstance(s, str):
            result.append(s)
    return result


def discover_agent(
    agent_card_url: str,
    introducer: Optional[str] = None,
    discovery_method: str = "manual",
) -> Dict:
    """Fetch an agent card and build an AgentDirectoryEntry.

    Returns the entry dict ready for Firestore storage.
    Does NOT populate ai_assessed_capabilities — that's done separately
    by the AI layer after this function returns.
    """
    now = datetime.now(timezone.utc).isoformat()

    # Fetch the agent card
    try:
        resp = httpx.get(agent_card_url, timeout=15, follow_redirects=True)
        resp.raise_for_status()
        card = resp.json()
    except httpx.HTTPStatusError as e:
        logger.warning("HTTP error fetching %s: %s", agent_card_url, e)
        return _unreachable_entry(agent_card_url, now, introducer, discovery_method,
                                  f"HTTP {e.response.status_code}")
    except Exception as e:
        logger.warning("Failed to fetch agent card from %s: %s", agent_card_url, e)
        return _unreachable_entry(agent_card_url, now, introducer, discovery_method, str(e))

    # Validate
    validation_errors = _validate_agent_card(card)
    is_https = agent_card_url.startswith("https://")
    domain_ok = _check_domain_alignment(agent_card_url, card)

    if not validation_errors and is_https and domain_ok:
        trust_level = "TRUSTED"
        health_status = "healthy"
    elif not validation_errors:
        trust_level = "REVIEW"
        health_status = "healthy"
    else:
        trust_level = "REVIEW"
        health_status = "degraded"

    return {
        "discovered_at": now,
        "agent_card_url": agent_card_url,
        "agent_card": card,
        "last_health_check": now,
        "health_status": health_status,
        "self_described_skills": _extract_skills(card),
        "ai_assessed_capabilities": "",  # Populated separately by Gemini
        "trust_level": trust_level,
        "discovery_metadata": {
            "discovered_via": discovery_method,
            "introducer": introducer,
            "validation_errors": validation_errors,
        },
    }


def _unreachable_entry(url, now, introducer, method, error_detail):
    return {
        "discovered_at": now,
        "agent_card_url": url,
        "agent_card": {},
        "last_health_check": now,
        "health_status": "unreachable",
        "self_described_skills": [],
        "ai_assessed_capabilities": "",
        "trust_level": "REVIEW",
        "discovery_metadata": {
            "discovered_via": method,
            "introducer": introducer,
            "error": error_detail,
        },
    }


def health_check(agent_card_url: str) -> str:
    """Quick health check — returns 'healthy', 'degraded', or 'unreachable'."""
    try:
        resp = httpx.get(agent_card_url, timeout=10, follow_redirects=True)
        if resp.status_code == 200:
            return "healthy"
        return "degraded"
    except Exception:
        return "unreachable"
