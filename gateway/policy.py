"""Policy evaluation engine for agent action authorization.

Supports three rule types:
1. Action allowlist — which actions are permitted
2. Resource scope — which resources an agent can access
3. Rate limiting — maximum actions per time window

Policy can be loaded from a YAML file (POLICY_YAML_PATH env var)
or falls back to the built-in demo policy.
"""

from __future__ import annotations

import logging
import os
from pathlib import Path

import hashlib
import time
from dataclasses import dataclass, field

from .canonical import canonicalize


@dataclass
class PolicyRule:
    """A single policy rule."""
    id: str
    type: str  # "allowlist", "resource_scope", "rate_limit"
    config: dict


@dataclass
class Policy:
    """A collection of policy rules."""
    rules: list[PolicyRule] = field(default_factory=list)
    version: str = "1"
    require_resource_registration: bool = False

    def policy_hash(self) -> str:
        """Compute a deterministic hash of the policy for receipt binding."""
        policy_obj = {
            "v": self.version,
            "rules": [
                {"id": r.id, "type": r.type, "config": r.config}
                for r in self.rules
            ],
        }
        if self.require_resource_registration:
            policy_obj["require_resource_registration"] = True
        body_bytes = canonicalize(policy_obj)
        return "sha256:" + hashlib.sha256(body_bytes).hexdigest()


@dataclass
class EvaluationResult:
    decision: str  # "approve" or "deny"
    reason_codes: list[str]


class PolicyEngine:
    """Evaluates agent action intents against a policy."""

    def __init__(self, policy: Policy):
        self.policy = policy
        self._rate_counters: dict[str, list[float]] = {}

    def evaluate(
        self,
        agent_id: str,
        action: str,
        resource: str,
        parameters: dict | None = None,
        dry_run: bool = False,
    ) -> EvaluationResult:
        """Evaluate an action intent against all policy rules.

        Returns approve only if ALL rules pass. Any rule failure = deny.
        """
        deny_reasons: list[str] = []

        for rule in self.policy.rules:
            if rule.type == "allowlist":
                if not self._check_allowlist(rule, action):
                    deny_reasons.append(f"ACTION_NOT_ALLOWED:{rule.id}")

            elif rule.type == "resource_scope":
                if not self._check_resource_scope(rule, resource):
                    deny_reasons.append(f"RESOURCE_OUT_OF_SCOPE:{rule.id}")

            elif rule.type == "rate_limit":
                if not self._check_rate_limit(rule, agent_id, dry_run=dry_run):
                    deny_reasons.append(f"RATE_LIMIT_EXCEEDED:{rule.id}")

        if deny_reasons:
            return EvaluationResult(decision="deny", reason_codes=deny_reasons)

        return EvaluationResult(decision="approve", reason_codes=[])

    def _check_allowlist(self, rule: PolicyRule, action: str) -> bool:
        allowed = rule.config.get("allowed_actions", [])
        if not allowed:
            return True
        action_lower = action.lower()
        return any(a.lower() == action_lower for a in allowed)

    def _check_resource_scope(self, rule: PolicyRule, resource: str) -> bool:
        allowed_resources = rule.config.get("allowed_resources", [])
        denied_resources = rule.config.get("denied_resources", [])
        resource_lower = resource.lower()

        if denied_resources:
            if any(d.lower() in resource_lower for d in denied_resources):
                return False

        if allowed_resources:
            return any(a.lower() in resource_lower for a in allowed_resources)

        return True

    def _check_rate_limit(self, rule: PolicyRule, agent_id: str, dry_run: bool = False) -> bool:
        max_actions = rule.config.get("max_actions", 100)
        window_seconds = rule.config.get("window_seconds", 60)

        key = f"{agent_id}:{rule.id}"
        now = time.time()
        cutoff = now - window_seconds

        if key not in self._rate_counters:
            self._rate_counters[key] = []

        # Clean old entries
        self._rate_counters[key] = [t for t in self._rate_counters[key] if t > cutoff]

        if len(self._rate_counters[key]) >= max_actions:
            return False

        if not dry_run:
            self._rate_counters[key].append(now)
        return True


def create_demo_policy() -> Policy:
    """Create a demo policy for hackathon demonstration."""
    return Policy(
        version="1",
        rules=[
            PolicyRule(
                id="allowed_actions",
                type="allowlist",
                config={
                    "allowed_actions": [
                        "read",
                        "query",
                        "list",
                        "get",
                        "search",
                        "analyze",
                    ],
                },
            ),
            PolicyRule(
                id="resource_scope",
                type="resource_scope",
                config={
                    "allowed_resources": ["staging", "dev", "sandbox", "test"],
                    "denied_resources": ["production", "prod", "master-key", "admin"],
                },
            ),
            PolicyRule(
                id="rate_limit",
                type="rate_limit",
                config={
                    "max_actions": 10,
                    "window_seconds": 60,
                },
            ),
        ],
    )


logger = logging.getLogger("gateway.policy")

_KNOWN_RULE_TYPES = {"allowlist", "resource_scope", "rate_limit"}


def load_policy_from_yaml(path: str) -> Policy:
    """Load a Policy from a YAML file.

    Raises ValueError if the YAML is malformed, missing required fields,
    or contains unknown rule types. Never silently falls back to a
    permissive policy on error.
    """
    import yaml

    yaml_path = Path(path)
    if not yaml_path.exists():
        raise ValueError(
            f"Policy YAML not found at {path}. "
            f"Either provide the file or unset POLICY_YAML_PATH "
            f"to use the built-in demo policy."
        )

    try:
        with yaml_path.open() as f:
            data = yaml.safe_load(f)
    except yaml.YAMLError as e:
        raise ValueError(f"Policy YAML at {path} failed to parse: {e}") from e

    if not isinstance(data, dict):
        raise ValueError(
            f"Policy YAML at {path} must be a mapping at the top level, "
            f"got {type(data).__name__}"
        )

    version = data.get("version")
    if version is None:
        raise ValueError("Policy YAML missing required field: version")

    rules_data = data.get("rules")
    if not isinstance(rules_data, list):
        raise ValueError(
            f"Policy YAML 'rules' must be a list, got {type(rules_data).__name__}"
        )

    rules = []
    for i, rule_data in enumerate(rules_data):
        if not isinstance(rule_data, dict):
            raise ValueError(f"Rule {i} must be a mapping")
        rule_id = rule_data.get("id")
        rule_type = rule_data.get("type")
        rule_config = rule_data.get("config", {})

        if rule_id is None or rule_type is None:
            raise ValueError(f"Rule {i} missing required field: id or type")
        if rule_type not in _KNOWN_RULE_TYPES:
            raise ValueError(
                f"Rule {i} has unknown type: {rule_type!r}. "
                f"Known types: {sorted(_KNOWN_RULE_TYPES)}"
            )

        rules.append(PolicyRule(id=rule_id, type=rule_type, config=rule_config))

    require_resource_registration = bool(data.get("require_resource_registration", False))
    return Policy(version=str(version), rules=rules, require_resource_registration=require_resource_registration)


def get_active_policy() -> Policy:
    """Return the active policy for this Gateway instance.

    If POLICY_YAML_PATH is set, loads from that file.
    Otherwise falls back to the built-in demo policy.

    Loading failures raise — the Gateway will not start with a broken
    policy configuration.
    """
    yaml_path = os.environ.get("POLICY_YAML_PATH")
    if yaml_path:
        policy = load_policy_from_yaml(yaml_path)
        logger.info("Loaded policy from YAML: %s (version=%s, rules=%d, hash=%s)",
                    yaml_path, policy.version, len(policy.rules), policy.policy_hash()[:32])
        return policy
    policy = create_demo_policy()
    logger.info("Using built-in demo policy (version=%s, rules=%d, hash=%s)",
                policy.version, len(policy.rules), policy.policy_hash()[:32])
    return policy
