"""Policy evaluation engine for agent action authorization.

Supports three rule types:
1. Action allowlist — which actions are permitted
2. Resource scope — which resources an agent can access
3. Rate limiting — maximum actions per time window
"""

from __future__ import annotations

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

    def policy_hash(self) -> str:
        """Compute a deterministic hash of the policy for receipt binding."""
        policy_obj = {
            "v": self.version,
            "rules": [
                {"id": r.id, "type": r.type, "config": r.config}
                for r in self.rules
            ],
        }
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
                if not self._check_rate_limit(rule, agent_id):
                    deny_reasons.append(f"RATE_LIMIT_EXCEEDED:{rule.id}")

        if deny_reasons:
            return EvaluationResult(decision="deny", reason_codes=deny_reasons)

        return EvaluationResult(decision="approve", reason_codes=[])

    def _check_allowlist(self, rule: PolicyRule, action: str) -> bool:
        allowed = rule.config.get("allowed_actions", [])
        if not allowed:
            return True
        action_lower = action.lower()
        return any(a.lower() in action_lower for a in allowed)

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

    def _check_rate_limit(self, rule: PolicyRule, agent_id: str) -> bool:
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
