"""Tests for the Resource Registry (gateway/resources.py).

Uses in-memory mode (no Firestore) for all tests.
"""

import base64

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from gateway.resources import ResourceConflict, ResourceRegistry, validate_resource_id


class TestResourceIdValidation:
    def test_valid_ids(self):
        for rid in ["staging-db", "gcp.cloudsql.staging.customers", "my/resource/path", "a", "A_b-c.d/e"]:
            validate_resource_id(rid)  # should not raise

    def test_empty_rejected(self):
        with pytest.raises(ValueError, match="resource_id must match"):
            validate_resource_id("")

    def test_too_long_rejected(self):
        with pytest.raises(ValueError):
            validate_resource_id("a" * 257)

    def test_invalid_chars_rejected(self):
        for rid in ["has space", "has@sign", "has:colon", "has;semi", "has#hash"]:
            with pytest.raises(ValueError, match="resource_id must match"):
                validate_resource_id(rid)

    def test_special_allowed_chars(self):
        validate_resource_id("period.slash/hyphen-underscore_")


class TestResourceRegistry:
    def _make_registry(self, tenant="test-tenant"):
        return ResourceRegistry(tenant_id=tenant)

    def test_register_basic(self):
        reg = self._make_registry()
        result = reg.register("staging-db", display_name="Staging Database")
        assert result["resource_id"] == "staging-db"
        assert result["status"] == "active"
        assert result["tenant_id"] == "test-tenant"
        assert result["version"] == 1
        assert result["provenance"] == "manual"
        assert result["display_name"] == "Staging Database"

    def test_register_missing_display_name(self):
        reg = self._make_registry()
        with pytest.raises(ValueError, match="display_name is required"):
            reg.register("staging-db", display_name="")

    def test_register_invalid_id(self):
        reg = self._make_registry()
        with pytest.raises(ValueError, match="resource_id must match"):
            reg.register("bad id!", display_name="Bad")

    def test_duplicate_active_raises_conflict(self):
        reg = self._make_registry()
        reg.register("staging-db", display_name="DB")
        with pytest.raises(ResourceConflict, match="already registered"):
            reg.register("staging-db", display_name="DB Again")

    def test_re_register_after_revocation(self):
        reg = self._make_registry()
        reg.register("staging-db", display_name="DB v1")
        reg.revoke("staging-db")
        result = reg.register("staging-db", display_name="DB v2")
        assert result["status"] == "active"
        assert result["version"] == 2
        assert result["display_name"] == "DB v2"

    def test_revoke(self):
        reg = self._make_registry()
        reg.register("staging-db", display_name="DB")
        result = reg.revoke("staging-db", revoked_by="admin")
        assert result["status"] == "revoked"
        assert result["revoked_by"] == "admin"
        assert result["revoked_at"] is not None

    def test_revoke_nonexistent_raises(self):
        reg = self._make_registry()
        with pytest.raises(ValueError, match="not actively registered"):
            reg.revoke("nonexistent")

    def test_revoke_already_revoked_raises(self):
        reg = self._make_registry()
        reg.register("staging-db", display_name="DB")
        reg.revoke("staging-db")
        with pytest.raises(ValueError, match="not actively registered"):
            reg.revoke("staging-db")

    def test_get(self):
        reg = self._make_registry()
        assert reg.get("staging-db") is None
        reg.register("staging-db", display_name="DB")
        result = reg.get("staging-db")
        assert result is not None
        assert result["resource_id"] == "staging-db"

    def test_is_registered_and_active(self):
        reg = self._make_registry()
        assert reg.is_registered_and_active("staging-db") is False
        reg.register("staging-db", display_name="DB")
        assert reg.is_registered_and_active("staging-db") is True
        reg.revoke("staging-db")
        assert reg.is_registered_and_active("staging-db") is False

    def test_list_all_active_only(self):
        reg = self._make_registry()
        reg.register("a-db", display_name="A")
        reg.register("b-db", display_name="B")
        reg.register("c-db", display_name="C")
        reg.revoke("b-db")
        resources, cursor = reg.list_all(include_revoked=False)
        ids = [r["resource_id"] for r in resources]
        assert "a-db" in ids
        assert "c-db" in ids
        assert "b-db" not in ids

    def test_list_all_include_revoked(self):
        reg = self._make_registry()
        reg.register("a-db", display_name="A")
        reg.register("b-db", display_name="B")
        reg.revoke("b-db")
        resources, _ = reg.list_all(include_revoked=True)
        ids = [r["resource_id"] for r in resources]
        assert "a-db" in ids
        assert "b-db" in ids

    def test_pagination(self):
        reg = self._make_registry()
        for i in range(5):
            reg.register(f"r{i:02d}", display_name=f"R{i}")

        page1, cursor1 = reg.list_all(limit=2)
        assert len(page1) == 2
        assert cursor1 is not None

        page2, cursor2 = reg.list_all(limit=2, cursor=cursor1)
        assert len(page2) == 2

        page3, cursor3 = reg.list_all(limit=2, cursor=cursor2)
        assert len(page3) == 1
        assert cursor3 is None

        all_ids = [r["resource_id"] for r in page1 + page2 + page3]
        assert len(set(all_ids)) == 5

    def test_update_metadata(self):
        reg = self._make_registry()
        reg.register("staging-db", display_name="DB", description="old")
        result = reg.update_metadata("staging-db", display_name="New Name", description="new desc")
        assert result["display_name"] == "New Name"
        assert result["description"] == "new desc"
        assert result["version"] == 2

    def test_update_nonexistent_raises(self):
        reg = self._make_registry()
        with pytest.raises(ValueError, match="not found"):
            reg.update_metadata("nonexistent", display_name="X")

    def test_update_revoked_raises(self):
        reg = self._make_registry()
        reg.register("staging-db", display_name="DB")
        reg.revoke("staging-db")
        with pytest.raises(ValueError, match="revoked"):
            reg.update_metadata("staging-db", display_name="X")

    def test_cache_invalidation_on_revoke(self):
        reg = self._make_registry()
        reg.register("staging-db", display_name="DB")
        assert reg.is_registered_and_active("staging-db") is True
        reg.revoke("staging-db")
        # Cache should be updated immediately
        assert reg.is_registered_and_active("staging-db") is False

    def test_cache_invalidation_on_register(self):
        reg = self._make_registry()
        assert reg.is_registered_and_active("staging-db") is False
        reg.register("staging-db", display_name="DB")
        assert reg.is_registered_and_active("staging-db") is True

    def test_register_with_all_fields(self):
        reg = self._make_registry()
        result = reg.register(
            "gcp.cloudsql.staging.customers",
            display_name="Staging Customers DB",
            description="Cloud SQL instance for staging",
            resource_type="database",
            owner="platform-team",
            metadata={"sensitivity": "internal", "compliance": ["SOC2"]},
            registered_by="admin@corp.com",
            provenance="manual",
        )
        assert result["resource_type"] == "database"
        assert result["owner"] == "platform-team"
        assert result["metadata"]["sensitivity"] == "internal"
        assert result["registered_by"] == "admin@corp.com"

    def test_tenant_isolation(self):
        reg_a = self._make_registry("tenant-a")
        reg_b = self._make_registry("tenant-b")
        reg_a.register("shared-name", display_name="A's resource")
        reg_b.register("shared-name", display_name="B's resource")
        assert reg_a.is_registered_and_active("shared-name") is True
        assert reg_b.is_registered_and_active("shared-name") is True
        reg_a.revoke("shared-name")
        assert reg_a.is_registered_and_active("shared-name") is False
        assert reg_b.is_registered_and_active("shared-name") is True


class TestResourceRegistrationEnforcement:
    """Test that require_resource_registration integrates correctly with authorize."""

    def _make_gateway(self, require_registration=False):
        from gateway.gateway_service import GatewayService
        from gateway.policy import Policy, PolicyRule
        from gateway.identity import AgentRegistry
        policy = Policy(
            version="1",
            rules=[
                PolicyRule(id="allowed_actions", type="allowlist",
                           config={"allowed_actions": ["read", "query"]}),
                PolicyRule(id="resource_scope", type="resource_scope",
                           config={"allowed_resources": ["staging"], "denied_resources": ["prod"]}),
            ],
            require_resource_registration=require_registration,
        )
        gw = GatewayService(tenant="test", policy=policy)
        return gw

    def _register_agent(self, gw, agent_id="test-agent"):
        key = Ed25519PrivateKey.generate()
        pub_bytes = key.public_key().public_bytes_raw()
        jwk = {"kty": "OKP", "crv": "Ed25519",
               "x": base64.urlsafe_b64encode(pub_bytes).rstrip(b"=").decode()}
        gw._registry.register(agent_id, jwk)
        return key

    def _make_proof(self, key, agent_id, action, resource):
        from gateway.identity import create_agent_proof
        return create_agent_proof(key, agent_id, action, resource)

    def test_permissive_mode_no_registration_needed(self):
        gw = self._make_gateway(require_registration=False)
        key = self._register_agent(gw)
        proof = self._make_proof(key, "test-agent", "read", "staging-db")
        resp = gw.authorize("test-agent", "read", "staging-db", agent_proof=proof)
        assert resp.decision == "approve"
        # resource_registration_id should be None since resource is not registered
        body = resp.receipt["body"]
        assert "resource_registration_id" not in body

    def test_permissive_mode_with_registered_resource(self):
        gw = self._make_gateway(require_registration=False)
        key = self._register_agent(gw)
        gw._resource_registry.register("staging-db", display_name="Staging DB")
        proof = self._make_proof(key, "test-agent", "read", "staging-db")
        resp = gw.authorize("test-agent", "read", "staging-db", agent_proof=proof)
        assert resp.decision == "approve"
        body = resp.receipt["body"]
        assert body["resource_registration_id"] == "staging-db"

    def test_strict_mode_unregistered_resource_denied(self):
        gw = self._make_gateway(require_registration=True)
        key = self._register_agent(gw)
        proof = self._make_proof(key, "test-agent", "read", "staging-db")
        resp = gw.authorize("test-agent", "read", "staging-db", agent_proof=proof)
        assert resp.decision == "deny"
        assert "RESOURCE_NOT_REGISTERED" in resp.reason_codes

    def test_strict_mode_registered_resource_approved(self):
        gw = self._make_gateway(require_registration=True)
        key = self._register_agent(gw)
        gw._resource_registry.register("staging-db", display_name="Staging DB")
        proof = self._make_proof(key, "test-agent", "read", "staging-db")
        resp = gw.authorize("test-agent", "read", "staging-db", agent_proof=proof)
        assert resp.decision == "approve"
        body = resp.receipt["body"]
        assert body["resource_registration_id"] == "staging-db"

    def test_strict_mode_revoked_resource_denied(self):
        gw = self._make_gateway(require_registration=True)
        key = self._register_agent(gw)
        gw._resource_registry.register("staging-db", display_name="Staging DB")
        gw._resource_registry.revoke("staging-db")
        proof = self._make_proof(key, "test-agent", "read", "staging-db")
        resp = gw.authorize("test-agent", "read", "staging-db", agent_proof=proof)
        assert resp.decision == "deny"
        assert "RESOURCE_NOT_REGISTERED" in resp.reason_codes

    def test_receipt_chain_integrity_with_mixed_receipts(self):
        """Verify that receipts with and without resource_registration_id chain correctly."""
        from gateway.verify import verify_chain
        gw = self._make_gateway(require_registration=False)
        key = self._register_agent(gw)

        # Receipt 1: no resource registration
        proof1 = self._make_proof(key, "test-agent", "read", "staging-db")
        gw.authorize("test-agent", "read", "staging-db", agent_proof=proof1)

        # Register resource
        gw._resource_registry.register("staging-db", display_name="Staging DB")

        # Receipt 2: with resource registration
        from gateway import identity
        identity._proof_jti_cache.clear()
        proof2 = self._make_proof(key, "test-agent", "read", "staging-db")
        gw.authorize("test-agent", "read", "staging-db", agent_proof=proof2)

        # Verify the mixed chain
        chain = gw.get_receipt_chain()
        jwk = gw.get_public_key_jwk()
        result = verify_chain(chain, jwk)
        assert result.receipt_integrity == "PASS"
        assert result.chain_validity == "PASS"
        assert result.errors == []

        # Verify first receipt has no resource_registration_id
        assert "resource_registration_id" not in chain[0]["body"]
        # Second receipt has it
        assert chain[1]["body"]["resource_registration_id"] == "staging-db"
