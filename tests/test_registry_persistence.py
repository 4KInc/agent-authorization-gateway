"""Regression tests for agent registry Firestore persistence.

The original bug: AgentRegistry accepted a firestore_db kwarg but
ignored it. Registrations were in-memory only and lost on cold starts.
These tests ensure the fix holds.
"""

import base64

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from gateway.identity import AgentRegistry


def _make_jwk(key=None):
    if key is None:
        key = Ed25519PrivateKey.generate()
    pub_bytes = key.public_key().public_bytes_raw()
    x = base64.urlsafe_b64encode(pub_bytes).rstrip(b"=").decode()
    return {"kty": "OKP", "crv": "Ed25519", "x": x}


# ---------------------------------------------------------------------------
# Minimal Firestore mock that retains state across AgentRegistry instances
# ---------------------------------------------------------------------------

class _FakeDoc:
    def __init__(self, store, path, doc_id):
        self._store = store
        self._path = path
        self._id = doc_id

    def collection(self, name):
        """Support subcollection chaining: .document(x).collection(y)."""
        return _FakeCollection(self._store, f"{self._path}/{self._id}/{name}")

    def set(self, data):
        self._store.setdefault(self._path, {})[self._id] = dict(data)

    def get(self):
        data = self._store.get(self._path, {}).get(self._id)
        return _FakeSnapshot(self._id, data)

    def delete(self):
        self._store.get(self._path, {}).pop(self._id, None)


class _FakeSnapshot:
    def __init__(self, doc_id, data):
        self.id = doc_id
        self.exists = data is not None
        self._data = data

    def to_dict(self):
        return self._data


class _FakeCollection:
    def __init__(self, store, path):
        self._store = store
        self._path = path

    def document(self, doc_id):
        return _FakeDoc(self._store, self._path, doc_id)

    def stream(self):
        for doc_id, data in self._store.get(self._path, {}).items():
            yield _FakeSnapshot(doc_id, data)


class _FakeFirestore:
    """In-memory stand-in for google.cloud.firestore.Client."""
    def __init__(self):
        self._store = {}

    def collection(self, path):
        return _FakeCollection(self._store, path)


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

def test_agent_persists_across_registry_reinit():
    """Cold start regression: second AgentRegistry instance sees the agent."""
    db = _FakeFirestore()
    jwk = _make_jwk()

    # First "process"
    reg1 = AgentRegistry(tenant="test-tenant", firestore_db=db)
    agent = reg1.register("persist-agent", jwk)
    assert reg1.get("persist-agent") is not None

    # Second "process" — fresh instance, same Firestore
    reg2 = AgentRegistry(tenant="test-tenant", firestore_db=db)
    assert reg2.get("persist-agent") is None  # not yet loaded
    loaded = reg2.load_all()
    assert loaded == 1
    restored = reg2.get("persist-agent")
    assert restored is not None
    assert restored.kid == agent.kid
    assert restored.agent_id == "persist-agent"


def test_revoke_deletes_from_firestore():
    """Revoking an agent removes it from both memory and Firestore."""
    db = _FakeFirestore()
    jwk = _make_jwk()

    reg = AgentRegistry(tenant="test-tenant", firestore_db=db)
    reg.register("revoke-agent", jwk)
    reg.revoke("revoke-agent")

    # Fresh instance — agent should NOT be loadable
    reg2 = AgentRegistry(tenant="test-tenant", firestore_db=db)
    loaded = reg2.load_all()
    assert loaded == 0
    assert reg2.get("revoke-agent") is None


def test_replace_semantics_persist_latest_key():
    """Re-registration replaces the key in Firestore."""
    db = _FakeFirestore()
    jwk1 = _make_jwk()
    jwk2 = _make_jwk()

    reg = AgentRegistry(tenant="test-tenant", firestore_db=db)
    agent1 = reg.register("replace-agent", jwk1)
    agent2 = reg.register("replace-agent", jwk2)
    assert agent1.kid != agent2.kid

    # Fresh instance should see the LATEST key
    reg2 = AgentRegistry(tenant="test-tenant", firestore_db=db)
    reg2.load_all()
    restored = reg2.get("replace-agent")
    assert restored is not None
    assert restored.kid == agent2.kid


def test_no_firestore_still_works():
    """Without Firestore, the registry works in-memory (tests, local dev)."""
    reg = AgentRegistry(tenant="test-tenant")
    jwk = _make_jwk()
    agent = reg.register("memory-agent", jwk)
    assert reg.get("memory-agent") is not None
    assert agent.kid.startswith("agent-")

    reg.revoke("memory-agent")
    assert reg.get("memory-agent") is None


def test_firestore_write_failure_does_not_block_registration():
    """If Firestore is unreachable, registration still succeeds in memory."""
    class _FailingFirestore:
        def collection(self, path):
            raise Exception("simulated outage")

    reg = AgentRegistry(tenant="test-tenant", firestore_db=_FailingFirestore())
    jwk = _make_jwk()
    agent = reg.register("resilient-agent", jwk)
    assert reg.get("resilient-agent") is not None
    assert agent.kid.startswith("agent-")


def test_load_all_skips_invalid_entries():
    """Corrupt entries in Firestore are skipped, not fatal."""
    db = _FakeFirestore()
    # Seed a valid agent
    jwk = _make_jwk()
    reg = AgentRegistry(tenant="test-tenant", firestore_db=db)
    reg.register("good-agent", jwk)

    # Manually inject a corrupt entry
    path = "tenants/test-tenant/agent_registry"
    db._store.setdefault(path, {})["bad-agent"] = {"agent_id": "bad-agent"}  # missing public_key_jwk

    # Fresh load should get 1 (good) and skip 1 (bad)
    reg2 = AgentRegistry(tenant="test-tenant", firestore_db=db)
    loaded = reg2.load_all()
    assert loaded == 1
    assert reg2.get("good-agent") is not None
    assert reg2.get("bad-agent") is None


def test_live_challenge_url_persisted():
    """live_challenge_url round-trips through Firestore."""
    db = _FakeFirestore()
    jwk = _make_jwk()

    reg = AgentRegistry(tenant="test-tenant", firestore_db=db)
    reg.register("liveness-agent", jwk, live_challenge_url="https://agent.example.com/lc")

    reg2 = AgentRegistry(tenant="test-tenant", firestore_db=db)
    reg2.load_all()
    restored = reg2.get("liveness-agent")
    assert restored is not None
    assert restored.live_challenge_url == "https://agent.example.com/lc"


def test_tenant_isolation():
    """Agents registered under one tenant are not visible to another."""
    db = _FakeFirestore()
    jwk = _make_jwk()

    reg_a = AgentRegistry(tenant="tenant-a", firestore_db=db)
    reg_a.register("shared-name", jwk)

    reg_b = AgentRegistry(tenant="tenant-b", firestore_db=db)
    loaded = reg_b.load_all()
    assert loaded == 0
    assert reg_b.get("shared-name") is None
