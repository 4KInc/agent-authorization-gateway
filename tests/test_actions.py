"""Tests for the Actions Registry with resource_type scoping."""

import os
os.environ["FIRESTORE_ENABLED"] = ""

from fastapi.testclient import TestClient
from gateway.api import api_app

client = TestClient(api_app)


def test_register_action_requires_resource_type():
    resp = client.post("/actions/register", json={
        "action_id": "test-no-rt",
        "display_name": "Test",
        "risk_level": "low",
    })
    assert resp.status_code == 422


def test_register_action_rejects_invalid_resource_type():
    resp = client.post("/actions/register", json={
        "action_id": "test-bad-rt",
        "display_name": "Test",
        "risk_level": "low",
        "resource_type": "spaceship",
    })
    assert resp.status_code == 422


def test_register_action_with_db_resource_type():
    resp = client.post("/actions/register", json={
        "action_id": "test-db-action",
        "display_name": "Test DB Action",
        "risk_level": "low",
        "resource_type": "db",
    })
    assert resp.status_code == 200
    data = resp.json()
    assert data["resource_type"] == "db"
    assert data["action_id"] == "test-db-action"


def test_register_action_requires_risk_level():
    resp = client.post("/actions/register", json={
        "action_id": "test-no-risk",
        "display_name": "Test",
        "resource_type": "db",
    })
    assert resp.status_code == 422


def test_register_action_rejects_invalid_risk_level():
    resp = client.post("/actions/register", json={
        "action_id": "test-bad-risk",
        "display_name": "Test",
        "risk_level": "extreme",
        "resource_type": "db",
    })
    assert resp.status_code == 422


def test_list_actions_with_resource_type_filter():
    # Register an action to ensure at least one exists
    client.post("/actions/register", json={
        "action_id": "filter-test",
        "display_name": "Filter Test",
        "risk_level": "medium",
        "resource_type": "db",
    })
    resp = client.get("/actions?resource_type=db")
    assert resp.status_code == 200
    # All returned actions should have resource_type=db
    for a in resp.json()["actions"]:
        assert a.get("resource_type") == "db"


def test_get_action_with_resource_type():
    client.post("/actions/register", json={
        "action_id": "get-rt-test",
        "display_name": "Get RT Test",
        "risk_level": "high",
        "resource_type": "db",
    })
    resp = client.get("/actions/get-rt-test?resource_type=db")
    assert resp.status_code == 200
    assert resp.json()["action_id"] == "get-rt-test"
    assert resp.json()["resource_type"] == "db"


def test_get_action_without_resource_type_falls_back():
    """Without resource_type, get should still find the action."""
    client.post("/actions/register", json={
        "action_id": "fallback-test",
        "display_name": "Fallback",
        "risk_level": "low",
        "resource_type": "db",
    })
    resp = client.get("/actions/fallback-test")
    assert resp.status_code == 200
    assert resp.json()["action_id"] == "fallback-test"
