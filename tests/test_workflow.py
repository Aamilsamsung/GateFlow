"""Local-only flow checks for demo backend; NOT a production security certification."""
import importlib
import os
import sys

import pytest
from fastapi.testclient import TestClient


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{tmp_path / 'test.db'}")
    monkeypatch.setenv("GATEFLOW_DEMO_SECRET", "local-test-secret")
    sys.modules.pop("app.main", None)
    main = importlib.import_module("app.main")
    main.POLICIES.clear()
    with TestClient(main.app) as test_client:
        yield test_client


def headers(role, identity, tenant="pes"):
    return {"X-Demo-Auth": f"{tenant}:{role}:{identity}:local-test-secret"}


def test_default_requires_warden_and_full_flow(client):
    payload = {
        "guardian": "guardian1", "destination": "home", "reason": "weekend",
        "departure": "2030-01-01T09:00:00", "expected_return": "2030-01-02T19:00:00",
    }
    res = client.post("/leaves", headers=headers("student", "student1"), json=payload)
    assert res.status_code == 201, res.text
    leave_id = res.json()["id"]
    assert client.post(
        f"/leaves/{leave_id}/parent-decision",
        headers=headers("parent", "not-guardian"), json={"approve": True},
    ).status_code == 403
    res = client.post(
        f"/leaves/{leave_id}/parent-decision",
        headers=headers("parent", "guardian1"), json={"approve": True},
    )
    assert res.json()["status"] == "pending_warden"
    assert client.get(
        f"/leaves/{leave_id}/pass", headers=headers("student", "student1")
    ).status_code == 409
    res = client.post(
        f"/leaves/{leave_id}/warden-decision",
        headers=headers("warden", "warden1"), json={"approve": True},
    )
    assert res.json()["status"] == "approved"
    token = client.get(
        f"/leaves/{leave_id}/pass", headers=headers("student", "student1")
    ).json()["token"]
    assert client.post(
        "/gate/scan", headers=headers("student", "student1"),
        json={"token": token, "action": "exit"},
    ).status_code == 403
    res = client.post(
        "/gate/scan", headers=headers("security", "guard1"),
        json={"token": token, "action": "exit"},
    )
    assert res.json()["status"] == "outside"
    assert client.post(
        "/gate/scan", headers=headers("security", "guard1"),
        json={"token": token, "action": "exit"},
    ).status_code == 409
    res = client.post(
        "/gate/scan", headers=headers("security", "guard1"),
        json={"token": token, "action": "return"},
    )
    assert res.json()["status"] == "returned"
    assert client.get(
        "/leaves", headers=headers("warden", "warden1", tenant="other-hostel")
    ).json() == []
    assert client.post(
        "/gate/scan", headers=headers("security", "guard2", tenant="other-hostel"),
        json={"token": token, "action": "exit"},
    ).status_code == 404


def test_demo_secret_required(client):
    assert client.get("/leaves").status_code == 401
    assert client.get("/leaves", headers={
        "X-Demo-Auth": "pes:student:student1:wrong"
    }).status_code == 401
