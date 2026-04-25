"""
Tests for GET /audit and GET /audit/verify routes.

(REQ-P0-P6-005, DEC-AUDIT-P6-001, DEC-AUDIT-P6-002)

Uses FastAPI TestClient with real in-memory SQLite via monkeypatching of the
module-level singletons in agent.main (_db, _settings, _audit_hmac_key).
No internal modules are mocked — only the module-level state is injected.
"""

import os
import sqlite3
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient

import agent.main as _main
from agent.auth import generate_token, hash_password
from agent.models import (
    init_db,
    insert_user,
    insert_user_token,
)
from agent.audit import record_audit

# ---------------------------------------------------------------------------
# Test HMAC key
# ---------------------------------------------------------------------------

_TEST_KEY = b"test-audit-key-for-pytest-routes"

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def db(tmp_path):
    """Real SQLite connection with full Phase 6 schema."""
    conn = init_db(str(tmp_path / "routes_test.db"))
    yield conn
    conn.close()


def _make_user_and_token(db, username, role):
    """Insert user + token; return (raw_token, user_id)."""
    ph = hash_password("pw")
    uid = insert_user(db, username, ph, role)
    raw, h = generate_token()
    insert_user_token(db, uid, h, f"{username}-tok")
    return raw, uid


def _settings_multi(token=""):
    """SimpleNamespace mimicking Settings with multi auth mode."""
    return SimpleNamespace(
        shaferhund_token=token,
        shaferhund_auth_mode="multi",
        shaferhund_audit_key="",
        sigmac_available=False,
        sigmac_version=None,
        cloudtrail_enabled=False,
        AUTO_DEPLOY_ENABLED=False,
        triage_hourly_budget=20,
    )


@pytest.fixture()
def client(db):
    """TestClient wired to a real DB in multi auth mode with test HMAC key.

    Uses patch.object on module-level singletons rather than TestClient lifespan
    context manager so the lifespan doesn't try to create /data (permission error).
    Same pattern as test_role_middleware.py / test_main_auth_modes.py.
    # @mock-exempt: patch.object targets module-level singletons populated by
    #               lifespan() — equivalent to dependency injection at app boundary.
    """
    from unittest.mock import patch
    settings = _settings_multi()
    with (
        patch.object(_main, "_db", db),
        patch.object(_main, "_settings", settings),
        patch.object(_main, "_audit_hmac_key", _TEST_KEY),
        patch.object(_main, "_triage_queue", None),
        patch.object(_main, "_poller_healthy", True),
    ):
        yield TestClient(_main.app, raise_server_exceptions=True)


@pytest.fixture()
def admin_token(db):
    raw, _ = _make_user_and_token(db, "admin1", "admin")
    return raw


@pytest.fixture()
def operator_token(db):
    raw, _ = _make_user_and_token(db, "op1", "operator")
    return raw


@pytest.fixture()
def viewer_token(db):
    raw, _ = _make_user_and_token(db, "viewer1", "viewer")
    return raw


# ---------------------------------------------------------------------------
# Auth gate matrix — GET /audit
# ---------------------------------------------------------------------------


def test_audit_list_no_auth_returns_401(client):
    r = client.get("/audit")
    assert r.status_code == 401


def test_audit_list_viewer_returns_403(client, viewer_token):
    r = client.get("/audit", headers={"Authorization": f"Bearer {viewer_token}"})
    assert r.status_code == 403


def test_audit_list_operator_returns_403(client, operator_token):
    r = client.get("/audit", headers={"Authorization": f"Bearer {operator_token}"})
    assert r.status_code == 403


def test_audit_list_admin_returns_200(client, admin_token):
    r = client.get("/audit", headers={"Authorization": f"Bearer {admin_token}"})
    assert r.status_code == 200


# ---------------------------------------------------------------------------
# Auth gate matrix — GET /audit/verify
# ---------------------------------------------------------------------------


def test_audit_verify_no_auth_returns_401(client):
    r = client.get("/audit/verify")
    assert r.status_code == 401


def test_audit_verify_viewer_returns_403(client, viewer_token):
    r = client.get("/audit/verify", headers={"Authorization": f"Bearer {viewer_token}"})
    assert r.status_code == 403


def test_audit_verify_operator_returns_403(client, operator_token):
    r = client.get("/audit/verify", headers={"Authorization": f"Bearer {operator_token}"})
    assert r.status_code == 403


def test_audit_verify_admin_returns_200(client, admin_token):
    r = client.get("/audit/verify", headers={"Authorization": f"Bearer {admin_token}"})
    assert r.status_code == 200


# ---------------------------------------------------------------------------
# GET /audit — content tests
# ---------------------------------------------------------------------------


def test_audit_list_returns_empty_array_when_no_rows(client, admin_token):
    """GET /audit on empty table returns []."""
    r = client.get("/audit", headers={"Authorization": f"Bearer {admin_token}"})
    assert r.status_code == 200
    assert r.json() == []


def test_audit_list_returns_rows_newest_first(db, client, admin_token):
    """GET /audit returns rows in descending id order."""
    for i in range(3):
        record_audit(
            conn=db,
            key=_TEST_KEY,
            actor_username="alice",
            actor_role="admin",
            method="POST",
            path=f"/step/{i}",
            status_code=200,
            body_excerpt=None,
        )

    r = client.get("/audit", headers={"Authorization": f"Bearer {admin_token}"})
    assert r.status_code == 200
    rows = r.json()
    assert len(rows) == 3
    ids = [row["id"] for row in rows]
    assert ids == sorted(ids, reverse=True), "Rows must be newest-first"


def test_audit_list_limit_param(db, client, admin_token):
    """GET /audit?limit=2 returns at most 2 rows."""
    for i in range(5):
        record_audit(
            conn=db, key=_TEST_KEY,
            actor_username="alice", actor_role="admin",
            method="POST", path=f"/step/{i}",
            status_code=200, body_excerpt=None,
        )

    r = client.get("/audit?limit=2", headers={"Authorization": f"Bearer {admin_token}"})
    assert r.status_code == 200
    assert len(r.json()) == 2


def test_audit_list_actor_filter(db, client, admin_token):
    """GET /audit?actor=alice returns only alice's rows."""
    record_audit(db, _TEST_KEY, "alice", "admin", "POST", "/p", 200, None)
    record_audit(db, _TEST_KEY, "bob",   "operator", "POST", "/p", 200, None)
    record_audit(db, _TEST_KEY, "alice", "admin", "DELETE", "/p/2", 204, None)

    r = client.get("/audit?actor=alice", headers={"Authorization": f"Bearer {admin_token}"})
    assert r.status_code == 200
    rows = r.json()
    assert all(row["actor_username"] == "alice" for row in rows)
    assert len(rows) == 2


def test_audit_list_row_fields_present(db, client, admin_token):
    """Each row from GET /audit has the expected fields."""
    record_audit(db, _TEST_KEY, "alice", "admin", "POST", "/posture/run", 200, "body")
    r = client.get("/audit", headers={"Authorization": f"Bearer {admin_token}"})
    row = r.json()[0]
    for field in ("id", "ts", "actor_username", "actor_role", "method",
                  "path", "status_code", "body_excerpt", "prev_hmac", "row_hmac"):
        assert field in row, f"Expected field {field!r} in audit row"


# ---------------------------------------------------------------------------
# GET /audit/verify — chain integrity
# ---------------------------------------------------------------------------


def test_audit_verify_empty_chain(client, admin_token):
    """GET /audit/verify on empty table returns intact=True, total_rows=0."""
    r = client.get("/audit/verify", headers={"Authorization": f"Bearer {admin_token}"})
    assert r.status_code == 200
    data = r.json()
    assert data["intact"] is True
    assert data["total_rows"] == 0
    assert data["broken_at_id"] is None


def test_audit_verify_intact_chain(db, client, admin_token):
    """GET /audit/verify after clean inserts returns intact=True."""
    for i in range(5):
        record_audit(db, _TEST_KEY, "alice", "admin", "POST", f"/op/{i}", 200, None)

    r = client.get("/audit/verify", headers={"Authorization": f"Bearer {admin_token}"})
    assert r.status_code == 200
    data = r.json()
    assert data["intact"] is True
    assert data["total_rows"] == 5


def test_audit_verify_tampered_row_detected(db, client, admin_token):
    """GET /audit/verify after tampering with row 2 returns intact=False."""
    for i in range(4):
        record_audit(db, _TEST_KEY, "alice", "admin", "POST", f"/op/{i}", 200, None)

    # Tamper with row id=2
    db.execute("UPDATE audit_log SET path='/tampered' WHERE id=2")
    db.commit()

    r = client.get("/audit/verify", headers={"Authorization": f"Bearer {admin_token}"})
    assert r.status_code == 200
    data = r.json()
    assert data["intact"] is False
    assert data["broken_at_id"] == 2


def test_audit_verify_response_shape(db, client, admin_token):
    """GET /audit/verify response has exactly the expected keys."""
    record_audit(db, _TEST_KEY, "alice", "admin", "POST", "/p", 200, None)
    r = client.get("/audit/verify", headers={"Authorization": f"Bearer {admin_token}"})
    data = r.json()
    expected_keys = {"intact", "total_rows", "broken_at_id", "broken_field_clue"}
    assert set(data.keys()) == expected_keys
