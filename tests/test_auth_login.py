"""
Tests for POST /auth/login (Phase 6 Wave B1, REQ-P0-P6-006).

# @mock-exempt: patch.object targets _settings and _db — module-level singletons
# in main.py populated by lifespan(). Swapping for test-controlled objects is
# the established boundary-injection pattern (see test_main_auth_modes.py).
# All auth logic runs against a real in-memory SQLite connection with no mocks
# of internal behaviour.

Test matrix:
  - multi mode correct credentials → 200 + raw token
  - multi mode wrong password → 401
  - multi mode unknown user → 401 (don't leak username existence via timing)
  - multi mode disabled user → 401
  - single mode → 400 with clear message
  - token returned from login authenticates a subsequent request
"""

from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

from agent.auth import generate_token, hash_password, hash_token
from agent.models import (
    init_db,
    insert_user,
    insert_user_token,
    set_user_disabled,
)


# ---------------------------------------------------------------------------
# Fixtures / helpers
# ---------------------------------------------------------------------------

@pytest.fixture()
def db(tmp_path):
    conn = init_db(str(tmp_path / "test.db"))
    yield conn
    conn.close()


def _make_client(db_conn, auth_mode="multi", legacy_token=""):
    """Return a TestClient with patched _settings and _db singletons."""
    import agent.main as main_mod
    from agent.config import Settings

    settings = Settings(
        anthropic_api_key="test-key",
        shaferhund_auth_mode=auth_mode,
        shaferhund_token=legacy_token,
        shaferhund_audit_key="a" * 64,
    )
    with (
        patch.object(main_mod, "_settings", settings),
        patch.object(main_mod, "_db", db_conn),
        patch.object(main_mod, "_audit_hmac_key", b"x" * 32),
    ):
        client = TestClient(main_mod.app, raise_server_exceptions=True)
        yield client


@pytest.fixture()
def alice(db):
    """Insert alice (operator) with a known password; return (user_id, password)."""
    ph = hash_password("alice-correct-pass")
    user_id = insert_user(db, "alice", ph, "operator")
    return user_id, "alice-correct-pass"


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

def test_login_multi_mode_correct_credentials(db, alice):
    """Correct credentials in multi mode → 200 with raw token."""
    user_id, password = alice
    for client in _make_client(db, auth_mode="multi"):
        r = client.post("/auth/login", json={"username": "alice", "password": password})
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["user_id"] == user_id
        assert body["username"] == "alice"
        assert body["role"] == "operator"
        assert "token" in body
        assert len(body["token"]) > 20  # raw token should be substantial


def test_login_multi_mode_wrong_password(db, alice):
    """Wrong password → 401."""
    for client in _make_client(db, auth_mode="multi"):
        r = client.post("/auth/login", json={"username": "alice", "password": "wrong"})
        assert r.status_code == 401, r.text


def test_login_multi_mode_unknown_user(db):
    """Unknown username → 401 (no username-enumeration leak)."""
    for client in _make_client(db, auth_mode="multi"):
        r = client.post("/auth/login", json={"username": "nobody", "password": "x"})
        assert r.status_code == 401, r.text
        # Error message should not reveal whether username exists
        detail = r.json().get("detail", "")
        assert "nobody" not in detail.lower() or "invalid credentials" in detail.lower()


def test_login_disabled_user(db, alice):
    """Disabled user cannot log in → 401."""
    user_id, password = alice
    set_user_disabled(db, user_id, True)
    for client in _make_client(db, auth_mode="multi"):
        r = client.post("/auth/login", json={"username": "alice", "password": password})
        assert r.status_code == 401, r.text


def test_login_single_mode_returns_400(db):
    """POST /auth/login in single mode → 400 with clear error."""
    for client in _make_client(db, auth_mode="single"):
        r = client.post("/auth/login", json={"username": "anyone", "password": "x"})
        assert r.status_code == 400, r.text
        detail = r.json().get("detail", "")
        assert "single" in detail.lower() or "multi" in detail.lower(), (
            f"Expected clear mode message, got: {detail}"
        )


def test_login_token_works_for_authenticated_request(db, alice):
    """Token from login → can authenticate subsequent requests (e.g. GET /metrics)."""
    user_id, password = alice
    for client in _make_client(db, auth_mode="multi"):
        # Log in
        r = client.post("/auth/login", json={"username": "alice", "password": password})
        assert r.status_code == 200, r.text
        token = r.json()["token"]

        # Use token for an authenticated endpoint (viewer+)
        r2 = client.get("/metrics", headers={"Authorization": f"Bearer {token}"})
        assert r2.status_code == 200, f"Expected 200 on /metrics with fresh token, got {r2.status_code}: {r2.text}"


def test_login_response_has_no_password_hash(db, alice):
    """Login response must NEVER include password_hash (DEC-AUTH-P6-008)."""
    user_id, password = alice
    for client in _make_client(db, auth_mode="multi"):
        r = client.post("/auth/login", json={"username": "alice", "password": password})
        assert r.status_code == 200
        body = r.json()
        assert "password_hash" not in body
        assert "password" not in body


def test_login_response_has_no_token_hash(db, alice):
    """Login response must NEVER include token_hash (DEC-AUTH-P6-003)."""
    user_id, password = alice
    for client in _make_client(db, auth_mode="multi"):
        r = client.post("/auth/login", json={"username": "alice", "password": password})
        assert r.status_code == 200
        body = r.json()
        assert "token_hash" not in body
