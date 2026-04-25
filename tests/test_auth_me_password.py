"""
Tests for POST /auth/me/password — self-service password change
(Phase 6 Wave B1, REQ-P0-P6-006).

# @mock-exempt: patch.object targets _settings and _db — module-level singletons
# in main.py populated by lifespan(). Established boundary-injection pattern
# (see test_main_auth_modes.py). All auth and DB logic runs against a real
# in-memory SQLite connection with no mocks of internal behaviour.

Test matrix:
  - correct current password → 200, new password works for login
  - wrong current password → 401
  - single-mode legacy token (SHAFERHUND_TOKEN) → 400
  - missing fields → 422
  - response never includes password_hash (DEC-AUTH-P6-008)
"""

from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

from agent.auth import generate_token, hash_password, verify_password
from agent.models import (
    init_db,
    insert_user,
    insert_user_token,
    get_user_by_id,
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
        yield TestClient(main_mod.app, raise_server_exceptions=True)


def _seed_user(db, username="alice", role="operator", password="old-pass"):
    ph = hash_password(password)
    user_id = insert_user(db, username, ph, role)
    raw_token, token_hash = generate_token()
    insert_user_token(db, user_id, token_hash, f"{username}-session")
    return user_id, raw_token, password


def _auth(token):
    return {"Authorization": f"Bearer {token}"}


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

def test_self_change_password_correct_current(db):
    """Correct current_password → 200; new password works for login."""
    user_id, token, old_pass = _seed_user(db)
    for client in _make_client(db, auth_mode="multi"):
        r = client.post(
            "/auth/me/password",
            headers=_auth(token),
            json={"current_password": old_pass, "new_password": "brand-new-pass"},
        )
        assert r.status_code == 200, r.text
        assert r.json().get("ok") is True

        # Verify new password works via login
        r2 = client.post("/auth/login", json={"username": "alice", "password": "brand-new-pass"})
        assert r2.status_code == 200, f"New password should work for login: {r2.text}"

        # Old password should no longer work
        r3 = client.post("/auth/login", json={"username": "alice", "password": old_pass})
        assert r3.status_code == 401, f"Old password should be rejected: {r3.text}"


def test_self_change_password_wrong_current(db):
    """Wrong current_password → 401."""
    user_id, token, old_pass = _seed_user(db)
    for client in _make_client(db, auth_mode="multi"):
        r = client.post(
            "/auth/me/password",
            headers=_auth(token),
            json={"current_password": "totally-wrong", "new_password": "new-pass"},
        )
        assert r.status_code == 401, r.text


def test_self_change_password_single_mode_returns_400(db):
    """In single mode, POST /auth/me/password → 400 (SHAFERHUND_TOKEN admin has no password)."""
    for client in _make_client(db, auth_mode="single", legacy_token="my-legacy-token"):
        r = client.post(
            "/auth/me/password",
            headers={"Authorization": "Bearer my-legacy-token"},
            json={"current_password": "anything", "new_password": "new"},
        )
        assert r.status_code == 400, r.text
        detail = r.json().get("detail", "")
        assert "single" in detail.lower() or "cannot" in detail.lower(), (
            f"Expected clear single-mode message, got: {detail}"
        )


def test_self_change_password_missing_fields(db):
    """Missing current_password or new_password → 422."""
    user_id, token, old_pass = _seed_user(db)
    for client in _make_client(db, auth_mode="multi"):
        # Missing new_password
        r = client.post(
            "/auth/me/password",
            headers=_auth(token),
            json={"current_password": old_pass},
        )
        assert r.status_code == 422, r.text

        # Missing current_password
        r2 = client.post(
            "/auth/me/password",
            headers=_auth(token),
            json={"new_password": "something"},
        )
        assert r2.status_code == 422, r2.text


def test_self_change_password_requires_auth(db):
    """POST /auth/me/password without token → 401."""
    for client in _make_client(db, auth_mode="multi"):
        r = client.post(
            "/auth/me/password",
            json={"current_password": "x", "new_password": "y"},
        )
        assert r.status_code == 401, r.text


def test_self_change_password_response_has_no_hash(db):
    """Response must not include password_hash (DEC-AUTH-P6-008)."""
    user_id, token, old_pass = _seed_user(db)
    for client in _make_client(db, auth_mode="multi"):
        r = client.post(
            "/auth/me/password",
            headers=_auth(token),
            json={"current_password": old_pass, "new_password": "new-secure-pass"},
        )
        assert r.status_code == 200
        body = r.json()
        assert "password_hash" not in body
        assert "password" not in body
