"""
Tests for admin-only user/token CRUD routes (Phase 6 Wave B1, REQ-P0-P6-006).

# @mock-exempt: patch.object targets _settings and _db — module-level singletons
# in main.py populated by lifespan(). Established boundary-injection pattern
# (see test_main_auth_modes.py). All auth, hash, and DB logic runs against a
# real in-memory SQLite connection with no mocks of internal behaviour.

Routes covered:
  GET  /auth/users                        — list users (admin-only)
  POST /auth/users                        — create user (admin-only)
  POST /auth/users/{id}/disable           — disable user (admin-only)
  POST /auth/users/{id}/enable            — enable user (admin-only)
  POST /auth/users/{id}/password          — admin password reset (admin-only)
  POST /auth/users/{id}/tokens            — issue token for user (admin-only)
  GET  /auth/users/{id}/tokens            — list user tokens (admin-only)
  POST /auth/tokens/{id}/revoke           — revoke token (admin-only)
"""

from datetime import datetime, timezone
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

from agent.auth import generate_token, hash_password, hash_token, verify_password
from agent.models import (
    init_db,
    insert_user,
    insert_user_token,
    get_user_by_id,
    get_user_by_username,
)


# ---------------------------------------------------------------------------
# Helpers / fixtures
# ---------------------------------------------------------------------------

@pytest.fixture()
def db(tmp_path):
    conn = init_db(str(tmp_path / "test.db"))
    yield conn
    conn.close()


def _client_context(db_conn, auth_mode="multi", legacy_token=""):
    import agent.main as main_mod
    from agent.config import Settings

    settings = Settings(
        anthropic_api_key="test-key",
        shaferhund_auth_mode=auth_mode,
        shaferhund_token=legacy_token,
        shaferhund_audit_key="a" * 64,
    )
    return (
        patch.object(main_mod, "_settings", settings),
        patch.object(main_mod, "_db", db_conn),
        patch.object(main_mod, "_audit_hmac_key", b"x" * 32),
    )


def _seed_user_with_token(db, username, role, password="test-pass"):
    """Insert a user + token; return (user_id, raw_token, token_id)."""
    ph = hash_password(password)
    user_id = insert_user(db, username, ph, role)
    raw_token, token_hash = generate_token()
    token_id = insert_user_token(db, user_id, token_hash, f"{username}-token")
    return user_id, raw_token, token_id


@pytest.fixture()
def admin_user(db):
    user_id, raw_token, token_id = _seed_user_with_token(db, "admin", "admin")
    return {"user_id": user_id, "token": raw_token, "token_id": token_id}


@pytest.fixture()
def viewer_user(db):
    user_id, raw_token, token_id = _seed_user_with_token(db, "viewer", "viewer")
    return {"user_id": user_id, "token": raw_token, "token_id": token_id}


@pytest.fixture()
def operator_user(db):
    user_id, raw_token, token_id = _seed_user_with_token(db, "operator", "operator")
    return {"user_id": user_id, "token": raw_token, "token_id": token_id}


def _auth(token):
    return {"Authorization": f"Bearer {token}"}


# ---------------------------------------------------------------------------
# GET /auth/users — auth gate
# ---------------------------------------------------------------------------

def test_list_users_requires_auth(db, admin_user):
    """GET /auth/users → 401 without token."""
    with _client_context(db)[0], _client_context(db)[1], _client_context(db)[2]:
        import agent.main as main_mod
        from agent.config import Settings
        settings = Settings(
            anthropic_api_key="test-key",
            shaferhund_auth_mode="multi",
            shaferhund_audit_key="a" * 64,
        )
        with (
            patch.object(main_mod, "_settings", settings),
            patch.object(main_mod, "_db", db),
            patch.object(main_mod, "_audit_hmac_key", b"x" * 32),
        ):
            c = TestClient(main_mod.app, raise_server_exceptions=True)
            r = c.get("/auth/users")
            assert r.status_code == 401, r.text


def test_list_users_viewer_gets_403(db, admin_user, viewer_user):
    """GET /auth/users → 403 for viewer role."""
    import agent.main as main_mod
    from agent.config import Settings
    settings = Settings(
        anthropic_api_key="test-key",
        shaferhund_auth_mode="multi",
        shaferhund_audit_key="a" * 64,
    )
    with (
        patch.object(main_mod, "_settings", settings),
        patch.object(main_mod, "_db", db),
        patch.object(main_mod, "_audit_hmac_key", b"x" * 32),
    ):
        c = TestClient(main_mod.app, raise_server_exceptions=True)
        r = c.get("/auth/users", headers=_auth(viewer_user["token"]))
        assert r.status_code == 403, r.text


def test_list_users_operator_gets_403(db, admin_user, operator_user):
    """GET /auth/users → 403 for operator role."""
    import agent.main as main_mod
    from agent.config import Settings
    settings = Settings(
        anthropic_api_key="test-key",
        shaferhund_auth_mode="multi",
        shaferhund_audit_key="a" * 64,
    )
    with (
        patch.object(main_mod, "_settings", settings),
        patch.object(main_mod, "_db", db),
        patch.object(main_mod, "_audit_hmac_key", b"x" * 32),
    ):
        c = TestClient(main_mod.app, raise_server_exceptions=True)
        r = c.get("/auth/users", headers=_auth(operator_user["token"]))
        assert r.status_code == 403, r.text


def test_list_users_admin_gets_200(db, admin_user):
    """GET /auth/users → 200 for admin role."""
    import agent.main as main_mod
    from agent.config import Settings
    settings = Settings(
        anthropic_api_key="test-key",
        shaferhund_auth_mode="multi",
        shaferhund_audit_key="a" * 64,
    )
    with (
        patch.object(main_mod, "_settings", settings),
        patch.object(main_mod, "_db", db),
        patch.object(main_mod, "_audit_hmac_key", b"x" * 32),
    ):
        c = TestClient(main_mod.app, raise_server_exceptions=True)
        r = c.get("/auth/users", headers=_auth(admin_user["token"]))
        assert r.status_code == 200, r.text
        users = r.json()
        assert isinstance(users, list)
        assert any(u["username"] == "admin" for u in users)


def test_list_users_no_password_hash_in_response(db, admin_user):
    """GET /auth/users response must NEVER include password_hash (DEC-AUTH-P6-008)."""
    import agent.main as main_mod
    from agent.config import Settings
    settings = Settings(
        anthropic_api_key="test-key",
        shaferhund_auth_mode="multi",
        shaferhund_audit_key="a" * 64,
    )
    with (
        patch.object(main_mod, "_settings", settings),
        patch.object(main_mod, "_db", db),
        patch.object(main_mod, "_audit_hmac_key", b"x" * 32),
    ):
        c = TestClient(main_mod.app, raise_server_exceptions=True)
        r = c.get("/auth/users", headers=_auth(admin_user["token"]))
        assert r.status_code == 200
        for user in r.json():
            assert "password_hash" not in user, f"password_hash leaked in user: {user}"
            assert "password" not in user


# ---------------------------------------------------------------------------
# Shared client fixture to avoid boilerplate
# ---------------------------------------------------------------------------

@pytest.fixture()
def client_and_admin(db, admin_user):
    """Yield (TestClient, admin_token) with patched singletons."""
    import agent.main as main_mod
    from agent.config import Settings
    settings = Settings(
        anthropic_api_key="test-key",
        shaferhund_auth_mode="multi",
        shaferhund_audit_key="a" * 64,
    )
    with (
        patch.object(main_mod, "_settings", settings),
        patch.object(main_mod, "_db", db),
        patch.object(main_mod, "_audit_hmac_key", b"x" * 32),
    ):
        c = TestClient(main_mod.app, raise_server_exceptions=True)
        yield c, admin_user["token"]


# ---------------------------------------------------------------------------
# POST /auth/users — create user
# ---------------------------------------------------------------------------

def test_create_user_admin_only(client_and_admin):
    """POST /auth/users creates a user and returns id."""
    c, admin_token = client_and_admin
    r = c.post(
        "/auth/users",
        headers=_auth(admin_token),
        json={"username": "alice", "password": "alice-pass", "role": "viewer"},
    )
    assert r.status_code == 201, r.text
    body = r.json()
    assert body["username"] == "alice"
    assert body["role"] == "viewer"
    assert "id" in body
    assert "password_hash" not in body
    assert "password" not in body


def test_create_user_invalid_role(client_and_admin):
    """POST /auth/users with invalid role → 422."""
    c, admin_token = client_and_admin
    r = c.post(
        "/auth/users",
        headers=_auth(admin_token),
        json={"username": "bad", "password": "x", "role": "superuser"},
    )
    assert r.status_code == 422, r.text


def test_create_user_duplicate_username(client_and_admin, db, admin_user):
    """POST /auth/users with duplicate username → 409."""
    c, admin_token = client_and_admin
    # admin already exists in db
    r = c.post(
        "/auth/users",
        headers=_auth(admin_token),
        json={"username": "admin", "password": "x", "role": "viewer"},
    )
    assert r.status_code == 409, r.text


# ---------------------------------------------------------------------------
# POST /auth/users/{id}/disable and enable
# ---------------------------------------------------------------------------

def test_disable_user_blocks_auth(db, admin_user):
    """Disabling a user → their tokens return 401 on subsequent requests."""
    # Create alice with a token
    ph = hash_password("alice-pass")
    alice_id = insert_user(db, "alice", ph, "viewer")
    raw_alice, alice_hash = generate_token()
    insert_user_token(db, alice_id, alice_hash, "alice-session")

    import agent.main as main_mod
    from agent.config import Settings
    settings = Settings(
        anthropic_api_key="test-key",
        shaferhund_auth_mode="multi",
        shaferhund_audit_key="a" * 64,
    )
    with (
        patch.object(main_mod, "_settings", settings),
        patch.object(main_mod, "_db", db),
        patch.object(main_mod, "_audit_hmac_key", b"x" * 32),
    ):
        c = TestClient(main_mod.app, raise_server_exceptions=True)
        # Alice can initially hit /metrics
        r = c.get("/metrics", headers=_auth(raw_alice))
        assert r.status_code == 200, f"Alice should access /metrics before disable: {r.text}"

        # Admin disables alice
        r = c.post(f"/auth/users/{alice_id}/disable", headers=_auth(admin_user["token"]))
        assert r.status_code == 200, r.text
        assert r.json()["disabled"] is True

        # Alice's token now → 401
        r = c.get("/metrics", headers=_auth(raw_alice))
        assert r.status_code == 401, f"Disabled user should get 401, got {r.status_code}"


def test_enable_user_restores_auth(db, admin_user):
    """Re-enabling a disabled user → their tokens work again."""
    ph = hash_password("alice-pass")
    alice_id = insert_user(db, "alice", ph, "viewer")
    raw_alice, alice_hash = generate_token()
    insert_user_token(db, alice_id, alice_hash, "alice-session")

    import agent.main as main_mod
    from agent.config import Settings
    settings = Settings(
        anthropic_api_key="test-key",
        shaferhund_auth_mode="multi",
        shaferhund_audit_key="a" * 64,
    )
    with (
        patch.object(main_mod, "_settings", settings),
        patch.object(main_mod, "_db", db),
        patch.object(main_mod, "_audit_hmac_key", b"x" * 32),
    ):
        c = TestClient(main_mod.app, raise_server_exceptions=True)
        # Disable
        c.post(f"/auth/users/{alice_id}/disable", headers=_auth(admin_user["token"]))
        r = c.get("/metrics", headers=_auth(raw_alice))
        assert r.status_code == 401

        # Enable
        r = c.post(f"/auth/users/{alice_id}/enable", headers=_auth(admin_user["token"]))
        assert r.status_code == 200
        assert r.json()["disabled"] is False

        # Alice's token works again
        r = c.get("/metrics", headers=_auth(raw_alice))
        assert r.status_code == 200


# ---------------------------------------------------------------------------
# POST /auth/users/{id}/password — admin password reset
# ---------------------------------------------------------------------------

def test_admin_reset_password(db, admin_user):
    """Admin can reset another user's password; old password fails, new works."""
    ph = hash_password("old-pass")
    alice_id = insert_user(db, "alice", ph, "viewer")

    import agent.main as main_mod
    from agent.config import Settings
    settings = Settings(
        anthropic_api_key="test-key",
        shaferhund_auth_mode="multi",
        shaferhund_audit_key="a" * 64,
    )
    with (
        patch.object(main_mod, "_settings", settings),
        patch.object(main_mod, "_db", db),
        patch.object(main_mod, "_audit_hmac_key", b"x" * 32),
    ):
        c = TestClient(main_mod.app, raise_server_exceptions=True)
        r = c.post(
            f"/auth/users/{alice_id}/password",
            headers=_auth(admin_user["token"]),
            json={"password": "new-pass"},
        )
        assert r.status_code == 200, r.text

        # Verify old password no longer works via login
        r = c.post("/auth/login", json={"username": "alice", "password": "old-pass"})
        assert r.status_code == 401

        # New password works
        r = c.post("/auth/login", json={"username": "alice", "password": "new-pass"})
        assert r.status_code == 200


def test_admin_reset_password_response_has_no_hash(db, admin_user):
    """Admin password reset response must not include password_hash."""
    ph = hash_password("old-pass")
    alice_id = insert_user(db, "alice", ph, "viewer")

    import agent.main as main_mod
    from agent.config import Settings
    settings = Settings(
        anthropic_api_key="test-key",
        shaferhund_auth_mode="multi",
        shaferhund_audit_key="a" * 64,
    )
    with (
        patch.object(main_mod, "_settings", settings),
        patch.object(main_mod, "_db", db),
        patch.object(main_mod, "_audit_hmac_key", b"x" * 32),
    ):
        c = TestClient(main_mod.app, raise_server_exceptions=True)
        r = c.post(
            f"/auth/users/{alice_id}/password",
            headers=_auth(admin_user["token"]),
            json={"password": "new-pass"},
        )
        assert r.status_code == 200
        body = r.json()
        assert "password_hash" not in body
        assert "password" not in body


# ---------------------------------------------------------------------------
# POST /auth/users/{id}/tokens — issue token
# ---------------------------------------------------------------------------

def test_issue_token_returns_raw_once(db, admin_user):
    """POST /auth/users/{id}/tokens returns raw_token; subsequent list → no raw."""
    ph = hash_password("alice-pass")
    alice_id = insert_user(db, "alice", ph, "viewer")

    import agent.main as main_mod
    from agent.config import Settings
    settings = Settings(
        anthropic_api_key="test-key",
        shaferhund_auth_mode="multi",
        shaferhund_audit_key="a" * 64,
    )
    with (
        patch.object(main_mod, "_settings", settings),
        patch.object(main_mod, "_db", db),
        patch.object(main_mod, "_audit_hmac_key", b"x" * 32),
    ):
        c = TestClient(main_mod.app, raise_server_exceptions=True)

        r = c.post(
            f"/auth/users/{alice_id}/tokens",
            headers=_auth(admin_user["token"]),
            json={"name": "alice-service-token", "expires_at": None},
        )
        assert r.status_code == 201, r.text
        body = r.json()
        assert "raw_token" in body
        assert "token_hash" not in body
        raw = body["raw_token"]
        assert len(raw) > 20

        # List tokens → no raw_token, no token_hash
        r2 = c.get(f"/auth/users/{alice_id}/tokens", headers=_auth(admin_user["token"]))
        assert r2.status_code == 200
        tokens = r2.json()
        assert isinstance(tokens, list)
        assert len(tokens) == 1
        assert "raw_token" not in tokens[0]
        assert "token_hash" not in tokens[0]


def test_issued_token_authenticates_requests(db, admin_user):
    """Token issued via /auth/users/{id}/tokens → works for auth'd requests."""
    ph = hash_password("alice-pass")
    alice_id = insert_user(db, "alice", ph, "viewer")

    import agent.main as main_mod
    from agent.config import Settings
    settings = Settings(
        anthropic_api_key="test-key",
        shaferhund_auth_mode="multi",
        shaferhund_audit_key="a" * 64,
    )
    with (
        patch.object(main_mod, "_settings", settings),
        patch.object(main_mod, "_db", db),
        patch.object(main_mod, "_audit_hmac_key", b"x" * 32),
    ):
        c = TestClient(main_mod.app, raise_server_exceptions=True)

        r = c.post(
            f"/auth/users/{alice_id}/tokens",
            headers=_auth(admin_user["token"]),
            json={"name": "alice-svc", "expires_at": None},
        )
        assert r.status_code == 201
        raw = r.json()["raw_token"]

        r2 = c.get("/metrics", headers=_auth(raw))
        assert r2.status_code == 200, f"Issued token should work for /metrics: {r2.text}"


# ---------------------------------------------------------------------------
# GET /auth/users/{id}/tokens — list tokens
# ---------------------------------------------------------------------------

def test_list_tokens_no_token_hash(db, admin_user):
    """GET /auth/users/{id}/tokens must never include token_hash (DEC-AUTH-P6-003)."""
    ph = hash_password("alice-pass")
    alice_id = insert_user(db, "alice", ph, "viewer")
    raw, th = generate_token()
    insert_user_token(db, alice_id, th, "alice-svc")

    import agent.main as main_mod
    from agent.config import Settings
    settings = Settings(
        anthropic_api_key="test-key",
        shaferhund_auth_mode="multi",
        shaferhund_audit_key="a" * 64,
    )
    with (
        patch.object(main_mod, "_settings", settings),
        patch.object(main_mod, "_db", db),
        patch.object(main_mod, "_audit_hmac_key", b"x" * 32),
    ):
        c = TestClient(main_mod.app, raise_server_exceptions=True)
        r = c.get(f"/auth/users/{alice_id}/tokens", headers=_auth(admin_user["token"]))
        assert r.status_code == 200
        for tok in r.json():
            assert "token_hash" not in tok, f"token_hash leaked: {tok}"
            assert "raw_token" not in tok


# ---------------------------------------------------------------------------
# POST /auth/tokens/{id}/revoke
# ---------------------------------------------------------------------------

def test_revoke_token_blocks_auth(db, admin_user):
    """Revoking a token → subsequent requests with that token return 401."""
    ph = hash_password("alice-pass")
    alice_id = insert_user(db, "alice", ph, "viewer")
    raw_alice, alice_hash = generate_token()
    token_id = insert_user_token(db, alice_id, alice_hash, "alice-session")

    import agent.main as main_mod
    from agent.config import Settings
    settings = Settings(
        anthropic_api_key="test-key",
        shaferhund_auth_mode="multi",
        shaferhund_audit_key="a" * 64,
    )
    with (
        patch.object(main_mod, "_settings", settings),
        patch.object(main_mod, "_db", db),
        patch.object(main_mod, "_audit_hmac_key", b"x" * 32),
    ):
        c = TestClient(main_mod.app, raise_server_exceptions=True)

        # Token works before revocation
        r = c.get("/metrics", headers=_auth(raw_alice))
        assert r.status_code == 200

        # Revoke
        r = c.post(f"/auth/tokens/{token_id}/revoke", headers=_auth(admin_user["token"]))
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["ok"] is True
        assert body["token_id"] == token_id
        assert "revoked_at" in body

        # Token now → 401
        r = c.get("/metrics", headers=_auth(raw_alice))
        assert r.status_code == 401, f"Revoked token should get 401, got {r.status_code}"


def test_revoke_token_sets_revoked_at_in_list(db, admin_user):
    """After revocation, GET /auth/users/{id}/tokens shows non-null revoked_at."""
    ph = hash_password("alice-pass")
    alice_id = insert_user(db, "alice", ph, "viewer")
    raw_alice, alice_hash = generate_token()
    token_id = insert_user_token(db, alice_id, alice_hash, "alice-session")

    import agent.main as main_mod
    from agent.config import Settings
    settings = Settings(
        anthropic_api_key="test-key",
        shaferhund_auth_mode="multi",
        shaferhund_audit_key="a" * 64,
    )
    with (
        patch.object(main_mod, "_settings", settings),
        patch.object(main_mod, "_db", db),
        patch.object(main_mod, "_audit_hmac_key", b"x" * 32),
    ):
        c = TestClient(main_mod.app, raise_server_exceptions=True)
        c.post(f"/auth/tokens/{token_id}/revoke", headers=_auth(admin_user["token"]))

        r = c.get(f"/auth/users/{alice_id}/tokens", headers=_auth(admin_user["token"]))
        assert r.status_code == 200
        tokens = r.json()
        assert len(tokens) == 1
        assert tokens[0]["revoked_at"] is not None


def test_revoke_unknown_token_404(db, admin_user):
    """POST /auth/tokens/99999/revoke → 404 for nonexistent token."""
    import agent.main as main_mod
    from agent.config import Settings
    settings = Settings(
        anthropic_api_key="test-key",
        shaferhund_auth_mode="multi",
        shaferhund_audit_key="a" * 64,
    )
    with (
        patch.object(main_mod, "_settings", settings),
        patch.object(main_mod, "_db", db),
        patch.object(main_mod, "_audit_hmac_key", b"x" * 32),
    ):
        c = TestClient(main_mod.app, raise_server_exceptions=True)
        r = c.post("/auth/tokens/99999/revoke", headers=_auth(admin_user["token"]))
        assert r.status_code == 404, r.text
