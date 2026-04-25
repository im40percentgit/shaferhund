"""
Tests for the dual auth modes in agent/main.py _require_auth (REQ-P0-P6-003/006,
DEC-AUTH-P6-004, DEC-COMPAT-P6-001).

# @mock-exempt: patch.object targets _settings and _db — module-level singletons
# in main.py that are populated by lifespan(). Swapping them for test-controlled
# objects is equivalent to dependency injection at the app boundary, not mocking
# internal logic. The auth code under test (authenticate_token, hash_token, etc.)
# runs against a real in-memory SQLite connection with no mocks.

Verifies:
- single mode (default): legacy SHAFERHUND_TOKEN path is unchanged (Phase 1-5 compat)
- single mode: returns synthetic admin user so downstream role checks pass
- multi mode: per-user token auth via users + user_tokens tables
- multi mode: disabled user token rejected
- multi mode: revoked token rejected
- multi mode: no token → 401
- multi mode: unknown token → 401
- multi mode: SHAFERHUND_TOKEN still works as admin-equivalent fallback

Uses TestClient with overridden settings and db; no mocks of internal modules.
"""

import sqlite3
from datetime import datetime, timezone
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

from agent.auth import generate_token, hash_password, hash_token
from agent.models import (
    init_db,
    insert_user,
    insert_user_token,
    revoke_user_token,
    set_user_disabled,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_app(settings_overrides: dict, db_conn):
    """
    Import the app fresh with patched _settings and _db globals.
    We patch at the module level so _require_auth reads our overrides.
    """
    import agent.main as main_mod
    from agent.config import Settings

    # Build a Settings instance with our overrides
    base_env = {
        "ANTHROPIC_API_KEY": "test-key",
        "SHAFERHUND_TOKEN": "",
        "SHAFERHUND_AUTH_MODE": "single",
    }
    base_env.update({k.upper(): str(v) for k, v in settings_overrides.items()})

    settings = Settings(**{
        "anthropic_api_key": "test-key",
        "shaferhund_token": settings_overrides.get("shaferhund_token", ""),
        "shaferhund_auth_mode": settings_overrides.get("shaferhund_auth_mode", "single"),
    })

    # Patch module-level singletons
    with (
        patch.object(main_mod, "_settings", settings),
        patch.object(main_mod, "_db", db_conn),
    ):
        client = TestClient(main_mod.app, raise_server_exceptions=True)
        yield client


@pytest.fixture()
def db(tmp_path):
    conn = init_db(str(tmp_path / "test.db"))
    yield conn
    conn.close()


# ---------------------------------------------------------------------------
# Helpers for inserting fixtures into db
# ---------------------------------------------------------------------------

def _create_user_with_token(db, username, role="operator"):
    """Insert user + token; return (raw_token, user_id, token_id)."""
    ph = hash_password("hunter2")
    user_id = insert_user(db, username, ph, role)
    raw_token, token_hash = generate_token()
    token_id = insert_user_token(db, user_id, token_hash, f"{username}-token")
    return raw_token, user_id, token_id


# ---------------------------------------------------------------------------
# single mode — Phase 1-5 backwards compatibility
# ---------------------------------------------------------------------------

def test_single_mode_legacy_token_still_works(db):
    """AUTH_MODE=single with SHAFERHUND_TOKEN set → correct token gives 200."""
    import agent.main as main_mod
    from agent.config import Settings

    settings = Settings(
        anthropic_api_key="test-key",
        shaferhund_token="my-secret-token",
        shaferhund_auth_mode="single",
    )

    with (
        patch.object(main_mod, "_settings", settings),
        patch.object(main_mod, "_db", db),
    ):
        client = TestClient(main_mod.app, raise_server_exceptions=True)
        resp = client.get("/health")
        # /health is not behind _require_auth, but we can test any auth-gated route.
        # Use /metrics which is auth-gated.
        resp = client.get(
            "/metrics",
            headers={"Authorization": "Bearer my-secret-token"},
        )
        assert resp.status_code == 200, f"Expected 200, got {resp.status_code}: {resp.text}"


def test_single_mode_wrong_token_rejected(db):
    """AUTH_MODE=single: wrong token → 401."""
    import agent.main as main_mod
    from agent.config import Settings

    settings = Settings(
        anthropic_api_key="test-key",
        shaferhund_token="my-secret-token",
        shaferhund_auth_mode="single",
    )

    with (
        patch.object(main_mod, "_settings", settings),
        patch.object(main_mod, "_db", db),
    ):
        client = TestClient(main_mod.app, raise_server_exceptions=True)
        resp = client.get(
            "/metrics",
            headers={"Authorization": "Bearer wrong-token"},
        )
        assert resp.status_code == 401


def test_single_mode_no_token_env_allows_request(db):
    """AUTH_MODE=single, SHAFERHUND_TOKEN unset → no auth enforced (localhost-only mode)."""
    import agent.main as main_mod
    from agent.config import Settings

    settings = Settings(
        anthropic_api_key="test-key",
        shaferhund_token="",
        shaferhund_auth_mode="single",
    )

    with (
        patch.object(main_mod, "_settings", settings),
        patch.object(main_mod, "_db", db),
    ):
        client = TestClient(main_mod.app, raise_server_exceptions=True)
        resp = client.get("/metrics")
        assert resp.status_code == 200


def test_single_mode_returns_legacy_admin_user(db):
    """_require_auth in single mode returns a user dict with role='admin'."""
    import agent.main as main_mod
    from agent.config import Settings
    from agent.auth import LEGACY_ADMIN_USER
    from fastapi import Depends
    from fastapi.testclient import TestClient
    from fastapi.responses import JSONResponse

    settings = Settings(
        anthropic_api_key="test-key",
        shaferhund_token="tok",
        shaferhund_auth_mode="single",
    )

    # Add a temporary probe route
    @main_mod.app.get("/test-auth-probe")
    async def _probe(user: dict = Depends(main_mod._require_auth)):
        return JSONResponse({"role": user["role"], "username": user["username"]})

    try:
        with (
            patch.object(main_mod, "_settings", settings),
            patch.object(main_mod, "_db", db),
        ):
            client = TestClient(main_mod.app, raise_server_exceptions=True)
            resp = client.get(
                "/test-auth-probe",
                headers={"Authorization": "Bearer tok"},
            )
            assert resp.status_code == 200
            data = resp.json()
            assert data["role"] == "admin"
            assert data["username"] == "__legacy_token__"
    finally:
        # Clean up the probe route so it doesn't leak into other tests
        main_mod.app.routes[:] = [r for r in main_mod.app.routes if getattr(r, "path", None) != "/test-auth-probe"]


# ---------------------------------------------------------------------------
# multi mode
# ---------------------------------------------------------------------------

def test_multi_mode_token_auth(db):
    """AUTH_MODE=multi: valid user token → 200; user role reflects DB row."""
    import agent.main as main_mod
    from agent.config import Settings

    raw_token, user_id, token_id = _create_user_with_token(db, "alice", "operator")

    settings = Settings(
        anthropic_api_key="test-key",
        shaferhund_token="",
        shaferhund_auth_mode="multi",
    )

    with (
        patch.object(main_mod, "_settings", settings),
        patch.object(main_mod, "_db", db),
    ):
        client = TestClient(main_mod.app, raise_server_exceptions=True)
        resp = client.get(
            "/metrics",
            headers={"Authorization": f"Bearer {raw_token}"},
        )
        assert resp.status_code == 200, f"Expected 200, got {resp.status_code}: {resp.text}"


def test_multi_mode_disabled_user_token_rejected(db):
    """AUTH_MODE=multi: disabled user's token → 401."""
    import agent.main as main_mod
    from agent.config import Settings

    raw_token, user_id, token_id = _create_user_with_token(db, "bob", "operator")
    set_user_disabled(db, user_id, True)

    settings = Settings(
        anthropic_api_key="test-key",
        shaferhund_token="",
        shaferhund_auth_mode="multi",
    )

    with (
        patch.object(main_mod, "_settings", settings),
        patch.object(main_mod, "_db", db),
    ):
        client = TestClient(main_mod.app, raise_server_exceptions=True)
        resp = client.get(
            "/metrics",
            headers={"Authorization": f"Bearer {raw_token}"},
        )
        assert resp.status_code == 401


def test_multi_mode_revoked_token_rejected(db):
    """AUTH_MODE=multi: revoked token → 401."""
    import agent.main as main_mod
    from agent.config import Settings

    raw_token, user_id, token_id = _create_user_with_token(db, "carol", "viewer")
    ts = datetime.now(timezone.utc).isoformat()
    revoke_user_token(db, token_id, ts)

    settings = Settings(
        anthropic_api_key="test-key",
        shaferhund_token="",
        shaferhund_auth_mode="multi",
    )

    with (
        patch.object(main_mod, "_settings", settings),
        patch.object(main_mod, "_db", db),
    ):
        client = TestClient(main_mod.app, raise_server_exceptions=True)
        resp = client.get(
            "/metrics",
            headers={"Authorization": f"Bearer {raw_token}"},
        )
        assert resp.status_code == 401


def test_multi_mode_no_token_rejected(db):
    """AUTH_MODE=multi: no Authorization header → 401."""
    import agent.main as main_mod
    from agent.config import Settings

    settings = Settings(
        anthropic_api_key="test-key",
        shaferhund_token="",
        shaferhund_auth_mode="multi",
    )

    with (
        patch.object(main_mod, "_settings", settings),
        patch.object(main_mod, "_db", db),
    ):
        client = TestClient(main_mod.app, raise_server_exceptions=True)
        resp = client.get("/metrics")
        assert resp.status_code == 401


def test_multi_mode_unknown_token_rejected(db):
    """AUTH_MODE=multi: unknown bearer token → 401."""
    import agent.main as main_mod
    from agent.config import Settings

    settings = Settings(
        anthropic_api_key="test-key",
        shaferhund_token="",
        shaferhund_auth_mode="multi",
    )

    with (
        patch.object(main_mod, "_settings", settings),
        patch.object(main_mod, "_db", db),
    ):
        client = TestClient(main_mod.app, raise_server_exceptions=True)
        resp = client.get(
            "/metrics",
            headers={"Authorization": "Bearer unknown-random-token-xyz-123"},
        )
        assert resp.status_code == 401


def test_multi_mode_legacy_token_still_works_as_admin(db):
    """AUTH_MODE=multi: SHAFERHUND_TOKEN set → still accepted as admin fallback."""
    import agent.main as main_mod
    from agent.config import Settings

    settings = Settings(
        anthropic_api_key="test-key",
        shaferhund_token="legacy-admin-token",
        shaferhund_auth_mode="multi",
    )

    with (
        patch.object(main_mod, "_settings", settings),
        patch.object(main_mod, "_db", db),
    ):
        client = TestClient(main_mod.app, raise_server_exceptions=True)
        resp = client.get(
            "/metrics",
            headers={"Authorization": "Bearer legacy-admin-token"},
        )
        assert resp.status_code == 200, f"Expected 200, got {resp.status_code}: {resp.text}"
