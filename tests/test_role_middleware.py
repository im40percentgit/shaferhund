"""
Tests for _require_role(role) middleware — REQ-P0-P6-004.

Covers:
  - role_satisfies() hierarchy logic (DEC-AUTH-P6-005)
  - role_satisfies() closed-default for unknown roles
  - _require_role factory: ValueError on unknown required_role (boot-time safety)
  - 403 when authenticated user's role is too low
  - 200 when role is sufficient (operator on operator-required route)
  - 200 when admin hits any role-tagged route
  - 401 before 403: missing token → 401, not 403 (auth precedes role check)
  - single-mode legacy SHAFERHUND_TOKEN satisfies all role checks (DEC-AUTH-P6-004)

# @mock-exempt: patch.object targets _settings and _db — module-level singletons
# in main.py populated by lifespan(). Swapping them for test-controlled objects
# is equivalent to dependency injection, not internal mocking. auth.py logic
# runs against a real in-memory SQLite connection.
"""

import pytest
from unittest.mock import patch
from fastapi.testclient import TestClient

from agent.auth import (
    ROLE_HIERARCHY,
    VALID_ROLES,
    generate_token,
    hash_password,
    role_satisfies,
)
from agent.models import init_db, insert_user, insert_user_token


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def db(tmp_path):
    conn = init_db(str(tmp_path / "test.db"))
    yield conn
    conn.close()


def _make_user_token(db, username, role):
    """Insert a user + token; return the raw bearer token."""
    ph = hash_password("hunter2")
    user_id = insert_user(db, username, ph, role)
    raw_token, token_hash = generate_token()
    insert_user_token(db, user_id, token_hash, f"{username}-tok")
    return raw_token


def _make_multi_client(db):
    """Return a TestClient in multi-auth mode with patched singletons."""
    import agent.main as main_mod
    from agent.config import Settings

    settings = Settings(
        anthropic_api_key="test-key",
        shaferhund_token="",
        shaferhund_auth_mode="multi",
    )
    return patch.object(main_mod, "_settings", settings), patch.object(main_mod, "_db", db)


# ---------------------------------------------------------------------------
# role_satisfies() — hierarchy logic (DEC-AUTH-P6-005)
# ---------------------------------------------------------------------------


def test_role_satisfies_hierarchy_admin_satisfies_all():
    """admin satisfies viewer, operator, and admin."""
    assert role_satisfies("admin", "viewer") is True
    assert role_satisfies("admin", "operator") is True
    assert role_satisfies("admin", "admin") is True


def test_role_satisfies_hierarchy_operator_satisfies_operator_and_viewer():
    """operator satisfies operator and viewer but not admin."""
    assert role_satisfies("operator", "viewer") is True
    assert role_satisfies("operator", "operator") is True
    assert role_satisfies("operator", "admin") is False


def test_role_satisfies_hierarchy_viewer_satisfies_viewer_only():
    """viewer satisfies only viewer."""
    assert role_satisfies("viewer", "viewer") is True
    assert role_satisfies("viewer", "operator") is False
    assert role_satisfies("viewer", "admin") is False


def test_role_satisfies_unknown_user_role_returns_false():
    """Unknown user role (e.g. DB corruption / novel value) → False (closed-default)."""
    assert role_satisfies("superuser", "viewer") is False
    assert role_satisfies("hacker", "admin") is False
    assert role_satisfies("", "viewer") is False


def test_role_satisfies_unknown_required_role_returns_false():
    """Unknown required_role → False (closed-default, even for admin user)."""
    assert role_satisfies("admin", "hacker") is False
    assert role_satisfies("admin", "") is False
    assert role_satisfies("admin", "superadmin") is False


def test_role_hierarchy_tuple_order():
    """ROLE_HIERARCHY must be ordered viewer < operator < admin."""
    assert ROLE_HIERARCHY == ("viewer", "operator", "admin")
    assert ROLE_HIERARCHY.index("viewer") < ROLE_HIERARCHY.index("operator")
    assert ROLE_HIERARCHY.index("operator") < ROLE_HIERARCHY.index("admin")


def test_valid_roles_matches_hierarchy():
    """VALID_ROLES frozenset must contain exactly the roles in ROLE_HIERARCHY."""
    assert VALID_ROLES == frozenset(ROLE_HIERARCHY)


# ---------------------------------------------------------------------------
# _require_role factory — boot-time ValueError on bad role names
# ---------------------------------------------------------------------------


def test_require_role_factory_unknown_role_raises():
    """_require_role('hacker') raises ValueError at factory call time."""
    import agent.main as main_mod

    with pytest.raises(ValueError, match="Unknown required_role"):
        main_mod._require_role("hacker")


def test_require_role_factory_all_valid_roles_do_not_raise():
    """_require_role(r) for every valid role must not raise."""
    import agent.main as main_mod

    for role in ROLE_HIERARCHY:
        dep = main_mod._require_role(role)
        assert callable(dep), f"_require_role({role!r}) should return a callable"


# ---------------------------------------------------------------------------
# 401 before 403 — auth failure takes precedence over role failure
# ---------------------------------------------------------------------------


def test_require_role_401_before_403_no_token(db):
    """No Authorization header on an operator-required route → 401, not 403."""
    import agent.main as main_mod

    p_settings, p_db = _make_multi_client(db)
    with p_settings, p_db:
        client = TestClient(main_mod.app, raise_server_exceptions=True)
        resp = client.post("/posture/run")
        assert resp.status_code == 401, (
            f"Expected 401 (auth failure before role check), got {resp.status_code}: {resp.text}"
        )


def test_require_role_401_before_403_bad_token(db):
    """Invalid bearer token on an operator-required route → 401, not 403."""
    import agent.main as main_mod

    p_settings, p_db = _make_multi_client(db)
    with p_settings, p_db:
        client = TestClient(main_mod.app, raise_server_exceptions=True)
        resp = client.post(
            "/posture/run",
            headers={"Authorization": "Bearer totally-invalid-token-xyz"},
        )
        assert resp.status_code == 401


# ---------------------------------------------------------------------------
# 403 when role is insufficient
# ---------------------------------------------------------------------------


def test_require_role_403_viewer_on_operator_route(db):
    """viewer token on operator-required /posture/run → 403."""
    import agent.main as main_mod

    viewer_token = _make_user_token(db, "viewer_user", "viewer")
    p_settings, p_db = _make_multi_client(db)
    with p_settings, p_db:
        client = TestClient(main_mod.app, raise_server_exceptions=True)
        resp = client.post(
            "/posture/run",
            headers={"Authorization": f"Bearer {viewer_token}"},
        )
        assert resp.status_code == 403, (
            f"viewer on operator route: expected 403, got {resp.status_code}: {resp.text}"
        )
        assert "insufficient" in resp.json().get("detail", "").lower()


def test_require_role_403_viewer_on_execute_route(db):
    """viewer token on operator-required /recommendations/{id}/execute → 403."""
    import agent.main as main_mod

    viewer_token = _make_user_token(db, "viewer2", "viewer")
    p_settings, p_db = _make_multi_client(db)
    with p_settings, p_db:
        client = TestClient(main_mod.app, raise_server_exceptions=True)
        resp = client.post(
            "/recommendations/999/execute",
            headers={"Authorization": f"Bearer {viewer_token}"},
        )
        # 403 role failure takes precedence over 404 (not found) or 503 (db not ready)
        assert resp.status_code == 403, (
            f"viewer on execute route: expected 403, got {resp.status_code}: {resp.text}"
        )


# ---------------------------------------------------------------------------
# 200 when role is sufficient
# ---------------------------------------------------------------------------


def test_require_role_200_operator_on_operator_route(db):
    """operator token on operator-required /posture/run → not 401/403 (likely 503 db-not-ready or 422)."""
    import agent.main as main_mod

    operator_token = _make_user_token(db, "op_user", "operator")
    p_settings, p_db = _make_multi_client(db)
    with p_settings, p_db:
        client = TestClient(main_mod.app, raise_server_exceptions=True)
        resp = client.post(
            "/posture/run",
            headers={"Authorization": f"Bearer {operator_token}"},
        )
        # Role check passes → should NOT be 401 or 403 (may be 503 if settings missing)
        assert resp.status_code not in (401, 403), (
            f"operator on operator route: expected role to pass, got {resp.status_code}: {resp.text}"
        )


def test_require_role_200_admin_on_operator_route(db):
    """admin token on operator-required /posture/run → not 401/403."""
    import agent.main as main_mod

    admin_token = _make_user_token(db, "admin_user", "admin")
    p_settings, p_db = _make_multi_client(db)
    with p_settings, p_db:
        client = TestClient(main_mod.app, raise_server_exceptions=True)
        resp = client.post(
            "/posture/run",
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert resp.status_code not in (401, 403), (
            f"admin on operator route: expected role to pass, got {resp.status_code}: {resp.text}"
        )


def test_require_role_200_viewer_on_viewer_route(db):
    """viewer token on viewer-required /metrics → 200."""
    import agent.main as main_mod

    viewer_token = _make_user_token(db, "viewer3", "viewer")
    p_settings, p_db = _make_multi_client(db)
    with p_settings, p_db:
        client = TestClient(main_mod.app, raise_server_exceptions=True)
        resp = client.get(
            "/metrics",
            headers={"Authorization": f"Bearer {viewer_token}"},
        )
        assert resp.status_code == 200, (
            f"viewer on /metrics: expected 200, got {resp.status_code}: {resp.text}"
        )


def test_require_role_200_admin_on_viewer_route(db):
    """admin token on viewer-required /metrics → 200 (admin satisfies viewer)."""
    import agent.main as main_mod

    admin_token = _make_user_token(db, "admin2", "admin")
    p_settings, p_db = _make_multi_client(db)
    with p_settings, p_db:
        client = TestClient(main_mod.app, raise_server_exceptions=True)
        resp = client.get(
            "/metrics",
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert resp.status_code == 200, (
            f"admin on /metrics: expected 200, got {resp.status_code}: {resp.text}"
        )


# ---------------------------------------------------------------------------
# Single-mode backwards compatibility (DEC-AUTH-P6-004, DEC-COMPAT-P6-001)
# ---------------------------------------------------------------------------


def test_single_mode_legacy_token_passes_all_role_checks(db):
    """single mode: SHAFERHUND_TOKEN → synthetic admin → satisfies every role check.

    Phase 1-5 deployments must not break when role middleware is added.
    Tests both a viewer-required route (/metrics) and an operator-required
    route (/posture/run) to confirm the synthetic admin clears all checks.
    """
    import agent.main as main_mod
    from agent.config import Settings

    settings = Settings(
        anthropic_api_key="test-key",
        shaferhund_token="legacy-secret",
        shaferhund_auth_mode="single",
    )
    with (
        patch.object(main_mod, "_settings", settings),
        patch.object(main_mod, "_db", db),
    ):
        client = TestClient(main_mod.app, raise_server_exceptions=True)

        # viewer-required route
        resp = client.get(
            "/metrics",
            headers={"Authorization": "Bearer legacy-secret"},
        )
        assert resp.status_code == 200, (
            f"single-mode legacy token on /metrics: expected 200, got {resp.status_code}"
        )

        # operator-required route — role check must pass even though it's "operator"
        resp = client.post(
            "/posture/run",
            headers={"Authorization": "Bearer legacy-secret"},
        )
        assert resp.status_code not in (401, 403), (
            f"single-mode legacy token on /posture/run: expected role to pass, "
            f"got {resp.status_code}: {resp.text}"
        )
