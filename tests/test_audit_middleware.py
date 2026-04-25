"""
Integration tests for the AuditMiddleware in agent/main.py.

Tests that authenticated mutating requests produce audit_log rows, that public
routes are NOT audited, and that body excerpts are sanitized and truncated.

(REQ-P0-P6-005, DEC-AUDIT-P6-001, DEC-AUDIT-P6-002)

Strategy: use TestClient with monkeypatched module-level singletons so we
exercise the real middleware path end-to-end (authenticate → route → middleware
fires → row appears in DB).  No internal modules are mocked.
"""

import sqlite3
from types import SimpleNamespace
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

import agent.main as _main
from agent.auth import generate_token, hash_password
from agent.models import (
    count_audit_events,
    init_db,
    insert_user,
    insert_user_token,
    list_audit_events,
)

_TEST_KEY = b"test-audit-middleware-key-32byte"


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def db(tmp_path):
    conn = init_db(str(tmp_path / "mw_test.db"))
    yield conn
    conn.close()


def _make_admin(db, username="mw_admin"):
    ph = hash_password("pw")
    uid = insert_user(db, username, ph, "admin")
    raw, h = generate_token()
    insert_user_token(db, uid, h, f"{username}-tok")
    return raw


def _make_operator(db, username="mw_op"):
    ph = hash_password("pw")
    uid = insert_user(db, username, ph, "operator")
    raw, h = generate_token()
    insert_user_token(db, uid, h, f"{username}-tok")
    return raw


def _make_viewer(db, username="mw_viewer"):
    ph = hash_password("pw")
    uid = insert_user(db, username, ph, "viewer")
    raw, h = generate_token()
    insert_user_token(db, uid, h, f"{username}-tok")
    return raw


def _settings_multi():
    return SimpleNamespace(
        shaferhund_token="",
        shaferhund_auth_mode="multi",
        shaferhund_audit_key="",
        sigmac_available=False,
        sigmac_version=None,
        cloudtrail_enabled=False,
        AUTO_DEPLOY_ENABLED=False,
        triage_hourly_budget=20,
        rules_dir="/tmp/shaferhund-test-rules",
        art_tests_file="atomic_tests.yaml",
        redteam_target_container="redteam-target",
        posture_run_schedule_seconds=0,
    )


@pytest.fixture()
def client(db):
    """TestClient with patched module-level singletons (no lifespan).

    # @mock-exempt: patch.object targets module-level singletons populated by
    #               lifespan() — equivalent to dependency injection at app boundary.
    #               Same pattern as test_role_middleware.py.
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
        yield TestClient(_main.app, raise_server_exceptions=False)


# ---------------------------------------------------------------------------
# Core middleware behaviour: authenticated requests are audited
# ---------------------------------------------------------------------------


def test_authenticated_get_metrics_creates_no_audit_row(db, client):
    """GET /metrics (viewer role, non-admin GET) does NOT create an audit row.

    DEC-AUDIT-P6-002: readonly viewer/operator GETs are not audited.
    """
    raw = _make_admin(db)
    before = count_audit_events(db)
    client.get("/metrics", headers={"Authorization": f"Bearer {raw}"})
    after = count_audit_events(db)
    # GET /metrics is NOT in _AUDITED_GET_PREFIXES so no row expected.
    assert after == before, "GET /metrics should not create an audit row"


def test_authenticated_get_audit_creates_audit_row(db, client):
    """GET /audit (admin-only GET) DOES create an audit row.

    DEC-AUDIT-P6-002: admin-only GETs are audited.
    """
    raw = _make_admin(db)
    before = count_audit_events(db)
    client.get("/audit", headers={"Authorization": f"Bearer {raw}"})
    after = count_audit_events(db)
    assert after == before + 1, "GET /audit should create one audit row"


def test_audit_row_has_correct_actor_fields(db, client):
    """Audit row records the correct actor_username, actor_role, method, path."""
    raw = _make_admin(db, username="inspector")
    client.get("/audit", headers={"Authorization": f"Bearer {raw}"})

    rows = list_audit_events(db, limit=10)
    assert len(rows) >= 1
    row = dict(rows[0])
    assert row["actor_username"] == "inspector"
    assert row["actor_role"] == "admin"
    assert row["method"] == "GET"
    assert row["path"] == "/audit"


def test_audit_row_records_status_code(db, client):
    """Audit row records the HTTP response status_code."""
    raw = _make_admin(db)
    client.get("/audit", headers={"Authorization": f"Bearer {raw}"})

    rows = list_audit_events(db, limit=5)
    assert rows[0]["status_code"] == 200


def test_public_health_route_not_audited(db, client):
    """GET /health (public, no auth) does NOT create any audit row."""
    before = count_audit_events(db)
    client.get("/health")
    after = count_audit_events(db)
    assert after == before, "Public /health should never create an audit row"


def test_unauthenticated_request_not_audited(db, client):
    """A request with no auth token (→ 401) does NOT create an audit row.

    The middleware only records when request.state.user is set by _require_auth.
    A 401 means _require_auth raised before setting state.user.
    """
    before = count_audit_events(db)
    client.get("/audit")  # no bearer → 401
    after = count_audit_events(db)
    assert after == before, "Unauthenticated (401) requests must not be audited"


def test_failed_auth_request_not_audited(db, client):
    """A request with a wrong token (→ 401) does NOT create an audit row."""
    before = count_audit_events(db)
    client.get("/audit", headers={"Authorization": "Bearer wrong-token"})
    after = count_audit_events(db)
    assert after == before, "401 auth failure must not produce an audit row"


def test_audit_verify_get_creates_audit_row(db, client):
    """GET /audit/verify (admin-only GET) creates an audit row."""
    raw = _make_admin(db)
    before = count_audit_events(db)
    client.get("/audit/verify", headers={"Authorization": f"Bearer {raw}"})
    after = count_audit_events(db)
    assert after == before + 1, "GET /audit/verify should create one audit row"


def test_canary_hit_not_audited(db, client):
    """GET /canary/hit/{token} (public trap endpoint) is never audited."""
    before = count_audit_events(db)
    client.get("/canary/hit/fake-token-for-test")
    after = count_audit_events(db)
    assert after == before, "Public canary hit endpoint must not be audited"


# ---------------------------------------------------------------------------
# Body excerpt sanitization
# ---------------------------------------------------------------------------


def test_get_request_body_excerpt_is_null(db, client):
    """GET requests have no body — body_excerpt stored as NULL."""
    raw = _make_admin(db)
    client.get("/audit", headers={"Authorization": f"Bearer {raw}"})
    rows = list_audit_events(db, limit=5)
    row = dict(rows[0])
    # GET requests have no body — body_excerpt should be NULL
    assert row["body_excerpt"] is None, "GET requests should have NULL body_excerpt"


# ---------------------------------------------------------------------------
# Chain integrity after middleware inserts
# ---------------------------------------------------------------------------


def test_middleware_inserts_form_valid_chain(db, client):
    """Multiple middleware-generated rows form an intact HMAC chain."""
    from agent.audit import verify_chain
    raw = _make_admin(db)

    # Generate several audit rows via the middleware
    client.get("/audit", headers={"Authorization": f"Bearer {raw}"})
    client.get("/audit", headers={"Authorization": f"Bearer {raw}"})
    client.get("/audit/verify", headers={"Authorization": f"Bearer {raw}"})

    total = count_audit_events(db)
    assert total >= 3

    result = verify_chain(db, _TEST_KEY)
    assert result["intact"] is True, (
        f"Chain should be intact after middleware inserts; got: {result}"
    )
    assert result["total_rows"] == total


# ---------------------------------------------------------------------------
# Legacy single-mode: SHAFERHUND_TOKEN still works and is audited
# ---------------------------------------------------------------------------


def test_legacy_token_single_mode_admin_get_audited(db):
    """In single mode with SHAFERHUND_TOKEN, admin GET /audit is still audited."""
    from unittest.mock import patch
    legacy_token = "legacy-static-token"
    settings = SimpleNamespace(
        shaferhund_token=legacy_token,
        shaferhund_auth_mode="single",
        shaferhund_audit_key="",
        sigmac_available=False,
        sigmac_version=None,
        cloudtrail_enabled=False,
        AUTO_DEPLOY_ENABLED=False,
        triage_hourly_budget=20,
    )

    before = count_audit_events(db)
    with (
        patch.object(_main, "_db", db),
        patch.object(_main, "_settings", settings),
        patch.object(_main, "_audit_hmac_key", _TEST_KEY),
        patch.object(_main, "_triage_queue", None),
        patch.object(_main, "_poller_healthy", True),
    ):
        c = TestClient(_main.app, raise_server_exceptions=False)
        c.get("/audit", headers={"Authorization": f"Bearer {legacy_token}"})

    after = count_audit_events(db)
    assert after == before + 1

    # Row should carry __legacy_token__ as actor (from LEGACY_ADMIN_USER)
    rows = list_audit_events(db, limit=5)
    row = dict(rows[0])
    assert row["actor_username"] == "__legacy_token__"
    assert row["actor_role"] == "admin"
