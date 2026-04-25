"""
/health auth.* and fleet.* block tests — Phase 6 Wave B3, REQ-P1-P6-005.

Verifies:
  1. auth block present in single mode (zero-state)
  2. auth block present in multi mode with no users
  3. auth block reflects seeded users and last_login_at
  4. fleet block present with no activity (zeros + null)
  5. fleet block reflects audit_log after a real manifest GET
  6. top-level /health key set is exactly the 9-key set after Phase 6 Wave B3

Approach: patch agent.main singletons (_db, _settings) directly — same
pattern as test_health.py.  The fleet manifest test uses TestClient to
exercise the real manifest route so audit_log is written by AuditMiddleware,
verifying the end-to-end counter path.

# @mock-exempt: No mocks of internal modules. _db and _settings are module-level
# singletons (not function arguments) — patching them at the module level is the
# only way to inject test state without running the full lifespan.  AuditMiddleware,
# models, and observability are exercised against their real implementations.
"""

from datetime import datetime, timezone, timedelta
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient
from unittest.mock import patch

import agent.main as main_module
import agent.sources.cloudtrail as ct_module
from agent.auth import generate_token, hash_password
from agent.models import (
    init_db,
    insert_rule,
    insert_user,
    insert_user_token,
    tag_rule,
    update_user_last_login,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_EXPECTED_HEALTH_KEYS = {
    "status",
    "poller_healthy",
    "threat_intel",
    "canary",
    "posture",
    "recommendations",
    "cloudtrail",
    "auth",
    "fleet",
}


def _make_settings(auth_mode: str = "single") -> SimpleNamespace:
    return SimpleNamespace(
        shaferhund_token="",
        shaferhund_auth_mode=auth_mode,
        db_path=":memory:",
        alerts_file="/dev/null",
        suricata_eve_file="/dev/null",
        triage_hourly_budget=20,
        AUTO_DEPLOY_ENABLED=False,
        sigmac_available=False,
        sigmac_version=None,
        cloudtrail_enabled=False,
        cloudtrail_s3_bucket="",
        cloudtrail_s3_prefix="",
        # audit key — required by AuditMiddleware
        shaferhund_audit_key="aa" * 32,
    )


def _patch_singletons(conn, settings):
    """Patch main module singletons and reset ancillary state."""
    import hashlib
    main_module._db = conn
    main_module._settings = settings
    main_module._triage_queue = None
    main_module._poller_healthy = False
    main_module._last_poll_at = None
    main_module._audit_hmac_key = bytes.fromhex(settings.shaferhund_audit_key)
    # Reset CloudTrail stats to avoid cross-test pollution
    ct_module.CLOUDTRAIL_STATS["last_poll_at"] = None
    ct_module.CLOUDTRAIL_STATS["last_poll_status"] = None
    ct_module.CLOUDTRAIL_STATS["events_ingested_total"] = 0
    ct_module.CLOUDTRAIL_STATS["s3_list_errors_total"] = 0
    ct_module.CLOUDTRAIL_STATS["parse_errors_total"] = 0
    ct_module.CLOUDTRAIL_STATS["objects_processed_total"] = 0


def _client(conn, settings) -> TestClient:
    _patch_singletons(conn, settings)
    return TestClient(main_module.app, raise_server_exceptions=True)


# ---------------------------------------------------------------------------
# Tests — auth block
# ---------------------------------------------------------------------------


def test_health_includes_auth_block_single_mode():
    """single mode + empty users table → auth = {mode:'single', users_count:0, last_login_at:null}."""
    conn = init_db(":memory:")
    settings = _make_settings(auth_mode="single")
    c = _client(conn, settings)

    resp = c.get("/health")
    assert resp.status_code == 200
    data = resp.json()

    auth = data["auth"]
    assert auth["mode"] == "single"
    assert auth["users_count"] == 0
    assert auth["last_login_at"] is None


def test_health_includes_auth_block_multi_mode_no_users():
    """multi mode + empty users table → auth = {mode:'multi', users_count:0, last_login_at:null}."""
    conn = init_db(":memory:")
    settings = _make_settings(auth_mode="multi")
    c = _client(conn, settings)

    resp = c.get("/health")
    assert resp.status_code == 200
    data = resp.json()

    auth = data["auth"]
    assert auth["mode"] == "multi"
    assert auth["users_count"] == 0
    assert auth["last_login_at"] is None


def test_health_includes_auth_block_multi_mode_with_users_and_login():
    """2 users, one has logged in → users_count=2, last_login_at reflects that ts."""
    conn = init_db(":memory:")
    settings = _make_settings(auth_mode="multi")

    ph = hash_password("pw")
    uid1 = insert_user(conn, "alice", ph, "admin")
    uid2 = insert_user(conn, "bob", ph, "viewer")

    login_ts = "2026-04-24T10:00:00+00:00"
    update_user_last_login(conn, uid1, login_ts)
    # uid2 has never logged in (last_login_at stays NULL)

    c = _client(conn, settings)
    resp = c.get("/health")
    assert resp.status_code == 200
    data = resp.json()

    auth = data["auth"]
    assert auth["mode"] == "multi"
    assert auth["users_count"] == 2
    assert auth["last_login_at"] == login_ts


# ---------------------------------------------------------------------------
# Tests — fleet block
# ---------------------------------------------------------------------------


def test_health_includes_fleet_block_no_activity():
    """No manifest fetches → fleet = {manifest_fetches_24h:0, last_manifest_fetch_at:null}."""
    conn = init_db(":memory:")
    settings = _make_settings(auth_mode="single")
    c = _client(conn, settings)

    resp = c.get("/health")
    assert resp.status_code == 200
    data = resp.json()

    fleet = data["fleet"]
    assert fleet["manifest_fetches_24h"] == 0
    assert fleet["last_manifest_fetch_at"] is None


def test_health_includes_fleet_block_after_manifest_fetch():
    """After a real GET /fleet/manifest/<tag>, manifest_fetches_24h == 1 and last_manifest_fetch_at is set."""
    conn = init_db(":memory:")
    settings = _make_settings(auth_mode="multi")
    # Need a valid user + token to hit the auth-gated manifest route
    ph = hash_password("pw")
    uid = insert_user(conn, "admin", ph, "admin")
    raw, h = generate_token()
    insert_user_token(conn, uid, h, "admin-tok")

    # Seed a deployed rule with the tag so the manifest is non-empty.
    # cluster_id=None avoids FK constraint (NULL is valid for nullable FKs in SQLite).
    insert_rule(conn, rule_id="rule-obs-1", cluster_id=None,
                rule_type="yara", rule_content="rule r {}", syntax_valid=True)
    conn.execute("UPDATE rules SET deployed = 1 WHERE id = ?", ("rule-obs-1",))
    conn.commit()
    tag_rule(conn, "rule-obs-1", "edr-test")

    c = _client(conn, settings)

    # Hit the manifest endpoint — AuditMiddleware will write an audit_log row
    resp_manifest = c.get(
        "/fleet/manifest/edr-test",
        headers={"Authorization": f"Bearer {raw}"},
    )
    assert resp_manifest.status_code == 200

    resp = c.get("/health")
    assert resp.status_code == 200
    data = resp.json()

    fleet = data["fleet"]
    assert fleet["manifest_fetches_24h"] == 1
    assert fleet["last_manifest_fetch_at"] is not None
    # Timestamp should be a recent ISO string
    assert "2026" in fleet["last_manifest_fetch_at"]


# ---------------------------------------------------------------------------
# Tests — total key set
# ---------------------------------------------------------------------------


def test_health_total_keys():
    """Top-level /health keys are exactly the 9-key set after Phase 6 Wave B3."""
    conn = init_db(":memory:")
    settings = _make_settings(auth_mode="single")
    c = _client(conn, settings)

    resp = c.get("/health")
    assert resp.status_code == 200
    assert set(resp.json().keys()) == _EXPECTED_HEALTH_KEYS, (
        f"Expected {_EXPECTED_HEALTH_KEYS}, got {set(resp.json().keys())}"
    )
