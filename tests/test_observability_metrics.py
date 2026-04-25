"""
/metrics auth + fleet section tests — Phase 6 Wave B3, REQ-P1-P6-005.

Verifies:
  1. /metrics without auth returns 401 (regression guard)
  2. /metrics with auth includes the auth section with all 9 keys
  3. users_by_role aggregates correctly (1 admin + 2 operators + 3 viewers)
  4. tokens_by_status buckets correctly (2 active + 1 revoked + 1 expired)
  5. /metrics with auth includes the fleet section with all 6 keys
  6. rules_deployed_count counts only deployed=1 rules
  7. manifest_endpoints_seen reflects paths fetched in the last 24h

Approach: multi-auth mode with real in-memory SQLite.  _settings and _db
are patched at the module level (same pattern as test_route_role_tags.py).
AuditMiddleware writes real audit_log rows when TestClient exercises routes.

# @mock-exempt: No mocks of internal modules. The audit_log source-of-truth
# for fleet counters is exercised end-to-end by hitting /fleet/manifest/* via
# TestClient — the same path a real fleet agent would use (DEC-OBSERVABILITY-P6-001).
"""

from datetime import datetime, timezone, timedelta
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient
from unittest.mock import patch

import agent.main as main_module
import agent.sources.cloudtrail as ct_module
from agent.auth import generate_token, hash_password
from agent.config import Settings
from agent.models import (
    init_db,
    insert_rule,
    insert_user,
    insert_user_token,
    revoke_user_token,
    set_user_disabled,
    tag_rule,
    update_user_last_login,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_AUTH_SECTION_KEYS = {
    "mode",
    "users_total",
    "users_by_role",
    "users_disabled_count",
    "tokens_active_count",
    "tokens_revoked_count",
    "tokens_expired_count",
    "last_login_at",
    "last_user_created_at",
}

_FLEET_SECTION_KEYS = {
    "manifest_fetches_24h",
    "last_manifest_fetch_at",
    "rules_tagged_total",
    "tags_total",
    "rules_deployed_count",
    "manifest_endpoints_seen",
}


def _make_multi_settings() -> Settings:
    return Settings(
        anthropic_api_key="test-key",
        shaferhund_token="",
        shaferhund_auth_mode="multi",
        shaferhund_audit_key="bb" * 32,
    )


def _patch_singletons(conn, settings):
    main_module._db = conn
    main_module._settings = settings
    main_module._triage_queue = None
    main_module._poller_healthy = False
    main_module._last_poll_at = None
    main_module._audit_hmac_key = bytes.fromhex(settings.shaferhund_audit_key)
    ct_module.CLOUDTRAIL_STATS["last_poll_at"] = None
    ct_module.CLOUDTRAIL_STATS["last_poll_status"] = None
    ct_module.CLOUDTRAIL_STATS["events_ingested_total"] = 0
    ct_module.CLOUDTRAIL_STATS["s3_list_errors_total"] = 0
    ct_module.CLOUDTRAIL_STATS["parse_errors_total"] = 0
    ct_module.CLOUDTRAIL_STATS["objects_processed_total"] = 0


def _setup(conn=None):
    """Return (conn, settings, TestClient) with a fresh admin user + token."""
    if conn is None:
        conn = init_db(":memory:")
    settings = _make_multi_settings()
    _patch_singletons(conn, settings)

    ph = hash_password("pw")
    uid = insert_user(conn, "admin", ph, "admin")
    raw, h = generate_token()
    insert_user_token(conn, uid, h, "admin-tok")

    client = TestClient(main_module.app, raise_server_exceptions=True)
    return conn, raw, client


def _auth(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


# ---------------------------------------------------------------------------
# Tests — basic auth gate
# ---------------------------------------------------------------------------


def test_metrics_no_auth_returns_401():
    """GET /metrics without a token returns 401 (regression: auth gate must stay)."""
    conn = init_db(":memory:")
    settings = _make_multi_settings()
    _patch_singletons(conn, settings)
    c = TestClient(main_module.app, raise_server_exceptions=True)
    assert c.get("/metrics").status_code == 401


# ---------------------------------------------------------------------------
# Tests — auth section
# ---------------------------------------------------------------------------


def test_metrics_with_auth_includes_auth_section():
    """auth section present and has all 9 expected keys."""
    conn, token, c = _setup()
    resp = c.get("/metrics", headers=_auth(token))
    assert resp.status_code == 200
    data = resp.json()
    assert "auth" in data, "auth section missing from /metrics"
    assert set(data["auth"].keys()) == _AUTH_SECTION_KEYS, (
        f"auth section keys mismatch: {set(data['auth'].keys())}"
    )


def test_metrics_users_by_role_counts_correct():
    """1 admin + 2 operators + 3 viewers → users_by_role correct."""
    conn = init_db(":memory:")
    ph = hash_password("pw")

    # Seed roles: 1 admin (also the requesting user), 2 operators, 3 viewers
    admin_uid = insert_user(conn, "admin", ph, "admin")
    raw, h = generate_token()
    insert_user_token(conn, admin_uid, h, "admin-tok")

    for i in range(2):
        insert_user(conn, f"op{i}", ph, "operator")
    for i in range(3):
        insert_user(conn, f"viewer{i}", ph, "viewer")

    settings = _make_multi_settings()
    _patch_singletons(conn, settings)
    c = TestClient(main_module.app, raise_server_exceptions=True)

    resp = c.get("/metrics", headers=_auth(raw))
    assert resp.status_code == 200
    by_role = resp.json()["auth"]["users_by_role"]
    assert by_role["admin"] == 1, f"expected 1 admin, got {by_role['admin']}"
    assert by_role["operator"] == 2, f"expected 2 operators, got {by_role['operator']}"
    assert by_role["viewer"] == 3, f"expected 3 viewers, got {by_role['viewer']}"


def test_metrics_tokens_by_status():
    """2 active + 1 revoked + 1 expired → correct token bucket counts."""
    conn = init_db(":memory:")
    ph = hash_password("pw")
    uid = insert_user(conn, "admin", ph, "admin")

    # Token 1 — admin auth token (active, no expiry)
    raw_admin, h_admin = generate_token()
    insert_user_token(conn, uid, h_admin, "admin-auth")

    # Token 2 — active with future expiry
    future_ts = (datetime.now(timezone.utc) + timedelta(days=30)).isoformat()
    raw2, h2 = generate_token()
    insert_user_token(conn, uid, h2, "active-expiry", expires_at=future_ts)

    # Token 3 — revoked
    raw3, h3 = generate_token()
    tok3_id = insert_user_token(conn, uid, h3, "revoked-tok")
    revoke_user_token(conn, tok3_id, datetime.now(timezone.utc).isoformat())

    # Token 4 — expired (past expires_at, not revoked)
    past_ts = (datetime.now(timezone.utc) - timedelta(days=1)).isoformat()
    raw4, h4 = generate_token()
    insert_user_token(conn, uid, h4, "expired-tok", expires_at=past_ts)

    settings = _make_multi_settings()
    _patch_singletons(conn, settings)
    c = TestClient(main_module.app, raise_server_exceptions=True)

    resp = c.get("/metrics", headers=_auth(raw_admin))
    assert resp.status_code == 200
    auth_section = resp.json()["auth"]

    assert auth_section["tokens_active_count"] == 2, (
        f"expected 2 active, got {auth_section['tokens_active_count']}"
    )
    assert auth_section["tokens_revoked_count"] == 1, (
        f"expected 1 revoked, got {auth_section['tokens_revoked_count']}"
    )
    assert auth_section["tokens_expired_count"] == 1, (
        f"expected 1 expired, got {auth_section['tokens_expired_count']}"
    )


# ---------------------------------------------------------------------------
# Tests — fleet section
# ---------------------------------------------------------------------------


def test_metrics_with_auth_includes_fleet_section():
    """fleet section present and has all 6 expected keys."""
    conn, token, c = _setup()
    resp = c.get("/metrics", headers=_auth(token))
    assert resp.status_code == 200
    data = resp.json()
    assert "fleet" in data, "fleet section missing from /metrics"
    assert set(data["fleet"].keys()) == _FLEET_SECTION_KEYS, (
        f"fleet section keys mismatch: {set(data['fleet'].keys())}"
    )


def test_metrics_rules_deployed_count():
    """3 deployed + 2 undeployed rules → rules_deployed_count == 3."""
    conn = init_db(":memory:")
    ph = hash_password("pw")
    uid = insert_user(conn, "admin", ph, "admin")
    raw, h = generate_token()
    insert_user_token(conn, uid, h, "admin-tok")

    # Seed 3 deployed and 2 undeployed rules.
    # cluster_id=None avoids FK constraint (NULL is valid for nullable FKs in SQLite).
    for i in range(3):
        insert_rule(conn, rule_id=f"rule-dep-{i}", cluster_id=None,
                    rule_type="yara", rule_content=f"rule r{i} {{}}", syntax_valid=True)
        conn.execute("UPDATE rules SET deployed = 1 WHERE id = ?", (f"rule-dep-{i}",))
    for i in range(2):
        insert_rule(conn, rule_id=f"rule-undep-{i}", cluster_id=None,
                    rule_type="yara", rule_content=f"rule u{i} {{}}", syntax_valid=True)
        # deployed stays 0 (default)
    conn.commit()

    settings = _make_multi_settings()
    _patch_singletons(conn, settings)
    c = TestClient(main_module.app, raise_server_exceptions=True)

    resp = c.get("/metrics", headers=_auth(raw))
    assert resp.status_code == 200
    fleet = resp.json()["fleet"]
    assert fleet["rules_deployed_count"] == 3, (
        f"expected 3 deployed, got {fleet['rules_deployed_count']}"
    )


def test_metrics_manifest_endpoints_seen():
    """Fetching /fleet/manifest/x and /fleet/manifest/y → both appear in manifest_endpoints_seen."""
    conn = init_db(":memory:")
    ph = hash_password("pw")
    uid = insert_user(conn, "admin", ph, "admin")
    raw, h = generate_token()
    insert_user_token(conn, uid, h, "admin-tok")

    # Seed deployed rules with two different tags.
    # cluster_id=None avoids FK constraint (NULL is valid for nullable FKs in SQLite).
    for tag in ("edr-prod", "ids-stage"):
        rule_id = f"rule-{tag}"
        insert_rule(conn, rule_id=rule_id, cluster_id=None,
                    rule_type="yara",
                    rule_content=f"rule r_{tag.replace('-', '_')} {{}}",
                    syntax_valid=True)
        conn.execute("UPDATE rules SET deployed = 1 WHERE id = ?", (rule_id,))
        conn.commit()
        tag_rule(conn, rule_id, tag)

    settings = _make_multi_settings()
    _patch_singletons(conn, settings)
    c = TestClient(main_module.app, raise_server_exceptions=True)

    # Fetch both manifest endpoints — AuditMiddleware writes audit_log rows
    for tag in ("edr-prod", "ids-stage"):
        resp_m = c.get(
            f"/fleet/manifest/{tag}",
            headers=_auth(raw),
        )
        assert resp_m.status_code == 200, f"manifest fetch for {tag} failed: {resp_m.status_code}"

    resp = c.get("/metrics", headers=_auth(raw))
    assert resp.status_code == 200
    seen = resp.json()["fleet"]["manifest_endpoints_seen"]
    assert "/fleet/manifest/edr-prod" in seen, f"edr-prod missing from seen: {seen}"
    assert "/fleet/manifest/ids-stage" in seen, f"ids-stage missing from seen: {seen}"
