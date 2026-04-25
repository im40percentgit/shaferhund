"""
HTTP route tests for GET /cloud/findings (Phase 5 Wave A2, REQ-P0-P5-005).

Covers:
  1. GET /cloud/findings — no auth → 401 when token set
  2. GET /cloud/findings — with auth → 200, [] on empty DB
  3. GET /cloud/findings — seeded rows → 200, correct count + newest-first
  4. GET /cloud/findings?severity=Critical — filters correctly
  5. GET /cloud/findings?limit=5 — honours limit param
  6. GET /cloud/findings?limit=999 — caps at 200

DB: real in-memory SQLite (Sacred Practice #5).
No mocks on internal modules.

@decision DEC-CLOUD-009
@title Route tests use real in-memory SQLite + TestClient, no mocks on models
@status accepted
@rationale The route, model helpers, and DB schema are all internal.
           Mocking any of them would test the mock, not the integration.
           TestClient runs the full FastAPI stack including auth middleware.
"""

import time
from datetime import datetime, timezone
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient

import agent.main as main_module
from agent.models import init_db, insert_cloud_finding


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_settings(tmp_path, token: str = "") -> SimpleNamespace:
    return SimpleNamespace(
        shaferhund_token=token,
        rules_dir=str(tmp_path / "rules"),
        db_path=":memory:",
        alerts_file="/dev/null",
        suricata_eve_file="/dev/null",
        triage_hourly_budget=20,
        AUTO_DEPLOY_ENABLED=False,
        sigmac_available=False,
        sigmac_version=None,
        canary_base_url="http://127.0.0.1:8000",
        canary_base_hostname="canary.local",
        redteam_target_container="test-container",
    )


def _make_client(tmp_path, token: str = ""):
    """Return (TestClient, conn) with module singletons wired to an in-memory DB."""
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir(exist_ok=True)

    conn = init_db(":memory:")
    settings = _make_settings(tmp_path, token=token)

    main_module._db = conn
    main_module._settings = settings
    main_module._triage_queue = None
    main_module._clusterer = None
    main_module._poller_healthy = False
    main_module._last_poll_at = None

    client = TestClient(main_module.app, raise_server_exceptions=True)
    return client, conn


def _seed_finding(
    conn,
    rule_name: str = "root_console_login",
    rule_severity: str = "Critical",
    title: str = "Root user console login from 198.51.100.42",
) -> int:
    """Insert a cloud_audit_findings row and return its id."""
    return insert_cloud_finding(
        conn=conn,
        alert_id=None,
        rule_name=rule_name,
        rule_severity=rule_severity,
        title=title,
        description="Test description",
        principal="arn:aws:iam::123456789012:root",
        src_ip="198.51.100.42",
        event_name="ConsoleLogin",
        event_source="signin.amazonaws.com",
        raw_event='{"eventName": "ConsoleLogin"}',
    )


# ---------------------------------------------------------------------------
# Auth gate tests
# ---------------------------------------------------------------------------


def test_get_findings_no_auth(tmp_path):
    """GET /cloud/findings → 401 when SHAFERHUND_TOKEN is set and no header sent."""
    client, conn = _make_client(tmp_path, token="secrettoken")
    resp = client.get("/cloud/findings")
    assert resp.status_code == 401, f"Expected 401, got {resp.status_code}: {resp.text}"
    conn.close()


def test_get_findings_wrong_token(tmp_path):
    """GET /cloud/findings → 401 with wrong bearer token."""
    client, conn = _make_client(tmp_path, token="secrettoken")
    resp = client.get("/cloud/findings", headers={"Authorization": "Bearer wrongtoken"})
    assert resp.status_code == 401
    conn.close()


# ---------------------------------------------------------------------------
# Success path — empty DB
# ---------------------------------------------------------------------------


def test_get_findings_with_auth_empty(tmp_path):
    """GET /cloud/findings with auth on empty DB → 200, []."""
    client, conn = _make_client(tmp_path, token="")
    resp = client.get("/cloud/findings")
    assert resp.status_code == 200, f"Expected 200, got {resp.status_code}: {resp.text}"
    assert resp.json() == []
    conn.close()


# ---------------------------------------------------------------------------
# Seeded rows
# ---------------------------------------------------------------------------


def test_get_findings_returns_seeded_rows(tmp_path):
    """Insert 3 findings via models helper → GET returns 3 rows newest-first."""
    client, conn = _make_client(tmp_path, token="")

    id1 = _seed_finding(conn, rule_name="root_console_login", rule_severity="Critical")
    id2 = _seed_finding(conn, rule_name="mfa_disabled_for_user", rule_severity="High")
    id3 = _seed_finding(conn, rule_name="iam_user_created", rule_severity="Medium")

    resp = client.get("/cloud/findings")
    assert resp.status_code == 200
    data = resp.json()
    assert len(data) == 3, f"Expected 3 findings, got {len(data)}"

    # Required fields present on every row
    for row in data:
        for field in (
            "id", "alert_id", "rule_name", "rule_severity",
            "title", "description", "principal", "src_ip",
            "event_name", "event_source", "detected_at", "event_age_seconds",
        ):
            assert field in row, f"Field '{field}' missing from row: {row.keys()}"

    # Newest-first: detected_at values should be non-increasing
    timestamps = [row["detected_at"] for row in data]
    assert timestamps == sorted(timestamps, reverse=True) or len(set(timestamps)) == 1, (
        f"Rows not in newest-first order: {timestamps}"
    )

    conn.close()


def test_get_findings_event_age_seconds_is_non_negative(tmp_path):
    """event_age_seconds derived field should be >= 0 for a freshly inserted finding."""
    client, conn = _make_client(tmp_path, token="")
    _seed_finding(conn)

    resp = client.get("/cloud/findings")
    assert resp.status_code == 200
    data = resp.json()
    assert len(data) == 1
    assert data[0]["event_age_seconds"] >= 0
    conn.close()


# ---------------------------------------------------------------------------
# Severity filter
# ---------------------------------------------------------------------------


def test_get_findings_severity_filter(tmp_path):
    """Insert 2 Low + 1 Critical → ?severity=Critical returns only the Critical one."""
    client, conn = _make_client(tmp_path, token="")

    _seed_finding(conn, rule_name="access_key_created", rule_severity="Low", title="Low finding 1")
    _seed_finding(conn, rule_name="s3_bucket_policy_changed", rule_severity="Low", title="Low finding 2")
    _seed_finding(conn, rule_name="root_console_login", rule_severity="Critical", title="Critical finding")

    resp = client.get("/cloud/findings?severity=Critical")
    assert resp.status_code == 200
    data = resp.json()
    assert len(data) == 1, f"Expected 1 Critical finding, got {len(data)}: {data}"
    assert data[0]["rule_severity"] == "Critical"
    assert data[0]["rule_name"] == "root_console_login"

    conn.close()


def test_get_findings_severity_filter_returns_all_when_absent(tmp_path):
    """No ?severity param → all severities returned."""
    client, conn = _make_client(tmp_path, token="")

    _seed_finding(conn, rule_severity="Critical")
    _seed_finding(conn, rule_severity="High")
    _seed_finding(conn, rule_severity="Medium")

    resp = client.get("/cloud/findings")
    assert resp.status_code == 200
    assert len(resp.json()) == 3
    conn.close()


# ---------------------------------------------------------------------------
# Limit param
# ---------------------------------------------------------------------------


def test_get_findings_limit_param(tmp_path):
    """Insert 10 findings → GET with ?limit=5 returns exactly 5."""
    client, conn = _make_client(tmp_path, token="")

    for i in range(10):
        _seed_finding(conn, rule_name="access_key_created", title=f"Finding {i}")

    resp = client.get("/cloud/findings?limit=5")
    assert resp.status_code == 200
    assert len(resp.json()) == 5
    conn.close()


def test_get_findings_limit_caps_at_200(tmp_path):
    """?limit=999 → server caps at 200 (max allowed)."""
    client, conn = _make_client(tmp_path, token="")

    # Insert 210 findings so we can verify the cap, not just the DB row count
    for i in range(210):
        _seed_finding(conn, rule_name="access_key_created", title=f"Finding {i}")

    resp = client.get("/cloud/findings?limit=999")
    assert resp.status_code == 200
    # Must not return more than 200 regardless of DB row count
    assert len(resp.json()) <= 200
    conn.close()


def test_get_findings_default_limit_is_50(tmp_path):
    """No limit param → default is 50; inserting 60 rows returns 50."""
    client, conn = _make_client(tmp_path, token="")

    for i in range(60):
        _seed_finding(conn, rule_name="access_key_created", title=f"Finding {i}")

    resp = client.get("/cloud/findings")
    assert resp.status_code == 200
    assert len(resp.json()) == 50
    conn.close()
