"""
CloudTrail observability tests — /health + /metrics extensions (REQ-P0-P5-006).

Wave A3 adds a ``cloudtrail`` block to both endpoints:
  /health  (public)  — enabled, events_ingested_24h, last_poll_at, findings_count
  /metrics (auth)    — full counter set + cursor fields + findings_count_total

DEC-HEALTH-002: /health stays minimal; all operational stats in /metrics.

@decision DEC-HEALTH-002
@title Split /health (public liveness) and /metrics (authenticated stats)
@status accepted
@rationale Operational stats (error counts, cursor fields, lifetime totals) are
           gated behind auth in /metrics. /health exposes only the minimum needed
           for a container liveness probe: enabled bool, 24h event count,
           last_poll_at, and findings_count. This prevents unauthenticated
           reconnaissance of CloudTrail pipeline internals.
"""

import sqlite3
import uuid
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient

import agent.main as main_module
import agent.sources.cloudtrail as ct_module
from agent.models import init_db


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_settings(tmp_path, token: str = "", cloudtrail_enabled: bool = False) -> SimpleNamespace:
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
        cloudtrail_enabled=cloudtrail_enabled,
        cloudtrail_s3_bucket="test-bucket",
        cloudtrail_s3_prefix="AWSLogs/",
        cloudtrail_aws_region="us-east-1",
        cloudtrail_poll_interval_seconds=60,
    )


def _make_client(tmp_path, token: str = "", cloudtrail_enabled: bool = False):
    """Return (TestClient, conn) with module singletons patched."""
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir(exist_ok=True)

    conn = init_db(":memory:")
    settings = _make_settings(tmp_path, token=token, cloudtrail_enabled=cloudtrail_enabled)

    main_module._db = conn
    main_module._settings = settings
    main_module._triage_queue = None
    main_module._poller_healthy = False
    main_module._last_poll_at = None

    # Reset CLOUDTRAIL_STATS between tests
    ct_module.CLOUDTRAIL_STATS["events_ingested_total"] = 0
    ct_module.CLOUDTRAIL_STATS["last_poll_at"] = None
    ct_module.CLOUDTRAIL_STATS["last_poll_status"] = None
    ct_module.CLOUDTRAIL_STATS["s3_list_errors_total"] = 0
    ct_module.CLOUDTRAIL_STATS["parse_errors_total"] = 0
    ct_module.CLOUDTRAIL_STATS["objects_processed_total"] = 0

    client = TestClient(main_module.app, raise_server_exceptions=True)
    return client, conn


def _insert_cloudtrail_row(conn: sqlite3.Connection, ingested_at: str) -> None:
    """Insert a cloudtrail alert row with an explicit ingested_at value.

    Uses direct SQL rather than insert_cloudtrail_alert() so we can control
    the ingested_at column (which DEFAULT CURRENT_TIMESTAMP would otherwise
    always set to now).  This lets the 24h window test seed rows in the past.
    """
    row_id = str(uuid.uuid4())
    conn.execute(
        """
        INSERT OR IGNORE INTO alerts
            (id, rule_id, src_ip, severity, cluster_id, source,
             dest_ip, protocol, normalized_severity, ingested_at)
        VALUES (?, ?, ?, ?, NULL, ?, ?, ?, ?, ?)
        """,
        (
            row_id,
            "cloudtrail:iam.amazonaws.com:CreateUser",
            "1.2.3.4",
            10,
            "cloudtrail",
            None,
            "https",
            "High",
            ingested_at,
        ),
    )
    conn.commit()


# ---------------------------------------------------------------------------
# /health — cloudtrail block present when enabled
# ---------------------------------------------------------------------------


def test_health_includes_cloudtrail_block_when_enabled(tmp_path):
    """/health includes cloudtrail block with 4 expected keys when enabled."""
    client, conn = _make_client(tmp_path, cloudtrail_enabled=True)

    resp = client.get("/health")
    assert resp.status_code == 200

    data = resp.json()
    assert "cloudtrail" in data, "cloudtrail block missing from /health"

    ct = data["cloudtrail"]
    assert set(ct.keys()) == {"enabled", "events_ingested_24h", "last_poll_at", "findings_count"}, (
        f"Unexpected cloudtrail keys in /health: {set(ct.keys())}"
    )
    assert ct["enabled"] is True
    assert isinstance(ct["events_ingested_24h"], int)
    assert ct["last_poll_at"] is None   # no poll yet
    assert isinstance(ct["findings_count"], int)

    conn.close()


def test_health_includes_cloudtrail_block_when_disabled(tmp_path):
    """/health cloudtrail block present with enabled=false when cloudtrail disabled."""
    client, conn = _make_client(tmp_path, cloudtrail_enabled=False)

    resp = client.get("/health")
    assert resp.status_code == 200

    data = resp.json()
    assert "cloudtrail" in data, "cloudtrail block must be present even when disabled"

    ct = data["cloudtrail"]
    assert ct["enabled"] is False
    assert ct["events_ingested_24h"] == 0
    assert ct["last_poll_at"] is None

    conn.close()


# ---------------------------------------------------------------------------
# /health — events_ingested_24h reflects DB
# ---------------------------------------------------------------------------


def test_health_24h_counter_reflects_db(tmp_path):
    """events_ingested_24h counts only rows within the last 24 hours."""
    client, conn = _make_client(tmp_path, cloudtrail_enabled=True)

    now = datetime.now(timezone.utc)
    recent = (now - timedelta(hours=1)).isoformat()
    old = (now - timedelta(hours=25)).isoformat()

    # 2 recent + 1 old
    _insert_cloudtrail_row(conn, recent)
    _insert_cloudtrail_row(conn, recent)
    _insert_cloudtrail_row(conn, old)

    resp = client.get("/health")
    assert resp.status_code == 200

    ct = resp.json()["cloudtrail"]
    assert ct["events_ingested_24h"] == 2, (
        f"Expected 2 events in 24h window, got {ct['events_ingested_24h']}"
    )

    conn.close()


# ---------------------------------------------------------------------------
# /metrics — auth gate regression
# ---------------------------------------------------------------------------


def test_metrics_no_auth_returns_401(tmp_path):
    """/metrics with token set and no auth header returns 401."""
    client, conn = _make_client(tmp_path, token="secret")

    resp = client.get("/metrics")
    assert resp.status_code == 401, f"Expected 401, got {resp.status_code}"

    conn.close()


# ---------------------------------------------------------------------------
# /metrics — cloudtrail section present with correct keys
# ---------------------------------------------------------------------------


def test_metrics_with_auth_includes_cloudtrail_section(tmp_path):
    """/metrics cloudtrail block has all expected flat counter + cursor keys."""
    client, conn = _make_client(tmp_path, token="tok", cloudtrail_enabled=True)

    resp = client.get("/metrics", headers={"Authorization": "Bearer tok"})
    assert resp.status_code == 200

    data = resp.json()
    assert "cloudtrail" in data, "cloudtrail section missing from /metrics"

    ct = data["cloudtrail"]
    expected_keys = {
        "enabled",
        "events_ingested_total",
        "events_ingested_24h",
        "last_poll_at",
        "last_poll_status",
        "s3_list_errors_total",
        "parse_errors_total",
        "objects_processed_total",
        "cursor_bucket",
        "cursor_prefix",
        "cursor_last_object_key",
        "cursor_last_event_ts",
        "findings_count_total",
    }
    assert expected_keys.issubset(set(ct.keys())), (
        f"Missing cloudtrail keys in /metrics: {expected_keys - set(ct.keys())}"
    )

    conn.close()


# ---------------------------------------------------------------------------
# /metrics — cursor fields reflected from DB
# ---------------------------------------------------------------------------


def test_metrics_cursor_reflects_db(tmp_path):
    """When a cursor row exists, /metrics cursor_* fields reflect it."""
    from agent.models import update_cloudtrail_cursor

    client, conn = _make_client(tmp_path, token="tok", cloudtrail_enabled=True)

    # Insert a cursor row
    update_cloudtrail_cursor(
        conn,
        "test-bucket",
        "AWSLogs/",
        "AWSLogs/123/CloudTrail/us-east-1/2026/04/25/file.json.gz",
        "2026-04-25T05:29:42+00:00",
    )

    resp = client.get("/metrics", headers={"Authorization": "Bearer tok"})
    assert resp.status_code == 200

    ct = resp.json()["cloudtrail"]
    assert ct["cursor_bucket"] == "test-bucket", f"cursor_bucket wrong: {ct['cursor_bucket']}"
    assert ct["cursor_prefix"] == "AWSLogs/", f"cursor_prefix wrong: {ct['cursor_prefix']}"
    assert ct["cursor_last_object_key"] == (
        "AWSLogs/123/CloudTrail/us-east-1/2026/04/25/file.json.gz"
    ), f"cursor_last_object_key wrong: {ct['cursor_last_object_key']}"
    assert ct["cursor_last_event_ts"] == "2026-04-25T05:29:42+00:00", (
        f"cursor_last_event_ts wrong: {ct['cursor_last_event_ts']}"
    )

    conn.close()


# ---------------------------------------------------------------------------
# /metrics — findings_count_total reflects DB
# ---------------------------------------------------------------------------


def test_metrics_findings_count_reflects_db(tmp_path):
    """findings_count_total reflects cloud_audit_findings rows in DB."""
    from agent.models import get_cursor

    client, conn = _make_client(tmp_path, token="tok", cloudtrail_enabled=True)

    # Insert 3 findings directly using the real table schema
    with get_cursor(conn) as cur:
        for i in range(3):
            cur.execute(
                """INSERT INTO cloud_audit_findings
                   (alert_id, rule_name, rule_severity, title, description, detected_at)
                   VALUES (?, ?, ?, ?, ?, ?)""",
                (None, f"RULE-00{i+1}", "High", f"Finding {i+1}", "{}", "2026-04-25T00:00:00"),
            )

    resp = client.get("/metrics", headers={"Authorization": "Bearer tok"})
    assert resp.status_code == 200

    ct = resp.json()["cloudtrail"]
    assert ct["findings_count_total"] == 3, (
        f"Expected findings_count_total=3, got {ct['findings_count_total']}"
    )

    conn.close()


# ---------------------------------------------------------------------------
# /metrics — in-memory CLOUDTRAIL_STATS reflected
# ---------------------------------------------------------------------------


def test_metrics_after_simulated_poll(tmp_path):
    """CLOUDTRAIL_STATS set directly → /metrics reflects the values."""
    client, conn = _make_client(tmp_path, token="tok", cloudtrail_enabled=True)

    # Simulate a completed poll cycle
    ct_module.CLOUDTRAIL_STATS["events_ingested_total"] = 42
    ct_module.CLOUDTRAIL_STATS["last_poll_at"] = "2026-04-25T05:30:00+00:00"
    ct_module.CLOUDTRAIL_STATS["last_poll_status"] = "success"
    ct_module.CLOUDTRAIL_STATS["objects_processed_total"] = 18
    ct_module.CLOUDTRAIL_STATS["s3_list_errors_total"] = 1
    ct_module.CLOUDTRAIL_STATS["parse_errors_total"] = 2

    resp = client.get("/metrics", headers={"Authorization": "Bearer tok"})
    assert resp.status_code == 200

    ct = resp.json()["cloudtrail"]
    assert ct["events_ingested_total"] == 42
    assert ct["last_poll_at"] == "2026-04-25T05:30:00+00:00"
    assert ct["last_poll_status"] == "success"
    assert ct["objects_processed_total"] == 18
    assert ct["s3_list_errors_total"] == 1
    assert ct["parse_errors_total"] == 2

    conn.close()
