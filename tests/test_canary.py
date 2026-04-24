"""
Canary token tests (Phase 3, REQ-P0-P3-004).

Tests cover:
  1. test_spawn_http_canary_creates_db_row  — HTTP canary: DB row inserted, trap_url shape
  2. test_spawn_dns_canary_creates_db_row   — DNS canary: DB row inserted, trap_hostname shape
  3. test_spawn_invalid_type_raises         — ValueError on bad type param
  4. test_hit_records_alert_row             — GET /canary/hit/{token} → alert in DB with source='canary'
  5. test_hit_increments_trigger_count      — trigger_count increments, last_triggered_at set
  6. test_hit_invalid_token_no_db_mutation  — unknown token → innocuous 200, no DB changes
  7. test_spawn_auth_gate_401_no_token      — POST /canary/spawn requires auth when token set
  8. test_spawn_auth_gate_200_with_token    — POST /canary/spawn → 201 with correct bearer
  9. test_health_includes_canary_field      — GET /health has canary.trigger_count_24h
  10. test_count_canary_triggers_since       — count_canary_triggers_since returns correct int
  11. test_spawn_name_sanitized             — overly long name is truncated before storage
  12. test_canary_hit_sanitizes_user_agent  — attacker user-agent value stored safely (truncated)

# @mock-exempt: No external HTTP boundaries are mocked here. All tests use either
# the in-memory SQLite DB (via init_db(":memory:")) or FastAPI TestClient with
# module-level singletons patched — same pattern as test_health.py and test_dashboard.py.
"""

import sqlite3
import time
from types import SimpleNamespace
from typing import Optional

import pytest
from fastapi.testclient import TestClient

import agent.main as main_module
from agent.canary import (
    count_canary_triggers_since,
    get_canary_token_by_token,
    increment_canary_trigger,
    insert_canary_token,
    list_canary_tokens,
    record_hit,
    spawn_canary,
)
from agent.models import init_db


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _fresh_db() -> sqlite3.Connection:
    """In-memory SQLite DB with full Phase 3 schema (including canary_tokens)."""
    return init_db(":memory:")


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
    )


def _make_client(tmp_path, token: str = ""):
    """Return (TestClient, conn) with module singletons patched."""
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir(exist_ok=True)

    conn = _fresh_db()
    settings = _make_settings(tmp_path, token=token)

    main_module._db = conn
    main_module._settings = settings
    main_module._triage_queue = None
    main_module._clusterer = None
    main_module._poller_healthy = False
    main_module._last_poll_at = None

    client = TestClient(main_module.app, raise_server_exceptions=True)
    return client, conn


# ---------------------------------------------------------------------------
# Test 1: spawn_http_canary — DB row + trap_url shape
# ---------------------------------------------------------------------------

def test_spawn_http_canary_creates_db_row():
    """spawn_canary('http') inserts a canary_tokens row and returns trap_url."""
    conn = _fresh_db()

    result = spawn_canary(conn, token_type="http", name="test-http-canary")

    assert "token" in result
    assert "trap_url" in result
    assert result["type"] == "http"
    assert result["name"] == "test-http-canary"
    assert isinstance(result["id"], int)

    # trap_url must contain the token
    assert result["token"] in result["trap_url"]
    assert "/canary/hit/" in result["trap_url"]

    # DB row must exist
    row = get_canary_token_by_token(conn, result["token"])
    assert row is not None
    assert row["type"] == "http"
    assert row["trigger_count"] == 0
    assert row["last_triggered_at"] is None

    conn.close()


# ---------------------------------------------------------------------------
# Test 2: spawn_dns_canary — DB row + trap_hostname shape
# ---------------------------------------------------------------------------

def test_spawn_dns_canary_creates_db_row():
    """spawn_canary('dns') inserts a canary_tokens row and returns trap_hostname."""
    conn = _fresh_db()

    result = spawn_canary(
        conn,
        token_type="dns",
        name="test-dns-canary",
        base_hostname="canary.local",
    )

    assert "token" in result
    assert "trap_hostname" in result
    assert "trap_url" not in result
    assert result["type"] == "dns"
    assert result["trap_hostname"].startswith(result["token"])
    assert result["trap_hostname"].endswith(".canary.local")

    row = get_canary_token_by_token(conn, result["token"])
    assert row is not None
    assert row["type"] == "dns"

    conn.close()


# ---------------------------------------------------------------------------
# Test 3: invalid type raises ValueError
# ---------------------------------------------------------------------------

def test_spawn_invalid_type_raises():
    """spawn_canary raises ValueError for unsupported token_type."""
    conn = _fresh_db()

    with pytest.raises(ValueError, match="token_type must be"):
        spawn_canary(conn, token_type="smtp", name="bad-type")

    conn.close()


# ---------------------------------------------------------------------------
# Test 4: GET /canary/hit/{token} → alert row in DB with source='canary'
# ---------------------------------------------------------------------------

def test_hit_records_alert_row(tmp_path):
    """Hitting a canary trap URL writes a source='canary' row to the alerts table."""
    client, conn = _make_client(tmp_path)

    # Spawn an HTTP canary
    spawned = spawn_canary(conn, "http", "hit-test-canary")
    token = spawned["token"]

    resp = client.get(f"/canary/hit/{token}")
    assert resp.status_code == 200
    assert resp.json() == {"ok": True}

    # Alert row should exist with source='canary'
    rows = conn.execute(
        "SELECT * FROM alerts WHERE source = 'canary'"
    ).fetchall()
    assert len(rows) >= 1, "Expected at least one canary alert row"

    alert = dict(rows[0])
    assert alert["source"] == "canary"

    # raw_json should contain the canary-specific fields
    import json
    raw = json.loads(
        conn.execute(
            "SELECT raw_json FROM alert_details WHERE alert_id = ?",
            (alert["id"],),
        ).fetchone()["raw_json"]
    )
    assert raw["source"] == "canary"
    assert raw["token"] == token


# ---------------------------------------------------------------------------
# Test 5: trigger_count increments and last_triggered_at is set
# ---------------------------------------------------------------------------

def test_hit_increments_trigger_count(tmp_path):
    """After a canary hit, trigger_count == 1 and last_triggered_at is not None."""
    client, conn = _make_client(tmp_path)

    spawned = spawn_canary(conn, "http", "count-test")
    token = spawned["token"]

    # Verify initial state
    row_before = get_canary_token_by_token(conn, token)
    assert row_before["trigger_count"] == 0
    assert row_before["last_triggered_at"] is None

    client.get(f"/canary/hit/{token}")

    row_after = get_canary_token_by_token(conn, token)
    assert row_after["trigger_count"] == 1
    assert row_after["last_triggered_at"] is not None


# ---------------------------------------------------------------------------
# Test 6: unknown token → innocuous 200, no DB mutations
# ---------------------------------------------------------------------------

def test_hit_invalid_token_no_db_mutation(tmp_path):
    """Unknown token returns innocuous 200 and leaves the DB unchanged."""
    client, conn = _make_client(tmp_path)

    alert_count_before = conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]

    resp = client.get("/canary/hit/notavalidtoken12345")

    assert resp.status_code == 200
    assert resp.json() == {"ok": True}

    alert_count_after = conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
    assert alert_count_after == alert_count_before, (
        "Unknown token hit must not insert alert rows"
    )


# ---------------------------------------------------------------------------
# Test 7: POST /canary/spawn requires auth when token is set (401 without header)
# ---------------------------------------------------------------------------

def test_spawn_auth_gate_401_no_token(tmp_path):
    """POST /canary/spawn → 401 when SHAFERHUND_TOKEN is set and no bearer provided."""
    client, conn = _make_client(tmp_path, token="secret999")

    resp = client.post("/canary/spawn", json={"type": "http", "name": "auth-test"})
    assert resp.status_code == 401, (
        f"Expected 401 for unauthenticated /canary/spawn, got {resp.status_code}"
    )

    conn.close()


# ---------------------------------------------------------------------------
# Test 8: POST /canary/spawn → 201 with correct bearer
# ---------------------------------------------------------------------------

def test_spawn_auth_gate_200_with_token(tmp_path):
    """POST /canary/spawn → 201 with correct bearer token when auth is configured."""
    client, conn = _make_client(tmp_path, token="secret999")

    resp = client.post(
        "/canary/spawn",
        json={"type": "http", "name": "auth-ok-test"},
        headers={"Authorization": "Bearer secret999"},
    )
    assert resp.status_code == 201, (
        f"Expected 201 from /canary/spawn with valid token, got {resp.status_code}"
    )

    data = resp.json()
    assert "token" in data
    assert "trap_url" in data
    assert data["type"] == "http"

    conn.close()


# ---------------------------------------------------------------------------
# Test 9: GET /health includes canary.trigger_count_24h
# ---------------------------------------------------------------------------

def test_health_includes_canary_field(tmp_path):
    """GET /health response includes canary.trigger_count_24h (int)."""
    client, conn = _make_client(tmp_path)

    resp = client.get("/health")
    assert resp.status_code == 200

    data = resp.json()
    assert "canary" in data, f"'canary' key missing from /health: {data.keys()}"
    assert "trigger_count_24h" in data["canary"], (
        f"'trigger_count_24h' missing from canary block: {data['canary']}"
    )
    assert isinstance(data["canary"]["trigger_count_24h"], int)

    # threat_intel must still be present (no regression)
    assert "threat_intel" in data, "'threat_intel' key removed from /health — regression"
    assert "record_count" in data["threat_intel"]

    conn.close()


# ---------------------------------------------------------------------------
# Test 10: count_canary_triggers_since returns correct count
# ---------------------------------------------------------------------------

def test_count_canary_triggers_since():
    """count_canary_triggers_since sums trigger_count for recently-triggered tokens."""
    conn = _fresh_db()

    # Spawn two tokens and hit each once
    s1 = spawn_canary(conn, "http", "canary-a")
    s2 = spawn_canary(conn, "http", "canary-b")

    increment_canary_trigger(conn, s1["token"])
    increment_canary_trigger(conn, s2["token"])

    # Both were triggered now — should appear in the 24h window
    count = count_canary_triggers_since(conn, time.time() - 86400)
    assert count == 2, f"Expected 2 triggers in 24h window, got {count}"

    # Future anchor — nothing triggered after this moment yet
    count_future = count_canary_triggers_since(conn, time.time() + 3600)
    assert count_future == 0, f"Expected 0 triggers in future window, got {count_future}"

    conn.close()


# ---------------------------------------------------------------------------
# Test 11: name is sanitized (truncated to _MAX_FIELD_LEN)
# ---------------------------------------------------------------------------

def test_spawn_name_sanitized():
    """Very long name is truncated before being stored in canary_tokens."""
    conn = _fresh_db()

    long_name = "x" * 2000
    result = spawn_canary(conn, "http", long_name)

    # The stored name must be at most 1024 chars
    row = get_canary_token_by_token(conn, result["token"])
    assert len(row["name"]) <= 1024, (
        f"name not truncated: stored {len(row['name'])} chars"
    )

    conn.close()


# ---------------------------------------------------------------------------
# Test 12: attacker-controlled user-agent is sanitized (truncated)
# ---------------------------------------------------------------------------

def test_canary_hit_sanitizes_user_agent():
    """record_hit() truncates oversized user-agent before writing to the alert row."""
    conn = _fresh_db()

    spawned = spawn_canary(conn, "http", "ua-sanitize-test")
    token = spawned["token"]

    evil_ua = "A" * 5000  # massively oversized
    request_meta = {
        "src_ip": "10.0.0.1",
        "user_agent": evil_ua,
        "path": "/canary/hit/" + token,
    }

    hit = record_hit(conn, token, request_meta, enqueue_fn=None)
    assert hit is True

    # Retrieve raw alert and check user_agent length
    import json
    raw_row = conn.execute(
        "SELECT raw_json FROM alert_details WHERE alert_id LIKE 'canary:%'"
    ).fetchone()
    assert raw_row is not None
    raw = json.loads(raw_row["raw_json"])
    assert len(raw.get("user_agent", "")) <= 1024, (
        "user_agent not truncated in stored alert"
    )

    conn.close()
