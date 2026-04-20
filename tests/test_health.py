"""
/health endpoint tests — Phase 2, REQ-P1-P2-004.

Verifies that:
  1. Phase 1 fields are still present and correct (no regression).
  2. New ``orchestrator`` block exists with the four expected keys/types.
  3. New ``auto_deploy`` block exists with the four expected keys/types.
  4. auto_deploy counts reflect seeded deploy_events data (24h window filter).
  5. orchestrator counters increment correctly after a mock run_triage_loop call.
  6. Zero-state: fresh DB + no runs → all counts 0, avg=0.0 (no divide-by-zero).

# @mock-exempt: claude_client is the Anthropic HTTP API — an external boundary.
# run_triage_loop is tested against its real implementation; only the HTTP
# client is mocked.  app singletons (_db, _settings) are patched at module
# level — minimal setup boundary, same pattern as test_dashboard.py.

@decision DEC-HEALTH-001
@title Single-dict in-memory counters, no lock required
@status accepted
@rationale Tests confirm counter semantics: total_runs increments per call,
           tool_calls accumulates across invocations, avg is derived at read
           time. The mock client reproduces the tool-use protocol exactly so
           run_triage_loop exercises the real counter increment sites.
"""

import time
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest
from fastapi.testclient import TestClient

import agent.main as main_module
import agent.orchestrator as orch_module
from agent.models import init_db, record_deploy_event, upsert_cluster
from agent.orchestrator import run_triage_loop


# ---------------------------------------------------------------------------
# Shared test helpers
# ---------------------------------------------------------------------------


def _make_settings(rules_dir: str, token: str = "") -> SimpleNamespace:
    """Minimal settings namespace — avoids requiring ANTHROPIC_API_KEY in CI."""
    return SimpleNamespace(
        shaferhund_token=token,
        rules_dir=str(rules_dir),
        db_path=":memory:",
        alerts_file="/dev/null",
        suricata_eve_file="/dev/null",
        triage_hourly_budget=20,
        AUTO_DEPLOY_ENABLED=False,
    )


def _make_client(tmp_path, token: str = ""):
    """Return (TestClient, conn) with module singletons patched to in-memory DB."""
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir(exist_ok=True)

    conn = init_db(":memory:")
    settings = _make_settings(str(rules_dir), token=token)

    main_module._db = conn
    main_module._settings = settings
    main_module._triage_queue = None  # not needed for /health
    main_module._poller_healthy = False
    main_module._last_poll_at = None

    client = TestClient(main_module.app, raise_server_exceptions=True)
    return client, conn


def _reset_orchestrator_stats() -> None:
    """Reset the module-level _STATS dict to zero between tests."""
    orch_module._STATS["total_runs"] = 0
    orch_module._STATS["tool_calls"] = 0
    orch_module._STATS["timeouts"] = 0
    orch_module._STATS["failsafe_finalizations"] = 0


# ---------------------------------------------------------------------------
# Mock client helpers (mirrors test_orchestrator.py pattern)
# ---------------------------------------------------------------------------


def _tool_use_response(tool_name: str, tool_input: dict, tool_id: str = "tu_001") -> MagicMock:
    """Mock Claude response with stop_reason='tool_use'."""
    block = SimpleNamespace(
        type="tool_use",
        id=tool_id,
        name=tool_name,
        input=tool_input,
    )
    resp = MagicMock()
    resp.stop_reason = "tool_use"
    resp.content = [block]
    return resp


def _make_mock_client(responses: list) -> MagicMock:
    client = MagicMock()
    client.messages.create = MagicMock(side_effect=responses)
    return client


def _make_config(max_calls: int = 5, wall_timeout: float = 10.0) -> SimpleNamespace:
    return SimpleNamespace(
        orch_max_tool_calls=max_calls,
        orch_wall_timeout_seconds=wall_timeout,
        claude_model="claude-opus-4-5",
        AUTO_DEPLOY_ENABLED=False,
        AUTO_DEPLOY_CONF_THRESHOLD=0.85,
        AUTO_DEPLOY_DEDUP_WINDOW_SECONDS=3600,
        AUTO_DEPLOY_SEVERITIES=["Critical", "High"],
        rules_dir="/tmp/rules-test",
    )


# ---------------------------------------------------------------------------
# Case 1 — Phase 1 fields still present
# ---------------------------------------------------------------------------


def test_health_phase1_fields_present(tmp_path):
    """GET /health → Phase 1 contract fields must all be present."""
    _reset_orchestrator_stats()
    client, conn = _make_client(tmp_path)

    resp = client.get("/health")
    assert resp.status_code == 200

    data = resp.json()
    for key in ("status", "poller_healthy", "queue_depth", "last_triage_at"):
        assert key in data, f"Phase 1 field {key!r} missing from /health"

    assert data["status"] == "ok"

    conn.close()


# ---------------------------------------------------------------------------
# Case 2 — orchestrator block present with correct types
# ---------------------------------------------------------------------------


def test_health_orchestrator_block_present(tmp_path):
    """GET /health → orchestrator block has 4 keys, correct types, no nulls."""
    _reset_orchestrator_stats()
    client, conn = _make_client(tmp_path)

    resp = client.get("/health")
    assert resp.status_code == 200

    data = resp.json()
    assert "orchestrator" in data, "'orchestrator' key missing from /health"

    orch = data["orchestrator"]
    assert isinstance(orch["total_runs"], int), "total_runs must be int"
    assert isinstance(orch["avg_tool_calls_per_run"], float), "avg_tool_calls_per_run must be float"
    assert isinstance(orch["timeouts"], int), "timeouts must be int"
    assert isinstance(orch["failsafe_finalizations"], int), "failsafe_finalizations must be int"

    # No nulls
    for k, v in orch.items():
        assert v is not None, f"orchestrator.{k} must not be null"

    conn.close()


# ---------------------------------------------------------------------------
# Case 3 — auto_deploy block present with correct types
# ---------------------------------------------------------------------------


def test_health_auto_deploy_block_present(tmp_path):
    """GET /health → auto_deploy block has 4 keys, correct types."""
    _reset_orchestrator_stats()
    client, conn = _make_client(tmp_path)

    resp = client.get("/health")
    assert resp.status_code == 200

    data = resp.json()
    assert "auto_deploy" in data, "'auto_deploy' key missing from /health"

    ad = data["auto_deploy"]
    assert isinstance(ad["enabled"], bool), "enabled must be bool"
    assert isinstance(ad["deployed_last_24h"], int), "deployed_last_24h must be int"
    assert isinstance(ad["skipped_last_24h"], int), "skipped_last_24h must be int"
    assert isinstance(ad["reverted_last_24h"], int), "reverted_last_24h must be int"

    conn.close()


# ---------------------------------------------------------------------------
# Case 4 — counts reflect data, 24h window filter works
# ---------------------------------------------------------------------------


def test_health_auto_deploy_counts_reflect_data(tmp_path):
    """Seed deploy events and verify 24h window counts.

    Seeding:
      - 1 auto-deploy outside 24h window (should NOT appear in deployed_last_24h)
      - 2 auto-deploy inside 24h window (not reverted)
      - 1 skipped inside 24h window
      - 1 auto-deploy inside 24h window that was also reverted (reverted_at set)

    deployed_last_24h counts action='auto-deploy' rows with deployed_at in window.
    The reverted row has action='auto-deploy' so it is ALSO counted as deployed —
    deployed_last_24h is a raw deploy count, not a "currently active" count.
    reverted_last_24h is tracked separately via the reverted_at column.

    Expected: deployed=3, skipped=1, reverted=1.
    """
    from datetime import datetime, timezone, timedelta
    from agent.models import get_cursor

    _reset_orchestrator_stats()
    client, conn = _make_client(tmp_path)

    now = datetime.now(timezone.utc)
    old_ts = (now - timedelta(hours=25)).isoformat()   # outside 24h window
    recent_ts = (now - timedelta(hours=1)).isoformat()  # inside 24h window

    with get_cursor(conn) as cur:
        # Outside window — must NOT be counted
        cur.execute(
            "INSERT INTO deploy_events (rule_id, action, reason, actor, deployed_at) VALUES (?, ?, ?, ?, ?)",
            (0, "auto-deploy", "ok", "orchestrator", old_ts),
        )
        # Two plain recent deploys
        cur.execute(
            "INSERT INTO deploy_events (rule_id, action, reason, actor, deployed_at) VALUES (?, ?, ?, ?, ?)",
            (0, "auto-deploy", "ok", "orchestrator", recent_ts),
        )
        cur.execute(
            "INSERT INTO deploy_events (rule_id, action, reason, actor, deployed_at) VALUES (?, ?, ?, ?, ?)",
            (0, "auto-deploy", "ok", "orchestrator", recent_ts),
        )
        # 1 skipped (recent)
        cur.execute(
            "INSERT INTO deploy_events (rule_id, action, reason, actor, deployed_at) VALUES (?, ?, ?, ?, ?)",
            (0, "skipped", "auto-deploy disabled", "orchestrator", recent_ts),
        )
        # 1 auto-deploy that was subsequently reverted (both timestamps recent)
        cur.execute(
            "INSERT INTO deploy_events (rule_id, action, reason, actor, deployed_at, reverted_at) VALUES (?, ?, ?, ?, ?, ?)",
            (0, "auto-deploy", "ok", "orchestrator", recent_ts, recent_ts),
        )

    resp = client.get("/health")
    assert resp.status_code == 200

    ad = resp.json()["auto_deploy"]
    # 3 rows with action='auto-deploy' and deployed_at within 24h (old one excluded)
    assert ad["deployed_last_24h"] == 3, f"Expected 3 deployed in 24h, got {ad['deployed_last_24h']}"
    assert ad["skipped_last_24h"] == 1, f"Expected 1 skipped in 24h, got {ad['skipped_last_24h']}"
    assert ad["reverted_last_24h"] == 1, f"Expected 1 reverted in 24h, got {ad['reverted_last_24h']}"

    conn.close()


# ---------------------------------------------------------------------------
# Case 5 — orchestrator counters increment after a mock loop run
# ---------------------------------------------------------------------------


def test_health_orchestrator_counters_increment(tmp_path):
    """run_triage_loop with 2 tool calls + finalize → total_runs=1, avg reflects 2 calls."""
    _reset_orchestrator_stats()

    # Build a mock client: get_cluster_context, search_related_alerts, finalize_triage
    responses = [
        _tool_use_response(
            "get_cluster_context",
            {"cluster_id": "cluster-h5"},
            tool_id="tu_1",
        ),
        _tool_use_response(
            "search_related_alerts",
            {"src_ip": "10.0.0.1", "time_range_hours": 24},
            tool_id="tu_2",
        ),
        _tool_use_response(
            "finalize_triage",
            {"severity": "High", "analysis": "test analysis", "rule_ids": []},
            tool_id="tu_3",
        ),
    ]
    mock_client = _make_mock_client(responses)
    config = _make_config()

    cluster = {
        "cluster_id": "cluster-h5",
        "src_ip": "10.0.0.1",
        "rule_id": 1001,
        "alert_count": 2,
        "window_start": "2026-01-01T00:00:00",
        "window_end": "2026-01-01T00:05:00",
        "sample_alerts": [],
    }

    result = run_triage_loop(cluster, mock_client, config, conn=None)

    assert result.severity == "High"

    stats = orch_module.get_orchestrator_stats()
    assert stats["total_runs"] == 1, f"Expected total_runs=1, got {stats['total_runs']}"
    # tool_calls: get_cluster_context + search_related_alerts (finalize_triage exits before dispatch)
    assert stats["avg_tool_calls_per_run"] == 2.0, (
        f"Expected avg=2.0, got {stats['avg_tool_calls_per_run']}"
    )
    assert stats["timeouts"] == 0
    assert stats["failsafe_finalizations"] == 0


# ---------------------------------------------------------------------------
# Case 6 — zero state: fresh counters, no divide-by-zero
# ---------------------------------------------------------------------------


def test_health_zero_state_no_divide_by_zero(tmp_path):
    """Fresh DB + no runs → all counts 0, avg_tool_calls_per_run == 0.0."""
    _reset_orchestrator_stats()
    client, conn = _make_client(tmp_path)

    resp = client.get("/health")
    assert resp.status_code == 200

    data = resp.json()
    orch = data["orchestrator"]
    assert orch["total_runs"] == 0
    assert orch["avg_tool_calls_per_run"] == 0.0, (
        f"avg should be 0.0 on zero runs, got {orch['avg_tool_calls_per_run']}"
    )
    assert orch["timeouts"] == 0
    assert orch["failsafe_finalizations"] == 0

    ad = data["auto_deploy"]
    assert ad["deployed_last_24h"] == 0
    assert ad["skipped_last_24h"] == 0
    assert ad["reverted_last_24h"] == 0

    conn.close()
