"""
/health and /metrics endpoint tests — CSO F5 split.

/health (unauthenticated liveness probe):
  1. Returns exactly {status, poller_healthy} — no extra keys.
  2. Always returns 200 regardless of token configuration.
  3. Rich recon fields (queue_depth, total_alerts, orchestrator, …)
     are NOT present in /health.

/metrics (authenticated operational stats):
  4. When SHAFERHUND_TOKEN is unset → 200 with full stats payload.
  5. When SHAFERHUND_TOKEN is set and no auth header → 401.
  6. When SHAFERHUND_TOKEN is set and correct bearer → 200 with full stats.
  7. Wrong bearer → 401.
  8. orchestrator block present with correct types, no nulls.
  9. auto_deploy block present with correct types.
  10. auto_deploy counts reflect seeded deploy_events data (24h window filter).
  11. orchestrator counters increment after a mock run_triage_loop call.
  12. Zero-state: fresh DB + no runs → all counts 0, avg=0.0 (no divide-by-zero).

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
        # Sigma-cli probe fields (REQ-P0-P25-003) — default False (not probed in tests)
        sigmac_available=False,
        sigmac_version=None,
    )


def _make_client(tmp_path, token: str = ""):
    """Return (TestClient, conn) with module singletons patched to in-memory DB."""
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir(exist_ok=True)

    conn = init_db(":memory:")
    settings = _make_settings(str(rules_dir), token=token)

    main_module._db = conn
    main_module._settings = settings
    main_module._triage_queue = None  # not needed for /health or /metrics
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
# /health tests — unauthenticated liveness probe
# ---------------------------------------------------------------------------


def test_health_returns_only_liveness_fields(tmp_path):
    """GET /health → exactly {status, poller_healthy, threat_intel}, nothing else.

    Phase 3 (REQ-P0-P3-005) added threat_intel.record_count to /health.
    The field is minimal (a count only) and does not expose operational detail,
    consistent with DEC-HEALTH-002's "public liveness probe" intent.
    """
    _reset_orchestrator_stats()
    client, conn = _make_client(tmp_path)

    resp = client.get("/health")
    assert resp.status_code == 200

    data = resp.json()
    assert set(data.keys()) == {"status", "poller_healthy", "threat_intel"}, (
        f"Expected exactly {{status, poller_healthy, threat_intel}}, got keys: {set(data.keys())}"
    )
    assert data["status"] == "ok"
    assert isinstance(data["poller_healthy"], bool)
    assert "record_count" in data["threat_intel"]
    assert isinstance(data["threat_intel"]["record_count"], int)

    conn.close()


def test_health_no_recon_fields(tmp_path):
    """GET /health must NOT contain operational/recon fields."""
    _reset_orchestrator_stats()
    client, conn = _make_client(tmp_path)

    resp = client.get("/health")
    assert resp.status_code == 200

    data = resp.json()
    recon_fields = {
        "queue_depth", "calls_this_hour", "hourly_budget",
        "last_poll_at", "last_triage_at",
        "total_alerts", "total_clusters", "pending_triage",
        "orchestrator", "auto_deploy",
    }
    present = recon_fields & set(data.keys())
    assert not present, f"Recon fields must not appear in /health: {present}"

    conn.close()


def test_health_unauthenticated_no_token_set(tmp_path):
    """GET /health returns 200 even when no token is configured."""
    _reset_orchestrator_stats()
    client, conn = _make_client(tmp_path, token="")

    resp = client.get("/health")
    assert resp.status_code == 200

    conn.close()


def test_health_unauthenticated_token_set_no_header(tmp_path):
    """GET /health returns 200 even when token is set and no auth header is sent."""
    _reset_orchestrator_stats()
    client, conn = _make_client(tmp_path, token="secret123")

    resp = client.get("/health")
    assert resp.status_code == 200, (
        f"/health must remain unauthenticated even with token set, got {resp.status_code}"
    )

    conn.close()


# ---------------------------------------------------------------------------
# /metrics tests — authenticated operational stats
# ---------------------------------------------------------------------------


def test_metrics_no_token_returns_200_with_full_payload(tmp_path):
    """GET /metrics with no token configured → 200 with full operational stats."""
    _reset_orchestrator_stats()
    client, conn = _make_client(tmp_path, token="")

    resp = client.get("/metrics")
    assert resp.status_code == 200

    data = resp.json()
    for key in (
        "queue_depth", "calls_this_hour", "hourly_budget",
        "last_poll_at", "last_triage_at",
        "total_alerts", "total_clusters", "pending_triage",
        "orchestrator", "auto_deploy",
    ):
        assert key in data, f"Expected field {key!r} missing from /metrics"

    conn.close()


def test_metrics_token_set_no_auth_returns_401(tmp_path):
    """GET /metrics with token set and no auth header → 401."""
    _reset_orchestrator_stats()
    client, conn = _make_client(tmp_path, token="secret123")

    resp = client.get("/metrics")
    assert resp.status_code == 401, (
        f"Expected 401 for unauthenticated /metrics, got {resp.status_code}"
    )

    conn.close()


def test_metrics_token_set_correct_bearer_returns_200(tmp_path):
    """GET /metrics with correct bearer token → 200 with full stats."""
    _reset_orchestrator_stats()
    client, conn = _make_client(tmp_path, token="secret123")

    resp = client.get("/metrics", headers={"Authorization": "Bearer secret123"})
    assert resp.status_code == 200

    data = resp.json()
    for key in (
        "queue_depth", "calls_this_hour", "hourly_budget",
        "last_poll_at", "last_triage_at",
        "total_alerts", "total_clusters", "pending_triage",
        "orchestrator", "auto_deploy",
    ):
        assert key in data, f"Expected field {key!r} missing from /metrics"

    conn.close()


def test_metrics_wrong_bearer_returns_401(tmp_path):
    """GET /metrics with wrong bearer token → 401."""
    _reset_orchestrator_stats()
    client, conn = _make_client(tmp_path, token="secret123")

    resp = client.get("/metrics", headers={"Authorization": "Bearer wrongtoken"})
    assert resp.status_code == 401

    conn.close()


# ---------------------------------------------------------------------------
# /metrics — orchestrator block correct types
# ---------------------------------------------------------------------------


def test_metrics_orchestrator_block_present(tmp_path):
    """/metrics → orchestrator block has 4 keys, correct types, no nulls."""
    _reset_orchestrator_stats()
    client, conn = _make_client(tmp_path)

    resp = client.get("/metrics")
    assert resp.status_code == 200

    data = resp.json()
    assert "orchestrator" in data, "'orchestrator' key missing from /metrics"

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
# /metrics — auto_deploy block correct types
# ---------------------------------------------------------------------------


def test_metrics_auto_deploy_block_present(tmp_path):
    """/metrics → auto_deploy block has 4 keys, correct types."""
    _reset_orchestrator_stats()
    client, conn = _make_client(tmp_path)

    resp = client.get("/metrics")
    assert resp.status_code == 200

    data = resp.json()
    assert "auto_deploy" in data, "'auto_deploy' key missing from /metrics"

    ad = data["auto_deploy"]
    assert isinstance(ad["enabled"], bool), "enabled must be bool"
    assert isinstance(ad["deployed_last_24h"], int), "deployed_last_24h must be int"
    assert isinstance(ad["skipped_last_24h"], int), "skipped_last_24h must be int"
    assert isinstance(ad["reverted_last_24h"], int), "reverted_last_24h must be int"

    conn.close()


# ---------------------------------------------------------------------------
# /metrics — counts reflect data, 24h window filter works
# ---------------------------------------------------------------------------


def test_metrics_auto_deploy_counts_reflect_data(tmp_path):
    """Seed deploy events and verify 24h window counts via /metrics.

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

    resp = client.get("/metrics")
    assert resp.status_code == 200

    ad = resp.json()["auto_deploy"]
    # 3 rows with action='auto-deploy' and deployed_at within 24h (old one excluded)
    assert ad["deployed_last_24h"] == 3, f"Expected 3 deployed in 24h, got {ad['deployed_last_24h']}"
    assert ad["skipped_last_24h"] == 1, f"Expected 1 skipped in 24h, got {ad['skipped_last_24h']}"
    assert ad["reverted_last_24h"] == 1, f"Expected 1 reverted in 24h, got {ad['reverted_last_24h']}"

    conn.close()


# ---------------------------------------------------------------------------
# /metrics — orchestrator counters increment after a mock loop run
# ---------------------------------------------------------------------------


def test_metrics_orchestrator_counters_increment(tmp_path):
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
# /metrics — zero state: fresh counters, no divide-by-zero
# ---------------------------------------------------------------------------


def test_metrics_zero_state_no_divide_by_zero(tmp_path):
    """Fresh DB + no runs → all counts 0, avg_tool_calls_per_run == 0.0."""
    _reset_orchestrator_stats()
    client, conn = _make_client(tmp_path)

    resp = client.get("/metrics")
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
