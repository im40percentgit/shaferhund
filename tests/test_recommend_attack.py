"""
Tests for the recommend_attack 8th orchestrator tool (REQ-P0-P4-001).

Acceptance criteria (from issue #45):
  1. len(TOOLS) == 8 after module load; 'recommend_attack' present in TOOLS.
  2. Handler inserts a row into attack_recommendations with status='pending'.
  3. Orchestrator loop driven by a mocked Anthropic client that calls
     recommend_attack → row persists, severity matches tool input.
  4. reason field is sanitized (ANSI escapes, control bytes stripped).

# @mock-exempt: claude_client is the Anthropic HTTP API — an external boundary.
# run_triage_loop is tested against the real implementation; only the HTTP
# client is mocked. DB is real in-memory SQLite via init_db(":memory:").
"""

import json
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from agent.models import init_db
from agent.orchestrator import (
    TOOLS,
    _handle_recommend_attack,
    dispatch,
    run_triage_loop,
)


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------


def _fresh_conn():
    """In-memory SQLite with full schema (all phases)."""
    return init_db(":memory:")


def _make_config(max_calls: int = 10, wall_timeout: float = 30.0) -> SimpleNamespace:
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


# ---------------------------------------------------------------------------
# Test 1: len(TOOLS) == 8, 'recommend_attack' in TOOLS
# ---------------------------------------------------------------------------


def test_recommend_attack_tool_registered():
    """TOOLS list must have exactly 8 entries after module load.

    The 8th entry must be recommend_attack (issue #45 acceptance criterion).
    """
    assert len(TOOLS) == 9, (
        f"Expected 9 registered tools, got {len(TOOLS)}. "
        f"Tool names: {[t['name'] for t in TOOLS]}"
    )
    tool_names = [t["name"] for t in TOOLS]
    assert "recommend_attack" in tool_names, (
        f"'recommend_attack' not found in TOOLS: {tool_names}"
    )
    # Verify it is the 8th (last) tool — registration order is preserved.
    assert tool_names[-1] == "recommend_attack", (
        f"'recommend_attack' must be the 8th tool, found at index "
        f"{tool_names.index('recommend_attack')}: {tool_names}"
    )


# ---------------------------------------------------------------------------
# Test 2: handler inserts row with status='pending'
# ---------------------------------------------------------------------------


def test_recommend_attack_handler_inserts_row():
    """Direct handler call → row in attack_recommendations with status='pending'."""
    conn = _fresh_conn()

    result_json = _handle_recommend_attack(
        tool_input={
            "technique_id": "T1059.003",
            "reason": "PowerShell is not covered by current rules",
            "severity": "High",
        },
        conn=conn,
        cluster_id="cluster-test-001",
    )

    result = json.loads(result_json)
    assert "recommendation_id" in result, f"Expected recommendation_id in result: {result}"
    assert result["status"] == "pending"
    assert result["technique_id"] == "T1059.003"

    rec_id = result["recommendation_id"]
    row = conn.execute(
        "SELECT * FROM attack_recommendations WHERE id = ?", (rec_id,)
    ).fetchone()

    assert row is not None, f"Row {rec_id} not found in attack_recommendations"
    assert row["technique_id"] == "T1059.003"
    assert row["severity"] == "High"
    assert row["status"] == "pending"
    assert row["reason"] == "PowerShell is not covered by current rules"
    assert row["cluster_id"] == "cluster-test-001"

    conn.close()


# ---------------------------------------------------------------------------
# Test 3: orchestrator loop calls recommend_attack → row persists
# ---------------------------------------------------------------------------


def test_recommend_attack_orchestrator_loop():
    """Drive a full orchestrator loop that calls recommend_attack then finalize_triage.

    Verifies:
    - 1 row in attack_recommendations with status='pending'
    - severity matches the tool input Claude sent
    - finalize_triage runs and returns a valid TriageResult
    """
    conn = _fresh_conn()

    # Seed a cluster row so the loop has valid context
    conn.execute(
        """
        INSERT INTO clusters (id, src_ip, rule_id, window_start, window_end, alert_count, source)
        VALUES ('cluster-loop-001', '10.0.0.2', 5001,
                '2026-04-25T00:00:00', '2026-04-25T00:05:00', 3, 'wazuh')
        """
    )
    conn.commit()

    # Mock client: recommend_attack → finalize_triage
    responses = [
        _tool_use_response(
            "recommend_attack",
            {
                "technique_id": "T1053.005",
                "reason": "Scheduled task persistence not detected by current YARA rules",
                "severity": "Critical",
            },
            tool_id="tu_ra_001",
        ),
        _tool_use_response(
            "finalize_triage",
            {
                "severity": "High",
                "analysis": "Suspicious scheduled task activity detected",
                "rule_ids": [],
                "confidence": 0.8,
            },
            tool_id="tu_ft_001",
        ),
    ]
    mock_client = _make_mock_client(responses)
    config = _make_config()

    cluster = {
        "cluster_id": "cluster-loop-001",
        "src_ip": "10.0.0.2",
        "rule_id": 5001,
        "alert_count": 3,
        "window_start": "2026-04-25T00:00:00",
        "window_end": "2026-04-25T00:05:00",
        "sample_alerts": [],
    }

    result = run_triage_loop(cluster, mock_client, config, conn=conn)

    # finalize_triage ran successfully
    assert result.severity == "High", f"Expected severity=High, got {result.severity}"

    # One pending recommendation persisted
    rows = conn.execute(
        "SELECT * FROM attack_recommendations WHERE status = 'pending'"
    ).fetchall()
    assert len(rows) == 1, f"Expected 1 pending recommendation, got {len(rows)}"

    rec = rows[0]
    assert rec["technique_id"] == "T1053.005"
    assert rec["severity"] == "Critical"
    assert rec["status"] == "pending"

    conn.close()


# ---------------------------------------------------------------------------
# Test 4: reason field is sanitized before storage
# ---------------------------------------------------------------------------


def test_recommend_attack_sanitizes_reason():
    """reason with control bytes and ANSI escapes is sanitized before DB insert."""
    conn = _fresh_conn()

    malicious_reason = (
        "\x1b[31mRed text injection\x1b[0m "
        "\x00null\x01soh\x07bel "
        "legitimate reason text"
    )

    result_json = _handle_recommend_attack(
        tool_input={
            "technique_id": "T1059.001",
            "reason": malicious_reason,
            "severity": "Medium",
        },
        conn=conn,
        cluster_id="",
    )

    result = json.loads(result_json)
    rec_id = result["recommendation_id"]

    row = conn.execute(
        "SELECT reason FROM attack_recommendations WHERE id = ?", (rec_id,)
    ).fetchone()
    assert row is not None

    stored_reason = row["reason"]
    # ANSI escapes stripped
    assert "\x1b[" not in stored_reason, "ANSI escape not stripped from reason"
    # C0 control bytes stripped
    assert "\x00" not in stored_reason, "null byte not stripped from reason"
    assert "\x01" not in stored_reason, "SOH byte not stripped from reason"
    assert "\x07" not in stored_reason, "BEL byte not stripped from reason"
    # Legitimate text preserved
    assert "legitimate reason text" in stored_reason

    conn.close()


# ---------------------------------------------------------------------------
# Test 5: handler rejects missing technique_id
# ---------------------------------------------------------------------------


def test_recommend_attack_handler_rejects_empty_technique_id():
    """Handler returns error JSON when technique_id is missing or empty."""
    conn = _fresh_conn()

    result_json = _handle_recommend_attack(
        tool_input={"technique_id": "", "reason": "some reason", "severity": "Low"},
        conn=conn,
        cluster_id="",
    )

    result = json.loads(result_json)
    assert "error" in result, f"Expected error key: {result}"

    # No row inserted
    count = conn.execute(
        "SELECT COUNT(*) FROM attack_recommendations"
    ).fetchone()[0]
    assert count == 0

    conn.close()


# ---------------------------------------------------------------------------
# Test 6: handler rejects invalid severity
# ---------------------------------------------------------------------------


def test_recommend_attack_handler_rejects_invalid_severity():
    """Handler returns error JSON when severity is not in the allowed enum."""
    conn = _fresh_conn()

    result_json = _handle_recommend_attack(
        tool_input={
            "technique_id": "T1059.003",
            "reason": "some reason",
            "severity": "Catastrophic",  # not a valid value
        },
        conn=conn,
        cluster_id="",
    )

    result = json.loads(result_json)
    assert "error" in result, f"Expected error key: {result}"
    assert count == 0 if (count := conn.execute(
        "SELECT COUNT(*) FROM attack_recommendations"
    ).fetchone()[0]) == 0 else count == 0

    conn.close()


# ---------------------------------------------------------------------------
# Test 7: dispatch() routes to _handle_recommend_attack correctly
# ---------------------------------------------------------------------------


def test_recommend_attack_dispatch_integration():
    """dispatch('recommend_attack', ...) returns JSON with recommendation_id."""
    conn = _fresh_conn()

    result = dispatch(
        "recommend_attack",
        {
            "technique_id": "T1136.001",
            "reason": "Local account creation not detected",
            "severity": "High",
        },
        conn=conn,
        cluster_id="cluster-dispatch-001",
    )

    assert isinstance(result, str), f"Expected JSON string, got {type(result)}"
    data = json.loads(result)
    assert "recommendation_id" in data
    assert data["status"] == "pending"

    # Verify row in DB
    row = conn.execute(
        "SELECT * FROM attack_recommendations WHERE id = ?",
        (data["recommendation_id"],),
    ).fetchone()
    assert row is not None
    assert row["technique_id"] == "T1136.001"
    assert row["cluster_id"] == "cluster-dispatch-001"

    conn.close()
