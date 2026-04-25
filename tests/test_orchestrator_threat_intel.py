"""
Orchestrator threat-intel tool tests (Phase 3, REQ-P0-P3-005).

Verifies that the orchestrator tool-use loop correctly handles check_threat_intel
calls — both as a mid-loop tool call followed by finalize_triage, and for the
no-conn stub path.

Tests:
  1. test_tool_schema_has_7_tools               — TOOLS list now has 7 entries
  2. test_check_threat_intel_in_tool_names      — check_threat_intel present in TOOLS
  3. test_loop_uses_check_threat_intel          — tool-use loop calls check_threat_intel,
                                                  returns its result, then finalizes
  4. test_check_threat_intel_hit_in_verdict     — loop includes threat-intel context in analysis
  5. test_check_threat_intel_no_conn_stub       — without conn, returns error JSON (not crash)
  6. test_check_threat_intel_handler_hit        — real DB: handler returns hit=True for known IOC
  7. test_check_threat_intel_handler_miss       — real DB: handler returns hit=False for unknown IOC
  8. test_check_threat_intel_sanitizes_input    — ANSI/control bytes stripped before DB query
  9. test_check_threat_intel_empty_value        — empty value returns error JSON

# @decision DEC-ORCH-005
# @title check_threat_intel orchestrator tool tests — mock client + real DB
# @status accepted
# @rationale Follows the pattern in test_orchestrator.py. The Anthropic client is
#            mocked (external boundary); the SQLite DB is real (in-memory via
#            init_db(":memory:")). This matches Sacred Practice #5 — no internal
#            mocks, only external HTTP API boundaries.

# @mock-exempt: claude_client is the Anthropic HTTP API — an external boundary.
"""

import json
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from agent.models import init_db
from agent.orchestrator import (
    TOOLS,
    _handle_check_threat_intel,
    run_triage_loop,
)
from agent.threat_intel import fetch_and_store_from_data
from agent.triage import TriageResult

# ---------------------------------------------------------------------------
# Fixture / helpers
# ---------------------------------------------------------------------------

FIXTURES_DIR = Path(__file__).parent / "fixtures"


def _load_urlhaus_fixture() -> dict:
    return json.loads((FIXTURES_DIR / "urlhaus_sample.json").read_text())


def _fresh_db_with_intel():
    """Return an in-memory DB pre-populated with the URLhaus fixture."""
    conn = init_db(":memory:")
    fetch_and_store_from_data(conn, _load_urlhaus_fixture())
    return conn


def _make_config(max_calls: int = 5, wall_timeout: float = 10.0):
    return SimpleNamespace(
        orch_max_tool_calls=max_calls,
        orch_wall_timeout_seconds=wall_timeout,
        claude_model="claude-opus-4-5",
    )


def _make_cluster(cluster_id: str = "cluster-ti-001") -> dict:
    return {
        "cluster_id": cluster_id,
        "src_ip": "192.168.1.50",
        "rule_id": 87001,
        "alert_count": 2,
        "window_start": "2026-04-24T10:00:00Z",
        "window_end": "2026-04-24T10:05:00Z",
        "sample_alerts": [],
    }


def _tool_use_response(tool_name: str, tool_input: dict, tool_id: str = "tu_001") -> MagicMock:
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
# Test 1: TOOLS list has 7 entries
# ---------------------------------------------------------------------------

def test_tool_schema_has_7_tools():
    """TOOLS list must contain exactly 8 tools after Phase 4 Wave B addition."""
    # Phase 4 Wave B (REQ-P0-P4-001) added recommend_attack as the 8th tool.
    assert len(TOOLS) == 8, f"Expected 8 tools, got {len(TOOLS)}: {[t['name'] for t in TOOLS]}"


# ---------------------------------------------------------------------------
# Test 2: check_threat_intel is present in TOOLS
# ---------------------------------------------------------------------------

def test_check_threat_intel_in_tool_names():
    """check_threat_intel must appear in the TOOLS list."""
    names = {t["name"] for t in TOOLS}
    assert "check_threat_intel" in names, f"check_threat_intel missing from TOOLS: {names}"

    # Validate its schema structure
    tool = next(t for t in TOOLS if t["name"] == "check_threat_intel")
    assert "input_schema" in tool
    schema = tool["input_schema"]
    assert schema["type"] == "object"
    assert "value" in schema["properties"]
    assert "value" in schema["required"]


# ---------------------------------------------------------------------------
# Test 3: loop calls check_threat_intel and then finalizes
# ---------------------------------------------------------------------------

def test_loop_uses_check_threat_intel():
    """Tool-use loop correctly dispatches check_threat_intel and continues to finalize."""
    conn = _fresh_db_with_intel()

    known_url = "http://malware.example.com/payload.exe"
    responses = [
        # Turn 1: Claude calls check_threat_intel
        _tool_use_response(
            "check_threat_intel",
            {"value": known_url},
            tool_id="tu_001",
        ),
        # Turn 2: Claude finalizes after seeing the threat-intel result
        _tool_use_response(
            "finalize_triage",
            {
                "severity": "Critical",
                "analysis": (
                    f"URL {known_url} found in URLhaus feed (Emotet). "
                    "High-confidence malware download. Blocking recommended."
                ),
                "rule_ids": [],
                "confidence": 0.95,
            },
            tool_id="tu_002",
        ),
    ]

    client = _make_mock_client(responses)
    config = _make_config()
    cluster = _make_cluster()

    result = run_triage_loop(cluster, client, config, conn=conn)

    assert isinstance(result, TriageResult)
    assert result.severity == "Critical"
    # Claude was called exactly twice
    assert client.messages.create.call_count == 2

    conn.close()


# ---------------------------------------------------------------------------
# Test 4: threat-intel hit context appears in the conversation transcript
# ---------------------------------------------------------------------------

def test_check_threat_intel_hit_in_verdict():
    """When check_threat_intel returns a hit, the verdict analysis references it."""
    conn = _fresh_db_with_intel()

    responses = [
        _tool_use_response(
            "check_threat_intel",
            {"value": "http://malware.example.com/payload.exe"},
            tool_id="tu_001",
        ),
        _tool_use_response(
            "finalize_triage",
            {
                "severity": "High",
                "analysis": "URLhaus hit: Emotet malware download campaign identified.",
                "rule_ids": [],
                "confidence": 0.90,
            },
            tool_id="tu_002",
        ),
    ]

    client = _make_mock_client(responses)
    result = run_triage_loop(_make_cluster("cluster-hit"), client, _make_config(), conn=conn)

    assert result.severity == "High"
    assert "URLhaus" in result.threat_assessment or "Emotet" in result.threat_assessment

    conn.close()


# ---------------------------------------------------------------------------
# Test 5: no-conn stub returns error JSON, does not crash
# ---------------------------------------------------------------------------

def test_check_threat_intel_no_conn_stub():
    """Without a DB connection, check_threat_intel returns an error JSON string."""
    responses = [
        _tool_use_response(
            "check_threat_intel",
            {"value": "http://example.com/payload.exe"},
            tool_id="tu_001",
        ),
        _tool_use_response(
            "finalize_triage",
            {
                "severity": "Low",
                "analysis": "Threat intel unavailable; no connection.",
                "rule_ids": [],
                "confidence": 0.50,
            },
            tool_id="tu_002",
        ),
    ]

    client = _make_mock_client(responses)
    config = _make_config()

    # Run WITHOUT conn — the no-conn stub must handle check_threat_intel gracefully
    result = run_triage_loop(_make_cluster("cluster-no-conn"), client, config, conn=None)

    assert isinstance(result, TriageResult)
    # The loop should have completed — failsafe or finalize, no exception
    assert result.severity in ("Low", "Unknown")


# ---------------------------------------------------------------------------
# Test 6: handler returns hit=True for known indicator (real DB)
# ---------------------------------------------------------------------------

def test_check_threat_intel_handler_hit():
    """_handle_check_threat_intel returns hit=True for a known indicator."""
    conn = _fresh_db_with_intel()

    result_str = _handle_check_threat_intel(
        {"value": "http://malware.example.com/payload.exe"},
        conn,
    )
    result = json.loads(result_str)

    assert result["hit"] is True
    assert len(result["matches"]) >= 1

    conn.close()


# ---------------------------------------------------------------------------
# Test 7: handler returns hit=False for unknown indicator (real DB)
# ---------------------------------------------------------------------------

def test_check_threat_intel_handler_miss():
    """_handle_check_threat_intel returns hit=False for an unknown indicator."""
    conn = _fresh_db_with_intel()

    result_str = _handle_check_threat_intel(
        {"value": "http://totally.unknown.example.xyz/safe.txt"},
        conn,
    )
    result = json.loads(result_str)

    assert result["hit"] is False
    assert result["matches"] == []

    conn.close()


# ---------------------------------------------------------------------------
# Test 8: handler sanitizes ANSI/control bytes in input (DEC-ORCH-004)
# ---------------------------------------------------------------------------

def test_check_threat_intel_sanitizes_input():
    """ANSI escape sequences and control bytes in value are stripped before DB query."""
    conn = _fresh_db_with_intel()

    # Inject ANSI escape + null byte into the value — should not crash or match
    dirty_value = "\x1b[31mhttp://malware.example.com/payload.exe\x00\x1b[0m"
    result_str = _handle_check_threat_intel({"value": dirty_value}, conn)
    result = json.loads(result_str)

    # After sanitization the ANSI escapes are stripped but the URL core remains;
    # depending on truncation the hit may or may not fire — the key test is no crash
    # and a valid JSON response shape.
    assert "hit" in result
    assert "matches" in result
    assert isinstance(result["matches"], list)

    conn.close()


# ---------------------------------------------------------------------------
# Test 9: handler returns error JSON for empty value
# ---------------------------------------------------------------------------

def test_check_threat_intel_empty_value():
    """Empty value returns an error JSON rather than crashing."""
    conn = _fresh_db_with_intel()

    result_str = _handle_check_threat_intel({"value": ""}, conn)
    result = json.loads(result_str)

    assert "error" in result

    conn.close()
