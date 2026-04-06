"""
Orchestrator tests — mock-driven, no real Anthropic API calls required.

# @mock-exempt: claude_client is the Anthropic HTTP API — an external boundary.
# Mocking it is the correct approach: no API key in CI, deterministic scripted
# responses are needed to test cap enforcement and failsafe paths precisely.
# Internal logic (run_triage_loop, handlers, schema) is tested against real
# implementations — nothing internal is mocked.

Tests:
  1. test_tool_schema_valid         — TOOLS list has all required keys + correct structure
  2. test_loop_finalizes_successfully — 3-call loop ending in finalize_triage returns result
  3. test_loop_enforces_call_cap    — 6 tool_use responses, loop stops after 5 (cap)
  4. test_loop_enforces_wall_timeout — mock sleeps, wall timeout fires, failsafe returned
  5. test_failsafe_on_end_turn_without_finalize — end_turn without finalize → failsafe
  6. test_stub_handlers_raise_not_implemented — stub handlers raise NotImplementedError

All mock clients are synchronous MagicMock instances — run_triage_loop is sync.

@decision DEC-ORCH-001
@title Claude tool-use loop with 6 tools, 5-call / 10s caps
@status planned
@rationale Tests cover the control-flow contracts (caps, failsafe, finalize path)
           using a scripted mock client. No real API key required. The mock
           returns pre-scripted response objects in sequence, simulating a
           realistic multi-turn tool-use conversation.
"""

import time
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from agent.orchestrator import (
    TOOLS,
    _handle_get_cluster_context,
    _handle_recommend_deploy,
    _handle_search_related_alerts,
    _handle_write_sigma_rule,
    _handle_write_yara_rule,
    build_cluster_context_prompt,
    run_triage_loop,
)
from agent.triage import TriageResult


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_config(max_calls: int = 5, wall_timeout: float = 10.0):
    """Return a minimal config object with orchestrator caps."""
    return SimpleNamespace(
        orch_max_tool_calls=max_calls,
        orch_wall_timeout_seconds=wall_timeout,
        claude_model="claude-opus-4-5",
    )


def _make_cluster(cluster_id: str = "cluster-001") -> dict:
    return {
        "cluster_id": cluster_id,
        "src_ip": "10.0.0.42",
        "rule_id": 5501,
        "alert_count": 3,
        "window_start": "2026-01-01T12:00:00Z",
        "window_end": "2026-01-01T12:05:00Z",
        "sample_alerts": [],
    }


def _tool_use_response(tool_name: str, tool_input: dict, tool_id: str = "tu_001") -> MagicMock:
    """Build a mock Claude response with stop_reason='tool_use'."""
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


def _end_turn_response() -> MagicMock:
    """Build a mock Claude response with stop_reason='end_turn'."""
    resp = MagicMock()
    resp.stop_reason = "end_turn"
    resp.content = []
    return resp


def _make_mock_client(responses: list) -> MagicMock:
    """Build a mock Claude client whose messages.create() returns responses in order."""
    client = MagicMock()
    client.messages.create = MagicMock(side_effect=responses)
    return client


# ---------------------------------------------------------------------------
# Test 1: Tool schema structure
# ---------------------------------------------------------------------------

def test_tool_schema_valid():
    """Every entry in TOOLS has the required keys and a valid input_schema."""
    assert len(TOOLS) == 6, f"Expected 6 tools, got {len(TOOLS)}"

    required_names = {
        "get_cluster_context",
        "search_related_alerts",
        "write_yara_rule",
        "write_sigma_rule",
        "recommend_deploy",
        "finalize_triage",
    }
    found_names = {t["name"] for t in TOOLS}
    assert found_names == required_names, f"Tool name mismatch: {found_names}"

    for tool in TOOLS:
        assert "name" in tool, f"Tool missing 'name': {tool}"
        assert "description" in tool, f"Tool {tool['name']!r} missing 'description'"
        assert "input_schema" in tool, f"Tool {tool['name']!r} missing 'input_schema'"

        schema = tool["input_schema"]
        assert isinstance(schema, dict), f"Tool {tool['name']!r} input_schema is not a dict"
        assert schema.get("type") == "object", (
            f"Tool {tool['name']!r} input_schema.type must be 'object', got {schema.get('type')!r}"
        )
        assert "properties" in schema, f"Tool {tool['name']!r} input_schema missing 'properties'"
        assert "required" in schema, f"Tool {tool['name']!r} input_schema missing 'required'"

        # All required fields must be present in properties
        for req_field in schema["required"]:
            assert req_field in schema["properties"], (
                f"Tool {tool['name']!r}: required field {req_field!r} not in properties"
            )


# ---------------------------------------------------------------------------
# Test 2: Loop finalizes successfully (3-call happy path)
# ---------------------------------------------------------------------------

def test_loop_finalizes_successfully():
    """A 3-call loop ending in finalize_triage returns the expected TriageResult."""
    responses = [
        # Call 1: get_cluster_context
        _tool_use_response(
            "get_cluster_context",
            {"cluster_id": 1},
            tool_id="tu_001",
        ),
        # Call 2: write_yara_rule
        _tool_use_response(
            "write_yara_rule",
            {"content": "rule test { condition: true }", "description": "test rule"},
            tool_id="tu_002",
        ),
        # Call 3: finalize_triage
        _tool_use_response(
            "finalize_triage",
            {
                "severity": "High",
                "analysis": "Brute-force SSH attack detected from 10.0.0.42.",
                "rule_ids": [1],
            },
            tool_id="tu_003",
        ),
    ]

    client = _make_mock_client(responses)
    config = _make_config(max_calls=5, wall_timeout=10.0)
    cluster = _make_cluster("cluster-happy")

    result = run_triage_loop(cluster, client, config)

    assert isinstance(result, TriageResult)
    assert result.severity == "High"
    assert result.threat_assessment == "Brute-force SSH attack detected from 10.0.0.42."
    assert result.cluster_id == "cluster-happy"

    # Claude was called exactly 3 times
    assert client.messages.create.call_count == 3


# ---------------------------------------------------------------------------
# Test 3: Loop enforces the 5-call cap
# ---------------------------------------------------------------------------

def test_loop_enforces_call_cap():
    """With 6 tool_use responses and none being finalize_triage, loop stops at 5 calls."""
    # 6 non-finalizing tool_use responses (only 5 can be consumed due to cap)
    responses = [
        _tool_use_response("get_cluster_context", {"cluster_id": 1}, f"tu_{i:03d}")
        for i in range(6)
    ]

    client = _make_mock_client(responses)
    config = _make_config(max_calls=5, wall_timeout=30.0)
    cluster = _make_cluster("cluster-cap")

    result = run_triage_loop(cluster, client, config)

    # Failsafe returned
    assert isinstance(result, TriageResult)
    assert result.severity == "Unknown"
    assert "exited without finalizing" in result.threat_assessment

    # Cap was respected — exactly 5 calls, not 6
    assert client.messages.create.call_count == 5


# ---------------------------------------------------------------------------
# Test 4: Loop enforces wall-clock timeout
# ---------------------------------------------------------------------------

def test_loop_enforces_wall_timeout():
    """When the mock sleeps longer than the wall timeout, failsafe is returned."""

    def slow_response(*args, **kwargs):
        time.sleep(0.15)  # sleep longer than the 0.1s wall timeout
        return _tool_use_response("get_cluster_context", {"cluster_id": 1})

    client = MagicMock()
    client.messages.create = MagicMock(side_effect=slow_response)

    # Very short wall timeout: 0.1s
    config = _make_config(max_calls=5, wall_timeout=0.1)
    cluster = _make_cluster("cluster-timeout")

    result = run_triage_loop(cluster, client, config)

    assert isinstance(result, TriageResult)
    assert result.severity == "Unknown"
    assert "exited without finalizing" in result.threat_assessment


# ---------------------------------------------------------------------------
# Test 5: Failsafe on end_turn without finalize_triage
# ---------------------------------------------------------------------------

def test_failsafe_on_end_turn_without_finalize():
    """If Claude returns end_turn on the first call without finalize, failsafe is returned."""
    client = _make_mock_client([_end_turn_response()])
    config = _make_config(max_calls=5, wall_timeout=10.0)
    cluster = _make_cluster("cluster-end-turn")

    result = run_triage_loop(cluster, client, config)

    assert isinstance(result, TriageResult)
    assert result.severity == "Unknown"
    assert "exited without finalizing" in result.threat_assessment
    assert client.messages.create.call_count == 1


# ---------------------------------------------------------------------------
# Test 6: Stub handlers raise NotImplementedError
# ---------------------------------------------------------------------------

def test_stub_handlers_raise_not_implemented():
    """Each stub tool handler raises NotImplementedError when called directly."""
    stubs = [
        (_handle_get_cluster_context, {"cluster_id": 1}),
        (_handle_search_related_alerts, {"src_ip": "10.0.0.1", "time_range_hours": 24}),
        (_handle_write_yara_rule, {"content": "rule x {condition: true}", "description": "x"}),
        (_handle_write_sigma_rule, {"content": "title: x\n", "description": "x"}),
        (_handle_recommend_deploy, {"rule_id": 1, "reason": "high confidence"}),
    ]

    for handler, args in stubs:
        with pytest.raises(NotImplementedError):
            handler(args)


# ---------------------------------------------------------------------------
# Test 7: build_cluster_context_prompt includes cluster data
# ---------------------------------------------------------------------------

def test_build_cluster_context_prompt_includes_data():
    """build_cluster_context_prompt includes the cluster's src_ip and rule_id."""
    cluster = _make_cluster("cluster-prompt")
    prompt = build_cluster_context_prompt(cluster)

    assert "10.0.0.42" in prompt
    assert "cluster-prompt" in prompt
    assert "finalize_triage" in prompt  # instructions mention finalize_triage
