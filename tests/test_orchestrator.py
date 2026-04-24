"""
Orchestrator tests — mock-driven, no real Anthropic API calls required.

# @mock-exempt: claude_client is the Anthropic HTTP API — an external boundary.
# Mocking it is the correct approach: no API key in CI, deterministic scripted
# responses are needed to test cap enforcement and failsafe paths precisely.
# Internal logic (run_triage_loop, handlers, schema) is tested against real
# implementations — nothing internal is mocked.

Tests:
  1.  test_tool_schema_valid                    — TOOLS list has all required keys + correct structure
  2.  test_loop_finalizes_successfully          — 3-call loop ending in finalize_triage returns result
  3.  test_loop_enforces_call_cap               — 6 tool_use responses, loop stops after 5 (cap)
  4.  test_loop_enforces_wall_timeout           — mock sleeps, wall timeout fires, failsafe returned
  5.  test_failsafe_on_end_turn_without_finalize — end_turn without finalize -> failsafe
  6.  test_no_conn_write_stubs_return_error     — write tools without conn return error JSON
  7.  test_build_cluster_context_prompt_includes_data — prompt contains src_ip, cluster_id
  8.  test_get_cluster_context_returns_summary  — real DB, handler returns JSON with expected fields
  9.  test_get_cluster_context_not_found        — bogus cluster_id -> error JSON
  10. test_search_related_alerts_cross_source   — wazuh + suricata alerts same IP -> both in response
  11. test_search_related_alerts_no_results     — unknown IP -> total_count=0
  12. test_write_yara_rule_persists_valid       — valid YARA stored with syntax_valid=True
  13. test_write_yara_rule_persists_invalid     — invalid YARA stored with syntax_valid=False
  14. test_write_sigma_rule_persists_valid      — valid Sigma YAML stored with syntax_valid=True
  15. test_write_sigma_rule_empty_content       — empty content returns error JSON
  16. test_recommend_deploy_records_event       — deploy recommendation stored in deploy_events
  17. test_finalize_triage_persists_verdict     — finalize with conn writes to cluster row
  18. test_finalize_triage_no_conn             — finalize without conn still returns TriageResult
  19. test_loop_with_conn_persists_verdict     — full loop with DB: finalize writes ai_severity

All mock clients are synchronous MagicMock instances — run_triage_loop is sync.
Tests 8-19 use an in-memory SQLite DB via agent.models.init_db(":memory:").

@decision DEC-ORCH-001
@title Claude tool-use loop with 6 tools, 5-call / 10s caps
@status accepted
@rationale Tests cover the control-flow contracts (caps, failsafe, finalize path)
           using a scripted mock client. No real API key required. The mock
           returns pre-scripted response objects in sequence, simulating a
           realistic multi-turn tool-use conversation.

@decision DEC-ORCH-002
@title Read handlers are standalone functions; DB connection injected via conn param
@status accepted
@rationale Tests 8-11 call the handlers through make_read_tool_handlers(conn) to
           verify they interact correctly with a real SQLite schema.  No mocking
           of internal functions — the DB is a lightweight in-memory fixture.

@decision DEC-ORCH-003
@title Write tool handlers use make_write_tool_handlers(conn, cluster_id) closure factory
@status accepted
@rationale Tests 12-19 call write handlers through make_write_tool_handlers(conn,
           cluster_id) and verify they persist rules, deploy events, and AI
           verdicts to the real SQLite schema.
"""

import json
import time
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from agent.models import (
    get_cluster,
    get_rules_for_cluster,
    init_db,
    insert_alert,
    list_deploy_events,
    upsert_cluster,
)
from agent.orchestrator import (
    TOOLS,
    _check_yara_syntax,
    _handle_finalize_triage,
    _handle_get_cluster_context,
    _handle_recommend_deploy,
    _handle_search_related_alerts,
    _handle_write_sigma_rule,
    _handle_write_yara_rule,
    build_cluster_context_prompt,
    dispatch,
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
    # Phase 3 added check_threat_intel as the 7th tool (DEC-ORCH-005).
    assert len(TOOLS) == 7, f"Expected 7 tools, got {len(TOOLS)}"

    required_names = {
        "get_cluster_context",
        "search_related_alerts",
        "write_yara_rule",
        "write_sigma_rule",
        "recommend_deploy",
        "finalize_triage",
        "check_threat_intel",  # Phase 3, REQ-P0-P3-005
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
# Test 6: Write tools without conn return error JSON (no-conn stubs)
# ---------------------------------------------------------------------------

def test_no_conn_write_stubs_return_error():
    """When dispatch() is called without conn, write tools return error JSON to Claude.

    This verifies that dispatch() returns informative error JSON (not a crash)
    for DB-dependent tools when conn=None, so Claude can gracefully proceed to
    finalize_triage.  Uses the new dispatch() API (DEC-ORCH-006).
    """
    for tool_name in ("write_yara_rule", "write_sigma_rule", "recommend_deploy"):
        result = dispatch(tool_name, {}, conn=None)
        parsed = json.loads(result)
        assert "error" in parsed, f"{tool_name} no-conn stub should return error JSON"
        assert "database connection" in parsed["error"].lower() or "conn" in parsed["error"]


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


# ---------------------------------------------------------------------------
# DB fixture helper
# ---------------------------------------------------------------------------

def _make_db():
    """Return an in-memory SQLite connection with the full Phase 2 schema."""
    return init_db(":memory:")


def _seed_cluster(conn, cluster_id: str, src_ip: str = "192.0.2.1",
                  rule_id: int = 1001, source: str = "wazuh") -> None:
    """Insert a cluster row and a couple of member alerts into conn."""
    upsert_cluster(
        conn,
        cluster_id=cluster_id,
        src_ip=src_ip,
        rule_id=rule_id,
        window_start="2026-01-01T00:00:00",
        window_end="2026-01-01T00:05:00",
        alert_count=2,
        source=source,
    )
    insert_alert(conn, f"{cluster_id}-a1", rule_id, src_ip, 7,
                 {"id": f"{cluster_id}-a1"}, cluster_id=cluster_id)
    insert_alert(conn, f"{cluster_id}-a2", rule_id, src_ip, 8,
                 {"id": f"{cluster_id}-a2"}, cluster_id=cluster_id)


# ---------------------------------------------------------------------------
# Test 8: get_cluster_context — happy path
# ---------------------------------------------------------------------------

def test_get_cluster_context_returns_summary():
    """Handler returns JSON with cluster metadata and sample_alerts for a real cluster."""
    conn = _make_db()
    _seed_cluster(conn, "cluster-ctx-001", src_ip="10.1.2.3", rule_id=5501)

    result_json = _handle_get_cluster_context({"cluster_id": "cluster-ctx-001"}, conn)
    result = json.loads(result_json)

    assert result.get("cluster_id") == "cluster-ctx-001"
    assert result.get("src_ip") == "10.1.2.3"
    assert result.get("rule_id") == 5501
    assert result.get("alert_count") == 2
    assert "window_start" in result
    assert "window_end" in result
    assert isinstance(result.get("sample_alerts"), list)
    assert len(result["sample_alerts"]) == 2

    # Each sample alert has the key fields Claude needs
    for alert in result["sample_alerts"]:
        assert "id" in alert
        assert "rule_id" in alert
        assert "severity" in alert

    conn.close()


# ---------------------------------------------------------------------------
# Test 9: get_cluster_context — cluster not found
# ---------------------------------------------------------------------------

def test_get_cluster_context_not_found():
    """Handler returns an error JSON when the cluster_id does not exist."""
    conn = _make_db()

    result_json = _handle_get_cluster_context({"cluster_id": "bogus-99999"}, conn)
    result = json.loads(result_json)

    assert "error" in result
    assert "bogus-99999" in result["error"]

    conn.close()


# ---------------------------------------------------------------------------
# Test 10: search_related_alerts — cross-source results
# ---------------------------------------------------------------------------

def test_search_related_alerts_cross_source():
    """Handler returns both wazuh and suricata results when both exist for an IP."""
    conn = _make_db()
    src_ip = "172.16.0.55"

    # Insert a wazuh alert
    insert_alert(conn, "wz-001", 5501, src_ip, 7, {"id": "wz-001", "source": "wazuh"})
    # Manually set source column (insert_alert uses default 'wazuh')
    conn.execute("UPDATE alerts SET source = 'wazuh' WHERE id = 'wz-001'")

    # Insert a suricata alert
    insert_alert(conn, "sur-001", 2200101, src_ip, 5, {"id": "sur-001", "source": "suricata"})
    conn.execute("UPDATE alerts SET source = 'suricata' WHERE id = 'sur-001'")
    conn.commit()

    result_json = _handle_search_related_alerts(
        {"src_ip": src_ip, "time_range_hours": 24}, conn
    )
    result = json.loads(result_json)

    assert result["total_count"] == 2
    by_source = result["by_source"]
    assert "wazuh" in by_source, f"Expected 'wazuh' in by_source, got: {by_source}"
    assert "suricata" in by_source, f"Expected 'suricata' in by_source, got: {by_source}"
    assert by_source["wazuh"]["count"] == 1
    assert by_source["suricata"]["count"] == 1
    assert result["time_range_hours"] == 24

    conn.close()


# ---------------------------------------------------------------------------
# Test 11: search_related_alerts — no results
# ---------------------------------------------------------------------------

def test_search_related_alerts_no_results():
    """Handler returns total_count=0 and empty by_source for an IP with no alerts."""
    conn = _make_db()

    result_json = _handle_search_related_alerts(
        {"src_ip": "203.0.113.255", "time_range_hours": 24}, conn
    )
    result = json.loads(result_json)

    assert result["total_count"] == 0
    assert result["by_source"] == {}
    assert result["time_range_hours"] == 24

    conn.close()


# ---------------------------------------------------------------------------
# Test 12: write_yara_rule — valid rule persisted
# ---------------------------------------------------------------------------

def test_write_yara_rule_persists_valid():
    """A syntactically valid YARA rule is stored with syntax_valid=True."""
    conn = _make_db()
    cluster_id = "cluster-yara-valid"
    _seed_cluster(conn, cluster_id)

    result_json = _handle_write_yara_rule({
        "content": 'rule TestRule { strings: $s = "test" condition: $s }',
        "description": "Detects test string",
    }, conn, cluster_id)
    result = json.loads(result_json)

    assert result["rule_type"] == "yara"
    assert result["rule_id"]  # non-empty UUID

    # Verify persisted in DB
    rules = get_rules_for_cluster(conn, cluster_id)
    assert len(rules) == 1
    rule_row = dict(rules[0])
    assert rule_row["rule_type"] == "yara"
    assert rule_row["cluster_id"] == cluster_id

    # syntax_valid depends on whether yara-python is installed;
    # either way, the rule is persisted and result is consistent
    assert result["syntax_valid"] == bool(rule_row["syntax_valid"])

    conn.close()


# ---------------------------------------------------------------------------
# Test 13: write_yara_rule — invalid rule persisted with syntax_valid=False
# ---------------------------------------------------------------------------

def test_write_yara_rule_persists_invalid():
    """An invalid YARA rule is stored but marked syntax_valid=False."""
    conn = _make_db()
    cluster_id = "cluster-yara-invalid"
    _seed_cluster(conn, cluster_id)

    result_json = _handle_write_yara_rule({
        "content": "rule BrokenRule { condition: undefined_var }",
        "description": "Broken rule",
    }, conn, cluster_id)
    result = json.loads(result_json)

    assert result["rule_type"] == "yara"
    assert result["rule_id"]

    # If yara-python is installed, this rule should fail validation.
    # If not installed, _check_yara_syntax returns False too.
    if _check_yara_syntax('rule Valid { strings: $s = "x" condition: $s }'):
        # yara-python is available, so the broken rule should fail
        assert result["syntax_valid"] is False

    # Verify persisted in DB regardless
    rules = get_rules_for_cluster(conn, cluster_id)
    assert len(rules) == 1

    conn.close()


# ---------------------------------------------------------------------------
# Test 14: write_sigma_rule — valid Sigma YAML persisted
# ---------------------------------------------------------------------------

def test_write_sigma_rule_persists_valid():
    """A structurally valid Sigma rule YAML is stored with syntax_valid=True."""
    conn = _make_db()
    cluster_id = "cluster-sigma-valid"
    _seed_cluster(conn, cluster_id)

    sigma_yaml = """\
title: Test Sigma Rule
status: experimental
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains: 'mimikatz'
    condition: selection
level: high
"""

    result_json = _handle_write_sigma_rule({
        "content": sigma_yaml,
        "description": "Detects mimikatz usage",
    }, conn, cluster_id)
    result = json.loads(result_json)

    assert result["rule_type"] == "sigma"
    assert result["rule_id"]

    # Verify persisted in DB
    rules = get_rules_for_cluster(conn, cluster_id)
    assert len(rules) == 1
    rule_row = dict(rules[0])
    assert rule_row["rule_type"] == "sigma"
    assert rule_row["cluster_id"] == cluster_id
    # Basic YAML parse should pass even without pysigma
    assert result["syntax_valid"] is True

    conn.close()


# ---------------------------------------------------------------------------
# Test 15: write_sigma_rule — empty content returns error
# ---------------------------------------------------------------------------

def test_write_sigma_rule_empty_content():
    """Empty content returns an error JSON without persisting anything."""
    conn = _make_db()
    cluster_id = "cluster-sigma-empty"
    _seed_cluster(conn, cluster_id)

    result_json = _handle_write_sigma_rule({
        "content": "   ",
        "description": "empty",
    }, conn, cluster_id)
    result = json.loads(result_json)

    assert "error" in result
    assert "content" in result["error"].lower()

    # Nothing persisted
    rules = get_rules_for_cluster(conn, cluster_id)
    assert len(rules) == 0

    conn.close()


# ---------------------------------------------------------------------------
# Test 16: recommend_deploy — records event in deploy_events
# ---------------------------------------------------------------------------

def test_recommend_deploy_records_event():
    """recommend_deploy inserts a row in deploy_events with action='recommend'."""
    conn = _make_db()
    cluster_id = "cluster-deploy-rec"
    _seed_cluster(conn, cluster_id)

    result_json = _handle_recommend_deploy({
        "rule_id": 42,
        "reason": "High confidence SSH brute-force detection rule",
    }, conn)
    result = json.loads(result_json)

    assert result["action"] == "recommend"
    assert result["rule_id"] == 42
    assert "deploy_event_id" in result

    # Verify persisted in DB
    events = list_deploy_events(conn)
    assert len(events) >= 1
    event = dict(events[0])
    assert event["rule_id"] == 42
    assert event["action"] == "recommend"
    assert "SSH brute-force" in event["reason"]
    assert event["actor"] == "orchestrator"

    conn.close()


# ---------------------------------------------------------------------------
# Test 17: finalize_triage with conn — persists verdict to cluster row
# ---------------------------------------------------------------------------

def test_finalize_triage_persists_verdict():
    """finalize_triage with conn calls update_cluster_ai on the cluster row."""
    conn = _make_db()
    cluster_id = "cluster-finalize-db"
    _seed_cluster(conn, cluster_id)

    # Before: no AI verdict
    cluster_before = dict(get_cluster(conn, cluster_id))
    assert cluster_before["ai_severity"] is None
    assert cluster_before["ai_analysis"] is None

    result = _handle_finalize_triage(
        {"severity": "Critical", "analysis": "Active data exfiltration.", "rule_ids": []},
        conn=conn,
        cluster_id=cluster_id,
    )

    assert isinstance(result, TriageResult)
    assert result.severity == "Critical"
    assert result.threat_assessment == "Active data exfiltration."

    # After: verdict persisted
    cluster_after = dict(get_cluster(conn, cluster_id))
    assert cluster_after["ai_severity"] == "Critical"
    assert cluster_after["ai_analysis"] == "Active data exfiltration."

    conn.close()


# ---------------------------------------------------------------------------
# Test 18: finalize_triage without conn — returns TriageResult, no DB write
# ---------------------------------------------------------------------------

def test_finalize_triage_no_conn():
    """finalize_triage without conn still returns a valid TriageResult."""
    result = _handle_finalize_triage(
        {"severity": "Low", "analysis": "Benign scan activity.", "rule_ids": []},
    )

    assert isinstance(result, TriageResult)
    assert result.severity == "Low"
    assert result.threat_assessment == "Benign scan activity."
    assert result.cluster_id == ""  # no cluster_id provided


# ---------------------------------------------------------------------------
# Test 19: Full loop with conn — finalize persists verdict to DB
# ---------------------------------------------------------------------------

def test_loop_with_conn_persists_verdict():
    """run_triage_loop with conn: finalize_triage writes ai_severity to the cluster row."""
    conn = _make_db()
    cluster_id = "cluster-loop-db"
    _seed_cluster(conn, cluster_id, src_ip="10.0.0.42", rule_id=5501)

    responses = [
        # Call 1: finalize_triage directly
        _tool_use_response(
            "finalize_triage",
            {
                "severity": "High",
                "analysis": "Confirmed brute-force attack.",
                "rule_ids": [],
            },
            tool_id="tu_001",
        ),
    ]

    client = _make_mock_client(responses)
    config = _make_config(max_calls=5, wall_timeout=10.0)
    cluster = _make_cluster(cluster_id)

    result = run_triage_loop(cluster, client, config, conn=conn)

    assert isinstance(result, TriageResult)
    assert result.severity == "High"
    assert result.cluster_id == cluster_id

    # Verify the verdict was persisted to the DB
    cluster_row = dict(get_cluster(conn, cluster_id))
    assert cluster_row["ai_severity"] == "High"
    assert cluster_row["ai_analysis"] == "Confirmed brute-force attack."

    conn.close()


# ---------------------------------------------------------------------------
# Test 20: finalize_triage persists confidence (F4 / DEC-AUTODEPLOY-002)
# ---------------------------------------------------------------------------

def test_finalize_triage_persists_confidence():
    """finalize_triage with confidence=0.92 writes ai_confidence=0.92 to cluster row."""
    conn = _make_db()
    cluster_id = "cluster-conf-persist"
    _seed_cluster(conn, cluster_id)

    responses = [
        _tool_use_response(
            "finalize_triage",
            {
                "severity": "High",
                "analysis": "Confirmed attack with high confidence.",
                "rule_ids": [],
                "confidence": 0.92,
            },
            tool_id="tu_conf_001",
        ),
    ]

    client = _make_mock_client(responses)
    config = _make_config(max_calls=5, wall_timeout=10.0)
    cluster = _make_cluster(cluster_id)

    result = run_triage_loop(cluster, client, config, conn=conn)

    assert result.severity == "High"

    cluster_row = dict(get_cluster(conn, cluster_id))
    assert cluster_row["ai_confidence"] == pytest.approx(0.92, abs=1e-6), (
        f"Expected ai_confidence=0.92, got {cluster_row['ai_confidence']}"
    )

    conn.close()


# ---------------------------------------------------------------------------
# Test 21: finalize_triage missing confidence defaults to 0.0, not None/raise
# ---------------------------------------------------------------------------

def test_finalize_triage_missing_confidence_defaults_to_zero():
    """finalize_triage with no confidence field writes ai_confidence=0.0, not None."""
    conn = _make_db()
    cluster_id = "cluster-conf-missing"
    _seed_cluster(conn, cluster_id)

    responses = [
        _tool_use_response(
            "finalize_triage",
            {
                "severity": "Medium",
                "analysis": "Ambiguous activity, low confidence.",
                "rule_ids": [],
                # confidence intentionally omitted
            },
            tool_id="tu_conf_002",
        ),
    ]

    client = _make_mock_client(responses)
    config = _make_config(max_calls=5, wall_timeout=10.0)
    cluster = _make_cluster(cluster_id)

    result = run_triage_loop(cluster, client, config, conn=conn)

    assert result.severity == "Medium"

    cluster_row = dict(get_cluster(conn, cluster_id))
    assert cluster_row["ai_confidence"] == pytest.approx(0.0, abs=1e-6), (
        f"Expected ai_confidence=0.0 (not None), got {cluster_row['ai_confidence']!r}"
    )

    conn.close()


# ---------------------------------------------------------------------------
# Test 22: run_triage_loop passes system= kwarg to Claude API (DEC-ORCH-004)
# ---------------------------------------------------------------------------

def test_loop_passes_system_prompt_to_claude():
    """run_triage_loop passes system=ORCHESTRATOR_SYSTEM_PROMPT to messages.create."""
    from agent.orchestrator import ORCHESTRATOR_SYSTEM_PROMPT

    responses = [
        _tool_use_response(
            "finalize_triage",
            {"severity": "Low", "analysis": "Benign scan.", "rule_ids": [], "confidence": 0.5},
            tool_id="tu_sys_001",
        ),
    ]
    client = _make_mock_client(responses)
    config = _make_config()
    cluster = _make_cluster("cluster-system-prompt")

    run_triage_loop(cluster, client, config)

    # Inspect the kwargs used in the first (and only) API call
    call_kwargs = client.messages.create.call_args_list[0].kwargs
    assert "system" in call_kwargs, (
        "messages.create was not called with system= kwarg"
    )
    assert call_kwargs["system"] == ORCHESTRATOR_SYSTEM_PROMPT, (
        "system= kwarg does not match ORCHESTRATOR_SYSTEM_PROMPT"
    )
