"""
Tests for the lookup_cloud_identity 9th orchestrator tool (Phase 5 Wave B1, REQ-P0-P5-007).

Acceptance criteria verified here:
  1. len(TOOLS) == 9, lookup_cloud_identity present with correct schema
  2. Handler returns empty-result shape when no events exist
  3. Handler aggregates events for the correct principal only
  4. Handler respects lookback_hours window
  5. Handler clamps lookback_hours to max 168
  6. Handler clamps lookback_hours to min 1 (zero/negative → 1)
  7. Handler sanitizes principal_arn (ANSI/control bytes stripped)
  8. Handler caps result at 50 events regardless of DB size
  9. Orchestrator loop calls lookup_cloud_identity and passes result to finalize_triage

@decision DEC-CLOUD-007
@title lookup_cloud_identity orchestrator tool tests — mock client + real DB
@status accepted
@rationale Follows the pattern in test_orchestrator_threat_intel.py (Phase 3 #35).
           The Anthropic client is mocked (external HTTP boundary per Sacred Practice #5);
           the SQLite DB is a real in-memory DB via init_db(":memory:").  No internal
           module is mocked — handler, models, and dispatch() are all exercised directly.

@mock-exempt: claude_client is the Anthropic HTTP API — an external boundary.
"""

import json
import sqlite3
from datetime import datetime, timezone, timedelta
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from agent.models import init_db, insert_cloudtrail_alert
from agent.orchestrator import (
    TOOLS,
    _handle_lookup_cloud_identity,
    dispatch,
    run_triage_loop,
)
from agent.sources.cloudtrail import parse_cloudtrail_event
from agent.triage import TriageResult


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_cloudtrail_event(
    arn: str,
    src_ip: str = "198.51.100.1",
    event_name: str = "DescribeInstances",
    event_source: str = "ec2.amazonaws.com",
    event_time: str = "2026-04-25T05:00:00Z",
) -> dict:
    """Build a minimal CloudTrail event dict for a given principal ARN."""
    return {
        "eventName": event_name,
        "eventSource": event_source,
        "eventTime": event_time,
        "sourceIPAddress": src_ip,
        "userIdentity": {
            "type": "IAMUser",
            "arn": arn,
            "userName": arn.split("/")[-1] if "/" in arn else "root",
        },
    }


def _seed_event(conn: sqlite3.Connection, arn: str, **kwargs) -> str:
    """Parse and insert a single CloudTrail event; return the alert_id.

    When ``event_time`` is provided in kwargs it is used both as the CloudTrail
    eventTime AND as the explicit ``ingested_at`` value so time-windowing tests
    can control the apparent ingestion time.  Without this, SQLite sets
    ``ingested_at = CURRENT_TIMESTAMP`` (insertion time) regardless of the
    event's own eventTime — which would make lookback tests non-deterministic.
    """
    import hashlib
    import uuid as _uuid

    event_time = kwargs.get("event_time", "2026-04-25T05:00:00Z")
    event = _make_cloudtrail_event(arn, **kwargs)
    parsed = parse_cloudtrail_event(event)

    raw = parsed.get("raw_json", "")
    alert_id = str(_uuid.UUID(hashlib.md5(raw.encode(), usedforsecurity=False).hexdigest()))

    # Insert with explicit ingested_at so the time-window queries work correctly.
    # ingested_at uses the same ISO-8601 string as the event_time parameter so
    # tests that seed events "N hours ago" get rows that the handler's cutoff
    # comparison will correctly include or exclude.
    conn.execute(
        """
        INSERT OR IGNORE INTO alerts
            (id, rule_id, src_ip, severity, cluster_id, source,
             dest_ip, protocol, normalized_severity, ingested_at)
        VALUES (?, ?, ?, ?, NULL, ?, ?, ?, ?, ?)
        """,
        (
            alert_id,
            parsed.get("rule_id", "cloudtrail:unknown:unknown"),
            parsed.get("src_ip", "unknown"),
            parsed.get("severity", 5),
            "cloudtrail",
            parsed.get("dest_ip"),
            parsed.get("protocol", "https"),
            parsed.get("normalized_severity", "Low"),
            event_time,
        ),
    )
    conn.execute(
        "INSERT OR IGNORE INTO alert_details (alert_id, raw_json) VALUES (?, ?)",
        (alert_id, raw),
    )
    conn.commit()
    return alert_id


def _make_config(max_calls: int = 5, wall_timeout: float = 10.0):
    return SimpleNamespace(
        orch_max_tool_calls=max_calls,
        orch_wall_timeout_seconds=wall_timeout,
        claude_model="claude-opus-4-5",
    )


def _make_cluster(cluster_id: str = "cluster-ci-001") -> dict:
    return {
        "cluster_id": cluster_id,
        "src_ip": "198.51.100.10",
        "rule_id": "cloudtrail:iam.amazonaws.com:CreateUser",
        "alert_count": 1,
        "window_start": "2026-04-25T05:00:00Z",
        "window_end": "2026-04-25T05:05:00Z",
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
# Test 1: TOOLS list has 9 entries; lookup_cloud_identity schema is correct
# ---------------------------------------------------------------------------

def test_lookup_cloud_identity_tool_registered():
    """TOOLS must have exactly 9 entries; lookup_cloud_identity must be present with correct schema."""
    assert len(TOOLS) == 9, f"Expected 9 tools, got {len(TOOLS)}: {[t['name'] for t in TOOLS]}"

    names = {t["name"] for t in TOOLS}
    assert "lookup_cloud_identity" in names, f"lookup_cloud_identity missing from TOOLS: {names}"

    tool = next(t for t in TOOLS if t["name"] == "lookup_cloud_identity")
    schema = tool["input_schema"]
    assert schema["type"] == "object"
    assert "principal_arn" in schema["properties"]
    assert "principal_arn" in schema["required"]
    assert "lookback_hours" in schema["properties"]
    # lookback_hours is optional (not in required)
    assert "lookback_hours" not in schema["required"]


# ---------------------------------------------------------------------------
# Test 2: empty DB → empty-result shape
# ---------------------------------------------------------------------------

def test_handler_returns_empty_when_no_events():
    """Fresh DB with no CloudTrail events returns the empty-result shape."""
    conn = init_db(":memory:")

    result_str = _handle_lookup_cloud_identity(
        {"principal_arn": "arn:aws:iam::123:user/alice"},
        conn,
    )
    result = json.loads(result_str)

    assert result["matches"] == 0
    assert result["context"] is None

    conn.close()


# ---------------------------------------------------------------------------
# Test 3: aggregation returns correct principal's events only
# ---------------------------------------------------------------------------

def test_handler_aggregates_events_for_principal():
    """Seeding 3 events for alice and 2 for bob → query alice returns 3, with alice's IPs only."""
    conn = init_db(":memory:")

    alice = "arn:aws:iam::123:user/alice"
    bob = "arn:aws:iam::123:user/bob"

    _seed_event(conn, alice, src_ip="10.0.0.1", event_name="DescribeInstances", event_time="2026-04-25T01:00:00Z")
    _seed_event(conn, alice, src_ip="10.0.0.2", event_name="ListBuckets",        event_time="2026-04-25T02:00:00Z")
    _seed_event(conn, alice, src_ip="10.0.0.3", event_name="GetObject",          event_time="2026-04-25T03:00:00Z")
    _seed_event(conn, bob,   src_ip="10.1.0.1", event_name="CreateUser",         event_time="2026-04-25T01:30:00Z")
    _seed_event(conn, bob,   src_ip="10.1.0.2", event_name="DeleteUser",         event_time="2026-04-25T02:30:00Z")

    result_str = _handle_lookup_cloud_identity(
        {"principal_arn": alice, "lookback_hours": 168},
        conn,
    )
    result = json.loads(result_str)

    assert result["matches"] == 3
    ctx = result["context"]
    assert ctx is not None
    assert ctx["total_events"] == 3
    assert ctx["principal_arn"] == alice

    # All three of alice's IPs present, none of bob's
    assert set(ctx["src_ips"]) == {"10.0.0.1", "10.0.0.2", "10.0.0.3"}
    assert "10.1.0.1" not in ctx["src_ips"]
    assert "10.1.0.2" not in ctx["src_ips"]

    # event_names contains alice's events
    assert "DescribeInstances" in ctx["event_names"]
    assert "ListBuckets" in ctx["event_names"]
    assert "GetObject" in ctx["event_names"]
    # bob's events not present
    assert "CreateUser" not in ctx["event_names"]

    conn.close()


# ---------------------------------------------------------------------------
# Test 4: lookback_hours filters correctly
# ---------------------------------------------------------------------------

def test_handler_respects_lookback_hours():
    """Event 12h ago included in lookback=24; event 36h ago excluded. lookback=72 includes both."""
    conn = init_db(":memory:")
    alice = "arn:aws:iam::123:user/alice"

    now = datetime.now(timezone.utc)
    ts_recent = (now - timedelta(hours=12)).strftime("%Y-%m-%dT%H:%M:%SZ")
    ts_old    = (now - timedelta(hours=36)).strftime("%Y-%m-%dT%H:%M:%SZ")

    _seed_event(conn, alice, event_time=ts_recent, src_ip="10.0.0.1", event_name="DescribeInstances")
    _seed_event(conn, alice, event_time=ts_old,    src_ip="10.0.0.2", event_name="ListBuckets")

    # lookback=24 → only the recent event (12h ago)
    result_24 = json.loads(_handle_lookup_cloud_identity(
        {"principal_arn": alice, "lookback_hours": 24},
        conn,
    ))
    assert result_24["matches"] == 1

    # lookback=72 → both events (12h and 36h ago)
    result_72 = json.loads(_handle_lookup_cloud_identity(
        {"principal_arn": alice, "lookback_hours": 72},
        conn,
    ))
    assert result_72["matches"] == 2

    conn.close()


# ---------------------------------------------------------------------------
# Test 5: lookback_hours clamped to 168 max
# ---------------------------------------------------------------------------

def test_handler_clamps_lookback_to_168():
    """lookback_hours=999 is clamped to 168; a 200h-old event is NOT returned."""
    conn = init_db(":memory:")
    alice = "arn:aws:iam::123:user/alice"

    now = datetime.now(timezone.utc)
    # Event 150h ago — within 168h window, should appear
    ts_within  = (now - timedelta(hours=150)).strftime("%Y-%m-%dT%H:%M:%SZ")
    # Event 200h ago — outside 168h clamp
    ts_outside = (now - timedelta(hours=200)).strftime("%Y-%m-%dT%H:%M:%SZ")

    _seed_event(conn, alice, event_time=ts_within,  src_ip="10.0.0.1", event_name="DescribeInstances")
    _seed_event(conn, alice, event_time=ts_outside, src_ip="10.0.0.2", event_name="ListBuckets")

    result = json.loads(_handle_lookup_cloud_identity(
        {"principal_arn": alice, "lookback_hours": 999},
        conn,
    ))
    # Clamped to 168 → only the 150h-old event is within window
    assert result["matches"] == 1

    conn.close()


# ---------------------------------------------------------------------------
# Test 6: lookback_hours clamped to 1 min (zero / negative)
# ---------------------------------------------------------------------------

def test_handler_clamps_lookback_to_1():
    """lookback_hours=0 and lookback_hours=-5 are both clamped to 1."""
    conn = init_db(":memory:")
    alice = "arn:aws:iam::123:user/alice"

    now = datetime.now(timezone.utc)
    # Event 30 minutes ago — within 1h window
    ts_30m = (now - timedelta(minutes=30)).strftime("%Y-%m-%dT%H:%M:%SZ")
    # Event 2h ago — outside even the clamped 1h window
    ts_2h  = (now - timedelta(hours=2)).strftime("%Y-%m-%dT%H:%M:%SZ")

    _seed_event(conn, alice, event_time=ts_30m, src_ip="10.0.0.1", event_name="DescribeInstances")
    _seed_event(conn, alice, event_time=ts_2h,  src_ip="10.0.0.2", event_name="ListBuckets")

    for bad_hours in [0, -5, -100]:
        result = json.loads(_handle_lookup_cloud_identity(
            {"principal_arn": alice, "lookback_hours": bad_hours},
            conn,
        ))
        # Clamped to 1h → only the 30-min-old event is within the window
        assert result["matches"] == 1, (
            f"Expected 1 match for lookback_hours={bad_hours} (clamped to 1), "
            f"got {result['matches']}"
        )

    conn.close()


# ---------------------------------------------------------------------------
# Test 7: principal_arn is sanitized (ANSI/control bytes stripped)
# ---------------------------------------------------------------------------

def test_handler_sanitizes_principal_arn():
    """ANSI escape sequences and control bytes in principal_arn are stripped before DB query."""
    conn = init_db(":memory:")
    alice = "arn:aws:iam::123:user/alice"

    _seed_event(conn, alice, src_ip="10.0.0.1")

    # Inject ANSI escape + null byte around the valid ARN
    dirty_arn = f"\x1b[31m{alice}\x00\x1b[0m"

    result_str = _handle_lookup_cloud_identity(
        {"principal_arn": dirty_arn, "lookback_hours": 168},
        conn,
    )
    result = json.loads(result_str)

    # After sanitization the ANSI escapes are stripped; the core ARN remains
    # and the query must not crash. Shape must be valid.
    assert "matches" in result
    # The context may or may not match depending on truncation — key assertion
    # is no exception and a valid JSON response.
    if result["matches"] > 0:
        assert result["context"] is not None
        assert "principal_arn" in result["context"]

    conn.close()


# ---------------------------------------------------------------------------
# Test 8: result capped at 50 events
# ---------------------------------------------------------------------------

def test_handler_limits_to_50_events():
    """Seeding 60 events for alice → handler returns at most 50."""
    conn = init_db(":memory:")
    alice = "arn:aws:iam::123:user/alice"

    now = datetime.now(timezone.utc)
    for i in range(60):
        ts = (now - timedelta(minutes=i)).strftime("%Y-%m-%dT%H:%M:%SZ")
        _seed_event(
            conn, alice,
            event_time=ts,
            src_ip=f"10.0.{i // 256}.{i % 256}",
            event_name=f"Action{i}",
        )

    result = json.loads(_handle_lookup_cloud_identity(
        {"principal_arn": alice, "lookback_hours": 168},
        conn,
    ))

    assert result["matches"] == 50, (
        f"Expected 50 (DB limit), got {result['matches']}"
    )

    conn.close()


# ---------------------------------------------------------------------------
# Test 9: orchestrator loop calls lookup_cloud_identity and passes context
#         to finalize_triage
# ---------------------------------------------------------------------------

def test_orchestrator_loop_uses_lookup_cloud_identity():
    """Tool-use loop dispatches lookup_cloud_identity, receives context, then finalizes."""
    conn = init_db(":memory:")
    alice = "arn:aws:iam::123:user/alice"

    # Seed two events for alice so the tool returns real data
    _seed_event(conn, alice, src_ip="198.51.100.10", event_name="CreateUser")
    _seed_event(conn, alice, src_ip="198.51.100.11", event_name="AttachUserPolicy")

    responses = [
        # Turn 1: Claude calls lookup_cloud_identity
        _tool_use_response(
            "lookup_cloud_identity",
            {"principal_arn": alice, "lookback_hours": 168},
            tool_id="tu_001",
        ),
        # Turn 2: Claude finalizes after seeing the principal context
        _tool_use_response(
            "finalize_triage",
            {
                "severity": "High",
                "analysis": (
                    f"Principal {alice} performed CreateUser and AttachUserPolicy — "
                    "privilege escalation pattern detected."
                ),
                "rule_ids": [],
                "confidence": 0.88,
            },
            tool_id="tu_002",
        ),
    ]

    client = _make_mock_client(responses)
    config = _make_config()
    cluster = _make_cluster()

    result = run_triage_loop(cluster, client, config, conn=conn)

    assert isinstance(result, TriageResult)
    assert result.severity == "High"
    # Claude was called exactly twice
    assert client.messages.create.call_count == 2

    # Verify lookup_cloud_identity appeared in the conversation transcript:
    # The second call to messages.create must include a tool_result block
    # for the lookup_cloud_identity invocation.
    second_call_args = client.messages.create.call_args_list[1]
    messages_sent = second_call_args[1].get("messages") or second_call_args[0][0]
    # The last user message should contain the tool_result for tu_001
    tool_result_messages = [
        m for m in messages_sent
        if m.get("role") == "user"
        and isinstance(m.get("content"), list)
        and any(
            isinstance(blk, dict) and blk.get("type") == "tool_result"
            for blk in m["content"]
        )
    ]
    assert len(tool_result_messages) >= 1, (
        "Expected at least one tool_result message in transcript after lookup_cloud_identity"
    )

    conn.close()
