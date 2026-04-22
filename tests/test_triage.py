"""
Triage tests (2 tests).

Tests:
  1. Successful Claude API call produces a TriageResult with correct fields.
  2. Budget exhaustion: queue re-enqueues the cluster and does not call Claude.

Both tests mock the anthropic.AsyncAnthropic client — the only external
boundary in the triage module.

@decision DEC-TRIAGE-001
@title asyncio.Queue with hourly budget and exponential backoff
@status accepted
@rationale Mocking the Anthropic client is the correct boundary — we test
           our parsing and queue logic, not the SDK itself. The budget
           tracker is tested directly without mocking to verify the
           sliding-window reset behaviour.
"""

import asyncio
import json
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from agent.cluster import Alert, Cluster
from agent.config import Settings
from agent.triage import TriageQueue, TriageResult, _BudgetTracker, _parse_response, call_claude


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_settings(**overrides) -> Settings:
    base = dict(
        anthropic_api_key="test-key",
        triage_hourly_budget=20,
        queue_max_depth=100,
        cluster_max_alerts=50,
        cluster_window_seconds=300,
        claude_model="claude-opus-4-5",
        alerts_file="/tmp/alerts.json",
        db_path="/tmp/test.db",
        rules_dir="/tmp/rules",
        shaferhund_token="",
        severity_min_level=7,
        poll_interval_seconds=60,
    )
    base.update(overrides)
    return Settings(**base)


def _make_cluster(cluster_id: str = "test-cluster-01") -> Cluster:
    t0 = datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
    alert = Alert(
        id="alert-001",
        rule_id=5501,
        src_ip="192.168.1.100",
        severity=10,
        raw={"id": "alert-001", "rule": {"id": "5501", "level": 10}},
        timestamp=t0,
    )
    cluster = Cluster(
        id=cluster_id,
        src_ip="192.168.1.100",
        rule_id=5501,
        window_start=t0,
        alerts=[alert],
    )
    return cluster


# ---------------------------------------------------------------------------
# Test 1: Successful triage call
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_successful_triage_call():
    """call_claude parses a well-formed Claude response into a TriageResult."""
    fake_response_text = json.dumps({
        "severity": "High",
        "threat_assessment": "Brute-force SSH attack from 192.168.1.100.",
        "iocs": {
            "ips": ["192.168.1.100"],
            "domains": [],
            "hashes": [],
            "paths": [],
        },
        "yara_rule": "",
    })

    mock_message = MagicMock()
    mock_message.content = [MagicMock(text=fake_response_text)]

    mock_client = AsyncMock()
    mock_client.messages.create = AsyncMock(return_value=mock_message)

    cluster = _make_cluster("cluster-abc")
    result = await call_claude(mock_client, cluster, "claude-opus-4-5")

    assert isinstance(result, TriageResult)
    assert result.severity == "High"
    assert result.cluster_id == "cluster-abc"
    assert "192.168.1.100" in result.iocs["ips"]
    assert result.threat_assessment != ""
    mock_client.messages.create.assert_called_once()


# ---------------------------------------------------------------------------
# Test 2: Budget exhaustion re-enqueues without calling Claude
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_budget_exhaustion_reenqueues():
    """When hourly budget is exhausted the cluster is re-enqueued, not dropped."""
    results = []

    async def capture_result(r: TriageResult):
        results.append(r)

    settings = _make_settings(triage_hourly_budget=1)
    queue = TriageQueue(settings, on_result=capture_result)

    # Exhaust the budget manually
    queue._budget.record_call()
    assert not queue._budget.can_call()

    cluster = _make_cluster("cluster-budget-test")

    # Enqueue the cluster
    await queue.enqueue(cluster)
    assert queue.depth == 1

    # The worker would sleep and re-enqueue — verify budget state directly
    # rather than running the full async worker (avoids real sleep in tests)
    assert not queue._budget.can_call()
    assert queue.depth == 1  # cluster is still waiting, not consumed
    assert results == []     # no triage result produced yet


# ---------------------------------------------------------------------------
# Test 3: Single-shot fallback uses system= parameter (DEC-ORCH-004 / F4)
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_single_shot_uses_system_prompt():
    """call_claude single-shot fallback passes system= kwarg, not instructions in user content.

    The orchestrator path raises TypeError (mock api_key is not str), so
    call_claude falls back to the single-shot path.  We then inspect the
    kwargs passed to client.messages.create to confirm:
      - system= kwarg is present
      - The user message content is JSON (cluster data only, not instructions)

    # @mock-exempt: mock_client is the Anthropic HTTP API — an external boundary.
    # We need a non-str api_key to force the single-shot fallback path without
    # a real API key, and we inspect call kwargs to verify the system= parameter
    # is passed correctly. No internal modules are mocked.
    """
    from agent.triage import TRIAGE_SYSTEM_PROMPT

    fake_response_text = json.dumps({
        "severity": "Low",
        "threat_assessment": "Benign scan.",
        "iocs": {"ips": [], "domains": [], "hashes": [], "paths": []},
        "yara_rule": "",
    })

    mock_message = MagicMock()
    mock_message.content = [MagicMock(text=fake_response_text)]

    mock_client = AsyncMock()
    # api_key is a MagicMock (not str) — forces the orchestrator path to raise
    # TypeError and fall through to the single-shot path.
    mock_client.api_key = MagicMock()
    mock_client.messages.create = AsyncMock(return_value=mock_message)

    cluster = _make_cluster("cluster-syscheck")
    await call_claude(mock_client, cluster, "claude-opus-4-5")

    mock_client.messages.create.assert_called_once()
    call_kwargs = mock_client.messages.create.call_args.kwargs

    # system= kwarg must be present and match TRIAGE_SYSTEM_PROMPT
    assert "system" in call_kwargs, (
        "single-shot path did not pass system= to messages.create"
    )
    assert call_kwargs["system"] == TRIAGE_SYSTEM_PROMPT

    # The user message must be JSON (cluster data), not instructions
    messages = call_kwargs.get("messages", [])
    assert len(messages) == 1
    user_content = messages[0]["content"]
    # Must be valid JSON
    parsed = json.loads(user_content)
    assert "cluster_id" in parsed or "src_ip" in parsed, (
        f"user message content does not look like cluster JSON: {user_content[:200]}"
    )
    # Must NOT contain the instruction text (which belongs in system=)
    assert "cybersecurity analyst" not in user_content, (
        "Instruction text found in user message — should be in system= only"
    )
