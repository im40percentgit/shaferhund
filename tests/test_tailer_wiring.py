"""
Tests for the dual-tailer wiring introduced in issue #7.

Covers:
  1. Settings has suricata_eve_file and suricata_poll_seconds fields.
  2. Suricata severity mapping to Wazuh scale (the _SURICATA_SEVERITY_MAP constant).
  3. _process_suricata_alert correctly filters low-severity events.
  4. _process_suricata_alert creates Alert with source='suricata' and feeds clusterer.
  5. _process_suricata_alert handles non-alert eve.json events (returns None from parser).
  6. _process_suricata_alert handles missing rule_id gracefully.
  7. call_claude shim falls back to single-shot when api_key is not a plain string.
  8. call_claude shim falls back to single-shot on NotImplementedError from orchestrator.

Mock policy (Sacred Practice #5):
  - anthropic.AsyncAnthropic client is mocked — it is an external HTTP boundary.
  - SQLite _db is mocked — it is an external persistence boundary; these are
    unit tests for the tailer/clusterer logic, not the DB layer.
  - AlertClusterer is used real (in-memory); no mocks for internal modules.

# @mock-exempt: anthropic.AsyncAnthropic is an external HTTP API boundary
# @mock-exempt: SQLite _db is an external persistence boundary; DB layer has its own tests

@decision DEC-TAILER-001
@title Dual independent tailer tasks feeding a single shared AlertClusterer
@status accepted
@rationale See agent/main.py module docstring for full rationale. These tests
           verify the severity-mapping contract and the clusterer integration
           without starting a real FastAPI app or touching the filesystem.
"""

import asyncio
import json
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from agent.cluster import Alert, AlertClusterer, Cluster
from agent.config import Settings
from agent.main import _SURICATA_SEVERITY_MAP, _process_suricata_alert
from agent.triage import TriageResult, call_claude


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


def _make_eve_alert(
    event_type: str = "alert",
    src_ip: str = "10.0.0.1",
    dest_ip: str = "8.8.8.8",
    signature_id: int = 2100498,
    severity: int = 1,
    signature: str = "GPL ATTACK_RESPONSE id check returned root",
) -> dict:
    """Build a minimal eve.json event dict."""
    base = {
        "timestamp": "2026-01-01T12:00:00.000000+0000",
        "event_type": event_type,
        "src_ip": src_ip,
        "dest_ip": dest_ip,
        "proto": "TCP",
    }
    if event_type == "alert":
        base["alert"] = {
            "signature_id": signature_id,
            "severity": severity,
            "signature": signature,
        }
    return base


def _make_cluster(cluster_id: str = "test-cluster") -> Cluster:
    t0 = datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
    alert = Alert(
        id="alert-001",
        rule_id=5501,
        src_ip="192.168.1.100",
        severity=10,
        raw={"id": "alert-001"},
        timestamp=t0,
    )
    return Cluster(
        id=cluster_id,
        src_ip="192.168.1.100",
        rule_id=5501,
        window_start=t0,
        alerts=[alert],
    )


# ---------------------------------------------------------------------------
# 1. Config fields
# ---------------------------------------------------------------------------

def test_settings_has_suricata_eve_file():
    """Settings includes suricata_eve_file with the expected default."""
    s = _make_settings()
    assert hasattr(s, "suricata_eve_file")
    assert s.suricata_eve_file == "/var/log/suricata/eve.json"


def test_settings_has_suricata_poll_seconds():
    """Settings includes suricata_poll_seconds with default of 60."""
    s = _make_settings()
    assert hasattr(s, "suricata_poll_seconds")
    assert s.suricata_poll_seconds == 60


def test_settings_suricata_eve_file_env(monkeypatch):
    """SURICATA_EVE_FILE env var overrides the default path."""
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")
    monkeypatch.setenv("SURICATA_EVE_FILE", "/custom/path/eve.json")
    s = Settings()
    assert s.suricata_eve_file == "/custom/path/eve.json"


# ---------------------------------------------------------------------------
# 2. Severity mapping constant
# ---------------------------------------------------------------------------

def test_suricata_severity_map_critical():
    """Suricata sev 1 maps to 7 (passes default threshold of 7)."""
    assert _SURICATA_SEVERITY_MAP[1] == 7


def test_suricata_severity_map_high():
    """Suricata sev 2 maps to 6 (below default threshold, filtered out)."""
    assert _SURICATA_SEVERITY_MAP[2] == 6


def test_suricata_severity_map_medium():
    """Suricata sev 3 maps to 5 (below default threshold, filtered out)."""
    assert _SURICATA_SEVERITY_MAP[3] == 5


def test_suricata_severity_map_unknown_defaults_zero():
    """Unmapped severities return 0 via .get default, ensuring they are filtered."""
    assert _SURICATA_SEVERITY_MAP.get(99, 0) == 0
    assert _SURICATA_SEVERITY_MAP.get(None, 0) == 0


# ---------------------------------------------------------------------------
# 3. Severity pre-filter: low-severity alerts are dropped
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_process_suricata_alert_filters_medium_severity():
    """Suricata sev=3 (Medium → wazuh_scale=5) is filtered when severity_min_level=7."""
    # Module-level globals in main.py need to be set for _process_suricata_alert to work.
    import agent.main as main_module

    clusterer = AlertClusterer(window_seconds=300, max_alerts=50)
    settings = _make_settings(severity_min_level=7)

    main_module._clusterer = clusterer
    main_module._settings = settings
    main_module._db = MagicMock()

    eve_line = _make_eve_alert(severity=3)  # Medium → 5, below threshold 7

    open_before = clusterer.open_count
    await _process_suricata_alert(eve_line)
    # No alert should have been added to the clusterer
    assert clusterer.open_count == open_before


# ---------------------------------------------------------------------------
# 4. Valid high-severity alert reaches clusterer with source='suricata'
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_process_suricata_alert_critical_reaches_clusterer():
    """Suricata sev=1 (Critical → wazuh_scale=7) passes filter and is clustered."""
    import agent.main as main_module

    clusterer = AlertClusterer(window_seconds=300, max_alerts=50)
    settings = _make_settings(severity_min_level=7)

    main_module._clusterer = clusterer
    main_module._settings = settings

    # Mock DB to avoid hitting real SQLite
    mock_db = MagicMock()
    main_module._db = mock_db

    eve_line = _make_eve_alert(severity=1, signature_id=2100498, src_ip="10.0.0.5")

    await _process_suricata_alert(eve_line)

    # One cluster should now be open in the clusterer
    assert clusterer.open_count == 1

    # Verify the open cluster has source='suricata'
    with clusterer._lock:
        clusters = list(clusterer._open.values())
    assert len(clusters) == 1
    assert clusters[0].source == "suricata"
    assert clusters[0].src_ip == "10.0.0.5"
    assert clusters[0].rule_id == 2100498


# ---------------------------------------------------------------------------
# 5. Non-alert eve.json events are silently ignored
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_process_suricata_alert_ignores_flow_events():
    """flow event_type returns None from parser and is not clustered."""
    import agent.main as main_module

    clusterer = AlertClusterer(window_seconds=300, max_alerts=50)
    main_module._clusterer = clusterer
    main_module._settings = _make_settings()
    main_module._db = MagicMock()

    flow_line = _make_eve_alert(event_type="flow")
    open_before = clusterer.open_count

    await _process_suricata_alert(flow_line)

    assert clusterer.open_count == open_before


# ---------------------------------------------------------------------------
# 6. Missing rule_id is handled gracefully
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_process_suricata_alert_missing_rule_id():
    """Alert event with missing signature_id logs warning and does not crash."""
    import agent.main as main_module

    clusterer = AlertClusterer(window_seconds=300, max_alerts=50)
    main_module._clusterer = clusterer
    main_module._settings = _make_settings(severity_min_level=7)
    main_module._db = MagicMock()

    # Build an alert event with a non-integer signature_id
    bad_line = {
        "timestamp": "2026-01-01T12:00:00.000000+0000",
        "event_type": "alert",
        "src_ip": "10.0.0.1",
        "alert": {
            "signature_id": "NOT_AN_INT",
            "severity": 1,
            "signature": "bad rule",
        },
    }

    open_before = clusterer.open_count
    # Should not raise
    await _process_suricata_alert(bad_line)
    # Clusterer should be unchanged — bad alert discarded
    assert clusterer.open_count == open_before


# ---------------------------------------------------------------------------
# 7. call_claude shim falls back when api_key is not a plain string
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_call_claude_shim_fallback_on_mock_client():
    """call_claude falls back to single-shot when client.api_key is not a str."""
    fake_response_text = json.dumps({
        "severity": "High",
        "threat_assessment": "Test assessment.",
        "iocs": {"ips": [], "domains": [], "hashes": [], "paths": []},
        "yara_rule": "",
    })

    mock_message = MagicMock()
    mock_message.content = [MagicMock(text=fake_response_text)]

    mock_client = AsyncMock()
    mock_client.messages.create = AsyncMock(return_value=mock_message)
    # api_key is an AsyncMock (not a str) — triggers TypeError fallback
    # No explicit assignment needed; AsyncMock attributes are AsyncMocks by default

    cluster = _make_cluster("cluster-shim-test")
    result = await call_claude(mock_client, cluster, "claude-opus-4-5")

    assert isinstance(result, TriageResult)
    assert result.severity == "High"
    assert result.cluster_id == "cluster-shim-test"
    # The fallback path must have called the async client
    mock_client.messages.create.assert_called_once()


# ---------------------------------------------------------------------------
# 8. call_claude shim falls back on NotImplementedError from orchestrator
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_call_claude_shim_fallback_on_not_implemented():
    """call_claude falls back to single-shot when orchestrator raises NotImplementedError."""
    fake_response_text = json.dumps({
        "severity": "Critical",
        "threat_assessment": "Lateral movement detected.",
        "iocs": {"ips": ["1.2.3.4"], "domains": [], "hashes": [], "paths": []},
        "yara_rule": "",
    })

    mock_message = MagicMock()
    mock_message.content = [MagicMock(text=fake_response_text)]

    mock_client = AsyncMock()
    mock_client.api_key = "real-string-key"
    mock_client.messages.create = AsyncMock(return_value=mock_message)

    cluster = _make_cluster("cluster-ni-test")

    # Patch run_triage_loop to raise NotImplementedError (simulating stub state)
    with patch("agent.triage.asyncio.to_thread", side_effect=NotImplementedError("stub")):
        result = await call_claude(mock_client, cluster, "claude-opus-4-5")

    assert isinstance(result, TriageResult)
    assert result.severity == "Critical"
    assert result.cluster_id == "cluster-ni-test"
    mock_client.messages.create.assert_called_once()
