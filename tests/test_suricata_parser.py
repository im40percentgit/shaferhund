"""
Tests for agent.sources.suricata — the Suricata EVE JSON parser.

Covers: severity mapping, alert parsing, non-alert event filtering,
graceful error handling, and the file tailer generator.

All tests run against the real implementation with no mocks.
Fixture: tests/fixtures/suricata_eve_sample.json (5 NDJSON lines).

@decision DEC-SURICATA-002
@title Real-implementation tests against NDJSON fixture, no mocks
@status accepted
@rationale Tests exercise the actual parse_suricata_alert, map_severity,
           and tail_eve_json functions directly. Using a static NDJSON
           fixture (not a mock file object) means the tailer's file-seek
           logic is tested end-to-end, matching Sacred Practice #5
           (no mocks for internal modules).
"""

import json
from pathlib import Path

import pytest

from agent.sources.suricata import map_severity, parse_suricata_alert, tail_eve_json

# ---------------------------------------------------------------------------
# Fixture path
# ---------------------------------------------------------------------------

FIXTURE_PATH = Path(__file__).parent / "fixtures" / "suricata_eve_sample.json"


def load_fixture_lines() -> list[dict]:
    """Read FIXTURE_PATH, parse each non-empty line as JSON, return list."""
    lines = []
    for raw in FIXTURE_PATH.read_text(encoding="utf-8").splitlines():
        stripped = raw.strip()
        if stripped:
            lines.append(json.loads(stripped))
    return lines


# ---------------------------------------------------------------------------
# Severity mapping tests
# ---------------------------------------------------------------------------

def test_map_severity_critical():
    assert map_severity(1) == "Critical"


def test_map_severity_high():
    assert map_severity(2) == "High"


def test_map_severity_medium():
    assert map_severity(3) == "Medium"


def test_map_severity_default_low():
    assert map_severity(None) == "Low"
    assert map_severity(99) == "Low"


# ---------------------------------------------------------------------------
# Alert parsing tests
# ---------------------------------------------------------------------------

def test_parse_alert_critical():
    """Line 0: severity=1 GPL ATTACK_RESPONSE alert."""
    lines = load_fixture_lines()
    result = parse_suricata_alert(lines[0])

    assert result is not None
    assert result["source"] == "suricata"
    assert result["src_ip"] == "192.168.1.105"
    assert result["dest_ip"] == "93.184.216.34"
    assert result["protocol"] == "TCP"
    assert result["rule_id"] == "2100498"
    assert result["normalized_severity"] == "Critical"
    assert "GPL ATTACK_RESPONSE" in result["rule_description"]


def test_parse_alert_high():
    """Line 1: severity=2 Cobalt Strike alert."""
    lines = load_fixture_lines()
    result = parse_suricata_alert(lines[1])

    assert result is not None
    assert result["normalized_severity"] == "High"
    assert result["rule_id"] == "2022973"


def test_parse_alert_medium():
    """Line 4: severity=3 curl User-Agent alert."""
    lines = load_fixture_lines()
    result = parse_suricata_alert(lines[4])

    assert result is not None
    assert result["normalized_severity"] == "Medium"


def test_parse_flow_returns_none():
    """Line 2 is a flow event — must return None."""
    lines = load_fixture_lines()
    assert lines[2]["event_type"] == "flow"
    assert parse_suricata_alert(lines[2]) is None


def test_parse_anomaly_returns_none():
    """Line 3 is an anomaly event — must return None."""
    lines = load_fixture_lines()
    assert lines[3]["event_type"] == "anomaly"
    assert parse_suricata_alert(lines[3]) is None


def test_missing_alert_key_graceful():
    """A dict with event_type='alert' but no 'alert' sub-key returns None without raising."""
    line = {"event_type": "alert", "src_ip": "1.2.3.4"}
    result = parse_suricata_alert(line)
    assert result is None


# ---------------------------------------------------------------------------
# Tailer tests
# ---------------------------------------------------------------------------

def test_tail_eve_json_reads_all_lines(tmp_path):
    """Tailer yields all 5 lines from the fixture and positions are monotonically increasing."""
    fixture_copy = tmp_path / "eve.json"
    fixture_copy.write_bytes(FIXTURE_PATH.read_bytes())

    results = list(tail_eve_json(str(fixture_copy)))

    assert len(results) == 5

    positions = [pos for pos, _ in results]
    for i in range(1, len(positions)):
        assert positions[i] > positions[i - 1], (
            f"Position {positions[i]} at index {i} is not greater than "
            f"{positions[i-1]} at index {i-1}"
        )


def test_tail_eve_json_missing_file_returns_empty(tmp_path):
    """Tailer on a nonexistent path yields nothing and raises no exception."""
    nonexistent = str(tmp_path / "does_not_exist.json")
    results = list(tail_eve_json(nonexistent))
    assert results == []
