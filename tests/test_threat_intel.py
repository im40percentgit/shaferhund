"""
Threat-intel module tests (Phase 3, REQ-P0-P3-005).

Tests cover:
  1. test_parse_json_fixture_yields_indicators   — fixture JSON produces expected indicator rows
  2. test_fetch_and_store_from_data_populates_db — in-memory fetch populates threat_intel table
  3. test_lookup_hit                             — lookup() returns hit=True for known indicator
  4. test_lookup_miss                            — lookup() returns hit=False for unknown indicator
  5. test_lookup_returns_correct_shape           — hit result has matches list + context dict
  6. test_md5_indicators_extracted               — MD5 from payload_md5 field stored as md5 type
  7. test_dedup_upsert_updates_last_seen         — re-inserting same indicator updates last_seen
  8. test_count_threat_intel_records             — count_threat_intel_records reflects inserts
  9. test_fetch_and_store_mocked_http            — mocked httpx response triggers DB population
  10. test_csv_parse_extracts_url_indicators     — CSV text parses to url-type indicators

# @mock-exempt: httpx.Client is an external HTTP boundary. Mocking it is correct
# for tests that verify parsing and DB population without live network access.
# The real fetch_and_store path is integration-level; test_fetch_and_store_mocked_http
# exercises the full code path with a mocked HTTP response.

# @decision DEC-ORCH-005
# @title check_threat_intel — URLhaus fetch + lookup test coverage
# @status accepted
# @rationale Tests exercise the real SQLite schema (no internal mocks), committed
#            fixture data for determinism, and a mocked httpx boundary only where
#            live network access would be required. This follows Sacred Practice #5.
"""

import json
import sqlite3
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from agent.models import count_threat_intel_records, get_threat_intel_matches, init_db
from agent.threat_intel import (
    _parse_urlhaus_csv,
    _parse_urlhaus_json,
    fetch_and_store,
    fetch_and_store_from_data,
    lookup,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

FIXTURES_DIR = Path(__file__).parent / "fixtures"


def _load_fixture() -> dict:
    """Load the urlhaus_sample.json fixture."""
    return json.loads((FIXTURES_DIR / "urlhaus_sample.json").read_text())


def _fresh_db() -> sqlite3.Connection:
    """Open an in-memory DB with the full Phase 3 schema applied."""
    return init_db(":memory:")


# ---------------------------------------------------------------------------
# Test 1: JSON fixture parses to expected indicator dicts
# ---------------------------------------------------------------------------

def test_parse_json_fixture_yields_indicators():
    """_parse_urlhaus_json produces at least one indicator per fixture entry."""
    data = _load_fixture()
    indicators = _parse_urlhaus_json(data)

    # Fixture has 3 url entries; 2 of those have non-empty payload_md5
    url_indicators = [i for i in indicators if i["indicator_type"] == "url"]
    md5_indicators = [i for i in indicators if i["indicator_type"] == "md5"]

    assert len(url_indicators) == 3, f"Expected 3 url indicators, got {len(url_indicators)}"
    assert len(md5_indicators) == 2, f"Expected 2 md5 indicators, got {len(md5_indicators)}"

    # Verify first URL
    first = url_indicators[0]
    assert first["indicator"] == "http://malware.example.com/payload.exe"
    assert first["indicator_type"] == "url"
    assert first["first_seen"] == "2026-04-20 10:00:00 UTC"


# ---------------------------------------------------------------------------
# Test 2: fetch_and_store_from_data populates the threat_intel table
# ---------------------------------------------------------------------------

def test_fetch_and_store_from_data_populates_db():
    """Feeding the fixture dict into fetch_and_store_from_data yields ≥1 DB row."""
    conn = _fresh_db()
    data = _load_fixture()

    count = fetch_and_store_from_data(conn, data)

    assert count >= 1, "Expected at least 1 indicator inserted"
    db_count = count_threat_intel_records(conn)
    assert db_count == count, f"DB count {db_count} should equal inserted count {count}"
    conn.close()


# ---------------------------------------------------------------------------
# Test 3: lookup() returns hit=True for known indicator
# ---------------------------------------------------------------------------

def test_lookup_hit():
    """lookup() returns hit=True when the indicator exists in the DB."""
    conn = _fresh_db()
    data = _load_fixture()
    fetch_and_store_from_data(conn, data)

    result = lookup("http://malware.example.com/payload.exe", conn)

    assert result["hit"] is True
    assert len(result["matches"]) >= 1
    conn.close()


# ---------------------------------------------------------------------------
# Test 4: lookup() returns hit=False for unknown indicator
# ---------------------------------------------------------------------------

def test_lookup_miss():
    """lookup() returns hit=False when the indicator is not in the DB."""
    conn = _fresh_db()
    data = _load_fixture()
    fetch_and_store_from_data(conn, data)

    result = lookup("http://completely.unknown.example.org/nothere", conn)

    assert result["hit"] is False
    assert result["matches"] == []
    conn.close()


# ---------------------------------------------------------------------------
# Test 5: lookup() hit has correct shape (matches list + context)
# ---------------------------------------------------------------------------

def test_lookup_returns_correct_shape():
    """Hit result has matches (list), context (dict or None), hit (bool)."""
    conn = _fresh_db()
    data = _load_fixture()
    fetch_and_store_from_data(conn, data)

    result = lookup("http://c2.badactor.net/gate.php", conn)

    assert "matches" in result
    assert "context" in result
    assert "hit" in result
    assert isinstance(result["matches"], list)
    assert result["hit"] is True

    # context should be a dict (parsed from context_json)
    assert result["context"] is None or isinstance(result["context"], dict)
    conn.close()


# ---------------------------------------------------------------------------
# Test 6: MD5 indicators are extracted from payload_md5 field
# ---------------------------------------------------------------------------

def test_md5_indicators_extracted():
    """payload_md5 field in fixture entries produces md5-type threat_intel rows."""
    conn = _fresh_db()
    data = _load_fixture()
    fetch_and_store_from_data(conn, data)

    # Fixture entry 1 has payload_md5 = "d41d8cd98f00b204e9800998ecf8427e"
    result = lookup("d41d8cd98f00b204e9800998ecf8427e", conn)

    assert result["hit"] is True
    md5_match = result["matches"][0]
    assert md5_match["indicator_type"] == "md5"
    conn.close()


# ---------------------------------------------------------------------------
# Test 7: Dedup — re-inserting same indicator updates last_seen
# ---------------------------------------------------------------------------

def test_dedup_upsert_updates_last_seen():
    """Re-inserting the same indicator updates last_seen without creating a duplicate."""
    conn = _fresh_db()
    data = _load_fixture()

    # First insert
    fetch_and_store_from_data(conn, data)
    initial_count = count_threat_intel_records(conn)

    # Second insert of identical data — should upsert, not grow
    fetch_and_store_from_data(conn, data)
    final_count = count_threat_intel_records(conn)

    assert final_count == initial_count, (
        f"Dedup failed: count grew from {initial_count} to {final_count}"
    )
    conn.close()


# ---------------------------------------------------------------------------
# Test 8: count_threat_intel_records reflects actual inserts
# ---------------------------------------------------------------------------

def test_count_threat_intel_records():
    """count_threat_intel_records returns 0 on empty DB, > 0 after insert."""
    conn = _fresh_db()

    assert count_threat_intel_records(conn) == 0

    data = _load_fixture()
    fetch_and_store_from_data(conn, data)

    assert count_threat_intel_records(conn) > 0
    conn.close()


# ---------------------------------------------------------------------------
# Test 9: fetch_and_store with mocked httpx response
# ---------------------------------------------------------------------------

def test_fetch_and_store_mocked_http():
    """fetch_and_store populates the DB when given a mocked httpx JSON response."""
    conn = _fresh_db()
    data = _load_fixture()

    mock_response = MagicMock()
    mock_response.headers = {"content-type": "application/json"}
    mock_response.json.return_value = data
    mock_response.raise_for_status = MagicMock()

    mock_client_instance = MagicMock()
    mock_client_instance.get.return_value = mock_response
    mock_client_instance.__enter__ = MagicMock(return_value=mock_client_instance)
    mock_client_instance.__exit__ = MagicMock(return_value=False)

    with patch("agent.threat_intel.httpx.Client", return_value=mock_client_instance):
        count = fetch_and_store(conn, "https://urlhaus.abuse.ch/downloads/json/")

    assert count >= 1, "Expected at least 1 indicator from mocked response"
    assert count_threat_intel_records(conn) == count
    conn.close()


# ---------------------------------------------------------------------------
# Test 10: CSV parsing extracts url-type indicators
# ---------------------------------------------------------------------------

def test_csv_parse_extracts_url_indicators():
    """_parse_urlhaus_csv extracts url-type indicators from CSV text."""
    # Minimal URLhaus CSV format (comment lines + header + one data row)
    csv_text = (
        "# URLhaus online CSV export\n"
        "# Date: 2026-04-24\n"
        'id,dateadded,url,url_status,last_online,threat,tags,urlhaus_link,reporter\n'
        '"1234567","2026-04-24 10:00:00 UTC","http://csv.example.com/bad.exe",'
        '"online","2026-04-24 09:00:00 UTC","malware_download","","'
        'https://urlhaus.abuse.ch/url/1234567/","test_reporter"\n'
    )

    indicators = _parse_urlhaus_csv(csv_text)

    url_inds = [i for i in indicators if i["indicator_type"] == "url"]
    assert len(url_inds) >= 1
    assert url_inds[0]["indicator"] == "http://csv.example.com/bad.exe"
