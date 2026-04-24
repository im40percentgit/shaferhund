"""
URLhaus threat-intelligence ingestion and lookup for Shaferhund Phase 3.

Fetches the Abuse.ch URLhaus "online URLs" CSV feed on a configurable interval
and persists indicators to the local ``threat_intel`` SQLite table for offline
lookups by the orchestrator's ``check_threat_intel`` tool.

Feed URL: https://urlhaus.abuse.ch/downloads/csv_online/
The feed is a CSV with comment lines starting with '#'. Each data row contains:
  id, dateadded, url, url_status, last_online, threat, tags, urlhaus_link, reporter

The poller also extracts the URL value itself as a 'url' indicator and, where
available, any MD5 hash listed in the ``tags`` field as 'md5' indicators.

Lookup behaviour:
    lookup(value, conn) queries threat_intel for an exact case-insensitive match
    on the indicator column and returns a dict compatible with the
    check_threat_intel orchestrator tool's expected output shape.

@decision DEC-ORCH-005
@title check_threat_intel is the 7th orchestrator tool — URLhaus feed via httpx
@status accepted
@rationale Phase 3 threat intel spec (REQ-P0-P3-005) requires URLhaus indicators
           (URL + payload MD5) to be available in the orchestrator's reasoning loop.
           httpx is already present in requirements.txt (0.28.1); no new dependency.
           The feed is fetched hourly via an asyncio.Task registered in lifespan —
           the same pattern as the Wazuh and Suricata tailers. Direct TOOLS-list
           patch follows DEC-ORCH-003 (dynamic registration is a Phase 4 concern,
           per REQ-NOGO-P3-008). The tool is a read-only lookup with sanitized
           input (DEC-ORCH-004) to guard against attacker-influenced indicator
           values smuggled through alert fields.
"""

import asyncio
import csv
import io
import json
import logging
import sqlite3
from datetime import datetime, timezone
from typing import Optional

import httpx

from .models import count_threat_intel_records, get_threat_intel_matches, insert_threat_intel

log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Default URLhaus online-URL CSV feed. Overrideable via URLHAUS_FEED_URL env var.
_DEFAULT_FEED_URL = "https://urlhaus.abuse.ch/downloads/csv_online/"

# Seconds to wait after a transient HTTP failure before retrying inside the
# poll loop. The poll loop itself is called every urlhaus_fetch_interval_seconds;
# this value only applies to quick back-off inside a single failed fetch.
_RETRY_BACKOFF_SECONDS = 60

# How many indicator rows to bulk-insert before committing (prevents holding
# a write lock for the entire (potentially large) feed parse).
_BATCH_SIZE = 500


# ---------------------------------------------------------------------------
# Feed parser
# ---------------------------------------------------------------------------

def _parse_urlhaus_csv(raw_text: str) -> list[dict]:
    """Parse the URLhaus online CSV feed and return a list of indicator dicts.

    Each returned dict has keys:
        indicator      (str)  — the URL or extracted MD5
        indicator_type (str)  — 'url'
        first_seen     (str)  — ISO8601 dateadded from the feed
        last_seen      (str)  — ISO8601 last_online from the feed (may be None)
        context_json   (str)  — JSON with tags, threat, urlhaus_link, reporter

    Comment lines (starting with '#') are skipped. Rows with empty 'url' fields
    are also skipped. MD5 hashes embedded in the 'tags' column (URLhaus sometimes
    includes them as comma-separated tag values) are extracted as separate 'md5'
    indicator entries.

    Args:
        raw_text: Full text of the URLhaus CSV response.

    Returns:
        List of indicator dicts ready to pass to insert_threat_intel.
    """
    indicators: list[dict] = []

    # Strip comment lines; URLhaus comments start with '#'
    lines = [line for line in raw_text.splitlines() if not line.startswith("#")]
    if not lines:
        return indicators

    reader = csv.DictReader(lines)
    for row in reader:
        url = (row.get("url") or "").strip()
        if not url:
            continue

        dateadded = (row.get("dateadded") or "").strip()
        last_online = (row.get("last_online") or "").strip() or None
        threat = (row.get("threat") or "").strip()
        tags = (row.get("tags") or "").strip()
        urlhaus_link = (row.get("urlhaus_link") or "").strip()
        reporter = (row.get("reporter") or "").strip()

        context = json.dumps({
            "threat": threat,
            "tags": tags,
            "urlhaus_link": urlhaus_link,
            "reporter": reporter,
        })

        indicators.append({
            "indicator": url,
            "indicator_type": "url",
            "first_seen": dateadded or None,
            "last_seen": last_online,
            "context_json": context,
        })

        # Extract MD5 hashes from tags if present (format: "md5:<hash>")
        for tag in tags.split(","):
            tag = tag.strip()
            if tag.startswith("md5:"):
                md5_val = tag[4:].strip()
                if len(md5_val) == 32:  # basic sanity: MD5 is always 32 hex chars
                    indicators.append({
                        "indicator": md5_val.lower(),
                        "indicator_type": "md5",
                        "first_seen": dateadded or None,
                        "last_seen": last_online,
                        "context_json": context,
                    })

    return indicators


def _parse_urlhaus_json(raw_json: dict) -> list[dict]:
    """Parse a URLhaus JSON payload (used for test fixtures).

    Accepts the same shape as the URLhaus JSON API:
      {"urls": [{"url": "...", "date_added": "...", ...}, ...]}

    Args:
        raw_json: Parsed JSON dict from the URLhaus API or test fixture.

    Returns:
        List of indicator dicts compatible with insert_threat_intel.
    """
    indicators: list[dict] = []
    urls = raw_json.get("urls", [])
    for entry in urls:
        url = (entry.get("url") or "").strip()
        if not url:
            continue

        dateadded = (entry.get("date_added") or "").strip() or None
        last_online = (entry.get("last_online") or "").strip() or None
        threat = (entry.get("threat") or "").strip()
        tags_raw = entry.get("tags") or []
        tags_str = ",".join(tags_raw) if isinstance(tags_raw, list) else str(tags_raw)
        urlhaus_link = (entry.get("urlhaus_reference") or "").strip()
        reporter = (entry.get("reporter") or "").strip()

        context = json.dumps({
            "threat": threat,
            "tags": tags_str,
            "urlhaus_link": urlhaus_link,
            "reporter": reporter,
        })

        indicators.append({
            "indicator": url,
            "indicator_type": "url",
            "first_seen": dateadded,
            "last_seen": last_online,
            "context_json": context,
        })

        # Extract MD5 hash from payload field if present
        payload_hash = (entry.get("payload_md5") or "").strip().lower()
        if len(payload_hash) == 32:
            indicators.append({
                "indicator": payload_hash,
                "indicator_type": "md5",
                "first_seen": dateadded,
                "last_seen": last_online,
                "context_json": context,
            })

    return indicators


# ---------------------------------------------------------------------------
# Fetch and persist
# ---------------------------------------------------------------------------

def fetch_and_store(conn: sqlite3.Connection, feed_url: str) -> int:
    """Fetch the URLhaus feed and upsert all indicators into threat_intel.

    Detects the feed format by inspecting the Content-Type header:
      - application/json or URL ending in .json → JSON path (_parse_urlhaus_json)
      - anything else (text/plain, text/csv, default) → CSV path (_parse_urlhaus_csv)

    This makes the function work with both the live CSV feed and the JSON-format
    test fixtures committed in tests/fixtures/.

    Args:
        conn:     Open SQLite connection.
        feed_url: URL of the URLhaus feed to fetch.

    Returns:
        Number of indicator rows processed (inserted or updated).

    Raises:
        httpx.HTTPError: On network-level failures (propagated to caller for
                         logging and back-off handling in the poll loop).
    """
    log.info("Fetching URLhaus feed from %s", feed_url)
    with httpx.Client(timeout=30.0, follow_redirects=True) as client:
        response = client.get(feed_url)
        response.raise_for_status()

    content_type = response.headers.get("content-type", "")
    is_json = "json" in content_type or feed_url.rstrip("/").endswith(".json")

    if is_json:
        raw_json = response.json()
        indicators = _parse_urlhaus_json(raw_json)
    else:
        indicators = _parse_urlhaus_csv(response.text)

    if not indicators:
        log.warning("URLhaus feed parsed but yielded 0 indicators from %s", feed_url)
        return 0

    inserted = 0
    for i in range(0, len(indicators), _BATCH_SIZE):
        batch = indicators[i : i + _BATCH_SIZE]
        for ind in batch:
            insert_threat_intel(
                conn,
                indicator=ind["indicator"],
                indicator_type=ind["indicator_type"],
                first_seen=ind.get("first_seen"),
                last_seen=ind.get("last_seen"),
                source="urlhaus_online",
                context_json=ind.get("context_json"),
            )
            inserted += 1

    log.info(
        "URLhaus fetch complete: %d indicators upserted (total in DB: %d)",
        inserted,
        count_threat_intel_records(conn),
    )
    return inserted


def fetch_and_store_from_data(conn: sqlite3.Connection, data: dict | str) -> int:
    """Parse and store threat intel directly from an in-memory payload.

    Accepts either a dict (JSON payload, used by tests) or a raw string (CSV text).
    Does NOT make any HTTP request — purely parses and persists.

    Args:
        conn: Open SQLite connection.
        data: Either a dict (JSON) or a str (CSV text).

    Returns:
        Number of indicator rows processed.
    """
    if isinstance(data, dict):
        indicators = _parse_urlhaus_json(data)
    else:
        indicators = _parse_urlhaus_csv(data)

    inserted = 0
    for ind in indicators:
        insert_threat_intel(
            conn,
            indicator=ind["indicator"],
            indicator_type=ind["indicator_type"],
            first_seen=ind.get("first_seen"),
            last_seen=ind.get("last_seen"),
            source="urlhaus_online",
            context_json=ind.get("context_json"),
        )
        inserted += 1
    return inserted


# ---------------------------------------------------------------------------
# Lookup
# ---------------------------------------------------------------------------

def lookup(value: str, conn: sqlite3.Connection) -> dict:
    """Query the local threat_intel table for an indicator value.

    Returns a dict with keys:
        matches (list[dict]) — all matching rows from threat_intel.
        context (str | None) — the context_json from the first match, or None.
        hit (bool)           — True when at least one match was found.

    The returned shape is used directly as the tool result for the orchestrator's
    check_threat_intel tool.

    Args:
        value: The indicator to look up (URL or MD5 hash).
        conn:  Open SQLite connection.

    Returns:
        Dict with keys: matches, context, hit.
    """
    rows = get_threat_intel_matches(conn, value)
    first_context = None
    if rows:
        first_context = rows[0].get("context_json")
        try:
            first_context = json.loads(first_context) if first_context else None
        except (json.JSONDecodeError, TypeError):
            pass  # leave as raw string if not valid JSON

    return {
        "matches": rows,
        "context": first_context,
        "hit": len(rows) > 0,
    }


# ---------------------------------------------------------------------------
# Async poll loop (registered as a lifespan Task in main.py)
# ---------------------------------------------------------------------------

async def urlhaus_poll_loop(
    conn: sqlite3.Connection,
    feed_url: str,
    interval_seconds: int,
) -> None:
    """Async loop that fetches the URLhaus feed every interval_seconds.

    Designed to run as an asyncio.Task via lifespan. Each iteration calls
    fetch_and_store in a thread executor (httpx is synchronous) so the event
    loop is not blocked during the HTTP fetch.

    On HTTP or network errors, logs a warning and waits _RETRY_BACKOFF_SECONDS
    before the next sleep (not the full interval) so transient failures don't
    delay the next attempt by a full hour.

    Args:
        conn:             Open SQLite connection (shared with the main app).
        feed_url:         URLhaus feed URL.
        interval_seconds: How many seconds to sleep between fetches.
    """
    log.info(
        "URLhaus poller started (feed=%s interval=%ds)",
        feed_url,
        interval_seconds,
    )
    loop = asyncio.get_event_loop()

    while True:
        try:
            await loop.run_in_executor(
                None,
                fetch_and_store,
                conn,
                feed_url,
            )
            await asyncio.sleep(interval_seconds)
        except asyncio.CancelledError:
            log.info("URLhaus poller cancelled")
            return
        except Exception as exc:
            log.warning(
                "URLhaus fetch failed (will retry in %ds): %s",
                _RETRY_BACKOFF_SECONDS,
                exc,
            )
            try:
                await asyncio.sleep(_RETRY_BACKOFF_SECONDS)
            except asyncio.CancelledError:
                log.info("URLhaus poller cancelled during backoff")
                return
