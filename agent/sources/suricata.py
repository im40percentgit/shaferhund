"""
Suricata eve.json alert parser for Shaferhund.

Parses lines from Suricata's EVE JSON log into the shared alert shape
consumed by the Alert Normaliser (Wave B, issue #6).

@decision DEC-SURICATA-001
@title Suricata 7 container + pcap-replay via tcpreplay — this file parses eve.json into the shared Alert shape
@status accepted
@rationale Suricata 7's EVE JSON format is stable and well-documented.
           Parsing each line from the eve.json output file as NDJSON is
           lower-friction than the Unix socket API and works identically
           with both live capture and pcap-replay test scenarios.
           Wave B will wire this into the shared normaliser; for now
           this module stands alone and is independently testable.
"""

import json
import logging
from typing import Iterator, Optional

log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Severity mapping
# ---------------------------------------------------------------------------

SEVERITY_MAP: dict[int, str] = {
    1: "Critical",
    2: "High",
    3: "Medium",
}


def map_severity(suricata_severity: int) -> str:
    """Map a Suricata integer severity (1-3) to a human-readable string.

    Suricata uses 1=highest, 3=lowest for rule-defined severities.
    Any value outside 1-3 (including None) returns 'Low'.

    Args:
        suricata_severity: Integer severity from Suricata alert.severity field.

    Returns:
        One of 'Critical', 'High', 'Medium', or 'Low'.
    """
    return SEVERITY_MAP.get(suricata_severity, "Low")


# ---------------------------------------------------------------------------
# Alert parser
# ---------------------------------------------------------------------------

def parse_suricata_alert(line: dict) -> Optional[dict]:
    """Parse a single parsed eve.json line dict into the shared alert shape.

    Only processes lines with event_type == 'alert'. Non-alert lines
    (flow, anomaly, dns, etc.) return None. Lines with missing or
    malformed 'alert' sub-object also return None — no exception raised.

    Args:
        line: A single parsed eve.json event as a dict (not a raw JSON string).

    Returns:
        A dict with keys: source, src_ip, dest_ip, protocol, rule_id,
        rule_description, normalized_severity, timestamp, raw_json.
        Returns None if the line is not a parseable alert.
    """
    if line.get("event_type") != "alert":
        return None

    alert_block = line.get("alert")
    if not alert_block or not isinstance(alert_block, dict):
        return None

    try:
        rule_id = str(alert_block["signature_id"])
    except (KeyError, TypeError):
        return None

    return {
        "source": "suricata",
        "src_ip": line.get("src_ip"),
        "dest_ip": line.get("dest_ip"),
        "protocol": line.get("proto"),
        "rule_id": rule_id,
        "rule_description": alert_block.get("signature", ""),
        "normalized_severity": map_severity(alert_block.get("severity")),
        "timestamp": line.get("timestamp"),
        "raw_json": json.dumps(line),
    }


# ---------------------------------------------------------------------------
# File tailer
# ---------------------------------------------------------------------------

def tail_eve_json(path: str, from_position: int = 0) -> Iterator[tuple[int, dict]]:
    """Generator that yields (new_position, parsed_line) from a Suricata eve.json.

    Reads from byte offset from_position to EOF. Caller is responsible for
    tracking the returned position across successive calls to implement
    incremental tailing (same pattern as Phase 1's _read_new_lines helper
    in agent/main.py).

    Malformed JSON lines are skipped with a logged warning rather than
    raising. FileNotFoundError is handled by returning immediately —
    matching the resilient tailer pattern used in the Wazuh poller.

    Args:
        path: Absolute or relative path to the eve.json file.
        from_position: Byte offset to start reading from (default 0).

    Yields:
        Tuples of (new_position, parsed_line_dict). new_position is the
        byte offset after the yielded line, suitable for use as
        from_position in the next call.
    """
    try:
        fh = open(path, "r", encoding="utf-8", errors="replace")
    except FileNotFoundError:
        log.debug("eve.json not found at %s — skipping", path)
        return

    with fh:
        fh.seek(from_position)
        while True:
            raw_line = fh.readline()
            if not raw_line:
                break  # EOF
            stripped = raw_line.strip()
            if not stripped:
                continue
            try:
                parsed = json.loads(stripped)
            except json.JSONDecodeError as exc:
                log.warning("Malformed JSON line in eve.json (skipped): %s", exc)
                continue
            new_position = fh.tell()
            yield new_position, parsed
