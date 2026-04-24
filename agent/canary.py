"""
Canary token infrastructure for Shaferhund Phase 3 (REQ-P0-P3-004).

Provides DNS and HTTP trap tokens that, when triggered by an attacker probing
the environment, inject ``source='canary'`` alert rows into the shared alert
pipeline. Those alerts flow through the clusterer, triage queue, and
orchestrator identically to Wazuh and Suricata alerts.

Spawn flow:
    POST /canary/spawn → spawn_canary() → canary_tokens row → trap URL/hostname

Hit flow:
    GET /canary/hit/{token} → record_hit() → increment trigger_count →
    write alert row with source='canary' → clusterer → triage

Security notes:
  - token is generated with secrets.token_urlsafe(16) (128 bits of entropy).
  - request_meta keys (User-Agent, X-Forwarded-For, etc.) are attacker-controlled;
    all values passed to the alert row are sanitized via sanitize_alert_field().
  - The name param to spawn_canary() is operator-controlled but is also sanitized
    as a defence-in-depth measure.

@decision DEC-CANARY-001
@title Canary tokens use secrets.token_urlsafe(16) for 128-bit entropy
@status accepted
@rationale Tokens are embedded in public trap URLs / hostnames. 16 bytes of
           cryptographic randomness (≈ 22 base64 chars) gives 2^128 entropy,
           making brute-force guessing impractical. secrets module is stdlib —
           no external dependency. URL-safe alphabet avoids percent-encoding
           issues in trap URLs and DNS labels.

@decision DEC-CANARY-002
@title Canary hits inject source='canary' alerts via the shared _persist_and_enqueue path
@status accepted
@rationale Canary hits are threats just like Wazuh or Suricata alerts — they
           deserve the same clustering, triage, and rule-generation pipeline.
           Routing them through the same entry point (Cluster → TriageQueue →
           orchestrator) means canary alerts automatically get AI triage and
           can trigger YARA/Sigma rule generation. A separate pipeline would
           duplicate logic and create a maintenance burden. The alert id uses a
           'canary:' prefix so dedup works without colliding with Wazuh IDs.

@decision DEC-CANARY-003
@title spawn_canary and record_hit are pure DB helpers; HTTP wiring lives in main.py
@status accepted
@rationale Keeping network concerns (request parsing, response formatting) in
           main.py and persistence concerns here follows the same separation
           used for threat_intel.py vs main.py. This makes record_hit testable
           without a running FastAPI app — tests call it directly with a
           fabricated request_meta dict and an in-memory connection.
"""

import logging
import secrets
import sqlite3
from datetime import datetime, timezone
from typing import Optional

log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Sanitization
# ---------------------------------------------------------------------------

_MAX_FIELD_LEN = 1024


def sanitize_alert_field(value: str) -> str:
    """Sanitize an attacker- or operator-controlled string for safe storage.

    Strips leading/trailing whitespace and truncates to _MAX_FIELD_LEN
    characters. Does NOT strip non-printable characters — the raw value
    may be useful for forensics — but keeps the field bounded to prevent
    storage abuse.

    Args:
        value: Input string (may be attacker-controlled).

    Returns:
        Sanitized string, at most _MAX_FIELD_LEN characters.
    """
    if not isinstance(value, str):
        value = str(value)
    return value.strip()[:_MAX_FIELD_LEN]


# ---------------------------------------------------------------------------
# Canary token CRUD
# ---------------------------------------------------------------------------

def insert_canary_token(
    conn: sqlite3.Connection,
    token: str,
    token_type: str,
    name: str,
) -> int:
    """Insert a new canary_tokens row and return the row id.

    Args:
        conn:       Open SQLite connection.
        token:      Unique opaque token string (URL-safe base64).
        token_type: 'dns' or 'http'.
        name:       Human-readable label for this canary.

    Returns:
        The INTEGER PRIMARY KEY of the new row.
    """
    created_at = datetime.now(timezone.utc).isoformat()
    with _cursor(conn) as cur:
        cur.execute(
            """
            INSERT INTO canary_tokens (token, type, name, created_at, trigger_count)
            VALUES (?, ?, ?, ?, 0)
            """,
            (token, token_type, name, created_at),
        )
        return cur.lastrowid


def get_canary_token_by_token(
    conn: sqlite3.Connection,
    token: str,
) -> Optional[sqlite3.Row]:
    """Return the canary_tokens row for a given token string, or None.

    Args:
        conn:  Open SQLite connection.
        token: The opaque token value to look up.

    Returns:
        sqlite3.Row or None.
    """
    return conn.execute(
        "SELECT * FROM canary_tokens WHERE token = ?",
        (token,),
    ).fetchone()


def increment_canary_trigger(
    conn: sqlite3.Connection,
    token: str,
) -> None:
    """Increment trigger_count and set last_triggered_at for a token.

    Idempotent in the sense that repeated calls keep counting correctly.
    Does nothing if the token does not exist.

    Args:
        conn:  Open SQLite connection.
        token: The token that was triggered.
    """
    now = datetime.now(timezone.utc).isoformat()
    with _cursor(conn) as cur:
        cur.execute(
            """
            UPDATE canary_tokens
               SET trigger_count = trigger_count + 1,
                   last_triggered_at = ?
             WHERE token = ?
            """,
            (now, token),
        )


def list_canary_tokens(
    conn: sqlite3.Connection,
    limit: int = 100,
) -> list[sqlite3.Row]:
    """Return canary_tokens rows ordered newest-first.

    Args:
        conn:  Open SQLite connection.
        limit: Maximum rows to return.

    Returns:
        List of sqlite3.Row objects.
    """
    return conn.execute(
        "SELECT * FROM canary_tokens ORDER BY created_at DESC LIMIT ?",
        (limit,),
    ).fetchall()


def count_canary_triggers_since(
    conn: sqlite3.Connection,
    ts: float,
) -> int:
    """Count canary trigger events where last_triggered_at >= ts.

    Sums trigger_count for tokens whose last_triggered_at falls within the
    window. This is a proxy: it counts distinct tokens that were triggered
    in the window, not total trigger events (which would require an event log).
    For /health purposes (24h count) this is sufficient — a single token
    triggered many times in 24h still shows as 1.

    For an accurate total, sum trigger_count across all rows that were
    last triggered within the window.

    Args:
        conn: Open SQLite connection.
        ts:   Unix epoch float (e.g. time.time() - 86400).

    Returns:
        Integer count of trigger_count sum for tokens triggered since ts.
    """
    since_iso = datetime.fromtimestamp(ts, tz=timezone.utc).isoformat()
    row = conn.execute(
        """
        SELECT COALESCE(SUM(trigger_count), 0)
          FROM canary_tokens
         WHERE last_triggered_at >= ?
        """,
        (since_iso,),
    ).fetchone()
    return int(row[0]) if row else 0


# ---------------------------------------------------------------------------
# Core canary operations
# ---------------------------------------------------------------------------

def spawn_canary(
    conn: sqlite3.Connection,
    token_type: str,
    name: str,
    base_url: str = "http://127.0.0.1:8000",
    base_hostname: str = "canary.local",
) -> dict:
    """Create a new canary token and return spawn metadata.

    Generates a cryptographically random token, inserts a canary_tokens row,
    and returns the token along with the appropriate trap URL or hostname.

    Args:
        conn:          Open SQLite connection.
        token_type:    'http' or 'dns'.
        name:          Human-readable label (operator-controlled, sanitized).
        base_url:      Base URL for HTTP traps (from CANARY_BASE_URL env var).
        base_hostname: Base hostname for DNS traps (from CANARY_BASE_HOSTNAME).

    Returns:
        Dict with keys: id (int), token (str), type (str), name (str),
        trap_url (str for http), trap_hostname (str for dns).

    Raises:
        ValueError: If token_type is not 'http' or 'dns'.
    """
    if token_type not in ("http", "dns"):
        raise ValueError(f"token_type must be 'http' or 'dns', got {token_type!r}")

    safe_name = sanitize_alert_field(name)
    token = secrets.token_urlsafe(16)

    row_id = insert_canary_token(conn, token, token_type, safe_name)
    log.info(
        "Canary spawned: type=%s name=%r token=%s id=%d",
        token_type, safe_name, token, row_id,
    )

    result: dict = {
        "id": row_id,
        "token": token,
        "type": token_type,
        "name": safe_name,
    }

    if token_type == "http":
        trap_url = f"{base_url.rstrip('/')}/canary/hit/{token}"
        result["trap_url"] = trap_url
    else:
        # DNS: attacker queries <token>.<base_hostname>
        trap_hostname = f"{token}.{base_hostname}"
        result["trap_hostname"] = trap_hostname

    return result


def record_hit(
    conn: sqlite3.Connection,
    token: str,
    request_meta: dict,
    enqueue_fn=None,
) -> bool:
    """Record a canary hit and inject a source='canary' alert into the pipeline.

    Looks up the token, increments the trigger counter, and constructs an alert
    row with source='canary'. The alert is inserted directly (not via the
    file tailer) and passed to enqueue_fn so the shared clusterer + triage
    path picks it up.

    All request_meta values are sanitized before storage (attacker-controlled).

    Args:
        conn:        Open SQLite connection.
        token:       The token value from the trap URL.
        request_meta: Dict of request metadata: src_ip, user_agent, path, etc.
        enqueue_fn:  Async callable(cluster) from main.py's _persist_and_enqueue.
                     If None, the alert is written to DB only (useful in tests
                     that don't need live clustering).

    Returns:
        True if a known token was found and the hit recorded, False if unknown.
    """
    row = get_canary_token_by_token(conn, token)
    if row is None:
        log.warning("Canary hit for unknown token: %s", token[:40])
        return False

    # Increment the trigger counter
    increment_canary_trigger(conn, token)

    # Build a sanitized alert record
    src_ip = sanitize_alert_field(str(request_meta.get("src_ip") or "unknown"))
    user_agent = sanitize_alert_field(str(request_meta.get("user_agent") or ""))
    path = sanitize_alert_field(str(request_meta.get("path") or ""))
    canary_name = sanitize_alert_field(str(row["name"]))
    canary_type = sanitize_alert_field(str(row["type"]))

    # Unique alert id — canary: prefix avoids collision with Wazuh IDs
    now_iso = datetime.now(timezone.utc).isoformat()
    alert_id = f"canary:{token}:{now_iso}"

    # The alert is a minimal dict; rule_id 0 is a sentinel for canary hits.
    # Severity 10 (high): a canary hit means something is actively probing.
    raw_alert = {
        "id": alert_id,
        "source": "canary",
        "token": token,
        "canary_name": canary_name,
        "canary_type": canary_type,
        "src_ip": src_ip,
        "user_agent": user_agent,
        "path": path,
        "triggered_at": now_iso,
    }

    # Insert alert row directly (bypasses the file tailer)
    from .models import insert_alert, update_alert_cluster
    insert_alert(
        conn,
        alert_id=alert_id,
        rule_id=0,
        src_ip=src_ip,
        severity=10,
        raw_json=raw_alert,
    )

    # Set source column on the alert row (Phase 2 column, added idempotently)
    with _cursor(conn) as cur:
        cur.execute(
            "UPDATE alerts SET source = 'canary' WHERE id = ?",
            (alert_id,),
        )

    log.info(
        "Canary hit recorded: token=%s src_ip=%s canary=%r",
        token[:16], src_ip, canary_name,
    )

    # Route through the clusterer/triage pipeline if enqueue_fn was provided.
    # enqueue_fn is async; caller is responsible for awaiting it. In practice,
    # main.py's route handler uses asyncio.create_task to avoid blocking the
    # response, since the hit route must return immediately (suspicion avoidance).
    if enqueue_fn is not None:
        import asyncio
        from .cluster import Alert, AlertClusterer
        alert_obj = Alert(
            id=alert_id,
            rule_id=0,
            src_ip=src_ip,
            severity=10,
            raw=raw_alert,
            source="canary",
        )
        # Wrap the enqueue call as a task so the HTTP response is not delayed
        try:
            loop = asyncio.get_event_loop()
            if loop.is_running():
                asyncio.ensure_future(enqueue_fn(alert_obj))
            else:
                loop.run_until_complete(enqueue_fn(alert_obj))
        except RuntimeError:
            # No event loop — test context, skip async dispatch
            pass

    return True


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

from contextlib import contextmanager
from typing import Generator


@contextmanager
def _cursor(conn: sqlite3.Connection) -> Generator[sqlite3.Cursor, None, None]:
    """Context manager: yield cursor, commit on success, rollback on error."""
    cur = conn.cursor()
    try:
        yield cur
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        cur.close()
