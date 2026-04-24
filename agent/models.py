"""
SQLite persistence layer for Shaferhund.

Uses stdlib sqlite3 only — no ORM. Schema is the source of truth.
Four tables: alerts, alert_details, clusters, rules.
Raw alert JSON is stored separately (alert_details) to keep the
alerts table lean for indexed queries.

Phase 2 additions: multi-source alert columns on `alerts` table
(added via idempotent ALTER TABLE in init_db) and a new `deploy_events`
table for the policy-gated auto-deploy audit trail.

@decision DEC-CLUSTER-001
@title In-memory clusterer with SQLite persistence
@status accepted
@rationale Keeps the hot path (clustering) in memory for speed while
           persisting results durably. SQLite is sufficient for the
           target scale (<100 endpoints). No external DB dependency.

@decision DEC-SCHEMA-002
@title Extend alerts table via idempotent ALTER TABLE, no migration framework
@status accepted
@rationale Phase 1 databases are already deployed. Alembic or any migration
           framework would require a migration script per deployment and adds
           an operational dependency for a solo-dev tool. Instead, init_db
           checks PRAGMA table_info(alerts) on every startup and issues
           ALTER TABLE ADD COLUMN only for columns that are absent. This is
           safe to run repeatedly (idempotent), requires no migration history
           table, and upgrades a Phase 1 DB in place without data loss.
           deploy_events is a new table created with CREATE TABLE IF NOT EXISTS,
           which is already idempotent by definition.
"""

import sqlite3
import json
import logging
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Generator, Optional

log = logging.getLogger(__name__)

SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS alerts (
    id TEXT PRIMARY KEY,
    rule_id INTEGER,
    src_ip TEXT,
    severity INTEGER,
    cluster_id TEXT,
    ingested_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_alerts_cluster ON alerts(cluster_id);
CREATE INDEX IF NOT EXISTS idx_alerts_src_ip  ON alerts(src_ip);
CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts(severity);

CREATE TABLE IF NOT EXISTS alert_details (
    alert_id TEXT PRIMARY KEY REFERENCES alerts(id),
    raw_json TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS clusters (
    id TEXT PRIMARY KEY,
    src_ip TEXT,
    rule_id INTEGER,
    window_start DATETIME,
    window_end DATETIME,
    alert_count INTEGER,
    ai_severity TEXT,
    ai_analysis TEXT,
    source TEXT NOT NULL DEFAULT 'wazuh',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS rules (
    id TEXT PRIMARY KEY,
    cluster_id TEXT REFERENCES clusters(id),
    rule_type TEXT,
    rule_content TEXT,
    syntax_valid BOOLEAN,
    deployed BOOLEAN DEFAULT 0,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
"""

# ---------------------------------------------------------------------------
# Phase 2 schema additions
# ---------------------------------------------------------------------------
#
# New columns for the alerts table.  Each entry is (column_name, full_definition)
# where full_definition is the fragment that follows the column name in ALTER TABLE.
# These are applied by init_db via PRAGMA table_info + conditional ALTER TABLE so
# that Phase 1 databases upgrade in place and fresh databases land at the same shape.
#
_ALERTS_PHASE2_COLUMNS: list[tuple[str, str]] = [
    ("source",             "TEXT NOT NULL DEFAULT 'wazuh'"),
    ("dest_ip",            "TEXT"),
    ("protocol",           "TEXT"),
    ("normalized_severity","TEXT"),
]

# Idempotent additions to the clusters table.  Fresh DBs get the column via
# SCHEMA_SQL above; Phase 1/Wave-A DBs that predate DEC-CLUSTER-002 get it
# via the conditional ALTER TABLE in init_db.
# ai_confidence (Wave C): the orchestrator's confidence score returned by
# finalize_triage, stored for the policy gate's threshold check.
_CLUSTERS_PHASE2_COLUMNS: list[tuple[str, str]] = [
    ("source",        "TEXT NOT NULL DEFAULT 'wazuh'"),
    ("ai_confidence", "REAL"),
]

# deploy_events tracks every auto-deploy and manual-deploy with enough context
# to support one-click undo.  Created with IF NOT EXISTS so it is idempotent
# for both fresh DBs and Phase 1 upgrades.
_DEPLOY_EVENTS_SQL = """
CREATE TABLE IF NOT EXISTS deploy_events (
    id          INTEGER PRIMARY KEY,
    rule_id     INTEGER NOT NULL,
    action      TEXT    NOT NULL,
    reason      TEXT,
    actor       TEXT    NOT NULL DEFAULT 'orchestrator',
    deployed_at TEXT    NOT NULL,
    reverted_at TEXT
);
"""

# Phase 2 Wave C — auto-deploy integration (REQ-P0-P2-006, REQ-P0-P2-007).
# These columns are added to deploy_events idempotently so the dedup query
# in get_recent_deploys can project the fields that should_auto_deploy expects
# without a multi-table join that would be fragile against schema drift.
#
# rule_uuid: the generated rule's TEXT UUID (rules.id) — the existing rule_id
#            column is INTEGER for the legacy recommend_deploy tool path; the
#            auto-deploy path stores the UUID here instead.
# rule_type: 'yara' or 'sigma' — stored at event time so the dedup query
#            doesn't need to chase the rules row (which could be deleted).
# src_ip:    the cluster's source IP — same rationale: stored at event time.
_DEPLOY_EVENTS_WAVE_C_COLUMNS: list[tuple[str, str]] = [
    ("rule_uuid", "TEXT"),
    ("rule_type", "TEXT"),
    ("src_ip",    "TEXT"),
]


# ---------------------------------------------------------------------------
# Phase 3 schema additions — threat_intel table (REQ-P0-P3-005)
# ---------------------------------------------------------------------------
#
# Created with CREATE TABLE IF NOT EXISTS — idempotent for Phase 1/2/2.5
# databases that predate Phase 3 (per DEC-SCHEMA-002).
#
# Columns:
#   indicator      — the raw IOC value (URL, domain, or MD5 hash).
#   indicator_type — 'url', 'domain', or 'md5' (matches URLhaus feed fields).
#   first_seen     — ISO8601 timestamp when first observed by the feed source.
#   last_seen      — ISO8601 timestamp when last observed (updated on refresh).
#   source         — feed name, e.g. 'urlhaus_online'.
#   context_json   — JSON blob with any extra feed metadata (tags, reporter, etc.).
_THREAT_INTEL_SQL = """
CREATE TABLE IF NOT EXISTS threat_intel (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    indicator      TEXT NOT NULL,
    indicator_type TEXT NOT NULL,
    first_seen     TEXT,
    last_seen      TEXT,
    source         TEXT NOT NULL DEFAULT 'urlhaus_online',
    context_json   TEXT
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_threat_intel_indicator
    ON threat_intel(indicator, indicator_type, source);
CREATE INDEX IF NOT EXISTS idx_threat_intel_type
    ON threat_intel(indicator_type);
"""



# ---------------------------------------------------------------------------
# Phase 3 schema additions — canary_tokens table (REQ-P0-P3-004)
# ---------------------------------------------------------------------------
#
# Created with CREATE TABLE IF NOT EXISTS — idempotent for Phase 1/2/2.5/3
# databases (per DEC-SCHEMA-002).
#
# Columns:
#   token             — opaque URL-safe base64 string embedded in trap URL/hostname.
#   type              — 'dns' or 'http'; CHECK constraint enforced at DB level.
#   name              — operator-supplied label for this canary.
#   created_at        — ISO8601 timestamp when the token was spawned.
#   trigger_count     — number of times the trap has been hit (accumulated).
#   last_triggered_at — ISO8601 timestamp of the most recent hit (NULL until first hit).
_CANARY_TOKENS_SQL = """
CREATE TABLE IF NOT EXISTS canary_tokens (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    token             TEXT    NOT NULL UNIQUE,
    type              TEXT    NOT NULL CHECK(type IN ('dns', 'http')),
    name              TEXT    NOT NULL DEFAULT '',
    created_at        TEXT    NOT NULL,
    trigger_count     INTEGER NOT NULL DEFAULT 0,
    last_triggered_at TEXT
);

CREATE INDEX IF NOT EXISTS idx_canary_tokens_token
    ON canary_tokens(token);
CREATE INDEX IF NOT EXISTS idx_canary_tokens_last_triggered
    ON canary_tokens(last_triggered_at);
"""


def init_db(db_path: str) -> sqlite3.Connection:
    """Open (or create) the SQLite database and apply schema.

    Applies the Phase 1 base schema, then idempotently adds Phase 2 columns
    to the alerts table via PRAGMA table_info checks before each ALTER TABLE.
    Creates the deploy_events table with CREATE TABLE IF NOT EXISTS (always safe).

    Returns a connection with WAL mode enabled for concurrent reads.
    Caller is responsible for closing the connection.
    """
    path = Path(db_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(db_path, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    conn.executescript(SCHEMA_SQL)

    # Idempotent Phase 2 column additions — safe for Phase 1 DBs and fresh DBs.
    existing_alert_cols = {
        row[1]
        for row in conn.execute("PRAGMA table_info(alerts)").fetchall()
    }
    for col_name, col_def in _ALERTS_PHASE2_COLUMNS:
        if col_name not in existing_alert_cols:
            conn.execute(
                f"ALTER TABLE alerts ADD COLUMN {col_name} {col_def}"
            )
            log.info("alerts table: added column %s", col_name)

    # Idempotent clusters column additions (DEC-CLUSTER-002).
    existing_cluster_cols = {
        row[1]
        for row in conn.execute("PRAGMA table_info(clusters)").fetchall()
    }
    for col_name, col_def in _CLUSTERS_PHASE2_COLUMNS:
        if col_name not in existing_cluster_cols:
            conn.execute(
                f"ALTER TABLE clusters ADD COLUMN {col_name} {col_def}"
            )
            log.info("clusters table: added column %s", col_name)

    # deploy_events — idempotent by virtue of CREATE TABLE IF NOT EXISTS.
    conn.executescript(_DEPLOY_EVENTS_SQL)

    # Idempotent Wave C column additions to deploy_events (REQ-P0-P2-006).
    existing_deploy_cols = {
        row[1]
        for row in conn.execute("PRAGMA table_info(deploy_events)").fetchall()
    }
    for col_name, col_def in _DEPLOY_EVENTS_WAVE_C_COLUMNS:
        if col_name not in existing_deploy_cols:
            conn.execute(
                f"ALTER TABLE deploy_events ADD COLUMN {col_name} {col_def}"
            )
            log.info("deploy_events table: added column %s", col_name)

    # threat_intel table (Phase 3, REQ-P0-P3-005) — idempotent.
    conn.executescript(_THREAT_INTEL_SQL)

    # canary_tokens table (Phase 3, REQ-P0-P3-004) — idempotent.
    conn.executescript(_CANARY_TOKENS_SQL)

    conn.commit()
    log.info("Database initialised at %s", db_path)
    return conn


@contextmanager
def get_cursor(conn: sqlite3.Connection) -> Generator[sqlite3.Cursor, None, None]:
    """Context manager that yields a cursor and commits/rolls back automatically."""
    cur = conn.cursor()
    try:
        yield cur
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        cur.close()


# ---------------------------------------------------------------------------
# Alert CRUD
# ---------------------------------------------------------------------------

def insert_alert(
    conn: sqlite3.Connection,
    alert_id: str,
    rule_id: int,
    src_ip: str,
    severity: int,
    raw_json: dict,
    cluster_id: Optional[str] = None,
) -> None:
    """Insert an alert and its raw JSON detail. Silently skips duplicates."""
    with get_cursor(conn) as cur:
        cur.execute(
            """
            INSERT OR IGNORE INTO alerts (id, rule_id, src_ip, severity, cluster_id)
            VALUES (?, ?, ?, ?, ?)
            """,
            (alert_id, rule_id, src_ip, severity, cluster_id),
        )
        cur.execute(
            "INSERT OR IGNORE INTO alert_details (alert_id, raw_json) VALUES (?, ?)",
            (alert_id, json.dumps(raw_json)),
        )


def update_alert_cluster(
    conn: sqlite3.Connection, alert_id: str, cluster_id: str
) -> None:
    """Assign a cluster ID to an existing alert row."""
    with get_cursor(conn) as cur:
        cur.execute(
            "UPDATE alerts SET cluster_id = ? WHERE id = ?",
            (cluster_id, alert_id),
        )


# ---------------------------------------------------------------------------
# Cluster CRUD
# ---------------------------------------------------------------------------

def upsert_cluster(
    conn: sqlite3.Connection,
    cluster_id: str,
    src_ip: str,
    rule_id: int,
    window_start: str,
    window_end: str,
    alert_count: int,
    source: str = "wazuh",
) -> None:
    """Insert or update a cluster record (without AI fields).

    The source column was added to the clusters table in Wave A (Phase 2
    skeleton). It identifies which sensor produced the cluster's alerts
    so the dashboard and triage prompt can surface the right context.
    """
    with get_cursor(conn) as cur:
        cur.execute(
            """
            INSERT INTO clusters (id, src_ip, rule_id, window_start, window_end, alert_count, source)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(id) DO UPDATE SET
                window_end   = excluded.window_end,
                alert_count  = excluded.alert_count
            """,
            (cluster_id, src_ip, rule_id, window_start, window_end, alert_count, source),
        )


def update_cluster_ai(
    conn: sqlite3.Connection,
    cluster_id: str,
    ai_severity: str,
    ai_analysis: str,
    ai_confidence: Optional[float] = None,
) -> None:
    """Write AI triage results back to the cluster row.

    ai_confidence is optional for backward compatibility with existing callers
    that do not supply it.  When provided it is persisted for the auto-deploy
    policy gate's confidence threshold check (REQ-P0-P2-006).
    """
    with get_cursor(conn) as cur:
        cur.execute(
            """
            UPDATE clusters
               SET ai_severity = ?, ai_analysis = ?, ai_confidence = ?
             WHERE id = ?
            """,
            (ai_severity, ai_analysis, ai_confidence, cluster_id),
        )


def list_clusters(conn: sqlite3.Connection, limit: int = 50) -> list[sqlite3.Row]:
    """Return clusters ordered newest first."""
    cur = conn.execute(
        "SELECT * FROM clusters ORDER BY created_at DESC LIMIT ?", (limit,)
    )
    return cur.fetchall()


def get_cluster(conn: sqlite3.Connection, cluster_id: str) -> Optional[sqlite3.Row]:
    """Fetch a single cluster by ID."""
    cur = conn.execute("SELECT * FROM clusters WHERE id = ?", (cluster_id,))
    return cur.fetchone()


def get_cluster_alerts(
    conn: sqlite3.Connection, cluster_id: str
) -> list[sqlite3.Row]:
    """Return all alerts belonging to a cluster, newest first."""
    cur = conn.execute(
        """
        SELECT a.*, d.raw_json
        FROM alerts a
        JOIN alert_details d ON d.alert_id = a.id
        WHERE a.cluster_id = ?
        ORDER BY a.ingested_at DESC
        """,
        (cluster_id,),
    )
    return cur.fetchall()


def get_cluster_with_alerts(
    conn: sqlite3.Connection, cluster_id: str
) -> Optional[dict]:
    """Fetch a cluster row and all its member alerts in one call.

    Combines get_cluster + get_cluster_alerts into a single composite dict
    suitable for JSON serialisation by the orchestrator tool handler.

    Returns:
        dict with keys: cluster (all cluster columns as dict) and
        alerts (list of dicts, each with alert + raw_json fields).
        Returns None if the cluster does not exist.
    """
    cluster_row = get_cluster(conn, cluster_id)
    if cluster_row is None:
        return None

    alert_rows = get_cluster_alerts(conn, cluster_id)
    alerts = []
    for row in alert_rows:
        alert = dict(row)
        # raw_json is stored as a JSON string; parse it so callers get a dict.
        raw = alert.pop("raw_json", None)
        if raw:
            try:
                alert["raw"] = json.loads(raw)
            except (json.JSONDecodeError, TypeError):
                alert["raw"] = raw
        alerts.append(alert)

    return {
        "cluster": dict(cluster_row),
        "alerts": alerts,
    }


def get_alerts_by_src_ip(
    conn: sqlite3.Connection, src_ip: str, hours: int = 24
) -> list[dict]:
    """Return alerts for a given src_ip within a recent time window.

    Args:
        conn:   Open SQLite connection.
        src_ip: Source IP address to filter on.
        hours:  How many hours back from now to include. Defaults to 24.

    Returns:
        List of dicts with keys: id, rule_id, src_ip, severity, source,
        cluster_id, ingested_at.  Ordered newest first.
        Returns an empty list when no alerts match.
    """
    rows = conn.execute(
        """
        SELECT id, rule_id, src_ip, severity, source, cluster_id, ingested_at
        FROM alerts
        WHERE src_ip = ?
          AND ingested_at >= datetime('now', ? || ' hours')
        ORDER BY ingested_at DESC
        """,
        (src_ip, f"-{hours}"),
    ).fetchall()
    return [dict(row) for row in rows]


# ---------------------------------------------------------------------------
# Rules CRUD
# ---------------------------------------------------------------------------

def insert_rule(
    conn: sqlite3.Connection,
    rule_id: str,
    cluster_id: str,
    rule_type: str,
    rule_content: str,
    syntax_valid: bool,
) -> None:
    """Insert a generated detection rule."""
    with get_cursor(conn) as cur:
        cur.execute(
            """
            INSERT OR REPLACE INTO rules
                (id, cluster_id, rule_type, rule_content, syntax_valid)
            VALUES (?, ?, ?, ?, ?)
            """,
            (rule_id, cluster_id, rule_type, rule_content, syntax_valid),
        )


def mark_rule_deployed(conn: sqlite3.Connection, rule_id: str) -> None:
    """Mark a rule as deployed to the /rules/ volume."""
    with get_cursor(conn) as cur:
        cur.execute("UPDATE rules SET deployed = 1 WHERE id = ?", (rule_id,))


def get_rules_for_cluster(
    conn: sqlite3.Connection, cluster_id: str
) -> list[sqlite3.Row]:
    """Return all rules associated with a cluster."""
    cur = conn.execute(
        "SELECT * FROM rules WHERE cluster_id = ? ORDER BY created_at DESC",
        (cluster_id,),
    )
    return cur.fetchall()


# ---------------------------------------------------------------------------
# Health / stats
# ---------------------------------------------------------------------------

def get_stats(conn: sqlite3.Connection) -> dict:
    """Return aggregate counts for the /health endpoint."""
    row = conn.execute(
        """
        SELECT
            (SELECT COUNT(*) FROM alerts)   AS total_alerts,
            (SELECT COUNT(*) FROM clusters) AS total_clusters,
            (SELECT COUNT(*) FROM clusters WHERE ai_severity IS NULL) AS pending_triage,
            (SELECT MAX(created_at) FROM clusters WHERE ai_severity IS NOT NULL) AS last_triage
        """
    ).fetchone()
    return dict(row) if row else {}


# ---------------------------------------------------------------------------
# Deploy Events CRUD  (Phase 2 — REQ-P0-P2-007)
# ---------------------------------------------------------------------------

def insert_deploy_event(
    conn: sqlite3.Connection,
    rule_id: int,
    action: str,
    reason: Optional[str] = None,
    actor: str = "orchestrator",
) -> int:
    """Record a deploy lifecycle event and return the new row id.

    Args:
        rule_id: The integer PK of the rule being deployed/skipped/undone.
        action:  One of 'auto-deploy', 'manual-deploy', 'skipped', 'undo-deploy'.
        reason:  Human-readable explanation (optional).
        actor:   Who triggered the event; defaults to 'orchestrator'.

    Returns:
        The newly inserted row id (INTEGER PRIMARY KEY).
    """
    deployed_at = datetime.now(timezone.utc).isoformat()
    with get_cursor(conn) as cur:
        cur.execute(
            """
            INSERT INTO deploy_events (rule_id, action, reason, actor, deployed_at)
            VALUES (?, ?, ?, ?, ?)
            """,
            (rule_id, action, reason, actor, deployed_at),
        )
        return cur.lastrowid


def list_deploy_events(
    conn: sqlite3.Connection,
    rule_id: Optional[int] = None,
    since: Optional[str] = None,
) -> list[sqlite3.Row]:
    """Return deploy events, optionally filtered by rule_id and/or a since timestamp.

    Args:
        rule_id: If given, return only events for this rule.
        since:   ISO8601 string; if given, return only events where
                 deployed_at >= since.

    Returns:
        List of rows ordered by deployed_at descending (newest first).
    """
    clauses: list[str] = []
    params: list = []

    if rule_id is not None:
        clauses.append("rule_id = ?")
        params.append(rule_id)
    if since is not None:
        clauses.append("deployed_at >= ?")
        params.append(since)

    where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
    rows = conn.execute(
        f"SELECT * FROM deploy_events {where} ORDER BY deployed_at DESC",
        params,
    ).fetchall()
    return rows


def mark_deploy_reverted(conn: sqlite3.Connection, deploy_event_id: int) -> None:
    """Set reverted_at to the current UTC time for the given deploy event.

    Idempotent — calling twice sets reverted_at to a newer timestamp but
    does not raise an error.  The undo endpoint always records the most
    recent revert time.

    Args:
        deploy_event_id: The id (INTEGER PRIMARY KEY) of the deploy_events row.
    """
    reverted_at = datetime.now(timezone.utc).isoformat()
    with get_cursor(conn) as cur:
        cur.execute(
            "UPDATE deploy_events SET reverted_at = ? WHERE id = ?",
            (reverted_at, deploy_event_id),
        )


def record_deploy_event(
    conn: sqlite3.Connection,
    rule_id: str,
    action: str,
    reason: Optional[str] = None,
    actor: str = "orchestrator",
    rule_type: Optional[str] = None,
    src_ip: Optional[str] = None,
) -> int:
    """Record an auto-deploy or skip event and return the new row id.

    Extends insert_deploy_event with the Wave C columns (rule_uuid, rule_type,
    src_ip) needed by get_recent_deploys to serve the dedup projection that
    should_auto_deploy expects.  The existing rule_id INTEGER column is set to
    0 for auto-deploy events (the generated rule's identity is in rule_uuid).

    Args:
        rule_id:   The generated rule's TEXT UUID (rules.id).
        action:    'auto-deploy' or 'skipped'.
        reason:    Human-readable explanation — the string returned by
                   should_auto_deploy (e.g. 'ok', 'auto-deploy disabled').
        actor:     Who triggered the event; defaults to 'orchestrator'.
        rule_type: Rule type stored alongside the event for dedup queries.
        src_ip:    Cluster src_ip stored alongside the event for dedup queries.

    Returns:
        The newly inserted row id (INTEGER PRIMARY KEY).
    """
    deployed_at = datetime.now(timezone.utc).isoformat()
    with get_cursor(conn) as cur:
        cur.execute(
            """
            INSERT INTO deploy_events
                (rule_id, action, reason, actor, deployed_at, rule_uuid, rule_type, src_ip)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (0, action, reason, actor, deployed_at, rule_id, rule_type, src_ip),
        )
        return cur.lastrowid


# ---------------------------------------------------------------------------
# Wave D helpers  (Phase 2 — REQ-P0-P2-007 dashboard additions, issue #12)
# ---------------------------------------------------------------------------

def list_clusters_by_source(
    conn: sqlite3.Connection,
    source: Optional[str] = None,
    limit: int = 50,
) -> list[sqlite3.Row]:
    """Return clusters filtered by source, ordered newest first.

    Args:
        conn:   Open SQLite connection.
        source: 'wazuh', 'suricata', 'all', or None.  'all' and None both
                return clusters from every source (pass-through).
        limit:  Maximum rows to return.

    Returns:
        List of sqlite3.Row objects ordered by created_at DESC.
    """
    if source and source != "all":
        rows = conn.execute(
            "SELECT * FROM clusters WHERE source = ? ORDER BY created_at DESC LIMIT ?",
            (source, limit),
        ).fetchall()
    else:
        rows = conn.execute(
            "SELECT * FROM clusters ORDER BY created_at DESC LIMIT ?",
            (limit,),
        ).fetchall()
    return rows


def get_latest_deploy_event(
    conn: sqlite3.Connection,
    rule_id: str,
) -> Optional[sqlite3.Row]:
    """Return the most recent deploy_events row for a given rule UUID, or None.

    Matches against rule_uuid (the TEXT UUID stored by record_deploy_event /
    auto-deploy path).  Used by cluster_detail to surface per-rule deploy status.

    Args:
        conn:    Open SQLite connection.
        rule_id: The TEXT UUID from rules.id.

    Returns:
        The most recent sqlite3.Row from deploy_events, or None if no events.
    """
    row = conn.execute(
        """
        SELECT * FROM deploy_events
        WHERE rule_uuid = ?
        ORDER BY deployed_at DESC
        LIMIT 1
        """,
        (rule_id,),
    ).fetchone()
    return row


def mark_deploy_reverted_by_rule(
    conn: sqlite3.Connection,
    rule_id: str,
    reverted_at: Optional[str] = None,
) -> bool:
    """Mark the most recent auto-deploy event for rule_uuid as reverted.

    This is the undo-deploy path: find the latest 'auto-deploy' row for the
    given rule UUID and stamp reverted_at.  Returns True if a row was updated,
    False if no un-reverted auto-deploy event was found (idempotent / 404 path).

    The existing mark_deploy_reverted(conn, deploy_event_id) is preserved for
    the orchestrator tool path which works by event-id.  This helper works by
    rule UUID so the HTTP undo endpoint doesn't need to do a two-step lookup.

    Args:
        conn:        Open SQLite connection.
        rule_id:     The TEXT UUID from rules.id (deploy_events.rule_uuid).
        reverted_at: ISO8601 timestamp; defaults to now(UTC).

    Returns:
        True if a row was updated, False otherwise.
    """
    ts = reverted_at or datetime.now(timezone.utc).isoformat()
    with get_cursor(conn) as cur:
        cur.execute(
            """
            UPDATE deploy_events
               SET reverted_at = ?
             WHERE id = (
                 SELECT id FROM deploy_events
                  WHERE rule_uuid = ?
                    AND action    = 'auto-deploy'
                    AND reverted_at IS NULL
                  ORDER BY deployed_at DESC
                  LIMIT 1
             )
            """,
            (ts, rule_id),
        )
        return cur.rowcount > 0


def list_deploy_events_paginated(
    conn: sqlite3.Connection,
    limit: int = 50,
    offset: int = 0,
) -> list[sqlite3.Row]:
    """Return deploy events for the audit log page, newest first with pagination.

    Args:
        conn:   Open SQLite connection.
        limit:  Page size (default 50).
        offset: Row offset for pagination.

    Returns:
        List of sqlite3.Row objects ordered by deployed_at DESC.
    """
    rows = conn.execute(
        "SELECT * FROM deploy_events ORDER BY deployed_at DESC LIMIT ? OFFSET ?",
        (limit, offset),
    ).fetchall()
    return rows


def count_deploy_events_since(
    conn: sqlite3.Connection,
    since_ts: float,
    action: Optional[str] = None,
) -> int:
    """Count deploy_events rows with deployed_at >= since_ts, optionally by action.

    Used by the /health endpoint to report 24h deploy/skip/revert counts in O(1)
    without pulling full rows into Python. Timestamps stored as ISO8601 strings
    compare lexicographically correctly because they share the same UTC format.

    Args:
        conn:     Open SQLite connection.
        since_ts: Unix epoch float (e.g. time.time() - 86400). Converted to an
                  ISO8601 string for comparison against the deployed_at TEXT column.
        action:   If given, restrict to rows where action = this value.
                  Pass None to count all actions since since_ts.

    Returns:
        Integer count, 0 when no matching rows exist.
    """
    since_iso = datetime.fromtimestamp(since_ts, tz=timezone.utc).isoformat()

    if action is not None:
        row = conn.execute(
            "SELECT COUNT(*) FROM deploy_events WHERE deployed_at >= ? AND action = ?",
            (since_iso, action),
        ).fetchone()
    else:
        row = conn.execute(
            "SELECT COUNT(*) FROM deploy_events WHERE deployed_at >= ?",
            (since_iso,),
        ).fetchone()
    return int(row[0]) if row else 0


def count_reverted_since(conn: sqlite3.Connection, since_ts: float) -> int:
    """Count deploy_events rows where reverted_at >= since_ts.

    Separate from count_deploy_events_since because reverted_at is a different
    column — set by the undo endpoint, not at deploy time.

    Args:
        conn:     Open SQLite connection.
        since_ts: Unix epoch float.

    Returns:
        Integer count, 0 when no matching rows exist.
    """
    since_iso = datetime.fromtimestamp(since_ts, tz=timezone.utc).isoformat()
    row = conn.execute(
        "SELECT COUNT(*) FROM deploy_events WHERE reverted_at >= ?",
        (since_iso,),
    ).fetchone()
    return int(row[0]) if row else 0


def get_recent_deploys(conn: sqlite3.Connection, window_seconds: int) -> list[dict]:
    """Return successful auto-deploy events within the last window_seconds.

    Projects the fields that should_auto_deploy's dedup check expects:
      rule_type (str), src_ip (str), rule_id (int), deployed_at_ts (float).

    The rule_id in each dict is the cluster's Wazuh rule_id integer, obtained
    by joining deploy_events -> rules -> clusters.  src_ip and rule_type are
    stored directly on deploy_events (Wave C columns) to avoid fragile joins
    if the rules row is later deleted.

    Only events with action='auto-deploy' are returned — skipped events are
    not relevant for dedup.

    Args:
        conn:           Open SQLite connection.
        window_seconds: How many seconds back from now to include.

    Returns:
        List of dicts with keys: rule_type, src_ip, rule_id, deployed_at_ts.
        Empty list when no matching events exist.
    """
    rows = conn.execute(
        """
        SELECT
            de.rule_type,
            de.src_ip,
            COALESCE(cl.rule_id, 0)             AS rule_id,
            strftime('%s', de.deployed_at)       AS deployed_at_epoch
        FROM deploy_events de
        LEFT JOIN rules    r  ON r.id          = de.rule_uuid
        LEFT JOIN clusters cl ON cl.id         = r.cluster_id
        WHERE de.action      = 'auto-deploy'
          AND de.deployed_at >= datetime('now', ? || ' seconds')
        ORDER BY de.deployed_at DESC
        """,
        (f"-{window_seconds}",),
    ).fetchall()

    result = []
    for row in rows:
        result.append({
            "rule_type":      row["rule_type"],
            "src_ip":         row["src_ip"],
            "rule_id":        row["rule_id"],
            "deployed_at_ts": float(row["deployed_at_epoch"] or 0),
        })
    return result


# ---------------------------------------------------------------------------
# Threat Intel CRUD  (Phase 3 — REQ-P0-P3-005)
# ---------------------------------------------------------------------------

def insert_threat_intel(
    conn: sqlite3.Connection,
    indicator: str,
    indicator_type: str,
    first_seen: Optional[str] = None,
    last_seen: Optional[str] = None,
    source: str = "urlhaus_online",
    context_json: Optional[str] = None,
) -> None:
    """Insert or refresh a threat-intel indicator row.

    Uses INSERT OR REPLACE against the unique index on (indicator, indicator_type,
    source) so repeated feed refreshes update last_seen without creating duplicates.

    Args:
        conn:           Open SQLite connection.
        indicator:      The raw IOC value (URL, domain, or MD5 hash).
        indicator_type: 'url', 'domain', or 'md5'.
        first_seen:     ISO8601 string from the feed. None if not provided.
        last_seen:      ISO8601 string from the feed. None if not provided.
        source:         Feed name; defaults to 'urlhaus_online'.
        context_json:   JSON string with extra feed metadata.
    """
    with get_cursor(conn) as cur:
        cur.execute(
            """
            INSERT INTO threat_intel
                (indicator, indicator_type, first_seen, last_seen, source, context_json)
            VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT(indicator, indicator_type, source) DO UPDATE SET
                last_seen    = excluded.last_seen,
                context_json = excluded.context_json
            """,
            (indicator, indicator_type, first_seen, last_seen, source, context_json),
        )


def get_threat_intel_matches(
    conn: sqlite3.Connection,
    value: str,
) -> list[dict]:
    """Return all threat_intel rows whose indicator matches value (exact, case-insensitive).

    Queries all indicator_type columns for the same value so callers don't need to
    know the type upfront. URL lookups should be exact; MD5 lookups are inherently
    exact because hashes are fixed-length strings.

    Args:
        conn:  Open SQLite connection.
        value: The indicator value to look up (URL, domain, or MD5 hash).

    Returns:
        List of dicts — each dict has keys: id, indicator, indicator_type, first_seen,
        last_seen, source, context_json. Empty list when no match.
    """
    rows = conn.execute(
        "SELECT * FROM threat_intel WHERE LOWER(indicator) = LOWER(?)",
        (value,),
    ).fetchall()
    return [dict(row) for row in rows]


def count_threat_intel_records(conn: sqlite3.Connection) -> int:
    """Return the total number of rows in the threat_intel table.

    Used by the /health endpoint to report indicator count without pulling rows.

    Args:
        conn: Open SQLite connection.

    Returns:
        Integer row count, 0 if the table is empty.
    """
    row = conn.execute("SELECT COUNT(*) FROM threat_intel").fetchone()
    return int(row[0]) if row else 0
