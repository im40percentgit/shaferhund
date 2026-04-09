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
_CLUSTERS_PHASE2_COLUMNS: list[tuple[str, str]] = [
    ("source", "TEXT NOT NULL DEFAULT 'wazuh'"),
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
) -> None:
    """Write AI triage results back to the cluster row."""
    with get_cursor(conn) as cur:
        cur.execute(
            "UPDATE clusters SET ai_severity = ?, ai_analysis = ? WHERE id = ?",
            (ai_severity, ai_analysis, cluster_id),
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
