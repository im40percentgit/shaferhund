"""
SQLite persistence layer for Shaferhund.

Uses stdlib sqlite3 only — no ORM. Schema is the source of truth.
Four tables: alerts, alert_details, clusters, rules.
Raw alert JSON is stored separately (alert_details) to keep the
alerts table lean for indexed queries.

@decision DEC-CLUSTER-001
@title In-memory clusterer with SQLite persistence
@status accepted
@rationale Keeps the hot path (clustering) in memory for speed while
           persisting results durably. SQLite is sufficient for the
           target scale (<100 endpoints). No external DB dependency.
"""

import sqlite3
import json
import logging
from contextlib import contextmanager
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


def init_db(db_path: str) -> sqlite3.Connection:
    """Open (or create) the SQLite database and apply schema.

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
) -> None:
    """Insert or update a cluster record (without AI fields)."""
    with get_cursor(conn) as cur:
        cur.execute(
            """
            INSERT INTO clusters (id, src_ip, rule_id, window_start, window_end, alert_count)
            VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT(id) DO UPDATE SET
                window_end   = excluded.window_end,
                alert_count  = excluded.alert_count
            """,
            (cluster_id, src_ip, rule_id, window_start, window_end, alert_count),
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
