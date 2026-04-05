"""
Schema evolution tests (5 tests).

Verifies that init_db safely upgrades a Phase 1 database in place AND produces
the same table shape on a fresh database — with no data loss in either case.
Also exercises the deploy_events CRUD helpers introduced in Phase 2.

Tests:
  1. Phase 1 DB upgrade: build a Phase 1-shaped DB, run init_db, assert
     PRAGMA table_info(alerts) matches the target Phase 2 column set.
  2. Fresh DB shape: run init_db on an empty DB, assert identical column set.
  3. deploy_events round-trip: insert_deploy_event + list_deploy_events.
  4. mark_deploy_reverted: sets reverted_at on the correct row.
  5. Idempotency: calling init_db twice on the same DB is a no-op.

@decision DEC-SCHEMA-002
@title Extend alerts table via idempotent ALTER TABLE, no migration framework
@status accepted
@rationale Tests confirm both upgrade and fresh-install paths land at the same
           PRAGMA table_info shape, and that running init_db twice does not
           raise errors or produce duplicate columns. No Alembic, no migration
           history — just conditional ALTER TABLE checked on every startup.
"""

import sqlite3
import tempfile
import os

import pytest

from agent.models import (
    init_db,
    insert_deploy_event,
    list_deploy_events,
    mark_deploy_reverted,
)

# ---------------------------------------------------------------------------
# Expected Phase 2 column names for the alerts table (order-independent).
# Phase 1 columns are preserved; Phase 2 columns are added alongside them.
# ---------------------------------------------------------------------------

_PHASE1_ALERT_COLUMNS = {"id", "rule_id", "src_ip", "severity", "cluster_id", "ingested_at"}
_PHASE2_NEW_COLUMNS   = {"source", "dest_ip", "protocol", "normalized_severity"}
_TARGET_ALERT_COLUMNS = _PHASE1_ALERT_COLUMNS | _PHASE2_NEW_COLUMNS


# ---------------------------------------------------------------------------
# Helper: build a Phase 1-shaped database (no Phase 2 columns)
# ---------------------------------------------------------------------------

_PHASE1_SCHEMA = """
CREATE TABLE IF NOT EXISTS alerts (
    id TEXT PRIMARY KEY,
    rule_id INTEGER,
    src_ip TEXT,
    severity INTEGER,
    cluster_id TEXT,
    ingested_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

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


def _make_phase1_db(path: str) -> None:
    """Create a Phase 1-shaped SQLite file at path with one pre-existing alert row."""
    conn = sqlite3.connect(path)
    conn.executescript(_PHASE1_SCHEMA)
    conn.execute(
        "INSERT INTO alerts (id, rule_id, src_ip, severity) VALUES (?, ?, ?, ?)",
        ("alert-phase1-001", 5501, "10.0.0.1", 10),
    )
    conn.commit()
    conn.close()


def _column_names(conn: sqlite3.Connection, table: str) -> set[str]:
    """Return the set of column names for a table via PRAGMA table_info."""
    rows = conn.execute(f"PRAGMA table_info({table})").fetchall()
    return {row[1] for row in rows}


# ---------------------------------------------------------------------------
# Test 1: Phase 1 DB upgrade — new columns added, existing data preserved
# ---------------------------------------------------------------------------

def test_phase1_db_upgrade_adds_columns_without_data_loss():
    """init_db on a Phase 1 DB adds the 4 new columns and keeps existing rows."""
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = os.path.join(tmpdir, "upgrade.db")

        # Build Phase 1 DB with a pre-existing alert row
        _make_phase1_db(db_path)

        # Run Phase 2 init_db — this is the upgrade under test
        conn = init_db(db_path)

        try:
            # All target columns must be present
            actual_cols = _column_names(conn, "alerts")
            assert actual_cols == _TARGET_ALERT_COLUMNS, (
                f"Column mismatch.\n  expected: {sorted(_TARGET_ALERT_COLUMNS)}\n"
                f"  actual:   {sorted(actual_cols)}"
            )

            # The pre-existing Phase 1 row must still be there with its values intact
            row = conn.execute(
                "SELECT id, rule_id, src_ip, severity FROM alerts WHERE id = ?",
                ("alert-phase1-001",),
            ).fetchone()
            assert row is not None, "Phase 1 alert row was lost during upgrade"
            assert row["rule_id"] == 5501
            assert row["src_ip"] == "10.0.0.1"
            assert row["severity"] == 10

            # The new column should have its default value on the existing row
            row2 = conn.execute(
                "SELECT source FROM alerts WHERE id = ?",
                ("alert-phase1-001",),
            ).fetchone()
            assert row2["source"] == "wazuh", (
                f"Expected default 'wazuh' for source, got {row2['source']!r}"
            )

        finally:
            conn.close()


# ---------------------------------------------------------------------------
# Test 2: Fresh DB — identical PRAGMA table_info(alerts) shape
# ---------------------------------------------------------------------------

def test_fresh_db_has_same_column_shape():
    """init_db on an empty DB produces the same alerts column set as the upgrade path."""
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = os.path.join(tmpdir, "fresh.db")
        conn = init_db(db_path)
        try:
            actual_cols = _column_names(conn, "alerts")
            assert actual_cols == _TARGET_ALERT_COLUMNS, (
                f"Fresh DB column mismatch.\n  expected: {sorted(_TARGET_ALERT_COLUMNS)}\n"
                f"  actual:   {sorted(actual_cols)}"
            )
        finally:
            conn.close()


# ---------------------------------------------------------------------------
# Test 3: deploy_events insert + list round-trip
# ---------------------------------------------------------------------------

def test_insert_and_list_deploy_events():
    """insert_deploy_event followed by list_deploy_events returns the inserted row."""
    with tempfile.TemporaryDirectory() as tmpdir:
        conn = init_db(os.path.join(tmpdir, "events.db"))
        try:
            event_id = insert_deploy_event(
                conn,
                rule_id=42,
                action="auto-deploy",
                reason="High confidence YARA match",
                actor="orchestrator",
            )
            assert isinstance(event_id, int), "insert_deploy_event should return an int row id"

            # List all events
            rows = list_deploy_events(conn)
            assert len(rows) == 1
            row = rows[0]
            assert row["id"] == event_id
            assert row["rule_id"] == 42
            assert row["action"] == "auto-deploy"
            assert row["reason"] == "High confidence YARA match"
            assert row["actor"] == "orchestrator"
            assert row["deployed_at"] is not None
            assert row["reverted_at"] is None

            # List filtered by rule_id
            rows_filtered = list_deploy_events(conn, rule_id=42)
            assert len(rows_filtered) == 1

            rows_other = list_deploy_events(conn, rule_id=999)
            assert len(rows_other) == 0

        finally:
            conn.close()


# ---------------------------------------------------------------------------
# Test 4: mark_deploy_reverted sets reverted_at
# ---------------------------------------------------------------------------

def test_mark_deploy_reverted_sets_timestamp():
    """mark_deploy_reverted populates reverted_at on the correct row only."""
    with tempfile.TemporaryDirectory() as tmpdir:
        conn = init_db(os.path.join(tmpdir, "revert.db"))
        try:
            id1 = insert_deploy_event(conn, rule_id=10, action="auto-deploy")
            id2 = insert_deploy_event(conn, rule_id=11, action="auto-deploy")

            # Revert only the first event
            mark_deploy_reverted(conn, id1)

            rows = list_deploy_events(conn)
            by_id = {row["id"]: row for row in rows}

            # First event should have reverted_at set
            assert by_id[id1]["reverted_at"] is not None, (
                "reverted_at should be set after mark_deploy_reverted"
            )

            # Second event should remain un-reverted
            assert by_id[id2]["reverted_at"] is None, (
                "reverted_at should be None for the un-reverted event"
            )

        finally:
            conn.close()


# ---------------------------------------------------------------------------
# Test 5: Idempotency — calling init_db twice is a no-op
# ---------------------------------------------------------------------------

def test_init_db_twice_is_idempotent():
    """Calling init_db on the same path twice raises no errors and leaves one copy of each column."""
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = os.path.join(tmpdir, "idempotent.db")

        # First call — creates the DB
        conn1 = init_db(db_path)
        conn1.close()

        # Second call — should be a no-op with no errors
        conn2 = init_db(db_path)
        try:
            actual_cols = _column_names(conn2, "alerts")
            assert actual_cols == _TARGET_ALERT_COLUMNS, (
                "Column set changed after second init_db call"
            )

            # Verify no duplicate column names (SQLite would raise on ALTER TABLE
            # if a column already exists, so this also proves the guard works)
            rows = conn2.execute("PRAGMA table_info(alerts)").fetchall()
            col_names = [row[1] for row in rows]
            assert len(col_names) == len(set(col_names)), (
                "Duplicate column names found after second init_db call"
            )

        finally:
            conn2.close()
