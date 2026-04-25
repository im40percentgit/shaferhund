"""
SQLite persistence layer for Shaferhund.

Uses stdlib sqlite3 only — no ORM. Schema is the source of truth.
Four tables: alerts, alert_details, clusters, rules.
Raw alert JSON is stored separately (alert_details) to keep the
alerts table lean for indexed queries.

Phase 2 additions: multi-source alert columns on `alerts` table
(added via idempotent ALTER TABLE in init_db) and a new `deploy_events`
table for the policy-gated auto-deploy audit trail.

Phase 4 additions: weighted_score column on `posture_runs` and weight
column on `posture_test_results`, both added via the idempotent
_POSTURE_RUNS_PHASE4_COLUMNS pattern (DEC-SCHEMA-002). New helper
compute_posture_weighted_score_for_run() computes the weighted average.

Phase 4 Wave B additions: attack_recommendations table (DEC-RECOMMEND-001,
REQ-P0-P4-001/002). Created with CREATE TABLE IF NOT EXISTS — idempotent on
all prior Phase DBs (DEC-SCHEMA-002). CRUD helpers:
  insert_attack_recommendation, get_attack_recommendation,
  list_pending_attack_recommendations, mark_attack_recommendation_executed,
  count_pending_attack_recommendations.

Phase 5 Wave A1 additions: cloudtrail_progress table (REQ-P0-P5-001,
DEC-CLOUD-002, DEC-CLOUD-011). One row per (bucket, prefix) holds the
S3 StartAfter cursor for the CloudTrail poller — restart-safe, audit-friendly.
CRUD helpers: get_cloudtrail_cursor, update_cloudtrail_cursor,
insert_cloudtrail_alert.

@decision DEC-SCHEMA-P6-001
@title Phase 6 users + user_tokens tables via idempotent CREATE TABLE IF NOT EXISTS
@status accepted
@rationale Six new tables in Phase 6 (users, user_tokens, audit_log, fleet_agents,
           fleet_checkins, rule_tags). This Wave A1 issue adds users + user_tokens.
           Both use CREATE TABLE IF NOT EXISTS so a Phase 5 DB upgrades in place
           without data loss or a migration framework (DEC-SCHEMA-002 pattern).
           role CHECK constraint and UNIQUE constraints enforce integrity at the
           DB layer, not only at the application layer.

@decision DEC-CLOUD-011
@title cloudtrail_progress uses CREATE TABLE IF NOT EXISTS — idempotent for all prior DBs
@status accepted
@rationale Follows DEC-SCHEMA-002 pattern. A Phase 4-baseline DB upgraded to
           Phase 5 gets the new table on first startup without data loss or
           migration scripts. The UNIQUE(bucket, prefix) constraint ensures
           one cursor row per configured (bucket, prefix) pair regardless of
           how many times init_db runs.

@decision DEC-CLOUD-005
@title cloud_audit_findings detector rules are code-resident, not DB/env-loaded
@status accepted
@rationale The set of detected patterns (root login, MFA disable, IAM user
           create, etc.) is reviewed at code-review time in agent/cloud_findings.py.
           Storing rules in DB or .env would let an attacker who compromises
           the environment silently disable detections. Code-resident rules
           are immutable at runtime — same reasoning as DEC-RECOMMEND-002 for
           DESTRUCTIVE_TECHNIQUES. New patterns require a PR, which is auditable.

@decision DEC-POSTURE-003
@title Weighted posture score — declarative YAML weights, additive alongside flat score
@status accepted
@rationale The flat score (passes / total_tests) treats all MITRE techniques equally.
           Phase 4 adds a parallel weighted score (sum(weight * passed) / sum(weight))
           that reflects operator-assigned criticality from atomic_tests.yaml.
           Both scores persist on posture_runs and expose on /health so Phase 3
           callers are fully backwards-compatible. Weights are declared in YAML
           (not judged by Claude at runtime) for determinism: the same test set
           produces the same weighted score every run regardless of model version,
           token availability, or hourly budget. Claude-judged adaptive weights
           are a future enhancement (saves an LLM call per scoring run here).

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


# ---------------------------------------------------------------------------
# Phase 3 schema additions — posture_runs + posture_test_results tables
# (REQ-P0-P3-001, REQ-P0-P3-003)
# ---------------------------------------------------------------------------
#
# posture_runs tracks each Atomic Red Team posture evaluation run.
# posture_test_results tracks per-test fired_at timestamps for the scoring join.
# Both created with CREATE TABLE IF NOT EXISTS — idempotent for all prior DBs
# (DEC-SCHEMA-002).
#
# posture_runs columns:
#   started_at     — ISO8601 timestamp when run_batch() was called.
#   finished_at    — ISO8601 timestamp when all tests completed (NULL while running).
#   technique_ids  — JSON array of technique IDs tested (e.g. ["T1059.003", "T1053.003"]).
#   total_tests    — number of tests in the batch.
#   passes         — number of tests that scored as a pass (cluster + deployed rule found).
#   score          — passes / total_tests (REAL, 0.0–1.0).
#   status         — 'running' | 'complete' | 'failed'.
_POSTURE_RUNS_SQL = """
CREATE TABLE IF NOT EXISTS posture_runs (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    started_at     TEXT    NOT NULL,
    finished_at    TEXT,
    technique_ids  TEXT    NOT NULL DEFAULT '[]',
    total_tests    INTEGER NOT NULL DEFAULT 0,
    passes         INTEGER NOT NULL DEFAULT 0,
    score          REAL    NOT NULL DEFAULT 0.0,
    status         TEXT    NOT NULL DEFAULT 'running'
                           CHECK(status IN ('running', 'complete', 'failed'))
);

CREATE INDEX IF NOT EXISTS idx_posture_runs_started_at
    ON posture_runs(started_at DESC);
CREATE INDEX IF NOT EXISTS idx_posture_runs_status
    ON posture_runs(status);
"""

# posture_test_results: per-test row recording fired_at for the scoring join.
# Must be defined before init_db references it.
_POSTURE_TEST_RESULTS_SQL = """
CREATE TABLE IF NOT EXISTS posture_test_results (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id       INTEGER NOT NULL REFERENCES posture_runs(id),
    technique_id TEXT    NOT NULL,
    test_name    TEXT    NOT NULL DEFAULT '',
    fired_at     TEXT    NOT NULL,
    exit_code    INTEGER,
    output       TEXT,
    passed       INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_ptr_run_id ON posture_test_results(run_id);
CREATE INDEX IF NOT EXISTS idx_ptr_fired_at ON posture_test_results(fired_at);
"""


# ---------------------------------------------------------------------------
# Phase 4 schema additions — weighted posture score (REQ-P0-P4-003)
# ---------------------------------------------------------------------------
#
# Both columns are added idempotently via PRAGMA table_info() gating
# (DEC-SCHEMA-002) so a Phase 3 DB upgrades in place without data loss.
#
# posture_runs.weighted_score  — sum(weight * passed) / sum(weight), 0.0–1.0.
#   DEFAULT 0.0 so existing rows remain valid after the ALTER TABLE.
#
# posture_test_results.weight  — per-test importance weight from atomic_tests.yaml.
#   DEFAULT 1 so existing rows contribute equally until re-scored with real weights.
_POSTURE_RUNS_PHASE4_COLUMNS: list[tuple[str, str]] = [
    ("weighted_score", "REAL NOT NULL DEFAULT 0.0"),
]

_POSTURE_TEST_RESULTS_PHASE4_COLUMNS: list[tuple[str, str]] = [
    ("weight", "INTEGER NOT NULL DEFAULT 1"),
]


# ---------------------------------------------------------------------------
# Phase 4 schema additions — slo_breaches table (REQ-P0-P4-005)
# ---------------------------------------------------------------------------
#
# slo_breaches tracks each SLO breach session. Idempotency relies on the
# single open row constraint: at most one row has resolved_at IS NULL at
# any time. A breach is "open" when resolved_at is NULL.
#
# Columns:
#   started_at     — ISO8601 timestamp when breach was first detected.
#   resolved_at    — ISO8601 timestamp when score recovered (NULL while open).
#   threshold      — The configured SLO threshold at breach time.
#   breach_score   — The posture score that triggered the breach.
#   posture_run_id — FK to posture_runs.id (the run that triggered the breach).
#   webhook_fired  — 0=not attempted, 1=fired OK, -1=fire failed (DEC-SLO-002).
#   webhook_status — HTTP status code from the webhook attempt (NULL if no
#                    attempt or network error).
#   notes          — Optional operator notes.
#
# DEC-SLO-001: one row per breach session. The evaluator checks resolved_at
# IS NULL before opening a new breach — this is the idempotency guard.
# DEC-SCHEMA-002: CREATE TABLE IF NOT EXISTS is idempotent for Phase 4 DBs
# (post-#43) and any earlier DB being upgraded.
_SLO_BREACHES_SQL = """
CREATE TABLE IF NOT EXISTS slo_breaches (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    started_at      TEXT    NOT NULL,
    resolved_at     TEXT,
    threshold       REAL    NOT NULL,
    breach_score    REAL    NOT NULL,
    posture_run_id  INTEGER NOT NULL REFERENCES posture_runs(id),
    webhook_fired   INTEGER NOT NULL DEFAULT 0,
    webhook_status  INTEGER,
    notes           TEXT
);

CREATE INDEX IF NOT EXISTS idx_slo_breaches_resolved_at
    ON slo_breaches(resolved_at);
"""


# ---------------------------------------------------------------------------
# Phase 4 Wave B schema additions — attack_recommendations table
# (REQ-P0-P4-001, REQ-P0-P4-002)
# ---------------------------------------------------------------------------
#
# attack_recommendations: one row per Claude-generated recommendation.
# Claude writes rows via the recommend_attack tool handler (status='pending').
# Operator approval flows through POST /recommendations/{id}/execute which
# calls agent.recommendations.execute_recommendation() and transitions to
# status='executed'. Rejection (operator declines) sets status='rejected'.
# Expiration (future: TTL sweep) sets status='expired'.
#
# DEC-RECOMMEND-001: Claude's handler ONLY writes status='pending'. Execution
#   is a separate operator-gated HTTP action, never triggered automatically.
# DEC-SCHEMA-002: CREATE TABLE IF NOT EXISTS — idempotent for all prior DBs.
_ATTACK_RECOMMENDATIONS_SQL = """
CREATE TABLE IF NOT EXISTS attack_recommendations (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    cluster_id      TEXT,
    technique_id    TEXT    NOT NULL,
    reason          TEXT    NOT NULL,
    severity        TEXT    NOT NULL CHECK(severity IN ('Low','Medium','High','Critical')),
    status          TEXT    NOT NULL DEFAULT 'pending'
                            CHECK(status IN ('pending','executed','rejected','expired')),
    created_at      TEXT    NOT NULL,
    executed_at     TEXT,
    posture_run_id  INTEGER REFERENCES posture_runs(id),
    notes           TEXT
);

CREATE INDEX IF NOT EXISTS idx_attack_recommendations_status
    ON attack_recommendations(status);
"""


# ---------------------------------------------------------------------------
# Phase 5 Wave A1 schema additions — cloudtrail_progress table
# (REQ-P0-P5-001, DEC-CLOUD-002, DEC-CLOUD-011)
# ---------------------------------------------------------------------------
#
# cloudtrail_progress holds a restart-safe cursor for the S3 poller.
# One row per (bucket, prefix) pair. The poller reads last_object_key,
# passes it as StartAfter to list_objects_v2, and writes the new value
# after each successful batch. Survives restarts without re-ingesting
# already-processed objects.
#
# DEC-CLOUD-002: cursor-in-DB, not in-memory. A restart mid-poll does
#   not re-process objects already consumed. Same shape as slo_breaches
#   and deploy_events — consistency over convenience.
# DEC-CLOUD-011: CREATE TABLE IF NOT EXISTS — idempotent for all prior
#   Phase DBs (DEC-SCHEMA-002 pattern).
#
# Columns:
#   bucket          — S3 bucket name (part of the unique key).
#   prefix          — Key prefix within the bucket (part of the unique key).
#   last_object_key — The S3 object key of the last fully consumed object.
#                     NULL means "start from the beginning of the prefix."
#   last_event_ts   — ISO-8601 timestamp of the last parsed event (informational;
#                     used for /health lag_seconds computation in Wave A3).
#   updated_at      — ISO-8601 timestamp of the last cursor write.
_CLOUDTRAIL_PROGRESS_SQL = """
CREATE TABLE IF NOT EXISTS cloudtrail_progress (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    bucket          TEXT    NOT NULL,
    prefix          TEXT    NOT NULL,
    last_object_key TEXT,
    last_event_ts   TEXT,
    updated_at      TEXT    NOT NULL,
    UNIQUE(bucket, prefix)
);
"""


# ---------------------------------------------------------------------------
# Phase 5 Wave A2 schema additions — cloud_audit_findings table
# (REQ-P0-P5-005, DEC-CLOUD-005)
# ---------------------------------------------------------------------------
#
# cloud_audit_findings captures deterministic detector hits on CloudTrail
# events. One row per (alert_id, rule_name) finding — alert_id is the FK
# to alerts.id (a TEXT UUID from insert_cloudtrail_alert).
#
# DEC-CLOUD-005: detection rules are code-resident in agent/cloud_findings.py,
#   not loaded from env or DB. Same rationale as DEC-RECOMMEND-002 for
#   DESTRUCTIVE_TECHNIQUES — reviewers see what fires; env-var compromise
#   cannot disable detections.
# DEC-SCHEMA-002: CREATE TABLE IF NOT EXISTS — idempotent for all prior DBs.
#
# Columns:
#   alert_id     — FK to alerts.id (TEXT UUID from insert_cloudtrail_alert).
#   rule_name    — Detector rule that fired (e.g. 'root_console_login').
#   rule_severity — 'Low'|'Medium'|'High'|'Critical' — CHECK constraint.
#   title        — Human-readable title with interpolated fields.
#   description  — Free-form description of why this finding matters.
#   principal    — ARN or username of the IAM principal involved.
#   src_ip       — Source IP from the CloudTrail event.
#   event_name   — CloudTrail eventName (e.g. 'ConsoleLogin').
#   event_source — CloudTrail eventSource (e.g. 'signin.amazonaws.com').
#   detected_at  — UTC ISO-8601 timestamp when the finding was created.
#   raw_event    — Full raw CloudTrail event JSON (for operator drill-down).
_CLOUD_AUDIT_FINDINGS_SQL = """
CREATE TABLE IF NOT EXISTS cloud_audit_findings (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    alert_id        TEXT    REFERENCES alerts(id),
    rule_name       TEXT    NOT NULL,
    rule_severity   TEXT    NOT NULL CHECK(rule_severity IN ('Low','Medium','High','Critical')),
    title           TEXT    NOT NULL,
    description     TEXT    NOT NULL,
    principal       TEXT,
    src_ip          TEXT,
    event_name      TEXT,
    event_source    TEXT,
    detected_at     TEXT    NOT NULL,
    raw_event       TEXT
);

CREATE INDEX IF NOT EXISTS idx_cloud_audit_findings_detected_at
    ON cloud_audit_findings(detected_at DESC);
CREATE INDEX IF NOT EXISTS idx_cloud_audit_findings_severity
    ON cloud_audit_findings(rule_severity);
"""


# ---------------------------------------------------------------------------
# Phase 6 Wave A1 schema additions — users + user_tokens tables
# (REQ-P0-P6-003, DEC-AUTH-P6-001, DEC-SCHEMA-P6-001)
# ---------------------------------------------------------------------------
#
# users: one row per named operator/service account.
#   password_hash  — Argon2id encoded string (DEC-AUTH-P6-001). Never the raw
#                    password. The hash includes salt + parameters.
#   role           — CHECK constraint to (admin, operator, viewer). The set of
#                    valid roles is code-resident (DEC-AUTH-P6-002).
#   disabled       — integer boolean (0/1). Disabled users cannot authenticate
#                    even with a valid token. Single auth gate — is_active was
#                    dropped (see #69 follow-up) to eliminate drift risk.
#
# user_tokens: one row per issued bearer token.
#   token_hash     — SHA-256 hex of the raw bearer token. The raw token is
#                    shown once at creation and not stored (DEC-AUTH-P6-003).
#   name           — operator-supplied label (e.g. 'fleet-agent-nyc').
#   expires_at     — NULL means never expires.
#   revoked_at     — NULL means active; set to revocation timestamp on revoke.
#
# Both tables use CREATE TABLE IF NOT EXISTS — idempotent for Phase 5 DBs
# upgrading to Phase 6 (DEC-SCHEMA-002, DEC-SCHEMA-P6-001).
#
# @decision DEC-SCHEMA-P6-001
# @title Six new Phase 6 tables via idempotent CREATE TABLE IF NOT EXISTS
# @status accepted
# @rationale Follows the DEC-SCHEMA-002 pattern. No migration framework.
#            Phase 5 databases upgrade in place without data loss. Each table
#            is created via init_db on first startup after the Phase 6 upgrade.

_USERS_SQL = """
CREATE TABLE IF NOT EXISTS users (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    username        TEXT    NOT NULL UNIQUE,
    password_hash   TEXT    NOT NULL,
    role            TEXT    NOT NULL DEFAULT 'viewer'
                            CHECK(role IN ('admin','operator','viewer')),
    created_at      TEXT    NOT NULL,
    last_login_at   TEXT,
    disabled        INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);
"""

_USER_TOKENS_SQL = """
CREATE TABLE IF NOT EXISTS user_tokens (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id         INTEGER NOT NULL REFERENCES users(id),
    token_hash      TEXT    NOT NULL UNIQUE,
    name            TEXT    NOT NULL,
    created_at      TEXT    NOT NULL,
    last_used_at    TEXT,
    expires_at      TEXT,
    revoked_at      TEXT
);

CREATE INDEX IF NOT EXISTS idx_user_tokens_token_hash ON user_tokens(token_hash);
CREATE INDEX IF NOT EXISTS idx_user_tokens_user_id    ON user_tokens(user_id);
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

    # posture_runs table (Phase 3, REQ-P0-P3-001) — idempotent.
    conn.executescript(_POSTURE_RUNS_SQL)

    # posture_test_results table (Phase 3, REQ-P0-P3-003) — idempotent.
    conn.executescript(_POSTURE_TEST_RESULTS_SQL)

    # Phase 4: weighted_score column on posture_runs (REQ-P0-P4-003).
    existing_posture_run_cols = {
        row[1]
        for row in conn.execute("PRAGMA table_info(posture_runs)").fetchall()
    }
    for col_name, col_def in _POSTURE_RUNS_PHASE4_COLUMNS:
        if col_name not in existing_posture_run_cols:
            conn.execute(
                f"ALTER TABLE posture_runs ADD COLUMN {col_name} {col_def}"
            )
            log.info("posture_runs table: added column %s", col_name)

    # Phase 4: weight column on posture_test_results (REQ-P0-P4-003).
    existing_posture_tr_cols = {
        row[1]
        for row in conn.execute("PRAGMA table_info(posture_test_results)").fetchall()
    }
    for col_name, col_def in _POSTURE_TEST_RESULTS_PHASE4_COLUMNS:
        if col_name not in existing_posture_tr_cols:
            conn.execute(
                f"ALTER TABLE posture_test_results ADD COLUMN {col_name} {col_def}"
            )
            log.info("posture_test_results table: added column %s", col_name)

    # Phase 4: slo_breaches table (REQ-P0-P4-005) — idempotent via IF NOT EXISTS.
    conn.executescript(_SLO_BREACHES_SQL)

    # Phase 4 Wave B: attack_recommendations table (REQ-P0-P4-001/002) — idempotent.
    conn.executescript(_ATTACK_RECOMMENDATIONS_SQL)

    # Phase 5 Wave A1: cloudtrail_progress table (REQ-P0-P5-001, DEC-CLOUD-011).
    conn.executescript(_CLOUDTRAIL_PROGRESS_SQL)

    # Phase 5 Wave A2: cloud_audit_findings table (REQ-P0-P5-005, DEC-CLOUD-005).
    conn.executescript(_CLOUD_AUDIT_FINDINGS_SQL)

    # Phase 6 Wave A1: users table (REQ-P0-P6-003, DEC-SCHEMA-P6-001).
    conn.executescript(_USERS_SQL)

    # Phase 6 Wave A1: user_tokens table (REQ-P0-P6-003, DEC-SCHEMA-P6-001).
    conn.executescript(_USER_TOKENS_SQL)

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


# ---------------------------------------------------------------------------
# Posture Runs CRUD  (Phase 3 — REQ-P0-P3-001)
# ---------------------------------------------------------------------------

def insert_posture_run(
    conn: sqlite3.Connection,
    started_at: str,
    technique_ids: list,
    total_tests: int,
) -> int:
    """Insert a new posture_runs row with status='running' and return the row id.

    Called at the start of run_batch() before any tests execute.

    Args:
        conn:          Open SQLite connection.
        started_at:    ISO8601 timestamp when the run began.
        technique_ids: List of technique ID strings being tested.
        total_tests:   Total number of tests in this batch.

    Returns:
        The INTEGER PRIMARY KEY of the new row.
    """
    import json as _json
    with get_cursor(conn) as cur:
        cur.execute(
            """
            INSERT INTO posture_runs
                (started_at, technique_ids, total_tests, passes, score, status)
            VALUES (?, ?, ?, 0, 0.0, 'running')
            """,
            (started_at, _json.dumps(technique_ids), total_tests),
        )
        return cur.lastrowid


def update_posture_run(
    conn: sqlite3.Connection,
    run_id: int,
    finished_at: str,
    passes: int,
    score: float,
    status: str,
    weighted_score: float = 0.0,
) -> None:
    """Update a posture_runs row with final results.

    Called after run_batch() completes (successfully or with failures).
    Phase 4 adds weighted_score (REQ-P0-P4-003) alongside the existing flat
    score. The parameter defaults to 0.0 for backwards compatibility with any
    Phase 3 callers that don't supply it.

    Args:
        conn:           Open SQLite connection.
        run_id:         The posture_runs.id to update.
        finished_at:    ISO8601 timestamp when the run completed.
        passes:         Number of tests that scored as a pass.
        score:          passes / total_tests (flat, 0.0–1.0).
        status:         'complete' or 'failed'.
        weighted_score: sum(weight*passed)/sum(weight) (0.0–1.0). Default 0.0.
    """
    with get_cursor(conn) as cur:
        cur.execute(
            """
            UPDATE posture_runs
               SET finished_at    = ?,
                   passes         = ?,
                   score          = ?,
                   weighted_score = ?,
                   status         = ?
             WHERE id = ?
            """,
            (finished_at, passes, score, weighted_score, status, run_id),
        )


def get_posture_run(
    conn: sqlite3.Connection,
    run_id: int,
) -> Optional[sqlite3.Row]:
    """Return a single posture_runs row by id, or None.

    Args:
        conn:   Open SQLite connection.
        run_id: The posture_runs.id to fetch.

    Returns:
        sqlite3.Row or None.
    """
    return conn.execute(
        "SELECT * FROM posture_runs WHERE id = ?",
        (run_id,),
    ).fetchone()


def get_latest_posture_run(conn: sqlite3.Connection) -> Optional[sqlite3.Row]:
    """Return the most recently started posture_runs row, or None if no runs exist.

    Used by /health to surface last_score and last_run_at.

    Args:
        conn: Open SQLite connection.

    Returns:
        sqlite3.Row (most recent row) or None.
    """
    return conn.execute(
        "SELECT * FROM posture_runs ORDER BY started_at DESC LIMIT 1",
    ).fetchone()


def list_posture_runs(
    conn: sqlite3.Connection,
    limit: int = 50,
    status: Optional[str] = None,
) -> list[sqlite3.Row]:
    """Return posture_runs rows, newest first, optionally filtered by status.

    Args:
        conn:   Open SQLite connection.
        limit:  Maximum rows to return.
        status: If given, restrict to rows with this status value.

    Returns:
        List of sqlite3.Row objects.
    """
    if status is not None:
        return conn.execute(
            "SELECT * FROM posture_runs WHERE status = ? ORDER BY started_at DESC LIMIT ?",
            (status, limit),
        ).fetchall()
    return conn.execute(
        "SELECT * FROM posture_runs ORDER BY started_at DESC LIMIT ?",
        (limit,),
    ).fetchall()


def compute_posture_score_for_run(
    conn: sqlite3.Connection,
    run_id: int,
) -> dict:
    """Compute the posture score for a completed run via a SQL join.

    Scoring rule (DEC-POSTURE-001):
      A test "passes" when:
        1. The test's fired_at timestamp falls inside a cluster's time window
           (window_start <= fired_at <= window_end), AND
        2. That cluster has at least one rule with deployed=1.

    The join is done entirely in SQL to avoid pulling large rowsets into Python.
    The posture_runs row is updated in place with the computed passes and score.

    Args:
        conn:   Open SQLite connection.
        run_id: The posture_runs.id to score.

    Returns:
        Dict with keys: run_id, total_tests, passes, score.

    @decision DEC-POSTURE-001
    @title Posture pass = cluster window overlap AND deployed rule — pure SQL join
    @status accepted
    @rationale Implementing the scoring in SQL keeps it O(n log n) via indexes
               rather than O(n*m) via Python-side nested loops. The join touches
               posture_test_results (per-test fired_at), clusters (window bounds),
               and rules (deployed flag). No Python-side filtering on large rowsets.
               Edge cases (no cluster, cluster with no deployed rule) naturally
               produce 0 passes from the LEFT JOIN returning NULLs.
    """
    # Fetch the run to get total_tests
    run_row = get_posture_run(conn, run_id)
    if run_row is None:
        return {"run_id": run_id, "total_tests": 0, "passes": 0, "score": 0.0}

    total_tests = run_row["total_tests"]
    if total_tests == 0:
        return {"run_id": run_id, "total_tests": 0, "passes": 0, "score": 0.0}

    # Count passing tests: fired_at inside a cluster window AND that cluster
    # has a deployed rule. Uses posture_test_results joined to clusters+rules.
    row = conn.execute(
        """
        SELECT COUNT(DISTINCT ptr.id) AS passes
          FROM posture_test_results ptr
          JOIN clusters cl
            ON ptr.fired_at >= cl.window_start
           AND ptr.fired_at <= cl.window_end
          JOIN rules r
            ON r.cluster_id = cl.id
           AND r.deployed    = 1
         WHERE ptr.run_id = ?
        """,
        (run_id,),
    ).fetchone()

    passes = int(row["passes"]) if row else 0
    score = passes / total_tests if total_tests > 0 else 0.0

    # Persist the computed values back to posture_runs
    with get_cursor(conn) as cur:
        cur.execute(
            "UPDATE posture_runs SET passes = ?, score = ? WHERE id = ?",
            (passes, score, run_id),
        )

    return {"run_id": run_id, "total_tests": total_tests, "passes": passes, "score": score}


def compute_posture_weighted_score_for_run(
    conn: sqlite3.Connection,
    run_id: int,
) -> float:
    """Compute the weighted posture score for a completed run.

    Weighted scoring rule (REQ-P0-P4-003, DEC-POSTURE-003):
      weighted_score = SUM(ptr.weight * pass_flag) / SUM(ptr.weight)

    where pass_flag=1 when the test's fired_at falls inside a cluster window
    that has at least one deployed rule (same join condition as the flat score),
    and pass_flag=0 otherwise.

    The weight per test is stored in posture_test_results.weight at insert time
    (from atomic_tests.yaml, default 1). The SQL aggregation is done entirely
    in SQL to avoid pulling rowsets into Python (DEC-POSTURE-001 pattern).

    Divide-by-zero guard: returns 0.0 when SUM(weight) == 0 (e.g. all tests
    have weight=0, or no test_results rows exist for this run_id).

    This function does NOT update posture_runs — the caller (run_batch via
    compute_posture_score_for_run flow) controls persistence. Call
    update_posture_run(..., weighted_score=...) after this returns.

    Args:
        conn:   Open SQLite connection.
        run_id: The posture_runs.id to score.

    Returns:
        Float in [0.0, 1.0]. Returns 0.0 on divide-by-zero.
    """
    # SUM(weight * 1) for passing tests / SUM(weight) for all tests in run.
    # A test passes when fired_at is inside a cluster window AND that cluster
    # has a deployed rule. Tests with no matching cluster/rule contribute 0
    # to the numerator but their weight still appears in the denominator.
    row = conn.execute(
        """
        SELECT
            SUM(ptr.weight)                       AS total_weight,
            SUM(CASE
                WHEN EXISTS (
                    SELECT 1
                      FROM clusters cl
                      JOIN rules r ON r.cluster_id = cl.id AND r.deployed = 1
                     WHERE ptr.fired_at >= cl.window_start
                       AND ptr.fired_at <= cl.window_end
                ) THEN ptr.weight
                ELSE 0
            END)                                  AS weighted_passes
          FROM posture_test_results ptr
         WHERE ptr.run_id = ?
        """,
        (run_id,),
    ).fetchone()

    if row is None:
        return 0.0
    total_weight = row["total_weight"] or 0
    weighted_passes = row["weighted_passes"] or 0
    if total_weight == 0:
        return 0.0
    return float(weighted_passes) / float(total_weight)


# ---------------------------------------------------------------------------
# Posture Test Results CRUD  (Phase 3 — REQ-P0-P3-003)
# ---------------------------------------------------------------------------
#
# Per-test tracking table for the scoring join in compute_posture_score_for_run.
# Schema constant _POSTURE_TEST_RESULTS_SQL is defined above (before init_db)
# so init_db can reference it. CRUD helpers follow here.

def insert_posture_test_result(
    conn: sqlite3.Connection,
    run_id: int,
    technique_id: str,
    test_name: str,
    fired_at: str,
    exit_code: Optional[int] = None,
    output: Optional[str] = None,
    weight: int = 1,
) -> int:
    """Insert a per-test result row and return its id.

    Phase 4 (REQ-P0-P4-003): weight is now persisted on the row so that
    compute_posture_weighted_score_for_run can aggregate directly in SQL
    without re-joining to atomic_tests.yaml. Defaults to 1 for backwards
    compatibility with Phase 3 callers that don't supply it.

    Args:
        conn:         Open SQLite connection.
        run_id:       The parent posture_runs.id.
        technique_id: MITRE technique ID (e.g. 'T1059.003').
        test_name:    Human-readable test label.
        fired_at:     ISO8601 timestamp when the test command was launched.
        exit_code:    Shell exit code of the test command (None if not yet run).
        output:       Captured stdout/stderr (truncated to 4096 chars).
        weight:       Importance weight from atomic_tests.yaml (default 1).

    Returns:
        The new row's INTEGER PRIMARY KEY.
    """
    safe_output = (output or "")[:4096]
    with get_cursor(conn) as cur:
        cur.execute(
            """
            INSERT INTO posture_test_results
                (run_id, technique_id, test_name, fired_at, exit_code, output, passed, weight)
            VALUES (?, ?, ?, ?, ?, ?, 0, ?)
            """,
            (run_id, technique_id, test_name, fired_at, exit_code, safe_output, weight),
        )
        return cur.lastrowid


# ---------------------------------------------------------------------------
# SLO Breaches CRUD  (Phase 4 — REQ-P0-P4-005)
# ---------------------------------------------------------------------------

def insert_slo_breach(
    conn: sqlite3.Connection,
    started_at: str,
    threshold: float,
    breach_score: float,
    posture_run_id: int,
    notes: Optional[str] = None,
) -> int:
    """Insert a new slo_breaches row and return its id.

    webhook_fired defaults to 0 (not yet attempted); the caller updates it
    after the webhook POST attempt via mark_slo_breach_webhook().

    Args:
        conn:           Open SQLite connection.
        started_at:     ISO8601 timestamp when breach was detected.
        threshold:      The SLO threshold at breach time.
        breach_score:   The posture score that triggered the breach.
        posture_run_id: FK to posture_runs.id.
        notes:          Optional operator note.

    Returns:
        The INTEGER PRIMARY KEY of the new row.
    """
    with get_cursor(conn) as cur:
        cur.execute(
            """
            INSERT INTO slo_breaches
                (started_at, threshold, breach_score, posture_run_id, webhook_fired, notes)
            VALUES (?, ?, ?, ?, 0, ?)
            """,
            (started_at, threshold, breach_score, posture_run_id, notes),
        )
        return cur.lastrowid


def get_open_slo_breach(conn: sqlite3.Connection) -> Optional[sqlite3.Row]:
    """Return the single open slo_breaches row (resolved_at IS NULL), or None.

    At most one breach is open at a time. This function is the idempotency
    guard in evaluate_slo(): if it returns a row, no new breach is opened.

    Args:
        conn: Open SQLite connection.

    Returns:
        sqlite3.Row or None.
    """
    return conn.execute(
        "SELECT * FROM slo_breaches WHERE resolved_at IS NULL ORDER BY id DESC LIMIT 1"
    ).fetchone()


def mark_slo_breach_webhook(
    conn: sqlite3.Connection,
    breach_id: int,
    status_code: Optional[int],
    fired: int,
) -> None:
    """Update webhook_fired and webhook_status on a slo_breaches row.

    Called after a webhook POST attempt (success or failure).

    Args:
        conn:        Open SQLite connection.
        breach_id:   The slo_breaches.id to update.
        status_code: HTTP status code from the POST (None on network error).
        fired:       1=success, -1=failure, 0=not attempted.
    """
    with get_cursor(conn) as cur:
        cur.execute(
            "UPDATE slo_breaches SET webhook_fired = ?, webhook_status = ? WHERE id = ?",
            (fired, status_code, breach_id),
        )


def resolve_slo_breach(
    conn: sqlite3.Connection,
    breach_id: int,
    resolved_at: str,
) -> None:
    """Set resolved_at on a slo_breaches row, closing the breach session.

    Called when the posture score recovers above the threshold.

    Args:
        conn:        Open SQLite connection.
        breach_id:   The slo_breaches.id to close.
        resolved_at: ISO8601 timestamp when score recovered.
    """
    with get_cursor(conn) as cur:
        cur.execute(
            "UPDATE slo_breaches SET resolved_at = ? WHERE id = ?",
            (resolved_at, breach_id),
        )


# ---------------------------------------------------------------------------
# Attack Recommendations CRUD  (Phase 4 Wave B — REQ-P0-P4-001/002)
# ---------------------------------------------------------------------------

def insert_attack_recommendation(
    conn: sqlite3.Connection,
    technique_id: str,
    reason: str,
    severity: str,
    cluster_id: Optional[str] = None,
    notes: Optional[str] = None,
) -> int:
    """Insert a new attack_recommendations row with status='pending'.

    Called by the recommend_attack tool handler in orchestrator.py. The row
    represents Claude's suggestion to run an ART technique — it is NOT executed
    automatically (DEC-RECOMMEND-001). Execution requires operator approval via
    POST /recommendations/{id}/execute.

    Args:
        conn:         Open SQLite connection.
        technique_id: MITRE ATT&CK technique ID (e.g. 'T1059.003').
        reason:       Claude's rationale (sanitized by the handler before insert).
        severity:     One of 'Low', 'Medium', 'High', 'Critical'.
        cluster_id:   Optional cluster being triaged when the recommendation was made.
                      Soft reference to clusters.id (TEXT). No FK constraint —
                      the link is informational; tests and standalone handler calls
                      may supply a cluster_id that does not exist in clusters.
        notes:        Optional operator notes.

    Returns:
        The INTEGER PRIMARY KEY of the new row.
    """
    created_at = datetime.now(timezone.utc).isoformat()
    with get_cursor(conn) as cur:
        cur.execute(
            """
            INSERT INTO attack_recommendations
                (cluster_id, technique_id, reason, severity, status, created_at, notes)
            VALUES (?, ?, ?, ?, 'pending', ?, ?)
            """,
            (cluster_id, technique_id, reason, severity, created_at, notes),
        )
        return cur.lastrowid


def get_attack_recommendation(
    conn: sqlite3.Connection,
    recommendation_id: int,
) -> Optional[sqlite3.Row]:
    """Return a single attack_recommendations row by id, or None.

    Args:
        conn:              Open SQLite connection.
        recommendation_id: The attack_recommendations.id to fetch.

    Returns:
        sqlite3.Row or None if not found.
    """
    return conn.execute(
        "SELECT * FROM attack_recommendations WHERE id = ?",
        (recommendation_id,),
    ).fetchone()


def list_pending_attack_recommendations(
    conn: sqlite3.Connection,
    limit: int = 50,
) -> list[sqlite3.Row]:
    """Return attack_recommendations rows with status='pending', newest first.

    Used by GET /recommendations to surface pending items for operator review.

    Args:
        conn:  Open SQLite connection.
        limit: Maximum rows to return (default 50).

    Returns:
        List of sqlite3.Row objects ordered by created_at DESC.
    """
    return conn.execute(
        """
        SELECT * FROM attack_recommendations
        WHERE status = 'pending'
        ORDER BY created_at DESC
        LIMIT ?
        """,
        (limit,),
    ).fetchall()


def mark_attack_recommendation_executed(
    conn: sqlite3.Connection,
    recommendation_id: int,
    posture_run_id: Optional[int] = None,
) -> None:
    """Flip a recommendation row from 'pending' to 'executed'.

    Sets executed_at to now(UTC) and links posture_run_id so the operator can
    correlate the recommendation with the resulting posture run.

    Args:
        conn:              Open SQLite connection.
        recommendation_id: The attack_recommendations.id to update.
        posture_run_id:    The posture_runs.id created by execute_recommendation().
    """
    executed_at = datetime.now(timezone.utc).isoformat()
    with get_cursor(conn) as cur:
        cur.execute(
            """
            UPDATE attack_recommendations
               SET status         = 'executed',
                   executed_at    = ?,
                   posture_run_id = ?
             WHERE id = ?
            """,
            (executed_at, posture_run_id, recommendation_id),
        )


def count_pending_attack_recommendations(conn: sqlite3.Connection) -> int:
    """Return the count of attack_recommendations rows with status='pending'.

    Used by /health to expose recommendations.pending_count without returning
    full rows (DEC-HEALTH-002 — public, minimal).

    Args:
        conn: Open SQLite connection.

    Returns:
        Integer count, 0 when no pending rows exist.
    """
    row = conn.execute(
        "SELECT COUNT(*) FROM attack_recommendations WHERE status = 'pending'"
    ).fetchone()
    return int(row[0]) if row else 0


# ---------------------------------------------------------------------------
# Phase 5 Wave A1 CRUD — cloudtrail_progress cursor helpers
# (REQ-P0-P5-001, DEC-CLOUD-002, DEC-CLOUD-011)
# ---------------------------------------------------------------------------


def get_cloudtrail_cursor(
    conn: sqlite3.Connection,
    bucket: str,
    prefix: str,
) -> Optional[sqlite3.Row]:
    """Return the cloudtrail_progress row for (bucket, prefix), or None.

    The row's last_object_key field is the S3 StartAfter cursor for the
    next list_objects_v2 call. A None return means the poller has not yet
    processed any objects for this (bucket, prefix) pair.

    Args:
        conn:   Open SQLite connection.
        bucket: S3 bucket name.
        prefix: Key prefix within the bucket.

    Returns:
        sqlite3.Row with columns (id, bucket, prefix, last_object_key,
        last_event_ts, updated_at), or None if no row exists yet.
    """
    return conn.execute(
        "SELECT * FROM cloudtrail_progress WHERE bucket = ? AND prefix = ?",
        (bucket, prefix),
    ).fetchone()


def update_cloudtrail_cursor(
    conn: sqlite3.Connection,
    bucket: str,
    prefix: str,
    last_object_key: str,
    last_event_ts: Optional[str],
) -> None:
    """Upsert the cloudtrail_progress cursor for (bucket, prefix).

    Uses INSERT OR REPLACE keyed on the UNIQUE(bucket, prefix) constraint
    so successive calls are idempotent and restart-safe (DEC-CLOUD-002).

    Args:
        conn:            Open SQLite connection.
        bucket:          S3 bucket name.
        prefix:          Key prefix within the bucket.
        last_object_key: The S3 key of the last fully consumed object.
        last_event_ts:   ISO-8601 timestamp of the last parsed event
                         (may be None if no events were in the object).
    """
    from datetime import datetime, timezone as _tz
    updated_at = datetime.now(_tz.utc).isoformat()
    with get_cursor(conn) as cur:
        cur.execute(
            """
            INSERT INTO cloudtrail_progress
                (bucket, prefix, last_object_key, last_event_ts, updated_at)
            VALUES (?, ?, ?, ?, ?)
            ON CONFLICT(bucket, prefix) DO UPDATE SET
                last_object_key = excluded.last_object_key,
                last_event_ts   = excluded.last_event_ts,
                updated_at      = excluded.updated_at
            """,
            (bucket, prefix, last_object_key, last_event_ts, updated_at),
        )


def insert_cloudtrail_alert(
    conn: sqlite3.Connection,
    parsed: dict,
) -> str:
    """Insert a CloudTrail parsed alert into the alerts + alert_details tables.

    Generates a deterministic alert ID from the parsed dict's rule_id,
    timestamp, and src_ip so duplicate ingestion of the same CloudTrail event
    (e.g. on restart before cursor advances) is silently ignored via
    INSERT OR IGNORE.

    Args:
        conn:   Open SQLite connection.
        parsed: Dict returned by parse_cloudtrail_event().

    Returns:
        The alert ID string (may already exist in the DB — caller can ignore).
    """
    import hashlib
    import uuid as _uuid

    # Build a deterministic ID from the most stable CloudTrail fields.
    # raw_json contains the full event including eventID which AWS guarantees
    # unique per event — hashing it gives us dedup for free.
    raw = parsed.get("raw_json", "")
    alert_id = str(_uuid.UUID(hashlib.md5(raw.encode(), usedforsecurity=False).hexdigest()))

    with get_cursor(conn) as cur:
        cur.execute(
            """
            INSERT OR IGNORE INTO alerts
                (id, rule_id, src_ip, severity, cluster_id, source,
                 dest_ip, protocol, normalized_severity)
            VALUES (?, ?, ?, ?, NULL, ?, ?, ?, ?)
            """,
            (
                alert_id,
                parsed.get("rule_id", "cloudtrail:unknown:unknown"),
                parsed.get("src_ip", "unknown"),
                parsed.get("severity", 5),
                "cloudtrail",
                parsed.get("dest_ip"),
                parsed.get("protocol", "https"),
                parsed.get("normalized_severity", "Low"),
            ),
        )
        cur.execute(
            "INSERT OR IGNORE INTO alert_details (alert_id, raw_json) VALUES (?, ?)",
            (alert_id, raw),
        )

    return alert_id


# ---------------------------------------------------------------------------
# Cloud Audit Findings CRUD  (Phase 5 Wave A2 — REQ-P0-P5-005)
# ---------------------------------------------------------------------------


def insert_cloud_finding(
    conn: sqlite3.Connection,
    alert_id: Optional[str],
    rule_name: str,
    rule_severity: str,
    title: str,
    description: str,
    principal: Optional[str],
    src_ip: Optional[str],
    event_name: Optional[str],
    event_source: Optional[str],
    raw_event: Optional[str],
) -> int:
    """Insert a cloud audit finding row and return its integer id.

    Sets detected_at to the current UTC ISO-8601 timestamp.

    Args:
        conn:          Open SQLite connection.
        alert_id:      FK to alerts.id (TEXT UUID), or None for standalone findings.
        rule_name:     Name of the detector rule that fired.
        rule_severity: One of 'Low', 'Medium', 'High', 'Critical'.
        title:         Human-readable title (interpolated with event fields).
        description:   Free-form description of the finding.
        principal:     IAM principal ARN or username.
        src_ip:        Source IP from the CloudTrail event.
        event_name:    CloudTrail eventName.
        event_source:  CloudTrail eventSource.
        raw_event:     Full raw CloudTrail event as a JSON string.

    Returns:
        The integer primary key of the newly inserted row.
    """
    detected_at = datetime.now(timezone.utc).isoformat()
    with get_cursor(conn) as cur:
        cur.execute(
            """
            INSERT INTO cloud_audit_findings
                (alert_id, rule_name, rule_severity, title, description,
                 principal, src_ip, event_name, event_source, detected_at, raw_event)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                alert_id,
                rule_name,
                rule_severity,
                title,
                description,
                principal,
                src_ip,
                event_name,
                event_source,
                detected_at,
                raw_event,
            ),
        )
        return cur.lastrowid


def list_cloud_findings(
    conn: sqlite3.Connection,
    limit: int = 50,
    severity: Optional[str] = None,
) -> list:
    """Return cloud_audit_findings rows, newest first.

    Args:
        conn:     Open SQLite connection.
        limit:    Maximum number of rows to return (default 50).
        severity: Optional severity filter — one of 'Low', 'Medium', 'High',
                  'Critical'. When None, all severities are returned.

    Returns:
        List of sqlite3.Row objects ordered by detected_at DESC.
    """
    if severity is not None:
        rows = conn.execute(
            """
            SELECT * FROM cloud_audit_findings
            WHERE rule_severity = ?
            ORDER BY detected_at DESC
            LIMIT ?
            """,
            (severity, limit),
        ).fetchall()
    else:
        rows = conn.execute(
            """
            SELECT * FROM cloud_audit_findings
            ORDER BY detected_at DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()
    return rows


def count_cloud_findings(conn: sqlite3.Connection) -> int:
    """Return the total number of cloud_audit_findings rows.

    Used by Wave A3 (#56) for /health/metrics. Included here since A3 is the
    next issue and this helper belongs in models alongside the other count_*
    helpers.

    Args:
        conn: Open SQLite connection.

    Returns:
        Integer count of all rows in cloud_audit_findings.
    """
    row = conn.execute("SELECT COUNT(*) FROM cloud_audit_findings").fetchone()
    return row[0] if row else 0


def count_cloudtrail_alerts_since(conn: sqlite3.Connection, since_iso: str) -> int:
    """Return the count of cloudtrail-source alerts ingested since since_iso.

    Used by /health to show events_ingested_24h without relying on in-memory
    counters (which reset on restart).  DB-backed count survives restarts and
    stays accurate regardless of how many poller instances ran.

    Args:
        conn:       Open SQLite connection.
        since_iso:  ISO-8601 timestamp string (e.g. from
                    ``datetime.now(timezone.utc) - timedelta(days=1)``).
                    Rows with ``ingested_at >= since_iso`` are counted.

    Returns:
        Integer count of matching rows in the alerts table.
    """
    row = conn.execute(
        "SELECT COUNT(*) FROM alerts WHERE source='cloudtrail' AND ingested_at >= ?",
        (since_iso,),
    ).fetchone()
    return row[0] if row else 0


def get_cloud_finding(
    conn: sqlite3.Connection,
    finding_id: int,
) -> Optional[sqlite3.Row]:
    """Fetch a single cloud_audit_findings row by primary key.

    Args:
        conn:       Open SQLite connection.
        finding_id: The INTEGER PRIMARY KEY of the finding.

    Returns:
        sqlite3.Row if found, None otherwise.
    """
    return conn.execute(
        "SELECT * FROM cloud_audit_findings WHERE id = ?",
        (finding_id,),
    ).fetchone()


# ---------------------------------------------------------------------------
# CloudTrail principal lookup — Phase 5 Wave B1 (REQ-P0-P5-007)
# ---------------------------------------------------------------------------


def get_cloudtrail_events_by_principal_since(
    conn: sqlite3.Connection,
    principal_arn: str,
    since_ts: str,
    limit: int = 50,
) -> list[dict]:
    """Return up to ``limit`` recent CloudTrail alerts for the given principal ARN.

    The principal ARN is stored inside the ``raw_json`` column of
    ``alert_details`` (the full CloudTrail event JSON, including
    ``userIdentity.arn``).  We extract it via SQLite's ``json_extract()``
    rather than adding a dedicated column to the shared ``alerts`` table —
    consistent with DEC-CLOUD-003 / DEC-CLUSTER-002: source-specific fields
    stay out of the shared schema.  The query cost is acceptable because
    this is only called during operator-initiated triage (not in a tight loop).

    Args:
        conn:          Open SQLite connection.
        principal_arn: Full AWS principal ARN, e.g.
                       ``arn:aws:iam::123456789012:user/alice``.
                       Caller is responsible for sanitizing this value before
                       passing it here (see _handle_lookup_cloud_identity in
                       orchestrator.py which applies sanitize_alert_field).
        since_ts:      ISO-8601 cutoff timestamp.  Only alerts with
                       ``ingested_at >= since_ts`` are returned.
        limit:         Maximum rows to return (default 50).

    Returns:
        List of dicts with keys: id, rule_id, src_ip, severity, source,
        cluster_id, ingested_at, raw_json.  Ordered newest-first.
        Returns an empty list when no alerts match.
    """
    rows = conn.execute(
        """
        SELECT a.id,
               a.rule_id,
               a.src_ip,
               a.severity,
               a.source,
               a.cluster_id,
               a.ingested_at,
               d.raw_json
          FROM alerts a
          JOIN alert_details d ON d.alert_id = a.id
         WHERE a.source = 'cloudtrail'
           AND json_extract(d.raw_json, '$.userIdentity.arn') = ?
           AND a.ingested_at >= ?
         ORDER BY a.ingested_at DESC
         LIMIT ?
        """,
        (principal_arn, since_ts, limit),
    ).fetchall()
    return [dict(row) for row in rows]


# ---------------------------------------------------------------------------
# Phase 6 Wave A1 — users CRUD helpers (REQ-P0-P6-003)
# ---------------------------------------------------------------------------

def insert_user(
    conn: sqlite3.Connection,
    username: str,
    password_hash: str,
    role: str,
) -> int:
    """Insert a new user row and return the new ``users.id``.

    ``created_at`` is set to the current UTC timestamp.
    ``disabled`` defaults to 0 (active).
    Raises ``sqlite3.IntegrityError`` if ``username`` already exists (UNIQUE).
    Raises ``sqlite3.IntegrityError`` if ``role`` is not one of the CHECK values.
    """
    ts = datetime.now(timezone.utc).isoformat()
    with get_cursor(conn) as cur:
        cur.execute(
            """
            INSERT INTO users (username, password_hash, role, created_at, disabled)
            VALUES (?, ?, ?, ?, 0)
            """,
            (username, password_hash, role, ts),
        )
        return cur.lastrowid  # type: ignore[return-value]


def get_user_by_id(
    conn: sqlite3.Connection,
    user_id: int,
) -> Optional[sqlite3.Row]:
    """Return the ``users`` row for *user_id*, or None if not found."""
    return conn.execute(
        "SELECT * FROM users WHERE id = ?", (user_id,)
    ).fetchone()


def get_user_by_username(
    conn: sqlite3.Connection,
    username: str,
) -> Optional[sqlite3.Row]:
    """Return the ``users`` row for *username*, or None if not found."""
    return conn.execute(
        "SELECT * FROM users WHERE username = ?", (username,)
    ).fetchone()


def update_user_last_login(
    conn: sqlite3.Connection,
    user_id: int,
    ts: str,
) -> None:
    """Set ``users.last_login_at`` to *ts* for the given user."""
    with get_cursor(conn) as cur:
        cur.execute(
            "UPDATE users SET last_login_at = ? WHERE id = ?",
            (ts, user_id),
        )


def set_user_disabled(
    conn: sqlite3.Connection,
    user_id: int,
    disabled: bool,
) -> None:
    """Toggle the ``users.disabled`` flag.

    ``disabled`` is the single auth gate — ``is_active`` was dropped in the
    #69 follow-up to eliminate drift risk where a caller could set
    ``is_active=0`` without setting ``disabled=1`` and silently fail to block
    auth. One toggle, no ambiguity (DEC-AUTH-P6-004).
    """
    disabled_int = 1 if disabled else 0
    with get_cursor(conn) as cur:
        cur.execute(
            "UPDATE users SET disabled = ? WHERE id = ?",
            (disabled_int, user_id),
        )


def list_users(
    conn: sqlite3.Connection,
    limit: int = 100,
) -> list[sqlite3.Row]:
    """Return up to *limit* user rows ordered by ``created_at`` ascending."""
    return conn.execute(
        "SELECT * FROM users ORDER BY created_at ASC LIMIT ?", (limit,)
    ).fetchall()


# ---------------------------------------------------------------------------
# Phase 6 Wave A1 — user_tokens CRUD helpers (REQ-P0-P6-003)
# ---------------------------------------------------------------------------

def insert_user_token(
    conn: sqlite3.Connection,
    user_id: int,
    token_hash: str,
    name: str,
    expires_at: Optional[str] = None,
) -> int:
    """Insert a new user_token row and return the new ``user_tokens.id``.

    ``created_at`` is set to the current UTC timestamp.
    ``expires_at`` is stored as an ISO-8601 string; pass None for no expiry.
    Raises ``sqlite3.IntegrityError`` if ``token_hash`` is not unique.
    """
    ts = datetime.now(timezone.utc).isoformat()
    with get_cursor(conn) as cur:
        cur.execute(
            """
            INSERT INTO user_tokens (user_id, token_hash, name, created_at, expires_at)
            VALUES (?, ?, ?, ?, ?)
            """,
            (user_id, token_hash, name, ts, expires_at),
        )
        return cur.lastrowid  # type: ignore[return-value]


def get_user_token_by_hash(
    conn: sqlite3.Connection,
    token_hash: str,
) -> Optional[sqlite3.Row]:
    """Return the ``user_tokens`` row matching *token_hash*, or None.

    This is the hot path for every authenticated request in multi mode:
    the presented bearer is SHA-256 hashed and looked up here.
    """
    return conn.execute(
        "SELECT * FROM user_tokens WHERE token_hash = ?", (token_hash,)
    ).fetchone()


def update_user_token_last_used(
    conn: sqlite3.Connection,
    token_id: int,
    ts: str,
) -> None:
    """Set ``user_tokens.last_used_at`` to *ts* for the given token id."""
    with get_cursor(conn) as cur:
        cur.execute(
            "UPDATE user_tokens SET last_used_at = ? WHERE id = ?",
            (ts, token_id),
        )


def revoke_user_token(
    conn: sqlite3.Connection,
    token_id: int,
    ts: str,
) -> None:
    """Set ``user_tokens.revoked_at`` to *ts*, permanently revoking the token."""
    with get_cursor(conn) as cur:
        cur.execute(
            "UPDATE user_tokens SET revoked_at = ? WHERE id = ?",
            (ts, token_id),
        )


def list_user_tokens(
    conn: sqlite3.Connection,
    user_id: int,
) -> list[sqlite3.Row]:
    """Return all token rows for *user_id* ordered by ``created_at`` ascending."""
    return conn.execute(
        "SELECT * FROM user_tokens WHERE user_id = ? ORDER BY created_at ASC",
        (user_id,),
    ).fetchall()
