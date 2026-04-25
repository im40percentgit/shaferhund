"""
Phase 6 Wave B3 — /health and /metrics observability block builders.

Pulls auth.* and fleet.* block construction out of agent/main.py to keep
the route handlers lean (same structural pattern as _build_cloudtrail_metrics_block
introduced in Phase 5 Wave A3).

Four public functions:
  build_health_auth_block    — minimal auth summary for the public /health probe
  build_health_fleet_block   — minimal fleet summary for the public /health probe
  build_metrics_auth_block   — rich per-role auth stats for the auth-gated /metrics
  build_metrics_fleet_block  — rich fleet operational stats for /metrics

DEC-HEALTH-002 invariant is enforced structurally: the health_* functions only
return counters and one timestamp; per-user/per-token details are metrics_* only.

@decision DEC-OBSERVABILITY-P6-001
@title Audit-log as source-of-truth for fleet counters; observability blocks in own module
@status accepted
@rationale
  Two design choices captured here:

  1. Fleet counter source — The audit_log table (written by AuditMiddleware on
     every request) is the authoritative counter for manifest fetches.  The
     alternative (in-memory FLEET_STATS dict incremented by the manifest route)
     was rejected because: (a) it resets on restart, losing history; (b) it
     adds mutable shared state; (c) it duplicates the source-of-truth role
     already filled by audit_log.  Querying audit_log for path LIKE
     '/fleet/manifest/%' is a simple indexed scan on a small table — acceptable
     O(N) cost for a low-traffic operational endpoint.

  2. Module split — Block builders are extracted into agent/observability.py
     rather than inlined in agent/main.py.  agent/main.py already imports from
     ~12 modules; adding 4 more multi-line helper functions would push it past
     ~2000 lines.  The module split mirrors _build_cloudtrail_metrics_block's
     predecessor pattern and allows unit-testing the block builders independently
     of the FastAPI request/response cycle if needed.

  DEC-HEALTH-002 preserved: /health receives only mode, users_count,
  last_login_at (auth) and manifest_fetches_24h, last_manifest_fetch_at (fleet).
  All richer stats (per-role counts, token buckets, tag totals, deployed counts)
  remain in the auth-gated /metrics.
"""

import sqlite3
from datetime import datetime, timezone, timedelta
from typing import Optional

from .models import (
    count_audit_events_by_path_prefix,
    count_distinct_tags,
    count_rules_deployed,
    count_rules_tagged,
    count_tokens_by_status,
    count_users,
    count_users_by_role,
    count_users_disabled,
    get_latest_audit_event_by_path_prefix,
    get_max_user_created_at,
    get_max_user_last_login,
    list_distinct_manifest_paths_24h,
)
from .canary import sanitize_alert_field as _sanitize

_FLEET_MANIFEST_PREFIX = "/fleet/manifest/"


def _since_24h_iso() -> str:
    """Return ISO-8601 timestamp for 24 hours ago (UTC)."""
    return (datetime.now(timezone.utc) - timedelta(days=1)).isoformat()


# ---------------------------------------------------------------------------
# /health block builders (public, no auth required)
# ---------------------------------------------------------------------------


def build_health_auth_block(conn: Optional[sqlite3.Connection], settings) -> dict:
    """Build the minimal auth summary dict for the public /health endpoint.

    Fields (DEC-HEALTH-002 — minimal, no recon value):
      mode         -- 'single' or 'multi', from settings.shaferhund_auth_mode
      users_count  -- total rows in users table (0 in single mode)
      last_login_at -- max last_login_at across all users, or null

    Args:
        conn:     Open sqlite3.Connection or None (returns zero-state if None).
        settings: Settings-like object or None.

    Returns:
        dict with keys: mode, users_count, last_login_at
    """
    auth_mode = (
        getattr(settings, "shaferhund_auth_mode", "single")
        if settings is not None
        else "single"
    )
    if conn is None:
        return {"mode": auth_mode, "users_count": 0, "last_login_at": None}

    users_count = count_users(conn)
    last_login_at = get_max_user_last_login(conn)

    return {
        "mode": auth_mode,
        "users_count": users_count,
        "last_login_at": last_login_at,
    }


def build_health_fleet_block(conn: Optional[sqlite3.Connection]) -> dict:
    """Build the minimal fleet summary dict for the public /health endpoint.

    Fields (DEC-HEALTH-002 — counters and one timestamp only):
      manifest_fetches_24h    -- audit_log rows for /fleet/manifest/* in last 24h
      last_manifest_fetch_at  -- ts of most recent such row, or null

    Source of truth is audit_log (DEC-OBSERVABILITY-P6-001).

    Args:
        conn: Open sqlite3.Connection or None (returns zero-state if None).

    Returns:
        dict with keys: manifest_fetches_24h, last_manifest_fetch_at
    """
    if conn is None:
        return {"manifest_fetches_24h": 0, "last_manifest_fetch_at": None}

    since = _since_24h_iso()
    fetches_24h = count_audit_events_by_path_prefix(conn, _FLEET_MANIFEST_PREFIX, since)
    latest_row = get_latest_audit_event_by_path_prefix(conn, _FLEET_MANIFEST_PREFIX)
    last_fetch_at = latest_row["ts"] if latest_row is not None else None

    return {
        "manifest_fetches_24h": fetches_24h,
        "last_manifest_fetch_at": last_fetch_at,
    }


# ---------------------------------------------------------------------------
# /metrics block builders (auth-gated, richer operational stats)
# ---------------------------------------------------------------------------


def build_metrics_auth_block(
    conn: Optional[sqlite3.Connection], settings
) -> dict:
    """Build the rich auth stats dict for the auth-gated /metrics endpoint.

    Fields:
      mode                -- 'single' or 'multi'
      users_total         -- COUNT(*) from users
      users_by_role       -- {admin: N, operator: N, viewer: N} (non-disabled only)
      users_disabled_count -- COUNT(*) WHERE disabled=1
      tokens_active_count  -- tokens not revoked and not expired
      tokens_revoked_count -- tokens with revoked_at IS NOT NULL
      tokens_expired_count -- tokens past expires_at (not revoked)
      last_login_at        -- max last_login_at across all users, or null
      last_user_created_at -- max created_at across all users, or null

    Args:
        conn:     Open sqlite3.Connection or None (returns zero-state if None).
        settings: Settings-like object or None.

    Returns:
        dict with 9 keys.
    """
    auth_mode = (
        getattr(settings, "shaferhund_auth_mode", "single")
        if settings is not None
        else "single"
    )
    if conn is None:
        return {
            "mode": auth_mode,
            "users_total": 0,
            "users_by_role": {"admin": 0, "operator": 0, "viewer": 0},
            "users_disabled_count": 0,
            "tokens_active_count": 0,
            "tokens_revoked_count": 0,
            "tokens_expired_count": 0,
            "last_login_at": None,
            "last_user_created_at": None,
        }

    users_total = count_users(conn)
    users_by_role = count_users_by_role(conn)
    users_disabled = count_users_disabled(conn)
    token_buckets = count_tokens_by_status(conn)
    last_login_at = get_max_user_last_login(conn)
    last_created_at = get_max_user_created_at(conn)

    return {
        "mode": auth_mode,
        "users_total": users_total,
        "users_by_role": users_by_role,
        "users_disabled_count": users_disabled,
        "tokens_active_count": token_buckets["active"],
        "tokens_revoked_count": token_buckets["revoked"],
        "tokens_expired_count": token_buckets["expired"],
        "last_login_at": last_login_at,
        "last_user_created_at": last_created_at,
    }


def build_metrics_fleet_block(conn: Optional[sqlite3.Connection]) -> dict:
    """Build the rich fleet stats dict for the auth-gated /metrics endpoint.

    Fields:
      manifest_fetches_24h    -- audit_log rows for /fleet/manifest/* in last 24h
      last_manifest_fetch_at  -- ts of most recent such row, or null
      rules_tagged_total       -- distinct rule_ids in rule_tags
      tags_total               -- distinct tag values in rule_tags
      rules_deployed_count     -- COUNT(*) WHERE deployed=1 in rules
      manifest_endpoints_seen  -- sorted list of distinct paths from audit_log (24h)

    manifest_endpoints_seen path values are passed through sanitize_alert_field
    before inclusion (operator-influenced strings, REQ-MUST-PRESERVE-003).

    Source of truth is audit_log for fleet counters (DEC-OBSERVABILITY-P6-001).

    Args:
        conn: Open sqlite3.Connection or None (returns zero-state if None).

    Returns:
        dict with 6 keys.
    """
    if conn is None:
        return {
            "manifest_fetches_24h": 0,
            "last_manifest_fetch_at": None,
            "rules_tagged_total": 0,
            "tags_total": 0,
            "rules_deployed_count": 0,
            "manifest_endpoints_seen": [],
        }

    since = _since_24h_iso()
    fetches_24h = count_audit_events_by_path_prefix(conn, _FLEET_MANIFEST_PREFIX, since)
    latest_row = get_latest_audit_event_by_path_prefix(conn, _FLEET_MANIFEST_PREFIX)
    last_fetch_at = latest_row["ts"] if latest_row is not None else None

    rules_tagged = count_rules_tagged(conn)
    tags_total = count_distinct_tags(conn)
    rules_deployed = count_rules_deployed(conn)

    raw_paths = list_distinct_manifest_paths_24h(conn, since)
    # sanitize_alert_field on operator-influenced path strings (CSO)
    safe_paths = [_sanitize(p) for p in raw_paths]

    return {
        "manifest_fetches_24h": fetches_24h,
        "last_manifest_fetch_at": last_fetch_at,
        "rules_tagged_total": rules_tagged,
        "tags_total": tags_total,
        "rules_deployed_count": rules_deployed,
        "manifest_endpoints_seen": safe_paths,
    }
