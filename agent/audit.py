"""
Shaferhund Phase 6 — Append-only audit log with chained HMAC.

Every authenticated mutating request (POST/PUT/DELETE) and every admin-only
GET is recorded in the audit_log table.  Each row's HMAC is computed over a
canonical encoding of the row data chained with the previous row's HMAC, so
any tampering with historical rows breaks the chain at exactly that ID.

Design decisions:

@decision DEC-AUDIT-P6-001
@title Append-only audit_log with chained HMAC; GET /audit/verify exposes chain integrity
@status accepted
@rationale The HMAC chain (row_hmac = HMAC-SHA256(key, canonical(prev_hmac || row)))
           gives tamper evidence without requiring an external signer.  Same
           in-DB-state-with-cryptographic-integrity shape as Phase 4's slo_breaches.
           Operators verify the chain with one route call (GET /audit/verify); the
           moment a row is mutated or deleted, the chain breaks at exactly that ID.
           SHAFERHUND_AUDIT_KEY is separate from the password-hashing secret so
           rotation of one does not affect the other.

@decision DEC-AUDIT-P6-002
@title Audit middleware records non-GET requests + admin-only GETs; readonly viewer/operator GETs are not audited
@status accepted
@rationale Auditing every GET would flood the log with read-only viewer traffic
           (e.g. dashboard auto-refresh every 10s).  The threat model treats
           mutating operations (deploy_rule, exec recommendation, posture run,
           user CRUD, fleet registration) as the writes worth auditing.
           Admin-only GETs (GET /audit, GET /audit/verify) are also recorded
           because they reveal the audit trail itself — access to the trail is
           operationally significant.  Public endpoints (/health, /canary/hit)
           are intentionally excluded — they carry no identity and would
           contribute only noise.

Canonical-row encoding:

The canonical bytes for an audit row are a UTF-8-encoded JSON array in fixed
field order:

    [prev_hmac, ts, actor_username, actor_role, method, path, status_code, body_excerpt]

Using a JSON list (not a dict) preserves field order without sort_keys and
produces an unambiguous encoding — any field that contains a special character
is escaped by json.dumps, so there is no risk of field-boundary confusion.
prev_hmac is the string "null" (via json.dumps(None)) for the first row.

HMAC computation:

    row_hmac = HMAC-SHA256(key_bytes, canonical_bytes).hexdigest()

The key is derived from SHAFERHUND_AUDIT_KEY (hex-decoded to bytes).  If the
env var is absent, an ephemeral fallback key is derived at startup (see
config.py) with a logged WARNING — the chain is still tamper-evident within a
session but breaks across restarts.  Production deployments MUST set
SHAFERHUND_AUDIT_KEY to a stable 32-byte hex value.
"""

import hashlib
import hmac as _hmac
import json
import logging
import sqlite3
from datetime import datetime, timezone
from typing import Optional

from .canary import sanitize_alert_field
from .models import (
    get_latest_audit_hmac,
    insert_audit_event,
)

log = logging.getLogger(__name__)

# Maximum characters of request body stored in audit_log.body_excerpt.
_BODY_EXCERPT_MAX = 200

# HTTP methods that are audited unconditionally (mutating requests).
_AUDITED_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})

# GET paths that are audited because they expose admin-only data.
# These are exact-match strings.  The middleware checks startswith for
# prefix-based routes (e.g. /audit is the prefix for /audit/verify).
_AUDITED_GET_PREFIXES = frozenset({"/audit"})


# ---------------------------------------------------------------------------
# Canonical row encoding
# ---------------------------------------------------------------------------


def canonical_row(
    prev_hmac: Optional[str],
    ts: str,
    actor_username: str,
    actor_role: str,
    method: str,
    path: str,
    status_code: int,
    body_excerpt: Optional[str],
) -> bytes:
    """Return the canonical bytes for one audit row.

    The encoding is a UTF-8 JSON array in fixed field order:

        [prev_hmac, ts, actor_username, actor_role, method, path,
         status_code, body_excerpt]

    ``prev_hmac`` is None for the first row and encodes as JSON ``null``.
    All string fields are JSON-escaped, so the encoding is unambiguous regardless
    of field content — no field-separator injection is possible.

    The field order is load-bearing: swapping any two fields produces different
    bytes and a different HMAC, which is the desired property for tamper detection.
    """
    payload = [
        prev_hmac,       # None → JSON null; str → JSON string
        ts,
        actor_username,
        actor_role,
        method,
        path,
        status_code,     # int (no quotes in JSON)
        body_excerpt,    # None → JSON null; str → JSON string
    ]
    return json.dumps(
        payload,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


# ---------------------------------------------------------------------------
# HMAC computation
# ---------------------------------------------------------------------------


def compute_row_hmac(key: bytes, canonical: bytes) -> str:
    """Compute HMAC-SHA256 over canonical bytes using key.

    Returns a lowercase hex string (64 characters).

    Args:
        key:       Raw bytes of the HMAC key.  Must not be empty.
        canonical: Output of canonical_row() for this row.

    Returns:
        Hex digest string, e.g. ``'a3f1...9b2d'``.
    """
    return _hmac.new(key, canonical, hashlib.sha256).hexdigest()


# ---------------------------------------------------------------------------
# Chain verification
# ---------------------------------------------------------------------------


def verify_chain(conn: sqlite3.Connection, key: bytes) -> dict:
    """Walk all audit_log rows in id-order and re-compute each HMAC.

    Returns a dict:
        {
            "intact":          bool,             # True iff all HMACs match
            "total_rows":      int,              # number of rows examined
            "broken_at_id":    int | None,       # first row whose HMAC mismatches
            "broken_field_clue": str | None,     # human-readable hint
        }

    On the first mismatch the walk stops — there is no point continuing
    because every subsequent row's prev_hmac would also be wrong.

    An empty table (0 rows) returns intact=True, total_rows=0.
    """
    rows = conn.execute(
        """
        SELECT id, ts, actor_username, actor_role, method, path,
               status_code, body_excerpt, prev_hmac, row_hmac
        FROM audit_log
        ORDER BY id ASC
        """
    ).fetchall()

    if not rows:
        return {
            "intact": True,
            "total_rows": 0,
            "broken_at_id": None,
            "broken_field_clue": None,
        }

    prev_row_hmac: Optional[str] = None

    for i, row in enumerate(rows):
        row_d = dict(row)
        stored_prev = row_d["prev_hmac"]   # None for first row
        stored_hmac = row_d["row_hmac"]

        # Check that stored prev_hmac matches what we computed for the previous row.
        if stored_prev != prev_row_hmac:
            return {
                "intact": False,
                "total_rows": i + 1,
                "broken_at_id": row_d["id"],
                "broken_field_clue": (
                    f"prev_hmac mismatch at id={row_d['id']}: "
                    f"stored={stored_prev!r}, expected={prev_row_hmac!r}"
                ),
            }

        # Recompute this row's HMAC from its stored fields.
        canon = canonical_row(
            prev_hmac=row_d["prev_hmac"],
            ts=row_d["ts"],
            actor_username=row_d["actor_username"],
            actor_role=row_d["actor_role"],
            method=row_d["method"],
            path=row_d["path"],
            status_code=row_d["status_code"],
            body_excerpt=row_d["body_excerpt"],
        )
        expected_hmac = compute_row_hmac(key, canon)

        if stored_hmac != expected_hmac:
            return {
                "intact": False,
                "total_rows": i + 1,
                "broken_at_id": row_d["id"],
                "broken_field_clue": (
                    f"row_hmac mismatch at id={row_d['id']}: "
                    f"stored={stored_hmac!r}, expected={expected_hmac!r}"
                ),
            }

        prev_row_hmac = stored_hmac

    return {
        "intact": True,
        "total_rows": len(rows),
        "broken_at_id": None,
        "broken_field_clue": None,
    }


# ---------------------------------------------------------------------------
# Audit record helper
# ---------------------------------------------------------------------------


def record_audit(
    conn: sqlite3.Connection,
    key: bytes,
    actor_username: str,
    actor_role: str,
    method: str,
    path: str,
    status_code: int,
    body_excerpt: Optional[str],
) -> int:
    """Record one audit event to the audit_log table.

    Atomically reads the latest row_hmac, computes the new HMAC, and inserts
    the row in a single transaction via insert_audit_event (which takes an
    exclusive lock to prevent races).

    Sanitizes body_excerpt via sanitize_alert_field before storage so
    attacker-influenced request bodies are safe to store.

    Returns:
        The new audit_log row id.

    Raises:
        sqlite3.Error on DB failure — caller (middleware) catches and logs,
        then continues so the response is never blocked.
    """
    ts = datetime.now(timezone.utc).isoformat()

    # Sanitize attacker-influenced input (REQ-P0-P6-005 + must-preserve rule 3).
    safe_excerpt: Optional[str] = None
    if body_excerpt is not None:
        safe_excerpt = sanitize_alert_field(str(body_excerpt))[:_BODY_EXCERPT_MAX]

    prev_hmac = get_latest_audit_hmac(conn)
    canon = canonical_row(
        prev_hmac=prev_hmac,
        ts=ts,
        actor_username=actor_username,
        actor_role=actor_role,
        method=method,
        path=path,
        status_code=status_code,
        body_excerpt=safe_excerpt,
    )
    row_hmac = compute_row_hmac(key, canon)

    row_id = insert_audit_event(
        conn=conn,
        ts=ts,
        actor_username=actor_username,
        actor_role=actor_role,
        method=method,
        path=path,
        status_code=status_code,
        body_excerpt=safe_excerpt,
        prev_hmac=prev_hmac,
        row_hmac=row_hmac,
    )
    return row_id


# ---------------------------------------------------------------------------
# Middleware helper — should this request be audited?
# ---------------------------------------------------------------------------


def should_audit(method: str, path: str) -> bool:
    """Return True if this request should be recorded in audit_log.

    Audited (DEC-AUDIT-P6-002):
      - All mutating methods: POST, PUT, PATCH, DELETE.
      - Admin-only GET paths that expose audit data: /audit*.

    Not audited:
      - Public endpoints: /health, /canary/hit/* (no identity to record).
      - Standard viewer/operator GETs: /metrics, /, /clusters/*, etc.
        These would flood the log with read-only traffic.
    """
    if method.upper() in _AUDITED_METHODS:
        return True
    if method.upper() == "GET":
        for prefix in _AUDITED_GET_PREFIXES:
            if path.startswith(prefix):
                return True
    return False
