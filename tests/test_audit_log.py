"""
Tests for agent/audit.py — canonical_row encoding, HMAC computation,
chain verification, and the record_audit helper.

(REQ-P0-P6-005, DEC-AUDIT-P6-001, DEC-AUDIT-P6-002)

All tests use a real in-memory SQLite connection and the real HMAC implementation.
No internal functions are mocked.
"""

import sqlite3
import logging
from typing import Optional
from unittest.mock import patch, MagicMock

import pytest

from agent.audit import (
    canonical_row,
    compute_row_hmac,
    record_audit,
    verify_chain,
)
from agent.models import (
    count_audit_events,
    get_latest_audit_hmac,
    init_db,
    insert_audit_event,
    list_audit_events,
)

# Test key — 32-byte equivalent, deterministic.
_KEY = b"test-audit-key-for-pytest-32byte"

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def db(tmp_path):
    """Real SQLite connection with Phase 6 schema (including audit_log)."""
    conn = init_db(str(tmp_path / "test.db"))
    yield conn
    conn.close()


def _record(
    db,
    actor="alice",
    role="admin",
    method="POST",
    path="/posture/run",
    status_code=200,
    body_excerpt=None,
    key=_KEY,
):
    """Helper: insert one audit row via record_audit."""
    return record_audit(
        conn=db,
        key=key,
        actor_username=actor,
        actor_role=role,
        method=method,
        path=path,
        status_code=status_code,
        body_excerpt=body_excerpt,
    )


# ---------------------------------------------------------------------------
# canonical_row — encoding contract
# ---------------------------------------------------------------------------


def test_canonical_row_deterministic():
    """Same inputs produce the same canonical bytes every call."""
    args = (None, "2026-01-01T00:00:00+00:00", "alice", "admin",
            "POST", "/posture/run", 200, None)
    b1 = canonical_row(*args)
    b2 = canonical_row(*args)
    assert b1 == b2, "canonical_row must be deterministic"


def test_canonical_row_returns_bytes():
    """canonical_row returns bytes (UTF-8 JSON array)."""
    result = canonical_row(None, "ts", "u", "r", "POST", "/p", 200, None)
    assert isinstance(result, bytes)


def test_canonical_row_field_order_matters():
    """Swapping any two fields produces different bytes."""
    base = canonical_row("prev", "ts", "alice", "admin", "POST", "/p", 200, "body")
    # Swap actor_username and actor_role
    swapped = canonical_row("prev", "ts", "admin", "alice", "POST", "/p", 200, "body")
    assert base != swapped, "Field order must be load-bearing in canonical_row"


def test_canonical_row_null_prev_hmac():
    """None prev_hmac encodes as JSON null (not the string 'None')."""
    b = canonical_row(None, "ts", "u", "r", "POST", "/p", 200, None)
    decoded = b.decode("utf-8")
    assert decoded.startswith("[null,"), f"Expected JSON null at start, got: {decoded[:30]}"


def test_canonical_row_string_prev_hmac():
    """A string prev_hmac encodes as a JSON string (quoted)."""
    b = canonical_row("abc123", "ts", "u", "r", "POST", "/p", 200, None)
    decoded = b.decode("utf-8")
    assert '"abc123"' in decoded, "prev_hmac string must appear quoted in JSON"


def test_canonical_row_status_code_is_integer():
    """status_code must encode as a JSON integer (no quotes)."""
    b = canonical_row(None, "ts", "u", "r", "POST", "/p", 403, None)
    decoded = b.decode("utf-8")
    # 403 should appear as bare int, not "403"
    assert ",403," in decoded or decoded.endswith(",403]"), (
        f"status_code should be bare integer in JSON, got: {decoded}"
    )


def test_canonical_row_body_excerpt_null_vs_string():
    """None and non-empty body_excerpt produce different bytes."""
    b_null = canonical_row(None, "ts", "u", "r", "POST", "/p", 200, None)
    b_str = canonical_row(None, "ts", "u", "r", "POST", "/p", 200, "body")
    assert b_null != b_str


# ---------------------------------------------------------------------------
# compute_row_hmac
# ---------------------------------------------------------------------------


def test_compute_row_hmac_deterministic():
    """Same key + canonical → same hex digest every call."""
    canon = canonical_row(None, "2026-01-01T00:00:00", "u", "r", "POST", "/p", 200, None)
    h1 = compute_row_hmac(_KEY, canon)
    h2 = compute_row_hmac(_KEY, canon)
    assert h1 == h2


def test_compute_row_hmac_returns_hex_string():
    """compute_row_hmac returns a lowercase hex string of length 64."""
    canon = canonical_row(None, "ts", "u", "r", "POST", "/p", 200, None)
    h = compute_row_hmac(_KEY, canon)
    assert isinstance(h, str)
    assert len(h) == 64
    assert all(c in "0123456789abcdef" for c in h)


def test_compute_row_hmac_different_keys_differ():
    """Different keys produce different digests."""
    canon = canonical_row(None, "ts", "u", "r", "POST", "/p", 200, None)
    h1 = compute_row_hmac(b"key-one-32bytes-padded-here----!", canon)
    h2 = compute_row_hmac(b"key-two-32bytes-padded-here----!", canon)
    assert h1 != h2


# ---------------------------------------------------------------------------
# record_audit + chain continuity
# ---------------------------------------------------------------------------


def test_record_audit_first_row_prev_hmac_null(db):
    """First row in an empty table has prev_hmac=NULL."""
    _record(db)
    row = db.execute("SELECT prev_hmac FROM audit_log WHERE id=1").fetchone()
    assert row is not None
    assert row[0] is None, f"First row prev_hmac must be NULL, got: {row[0]}"


def test_record_audit_chain_continues(db):
    """Second row's prev_hmac equals first row's row_hmac."""
    _record(db, path="/first")
    _record(db, path="/second")
    rows = db.execute(
        "SELECT id, prev_hmac, row_hmac FROM audit_log ORDER BY id ASC"
    ).fetchall()
    assert len(rows) == 2
    first_hmac = rows[0]["row_hmac"]
    second_prev = rows[1]["prev_hmac"]
    assert second_prev == first_hmac, (
        f"Second row prev_hmac {second_prev!r} must equal first row_hmac {first_hmac!r}"
    )


def test_record_audit_returns_row_id(db):
    """record_audit returns the new row's integer id."""
    row_id = _record(db)
    assert isinstance(row_id, int)
    assert row_id >= 1


def test_record_audit_chain_of_five(db):
    """Five consecutive inserts produce a correctly linked chain."""
    for i in range(5):
        _record(db, path=f"/step/{i}")

    rows = db.execute(
        "SELECT id, prev_hmac, row_hmac FROM audit_log ORDER BY id ASC"
    ).fetchall()
    assert len(rows) == 5
    assert rows[0]["prev_hmac"] is None
    for i in range(1, 5):
        assert rows[i]["prev_hmac"] == rows[i - 1]["row_hmac"], (
            f"Row {rows[i]['id']} prev_hmac should equal row {rows[i-1]['id']} row_hmac"
        )


def test_record_audit_stores_actor_fields(db):
    """record_audit stores actor_username and actor_role correctly."""
    _record(db, actor="bob", role="operator", method="DELETE", path="/rules/x/deploy")
    row = dict(db.execute("SELECT * FROM audit_log WHERE id=1").fetchone())
    assert row["actor_username"] == "bob"
    assert row["actor_role"] == "operator"
    assert row["method"] == "DELETE"
    assert row["path"] == "/rules/x/deploy"


def test_record_audit_sanitizes_body_excerpt(db):
    """Body excerpts pass through sanitize_alert_field (strips whitespace, bounds length).

    sanitize_alert_field strips leading/trailing whitespace and truncates to
    _MAX_FIELD_LEN. It does not strip internal bytes — that is by design (raw
    forensic value). What matters is that the field is stored and bounded.
    """
    # Leading/trailing whitespace should be stripped.
    padded = "   some body content   "
    _record(db, body_excerpt=padded)
    row = db.execute("SELECT body_excerpt FROM audit_log WHERE id=1").fetchone()
    stored = row[0]
    assert stored is not None
    assert stored == stored.strip(), "sanitize_alert_field must strip whitespace"


def test_record_audit_truncates_body_excerpt(db):
    """Body excerpts longer than 200 chars are truncated."""
    long_body = "x" * 500
    _record(db, body_excerpt=long_body)
    row = db.execute("SELECT body_excerpt FROM audit_log WHERE id=1").fetchone()
    assert len(row[0]) <= 200


def test_record_audit_handles_db_error(tmp_path):
    """A DB error in record_audit raises sqlite3.Error — caller must catch it.

    The middleware catches and logs; this test verifies the exception propagates
    so the caller is explicitly responsible for best-effort handling.

    Uses a real closed connection (not a mock) to trigger a genuine DB error.
    # @mock-exempt: closing a real connection is not mocking an internal — it
    #               exercises the real sqlite3 error path end-to-end.
    """
    conn = init_db(str(tmp_path / "err.db"))
    conn.close()  # close it to force a ProgrammingError on the next write

    with pytest.raises(Exception):
        record_audit(
            conn=conn,
            key=_KEY,
            actor_username="alice",
            actor_role="admin",
            method="POST",
            path="/posture/run",
            status_code=200,
            body_excerpt=None,
        )


# ---------------------------------------------------------------------------
# verify_chain
# ---------------------------------------------------------------------------


def test_verify_chain_empty_log(db):
    """Empty audit_log → intact=True, total_rows=0."""
    result = verify_chain(db, _KEY)
    assert result["intact"] is True
    assert result["total_rows"] == 0
    assert result["broken_at_id"] is None


def test_verify_chain_intact_after_clean_inserts(db):
    """N clean inserts → verify_chain returns intact=True."""
    for i in range(5):
        _record(db, path=f"/op/{i}")

    result = verify_chain(db, _KEY)
    assert result["intact"] is True
    assert result["total_rows"] == 5
    assert result["broken_at_id"] is None


def test_verify_chain_detects_tampered_field(db):
    """Manually changing a stored field breaks the chain at that row's id."""
    for i in range(4):
        _record(db, path=f"/op/{i}")

    # Tamper with row id=2's path field
    db.execute("UPDATE audit_log SET path='/tampered' WHERE id=2")
    db.commit()

    result = verify_chain(db, _KEY)
    assert result["intact"] is False
    assert result["broken_at_id"] == 2
    assert result["total_rows"] >= 1


def test_verify_chain_detects_inserted_row(db):
    """A forged row inserted with a wrong row_hmac breaks the chain."""
    _record(db, path="/real-row-1")
    _record(db, path="/real-row-2")

    # Insert a forged row between real rows — this will have the wrong prev_hmac
    # relative to what the subsequent real row expects.
    real_rows = db.execute(
        "SELECT row_hmac FROM audit_log ORDER BY id ASC"
    ).fetchall()
    # We can't easily insert between rows in SQLite AUTOINCREMENT, but we can
    # corrupt a row's row_hmac to simulate a forged replacement.
    db.execute(
        "UPDATE audit_log SET row_hmac='forged-hmac-value' WHERE id=1"
    )
    db.commit()

    result = verify_chain(db, _KEY)
    assert result["intact"] is False
    # Chain breaks at row 1 (bad hmac) or row 2 (bad prev_hmac) depending on
    # which check triggers first — either way intact is False.
    assert result["broken_at_id"] is not None


def test_verify_chain_detects_deleted_row(db):
    """Deleting a row causes the next row's prev_hmac to not match."""
    for i in range(4):
        _record(db, path=f"/op/{i}")

    # Delete row id=2 — row id=3's prev_hmac now points to row 2's hash,
    # but when we walk id order we'll see id=1, id=3, id=4.
    # Row 3's stored prev_hmac is id=2's row_hmac, but verify_chain tracks
    # the last-seen row_hmac (from id=1). They will differ.
    db.execute("DELETE FROM audit_log WHERE id=2")
    db.commit()

    result = verify_chain(db, _KEY)
    assert result["intact"] is False
    assert result["broken_at_id"] is not None


def test_verify_chain_wrong_key(db):
    """Using a different key than what was used for inserts breaks every row."""
    for i in range(3):
        _record(db, path=f"/op/{i}", key=_KEY)

    wrong_key = b"wrong-key-32bytes-padded-here---"
    result = verify_chain(db, wrong_key)
    assert result["intact"] is False
    assert result["broken_at_id"] == 1  # First row fails immediately


# ---------------------------------------------------------------------------
# list_audit_events / count_audit_events
# ---------------------------------------------------------------------------


def test_list_audit_events_newest_first(db):
    """list_audit_events returns rows in descending id order."""
    for i in range(3):
        _record(db, path=f"/step/{i}")

    rows = list_audit_events(db, limit=10)
    ids = [r["id"] for r in rows]
    assert ids == sorted(ids, reverse=True), "Rows should be newest-first (desc id)"


def test_list_audit_events_limit(db):
    """limit parameter is respected."""
    for i in range(10):
        _record(db, path=f"/step/{i}")

    rows = list_audit_events(db, limit=3)
    assert len(rows) == 3


def test_list_audit_events_actor_filter(db):
    """actor filter returns only rows matching that actor_username."""
    _record(db, actor="alice")
    _record(db, actor="bob")
    _record(db, actor="alice")

    rows = list_audit_events(db, actor="alice")
    assert all(r["actor_username"] == "alice" for r in rows)
    assert len(rows) == 2


def test_count_audit_events(db):
    """count_audit_events returns the total number of rows."""
    assert count_audit_events(db) == 0
    _record(db)
    _record(db)
    assert count_audit_events(db) == 2


def test_get_latest_audit_hmac_none_on_empty(db):
    """get_latest_audit_hmac returns None on an empty table."""
    assert get_latest_audit_hmac(db) is None


def test_get_latest_audit_hmac_returns_last(db):
    """get_latest_audit_hmac returns the row_hmac of the last inserted row."""
    _record(db, path="/first")
    _record(db, path="/second")
    latest = get_latest_audit_hmac(db)
    row = db.execute(
        "SELECT row_hmac FROM audit_log WHERE id = (SELECT MAX(id) FROM audit_log)"
    ).fetchone()
    assert latest == row[0]
