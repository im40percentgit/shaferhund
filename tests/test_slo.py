"""
Tests for agent/slo.py — posture SLO evaluator and webhook poster.

Test index:
  1. test_evaluate_slo_opens_breach_on_threshold_drop  — score below threshold opens slo_breaches row
  2. test_evaluate_slo_idempotent_when_breach_open     — second eval with open breach = noop (DEC-SLO-001)
  3. test_evaluate_slo_resolves_on_recovery            — score recovery closes open breach
  4. test_evaluate_slo_after_recovery_can_open_fresh_breach — post-resolve breach opens new row
  5. test_evaluate_slo_noop_when_no_runs               — empty DB = noop, no crash
  6. test_evaluate_slo_noop_when_score_above_and_no_breach — healthy score = noop
  7. test_fire_webhook_success_returns_status_none_err  — 200 response → (200, None)
  8. test_fire_webhook_500_marks_failed                — 500 response → (500, msg) (DEC-SLO-002)
  9. test_fire_webhook_network_error_no_retry          — connection error → (None, msg), 1 attempt

Design notes:
  @mock-exempt: httpx.post is an external HTTP boundary (DEC-SLO-002). Mocking it is
  correct per Sacred Practice #5 ("mocks are acceptable ONLY for external boundaries").
  All SQLite operations use real in-memory DBs via init_db(":memory:").

@decision DEC-SLO-001
@title Idempotency via slo_breaches table — tests verify one breach per window
@status accepted
@rationale Tests 2 and 4 verify the core invariant: a second evaluate_slo call
           while a breach is already open takes no action (no new row), and that
           after a breach resolves the next drop opens a fresh row. These are the
           two paths where idempotency can fail silently.

@decision DEC-SLO-002
@title No retry on webhook failure — tests verify single-attempt semantics
@status accepted
@rationale Tests 8 and 9 mock httpx.post and assert call_count == 1 after a
           failure. If retry logic were ever added, these assertions would catch
           the regression immediately.
"""

import sqlite3
from unittest.mock import MagicMock, patch

import pytest

from agent.models import (
    get_open_slo_breach,
    init_db,
    insert_posture_run,
    update_posture_run,
)
from agent.slo import evaluate_slo, fire_webhook


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_conn() -> sqlite3.Connection:
    """Return a fresh in-memory SQLite connection with full schema applied."""
    return init_db(":memory:")


def _make_settings(threshold: float = 0.7) -> object:
    """Return a minimal settings-like namespace for evaluate_slo."""
    class _Settings:
        posture_slo_threshold = threshold
    return _Settings()


def _insert_complete_run(conn: sqlite3.Connection, score: float) -> int:
    """Insert a posture_runs row with status='complete' at the given score.

    Returns the row id.
    """
    from datetime import datetime, timezone
    now = datetime.now(timezone.utc).isoformat()
    run_id = insert_posture_run(conn, started_at=now, technique_ids=["T1059"], total_tests=1)
    passes = 1 if score >= 1.0 else 0
    update_posture_run(
        conn,
        run_id=run_id,
        finished_at=now,
        passes=passes,
        score=score,
        status="complete",
        weighted_score=score,
    )
    return run_id


# ---------------------------------------------------------------------------
# Tests: evaluate_slo
# ---------------------------------------------------------------------------

def test_evaluate_slo_opens_breach_on_threshold_drop():
    """Score 0.5 below threshold 0.7 → slo_breaches row opened, action='opened'."""
    conn = _make_conn()
    settings = _make_settings(threshold=0.7)
    run_id = _insert_complete_run(conn, score=0.5)

    result = evaluate_slo(conn, settings)

    assert result["action"] == "opened", f"Expected 'opened', got: {result}"
    assert result["score"] == pytest.approx(0.5)
    assert result["run_id"] == run_id
    assert "breach_id" in result

    # Verify DB row
    breach = get_open_slo_breach(conn)
    assert breach is not None, "Expected an open slo_breaches row"
    assert breach["resolved_at"] is None
    assert breach["breach_score"] == pytest.approx(0.5)
    assert breach["threshold"] == pytest.approx(0.7)
    assert breach["posture_run_id"] == run_id

    conn.close()


def test_evaluate_slo_idempotent_when_breach_open():
    """DEC-SLO-001: second evaluate_slo with open breach and lower score = noop.

    Only one slo_breaches row should ever exist for a single breach window.
    """
    conn = _make_conn()
    settings = _make_settings(threshold=0.7)

    # First call — opens breach
    _insert_complete_run(conn, score=0.5)
    first = evaluate_slo(conn, settings)
    assert first["action"] == "opened"

    # Second call with even lower score — breach still open, must be noop
    _insert_complete_run(conn, score=0.4)
    second = evaluate_slo(conn, settings)
    assert second["action"] == "noop", f"Expected noop, got: {second}"
    assert second.get("reason") == "already in breach"

    # Exactly one slo_breaches row
    rows = conn.execute("SELECT COUNT(*) FROM slo_breaches").fetchone()[0]
    assert rows == 1, f"Expected 1 slo_breaches row, found {rows}"

    conn.close()


def test_evaluate_slo_resolves_on_recovery():
    """Score recovers above threshold → open breach row is closed, action='resolved'."""
    conn = _make_conn()
    settings = _make_settings(threshold=0.7)

    # Open a breach
    _insert_complete_run(conn, score=0.5)
    opened = evaluate_slo(conn, settings)
    assert opened["action"] == "opened"
    breach_id = opened["breach_id"]

    # Recovery run
    _insert_complete_run(conn, score=0.85)
    resolved = evaluate_slo(conn, settings)

    assert resolved["action"] == "resolved", f"Expected 'resolved', got: {resolved}"
    assert resolved["breach_id"] == breach_id
    assert resolved["score"] == pytest.approx(0.85)

    # DB row should be closed
    row = conn.execute(
        "SELECT resolved_at FROM slo_breaches WHERE id = ?", (breach_id,)
    ).fetchone()
    assert row is not None
    assert row["resolved_at"] is not None, "resolved_at should be set after recovery"

    # No open breach remaining
    assert get_open_slo_breach(conn) is None

    conn.close()


def test_evaluate_slo_after_recovery_can_open_fresh_breach():
    """After resolving a breach, a new score drop opens a second, separate breach row."""
    conn = _make_conn()
    settings = _make_settings(threshold=0.7)

    # Cycle 1: open and resolve
    _insert_complete_run(conn, score=0.5)
    evaluate_slo(conn, settings)  # opened
    _insert_complete_run(conn, score=0.85)
    evaluate_slo(conn, settings)  # resolved

    # Cycle 2: new drop
    _insert_complete_run(conn, score=0.4)
    fresh = evaluate_slo(conn, settings)
    assert fresh["action"] == "opened", f"Expected 'opened' for new breach, got: {fresh}"

    # Two total rows; second one is open
    rows = conn.execute("SELECT COUNT(*) FROM slo_breaches").fetchone()[0]
    assert rows == 2, f"Expected 2 slo_breaches rows, found {rows}"

    open_breach = get_open_slo_breach(conn)
    assert open_breach is not None
    assert open_breach["resolved_at"] is None
    assert open_breach["breach_score"] == pytest.approx(0.4)

    conn.close()


def test_evaluate_slo_noop_when_no_runs():
    """Empty DB (no posture_runs rows) → noop with reason, no crash, no breach row."""
    conn = _make_conn()
    settings = _make_settings(threshold=0.7)

    result = evaluate_slo(conn, settings)

    assert result["action"] == "noop", f"Expected noop, got: {result}"
    assert "no posture runs" in result.get("reason", "").lower()

    rows = conn.execute("SELECT COUNT(*) FROM slo_breaches").fetchone()[0]
    assert rows == 0

    conn.close()


def test_evaluate_slo_noop_when_score_above_and_no_breach():
    """Score 0.85 above threshold 0.7 with no open breach → noop, no breach row created."""
    conn = _make_conn()
    settings = _make_settings(threshold=0.7)
    _insert_complete_run(conn, score=0.85)

    result = evaluate_slo(conn, settings)

    assert result["action"] == "noop", f"Expected noop, got: {result}"

    rows = conn.execute("SELECT COUNT(*) FROM slo_breaches").fetchone()[0]
    assert rows == 0

    conn.close()


# ---------------------------------------------------------------------------
# Tests: fire_webhook
# ---------------------------------------------------------------------------

def test_fire_webhook_success_returns_status_none_err():
    """200 response from webhook endpoint → returns (200, None). (DEC-SLO-003)"""
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.is_success = True

    with patch("agent.slo.httpx.post", return_value=mock_resp) as mock_post:
        status_code, err = fire_webhook("http://example.com/hook", {"text": "test"})

    assert status_code == 200
    assert err is None
    mock_post.assert_called_once()


def test_fire_webhook_500_marks_failed():
    """DEC-SLO-002: 500 response → (500, error_msg). Mock called exactly once — no retry."""
    mock_resp = MagicMock()
    mock_resp.status_code = 500
    mock_resp.is_success = False

    with patch("agent.slo.httpx.post", return_value=mock_resp) as mock_post:
        status_code, err = fire_webhook("http://example.com/hook", {"text": "test"})

    assert status_code == 500
    assert err is not None
    assert "500" in err
    # Exactly one attempt — no retry (DEC-SLO-002)
    assert mock_post.call_count == 1


def test_fire_webhook_network_error_no_retry():
    """DEC-SLO-002: network error → (None, str(exc)). Mock called exactly once — no retry."""
    with patch("agent.slo.httpx.post", side_effect=ConnectionError("timeout")) as mock_post:
        status_code, err = fire_webhook("http://example.com/hook", {"text": "test"})

    assert status_code is None
    assert err is not None
    assert len(err) > 0
    # Exactly one attempt — no retry (DEC-SLO-002)
    assert mock_post.call_count == 1


# ---------------------------------------------------------------------------
# Regression test: DEC-SLO-004 — callable() misfire on sqlite3.Connection
# ---------------------------------------------------------------------------

def test_evaluator_loop_accepts_raw_connection(tmp_path):
    """Regression for the callable(sqlite3.Connection) bug — DEC-SLO-004.

    sqlite3.Connection has __call__ (C extension), so callable(conn) returns True
    for a raw connection. The old dispatch called conn() and raised TypeError every
    cycle, silently swallowed by the broad except. In production (main.py passes _db
    directly) the SLO evaluator never inserted a breach row regardless of posture.

    Fix: isinstance(conn_factory, sqlite3.Connection) distinguishes a raw connection
    from a factory function without the false positive.

    This test exercises the async loop with a raw connection (matching the production
    wiring at agent/main.py) and asserts at least one breach row is created.
    """
    import asyncio
    from agent.slo import slo_evaluator_loop

    db_path = str(tmp_path / "test_regression.db")
    conn = init_db(db_path)  # init_db creates the schema and returns a Connection

    # Insert a posture run well below the 0.7 threshold to guarantee a breach
    run_id = _insert_complete_run(conn, score=0.4)

    class _Settings:
        posture_slo_enabled = True
        posture_slo_threshold = 0.7
        posture_slo_webhook_url = ""
        posture_slo_eval_interval_seconds = 1

    settings = _Settings()

    async def _run():
        task = asyncio.create_task(
            slo_evaluator_loop(conn, settings, interval_seconds=1)
        )
        await asyncio.sleep(2.5)
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass

    asyncio.run(_run())

    breaches = conn.execute(
        "SELECT id, breach_score, resolved_at FROM slo_breaches"
    ).fetchall()
    conn.close()

    assert len(breaches) == 1, (
        f"Expected 1 breach row (loop must have evaluated), got {len(breaches)}. "
        "This likely means the callable() misfire is still present."
    )
    assert breaches[0][1] == pytest.approx(0.4), f"Unexpected breach_score: {breaches[0][1]}"
    assert breaches[0][2] is None, "Breach should be open (resolved_at NULL)"
