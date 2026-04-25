"""
Tests for agent/recommendations.py (Phase 4 Wave B, REQ-P0-P4-002).

Covers:
  1. is_destructive — exact match
  2. is_destructive — sub-technique parent match
  3. is_destructive — safe technique returns False
  4. execute_recommendation — pending → executed (non-destructive, force=False)
  5. execute_recommendation — destructive + force=False → rejected, row unchanged
  6. execute_recommendation — destructive + force=True → executed
  7. execute_recommendation — already-executed row → 400-equivalent dict

# @mock-exempt: run_batch is called with an injectable executor (DEC-REDTEAM-003)
# so no real subprocess or container is required. DB is real in-memory SQLite.
"""

from unittest.mock import patch, MagicMock

import pytest

from agent.models import (
    init_db,
    insert_attack_recommendation,
    get_attack_recommendation,
)
from agent.recommendations import (
    DESTRUCTIVE_TECHNIQUES,
    execute_recommendation,
    is_destructive,
)


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------


def _fresh_conn():
    return init_db(":memory:")


def _fake_executor(container_name: str, command_hint: str) -> tuple[int, str]:
    """Injectable executor: always succeeds with exit_code=0."""
    return 0, f"fake output for: {command_hint}"


def _seed_pending(conn, technique_id: str = "T1059.003", severity: str = "High") -> int:
    """Insert a pending recommendation and return its id."""
    return insert_attack_recommendation(
        conn=conn,
        technique_id=technique_id,
        reason="Test reason for recommendation",
        severity=severity,
        cluster_id=None,
    )


# ---------------------------------------------------------------------------
# Test 1: is_destructive — exact match
# ---------------------------------------------------------------------------


def test_is_destructive_exact_match():
    """T1486 is in DESTRUCTIVE_TECHNIQUES → True."""
    assert "T1486" in DESTRUCTIVE_TECHNIQUES, "T1486 (ransomware) must be in allowlist"
    assert is_destructive("T1486") is True


def test_is_destructive_all_allowlisted_techniques():
    """Every technique in DESTRUCTIVE_TECHNIQUES returns True from is_destructive."""
    for tid in DESTRUCTIVE_TECHNIQUES:
        assert is_destructive(tid) is True, f"Expected is_destructive({tid!r}) == True"


# ---------------------------------------------------------------------------
# Test 2: is_destructive — sub-technique parent match
# ---------------------------------------------------------------------------


def test_is_destructive_subtechnique():
    """T1485.001 matches parent T1485 → True (DEC-RECOMMEND-004)."""
    assert "T1485" in DESTRUCTIVE_TECHNIQUES, "T1485 must be in allowlist for parent-match test"
    assert is_destructive("T1485.001") is True


def test_is_destructive_subtechnique_t1486():
    """T1486.001 matches parent T1486 → True."""
    assert is_destructive("T1486.001") is True


def test_is_destructive_subtechnique_t1561():
    """T1561.002 (Disk Structure Wipe) matches parent T1561 → True."""
    assert is_destructive("T1561.002") is True


# ---------------------------------------------------------------------------
# Test 3: is_destructive — safe technique
# ---------------------------------------------------------------------------


def test_is_destructive_safe_technique():
    """T1059 (Command and Scripting Interpreter) is NOT destructive → False."""
    assert is_destructive("T1059") is False


def test_is_destructive_safe_subtechnique():
    """T1059.003 (Windows Command Shell) is NOT destructive → False."""
    assert is_destructive("T1059.003") is False


def test_is_destructive_empty_string():
    """Empty string → False (no crash)."""
    assert is_destructive("") is False


def test_is_destructive_unknown_technique():
    """Unknown technique ID returns False (fail-closed)."""
    assert is_destructive("T9999") is False


# ---------------------------------------------------------------------------
# Test 4: execute_recommendation — pending → executed (non-destructive)
# ---------------------------------------------------------------------------


def test_execute_recommendation_pending_to_executed():
    """Non-destructive pending row → status='executed', posture_run_id set."""
    conn = _fresh_conn()
    rec_id = _seed_pending(conn, technique_id="T1059.003", severity="High")

    result = execute_recommendation(
        conn=conn,
        recommendation_id=rec_id,
        force=False,
        target_container="test-container",
        executor=_fake_executor,
    )

    assert result["status"] == "executed", f"Expected 'executed', got: {result}"
    assert result["run_id"] is not None, "run_id must be set after execution"
    assert result["recommendation_id"] == rec_id
    assert result["error"] is None

    # Verify DB row flipped to 'executed'
    row = get_attack_recommendation(conn, rec_id)
    assert row is not None
    assert row["status"] == "executed"
    assert row["executed_at"] is not None
    assert row["posture_run_id"] == result["run_id"]

    conn.close()


# ---------------------------------------------------------------------------
# Test 5: execute_recommendation — destructive + force=False → rejected
# ---------------------------------------------------------------------------


def test_execute_recommendation_destructive_no_force():
    """Destructive technique + force=False → rejected; row stays pending."""
    conn = _fresh_conn()
    rec_id = _seed_pending(conn, technique_id="T1486", severity="Critical")

    result = execute_recommendation(
        conn=conn,
        recommendation_id=rec_id,
        force=False,
        target_container="test-container",
        executor=_fake_executor,
    )

    assert result["status"] == "rejected", f"Expected 'rejected', got: {result}"
    assert result["run_id"] is None
    assert "force=true" in result["error"].lower() or "force" in result["error"], (
        f"Error message should mention force=true: {result['error']}"
    )

    # Row must still be 'pending'
    row = get_attack_recommendation(conn, rec_id)
    assert row["status"] == "pending", (
        f"Row must remain 'pending' after destructive rejection, got: {row['status']}"
    )

    conn.close()


# ---------------------------------------------------------------------------
# Test 6: execute_recommendation — destructive + force=True → executed
# ---------------------------------------------------------------------------


def test_execute_recommendation_destructive_with_force():
    """Destructive technique + force=True → executed (DEC-RECOMMEND-002 bypass)."""
    conn = _fresh_conn()
    rec_id = _seed_pending(conn, technique_id="T1486", severity="Critical")

    result = execute_recommendation(
        conn=conn,
        recommendation_id=rec_id,
        force=True,
        target_container="test-container",
        executor=_fake_executor,
    )

    assert result["status"] == "executed", f"Expected 'executed' with force=True, got: {result}"
    assert result["run_id"] is not None

    # Row flipped
    row = get_attack_recommendation(conn, rec_id)
    assert row["status"] == "executed"
    assert row["posture_run_id"] == result["run_id"]

    conn.close()


# ---------------------------------------------------------------------------
# Test 7: execute_recommendation — already-executed row
# ---------------------------------------------------------------------------


def test_execute_recommendation_already_executed():
    """Row with status='executed' → already_executed; row unchanged."""
    conn = _fresh_conn()
    rec_id = _seed_pending(conn, technique_id="T1059.003", severity="Medium")

    # First execute succeeds
    first = execute_recommendation(
        conn=conn,
        recommendation_id=rec_id,
        force=False,
        target_container="test-container",
        executor=_fake_executor,
    )
    assert first["status"] == "executed"

    # Second execute should be rejected
    second = execute_recommendation(
        conn=conn,
        recommendation_id=rec_id,
        force=False,
        target_container="test-container",
        executor=_fake_executor,
    )

    assert second["status"] == "already_executed", (
        f"Expected 'already_executed', got: {second}"
    )
    assert second["run_id"] is None
    assert "executed" in second["error"].lower()

    # Row still shows 'executed' (not mutated again)
    row = get_attack_recommendation(conn, rec_id)
    assert row["status"] == "executed"

    conn.close()


# ---------------------------------------------------------------------------
# Test 8: execute_recommendation — not found
# ---------------------------------------------------------------------------


def test_execute_recommendation_not_found():
    """Non-existent recommendation_id → not_found status."""
    conn = _fresh_conn()

    result = execute_recommendation(
        conn=conn,
        recommendation_id=99999,
        force=False,
        target_container="test-container",
        executor=_fake_executor,
    )

    assert result["status"] == "not_found"
    assert result["run_id"] is None

    conn.close()


# ---------------------------------------------------------------------------
# Test 9: DESTRUCTIVE_TECHNIQUES is a frozenset (immutable at runtime)
# ---------------------------------------------------------------------------


def test_destructive_techniques_is_frozenset():
    """DESTRUCTIVE_TECHNIQUES must be a frozenset — immutable, code-resident (DEC-RECOMMEND-002)."""
    assert isinstance(DESTRUCTIVE_TECHNIQUES, frozenset), (
        f"DESTRUCTIVE_TECHNIQUES must be frozenset, got {type(DESTRUCTIVE_TECHNIQUES)}"
    )


def test_destructive_techniques_cannot_be_mutated():
    """Attempting to add to DESTRUCTIVE_TECHNIQUES raises AttributeError."""
    with pytest.raises(AttributeError):
        DESTRUCTIVE_TECHNIQUES.add("T1059")  # type: ignore[attr-defined]


# ---------------------------------------------------------------------------
# Test 10: sub-technique with no parent match is safe
# ---------------------------------------------------------------------------


def test_is_destructive_subtechnique_safe_parent():
    """T1059.003 → parent T1059 is not in DESTRUCTIVE_TECHNIQUES → False."""
    assert "T1059" not in DESTRUCTIVE_TECHNIQUES
    assert is_destructive("T1059.003") is False
