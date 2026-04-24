"""
Posture score computation tests — REQ-P0-P3-001, REQ-P0-P3-003.

Tests compute_posture_score_for_run() via synthetic DB fixtures covering:
  A. ART test at T, cluster window spans T, cluster has deployed=1 rule → pass=1
  B. ART test at T, no cluster exists → pass=0
  C. ART test at T, cluster exists but no deployed rule → pass=0
  Mixed: 3-test batch (A+B+C) → passes=1, total=3, score≈0.333

All tests use in-memory SQLite with real schema via init_db() and real
SQL from compute_posture_score_for_run(). No mocks — the scoring SQL is
the production code under test (DEC-POSTURE-001, Sacred Practice #5).

@decision DEC-POSTURE-001
@title Posture pass = cluster window overlap AND deployed rule — pure SQL join
@status accepted
@rationale See models.py compute_posture_score_for_run docstring.
"""

import json
from datetime import datetime, timezone, timedelta

import pytest

from agent.models import (
    compute_posture_score_for_run,
    get_posture_run,
    init_db,
    insert_posture_run,
    insert_posture_test_result,
    update_posture_run,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _iso(dt: datetime) -> str:
    return dt.isoformat()


def _seed_cluster(conn, cluster_id: str, window_start: str, window_end: str) -> None:
    """Insert a minimal cluster row."""
    conn.execute(
        """
        INSERT INTO clusters (id, src_ip, rule_id, window_start, window_end, alert_count, source)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        (cluster_id, "10.0.0.1", 5501, window_start, window_end, 1, "wazuh"),
    )
    conn.commit()


def _seed_rule(conn, rule_id: str, cluster_id: str, deployed: bool) -> None:
    """Insert a minimal rule row with the given deployed flag."""
    conn.execute(
        """
        INSERT INTO rules (id, cluster_id, rule_type, rule_content, syntax_valid, deployed)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (rule_id, cluster_id, "yara", "rule test {}", 1, 1 if deployed else 0),
    )
    conn.commit()


def _make_run(conn, n_tests: int, technique_ids: list[str]) -> int:
    """Insert a posture_runs row and return its id."""
    started_at = _now_iso()
    return insert_posture_run(conn, started_at, technique_ids, n_tests)


def _add_result(conn, run_id: int, technique_id: str, fired_at: str) -> int:
    """Insert a posture_test_results row at the given fired_at timestamp."""
    return insert_posture_test_result(
        conn,
        run_id=run_id,
        technique_id=technique_id,
        test_name=f"test-{technique_id}",
        fired_at=fired_at,
        exit_code=0,
        output="ok",
    )


# ---------------------------------------------------------------------------
# Scenario A: cluster window spans fired_at AND deployed rule → pass
# ---------------------------------------------------------------------------

def test_scenario_a_cluster_and_deployed_rule_passes():
    """ART test at T inside cluster window [T-5m, T+5m] with deployed rule → pass=1."""
    conn = init_db(":memory:")

    now = datetime.now(timezone.utc)
    fired_at = _iso(now)
    window_start = _iso(now - timedelta(minutes=5))
    window_end = _iso(now + timedelta(minutes=5))

    _seed_cluster(conn, "cluster-a", window_start, window_end)
    _seed_rule(conn, "rule-a-1", "cluster-a", deployed=True)

    run_id = _make_run(conn, 1, ["T1059.003"])
    _add_result(conn, run_id, "T1059.003", fired_at)

    result = compute_posture_score_for_run(conn, run_id)

    assert result["passes"] == 1, f"Expected passes=1, got {result['passes']}"
    assert result["total_tests"] == 1
    assert abs(result["score"] - 1.0) < 1e-9, f"Expected score=1.0, got {result['score']}"

    conn.close()


# ---------------------------------------------------------------------------
# Scenario B: no cluster → no pass
# ---------------------------------------------------------------------------

def test_scenario_b_no_cluster_no_pass():
    """ART test at T with no cluster in DB → pass=0."""
    conn = init_db(":memory:")

    fired_at = _now_iso()
    run_id = _make_run(conn, 1, ["T1053.003"])
    _add_result(conn, run_id, "T1053.003", fired_at)

    result = compute_posture_score_for_run(conn, run_id)

    assert result["passes"] == 0, f"Expected passes=0, got {result['passes']}"
    assert result["score"] == 0.0

    conn.close()


# ---------------------------------------------------------------------------
# Scenario C: cluster exists but no deployed rule → no pass
# ---------------------------------------------------------------------------

def test_scenario_c_cluster_no_deployed_rule_no_pass():
    """ART test inside cluster window but cluster has no deployed rule → pass=0."""
    conn = init_db(":memory:")

    now = datetime.now(timezone.utc)
    fired_at = _iso(now)
    window_start = _iso(now - timedelta(minutes=5))
    window_end = _iso(now + timedelta(minutes=5))

    _seed_cluster(conn, "cluster-c", window_start, window_end)
    # Rule exists but NOT deployed
    _seed_rule(conn, "rule-c-1", "cluster-c", deployed=False)

    run_id = _make_run(conn, 1, ["T1087.001"])
    _add_result(conn, run_id, "T1087.001", fired_at)

    result = compute_posture_score_for_run(conn, run_id)

    assert result["passes"] == 0, (
        f"Expected passes=0 (undeployed rule), got {result['passes']}"
    )
    assert result["score"] == 0.0

    conn.close()


# ---------------------------------------------------------------------------
# Mixed batch: A + B + C → passes=1, total=3, score≈0.333
# ---------------------------------------------------------------------------

def test_mixed_batch_score():
    """3-test batch: 1 pass (A) + 1 no-cluster (B) + 1 undeployed (C) → score≈0.333.

    Each test fires in a distinct non-overlapping time window so that the SQL
    time-window join can unambiguously determine which cluster (if any) each
    test's fired_at falls into. Overlapping windows would cause tests B and C
    to also match cluster-mix-a (which has a deployed rule), producing passes=3.

    Window layout (relative to base time T):
      cluster-mix-a: [T-30m, T-20m]  — deployed rule   — fired_a = T-25m → pass
      (gap)         : [T-20m, T-10m]  — no cluster      — fired_b = T-15m → no pass
      cluster-mix-c: [T-10m, T+0m]   — undeployed rule  — fired_c = T-5m  → no pass
    """
    conn = init_db(":memory:")

    base = datetime.now(timezone.utc)

    # Cluster A — deployed rule, window [T-30m, T-20m]
    a_start = _iso(base - timedelta(minutes=30))
    a_end   = _iso(base - timedelta(minutes=20))
    _seed_cluster(conn, "cluster-mix-a", a_start, a_end)
    _seed_rule(conn, "rule-mix-a", "cluster-mix-a", deployed=True)

    # Cluster C — undeployed rule, window [T-10m, T+0m]
    c_start = _iso(base - timedelta(minutes=10))
    c_end   = _iso(base)
    _seed_cluster(conn, "cluster-mix-c", c_start, c_end)
    _seed_rule(conn, "rule-mix-c", "cluster-mix-c", deployed=False)

    # No cluster covers the gap [T-20m, T-10m]

    run_id = _make_run(conn, 3, ["T1059.003", "T1053.003", "T1087.001"])

    fired_a = _iso(base - timedelta(minutes=25))  # inside cluster-mix-a (deployed) → pass
    fired_b = _iso(base - timedelta(minutes=15))  # in gap, no cluster → no pass
    fired_c = _iso(base - timedelta(minutes=5))   # inside cluster-mix-c (undeployed) → no pass

    _add_result(conn, run_id, "T1059.003", fired_a)
    _add_result(conn, run_id, "T1053.003", fired_b)
    _add_result(conn, run_id, "T1087.001", fired_c)

    result = compute_posture_score_for_run(conn, run_id)

    assert result["total_tests"] == 3
    assert result["passes"] == 1, f"Expected passes=1, got {result['passes']}"
    expected_score = 1 / 3
    assert abs(result["score"] - expected_score) < 1e-9, (
        f"Expected score≈{expected_score:.6f}, got {result['score']:.6f}"
    )

    conn.close()


# ---------------------------------------------------------------------------
# Edge: zero tests → score=0.0, no divide-by-zero
# ---------------------------------------------------------------------------

def test_zero_tests_no_divide_by_zero():
    """compute_posture_score_for_run on a run with total_tests=0 → score=0.0."""
    conn = init_db(":memory:")

    run_id = _make_run(conn, 0, [])
    result = compute_posture_score_for_run(conn, run_id)

    assert result["passes"] == 0
    assert result["score"] == 0.0

    conn.close()


# ---------------------------------------------------------------------------
# Edge: fired_at outside cluster window → no pass
# ---------------------------------------------------------------------------

def test_fired_at_outside_cluster_window_no_pass():
    """ART test fired BEFORE the cluster window starts → no pass (boundary)."""
    conn = init_db(":memory:")

    now = datetime.now(timezone.utc)
    # Cluster window is 10 minutes in the future
    window_start = _iso(now + timedelta(minutes=10))
    window_end = _iso(now + timedelta(minutes=15))

    _seed_cluster(conn, "cluster-future", window_start, window_end)
    _seed_rule(conn, "rule-future", "cluster-future", deployed=True)

    fired_at = _iso(now)  # before the window
    run_id = _make_run(conn, 1, ["T1059.003"])
    _add_result(conn, run_id, "T1059.003", fired_at)

    result = compute_posture_score_for_run(conn, run_id)

    assert result["passes"] == 0, (
        f"Expected no pass when fired_at is before cluster window, got passes={result['passes']}"
    )

    conn.close()


# ---------------------------------------------------------------------------
# Persistence: compute_posture_score_for_run updates posture_runs row in place
# ---------------------------------------------------------------------------

def test_compute_posture_score_updates_posture_runs_row():
    """compute_posture_score_for_run persists passes and score back to posture_runs."""
    conn = init_db(":memory:")

    now = datetime.now(timezone.utc)
    fired_at = _iso(now)
    window_start = _iso(now - timedelta(minutes=1))
    window_end = _iso(now + timedelta(minutes=1))

    _seed_cluster(conn, "cluster-persist", window_start, window_end)
    _seed_rule(conn, "rule-persist", "cluster-persist", deployed=True)

    run_id = _make_run(conn, 2, ["T1059.003", "T1053.003"])
    _add_result(conn, run_id, "T1059.003", fired_at)
    _add_result(conn, run_id, "T1053.003", fired_at)

    compute_posture_score_for_run(conn, run_id)

    row = dict(get_posture_run(conn, run_id))
    # Both tests fired inside the window with a deployed rule → both pass
    assert row["passes"] == 2, f"Expected passes=2, got {row['passes']}"
    assert abs(row["score"] - 1.0) < 1e-9

    conn.close()
