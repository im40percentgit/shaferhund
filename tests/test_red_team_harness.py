"""
ART harness unit tests — REQ-P0-P3-001, REQ-P0-P3-003.

Tests the red_team module in isolation:
  1. load_atomic_tests parses the fixture YAML and returns the expected entries.
  2. run_batch with a fake executor creates correct posture_runs +
     posture_test_results rows.
  3. run_batch with an executor that raises records status='failed'.
  4. POST /posture/run returns 200 with a run_id; the DB row is visible
     immediately (status='running'), and after a brief async yield the
     background task completes (mocked run_batch).

# @mock-exempt: _default_executor (podman exec) is the external container
# boundary.  Tests inject a fake via the executor= parameter (DEC-REDTEAM-003).
# run_batch itself is tested against its real implementation; only the executor
# callable is replaced.  For the route test, run_batch is patched at module
# level so no subprocess is spawned.

@decision DEC-REDTEAM-003
@title Injectable executor confirms the test-isolation pattern in practice
@status accepted
@rationale See red_team.py module docstring. Every test that exercises
           run_batch() passes a fake executor so no container or subprocess
           is required. The fake returns (0, "ok") for success and raises for
           the failure scenario. The real _default_executor is not called in
           any test — the external boundary is fully mocked.
"""

import asyncio
import json
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest
from fastapi.testclient import TestClient

import agent.main as main_module
from agent.models import init_db, get_posture_run, list_posture_runs
from agent.red_team import load_atomic_tests, run_batch

# ---------------------------------------------------------------------------
# Fixture paths
# ---------------------------------------------------------------------------

FIXTURE_YAML = (
    Path(__file__).parent / "fixtures" / "atomic_test_sample.yaml"
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_fake_executor(exit_code: int = 0, output: str = "ok"):
    """Return an executor callable that always returns (exit_code, output)."""
    def _fake(container_name: str, command_hint: str) -> tuple[int, str]:
        return exit_code, output
    return _fake


def _make_raising_executor(exc: Exception):
    """Return an executor callable that always raises exc."""
    def _raise(container_name: str, command_hint: str) -> tuple[int, str]:
        raise exc
    return _raise


def _make_settings(tmp_path) -> SimpleNamespace:
    return SimpleNamespace(
        shaferhund_token="",
        rules_dir=str(tmp_path / "rules"),
        db_path=":memory:",
        alerts_file="/dev/null",
        suricata_eve_file="/dev/null",
        triage_hourly_budget=20,
        AUTO_DEPLOY_ENABLED=False,
        sigmac_available=False,
        sigmac_version=None,
        art_tests_file=str(FIXTURE_YAML),
        redteam_target_container="test-target",
        posture_run_schedule_seconds=0,
    )


def _make_client(tmp_path):
    """Return (TestClient, conn) with module singletons patched."""
    (tmp_path / "rules").mkdir(exist_ok=True)
    conn = init_db(":memory:")
    settings = _make_settings(tmp_path)

    main_module._db = conn
    main_module._settings = settings
    main_module._triage_queue = None
    main_module._poller_healthy = False
    main_module._last_poll_at = None

    client = TestClient(main_module.app, raise_server_exceptions=True)
    return client, conn


# ---------------------------------------------------------------------------
# 1. load_atomic_tests
# ---------------------------------------------------------------------------

def test_load_atomic_tests_returns_expected_count():
    """load_atomic_tests parses the fixture YAML and returns 3 entries."""
    tests = load_atomic_tests(str(FIXTURE_YAML))
    assert len(tests) == 3, f"Expected 3 test entries, got {len(tests)}"


def test_load_atomic_tests_entry_has_required_fields():
    """Each entry has technique_id, test_name, command_or_script_hint."""
    tests = load_atomic_tests(str(FIXTURE_YAML))
    for t in tests:
        assert "technique_id" in t, f"Missing technique_id in {t}"
        assert "test_name" in t, f"Missing test_name in {t}"
        assert "command_or_script_hint" in t, f"Missing command_or_script_hint in {t}"


def test_load_atomic_tests_technique_ids():
    """Fixture YAML contains exactly T1059.003, T1053.003, T1087.001."""
    tests = load_atomic_tests(str(FIXTURE_YAML))
    ids = [t["technique_id"] for t in tests]
    assert "T1059.003" in ids
    assert "T1053.003" in ids
    assert "T1087.001" in ids


def test_load_atomic_tests_missing_file():
    """load_atomic_tests raises FileNotFoundError for non-existent path."""
    with pytest.raises(FileNotFoundError):
        load_atomic_tests("/tmp/does-not-exist-art.yaml")


# ---------------------------------------------------------------------------
# 2. run_batch — success path
# ---------------------------------------------------------------------------

def test_run_batch_creates_posture_runs_row():
    """run_batch inserts a posture_runs row and returns a valid run_id."""
    conn = init_db(":memory:")
    tests = load_atomic_tests(str(FIXTURE_YAML))
    executor = _make_fake_executor(exit_code=0, output="test output")

    run_id = run_batch(conn, tests, "test-target", executor=executor)

    assert isinstance(run_id, int) and run_id > 0, f"Expected positive int run_id, got {run_id!r}"
    row = get_posture_run(conn, run_id)
    assert row is not None, "posture_runs row not found after run_batch"
    conn.close()


def test_run_batch_creates_correct_column_values():
    """posture_runs row has correct total_tests, status, technique_ids."""
    conn = init_db(":memory:")
    tests = load_atomic_tests(str(FIXTURE_YAML))
    executor = _make_fake_executor()

    run_id = run_batch(conn, tests, "test-target", executor=executor)

    row = dict(get_posture_run(conn, run_id))
    assert row["total_tests"] == len(tests), (
        f"total_tests={row['total_tests']}, expected {len(tests)}"
    )
    assert row["status"] == "complete", f"Expected status='complete', got {row['status']!r}"
    technique_ids_stored = json.loads(row["technique_ids"])
    assert isinstance(technique_ids_stored, list)
    assert len(technique_ids_stored) == len(tests)
    assert row["started_at"] is not None
    assert row["finished_at"] is not None
    conn.close()


def test_run_batch_creates_posture_test_results_rows():
    """run_batch inserts one posture_test_results row per test."""
    conn = init_db(":memory:")
    tests = load_atomic_tests(str(FIXTURE_YAML))
    executor = _make_fake_executor(exit_code=0, output="stdout line")

    run_id = run_batch(conn, tests, "test-target", executor=executor)

    rows = conn.execute(
        "SELECT * FROM posture_test_results WHERE run_id = ?", (run_id,)
    ).fetchall()
    assert len(rows) == len(tests), (
        f"Expected {len(tests)} result rows, got {len(rows)}"
    )
    for row in rows:
        assert row["technique_id"] in ("T1059.003", "T1053.003", "T1087.001")
        assert row["exit_code"] == 0
        assert row["fired_at"] is not None
    conn.close()


# ---------------------------------------------------------------------------
# 3. run_batch — failure path (executor raises)
# ---------------------------------------------------------------------------

def test_run_batch_executor_raises_sets_failed_status():
    """When executor raises on every test, posture_runs.status ends as 'failed'."""
    conn = init_db(":memory:")
    tests = load_atomic_tests(str(FIXTURE_YAML))
    # Raise on every call
    raising_executor = _make_raising_executor(RuntimeError("podman not found"))

    run_id = run_batch(conn, tests, "test-target", executor=raising_executor)

    row = dict(get_posture_run(conn, run_id))
    assert row["status"] == "failed", (
        f"Expected status='failed' when executor raises, got {row['status']!r}"
    )
    conn.close()


def test_run_batch_executor_raises_still_writes_result_rows():
    """Even when executor raises, posture_test_results rows are inserted (with negative exit_code)."""
    conn = init_db(":memory:")
    tests = load_atomic_tests(str(FIXTURE_YAML))
    raising_executor = _make_raising_executor(OSError("no such container"))

    run_id = run_batch(conn, tests, "test-target", executor=raising_executor)

    rows = conn.execute(
        "SELECT * FROM posture_test_results WHERE run_id = ?", (run_id,)
    ).fetchall()
    # All tests still get rows; exit_code should be -1 (from the catch block)
    assert len(rows) == len(tests)
    for row in rows:
        assert row["exit_code"] == -1
    conn.close()


# ---------------------------------------------------------------------------
# 4. POST /posture/run — route test
# ---------------------------------------------------------------------------

def test_posture_run_route_returns_run_id(tmp_path):
    """POST /posture/run returns 200 with {run_id, status='running'}."""
    client, conn = _make_client(tmp_path)

    # Patch run_batch at the red_team module level so no subprocess is called.
    # The fake immediately marks the row complete (as the real run_batch would).
    def _fake_run_batch(db_conn, tests, container, executor=None):
        from agent.models import update_posture_run
        from datetime import datetime, timezone
        # Find the most recently inserted running row
        row = db_conn.execute(
            "SELECT id FROM posture_runs WHERE status='running' ORDER BY id DESC LIMIT 1"
        ).fetchone()
        if row:
            update_posture_run(
                db_conn,
                run_id=row["id"],
                finished_at=datetime.now(timezone.utc).isoformat(),
                passes=0,
                score=0.0,
                status="complete",
            )
        return row["id"] if row else 1

    with patch("agent.red_team.run_batch", side_effect=_fake_run_batch):
        resp = client.post("/posture/run")

    assert resp.status_code == 200, f"Expected 200, got {resp.status_code}: {resp.text}"
    data = resp.json()
    assert "run_id" in data, f"Missing run_id in response: {data}"
    assert data["status"] == "running", f"Expected status='running', got {data['status']!r}"
    assert isinstance(data["run_id"], int) and data["run_id"] > 0

    conn.close()


def test_posture_run_route_inserts_db_row(tmp_path):
    """After POST /posture/run, a posture_runs row exists in the DB."""
    client, conn = _make_client(tmp_path)

    with patch("agent.red_team.run_batch", return_value=1):
        resp = client.post("/posture/run")

    assert resp.status_code == 200
    run_id = resp.json()["run_id"]

    # Row must exist immediately (inserted synchronously before the task fires)
    row = get_posture_run(conn, run_id)
    assert row is not None, f"posture_runs row {run_id} not found after POST /posture/run"

    conn.close()


def test_posture_run_route_requires_auth(tmp_path):
    """POST /posture/run returns 401 when token is set and no auth header provided."""
    (tmp_path / "rules").mkdir(exist_ok=True)
    conn = init_db(":memory:")
    settings = _make_settings(tmp_path)
    settings.shaferhund_token = "secret999"

    main_module._db = conn
    main_module._settings = settings
    main_module._triage_queue = None
    main_module._poller_healthy = False
    main_module._last_poll_at = None

    client = TestClient(main_module.app, raise_server_exceptions=True)
    resp = client.post("/posture/run")
    assert resp.status_code == 401, (
        f"Expected 401 for unauthenticated /posture/run, got {resp.status_code}"
    )
    conn.close()
