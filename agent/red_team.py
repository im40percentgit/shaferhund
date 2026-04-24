"""
Atomic Red Team harness for Shaferhund Phase 3 (REQ-P0-P3-001).

Loads a declarative list of ART test definitions from atomic_tests.yaml,
executes them against a target container, and records results in the
``posture_runs`` + ``posture_test_results`` tables. The final posture score
is computed via a SQL join (DEC-POSTURE-001) that checks whether each test's
fired_at timestamp falls inside a cluster window that has a deployed rule.

Design decisions:
  - No auto-discovery of the upstream ART repo filesystem (DEC-REDTEAM-002).
    The declarative yaml is the controlled test surface.
  - Tests execute via an injectable executor function (DEC-REDTEAM-003) so
    unit tests can inject a fake without needing a running container.
  - The scheduled-run mechanism is a simple asyncio.Task sleep loop, not a
    crontab expression. POSTURE_RUN_SCHEDULE_SECONDS=0 disables scheduling
    (ad-hoc POST /posture/run only). Phase 4 can promote this to a real
    scheduler if needed (DEC-REDTEAM-001).
  - ART events flow through the existing Wazuh tailer (DEC-REDTEAM-001):
    zero new tailer code here. The redteam-target container runs a Wazuh
    agent, so its alerts appear in alerts.json automatically.

@decision DEC-REDTEAM-003
@title Injectable executor function for ART test isolation in unit tests
@status accepted
@rationale run_batch() accepts an optional ``executor`` callable so tests can
           inject a fake that returns (exit_code, output) without spawning
           real subprocesses or requiring a running container. The default
           executor uses subprocess.run with podman exec. This follows
           Sacred Practice #5 (real implementations, mock only at external
           boundaries) — the external boundary here is the container runtime.

@decision DEC-REDTEAM-001
@title Scheduled harness only — no orchestrator tool for ART in Phase 3
@status accepted
@rationale The orchestrator is already at the 7-tool limit (DEC-ORCH-003).
           Adding a run_posture_test tool would mix reactive triage with
           proactive red-team scheduling concerns. Phase 3 scope is a simple
           scheduled/ad-hoc harness. Dynamic orchestrator integration is
           a Phase 4 concern.

@decision DEC-POSTURE-002
@title POSTURE_RUN_SCHEDULE_SECONDS=0 disables scheduler; >0 enables interval loop
@status accepted
@rationale A simple sleep loop avoids a cron-expression parser dependency.
           Operators who want fine-grained scheduling (e.g. 03:00 daily) can
           wrap the POST /posture/run endpoint in an external cron job.
           The interval approach is simpler, testable, and sufficient for
           Phase 3 scope.
"""

import asyncio
import json
import logging
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Optional

import yaml

from .models import (
    compute_posture_score_for_run,
    insert_posture_run,
    insert_posture_test_result,
    update_posture_run,
)

log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Types
# ---------------------------------------------------------------------------

# An executor callable accepts (container_name, command_hint) and returns
# (exit_code: int, output: str). The default uses podman exec; tests inject a fake.
ExecutorFn = Callable[[str, str], tuple[int, str]]

# ---------------------------------------------------------------------------
# YAML loader
# ---------------------------------------------------------------------------


def load_atomic_tests(path: str) -> list[dict]:
    """Parse atomic_tests.yaml and return the list of test definition dicts.

    Each dict has at minimum:
        technique_id (str)           — MITRE ATT&CK ID, e.g. 'T1059.003'
        test_name (str)              — human-readable label
        command_or_script_hint (str) — command executed via the target container
        expected_wazuh_rule_ids (list[int]) — optional, for scoring hints

    Args:
        path: Filesystem path to the YAML file (absolute or relative to cwd).

    Returns:
        List of test dicts. Empty list if the file is missing or malformed.

    Raises:
        FileNotFoundError: If path does not exist.
        yaml.YAMLError: If the file is not valid YAML.
        KeyError: If the 'tests' top-level key is absent.
    """
    p = Path(path)
    raw = p.read_text(encoding="utf-8")
    data = yaml.safe_load(raw)
    if not isinstance(data, dict) or "tests" not in data:
        raise KeyError(f"atomic_tests.yaml must have a top-level 'tests' key, got: {list(data.keys()) if isinstance(data, dict) else type(data)}")
    tests = data["tests"]
    if not isinstance(tests, list):
        raise KeyError(f"'tests' must be a list, got {type(tests)}")
    log.info("Loaded %d atomic tests from %s", len(tests), path)
    return tests


# ---------------------------------------------------------------------------
# Default executor (podman exec)
# ---------------------------------------------------------------------------


def _default_executor(container_name: str, command_hint: str) -> tuple[int, str]:
    """Execute a command inside a container via podman exec.

    This is the real executor used in production. Tests inject a fake via the
    ``executor`` parameter of run_batch() (DEC-REDTEAM-003).

    Args:
        container_name: The container name/id to exec into.
        command_hint:   The shell command string to run inside the container.

    Returns:
        Tuple of (exit_code, combined_output).
    """
    try:
        result = subprocess.run(
            ["podman", "exec", container_name, "/bin/bash", "-c", command_hint],
            capture_output=True,
            text=True,
            timeout=30,
        )
        combined = (result.stdout or "") + (result.stderr or "")
        return result.returncode, combined
    except subprocess.TimeoutExpired:
        log.warning("ART test timed out in container %s", container_name)
        return -1, "TIMEOUT"
    except FileNotFoundError:
        log.warning("podman not found — cannot exec into container %s", container_name)
        return -1, "podman not found"
    except Exception as exc:
        log.warning("Executor error for container %s: %s", container_name, exc)
        return -1, str(exc)


# ---------------------------------------------------------------------------
# Core batch runner
# ---------------------------------------------------------------------------


def run_batch(
    conn,
    tests: list[dict],
    target_container: str,
    executor: Optional[ExecutorFn] = None,
) -> int:
    """Run all ART tests against target_container and record results.

    Creates a posture_runs row with status='running', executes each test
    sequentially via the executor, records per-test results in
    posture_test_results, then calls compute_posture_score_for_run to compute
    passes/score via SQL join. Updates the posture_runs row to status='complete'
    or 'failed' on completion.

    Args:
        conn:             Open SQLite connection.
        tests:            List of test dicts from load_atomic_tests().
        target_container: Container name to exec commands into.
        executor:         Optional injectable executor fn (default: _default_executor).
                          Signature: (container_name, command_hint) -> (exit_code, output).

    Returns:
        The posture_runs.id of the created run.

    Raises:
        Does NOT raise — errors are caught and recorded as status='failed'.

    @decision DEC-REDTEAM-003
    @title Injectable executor — production uses podman exec, tests inject a fake
    @status accepted
    @rationale See module docstring.
    """
    if executor is None:
        executor = _default_executor

    started_at = datetime.now(timezone.utc).isoformat()
    technique_ids = [t.get("technique_id", "unknown") for t in tests]
    total_tests = len(tests)

    run_id = insert_posture_run(conn, started_at, technique_ids, total_tests)
    log.info(
        "Posture run %d started: %d tests against container=%s",
        run_id, total_tests, target_container,
    )

    overall_status = "complete"
    try:
        for test in tests:
            technique_id = test.get("technique_id", "unknown")
            test_name = test.get("test_name", "")
            command = test.get("command_or_script_hint", "echo 'no-op'")
            # Strip YAML block-scalar trailing whitespace
            if isinstance(command, str):
                command = command.strip()

            fired_at = datetime.now(timezone.utc).isoformat()
            log.info(
                "ART run %d: executing technique=%s name=%r",
                run_id, technique_id, test_name,
            )

            try:
                exit_code, output = executor(target_container, command)
            except Exception as exc:
                log.warning(
                    "ART run %d: executor raised for technique=%s: %s",
                    run_id, technique_id, exc,
                )
                exit_code = -1
                output = f"executor exception: {exc}"
                overall_status = "failed"

            insert_posture_test_result(
                conn,
                run_id=run_id,
                technique_id=technique_id,
                test_name=test_name,
                fired_at=fired_at,
                exit_code=exit_code,
                output=output,
            )

            log.info(
                "ART run %d: technique=%s exit_code=%d",
                run_id, technique_id, exit_code,
            )

    except Exception as exc:
        log.error("ART run %d: batch loop error: %s", run_id, exc, exc_info=True)
        overall_status = "failed"

    # Compute score via SQL join (DEC-POSTURE-001)
    try:
        score_result = compute_posture_score_for_run(conn, run_id)
        passes = score_result["passes"]
        score = score_result["score"]
    except Exception as exc:
        log.error("ART run %d: score computation failed: %s", run_id, exc)
        passes = 0
        score = 0.0
        overall_status = "failed"

    finished_at = datetime.now(timezone.utc).isoformat()
    update_posture_run(
        conn,
        run_id=run_id,
        finished_at=finished_at,
        passes=passes,
        score=score,
        status=overall_status,
    )

    log.info(
        "Posture run %d complete: status=%s passes=%d/%d score=%.3f",
        run_id, overall_status, passes, total_tests, score,
    )
    return run_id


# ---------------------------------------------------------------------------
# Async scheduled loop (registered in lifespan)
# ---------------------------------------------------------------------------


async def posture_schedule_loop(
    conn,
    tests: list[dict],
    target_container: str,
    interval_seconds: int,
    executor: Optional[ExecutorFn] = None,
) -> None:
    """Async loop that runs posture batches every interval_seconds.

    Designed to run as an asyncio.Task via lifespan. If interval_seconds is 0,
    this function returns immediately (schedule disabled — ad-hoc POST only).

    Each batch executes run_batch() in a thread executor so the event loop
    is not blocked during subprocess calls.

    Args:
        conn:             Open SQLite connection (shared with main app).
        tests:            List of test dicts from load_atomic_tests().
        target_container: Container name for exec.
        interval_seconds: Sleep between runs. 0 = disabled.
        executor:         Optional injectable executor fn.

    @decision DEC-POSTURE-002
    @title interval_seconds=0 disables scheduler; non-zero enables sleep loop
    @status accepted
    @rationale See module docstring.
    """
    if interval_seconds <= 0:
        log.info("Posture schedule disabled (POSTURE_RUN_SCHEDULE_SECONDS=0)")
        return

    log.info(
        "Posture scheduler started (interval=%ds, container=%s)",
        interval_seconds, target_container,
    )
    loop = asyncio.get_event_loop()

    while True:
        try:
            await loop.run_in_executor(
                None,
                run_batch,
                conn,
                tests,
                target_container,
                executor,
            )
            await asyncio.sleep(interval_seconds)
        except asyncio.CancelledError:
            log.info("Posture scheduler cancelled")
            return
        except Exception as exc:
            log.warning("Posture scheduler error (continuing): %s", exc)
            try:
                await asyncio.sleep(min(interval_seconds, 60))
            except asyncio.CancelledError:
                log.info("Posture scheduler cancelled during backoff")
                return
