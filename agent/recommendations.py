"""
Recommendation approval and execution module for Shaferhund Phase 4 Wave B.

Provides the logic for operator-gated ART technique execution:
  - DESTRUCTIVE_TECHNIQUES frozenset — code-resident allowlist of techniques
    that require force=True to run (DEC-RECOMMEND-002).
  - is_destructive(technique_id) — checks the frozenset including sub-technique
    parent matching (e.g. T1485.001 → T1485).
  - execute_recommendation(conn, recommendation_id, force) — validates the row,
    checks the allowlist, dispatches to red_team.run_batch for a single test,
    and marks the row 'executed'. Returns a result dict.

This module enforces the operator-gated execution model mandated by
DEC-RECOMMEND-001: Claude's recommend_attack tool ONLY writes a
status='pending' row. Execution flows through this module via the
POST /recommendations/{id}/execute endpoint. No path bypasses the
allowlist check except force=True in the request body — there is no
env-var bypass (DEC-RECOMMEND-002: the frozenset lives in code, not .env).

@decision DEC-RECOMMEND-001
@title recommend_attack writes to attack_recommendations only; execution requires explicit operator POST
@status accepted
@rationale Claude must not execute attacks autonomously. The recommendation
           row is a proposal; the operator's HTTP POST is the trigger. This
           preserves auditability and keeps the blast radius bounded by human
           review. Even in Phase 4 the system never crosses the line from
           "machine proposes" to "machine executes" without a human in the
           loop.

@decision DEC-RECOMMEND-002
@title Destructive allowlist as code-resident frozenset; force=True is the only runtime bypass
@status accepted
@rationale Storing the destructive technique list in code (not .env or DB)
           means a compromised operator env file cannot silently lower the
           safety bar. The frozenset is immutable at runtime. The sole bypass
           path is force=True in the execute request body — explicit,
           auditable, one request at a time. No env-var bypass exists by
           design.

@decision DEC-RECOMMEND-003
@title Single-test run_batch dispatch for recommendation execution
@status accepted
@rationale execute_recommendation constructs a one-element test list and calls
           the existing run_batch harness. This reuses all of run_batch's
           recording logic (posture_runs row, posture_test_results row, score
           computation) without duplicating it. The resulting posture_run_id
           is stored on the recommendation row for correlation.

@decision DEC-RECOMMEND-004
@title Sub-technique parent matching in is_destructive
@status accepted
@rationale MITRE sub-techniques (T1485.001) inherit the risk of their parent
           (T1485). Requiring operators to enumerate every sub-technique in
           DESTRUCTIVE_TECHNIQUES would create maintenance gaps. The check
           extracts the base ID (first dot-separated segment) and tests both
           the full ID and the base ID against the frozenset — conservative,
           correct, and maintainable.

@decision DEC-RECOMMEND-005
@title execute_recommendation returns a result dict; HTTP status mapping is in main.py
@status accepted
@rationale Keeping HTTP-layer concerns out of this module makes execute_recommendation
           independently unit-testable. The route handler in main.py maps the
           result dict fields (status, error, run_id) to appropriate HTTP
           responses (200 / 400 / 404). This follows the same boundary as
           red_team.run_batch which returns an int (run_id) not an HTTP response.
"""

import logging
from datetime import datetime, timezone
from typing import Optional

from .models import (
    get_attack_recommendation,
    insert_attack_recommendation,
    mark_attack_recommendation_executed,
)

log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Destructive technique allowlist (DEC-RECOMMEND-002)
#
# Techniques listed here require force=True in the execute request body.
# The set is intentionally conservative — default is fail-closed.
# Add new entries here (in code) when confirmed destructive impact is known.
# ---------------------------------------------------------------------------

DESTRUCTIVE_TECHNIQUES: frozenset[str] = frozenset({
    # Data Destruction
    "T1485",
    # Data Encrypted for Impact (ransomware-class)
    "T1486",
    # Inhibit System Recovery
    "T1490",
    # Disk Wipe
    "T1561",
    # System Shutdown/Reboot
    "T1529",
    # Endpoint Denial of Service
    "T1499",
    # Firmware Corruption
    "T1495",
    # Service Stop (can destabilise critical services)
    "T1489",
    # Resource Hijacking (DoS-adjacent impact on host)
    "T1496",
})


def is_destructive(technique_id: str) -> bool:
    """Return True if technique_id (or its parent) is in DESTRUCTIVE_TECHNIQUES.

    Checks both the exact technique_id AND the base parent ID so that
    sub-techniques (e.g. T1485.001) are covered by their parent entry (T1485)
    in DESTRUCTIVE_TECHNIQUES without requiring explicit enumeration of every
    sub-technique (DEC-RECOMMEND-004).

    Args:
        technique_id: MITRE ATT&CK ID, e.g. 'T1486' or 'T1485.001'.

    Returns:
        True if the technique or its parent is destructive, False otherwise.
    """
    if not technique_id:
        return False

    # Exact match
    if technique_id in DESTRUCTIVE_TECHNIQUES:
        return True

    # Parent match for sub-techniques (e.g. 'T1485.001' → 'T1485')
    parent = technique_id.split(".")[0]
    return parent in DESTRUCTIVE_TECHNIQUES


def execute_recommendation(
    conn,
    recommendation_id: int,
    force: bool = False,
    target_container: Optional[str] = None,
    executor=None,
) -> dict:
    """Execute an approved attack recommendation.

    Validates the recommendation row (must exist and be status='pending'),
    checks the destructive allowlist (DEC-RECOMMEND-002), constructs a
    single-test batch for run_batch, dispatches execution, and marks the
    row 'executed' with the resulting posture_run_id.

    This function is the execution boundary. Claude's recommend_attack handler
    never calls this function — only the operator's HTTP POST does
    (DEC-RECOMMEND-001).

    Args:
        conn:              Open SQLite connection.
        recommendation_id: The attack_recommendations.id to execute.
        force:             If True, bypass the destructive technique check.
                           This must come from the request body — there is no
                           env-var equivalent (DEC-RECOMMEND-002).
        target_container:  Container name for podman exec. Defaults to
                           'redteam-target' when None (mirrors red_team.py
                           default convention).
        executor:          Optional injectable executor fn for testing
                           (DEC-REDTEAM-003 pattern). Signature:
                           (container_name, command_hint) -> (exit_code, output).

    Returns:
        Dict with keys:
          - status: 'executed' | 'rejected' | 'not_found' | 'already_executed'
          - run_id: posture_runs.id (int) on success, None otherwise
          - recommendation_id: echoed back
          - error: human-readable rejection reason (on non-success)

    Raises:
        Nothing — errors are returned as result dicts so HTTP routes can
        map them to appropriate status codes (DEC-RECOMMEND-005).
    """
    # Lazy import to avoid circular imports at module load time
    from . import red_team as _red_team

    if target_container is None:
        target_container = "redteam-target"

    # --- Fetch row ---
    row = get_attack_recommendation(conn, recommendation_id)
    if row is None:
        log.warning(
            "execute_recommendation: recommendation_id=%d not found",
            recommendation_id,
        )
        return {
            "status": "not_found",
            "run_id": None,
            "recommendation_id": recommendation_id,
            "error": f"Recommendation {recommendation_id} not found",
        }

    row_status = row["status"]
    technique_id = row["technique_id"]

    # --- Status gate: only 'pending' rows can be executed ---
    if row_status != "pending":
        log.warning(
            "execute_recommendation: recommendation_id=%d has status=%r (expected 'pending')",
            recommendation_id,
            row_status,
        )
        return {
            "status": "already_executed",
            "run_id": None,
            "recommendation_id": recommendation_id,
            "error": (
                f"Recommendation {recommendation_id} cannot be executed: "
                f"current status is '{row_status}'"
            ),
        }

    # --- Destructive technique gate (DEC-RECOMMEND-002) ---
    if is_destructive(technique_id) and not force:
        log.warning(
            "execute_recommendation: technique=%r is destructive; force=False — rejecting",
            technique_id,
        )
        return {
            "status": "rejected",
            "run_id": None,
            "recommendation_id": recommendation_id,
            "error": (
                f"Technique {technique_id} is in DESTRUCTIVE_TECHNIQUES. "
                "Pass force=true in the request body to override."
            ),
        }

    # --- Build single-test batch for run_batch (DEC-RECOMMEND-003) ---
    test_entry = {
        "technique_id": technique_id,
        "test_name": row["reason"][:80] if row["reason"] else technique_id,
        "command_or_script_hint": f"echo 'ART recommendation: {technique_id}'",
        "weight": 1,
    }

    log.info(
        "execute_recommendation: dispatching technique=%r container=%s force=%s",
        technique_id,
        target_container,
        force,
    )

    try:
        run_id = _red_team.run_batch(
            conn=conn,
            tests=[test_entry],
            target_container=target_container,
            executor=executor,
        )
    except Exception as exc:
        log.error(
            "execute_recommendation: run_batch failed for recommendation=%d: %s",
            recommendation_id,
            exc,
            exc_info=True,
        )
        return {
            "status": "rejected",
            "run_id": None,
            "recommendation_id": recommendation_id,
            "error": f"run_batch failed: {exc}",
        }

    # --- Mark row executed and link posture_run_id ---
    mark_attack_recommendation_executed(conn, recommendation_id, posture_run_id=run_id)

    log.info(
        "execute_recommendation: recommendation_id=%d executed → run_id=%d",
        recommendation_id,
        run_id,
    )
    return {
        "status": "executed",
        "run_id": run_id,
        "recommendation_id": recommendation_id,
        "error": None,
    }
