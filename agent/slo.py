"""
Posture SLO evaluator and webhook poster for Shaferhund.

Evaluates the latest posture_runs row against an operator-configured threshold.
When the score drops below the threshold, opens a breach session (one row in
slo_breaches) and fires a single webhook POST. Subsequent evaluations that find
the score still below threshold take no action — idempotency is enforced by the
presence of an open breach row. When the score recovers, the breach row is
closed (resolved_at set). The next breach after recovery opens a fresh row.

Key design decisions:
  DEC-SLO-001 — Idempotency: tracked via slo_breaches table, not in-memory.
                 A restart mid-breach does not re-fire the webhook. The open
                 breach is detected by resolved_at IS NULL; one row per session.
  DEC-SLO-002 — No retries on webhook failure. A failed POST is logged and the
                 breach row records webhook_fired=-1 with the HTTP status (or
                 None on network error). The next evaluation cycle does NOT
                 retry for the same breach — the operator must investigate.
                 Rationale: paging systems have their own retry logic; double-
                 firing on every evaluation would create alert storms.
  DEC-SLO-003 — Generic webhook shape (not vendor-specific). The payload uses
                 a `text` field that Slack/Teams renders as the message body.
                 PagerDuty's Events API v2 uses different fields, but a generic
                 receiver can reformat. Vendor-specific integrations belong in
                 the operator's webhook bridge, not in the agent.

@decision DEC-SLO-001
@title Idempotency via slo_breaches table — one POST per breach window
@status accepted
@rationale A restart mid-breach must not re-fire. In-memory state is lost on
           restart; the database row persists. get_open_slo_breach() is the
           single source of truth for whether a breach is active. Only one
           open breach row can exist at a time (resolved_at IS NULL query).
           Recovery (score >= threshold) closes the row; the next breach opens
           a fresh one. This is the same idempotency pattern as deploy_events.

@decision DEC-SLO-002
@title No retry on webhook failure — one fire per breach session
@status accepted
@rationale Retrying on every evaluation cycle would cause alert storms when the
           webhook endpoint is degraded: a 1-hour breach with a 60s eval
           interval would generate 60 page attempts. PagerDuty, Slack, and
           OpsGenie all have their own retry logic at the ingestion tier.
           A failed webhook is recorded (webhook_fired=-1, webhook_status=code
           or None) and logged. The operator must investigate the delivery
           failure separately. Acceptable trade-off: one lost page is better
           than 60 duplicate pages.

@decision DEC-SLO-003
@title Generic webhook shape — text field + structured JSON
@status accepted
@rationale A vendor-specific payload (e.g. PagerDuty Events API v2) would make
           the agent brittle: one integration per paging tool, each with its
           own auth scheme and retry semantics. The generic shape (text + score
           + threshold + started_at + posture_run_id) works with Slack incoming
           webhooks, Teams connectors, and any custom receiver. Operators who
           need PD API v2 can run a thin translation proxy. No retries in the
           agent (DEC-SLO-002) — the proxy handles delivery guarantees.
"""

import asyncio
import logging
from datetime import datetime, timezone
from typing import Optional

import httpx

from .models import (
    get_latest_posture_run,
    get_open_slo_breach,
    insert_slo_breach,
    mark_slo_breach_webhook,
    resolve_slo_breach,
)

log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Webhook payload builder
# ---------------------------------------------------------------------------

def _build_webhook_payload(
    score: float,
    threshold: float,
    started_at: str,
    posture_run_id: int,
) -> dict:
    """Build the generic webhook payload (DEC-SLO-003).

    Returns a dict ready for JSON serialisation. The `text` field is the
    human-readable summary rendered by Slack/Teams as the message body.
    PagerDuty receivers should translate this payload in a proxy layer.
    """
    return {
        "text": "Shaferhund posture SLO breached",
        "score": score,
        "threshold": threshold,
        "started_at": started_at,
        "posture_run_id": posture_run_id,
    }


# ---------------------------------------------------------------------------
# Webhook poster (DEC-SLO-002: no retries)
# ---------------------------------------------------------------------------

def fire_webhook(url: str, payload: dict) -> tuple[Optional[int], Optional[str]]:
    """POST the webhook payload to url. Single attempt — NO retries (DEC-SLO-002).

    Uses httpx for the HTTP call (already a dep from Phase 3 threat-intel).

    Args:
        url:     The webhook endpoint URL.
        payload: Dict to serialise as JSON in the POST body.

    Returns:
        Tuple of (http_status_code, error_message).
        On success (2xx): (status_code, None).
        On non-2xx:       (status_code, "<method> <url> returned <status>").
        On network error: (None, str(exception)).

    @decision DEC-SLO-002
    @title No retry on webhook failure
    @status accepted
    @rationale See module-level docstring. One POST per breach session.
               The caller records the result in slo_breaches.webhook_fired
               (-1 on any failure, 1 on success) and webhook_status (HTTP
               code or None). The next evaluation cycle will NOT retry.
    """
    try:
        resp = httpx.post(url, json=payload, timeout=10.0)
        if resp.is_success:
            log.info(
                "SLO webhook delivered: status=%d url=%s", resp.status_code, url
            )
            return resp.status_code, None
        else:
            msg = f"POST {url} returned {resp.status_code}"
            log.warning("SLO webhook non-2xx: %s", msg)
            return resp.status_code, msg
    except Exception as exc:
        msg = str(exc)
        log.warning("SLO webhook network error: %s", msg)
        return None, msg


# ---------------------------------------------------------------------------
# Core SLO evaluator
# ---------------------------------------------------------------------------

def evaluate_slo(conn, settings) -> dict:
    """Evaluate posture SLO against the latest posture_runs row.

    Logic (DEC-SLO-001):
      1. Fetch the latest posture_runs row. If none exists, do nothing.
      2. Compare score against settings.posture_slo_threshold.
      3. If score < threshold AND no open breach → open a new breach.
         (Webhook firing is handled by the caller — slo_evaluator_loop.)
      4. If score < threshold AND open breach → do nothing (idempotent).
      5. If score >= threshold AND open breach → resolve the breach.
      6. If score >= threshold AND no open breach → do nothing (healthy).

    Args:
        conn:     Open SQLite connection.
        settings: Settings-like object with posture_slo_threshold (float).

    Returns:
        Dict describing the action taken:
          {"action": "opened", "breach_id": int, "score": float, "run_id": int}
          {"action": "resolved", "breach_id": int, "score": float, "run_id": int}
          {"action": "noop", "reason": str}
    """
    threshold = settings.posture_slo_threshold

    # Step 1: check the latest posture run
    latest = get_latest_posture_run(conn)
    if latest is None:
        return {"action": "noop", "reason": "no posture runs exist"}

    score = float(latest["score"])
    run_id = int(latest["id"])

    # Step 2: check for an existing open breach
    open_breach = get_open_slo_breach(conn)

    if score < threshold:
        # Below threshold
        if open_breach is not None:
            # Already in breach — idempotent; do nothing (DEC-SLO-001)
            return {
                "action": "noop",
                "reason": "already in breach",
                "breach_id": int(open_breach["id"]),
                "score": score,
                "run_id": run_id,
            }
        else:
            # New breach — open a row
            started_at = datetime.now(timezone.utc).isoformat()
            breach_id = insert_slo_breach(
                conn,
                started_at=started_at,
                threshold=threshold,
                breach_score=score,
                posture_run_id=run_id,
            )
            log.warning(
                "SLO breach opened: score=%.3f threshold=%.3f run_id=%d breach_id=%d",
                score, threshold, run_id, breach_id,
            )
            return {
                "action": "opened",
                "breach_id": breach_id,
                "score": score,
                "run_id": run_id,
                "started_at": started_at,
                "threshold": threshold,
            }
    else:
        # At or above threshold
        if open_breach is not None:
            # Resolve the breach
            resolved_at = datetime.now(timezone.utc).isoformat()
            resolve_slo_breach(conn, int(open_breach["id"]), resolved_at)
            log.info(
                "SLO breach resolved: score=%.3f threshold=%.3f breach_id=%d",
                score, threshold, int(open_breach["id"]),
            )
            return {
                "action": "resolved",
                "breach_id": int(open_breach["id"]),
                "score": score,
                "run_id": run_id,
            }
        else:
            # Healthy, no open breach
            return {"action": "noop", "reason": "score above threshold, no open breach"}


# ---------------------------------------------------------------------------
# Async evaluator loop
# ---------------------------------------------------------------------------

async def slo_evaluator_loop(
    conn_factory,
    settings,
    interval_seconds: int = 60,
) -> None:
    """Async loop: evaluate SLO every interval_seconds.

    On "opened" decision, attempts to fire the webhook (single attempt,
    DEC-SLO-002). The webhook result is recorded in the breach row.

    Fails gracefully: if the webhook URL is empty or unreachable, the breach
    row is still written with webhook_fired=-1 and an error logged. The loop
    continues so future evaluations can detect recovery.

    Args:
        conn_factory: Callable returning an open sqlite3.Connection, or the
                      connection itself. If a callable is passed it is called
                      once per loop iteration (allows a factory pattern). If
                      a connection object is passed directly it is reused.
        settings:     Settings-like object with:
                        posture_slo_threshold (float)
                        posture_slo_webhook_url (str, may be empty)
                        posture_slo_eval_interval_seconds (int)
        interval_seconds: Override the settings value (for testing). Defaults
                          to settings.posture_slo_eval_interval_seconds if
                          the settings attribute exists, else this param.

    Note: conn_factory may be either a callable or a raw connection. The loop
          detects by checking callable(). Tests typically pass a raw connection.
    """
    # Resolve effective interval
    eff_interval = interval_seconds
    if hasattr(settings, "posture_slo_eval_interval_seconds"):
        eff_interval = settings.posture_slo_eval_interval_seconds

    log.info(
        "SLO evaluator loop started (threshold=%.2f interval=%ds webhook=%s)",
        settings.posture_slo_threshold,
        eff_interval,
        "configured" if getattr(settings, "posture_slo_webhook_url", "") else "not configured",
    )

    while True:
        try:
            conn = conn_factory() if callable(conn_factory) else conn_factory
            result = evaluate_slo(conn, settings)

            if result["action"] == "opened":
                breach_id = result["breach_id"]
                webhook_url = getattr(settings, "posture_slo_webhook_url", "")

                if webhook_url:
                    payload = _build_webhook_payload(
                        score=result["score"],
                        threshold=result["threshold"],
                        started_at=result["started_at"],
                        posture_run_id=result["run_id"],
                    )
                    status_code, err = await asyncio.to_thread(
                        fire_webhook, webhook_url, payload
                    )
                    if err is None:
                        # Success
                        mark_slo_breach_webhook(conn, breach_id, status_code, fired=1)
                        log.info(
                            "SLO webhook fired successfully: breach_id=%d status=%s",
                            breach_id, status_code,
                        )
                    else:
                        # Failure — record but do NOT retry (DEC-SLO-002)
                        mark_slo_breach_webhook(conn, breach_id, status_code, fired=-1)
                        log.warning(
                            "SLO webhook failed (no retry): breach_id=%d status=%s err=%s",
                            breach_id, status_code, err,
                        )
                else:
                    # No webhook URL — still record the breach, just don't page
                    mark_slo_breach_webhook(conn, breach_id, None, fired=0)
                    log.info(
                        "SLO breach opened but no webhook URL configured: breach_id=%d",
                        breach_id,
                    )

            elif result["action"] == "resolved":
                log.info(
                    "SLO breach closed: breach_id=%d score=%.3f",
                    result["breach_id"], result["score"],
                )

            # "noop" actions are silent at INFO level — don't flood logs

        except asyncio.CancelledError:
            log.info("SLO evaluator loop cancelled")
            raise
        except Exception as exc:
            log.warning(
                "SLO evaluator loop error (continuing): %s", exc, exc_info=True
            )

        await asyncio.sleep(eff_interval)
