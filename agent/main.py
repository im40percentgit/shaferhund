"""
Shaferhund FastAPI application.

Responsibilities:
  - Serve the HTMX dashboard (GET /, GET /clusters/{id})
  - Expose GET /health for monitoring
  - Run the file tailer as a background asyncio task
  - Wire together: file tailer → clusterer → triage queue → SQLite

Background task lifecycle:
  - startup: init DB, start triage queue worker, start Wazuh + Suricata tailer loops
  - shutdown: cancel tailers, stop triage queue gracefully

Auth:
  - If SHAFERHUND_TOKEN is set, every non-health request requires
    Authorization: Bearer <token>.
  - If SHAFERHUND_TOKEN is unset, the server binds to 127.0.0.1 only
    (set via the uvicorn --host flag in __main__ / compose entrypoint).

@decision DEC-AUTH-001
@title SHAFERHUND_TOKEN bearer auth; unset = localhost-only binding
@status accepted
@rationale Simple token is sufficient for a single-user local deployment.
           Unset token = localhost-only is safer than unset token = open.
           No session management needed at this scale.

@decision DEC-AUTH-002
@title Query-param token fallback removed
@status accepted
@rationale The former ?token=<token> query-param fallback was removed 2026-04-22
           after CSO Finding 2. Query-string tokens leak into: uvicorn access
           logs, reverse-proxy logs, browser history, browser URL bar, and the
           Referer header on outbound navigation. Bearer-only keeps the secret
           in the Authorization header, which is not logged by default and is
           not sent as a Referer. If a shareable-link workflow is ever needed,
           implement a one-time /login?token=... handler that sets a signed
           cookie and immediately redirects, stripping the query string.

@decision DEC-TAILER-001
@title Dual independent tailer tasks feeding a single shared AlertClusterer
@status accepted
@rationale Wazuh and Suricata alert sources have different file formats,
           poll paths, and severity scales. Running them as independent
           asyncio Tasks allows each to maintain its own byte-offset state
           and backoff behaviour without coupling. Both feed into the same
           AlertClusterer instance so clustering, triage, and persistence
           logic stays unified. The clusterer key includes `source` so
           Wazuh and Suricata alerts on the same (src_ip, rule_id) pair
           remain in separate clusters (DEC-CLUSTER-002).
           Suricata severity (1-3) is mapped to the Wazuh 0-15 scale so
           the same severity_min_level filter applies to both sources:
           sev 1 → 7 (Critical), sev 2 → 6 (High), sev 3 → 5 (Medium).
           Only sev 1 and 2 pass the default threshold of 7.
"""

import asyncio
import json
import logging
import os
import subprocess
import time
import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from fastapi import Depends, FastAPI, HTTPException, Request, status
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from .cluster import Alert, AlertClusterer, Cluster, parse_wazuh_alert
from .config import Settings, get_settings
from .sources.suricata import parse_suricata_alert, tail_eve_json
from .models import (
    count_deploy_events_since,
    count_reverted_since,
    get_cluster,
    get_cluster_alerts,
    get_latest_deploy_event,
    get_rules_for_cluster,
    get_stats,
    init_db,
    insert_alert,
    insert_rule,
    list_clusters,
    list_clusters_by_source,
    list_deploy_events_paginated,
    mark_deploy_reverted_by_rule,
    mark_rule_deployed,
    update_cluster_ai,
    upsert_cluster,
)
from .orchestrator import get_orchestrator_stats
from .triage import TriageResult, TriageQueue
from . import threat_intel as _threat_intel
from .models import count_threat_intel_records
from . import canary as _canary
from .canary import spawn_canary, record_hit, count_canary_triggers_since
from . import red_team as _red_team
from .models import (
    get_latest_posture_run,
    insert_posture_run,
)

log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Module-level singletons (populated in lifespan)
# ---------------------------------------------------------------------------
_settings: Optional[Settings] = None
_db = None
_triage_queue: Optional[TriageQueue] = None
_clusterer: Optional[AlertClusterer] = None
_tailer_task: Optional[asyncio.Task] = None
_suricata_tailer_task: Optional[asyncio.Task] = None
_urlhaus_task: Optional[asyncio.Task] = None
_posture_task: Optional[asyncio.Task] = None
_poller_healthy: bool = False
_last_poll_at: Optional[str] = None


# ---------------------------------------------------------------------------
# Sigma-cli startup probe
# ---------------------------------------------------------------------------

def _probe_sigmac(settings: Settings) -> None:
    """Probe for sigma-cli at startup and mutate settings fields in place.

    Runs ``sigma --version`` once. On success, sets sigmac_available=True
    and sigmac_version to the version string. On any failure
    (FileNotFoundError, non-zero exit, or TimeoutExpired), leaves
    sigmac_available=False and logs a single WARNING. Does NOT raise —
    graceful degradation is the point.

    @decision DEC-SIGMA-DEGRADE-001
    @title Startup probe flips settings.sigmac_available once; downstream reads the bool
    @status accepted
    @rationale One sigma-cli invocation per startup is enough. Downstream code
               (policy gate, orchestrator) reads sigmac_available without re-probing.
               Re-probing on every triage would add 50-100 ms of latency per rule
               for no benefit. Defaults to False so a misconfigured container can
               never accidentally auto-deploy Sigma rules before the probe confirms
               sigma-cli is usable (fail-safe default).
    """
    try:
        result = subprocess.run(
            ["sigma", "--version"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        if result.returncode == 0 and result.stdout.strip():
            settings.sigmac_available = True
            settings.sigmac_version = result.stdout.strip()
            log.info("sigma-cli available: %s", settings.sigmac_version)
            return
        # Non-zero exit — treat as unavailable
        log.warning(
            "sigma-cli not available; Sigma rules will generate but not auto-deploy"
        )
    except FileNotFoundError:
        log.warning(
            "sigma-cli not available; Sigma rules will generate but not auto-deploy"
        )
    except subprocess.TimeoutExpired:
        log.warning(
            "sigma-cli not available; Sigma rules will generate but not auto-deploy"
        )


# ---------------------------------------------------------------------------
# Lifespan
# ---------------------------------------------------------------------------

@asynccontextmanager
async def lifespan(app: FastAPI):
    global _settings, _db, _triage_queue, _clusterer, _tailer_task, _suricata_tailer_task, _urlhaus_task, _posture_task

    _settings = get_settings()
    _probe_sigmac(_settings)
    _db = init_db(_settings.db_path)
    _clusterer = AlertClusterer(
        window_seconds=_settings.cluster_window_seconds,
        max_alerts=_settings.cluster_max_alerts,
    )
    _triage_queue = TriageQueue(_settings, on_result=_save_triage_result)
    await _triage_queue.start()

    _tailer_task = asyncio.create_task(_tailer_loop(), name="wazuh-tailer")
    _suricata_tailer_task = asyncio.create_task(
        _suricata_tailer_loop(), name="suricata-tailer"
    )

    # Phase 3 — URLhaus threat-intel hourly poller (REQ-P0-P3-005)
    _urlhaus_task = asyncio.create_task(
        _threat_intel.urlhaus_poll_loop(
            _db,
            _settings.urlhaus_feed_url,
            _settings.urlhaus_fetch_interval_seconds,
        ),
        name="urlhaus-poller",
    )

    # Phase 3 — Atomic Red Team posture scheduler (REQ-P0-P3-001, DEC-POSTURE-002)
    # Only starts a background task when POSTURE_RUN_SCHEDULE_SECONDS > 0.
    # When it is 0, posture_schedule_loop returns immediately and no task is needed.
    if _settings.posture_run_schedule_seconds > 0:
        try:
            _art_tests = _red_team.load_atomic_tests(_settings.art_tests_file)
        except Exception as exc:
            log.warning(
                "Posture scheduler disabled — failed to load %s: %s",
                _settings.art_tests_file, exc,
            )
            _art_tests = []

        if _art_tests:
            _posture_task = asyncio.create_task(
                _red_team.posture_schedule_loop(
                    _db,
                    _art_tests,
                    _settings.redteam_target_container,
                    _settings.posture_run_schedule_seconds,
                ),
                name="posture-scheduler",
            )

    log.info(
        "Shaferhund agent started (wazuh-tailer + suricata-tailer + urlhaus-poller running)"
    )

    yield

    # Shutdown — cancel all background tasks
    for task in (_tailer_task, _suricata_tailer_task, _urlhaus_task, _posture_task):
        if task:
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass
    if _triage_queue:
        await _triage_queue.stop()
    if _db:
        _db.close()
    log.info("Shaferhund agent stopped")


# ---------------------------------------------------------------------------
# App
# ---------------------------------------------------------------------------

app = FastAPI(title="Shaferhund", version="0.1.0", lifespan=lifespan)

TEMPLATES_DIR = Path(__file__).parent / "templates"
templates = Jinja2Templates(directory=str(TEMPLATES_DIR))

# ---------------------------------------------------------------------------
# Static assets — htmx vendored locally (CSO Finding F3)
#
# @decision DEC-SUPPLY-001
# @title Vendor htmx into agent/static/ and serve at /static/; remove CDN dependency
# @status accepted
# @rationale Loading htmx from unpkg.com introduced a CDN supply-chain risk: a
#            compromised or man-in-the-middle CDN response could inject arbitrary
#            JS into the dashboard. Vendoring eliminates the runtime external
#            dependency entirely. The trade-off is manual version bumps — update
#            agent/static/htmx-<ver>.min.js and the script tags in all three
#            templates whenever htmx is upgraded. At 48 KB the file is negligible
#            bloat. /static/* is intentionally NOT behind _require_auth: static
#            assets carry no secrets and gating them would break the login page
#            itself if one were ever added.
# ---------------------------------------------------------------------------
STATIC_DIR = Path(__file__).parent / "static"
app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")


# ---------------------------------------------------------------------------
# Auth
# ---------------------------------------------------------------------------

_bearer_scheme = HTTPBearer(auto_error=False)


def _require_auth(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(_bearer_scheme),
) -> None:
    """FastAPI dependency: enforce bearer token auth when SHAFERHUND_TOKEN is set.

    Accepts only the Authorization: Bearer <token> header.
    The former ?token=<query-param> fallback was removed (DEC-AUTH-002) because
    query-string tokens leak into access logs, browser history, and Referer headers.
    """
    token = _settings.shaferhund_token if _settings else ""
    if not token:
        return  # No token configured — localhost-only binding is the guard

    provided = None
    if credentials and credentials.scheme.lower() == "bearer":
        provided = credentials.credentials

    if provided != token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or missing token",
            headers={"WWW-Authenticate": "Bearer"},
        )


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.get("/health")
async def health() -> JSONResponse:
    """Minimal liveness probe — status and poller health only.

    Always returns 200 — even if the tailer is degraded — so container
    health checks don't cycle the service on transient read errors.

    Minimal — by design — so unauthenticated container probes can't be used
    for reconnaissance. See ``/metrics`` for full operational stats.

    @decision DEC-HEALTH-002
    @title Split /health (public liveness) and /metrics (authenticated stats) per CSO F5
    @status accepted
    @rationale Public /health was returning queue depth, alert counts, timestamps,
               and orchestrator counters — enough for an attacker to map the
               deployment's workload and timing. Moving stats behind auth (when
               SHAFERHUND_TOKEN is set) limits exposure without breaking container
               probes, which only need {status, poller_healthy} to decide liveness.
    """
    ti_count = count_threat_intel_records(_db) if _db is not None else 0
    canary_24h = (
        count_canary_triggers_since(_db, time.time() - 86400)
        if _db is not None
        else 0
    )
    posture_row = get_latest_posture_run(_db) if _db is not None else None
    posture_last_score = float(posture_row["score"]) if posture_row is not None else None
    posture_last_run_at = posture_row["started_at"] if posture_row is not None else None
    return JSONResponse({
        "status": "ok",
        "poller_healthy": _poller_healthy,
        "threat_intel": {
            "record_count": ti_count,
        },
        "canary": {
            "trigger_count_24h": canary_24h,
        },
        "posture": {
            "last_score": posture_last_score,
            "last_run_at": posture_last_run_at,
        },
    })


@app.get("/metrics", dependencies=[Depends(_require_auth)])
async def metrics() -> JSONResponse:
    """Authenticated operational stats. Migration from /health per CSO F5.

    Requires ``Authorization: Bearer <token>`` (or ``?token=<token>``) when
    ``SHAFERHUND_TOKEN`` is set. Returns 401 if auth fails; 200 with full
    payload otherwise. When ``SHAFERHUND_TOKEN`` is unset the endpoint is
    open, consistent with the localhost-only binding that replaces auth in
    that mode.

    Fields:
      queue_depth, calls_this_hour, hourly_budget — triage queue state.
      last_poll_at, last_triage_at               — activity timestamps.
      total_alerts, total_clusters, pending_triage — DB aggregate counts.
      orchestrator                               — in-memory counters from
                                                   the Claude tool-use loop.
      auto_deploy                                — 24h deploy/skip/revert
                                                   counts from deploy_events.
    """
    stats = get_stats(_db) if _db else {}

    # 24-hour window anchor — consistent UTC epoch throughout this request.
    since_24h = time.time() - 86400

    if _db is not None:
        deployed_24h = count_deploy_events_since(_db, since_24h, action="auto-deploy")
        skipped_24h = count_deploy_events_since(_db, since_24h, action="skipped")
        reverted_24h = count_reverted_since(_db, since_24h)
    else:
        deployed_24h = skipped_24h = reverted_24h = 0

    return JSONResponse({
        "queue_depth": _triage_queue.depth if _triage_queue else 0,
        "calls_this_hour": _triage_queue.calls_this_hour if _triage_queue else 0,
        "hourly_budget": _settings.triage_hourly_budget if _settings else 0,
        "last_poll_at": _last_poll_at,
        "last_triage_at": stats.get("last_triage"),
        "total_alerts": stats.get("total_alerts", 0),
        "total_clusters": stats.get("total_clusters", 0),
        "pending_triage": stats.get("pending_triage", 0),
        # Orchestrator in-memory stats (Phase 2, REQ-P1-P2-004)
        "orchestrator": get_orchestrator_stats(),
        # Auto-deploy 24h window counts (Phase 2, REQ-P1-P2-004)
        "auto_deploy": {
            "enabled": bool(_settings.AUTO_DEPLOY_ENABLED) if _settings else False,
            "deployed_last_24h": deployed_24h,
            "skipped_last_24h": skipped_24h,
            "reverted_last_24h": reverted_24h,
        },
        # Sigma-cli availability — set once at startup by _probe_sigmac()
        # (REQ-P0-P25-003, REQ-P1-P25-001). Not exposed via /health (CSO F5).
        "sigmac": {
            "available": getattr(_settings, "sigmac_available", False) if _settings else False,
            "version": getattr(_settings, "sigmac_version", None) if _settings else None,
        },
    })


@app.get("/", response_class=HTMLResponse, dependencies=[Depends(_require_auth)])
async def index(request: Request, source: Optional[str] = None):
    """Dashboard: cluster list with HTMX auto-refresh every 10 seconds.

    Accepts an optional ?source= query param ('wazuh', 'suricata', 'all').
    The active filter is forwarded to the template so the filter chips can
    highlight the active selection and HTMX polling preserves the param.
    """
    if _db is not None:
        rows = list_clusters_by_source(_db, source=source, limit=100)
    else:
        rows = []
    clusters = [dict(r) for r in rows]
    active_source = source or "all"
    return templates.TemplateResponse(
        "index.html",
        {"request": request, "clusters": clusters, "active_source": active_source},
    )


@app.get(
    "/deploy-events",
    response_class=HTMLResponse,
    dependencies=[Depends(_require_auth)],
)
async def deploy_events_page(request: Request, offset: int = 0):
    """Audit log page: paginated deploy events, 50 rows per page.

    @decision DEC-DASHBOARD-001
    @title Paginated deploy-events audit log at /deploy-events
    @status accepted
    @rationale A dedicated page keeps the index clean while providing full
               visibility into the auto-deploy/undo history for operators.
               50-row pages balance readability with query cost.
    """
    rows = list_deploy_events_paginated(_db, limit=50, offset=offset) if _db else []
    events = [dict(r) for r in rows]
    next_offset = offset + 50 if len(events) == 50 else None
    prev_offset = max(0, offset - 50) if offset > 0 else None
    return templates.TemplateResponse(
        "deploy_events.html",
        {
            "request": request,
            "events": events,
            "offset": offset,
            "next_offset": next_offset,
            "prev_offset": prev_offset,
        },
    )


@app.get(
    "/clusters/{cluster_id}",
    response_class=HTMLResponse,
    dependencies=[Depends(_require_auth)],
)
async def cluster_detail(request: Request, cluster_id: str):
    """Cluster detail: alert list, AI analysis, YARA and Sigma rules with deploy status."""
    cluster = get_cluster(_db, cluster_id) if _db else None
    if cluster is None:
        raise HTTPException(status_code=404, detail="Cluster not found")
    alerts = get_cluster_alerts(_db, cluster_id) if _db else []
    rule_rows = get_rules_for_cluster(_db, cluster_id) if _db else []

    # Enrich each rule with its most recent deploy event so the template can
    # render deploy status without a separate per-rule HTMX call.
    rules = []
    for r in rule_rows:
        rule = dict(r)
        evt = get_latest_deploy_event(_db, rule["id"]) if _db else None
        rule["latest_deploy_event"] = dict(evt) if evt else None
        rules.append(rule)

    return templates.TemplateResponse(
        "cluster_detail.html",
        {
            "request": request,
            "cluster": dict(cluster),
            "alerts": [dict(a) for a in alerts],
            "rules": rules,
        },
    )


@app.post(
    "/rules/{rule_id}/deploy",
    dependencies=[Depends(_require_auth)],
)
async def deploy_rule(rule_id: str):
    """Write a validated YARA rule to the /rules/ volume.

    The Wazuh manager container mounts /rules/ and can be configured to
    load YARA rules from that path. No docker exec required.

    @decision DEC-YARA-001
    @title Write YARA to /rules/ volume, no docker exec
    @status accepted
    @rationale Manual rule reload via shared volume is simpler and more
               portable than docker exec. Eng review mandated this approach.
    """
    if _db is None or _settings is None:
        raise HTTPException(status_code=503, detail="Database not ready")

    cur = _db.execute("SELECT * FROM rules WHERE id = ?", (rule_id,))
    row = cur.fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail="Rule not found")
    rule = dict(row)

    if not rule.get("syntax_valid"):
        raise HTTPException(status_code=422, detail="Rule failed syntax check")

    rules_dir = Path(_settings.rules_dir)
    rules_dir.mkdir(parents=True, exist_ok=True)
    rule_file = rules_dir / f"{rule_id}.yar"
    rule_file.write_text(rule["rule_content"])
    mark_rule_deployed(_db, rule_id)
    log.info("Deployed rule %s to %s", rule_id, rule_file)
    return {"deployed": True, "path": str(rule_file)}


@app.post(
    "/rules/{rule_id}/undo-deploy",
    dependencies=[Depends(_require_auth)],
)
async def undo_deploy_rule(rule_id: str):
    """Delete a deployed rule file and mark its audit row as reverted.

    Auth: same SHAFERHUND_TOKEN bearer/query-param scheme as /deploy.

    Behaviour:
      - 404  if the .yar file does not exist on disk (DB is NOT updated —
             idempotent safety; a missing file implies the rule was never
             written or was already cleaned up externally).
      - 200  {"reverted": true, "path": "..."}  on success.
      - 409  if no un-reverted auto-deploy event found for this rule UUID
             (already reverted — idempotent guard).

    @decision DEC-UNDO-001
    @title Undo returns 404 when file absent, 409 when already reverted
    @status accepted
    @rationale 404 on missing file avoids silently corrupting audit state
               when the file was removed externally.  409 on already-reverted
               is more informative than a silent 200 and makes retry logic
               explicit for callers.
    """
    if _db is None or _settings is None:
        raise HTTPException(status_code=503, detail="Database not ready")

    rules_dir = Path(_settings.rules_dir)
    rule_file = rules_dir / f"{rule_id}.yar"

    if not rule_file.exists():
        raise HTTPException(status_code=404, detail="Rule file not found on disk")

    # Delete the file first; only update DB if deletion succeeds.
    rule_file.unlink()
    log.info("Deleted rule file %s", rule_file)

    reverted = mark_deploy_reverted_by_rule(_db, rule_id)
    if not reverted:
        # File was present but no un-reverted auto-deploy event — already reverted
        # or was deployed via the manual endpoint (no rule_uuid on deploy_events).
        log.warning(
            "undo-deploy: file deleted but no un-reverted auto-deploy event for rule %s",
            rule_id,
        )
        raise HTTPException(
            status_code=409,
            detail="Rule file deleted but no un-reverted deploy event found",
        )

    return {"reverted": True, "path": str(rule_file)}


# ---------------------------------------------------------------------------
# Canary token routes (Phase 3, REQ-P0-P3-004)
# ---------------------------------------------------------------------------

@app.post(
    "/canary/spawn",
    dependencies=[Depends(_require_auth)],
)
async def canary_spawn(request: Request) -> JSONResponse:
    """Spawn a new DNS or HTTP canary token.

    Auth-gated (same SHAFERHUND_TOKEN bearer scheme as /metrics).

    Request body JSON:
        type (str): 'dns' or 'http'
        name (str): human-readable label for this canary

    Returns:
        JSON with: id, token, type, name, and either trap_url (http)
        or trap_hostname (dns).
    """
    if _db is None or _settings is None:
        raise HTTPException(status_code=503, detail="Database not ready")

    try:
        body = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="Request body must be valid JSON")

    token_type = body.get("type", "")
    name = body.get("name", "")

    if token_type not in ("dns", "http"):
        raise HTTPException(
            status_code=422,
            detail="type must be 'dns' or 'http'",
        )
    if not isinstance(name, str) or not name.strip():
        raise HTTPException(status_code=422, detail="name must be a non-empty string")

    try:
        result = spawn_canary(
            _db,
            token_type=token_type,
            name=name,
            base_url=_settings.canary_base_url,
            base_hostname=_settings.canary_base_hostname,
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))

    return JSONResponse(result, status_code=201)


@app.get("/canary/hit/{token}")
async def canary_hit(token: str, request: Request) -> JSONResponse:
    """Public trap endpoint — no auth required.

    Called when an attacker follows an HTTP canary link. Returns an innocuous
    response (200 with minimal body) to avoid tipping off the attacker that
    they hit a trap. The real work happens in record_hit() which writes a
    source='canary' alert row and routes it through the clusterer/triage pipeline.

    The /canary/hit path is intentionally NOT behind _require_auth: an attacker
    won't send a bearer token, and requiring auth would make the trap useless.
    """
    if _db is None:
        # DB not ready — still return innocuous 200 to avoid fingerprinting
        return JSONResponse({"ok": True})

    # Extract sanitized request metadata (all attacker-controlled)
    forwarded_for = request.headers.get("x-forwarded-for", "")
    client_ip = (
        forwarded_for.split(",")[0].strip()
        if forwarded_for
        else (request.client.host if request.client else "unknown")
    )
    request_meta = {
        "src_ip": client_ip,
        "user_agent": request.headers.get("user-agent", ""),
        "path": str(request.url.path),
        "x_forwarded_for": forwarded_for,
    }

    hit = record_hit(
        _db,
        token=token,
        request_meta=request_meta,
        enqueue_fn=_canary_enqueue,
    )

    # Always return innocuous 200 regardless of whether the token was known.
    # A 404 for unknown tokens would let an attacker enumerate valid tokens.
    return JSONResponse({"ok": True})


# ---------------------------------------------------------------------------
# Posture run route (Phase 3, REQ-P0-P3-001)
# ---------------------------------------------------------------------------

@app.post(
    "/posture/run",
    dependencies=[Depends(_require_auth)],
)
async def posture_run() -> JSONResponse:
    """Fire an ad-hoc Atomic Red Team posture batch and return immediately.

    Auth-gated via _require_auth — this endpoint execs commands inside a
    container and must NOT be exposed without token protection.

    Creates a posture_runs row with status='running', then fires the batch
    as an asyncio background task. Returns immediately with the run_id so
    callers can poll /health for last_score / last_run_at.

    Returns:
        JSON: {run_id: int, status: "running"}

    @decision DEC-REDTEAM-004
    @title POST /posture/run inserts the DB row before fire-and-forget
    @status accepted
    @rationale Inserting the posture_runs row synchronously before spawning
               the asyncio task means the caller receives a valid run_id
               immediately. The background task then updates the same row
               to 'complete' or 'failed'. This avoids a race where the
               caller polls before the row exists. The row is committed
               before the task starts — SQLite's WAL mode allows concurrent
               readers to see it immediately.
    """
    if _db is None or _settings is None:
        raise HTTPException(status_code=503, detail="Database not ready")

    try:
        tests = _red_team.load_atomic_tests(_settings.art_tests_file)
    except Exception as exc:
        raise HTTPException(
            status_code=503,
            detail=f"Failed to load ART tests file ({_settings.art_tests_file}): {exc}",
        )

    if not tests:
        raise HTTPException(status_code=422, detail="No ART tests defined in art_tests_file")

    started_at = datetime.now(timezone.utc).isoformat()
    technique_ids = [t.get("technique_id", "unknown") for t in tests]
    run_id = insert_posture_run(_db, started_at, technique_ids, len(tests))

    # Fire-and-forget: run_batch runs synchronously in a thread so the event
    # loop is not blocked during subprocess calls (same pattern as posture_schedule_loop).
    loop = asyncio.get_event_loop()

    async def _run_in_background() -> None:
        try:
            await loop.run_in_executor(
                None,
                _red_team.run_batch,
                _db,
                tests,
                _settings.redteam_target_container,
                None,  # use default executor (podman exec)
            )
        except Exception as exc:
            log.error("Background posture run %d error: %s", run_id, exc, exc_info=True)

    asyncio.create_task(_run_in_background(), name=f"posture-run-{run_id}")
    log.info("POST /posture/run: started run_id=%d (%d tests)", run_id, len(tests))
    return JSONResponse({"run_id": run_id, "status": "running"})


async def _canary_enqueue(alert_obj) -> None:
    """Bridge between record_hit() and the shared clusterer/triage pipeline.

    record_hit() calls this with an Alert object. We add it to the shared
    AlertClusterer (which may close a cluster) and persist + enqueue any
    closed clusters for triage.
    """
    if _clusterer is None or _db is None:
        return

    closed = _clusterer.add(alert_obj)
    for cluster in closed:
        await _persist_and_enqueue(cluster)


# ---------------------------------------------------------------------------
# Background: file tailer
# ---------------------------------------------------------------------------

async def _tailer_loop() -> None:
    """Continuously tail alerts.json, parse new lines, cluster alerts.

    Tails by tracking byte offset in memory. On read failure uses
    exponential backoff (2s → 300s) and logs a warning.
    """
    global _poller_healthy, _last_poll_at

    alerts_file = _settings.alerts_file
    offset = 0
    backoff = 2.0
    backoff_cap = 300.0

    # Seek to end on startup to avoid re-processing historical alerts
    try:
        offset = Path(alerts_file).stat().st_size
        log.info("Tailer starting at offset %d for %s", offset, alerts_file)
    except FileNotFoundError:
        log.warning("Alerts file not found yet: %s — will retry", alerts_file)

    while True:
        try:
            new_alerts = await asyncio.to_thread(_read_new_lines, alerts_file, offset)
            offset = new_alerts["new_offset"]
            lines = new_alerts["lines"]

            _poller_healthy = True
            _last_poll_at = datetime.now(timezone.utc).isoformat()
            backoff = 2.0  # reset on success

            for line in lines:
                await _process_line(line)

            # Flush clusters whose window has expired
            if _clusterer:
                expired = _clusterer.flush_expired()
                for cluster in expired:
                    await _persist_and_enqueue(cluster)

        except asyncio.CancelledError:
            raise
        except Exception as exc:
            _poller_healthy = False
            log.warning(
                "Tailer error (backoff=%.1fs): %s", backoff, exc, exc_info=True
            )
            await asyncio.sleep(backoff)
            backoff = min(backoff * 2, backoff_cap)
            continue

        await asyncio.sleep(_settings.poll_interval_seconds)


# Suricata severity (1-3) → Wazuh-scale integer for the shared severity_min_level filter.
# Mapping: 1=Critical→7, 2=High→6, 3=Medium→5.
# Only sev 1 (→7) and sev 2 (→6) pass the default threshold of 7.
# sev 3 (→5) and unknown (→0) are filtered out.
_SURICATA_SEVERITY_MAP: dict[int, int] = {1: 7, 2: 6, 3: 5}


async def _suricata_tailer_loop() -> None:
    """Continuously tail Suricata eve.json, parse alert events, cluster them.

    Mirrors the Wazuh _tailer_loop pattern: byte-offset tracking, exponential
    backoff on failure, and severity pre-filtering before feeding the shared
    AlertClusterer. Uses tail_eve_json() from agent.sources.suricata which
    handles JSON parsing and skips malformed lines internally.

    Suricata severity integers (1=Critical, 2=High, 3=Medium) are mapped to
    the Wazuh 0-15 scale so that severity_min_level applies to both sources
    (DEC-TAILER-001).
    """
    eve_file = _settings.suricata_eve_file
    offset = 0
    backoff = 2.0
    backoff_cap = 300.0

    # Seek to end on startup to avoid re-processing historical alerts
    try:
        offset = Path(eve_file).stat().st_size
        log.info("Suricata tailer starting at offset %d for %s", offset, eve_file)
    except FileNotFoundError:
        log.warning("Suricata eve.json not found yet: %s — will retry", eve_file)

    while True:
        try:
            new_offset, alerts_parsed = await asyncio.to_thread(
                _read_suricata_lines, eve_file, offset
            )
            offset = new_offset

            for fields in alerts_parsed:
                await _process_suricata_alert(fields)

            # Flush clusters whose window has expired (shared with Wazuh tailer)
            if _clusterer:
                expired = _clusterer.flush_expired()
                for cluster in expired:
                    await _persist_and_enqueue(cluster)

        except asyncio.CancelledError:
            raise
        except Exception as exc:
            log.warning(
                "Suricata tailer error (backoff=%.1fs): %s", backoff, exc, exc_info=True
            )
            await asyncio.sleep(backoff)
            backoff = min(backoff * 2, backoff_cap)
            continue

        await asyncio.sleep(_settings.suricata_poll_seconds)


def _read_suricata_lines(eve_file: str, offset: int) -> tuple[int, list[dict]]:
    """Read new alert lines from eve.json since last offset. Runs in thread pool.

    Calls tail_eve_json which handles FileNotFoundError and malformed JSON
    gracefully. Returns (new_offset, list_of_parsed_alert_dicts). Non-alert
    event types are returned as-is; _process_suricata_alert filters them via
    parse_suricata_alert.
    """
    parsed: list[dict] = []
    new_offset = offset
    for new_pos, line_dict in tail_eve_json(eve_file, from_position=offset):
        new_offset = new_pos
        parsed.append(line_dict)
    return new_offset, parsed


async def _process_suricata_alert(line_dict: dict) -> None:
    """Parse one eve.json event dict and route to clusterer if it passes filters.

    Filters:
      1. parse_suricata_alert returns None for non-alert event_types.
      2. Severity pre-filter: Suricata sev mapped to Wazuh scale, then
         compared against settings.severity_min_level.
    """
    fields = parse_suricata_alert(line_dict)
    if fields is None:
        return  # not an alert event (flow, dns, anomaly, etc.)

    # Map Suricata severity (1-3) to Wazuh integer scale for shared filter
    suricata_sev_str = fields.get("normalized_severity", "Low")
    sev_str_to_int = {"Critical": 1, "High": 2, "Medium": 3}
    suricata_int = sev_str_to_int.get(suricata_sev_str, 99)
    wazuh_scale_sev = _SURICATA_SEVERITY_MAP.get(suricata_int, 0)

    if wazuh_scale_sev < _settings.severity_min_level:
        return

    src_ip = fields.get("src_ip") or "unknown"
    try:
        rule_id = int(fields["rule_id"])
    except (KeyError, ValueError, TypeError):
        log.warning("Suricata alert missing valid rule_id: %s", str(fields)[:120])
        return

    alert = Alert(
        id=f"suricata:{fields.get('timestamp', '')}:{rule_id}:{src_ip}",
        rule_id=rule_id,
        src_ip=str(src_ip),
        severity=wazuh_scale_sev,
        raw=line_dict,
        source="suricata",
    )

    closed = _clusterer.add(alert)
    insert_alert(_db, alert.id, alert.rule_id, alert.src_ip, alert.severity, alert.raw)

    for cluster in closed:
        await _persist_and_enqueue(cluster)


def _read_new_lines(alerts_file: str, offset: int) -> dict:
    """Read new lines from alerts.json since last offset. Runs in thread pool."""
    try:
        size = Path(alerts_file).stat().st_size
    except FileNotFoundError:
        return {"lines": [], "new_offset": offset}

    if size < offset:
        # File was rotated
        offset = 0

    if size == offset:
        return {"lines": [], "new_offset": offset}

    lines = []
    with open(alerts_file, "r", encoding="utf-8", errors="replace") as fh:
        fh.seek(offset)
        for raw_line in fh:
            stripped = raw_line.strip()
            if stripped:
                lines.append(stripped)
        new_offset = fh.tell()

    return {"lines": lines, "new_offset": new_offset}


async def _process_line(line: str) -> None:
    """Parse one JSON line and route to clusterer if it passes severity filter."""
    try:
        raw = json.loads(line)
    except json.JSONDecodeError:
        log.debug("Non-JSON line skipped: %s", line[:80])
        return

    alert = parse_wazuh_alert(raw)
    if alert is None:
        return

    if alert.severity < _settings.severity_min_level:
        return

    closed = _clusterer.add(alert)
    # Persist the alert itself
    insert_alert(_db, alert.id, alert.rule_id, alert.src_ip, alert.severity, alert.raw)

    for cluster in closed:
        await _persist_and_enqueue(cluster)


async def _persist_and_enqueue(cluster: Cluster) -> None:
    """Write cluster to SQLite and add to triage queue."""
    if not cluster.alerts:
        return

    upsert_cluster(
        _db,
        cluster_id=cluster.id,
        src_ip=cluster.src_ip,
        rule_id=cluster.rule_id,
        window_start=cluster.window_start.isoformat(),
        window_end=cluster.window_end.isoformat(),
        alert_count=cluster.alert_count,
        source=cluster.source,
    )
    # Update alert rows with cluster assignment
    from .models import update_alert_cluster
    for alert in cluster.alerts:
        update_alert_cluster(_db, alert.id, cluster.id)

    await _triage_queue.enqueue(cluster)
    log.info(
        "Cluster %s persisted (%d alerts, src_ip=%s, rule=%d)",
        cluster.id,
        cluster.alert_count,
        cluster.src_ip,
        cluster.rule_id,
    )


async def _save_triage_result(result: TriageResult) -> None:
    """Callback invoked by TriageQueue worker after a successful Claude call."""
    update_cluster_ai(_db, result.cluster_id, result.severity, result.threat_assessment)

    if result.yara_rule:
        syntax_valid = _check_yara_syntax(result.yara_rule)
        rule_id = str(uuid.uuid4())
        insert_rule(
            _db,
            rule_id=rule_id,
            cluster_id=result.cluster_id,
            rule_type="yara",
            rule_content=result.yara_rule,
            syntax_valid=syntax_valid,
        )
        log.info(
            "YARA rule stored for cluster %s (syntax_valid=%s)",
            result.cluster_id,
            syntax_valid,
        )


def _check_yara_syntax(rule_content: str) -> bool:
    """Return True if the YARA rule compiles without errors.

    Gracefully returns False (rather than raising) if the yara Python
    library is not installed — the rule is stored but marked invalid.
    """
    try:
        import yara  # type: ignore
        yara.compile(source=rule_content)
        return True
    except ImportError:
        log.debug("yara-python not installed; skipping syntax check")
        return False
    except Exception as exc:
        log.warning("YARA syntax error: %s", exc)
        return False


# ---------------------------------------------------------------------------
# Entrypoint for local dev
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import uvicorn

    settings = get_settings()
    host = "127.0.0.1" if not settings.shaferhund_token else "0.0.0.0"
    uvicorn.run("agent.main:app", host=host, port=8000, reload=True)
