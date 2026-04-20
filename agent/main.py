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
    Authorization: Bearer <token> or the ?token=<token> query param.
  - If SHAFERHUND_TOKEN is unset, the server binds to 127.0.0.1 only
    (set via the uvicorn --host flag in __main__ / compose entrypoint).

@decision DEC-AUTH-001
@title SHAFERHUND_TOKEN bearer auth; unset = localhost-only binding
@status accepted
@rationale Simple token is sufficient for a single-user local deployment.
           Unset token = localhost-only is safer than unset token = open.
           No session management needed at this scale.

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
import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from fastapi import Depends, FastAPI, HTTPException, Request, status
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from fastapi.templating import Jinja2Templates

from .cluster import Alert, AlertClusterer, Cluster, parse_wazuh_alert
from .config import Settings, get_settings
from .sources.suricata import parse_suricata_alert, tail_eve_json
from .models import (
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
from .triage import TriageResult, TriageQueue

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
_poller_healthy: bool = False
_last_poll_at: Optional[str] = None


# ---------------------------------------------------------------------------
# Lifespan
# ---------------------------------------------------------------------------

@asynccontextmanager
async def lifespan(app: FastAPI):
    global _settings, _db, _triage_queue, _clusterer, _tailer_task, _suricata_tailer_task

    _settings = get_settings()
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
    log.info("Shaferhund agent started (wazuh-tailer + suricata-tailer running)")

    yield

    # Shutdown — cancel both tailer tasks
    for task in (_tailer_task, _suricata_tailer_task):
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
# Auth
# ---------------------------------------------------------------------------

_bearer_scheme = HTTPBearer(auto_error=False)


def _require_auth(
    request: Request,
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(_bearer_scheme),
) -> None:
    """FastAPI dependency: enforce token auth when SHAFERHUND_TOKEN is set."""
    token = _settings.shaferhund_token if _settings else ""
    if not token:
        return  # No token configured — localhost-only binding is the guard

    provided = None
    if credentials and credentials.scheme.lower() == "bearer":
        provided = credentials.credentials
    if not provided:
        provided = request.query_params.get("token")

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
    """Poller status, queue depth, and last triage timestamp.

    Always returns 200 — even if the tailer is degraded — so container
    health checks don't cycle the service on transient read errors.
    """
    stats = get_stats(_db) if _db else {}
    return JSONResponse({
        "status": "ok",
        "poller_healthy": _poller_healthy,
        "queue_depth": _triage_queue.depth if _triage_queue else 0,
        "calls_this_hour": _triage_queue.calls_this_hour if _triage_queue else 0,
        "hourly_budget": _settings.triage_hourly_budget if _settings else 0,
        "last_poll_at": _last_poll_at,
        "last_triage_at": stats.get("last_triage"),
        "total_alerts": stats.get("total_alerts", 0),
        "total_clusters": stats.get("total_clusters", 0),
        "pending_triage": stats.get("pending_triage", 0),
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
