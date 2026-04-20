# Shaferhund

Shaferhund is a self-hosted alert triage agent for the solo security engineer protecting fewer than 100 endpoints on no SIEM budget. It ingests alerts from Wazuh (HIDS) and Suricata (NIDS), clusters them, and hands each cluster to a Claude tool-use loop that drafts YARA and Sigma detection rules. High-confidence rules can auto-deploy through a conservative policy gate with a full audit trail and one-click undo. The dashboard is a single browser tab — no accounts, no cloud dependency, no recurring SaaS cost.

## Quickstart

```
1. cp .env.example .env
2. Fill in ANTHROPIC_API_KEY (and SHAFERHUND_TOKEN if binding to non-localhost)
3. podman compose up   (or: docker compose up)
4. Open http://localhost:8000
```

Wazuh Manager starts first. Once its healthcheck passes, the shaferhund agent comes up alongside Suricata. The first cluster should appear on the dashboard within a few minutes of the Wazuh manager generating alerts.

## Architecture

```
[Wazuh HIDS alerts.json]     [Suricata NIDS eve.json]
         |                            |
    [Wazuh Tailer]             [Suricata Tailer]
         |                            |
         +----------+    +-----------+
                    v    v
             [Alert Normaliser]
          source / dest_ip / protocol
             / normalized_severity
                    |
               [Clusterer]
          key: (source, src_ip, rule_id)
          5-min window, max 50 per cluster
                    |
             [Triage Queue]
          max depth 100, hourly budget 20
                    |
      [Orchestrator: Claude Tool-Use Loop]
        get_cluster_context
        search_related_alerts
        write_yara_rule
        write_sigma_rule
        recommend_deploy
        finalize_triage
        caps: 5 tool calls / 10 s wall time
                    |
              [SQLite]
        alerts / clusters / rules
        deploy_events (audit + undo)
                    |
         [Policy Gate]
     conf >= 0.85 AND severity in
     {Critical, High} AND dedup OK
     AND AUTO_DEPLOY_ENABLED=true
                    |
         [Auto-Deploy]  -->  /rules/<id>.yar
                    |
    [FastAPI + HTMX Dashboard]
    GET  /               cluster list, source filter
    GET  /clusters/{id}  detail, YARA, Sigma, deploy status
    GET  /deploy-events  audit log
    POST /rules/{id}/deploy       manual deploy
    POST /rules/{id}/undo-deploy  one-click undo
    GET  /health         orchestrator stats, counters
```

Two source streams feed a shared normaliser so adding a third source costs less than 200 lines. The clusterer keeps Wazuh and Suricata alert streams disjoint by keying on `(source, src_ip, rule_id)`. The orchestrator loop gives Claude multiple turns to gather context, draft rules, and commit a verdict before the budget slot is consumed.

## Phase 2 Highlights

**Dual NIDS/HIDS ingestion.** Suricata 7 runs in pcap-read mode alongside Wazuh. Both streams flow through the same normaliser and clusterer into a single SQLite database.

**Deterministic test stand.** Suricata reads pcap fixtures replayed by tcpreplay instead of tapping a live NIC. Test outcomes are reproducible in CI without network promiscuous mode.

**Claude tool-use orchestrator.** Replaces the Phase 1 single-shot call with a loop of up to 6 tools capped at 5 calls and 10 seconds wall time per cluster. The `call_claude` function remains importable as a backwards-compat shim.

**Sigma rule generation.** The `write_sigma_rule` tool drafts Sigma YAML validated with pysigma. Rules are stored with `rule_type='sigma'` and marked `syntax_valid` accordingly. Sigma-to-Wazuh conversion via sigmac is deferred to Phase 3.

**Policy-gated auto-deploy.** Default OFF. When enabled, YARA rules that meet `confidence >= 0.85`, `severity in {Critical, High}`, pass syntax check, and fall outside the dedup window are written to `/rules/` automatically. Every deploy event is audited. `POST /rules/{id}/undo-deploy` deletes the rule file and marks the audit row reverted.

**Audit log and undo.** The `/deploy-events` page shows every deploy and its current status. Undo is a single HTTP call.

**Health metrics.** `GET /health` exposes orchestrator statistics and 24-hour auto-deploy counters alongside the standard liveness fields.

## Configuration

Copy `.env.example` to `.env` and fill in your values. The only required variable is `ANTHROPIC_API_KEY`. All others have safe defaults.

Variable categories:

- **Claude API** — `ANTHROPIC_API_KEY`, `CLAUDE_MODEL`
- **Dashboard auth** — `SHAFERHUND_TOKEN` (unset = localhost-only binding)
- **Source paths** — `ALERTS_FILE`, `SURICATA_EVE_FILE`
- **Triage budget** — `TRIAGE_HOURLY_BUDGET`, `POLL_INTERVAL_SECONDS`, `SURICATA_POLL_SECONDS`, `SEVERITY_MIN_LEVEL`
- **Clustering** — `CLUSTER_MAX_ALERTS`, `CLUSTER_WINDOW_SECONDS`, `QUEUE_MAX_DEPTH`
- **Storage** — `DB_PATH`, `RULES_DIR`
- **Orchestrator caps** — `ORCH_MAX_TOOL_CALLS`, `ORCH_WALL_TIMEOUT_SECONDS`
- **Auto-deploy policy** — `AUTO_DEPLOY_ENABLED`, `AUTO_DEPLOY_CONF_THRESHOLD`, `AUTO_DEPLOY_DEDUP_WINDOW_SECONDS`, `AUTO_DEPLOY_SEVERITIES`

See `.env.example` for defaults and inline comments on each variable.

## Services

| Service | Image | Role |
|---------|-------|------|
| `wazuh.manager` | `wazuh/wazuh-manager:4.9.2` | HIDS manager; writes alerts to shared volume |
| `suricata` | `docker/Dockerfile.suricata` | NIDS; reads pcap via `-r`, writes eve.json |
| `tcpreplay` | `ghcr.io/appneta/tcpreplay:latest` | Replays pcap fixtures for live-replay testing |
| `shaferhund-agent` | `Dockerfile` | Tailer + clusterer + orchestrator + dashboard |

The shaferhund agent mounts `wazuh_logs` (read-only) and `suricata_logs` (read-only).

## Development

```bash
pip install -r requirements.txt
ANTHROPIC_API_KEY=test pytest tests/
```

## Endpoints

- `GET /` — HTMX dashboard (cluster list, source filter, auto-refresh 10s)
- `GET /clusters/{id}` — Cluster detail, YARA rule, Sigma rule, deploy status
- `GET /deploy-events` — Auto-deploy audit log
- `POST /rules/{id}/deploy` — Manually deploy a YARA rule to `/rules/`
- `POST /rules/{id}/undo-deploy` — Remove deployed rule file and mark audit row reverted
- `GET /health` — Poller status, queue depth, orchestrator stats, auto-deploy counters
