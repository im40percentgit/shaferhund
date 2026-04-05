# Shaferhund — Master Plan

## Original Intent

Build a fully automated, agentic blue-team cybersecurity defense platform. The user's vision (from the `hund` spec) covers 25 capability domains: real-time network traffic analysis, EDR, SIEM, UEBA, vulnerability management, IAM, cloud security, compliance, threat intelligence, automated incident response, phishing defense, DNS filtering, DLP, encryption management, container security, and more. The ultimate goal is a self-evolving offensive-defensive loop that attacks its own infrastructure, finds gaps, writes rules, and retests... an immune system, not a tool.

The user is having fun building this while also thinking about it as a potential startup. They chose the name "Shaferhund" (German Shepherd, a guard dog).

## Project Overview

Agentic blue-team cybersecurity defense platform for solo security engineers at startups. AI-powered alert triage that ingests Wazuh alerts, clusters them, sends to Claude API for severity classification / IOC detection / YARA rule generation.

**Target user:** Solo security engineer, <100 endpoints, no SIEM budget.
**Design doc:** `~/.gstack/projects/shaferhund/j-unknown-design-20260403-113500.md`

## Phase 1: Alert Triage Agent (Weekend Prototype)

**Status:** completed
**Landed:** 2026-04-05 (commit `cc301c8`, fast-forward merge of `feature/phase1-alert-triage`)
**Verified:** 2026-04-03 via tester trace `tester-20260403-184125-0382e0` — 7-layer verification, High confidence (unit tests ×9, module imports, YARA native extension, Docker image build, FastAPI live `/health`, parse→filter→cluster→SQLite pipeline smoke, source review vs spec). Acknowledged gaps: no live Claude API call (no key — mocked in unit tests), no full Wazuh compose stack run, no browser UI render.

### Architecture

```
[Wazuh Manager Container]
    |
    └── /var/ossec/logs/alerts/alerts.json (mounted volume)
                    |
              [File Tailer] (every 60s, dedup via alert ID)
              (severity pre-filter: level >= 7 only)
              (on read failure: exp. backoff, log warning)
                    |
              [Alert Clusterer] (5-min window, src_ip + rule_id)
              (max 50 alerts per cluster, split beyond that)
                    |
              [Triage Queue] (max depth: 100, oldest dropped)
              (hourly budget: 20 Claude calls, configurable)
                    |
              [Claude API] (structured: severity -> IOCs -> YARA)
              (on failure: queue + retry, dashboard shows "pending")
                    |
              [SQLite]
              ├── alerts (indexed columns)
              ├── alert_details (raw JSON, separate table)
              ├── clusters (AI analysis)
              └── rules (YARA content, syntax_valid flag)
                    |
              [FastAPI + HTMX Dashboard]
              ├── GET / (cluster list, hx-trigger="every 10s")
              ├── GET /clusters/{id} (detail + YARA rule)
              ├── POST /rules/{id}/deploy (write to /rules/ volume)
              └── GET /health (poller status, queue depth, last triage)
```

### Stack
- Python 3.12 + FastAPI
- Wazuh 4.x Docker image (Manager only, no OpenSearch)
- Claude API (anthropic SDK)
- SQLite
- HTMX + server-rendered HTML
- OCI-first: Podman + Docker compatible compose

### Eng Review Decisions
1. Wazuh 4.x Docker images (not 5.0-alpha0 fork)
2. Fork wazuh-docker single-node compose, strip to Manager only
3. Queue-and-retry with exponential backoff for Claude API failures
4. Manual rule reload (write YARA to volume, no docker exec)
5. pydantic-settings config module, fail fast on missing env vars
6. 8 core tests (config, clustering x3, triage x2, YARA validation)
7. Separate raw JSON into alert_details table
8. Tail alerts.json instead of OpenSearch (2 containers, ~1-2GB RAM)
9. Severity pre-filter (level >= 7) + hourly token budget (20 calls/hr)
10. /health endpoint + queue depth limit (100 clusters)
Also: max cluster size = 50 alerts

### Files to Create
```
shaferhund/
  compose.yaml                # Wazuh Manager + Shaferhund Agent
  agent/
    __init__.py
    main.py                   # FastAPI app + file tailer
    config.py                 # pydantic-settings, env var validation
    triage.py                 # Claude API integration
    cluster.py                # Alert clustering (5-min window)
    models.py                 # SQLite models
    templates/
      index.html              # HTMX dashboard
      cluster_detail.html     # Alert cluster detail + AI analysis
  tests/
    yara-fixtures/            # EICAR variants for YARA validation
    test_config.py            # Config validation tests (2)
    test_cluster.py           # Clustering tests (3)
    test_triage.py            # Triage tests (2)
    test_yara.py              # YARA syntax validation (1)
  Dockerfile                  # Python agent container
  requirements.txt            # Python dependencies
  README.md                   # Setup instructions
```

### Success Criteria
- `podman compose up` brings up Wazuh Manager + Shaferhund Agent
- Feed simulated alerts, AI triage produces severity rankings
- At least one YARA rule passes `yara --syntax-check`

### Decision Log

| ID | Title | Status |
|----|-------|--------|
| DEC-CONFIG-001 | pydantic-settings for env var validation | accepted |
| DEC-CLUSTER-001 | In-memory clusterer with SQLite persistence | accepted |
| DEC-TRIAGE-001 | asyncio.Queue with hourly budget + exp backoff | accepted |
| DEC-YARA-001 | Write YARA to /rules/ volume, no docker exec | accepted |
| DEC-AUTH-001 | SHAFERHUND_TOKEN; unset = localhost-only binding | accepted |
| DEC-PHASE1-LAND | Phase 1 merged to main after High-confidence verification (trace `tester-20260403-184125-0382e0`) | accepted |

## Phase 2: Unified Defense Agent (Weeks 2-4)

**Status:** planned

### Intent

Phase 1 shipped a *triage agent*. Phase 2 turns it into a *unified agentic defender*. "Unified" means Wazuh HIDS and Suricata NIDS feed a single clustering + triage + rules pipeline against one schema, so a third source in Phase 2.5 costs <200 LOC. "Agentic" means the Claude call is no longer a single-shot JSON extract: it becomes a tool-use loop where Claude can fetch extra cluster context, draft YARA and Sigma rules, and recommend deployment — all in one reasoning session, capped to prevent runaway spend. "Active defence" means high-confidence rules auto-deploy through a conservative policy gate with a full audit trail and one-click undo. The point of the gate is that mistakes are cheap to reverse; the point of the loop is that the agent thinks before it writes.

### Goals
- Ingest Suricata alerts through the existing pipeline (REQ-P0-P2-001)
- Schema evolves in place without a migration framework (REQ-P0-P2-002)
- Clustering keeps Wazuh and Suricata streams disjoint (REQ-P0-P2-003)
- Replace single-shot triage with a Claude tool-use orchestrator (REQ-P0-P2-004)
- Generate Sigma YAML alongside YARA, validated with pysigma (REQ-P0-P2-005)
- Policy-gated auto-deploy with audit + undo (REQ-P0-P2-006, REQ-P0-P2-007)
- Maintain Phase 1 test coverage and add ≥1 test per new capability (REQ-P0-P2-008, REQ-P0-P2-009)

### Non-Goals
- REQ-NOGO-P2-001: Cloud log ingestion (AWS CloudTrail, GCP Audit) — deferred to Phase 2.5
- REQ-NOGO-P2-002: OpenSearch or any non-SQLite storage — deferred to Phase 2.5/3
- REQ-NOGO-P2-003: Real-time posture scoring dashboard — deferred to Phase 3 after definition is locked
- REQ-NOGO-P2-004: Sigma → Wazuh/EDR rule conversion via `sigmac` — deferred to Phase 3 (needs manager rule reload)
- REQ-NOGO-P2-005: Live NIC tap for Suricata — Phase 2 uses pcap-replay only
- REQ-NOGO-P2-006: Multi-user auth / RBAC / signed audit logs — still single-user solo-dev scale
- REQ-NOGO-P2-007: Rule distribution to a fleet of agents — Phase 3

### Requirements

**Must-Have (P0)**
- REQ-P0-P2-001: Suricata container in `compose.yaml`, eve.json tailer, alerts parsed into the shared `alerts` table.
  - Acceptance: pcap-replay with a known-malicious pcap produces ≥1 row in `alerts` with `source='suricata'`.
- REQ-P0-P2-002: Schema extended with `source`, `dest_ip`, `protocol`, `normalized_severity` via idempotent `ALTER TABLE ADD COLUMN` in `init_db`.
  - Acceptance: starting on a Phase 1 DB and a fresh DB both yield identical `PRAGMA table_info(alerts)` output.
- REQ-P0-P2-003: Clustering key becomes `(source, src_ip, rule_id)` so Wazuh and Suricata alerts never merge.
  - Acceptance: unit test feeds 1 Wazuh alert + 1 Suricata alert with identical `src_ip` and `rule_id` → 2 distinct clusters.
- REQ-P0-P2-004: Tool-use orchestrator replacing the single-shot `call_claude`, with 6 tools and caps of 5 tool calls + 10s wall time per cluster.
  - Acceptance: mock Anthropic client drives a 3-tool-call loop ending in `finalize_triage`; cluster row gets `ai_severity` + `ai_analysis`.
- REQ-P0-P2-005: Sigma rule generation via `write_sigma_rule` tool; `pysigma` validates syntax; rules persist with `rule_type='sigma'`.
  - Acceptance: known-good Sigma YAML passes validation and lands in `rules` with `syntax_valid=1`; a malformed YAML lands with `syntax_valid=0`.
- REQ-P0-P2-006: Policy-gated auto-deploy, default OFF. When enabled, YARA rules auto-deploy iff `confidence≥0.85 AND severity∈{Critical,High} AND syntax_valid=1 AND no similar rule deployed in the last 60 min`.
  - Acceptance: with `AUTO_DEPLOY_ENABLED=true` a high-confidence Critical YARA rule deploys; a conf=0.6 rule does NOT.
- REQ-P0-P2-007: `deploy_events` audit table, dashboard section, and `POST /rules/{id}/undo-deploy` endpoint that deletes the rule file and marks the audit row `reverted_at`.
  - Acceptance: deploy → undo → rule file is gone and audit row shows `reverted_at` set.
- REQ-P0-P2-008: ≥1 new unit test per new capability (orchestrator, Suricata parser, policy gate, schema evolution, Sigma validation, deploy+undo).
- REQ-P0-P2-009: `call_claude` remains importable as a backwards-compat shim; all Phase 1 tests pass unchanged.

**Nice-to-Have (P1)**
- REQ-P1-P2-001: `search_related_alerts` tool surfaces Wazuh+Suricata events for the same `src_ip` in the prompt (cross-source correlation).
- REQ-P1-P2-002: Dashboard filter chip: view-by-source (`wazuh` / `suricata` / `all`).
- REQ-P1-P2-003: Dry-run mode for auto-deploy: logs "would deploy" events without writing files.
- REQ-P1-P2-004: Per-tool-call metrics (latency, success rate) on `/health`.

**Future Consideration (P2)**
- REQ-P2-P2-001: Posture scoring — definition TBD, candidates: running threat-level, per-source trust score, CIS-style pass rate.
- REQ-P2-P2-002: Cloud log source (CloudTrail, GCP Audit) — Phase 2.5.
- REQ-P2-P2-003: Sigma → Wazuh rule conversion via `sigmac` — Phase 3.
- REQ-P2-P2-004: Auto-deploy for Sigma rules (requires sigmac conversion first) — Phase 3.

### Architecture

```
[Wazuh Manager Container]                  [Suricata Container]
    |                                          |
    |-- /var/ossec/logs/alerts/alerts.json     |-- /var/log/suricata/eve.json
    |                                          |     (fed by tcpreplay pcaps)
    v                                          v
[Wazuh Tailer]                             [Suricata Tailer]
    |                                          |
    +--------------+             +-------------+
                   v             v
              [Alert Normaliser]
              (source, dest_ip, protocol, normalized_severity)
                   |
                   v
              [Clusterer]  key = (source, src_ip, rule_id)
                   |
                   v
              [Triage Queue]  (Phase 1 hourly budget unchanged)
                   |
                   v
              [Orchestrator: Claude Tool-Use Loop]
                 tools:
                   - get_cluster_context       (read)
                   - search_related_alerts     (read, cross-source)
                   - write_yara_rule           (write, YARA)
                   - write_sigma_rule          (write, Sigma + pysigma)
                   - recommend_deploy          (signal policy gate)
                   - finalize_triage           (commit verdict, close loop)
                 caps: 5 tool calls, 10s wall, 1 hourly-budget slot
                   |
                   v
              [SQLite]
              ├── alerts (+ source, dest_ip, protocol, normalized_severity)
              ├── alert_details
              ├── clusters
              ├── rules (rule_type in {'yara', 'sigma'})
              └── deploy_events  (NEW: audit + undo)
                   |
                   v
              [Policy Gate]
                 conf >= 0.85 AND severity in (Critical, High)
                 AND rule_type == 'yara' AND dedup OK
                 AND AUTO_DEPLOY_ENABLED=true
                   |
                   v
              [Auto-Deploy]  →  /rules/<rule_id>.yar  (+ deploy_events row)
              (else: stays pending, visible on dashboard)
                   |
                   v
              [FastAPI + HTMX Dashboard]
              ├── GET / (cluster list, source filter chip)
              ├── GET /clusters/{id} (detail + YARA + Sigma + deploy status)
              ├── GET /deploy-events (audit log)
              ├── POST /rules/{id}/deploy (manual, Phase 1 behaviour)
              ├── POST /rules/{id}/undo-deploy (NEW)
              └── GET /health (adds orchestrator + auto-deploy counters)
```

### Stack
- Existing Phase 1 stack (Python 3.12 + FastAPI + anthropic SDK + SQLite + HTMX)
- **New:** Suricata 7 via `jasonish/suricata:7.0-latest` image
- **New:** `tcpreplay` via `ghcr.io/appneta/tcpreplay:latest` for pcap replay
- **New:** `pysigma` Python library for Sigma rule validation
- **New:** Community pcap fixtures committed under `tests/pcap-fixtures/` (benign + malicious)
- **New env vars:** `AUTO_DEPLOY_ENABLED`, `AUTO_DEPLOY_CONF_THRESHOLD`, `AUTO_DEPLOY_DEDUP_WINDOW_SECONDS`, `SURICATA_EVE_FILE`, `ORCH_MAX_TOOL_CALLS`, `ORCH_WALL_TIMEOUT_SECONDS`

### Eng Review Decisions
1. Suricata 7 container with pcap-replay via tcpreplay (no live NIC tap) — deterministic test stand, solo-dev friendly
2. Sigma: generate YAML only, validate with `pysigma`, defer `sigmac` conversion to Phase 3
3. Claude tool-use loop replaces single-shot `call_claude`; 6 tools, 5 tool-calls/10s caps; `call_claude` becomes a shim for backwards compat
4. Policy-gated auto-deploy: `conf≥0.85 AND severity∈{Critical,High} AND rule_type=yara AND dedup-window OK`; default OFF; every deploy audited + reversible
5. Schema evolves via idempotent `ALTER TABLE ADD COLUMN` in `init_db`; no Alembic, no migration framework
6. Cluster key becomes `(source, src_ip, rule_id)` so Wazuh/Suricata streams stay disjoint
7. ≥1 new unit test per new capability; all Phase 1 tests pass unchanged
8. New `deploy_events` table captures who/what/when/why and supports undo
9. Auto-deploy for Sigma is explicitly out of scope (no deploy path without sigmac) — dashboard shows "stored, not deployed"
10. Suricata ruleset is ET Open community rules baked at image build time; per-deploy rule updates are a Phase 3 concern

### Files to Create
```
shaferhund/
  compose.yaml                     # (UPDATE) add suricata + tcpreplay services + eve.json volume
  requirements.txt                 # (UPDATE) add pysigma
  .env.example                     # (UPDATE) add Phase 2 env vars
  agent/
    orchestrator.py                # (NEW) Claude tool-use loop, 6 tools, caps
    policy.py                      # (NEW) should_auto_deploy() + dedup lookup
    normaliser.py                  # (NEW) alert → common schema shape
    sources/
      __init__.py                  # (NEW)
      wazuh.py                     # (NEW) moved from cluster.parse_wazuh_alert
      suricata.py                  # (NEW) parse_suricata_alert + eve.json tailer helper
    triage.py                      # (UPDATE) call_claude → shim over orchestrator.run_triage_loop
    cluster.py                     # (UPDATE) Alert.source field, key becomes (source, src_ip, rule_id)
    models.py                      # (UPDATE) ALTER TABLE + deploy_events + CRUD helpers
    main.py                        # (UPDATE) dual tailer loops, new routes, health metrics
    templates/
      index.html                   # (UPDATE) source filter chip
      cluster_detail.html          # (UPDATE) Sigma rule + deploy status
      deploy_events.html           # (NEW) audit log view
  tests/
    pcap-fixtures/                 # (NEW) benign.pcap + malicious.pcap
    fixtures/
      suricata_eve_sample.json     # (NEW) known-good eve.json lines
      sigma_valid.yml              # (NEW) known-good Sigma rule
      sigma_invalid.yml            # (NEW) malformed Sigma rule
    test_schema_evolution.py       # (NEW) Phase 1 DB + fresh DB → same table_info
    test_suricata_parser.py        # (NEW) parse eve.json fixture rows
    test_cluster_multi_source.py   # (NEW) cross-source disjoint clustering
    test_orchestrator.py           # (NEW) mock client drives multi-tool loop
    test_sigma_validation.py       # (NEW) pysigma valid + invalid fixtures
    test_policy_gate.py            # (NEW) conf, severity, dedup, disabled
    test_deploy_undo.py            # (NEW) deploy → undo → file gone, audit row reverted
```

### Success Criteria
- `podman compose up` brings up Wazuh Manager + Suricata + Shaferhund Agent
- `tcpreplay` replays a malicious pcap → Suricata emits eve.json → agent ingests, clusters, and triages
- Orchestrator log shows Claude making 2-5 tool calls on at least one cluster (read → write → finalize)
- At least one Sigma rule passes `pysigma` validation; at least one YARA rule passes `yara --syntax-check`
- With `AUTO_DEPLOY_ENABLED=true`, a simulated high-confidence Critical cluster produces a file in `/rules/` and a row in `deploy_events`
- Undo endpoint removes the file and marks the audit row `reverted_at`
- All Phase 1 tests pass unchanged; all new Phase 2 tests pass

### Decision Log

| ID | Title | Status |
|----|-------|--------|
| DEC-SURICATA-001 | Suricata 7 container + pcap-replay via tcpreplay | planned |
| DEC-SIGMA-001 | Generate Sigma YAML only, validate with pysigma, defer sigmac | planned |
| DEC-ORCH-001 | Claude tool-use loop with 6 tools, 5-call / 10s caps | planned |
| DEC-AUTODEPLOY-001 | Policy-gated auto-deploy, conservative defaults, default OFF | planned |
| DEC-SCHEMA-002 | Extend alerts table via idempotent ALTER TABLE, no migration framework | planned |
| DEC-CLUSTER-002 | Cluster key becomes (source, src_ip, rule_id) | planned |
| DEC-TEST-001 | ≥1 new unit test per new capability; Phase 1 tests pass unchanged | planned |

## Phase 3: Immune System (Month 2+)

**Status:** planned
- Atomic Red Team integration for continuous self-testing
- Offensive-defensive loop
- Auto-generated honeypots and canary tokens
- Threat intel mesh (requires separate design)

## TODOs
- [ ] Convert hund to ROADMAP.md (map 25 domains to phases)
