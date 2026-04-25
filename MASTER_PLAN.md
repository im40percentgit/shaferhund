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

**Status:** completed
**Landed:** 2026-04-09 through 2026-04-14 across waves b/c/d, 11 merge commits (first: `a269990` cluster-key-refactor #6; last: `7ac1d9e` docs-and-env #14). Issues #6–#15 all closed with `phase-2` labels.
**Verified:** no dedicated end-to-end tester trace recorded; each feature branch landed via PR-gated merge with per-branch test suite green.

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
- REQ-NOGO-P2-001: Cloud log ingestion (AWS CloudTrail, GCP Audit) — deferred to Phase 4 (re-routed from Phase 2.5 per DEC-CLOUDLOG-001)
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
- REQ-P2-P2-002: Cloud log source (CloudTrail, GCP Audit) — Phase 4 (re-routed from Phase 2.5 per DEC-CLOUDLOG-001).
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
| DEC-SURICATA-001 | Suricata 7 container + pcap-replay via tcpreplay | accepted |
| DEC-SIGMA-001 | Generate Sigma YAML only, validate with pysigma, defer sigmac | accepted |
| DEC-ORCH-001 | Claude tool-use loop with 6 tools, 5-call / 10s caps | accepted |
| DEC-AUTODEPLOY-001 | Policy-gated auto-deploy, conservative defaults, default OFF | accepted |
| DEC-SCHEMA-002 | Extend alerts table via idempotent ALTER TABLE, no migration framework | accepted |
| DEC-CLUSTER-002 | Cluster key becomes (source, src_ip, rule_id) | accepted |
| DEC-TEST-001 | ≥1 new unit test per new capability; Phase 1 tests pass unchanged | accepted |

## Phase 2.5: Sigma Deploy Path (3–4 days)

**Status:** completed
**Started:** 2026-04-22 (planner trace `planner-20260422-201536-956a04`, plan-only PR on `docs/plan-phase-2.5-start`)
**Completed:** 2026-04-22
**Timebox:** 3–4 days

### Shipped
- #30 — sigmac wrapper + Dockerfile install (REQ-P0-P25-001)
- #29 — sigma-cli startup probe + /metrics exposure (REQ-P0-P25-003, REQ-P1-P25-001)
- #31 — policy gate + orchestrator Sigma routing (REQ-P0-P25-002)
- #27 closed — no-regression gate satisfied by #31's test suite (REQ-P0-P25-004)

### Intent

Phase 2 shipped Sigma rule generation wired up but auto-deploy explicitly blocked at `agent/policy.py:73` (DEC-AUTODEPLOY-001) — Sigma YAML can't become a Wazuh-native rule without sigmac conversion. Phase 2.5 closes that gap only. Cloud log ingestion (originally `REQ-NOGO-P2-001`) moves to Phase 4 where it belongs alongside multi-cloud and CSPM — ingesting CloudTrail in a homelab without a real AWS footprint would be fixture theatre (violating backlog item #5, "fixture-only testing is insufficient"), and the "source-agnostic" architecture is already proven by Wazuh + Suricata. Rule fleet distribution also stays in Phase 4.

**Post-CSO reconciliation (2026-04-22):** The CSO audit (PRs #18–23) reshaped two surfaces this phase touches. (1) Operational stats moved from `/health` to `/metrics` behind `_require_auth` (DEC-HEALTH-002 at `agent/main.py:228`), so the P1 sigmac-exposure item targets `/metrics`, not `/health`. (2) `finalize_triage` now writes `ai_confidence` as a float (default 0.0) and `should_auto_deploy` hard-guards `None` before the threshold compare (DEC-AUTODEPLOY-002 at `agent/policy.py:82`); the Sigma auto-deploy path inherits that guarantee for free — the new `rule_type='sigma'` branch does not need to re-implement the None guard, only extend the eligibility check. Any new orchestrator-touching code must preserve the `system=` kwarg prompt pattern and the `sanitize_alert_field()` input-sanitisation applied in Phase 2's post-audit pass.

### Goals
- Sigma rules auto-deploy through the same policy gate as YARA, via upstream sigmac conversion (REQ-P0-P25-001, REQ-P0-P25-002)
- Graceful degradation if sigmac is absent — disable Sigma auto-deploy, don't crash (REQ-P0-P25-003)
- Zero regressions in Phase 1 or Phase 2 tests (REQ-P0-P25-004)

### Non-Goals
- REQ-NOGO-P25-001: Cloud log source ingestion — moved to Phase 4 (needs real footprint to test meaningfully)
- REQ-NOGO-P25-002: Custom Wazuh rule templates or sigmac patching — upstream sigmac defaults only
- REQ-NOGO-P25-003: Rule fleet distribution to remote agents — Phase 4
- REQ-NOGO-P25-004: Wazuh API reload — retain file-drop pattern from DEC-YARA-001
- REQ-NOGO-P25-005: Sigma rule format customisation beyond sigma-cli's Wazuh backend defaults

### Requirements

**Must-Have (P0)**
- REQ-P0-P25-001: `sigma-cli` (upstream `pysigma` + `pysigma-backend-wazuh`) installed in the container image; `agent/sigmac.py` wraps `sigma convert` as a subprocess call producing Wazuh XML at `/rules/sigma_{rule_id}.xml`.
  - Acceptance: a stored Sigma rule with `syntax_valid=1` produces a well-formed XML file under `/rules/`; `xmllint --noout` passes on the output.
- REQ-P0-P25-002: `should_auto_deploy()` in `agent/policy.py` accepts `rule_type ∈ {'yara', 'sigma'}` and additionally requires `settings.sigmac_available=True` before allowing Sigma deploys. `_run_auto_deploy` in `agent/orchestrator.py` routes Sigma rules through `agent/sigmac.py` before file drop.
  - Acceptance: a Critical Sigma rule with `ai_confidence≥0.85` auto-deploys (XML file + `deploy_events` row with `rule_type='sigma'`); a conf=0.6 Sigma rule stays pending.
- REQ-P0-P25-003: Startup probes `sigma-cli --version`; if missing, log one WARNING line and set `settings.sigmac_available=False`. Sigma rules continue to generate and persist, but `should_auto_deploy()` returns False for them.
  - Acceptance: container booted without sigma-cli installed starts cleanly and serves `/health`; Sigma rules are stored with `syntax_valid=1`, `deployed=0`.
- REQ-P0-P25-004: All Phase 1 and Phase 2 tests pass unchanged.

**Nice-to-Have (P1)**
- REQ-P1-P25-001: `/metrics` (the authenticated stats endpoint per DEC-HEALTH-002; CSO F5 split this off from `/health`) exposes `sigmac.available` (bool) and `sigmac.version` (string, nullable). `/health` itself stays minimal — status + poller health only.
- REQ-P1-P25-002: Dashboard cluster-detail view shows converted XML preview alongside raw Sigma YAML for rules that deployed.

**Future Consideration (P2)**
- REQ-P2-P25-001: Rule fleet distribution — Phase 4.
- REQ-P2-P25-002: Cloud log source ingestion (first provider) + multi-cloud coverage — Phase 4.

### Architecture Delta vs Phase 2

```
[Orchestrator finalize_triage]
         |
         v
    [Policy Gate]  (now accepts rule_type='sigma' when sigmac_available)
         |
         +--- rule_type='yara' ---> [/rules/{id}.yar]              (Phase 2 path, unchanged)
         |
         +--- rule_type='sigma' --> [agent/sigmac.py convert]
                                          |
                                          v
                                  [/rules/sigma_{id}.xml]
                                          |
                                          v
                                  [deploy_events audit row with rule_type='sigma']
```

### Stack Delta
- **New CLI:** `sigma-cli` installed via `pip install sigma-cli pysigma-backend-wazuh`
- **New env vars:** `SIGMAC_PATH` (default `sigma`)

### Eng Review Decisions
1. sigmac invocation: subprocess (`sigma convert`), not the Python API — sigma-cli's import surface is unstable across minor versions.
2. Sigma auto-deploy reuses the existing policy gate with an allowlist change plus an availability check; no parallel gate.
3. Graceful degradation if sigmac is missing — log a warning, keep Sigma rules as pending. No hard dependency.
4. Wazuh manager reload: retain file-drop pattern from DEC-YARA-001; rely on existing rule-directory monitoring. Document any manual restart requirement in README.
5. Cloud log source explicitly moved to Phase 4 — homelab lacks a real cloud footprint to test against, so an interim implementation would be fixture-only and violate the "fixture-only testing is insufficient" rule.

### Files to Create / Update
```
shaferhund/
  Dockerfile                          # (UPDATE) install sigma-cli
  requirements.txt                    # (UPDATE) add sigma-cli, pysigma-backend-wazuh
  .env.example                        # (UPDATE) document SIGMAC_PATH
  agent/
    policy.py                         # (UPDATE) rule_type allowlist + sigmac_available gate
    orchestrator.py                   # (UPDATE) route Sigma rules through sigmac in _run_auto_deploy
    sigmac.py                         # (NEW) subprocess wrapper + availability probe
    config.py                         # (UPDATE) sigmac_path field + sigmac_available runtime flag
    main.py                           # (UPDATE) /health additions (P1)
  tests/
    test_sigmac.py                    # (NEW) mock subprocess, validate XML output shape
    test_policy_gate_sigma.py         # (NEW) Sigma across conf/severity/sigmac-available matrix
    fixtures/
      sigma_wazuh_expected.xml        # (NEW) golden XML for a known-good Sigma input
```

### Success Criteria
- `podman compose up` brings up Wazuh + Suricata + Shaferhund; container reports `sigmac.available=true` on `/health`
- A simulated high-confidence Critical Sigma rule lands in `/rules/sigma_<id>.xml` with a matching `deploy_events` row
- Container started without sigma-cli installed serves `/health` cleanly, logs WARNING, and stores Sigma rules as pending
- Phase 1 and Phase 2 tests pass unchanged; new Phase 2.5 tests pass

### GitHub Issues

- **Wave A (parallel):**
  - #24 — REQ-P0-P25-001: agent/sigmac.py subprocess wrapper + Dockerfile sigma-cli install (`feature/phase2.5-sigmac-wrapper`)
  - #25 — REQ-P0-P25-003: sigma-cli startup probe + graceful degradation (`feature/phase2.5-sigmac-probe`)
- **Wave B (blocked by Wave A):**
  - #26 — REQ-P0-P25-002: policy gate accepts `rule_type='sigma'`; orchestrator routes through sigmac (`feature/phase2.5-policy-sigma-route`)
- **Wave C (gate, blocked by #24/#25/#26):**
  - #27 — REQ-P0-P25-004: zero regressions in Phase 1 + Phase 2 tests (merge-gate on integration branch)

### Decision Log

| ID | Title | Status |
|----|-------|--------|
| DEC-SIGMA-CONVERT-001 | sigmac invoked via subprocess (sigma-cli), not Python API — subprocess boundary isolates crashes; pysigma-backend-wazuh ships as a sigma-cli plugin, not a PyPI library | accepted |
| DEC-SIGMA-DEGRADE-001 | Startup probe sets `settings.sigmac_available`; downstream reads the bool (no re-probing per triage). Wrapper raises on missing binary; caller records a skipped `deploy_events` row before exception propagates | accepted |
| DEC-AUTODEPLOY-003 | `rule_type` gate expanded to `{yara, sigma}` via `_ELIGIBLE_RULE_TYPES` frozenset; Sigma additionally requires `settings.sigmac_available`; DEC-AUTODEPLOY-002's `ai_confidence` None-guard continues to protect both types; gate stays pure (attribute read only) | accepted |
| DEC-CLOUDLOG-001 | Cloud log source ingestion deferred to Phase 4 — needs real footprint to test, not fixtures | planned |

> Note: `DEC-AUTODEPLOY-002` is **already taken** by the CSO-audit None-guard decision at `agent/policy.py:82` (accepted). The original Phase 2.5 plan pre-reserved that ID for the Sigma gate; reassigned to `DEC-AUTODEPLOY-003` during the 2026-04-22 planner pass. Similarly `DEC-SIGMA-002`/`DEC-SIGMA-003` are renamed to `DEC-SIGMA-CONVERT-001`/`DEC-SIGMA-DEGRADE-001` so the IDs name the concept rather than the number.

## Phase 3: Immune System (2–3 weeks after Phase 2.5)

**Status:** completed
**Timebox:** 2–3 weeks
**Landed:** 2026-04-24 across PRs #37, #38, #39 (all squash-merged from `feature/phase3-*` branches; final commit `4e01640`)
**Verified:** 2026-04-24 via Phase 3 zero-regression gate (issue #36): 180 passed / 1 skipped / 0 failed; `/health` integrates `{threat_intel, canary, posture}` keys cleanly; DB migration Phase 2.5 → Phase 3 idempotent; compose.yaml integrates `redteam-target` for 5 services total.

### Intent

Phase 2 gave the agent eyes (unified Wazuh + Suricata ingestion), a brain (Claude tool-use orchestrator), and hands (policy-gated auto-deploy). Phase 2.5 finished the hands — Sigma rules auto-deploy too, via sigmac conversion. **Phase 3 gives it an immune system.** The agent attacks its own infrastructure on a schedule via Atomic Red Team, measures whether its deployed rules detect those attacks, and uses the resulting pass rate as a **single posture score**. An auto-spawnable canary network (DNS and HTTP tokens) traps opportunistic probing and feeds the same pipeline. A light-touch threat-intel feed (Abuse.ch URLhaus) adds indicator context to the orchestrator's reasoning. The platform becomes self-evaluating — when the posture score drops, the agent knows before the operator does.

This is deliberately **not** an agent-driven red team (Claude deciding when to attack) — that is Phase 4. Phase 3 is a scheduled, deterministic, measurable loop.

### Goals
- Atomic Red Team harness runs scheduled technique tests against a dedicated target container (REQ-P0-P3-001)
- ART-generated events propagate through the existing Wazuh pipeline unchanged (REQ-P0-P3-002)
- `posture_runs` table and `/posture` dashboard expose a single score: (ART tests that produced a triaged cluster with a deployed rule) / (total ART tests in the run) (REQ-P0-P3-003)
- Canary tokens (DNS + HTTP) spawn on demand; triggers land in the alerts pipeline with `source='canary'` (REQ-P0-P3-004)
- URLhaus indicators (URL + payload MD5) ingested hourly; orchestrator has a `check_threat_intel` tool (REQ-P0-P3-005)
- `/health` surfaces posture score + canary trigger count + threat-intel record count (REQ-P0-P3-006)
- All Phase 1, Phase 2, Phase 2.5 tests pass unchanged (REQ-P0-P3-007)

### Non-Goals
- REQ-NOGO-P3-001: Agent-driven red team (Claude decides when/what to attack) — Phase 4
- REQ-NOGO-P3-002: Full MITRE ATT&CK matrix coverage dashboard — only techniques actually executed by the declared ART test list
- REQ-NOGO-P3-003: Containerised service honeypots (SSH, MySQL, etc.) — DNS/HTTP canary tokens only
- REQ-NOGO-P3-004: STIX/TAXII threat-intel federation — URLhaus only
- REQ-NOGO-P3-005: Adversarial rule-effectiveness scoring (evasion variants, mutation) — Phase 4
- REQ-NOGO-P3-006: Alerting / paging when posture drops — log only in Phase 3
- REQ-NOGO-P3-007: Multi-tenant posture (per-team scores) — solo-dev still
- REQ-NOGO-P3-008: Dynamic orchestrator tool registration (refactor of `DEC-ORCH-003`) — Phase 4; Phase 3 patches `TOOLS` directly

### Requirements

**Must-Have (P0)**
- REQ-P0-P3-001: `redteam-runner` container executes a declarative list of ART tests (`atomic_tests.yaml`) on a schedule (cron inside the container or external orchestration). Each run writes a `posture_runs` row: `(id, started_at, finished_at, technique_ids JSON, total_tests, status)`. Endpoint `POST /posture/run` triggers an ad-hoc run.
  - Acceptance: hitting `POST /posture/run` spawns a run, emits visible Wazuh alert activity within 60s for at least one T1059 (PowerShell) test, and appends a row to `posture_runs` with `status='complete'`.
- REQ-P0-P3-002: ART tests execute inside a dedicated `redteam-target` container (minimal Ubuntu + Wazuh agent). Events flow through the existing Wazuh tailer — no new tailer code, no special parsing.
  - Acceptance: a T1059 PowerShell ART test produces at least one Wazuh alert matching a known rule_id; the alert is indistinguishable at the clusterer boundary from a production alert of the same technique.
- REQ-P0-P3-003: `posture_runs` joined with `clusters` and `rules` to compute per-run pass rate. A "pass" = test timestamp falls inside a cluster window AND cluster is linked to a rule with `deployed=1`. Overall score per run = `passes / total_tests`.
  - Acceptance: synthetic scenario (ART test fires → cluster triaged → rule deploys) yields pass > 0; ART test fires with no matching cluster → pass 0; ART test fires with matching cluster but no deployed rule → pass 0.
- REQ-P0-P3-004: `POST /canary/spawn` accepts `{type: 'dns'|'http', name}` and returns a trap URL or hostname. A lightweight receiver route (`GET /canary/hit/{token}`) and a DNS catch-all (via existing Wazuh DNS monitoring or a tiny dnslib responder in `redteam-target`) record hits as alerts with `source='canary'`.
  - Acceptance: spawn an HTTP canary, curl the trap URL, observe a `canary`-source row in `alerts` within 30s that triages through the normal pipeline.
- REQ-P0-P3-005: `threat_intel` table holds `(id, indicator, indicator_type, first_seen, last_seen, source, context_json)`. Hourly poller fetches URLhaus (online URLs + payload MD5s). New orchestrator tool `check_threat_intel(value)` returns `{matches: [...], context: ...}`.
  - Acceptance: a mocked URLhaus fixture yields ≥1 row in `threat_intel`; an orchestrator test drives a tool-use loop that includes `check_threat_intel` in its transcript and uses the response in the final verdict.
- REQ-P0-P3-006: `/health` JSON adds `posture.last_score` (float 0–1, null if no runs), `posture.last_run_at`, `canary.trigger_count_24h`, `threat_intel.record_count`.
  - Acceptance: hit `/health` after a completed posture run; `last_score` matches DB calculation; before any runs, `last_score` is null.
- REQ-P0-P3-007: All prior phases' tests pass unchanged; ≥1 new test per P0 capability.

**Nice-to-Have (P1)**
- REQ-P1-P3-001: `/posture` HTML dashboard — current score, 30-day sparkline, per-technique pass rate, failed-test drill-down.
- REQ-P1-P3-002: `/canary` dashboard page — active tokens, trigger counts, last-triggered timestamp, revoke action.
- REQ-P1-P3-003: Per-source pass-rate breakdown on posture dashboard (ART vs canary) so operators can see which half of the immune system is weaker.
- REQ-P1-P3-004: Orchestrator prefers Sigma output for process-execution ART techniques (T1059, T1053, etc.) since YARA isn't well-suited there — leverages Phase 2.5 Sigma auto-deploy path.
- REQ-P1-P3-005: Source filter chip on `/` extended with `canary`.

**Future Consideration (P2)**
- REQ-P2-P3-001: Agent-driven red team — Phase 4
- REQ-P2-P3-002: Containerised service honeypots — Phase 4
- REQ-P2-P3-003: Threat-intel federation (multiple feeds, STIX/TAXII) — Phase 4
- REQ-P2-P3-004: Posture SLO with paging — Phase 4
- REQ-P2-P3-005: Dynamic orchestrator tool registration — Phase 4 refactor

### Architecture

```
[redteam-runner container]     [Canary Receiver]         [URLhaus Poller]
(scheduled ART + on-demand)    (/canary/hit, DNS)        (hourly cron Task)
       |                              |                         |
       v                              v                         v
[redteam-target container]     [alerts: source='canary']  [threat_intel table]
(ART techniques execute here)         |                         ^
       |                              |                         |
       v                              v                         |
 [Wazuh + Suricata                    |                         |
  existing tailers]                   |                         |
       |                              |                         |
       v                              v                         |
[alerts: source='wazuh'/'suricata'/'canary']                    |
       |                              |                         |
       +--------+---------+-------[Clusterer] (unchanged)       |
                          |                                     |
                          v                                     |
                   [Triage Queue] (unchanged)                   |
                          |                                     |
                          v                                     |
              [Orchestrator Tool Loop]                          |
                existing 6 tools +                              |
                + check_threat_intel  ------------------------->+
                (patched into TOOLS list per DEC-ORCH-003)
                          |
                          v
              [Policy Gate] (YARA + Sigma via Phase 2.5)
                          |
                          v
              [/rules/ + deploy_events]
                          |
                          v
              [posture_runs join]
                ART test cross-check → pass/fail
                          |
                          v
              [/posture, /health]
```

### Stack
- Existing Phase 1/2/2.5 stack
- **New container:** `redteam-runner` — Atomic Red Team test invoker (upstream `redcanary/atomic-red-team` via `Invoke-AtomicTest` pwsh, OR a Python shim that clones the ART repo and runs technique scripts directly)
- **New container:** `redteam-target` — minimal Ubuntu + Wazuh agent, mounted into Wazuh manager's monitoring scope
- **New lib (optional):** `dnslib` for DNS canary responder if a standalone responder is needed; otherwise piggyback Wazuh DNS monitoring
- **New env vars:** `POSTURE_RUN_SCHEDULE` (cron expr), `URLHAUS_FEED_URL`, `URLHAUS_FETCH_INTERVAL_SECONDS` (default 3600), `CANARY_BASE_URL` (public hostname/port for HTTP traps), `ART_TESTS_FILE` (default `atomic_tests.yaml`), `RED_TEAM_TARGET_CONTAINER` (default `redteam-target`)

### Eng Review Decisions
1. ART harness runs external to the orchestrator (scheduled, not Claude-driven). Agent-driven red team is Phase 4. Keeps Phase 3 tight and deterministic.
2. Posture score = (ART tests with matching triaged cluster + deployed rule) / (total ART tests in the run). Simple, honest, matches the "immune system" intent and gives a single north-star number.
3. Canary tokens: DNS + HTTP only. Service honeypots (SSH/MySQL) are Phase 4 — they double attack surface and need separate isolation analysis.
4. Threat intel: URLhaus only (URL feed + payload MD5 feed). STIX/TAXII deferred. Matches the 2–3 week timebox.
5. `check_threat_intel` becomes the 7th orchestrator tool — added by direct patch to `TOOLS` + `_TOOL_DISPATCH` (per DEC-ORCH-003). No dynamic-registration refactor in this phase.
6. ART test list is declarative in `atomic_tests.yaml` — no auto-discovery of the full ART technique catalogue. Explicit beats clever.
7. ART events flow through the existing Wazuh tailer; `redteam-target` is just another monitored endpoint. Zero new tailer code.
8. Canary receiver is a new FastAPI route, not a new tailer. Hits persist directly via existing `_persist_and_enqueue`.
9. New tables (`posture_runs`, `canary_tokens`, `threat_intel`) follow DEC-SCHEMA-002: idempotent `ALTER TABLE` in `init_db`, no migration framework.
10. Posture scoring **depends on Phase 2.5 Sigma auto-deploy** for techniques YARA can't cover (process execution). If Phase 2.5 slips, Phase 3 P0 still ships but with biased score (YARA-only coverage) and REQ-P1-P3-004 becomes P2.
11. Dashboard uses existing HTMX pattern (`hx-trigger="every 10s"`); no SPA, no chart library beyond CSS/SVG.
12. Posture score persists per run in `posture_runs`; in-memory stats counters (per DEC-HEALTH-001) are additive — no lock added.

### Files to Create / Update
```
shaferhund/
  compose.yaml                          # (UPDATE) add redteam-runner + redteam-target containers
  requirements.txt                      # (UPDATE) add httpx (if not present), dnslib (optional)
  .env.example                          # (UPDATE) document Phase 3 env vars
  atomic_tests.yaml                     # (NEW) declarative ART technique list
  agent/
    red_team.py                         # (NEW) ART runner invocation + posture_runs CRUD + scoring
    canary.py                           # (NEW) spawn + receiver + token persistence
    threat_intel.py                     # (NEW) URLhaus fetcher + lookup + poller Task
    orchestrator.py                     # (UPDATE) add check_threat_intel tool def + dispatch entry + closure factory call
    models.py                           # (UPDATE) posture_runs, canary_tokens, threat_intel tables + CRUD helpers
    main.py                             # (UPDATE) /posture, /posture/run, /canary/spawn, /canary/hit/{token} routes; /health additions; URLhaus + ART schedule Tasks in lifespan
    config.py                           # (UPDATE) Phase 3 env fields
    templates/
      posture.html                      # (NEW) score + technique breakdown + sparkline (P1)
      canaries.html                     # (NEW, P1) active canary list + trigger counts
  tests/
    test_red_team_harness.py            # (NEW) mock ART runner → posture_runs row
    test_posture_score.py               # (NEW) pass/fail scoring matrix
    test_canary.py                      # (NEW) spawn → hit → alert row
    test_threat_intel.py                # (NEW) URLhaus fetcher + check_threat_intel tool behaviour
    test_orchestrator_threat_intel.py   # (NEW) tool-use loop includes check_threat_intel
    fixtures/
      urlhaus_sample.json               # (NEW) cached URLhaus payload for deterministic tests
      atomic_test_sample.yaml           # (NEW) sample ART test definition
      redteam_wazuh_alert.json          # (NEW) expected shape of a Wazuh alert from an ART run
```

### Success Criteria
- `podman compose up` brings up Wazuh + Suricata + Shaferhund + `redteam-runner` + `redteam-target`
- `POST /posture/run` triggers an ART batch; logs show technique execution within 10s
- Within 60s of ART run completion, `posture_runs` row populated and `/health` reports `posture.last_score`
- A DNS or HTTP canary spawn, triggered externally, produces a `source='canary'` alert that triages normally
- URLhaus fetcher populates `threat_intel` within the first scheduled interval; at least one orchestrator test shows `check_threat_intel` used during triage
- `/posture` (P1) renders the latest score and per-technique breakdown
- Phase 1 / Phase 2 / Phase 2.5 tests pass unchanged; all new Phase 3 tests pass

### Decision Log

| ID | Title | Status |
|----|-------|--------|
| DEC-REDTEAM-001 | External scheduled ART harness (not Claude-driven) | accepted |
| DEC-POSTURE-001 | Posture score = ART pass rate (deployed-rule coverage over total tests) | accepted |
| DEC-CANARY-001 | DNS + HTTP canary tokens only; service honeypots deferred to Phase 4 | accepted |
| DEC-THREATINTEL-001 | URLhaus only; STIX/TAXII federation deferred | accepted |
| DEC-ORCH-004 | `check_threat_intel` added via direct TOOLS patch (no dynamic registration refactor) | accepted |
| DEC-REDTEAM-002 | Declarative `atomic_tests.yaml`; no full ART auto-discovery | accepted |
| DEC-CANARY-002 | Canary events enter via existing `_persist_and_enqueue`; `source='canary'` | accepted |
| DEC-POSTURE-002 | Phase 3 P0 ships even if Phase 2.5 Sigma slips; YARA-biased score acceptable as interim | accepted |
| DEC-ORCH-005 | 7th orchestrator tool added via direct `TOOLS` list patch + `make_read_tool_handlers` closure factory + `_TOOL_DISPATCH` entry; validates the scaling pattern, dynamic-registration refactor remains a Phase 4 item (REQ-NOGO-P3-008). Annotated at `agent/orchestrator.py:84` and `agent/threat_intel.py:20` | accepted |
| DEC-CANARY-003 | Canary spawn/hit split: `agent/canary.py` owns DB helpers and pure functions; HTTP wiring (`POST /canary/spawn`, `GET /canary/hit/{token}`) stays in `agent/main.py` next to other route handlers — keeps the canary module testable without TestClient overhead. Annotated at `agent/canary.py:43` | accepted |
| DEC-REDTEAM-003 | `run_batch` accepts an injectable `executor` callable so unit tests can mock subprocess invocation without monkey-patching; real path uses `subprocess.run([... podman exec ...])`. Annotated in `agent/red_team.py` | accepted |
| DEC-REDTEAM-004 | `POST /posture/run` inserts the `posture_runs` row synchronously before spawning the asyncio background task, so the caller receives a valid `run_id` immediately and avoids a poll-before-row race; SQLite WAL mode lets concurrent readers see the committed row before the task completes. Annotated at `agent/main.py:711` | accepted |
| DEC-REDTEAM-005 | `redteam-target` container ships Wazuh agent installed but NOT enrolled at build time; enrollment is a runtime operator step (`agent-auth -m wazuh.manager` after first compose up), avoiding build-time secrets and matching Wazuh 4.x recommended workflow. Annotated in `compose.yaml` | accepted |

## Phase 4: Adaptive Immune System (3–4 weeks after Phase 3)

**Status:** completed
**Timebox:** 3–4 weeks
**Landed:** 2026-04-24/25 across PRs #48, #49, #50, #51 (all squash-merged from `feature/phase4-*` branches; final commit `0a43648`)
**Verified:** 2026-04-25 via Phase 4 zero-regression gate (issue #46): 242 passed / 1 skipped / 0 failed; `/health` integrates all 5 keys (`threat_intel`, `canary`, `posture` with 4 sub-keys `last_score`/`last_run_at`/`last_weighted_score`/`slo_breach_open`, `recommendations.pending_count`); DB migration Phase 3 → Phase 4 idempotent; orchestrator TOOLS=8; 5 compose services unchanged.

### Intent

Phase 3 gave the platform an immune system — a scheduled, deterministic loop of attack → measure → score. The agent now knows when its posture is weak, but it does not yet **decide** what to do about it. Phase 4 closes that decision loop. The agent gains the ability to recommend which Atomic Red Team techniques to run next based on posture gaps and cluster history, an operator-gated `redteam-runner` mode that executes those recommendations, and a posture SLO that pages when the score drops below threshold. The orchestrator's tool registry is refactored from the direct `TOOLS`-list patch pattern (DEC-ORCH-005) to a dynamic registration mechanism — necessary technical debt before crossing the 8-tool boundary, and the unblocking refactor for every future phase.

This is the conceptual unlock the Original Intent (line 5) names directly: *"a self-evolving offensive-defensive loop that attacks its own infrastructure, finds gaps, writes rules, and retests... an immune system, not a tool"*. Phase 1 built the triage. Phase 2 built the agent loop. Phase 2.5 closed the rule-deploy hands. Phase 3 built the measuring half (eyes that look inward). **Phase 4 builds the deciding half** — Claude becomes the conductor of the offensive-defensive feedback loop, not just the analyst at its end.

The phase is deliberately scoped to one new capability domain (agent-driven red team) plus one cross-cutting refactor (dynamic tool registration) plus one SRE-grade addition (posture SLO + paging). Cloud log ingestion, rule fleet distribution, containerised honeypots, threat-intel federation, and adversarial rule scoring are explicitly deferred to Phase 5+ — each is a real week of work and will not be rushed into a fused 6-month phase that never closes.

### Goals
- Orchestrator gains `recommend_attack` tool — Claude proposes ART techniques based on posture gaps + cluster history (REQ-P0-P4-001)
- New `redteam-runner` execution mode reads recommendations and runs them with operator gating for destructive techniques (REQ-P0-P4-002)
- Posture score becomes adaptive — technique weights influenced by Claude's relevance judgment, not flat-uniform (REQ-P0-P4-003)
- Orchestrator tool registration refactored from direct `TOOLS`-list patch to dynamic `register_tool()` API (REQ-P0-P4-004)
- Posture SLO with paging — when score drops below `POSTURE_SLO_THRESHOLD` for N consecutive runs, fire a webhook (REQ-P0-P4-005)
- All Phase 1, Phase 2, Phase 2.5, Phase 3 tests pass unchanged (REQ-P0-P4-006)

### Non-Goals
- REQ-NOGO-P4-001: Cloud log source ingestion (AWS CloudTrail / GCP Audit / Azure Monitor) — Phase 5; needs real-footprint validation per the recurring "fixture-only testing is insufficient" constraint
- REQ-NOGO-P4-002: Rule fleet distribution (signed pull, multi-agent rollout, version pinning) — Phase 5; orthogonal to the immune-system loop
- REQ-NOGO-P4-003: Containerised service honeypots (SSH, MySQL, Redis) — Phase 6; doubles attack surface and needs separate isolation analysis
- REQ-NOGO-P4-004: STIX/TAXII threat-intel federation (multiple feeds, indicator deconfliction) — Phase 6; URLhaus is sufficient for the timebox
- REQ-NOGO-P4-005: Adversarial rule-effectiveness scoring (evasion variants, ART payload mutation) — Phase 6; depends on a stable `recommend_attack` baseline first
- REQ-NOGO-P4-006: Multi-tenant posture / per-team scoring / RBAC — Phase 7; still solo-dev scale
- REQ-NOGO-P4-007: Multi-user auth / signed audit logs (REQ-NOGO-P2-006 carry-forward) — Phase 7
- REQ-NOGO-P4-008: Replacing the existing `redteam-target` Ubuntu container with a Windows or macOS target — Phase 6; broadens technique coverage but requires separate licensing and image strategy

### Requirements

**Must-Have (P0)**

- REQ-P0-P4-001: 8th orchestrator tool `recommend_attack(posture_gap_summary)` returns a structured `{techniques: [{technique_id, rationale, priority}], confidence}`. Read-only — never executes; only writes to a new `attack_recommendations` table for operator review.
  - Acceptance: a unit test seeds a posture run with two failing technique IDs, drives a triage loop, and verifies (a) `recommend_attack` appears in the tool transcript, (b) the returned techniques include at least one of the failing IDs in its rationale, (c) the recommendation persists in `attack_recommendations` with `status='pending'`.
- REQ-P0-P4-002: `POST /redteam/recommendations/{id}/approve` accepts an operator confirmation; `redteam-runner` then executes the recommended techniques via the existing `red_team.run_batch` path. Destructive techniques (a hardcoded allowlist set in `agent/red_team.py:DESTRUCTIVE_TECHNIQUES`) require explicit `force=true` in the approval body. Default behaviour for any unknown technique is **non-destructive only** — fail-closed.
  - Acceptance: approving a non-destructive recommendation triggers a posture run; approving a destructive one without `force=true` returns 409; with `force=true` it runs.
- REQ-P0-P4-003: `posture_runs.score` calculation gains a `weighted_score` column derived from per-technique weights stored in `attack_recommendations.priority`. Existing flat-pass-rate score remains as `score` for backwards compat. `/health` exposes both `posture.last_score` (flat) and `posture.last_weighted_score`.
  - Acceptance: a synthetic run with three techniques weighted [0.5, 0.3, 0.2] where only the highest-weighted one passes yields `weighted_score=0.5` while flat `score=1/3≈0.33`.
- REQ-P0-P4-004: `agent/orchestrator.py` exposes a public `register_tool(spec, handler, requires_conn)` API. The 7 existing tools register through this API at module load. `TOOLS` and `_TOOL_DISPATCH` become module-private build artifacts populated by `register_tool` calls — no external code mutates them. The 8th tool (`recommend_attack`) lands via `register_tool` in the same way the existing 7 are migrated. The closure-factory pattern (`make_read_tool_handlers`, `make_write_tool_handlers`) is preserved — `register_tool` declares the dependency set, the factories build the closures.
  - Acceptance: a unit test imports `register_tool`, registers a synthetic tool with a stub handler, drives `run_triage_loop` with a mocked Anthropic client that calls the synthetic tool, and verifies the handler executes. The 7 pre-existing tools continue to function with no behavioural change. `grep -r "TOOLS\.append\|_TOOL_DISPATCH\[" agent/` returns zero hits outside `orchestrator.py` itself.
- REQ-P0-P4-005: `POSTURE_SLO_THRESHOLD` (float, default 0.7) and `POSTURE_SLO_CONSECUTIVE_RUNS` (int, default 3). Background asyncio Task evaluates after each posture run; if the last N runs all scored below threshold, POST a JSON payload to `POSTURE_SLO_WEBHOOK_URL` (env var, optional). Idempotency: each breach fires once until score recovers above threshold for one run.
  - Acceptance: with threshold=0.7, consecutive=3, three sub-threshold runs trigger one webhook POST (verified via mock httpx). A fourth sub-threshold run does NOT re-fire. A run at 0.8 resets the counter; the next sub-threshold streak does fire again.
- REQ-P0-P4-006: All Phase 1 / Phase 2 / Phase 2.5 / Phase 3 tests pass unchanged. ≥1 new unit test per P0 capability above.

**Nice-to-Have (P1)**

- REQ-P1-P4-001: Dashboard `/redteam/recommendations` page — list pending recommendations with technique_id, rationale, priority, approve/dismiss actions (HTMX, no SPA).
- REQ-P1-P4-002: `recommend_attack` tool consults `threat_intel` for IOCs from recent failing clusters and incorporates them into the rationale (e.g. "URLhaus shows two recent C2 domains using T1059.003 — recommend testing PowerShell coverage").
- REQ-P1-P4-003: SLO breach payload includes a 30-day score sparkline (small ASCII or base64 SVG) so the paging channel gets actionable context without a dashboard click-through.
- REQ-P1-P4-004: `register_tool` accepts an optional `requires_capabilities=['threat_intel']` declaration; if a capability is unavailable at startup (e.g. URLhaus poller failed), the tool is silently dropped from `TOOLS`. Lays groundwork for future tools that depend on optional infrastructure.

**Future Consideration (P2)**

- REQ-P2-P4-001: Cloud log source ingestion (first provider, AWS CloudTrail) — Phase 5
- REQ-P2-P4-002: Rule fleet distribution (signed pull from a single shaferhund agent to N remote Wazuh agents) — Phase 5
- REQ-P2-P4-003: Containerised service honeypots (SSH/MySQL/Redis) — Phase 6
- REQ-P2-P4-004: STIX/TAXII threat-intel federation (multi-feed, indicator deconfliction) — Phase 6
- REQ-P2-P4-005: Adversarial rule-effectiveness scoring (evasion variants, payload mutation) — Phase 6
- REQ-P2-P4-006: Multi-tenant posture / RBAC / signed audit logs — Phase 7

### Architecture

```
[Phase 3 surface, unchanged: Wazuh + Suricata + canary + threat_intel + scheduled ART]
                              |
                              v
                   [posture_runs table]
                              |
                              v
                     posture-gap query
              (recent low-score runs grouped by technique)
                              |
                              v
              [Triage Queue → Orchestrator Tool Loop]
                tools (now 8, registered via register_tool):
                  - get_cluster_context        [read]
                  - search_related_alerts      [read]
                  - check_threat_intel         [read]
                  - write_yara_rule            [write]
                  - write_sigma_rule           [write]
                  - recommend_deploy           [write]
                  - finalize_triage            [write, terminal]
                  - recommend_attack           [write, NEW] ──┐
                                                              |
                              v                               v
              [Policy Gate]                        [attack_recommendations table]
                              |                       (status: pending|approved|dismissed)
                              v                               |
              [/rules/ + deploy_events]                       |
                              |                               |
                              v                               v
                   [posture_runs join]                [Operator Review UI]
                  + weighted_score column            (HTMX, /redteam/recommendations)
                              |                               |
                              v                               v
                   [Posture SLO Evaluator]             [POST /redteam/recommendations/{id}/approve]
                  (consecutive sub-threshold runs)            |
                              |                               v
                              v                       [redteam-runner: run_batch]
                   [POSTURE_SLO_WEBHOOK_URL]          (existing Phase 3 path, force= for destructive)
                  (one POST per breach window)                |
                                                              v
                                                   [Wazuh tailer → posture_runs]
                                                   (loop closes — gap addressed or persists)
```

### Stack Delta vs Phase 3
- **No new containers.** All Phase 4 work lands in the existing `shaferhund-agent` and reuses `redteam-target` from Phase 3.
- **No new Python libraries.** Webhook delivery uses existing `httpx` (already in requirements for URLhaus). Dynamic tool registration is pure Python.
- **New env vars:** `POSTURE_SLO_THRESHOLD` (default 0.7), `POSTURE_SLO_CONSECUTIVE_RUNS` (default 3), `POSTURE_SLO_WEBHOOK_URL` (optional), `REDTEAM_DESTRUCTIVE_ALLOW` (default empty — explicit allowlist for `force=true` techniques)
- **New table:** `attack_recommendations (id, generated_at, technique_id, rationale, priority REAL, status, approved_at, executed_at, posture_run_id)` — idempotent ALTER per DEC-SCHEMA-002
- **Extended table:** `posture_runs` gains `weighted_score REAL NULL` column (idempotent ADD COLUMN)

### Eng Review Decisions

1. **`recommend_attack` is read-only-from-Claude's-perspective.** It writes to `attack_recommendations` but executes nothing — execution requires an explicit operator HTTP POST. Self-attacking infrastructure without human approval is a hard line we don't cross in Phase 4 even though the loop conceptually invites it; pushing the gate to operator approval keeps the system auditable and makes the Claude call cheap to retry.
2. **Destructive technique allowlist is a frozenset in code, not a config file.** Operator `force=true` is the only path to running a destructive technique; the set is reviewed at code-review time, not runtime. Eliminates the "operator can YOLO any technique through env var" risk class.
3. **Dynamic tool registration via `register_tool(spec, handler, requires_conn)`** — extends the closure-factory pattern at `agent/orchestrator.py:674` rather than replacing it. The factories live, but `TOOLS` and `_TOOL_DISPATCH` become *outputs* of registration calls, not hand-edited lists. This is the smallest refactor that satisfies REQ-NOGO-P3-008 and unblocks Phase 5+ tools.
4. **`weighted_score` is additive, not replacement.** Flat `score` stays in `posture_runs` for backwards compat with Phase 3 dashboards and the existing `/health` field. Operators see both. This avoids a breaking schema change and lets us A/B the two scoring methods in real conditions before any future phase makes weighted the canonical metric.
5. **Posture SLO uses a webhook, not a paging integration.** PagerDuty / OpsGenie / Slack each have their own auth model; a generic webhook URL keeps the integration footprint zero and lets operators bridge to whatever they already use. The payload schema is documented; integration adapters are a Phase 5+ concern.
6. **SLO breach idempotency tracked in a new `slo_breaches` row, not in-memory.** A restart mid-breach must not re-fire. Recovery (one run above threshold) closes the breach row; the next streak opens a fresh row. Same idempotency pattern as `deploy_events`.
7. **`recommend_attack` runs inside the existing 5-tool-call / 10s-wall caps.** No new caps, no parallel orchestrator. If the loop runs out of budget after writing rules and lands the recommendation in turn 6+, it gets dropped — Claude must prioritise. This forces the right behaviour: rules first, recommendations second.
8. **Posture-gap context is pre-computed and injected into the system prompt at loop start**, not fetched via a tool. Tool calls are expensive (Claude turn + DB round-trip); the gap summary is small, deterministic, and known up-front. This is the same reasoning as DEC-ORCH-004 (instructions in system prompt) applied to context.
9. **No retry on webhook failure.** A transient failure means the operator misses one breach signal — but the breach record persists, so the next posture run will include it in the next webhook payload. Retries with backoff create a separate failure mode (delayed pages bunched together) that's worse than missing one.
10. **Migration of existing 7 tools to `register_tool` is mechanical, not redesigned.** Every existing tool's spec dict and dispatch entry is converted 1:1 to a `register_tool` call. No tool gets a new schema, new caps, or new behaviour. The refactor is invisible from outside `orchestrator.py`.
11. **`attack_recommendations.priority` defaults to 1/N where N=count(recommendations in same triage run).** Claude can override by returning explicit priority floats summing to ≤1.0. If they don't sum, we normalise. Removes the "Claude returns priority=999 for everything" footgun.
12. **`weighted_score` calculation is in SQL, not Python**, mirroring the Phase 3 `compute_posture_score_for_run` pattern at `agent/red_team.py`. Keeps scoring auditable via `EXPLAIN QUERY PLAN` and avoids round-tripping rows through Python for what is fundamentally a `SUM(passed * weight) / SUM(weight)`.

### Files to Create / Update

```
shaferhund/
  .env.example                              # (UPDATE) document Phase 4 env vars
  agent/
    orchestrator.py                         # (UPDATE) register_tool() API; migrate 7 tools to it; add recommend_attack as 8th tool via the new API; preserve closure factories
    red_team.py                             # (UPDATE) DESTRUCTIVE_TECHNIQUES frozenset; weighted_score helper; posture-gap query for system-prompt injection
    posture_slo.py                          # (NEW) SLO evaluator + breach idempotency + webhook poster
    recommendations.py                      # (NEW) attack_recommendations CRUD + approval flow + execution dispatch
    models.py                               # (UPDATE) attack_recommendations + slo_breaches tables; weighted_score column on posture_runs; helpers
    main.py                                 # (UPDATE) /redteam/recommendations, /redteam/recommendations/{id}/approve routes; SLO evaluator background Task in lifespan; /health adds posture.last_weighted_score + slo.last_breach_at
    config.py                               # (UPDATE) POSTURE_SLO_THRESHOLD, POSTURE_SLO_CONSECUTIVE_RUNS, POSTURE_SLO_WEBHOOK_URL, REDTEAM_DESTRUCTIVE_ALLOW
    templates/
      recommendations.html                  # (NEW, P1) pending recommendations list + approve action
  tests/
    test_register_tool.py                   # (NEW) register_tool API + 7-tool migration regression
    test_recommend_attack.py                # (NEW) tool transcript + persistence
    test_recommendation_approval.py         # (NEW) approve flow + destructive gate (force=true)
    test_weighted_score.py                  # (NEW) priority weighting matrix
    test_posture_slo.py                     # (NEW) consecutive-run breach detection + idempotency
    test_slo_webhook.py                     # (NEW) mock httpx webhook delivery + payload shape
    fixtures/
      recommend_attack_response.json        # (NEW) golden Claude response for tool replay
      slo_breach_payload.json               # (NEW) expected webhook JSON shape
```

### Success Criteria
- `podman compose up` brings up the existing 5-service stack (Phase 4 adds no containers); container logs show `register_tool` invocations for 8 tools at startup
- A scripted scenario (sub-threshold posture run × 3) produces exactly one webhook POST with the expected JSON shape; a recovery run resets the breach state
- `POST /redteam/recommendations/{id}/approve` with a non-destructive technique triggers a real ART batch run; the same call with a destructive technique returns 409 unless `force=true`
- Orchestrator transcript on a synthetic cluster shows `recommend_attack` called and persisted to `attack_recommendations` with `status='pending'`
- `/health` reports both `posture.last_score` and `posture.last_weighted_score`; the two diverge predictably on a weighted-test fixture
- `grep -r "TOOLS\.append\|_TOOL_DISPATCH\[" agent/` returns zero hits outside `agent/orchestrator.py`
- Phase 1 / Phase 2 / Phase 2.5 / Phase 3 tests pass unchanged; all new Phase 4 tests pass

### GitHub Issues

- **Wave A (parallel — no inter-dependencies):**
  - REQ-P0-P4-004 — `register_tool` API + 7-tool migration (`feature/phase4-register-tool`)
  - REQ-P0-P4-003 — `weighted_score` column + SQL helper + `/health` field (`feature/phase4-weighted-score`)
  - REQ-P0-P4-005 — Posture SLO evaluator + webhook + idempotency (`feature/phase4-posture-slo`)
- **Wave B (depends on Wave A `register_tool`):**
  - REQ-P0-P4-001 — `recommend_attack` tool + `attack_recommendations` table (`feature/phase4-recommend-attack`)
  - REQ-P0-P4-002 — recommendation approval route + destructive allowlist + execution dispatch (`feature/phase4-approval-flow`)
- **Wave C (gate, blocked by Wave A + B):**
  - REQ-P0-P4-006 — zero-regression gate across all prior phases; final integration smoke (`feature/phase4-regression-gate`)
- **Wave D (P1, parallelizable after Wave B; only if timebox allows):**
  - REQ-P1-P4-001 — `/redteam/recommendations` HTMX dashboard (`feature/phase4-recs-dashboard`)
  - REQ-P1-P4-002 — `recommend_attack` consults `threat_intel` for IOC context (`feature/phase4-recs-threat-intel`)
  - REQ-P1-P4-003 — Sparkline in SLO breach payload (`feature/phase4-slo-sparkline`)
  - REQ-P1-P4-004 — `requires_capabilities` for register_tool (`feature/phase4-capability-gating`)

### Decision Log

| ID | Title | Status |
|----|-------|--------|
| DEC-ORCH-006 | `register_tool(spec, handler, requires_conn)` API replaces direct `TOOLS`/`_TOOL_DISPATCH` mutation; preserves closure-factory pattern | accepted |
| DEC-RECOMMEND-001 | `recommend_attack` writes to `attack_recommendations` only; execution requires explicit operator approval HTTP POST | accepted |
| DEC-RECOMMEND-002 | Destructive technique allowlist as a code-resident frozenset; `force=true` is the only runtime path to bypass | accepted |
| DEC-RECOMMEND-003 | Priority defaults to 1/N normalisation when Claude returns malformed weights | accepted |
| DEC-POSTURE-003 | `weighted_score` is additive to flat `score`; both persisted; SQL-based calculation per DEC-POSTURE-001 pattern | accepted |
| DEC-SLO-001 | Generic webhook (not paging-vendor-specific); operators bridge externally | accepted |
| DEC-SLO-002 | Idempotency via `slo_breaches` table; one POST per breach window; recovery closes the row | accepted |
| DEC-SLO-003 | No retry on webhook failure; the next breach evaluation re-includes the missed run if still sub-threshold | accepted |
| DEC-RECOMMEND-004 | Posture-gap context injected into system prompt at loop start, not fetched via a tool — same reasoning as DEC-ORCH-004 | accepted |
| DEC-ORCH-007 | Migration of existing 7 tools to `register_tool` is mechanical 1:1; no behavioural changes; refactor invisible from outside `orchestrator.py` | accepted |
| DEC-RECOMMEND-005 | Cloud log + rule fleet + honeypots + STIX/TAXII + adversarial scoring all explicitly deferred to Phase 5+; Phase 4 stays scoped to one capability + one refactor + one SRE feature | accepted |
| DEC-SLO-004 | SLO evaluator dispatches raw connection vs. factory via `isinstance(conn, sqlite3.Connection)`, not `callable(conn)` — `sqlite3.Connection` exposes `__call__` from the C extension, so `callable()` returns True for a raw connection and the loop calls `conn()` which raises `TypeError`, silently swallowed by the broad `except`. In production (`agent/main.py:240` passes `_db` directly), the loop never evaluated. Surfaced via the V7 live-integration check during #44 verification — unit tests passed because they used a lambda factory. Fixed at `agent/slo.py:289` | accepted |

## Phase 5: Cloud Eyes (3 weeks after Phase 4)

**Status:** completed
**Timebox:** 3 weeks
**Landed:** 2026-04-25 across PRs #61, #62, #63, #64, #65 (all squash-merged from `feature/phase5-*` branches; final commit `9fe8158`)
**Verified:** 2026-04-25 via Phase 5 zero-regression gate (issue #59): 308 passed / 1 skipped / 3 deselected / 0 failed; `/health` integrates all 6 keys (`status`, `poller_healthy`, `threat_intel`, `canary`, `posture` with 4 sub-keys, `recommendations.pending_count`, `cloudtrail` with 4 keys); DB migration Phase 4 → Phase 5 idempotent (adds `cloudtrail_progress` and `cloud_audit_findings` tables); orchestrator TOOLS=9; `compose.yaml` unchanged at 5 services; `compose.localstack.yaml` separate opt-in for integration tests; IAM policy read-only verified (zero write actions).

### Intent

Phase 1–4 built a self-evaluating immune system over **on-prem** signals — Wazuh HIDS on hosts, Suricata NIDS on the wire, canary tokens on the perimeter, Atomic Red Team against `redteam-target`. The platform measures, decides, and recommends. But the modern attacker rarely starts on a host. They start in IAM — a stolen access key, an over-privileged role, an OAuth grant abused on a Sunday. Those attacks live in **cloud audit logs**, not on `eve.json` or `alerts.json`. The Original Intent (line 5) calls out "cloud security" as one of the 25 capability domains; every prior phase has explicitly deferred it (`REQ-NOGO-P2-001` → `REQ-NOGO-P25-001` → `REQ-NOGO-P4-001`). Phase 5 ends that deferral.

The phase adds **AWS CloudTrail** as a third source pipeline, slotting in alongside Wazuh and Suricata using the same shape: a poller that writes to the shared `alerts` table with `source='cloudtrail'`, a parser that emits the common alert dict (per `agent/sources/suricata.py:54`), and zero changes to the clusterer, orchestrator, or policy gate. The clean architecture proven over four phases pays its first big dividend here — a third source costs ~600 LOC of new code and zero refactor of the existing 8-tool / SLO / posture surface. CloudTrail unlocks five of the 25 `hund` domains in one hit: cloud security, IAM (anomalous role assumption), DLP (S3 download spikes), compliance evidence (audit log retention), and threat intelligence (cross-correlation of cloud IOCs against URLhaus). It also opens the door to multi-cloud (GCP Audit, Azure Monitor) as a Phase 6+ extension that follows the same pattern.

This is deliberately **one provider only**, and deliberately **without** rule fleet distribution or auth/RBAC tightening. CloudTrail is enough scope for three weeks if we do it right — real-footprint validation, S3 polling semantics, eventual-consistency handling, IAM-least-privilege for the agent's read role, and a cloud-aware orchestrator tool that lets Claude pivot from a Wazuh host alert to "what did this user's IAM identity do in the last hour?". Multi-cloud, fleet distribution, multi-user auth, and honeypots stay deferred — each is its own real week and forcing them into Phase 5 would produce the kind of fused, never-closing phase Phase 4 explicitly avoided.

### Goals
- AWS CloudTrail S3 polling adds a third source pipeline alongside Wazuh + Suricata, using the existing source-pipeline pattern (REQ-P0-P5-001)
- CloudTrail events normalise into the shared `alerts` table with `source='cloudtrail'`; clusterer + orchestrator + policy gate require zero changes (REQ-P0-P5-002)
- A new `lookup_cloud_identity` orchestrator tool lets Claude correlate on-prem alerts with cloud IAM activity by user/role ARN (REQ-P0-P5-003)
- Shaferhund operates in real AWS with IAM-least-privilege — no fixture-only theatre; integration tests run against LocalStack (REQ-P0-P5-004)
- A `cloud_audit_findings` table captures detections specific to cloud audit signals (anomalous role assumption, root-account use, MFA disable, etc.) for operator review (REQ-P0-P5-005)
- `/health` exposes CloudTrail poller status, lag, and event count; `/metrics` exposes per-event-type breakdown (REQ-P0-P5-006)
- All Phase 1 / Phase 2 / Phase 2.5 / Phase 3 / Phase 4 tests pass unchanged (REQ-P0-P5-007)

### Non-Goals
- REQ-NOGO-P5-001: GCP Audit Logs / Azure Monitor / multi-cloud — Phase 6; same pipeline pattern, but each provider is its own real integration week
- REQ-NOGO-P5-002: Rule fleet distribution to remote Wazuh agents — Phase 6; pairs better with auth/RBAC tightening
- REQ-NOGO-P5-003: Multi-user auth / RBAC / signed audit logs — Phase 6 (REQ-NOGO-P2-006 / REQ-NOGO-P4-007 carry-forward); CloudTrail polling uses the existing `SHAFERHUND_TOKEN` single-user model
- REQ-NOGO-P5-004: STIX/TAXII threat-intel federation (multi-feed, indicator deconfliction) — Phase 7
- REQ-NOGO-P5-005: Containerised service honeypots (SSH/MySQL/Redis) — Phase 7
- REQ-NOGO-P5-006: Multi-tenant posture (per-team scores, per-AWS-account isolation) — Phase 7
- REQ-NOGO-P5-007: CloudTrail Lake / Athena query backend — Phase 5 polls raw S3 objects; advanced query is a follow-up
- REQ-NOGO-P5-008: Real-time CloudTrail via EventBridge / Kinesis — Phase 5 uses S3-poll only (5-15 min lag) for solo-dev cost profile
- REQ-NOGO-P5-009: Cloud-native rule deploy (deploying a CloudTrail-derived YARA/Sigma rule back to AWS GuardDuty / Security Hub) — Phase 7; Phase 5 keeps the rule output local-file-drop per DEC-YARA-001
- REQ-NOGO-P5-010: Adversarial rule-effectiveness scoring against cloud techniques (T1078.004 cloud accounts, T1098.001 etc.) — Phase 7; depends on stable Phase 4 `recommend_attack` baseline first

### Requirements

**Must-Have (P0)**

- REQ-P0-P5-001: `agent/sources/cloudtrail.py` implements an S3 poller that lists new objects under a configured prefix, downloads, gunzips, parses CloudTrail's nested `Records[]` JSON, and yields `(s3_key, parsed_event)` tuples. Mirrors the `tail_eve_json` pattern at `agent/sources/suricata.py:98` — incremental progress tracked via `cloudtrail_progress` table (last-seen `s3_key` per prefix), not byte offsets.
  - Acceptance: a unit test seeds 3 gzipped CloudTrail JSON objects in a `moto`/LocalStack S3 bucket; calling the poller once yields all 3, calling it again yields 0; a 4th object added between calls is yielded on the second call.
- REQ-P0-P5-002: `parse_cloudtrail_event(event)` emits the shared alert dict shape (`source='cloudtrail'`, `src_ip`, `dest_ip=None`, `protocol='https'`, `rule_id`, `rule_description`, `normalized_severity`, `timestamp`, `raw_json`) for every CloudTrail event. `rule_id` is synthesised as `cloudtrail:{eventSource}:{eventName}` (e.g. `cloudtrail:iam.amazonaws.com:AssumeRole`). Severity is computed by a small heuristic table (root-account use → Critical, MFA disable → High, console login from new IP → Medium, default → Low).
  - Acceptance: a unit test feeds a fixture `AssumeRole` event and a fixture `ConsoleLogin` event; both produce well-formed alert dicts indistinguishable at the clusterer boundary from Wazuh/Suricata alerts of the same shape; the resulting clusters use key `('cloudtrail', src_ip, rule_id)`.
- REQ-P0-P5-003: 9th orchestrator tool `lookup_cloud_identity(user_or_role_arn)` registered via `register_tool()` (per DEC-ORCH-006). Returns the last 25 CloudTrail events for the given principal across the last 24 hours, summarising event names + counts. Read-only; queries the shared `alerts` table filtered by `source='cloudtrail'` and the principal pulled out of the raw event during parse.
  - Acceptance: a unit test seeds 30 CloudTrail alerts for `arn:aws:iam::123:role/admin`, drives a triage loop where Claude calls `lookup_cloud_identity`, and verifies the response contains exactly 25 events grouped by event name with correct counts. The tool transcript shows `lookup_cloud_identity` appears alongside the existing 8 tools.
- REQ-P0-P5-004: Integration tests against **LocalStack** (free, runnable in CI) cover end-to-end: poller writes to S3 → poller picks up → parser normalises → clusterer clusters → orchestrator triages → `cloud_audit_findings` row appears for at least one finding type. The IAM policy required for the poller is documented in `docs/cloudtrail-iam-policy.json` and minimised to `s3:ListBucket` + `s3:GetObject` on the configured prefix only — no `s3:*`, no wildcard buckets.
  - Acceptance: `tests/integration/test_cloudtrail_localstack.py` boots a LocalStack container, seeds CloudTrail-shaped events, and runs the full pipeline to a `cloud_audit_findings` row; CI green; the IAM policy file passes `aws iam validate-policy` (or `cfn-lint` equivalent) shape check.
- REQ-P0-P5-005: New `cloud_audit_findings` table (`id, alert_id, finding_type, principal, source_ip, severity, raw_summary, created_at, status`) — populated by a small detector module `agent/cloud_findings.py` that runs **after** the clusterer, on `source='cloudtrail'` alerts only, and emits findings for the deterministic patterns (root-account use, MFA disable, anomalous AssumeRole — defined as a role assumption from an IP not seen for that role in the last 7 days). New `/cloud/findings` route lists pending findings; `/health` adds `cloud.pending_findings`.
  - Acceptance: a unit test seeds an MFA-disable event → a row appears in `cloud_audit_findings` with `finding_type='mfa_disable'`, `severity='High'`, `status='pending'`. Same fixture replayed produces no duplicates (idempotent on `alert_id`).
- REQ-P0-P5-006: `/health` JSON adds `cloudtrail.poller_running` (bool), `cloudtrail.last_poll_at`, `cloudtrail.lag_seconds` (now − newest event timestamp), `cloudtrail.events_24h`, `cloud.pending_findings`. `/metrics` (auth-gated per DEC-HEALTH-002) adds per-event-type counts and a poll-error counter.
  - Acceptance: hit `/health` after a poller run; lag matches DB calculation; before any polls, fields are null/false and the route still returns 200.
- REQ-P0-P5-007: All Phase 1–4 tests pass unchanged. ≥1 new unit test per P0 capability above. The Phase 4 8-tool transcript test continues to pass; the Phase 5 transcript test asserts 9 tools.

**Nice-to-Have (P1)**

- REQ-P1-P5-001: `/cloud/findings` HTML dashboard — pending findings list with principal, finding_type, severity, raw_summary, and an "ack" action (HTMX, no SPA). Mirrors `/redteam/recommendations` from Phase 4.
- REQ-P1-P5-002: `lookup_cloud_identity` consults `threat_intel` to flag any cloud principal whose recent source IPs appear in URLhaus. Surfaces in the tool response so Claude can incorporate.
- REQ-P1-P5-003: `recommend_attack` (Phase 4 tool) gains awareness of cloud techniques — when posture gaps include T1078.004 / T1098.x, it can suggest cloud-relevant ART tests instead of host-only ones (no schema change; just a system-prompt augmentation referencing `cloud_audit_findings`).
- REQ-P1-P5-004: `agent/sources/cloudtrail.py` supports a `from_timestamp` cursor in addition to `last_s3_key`, so a fresh deploy can backfill from a chosen point rather than from the bucket's start.
- REQ-P1-P5-005: Source filter chip on `/` extended with `cloudtrail`.

**Future Consideration (P2)**

- REQ-P2-P5-001: GCP Audit Logs as a 4th source — Phase 6
- REQ-P2-P5-002: Azure Monitor / Activity Logs — Phase 6
- REQ-P2-P5-003: Real-time ingestion via EventBridge → SQS → poller — Phase 7 (S3-poll is sufficient for solo-dev scale)
- REQ-P2-P5-004: CloudTrail Lake / Athena query backend for `lookup_cloud_identity` at scale — Phase 7
- REQ-P2-P5-005: Cloud-native rule deploy (push rules to AWS GuardDuty / Security Hub) — Phase 7
- REQ-P2-P5-006: Multi-account / Organization Trail support (assume-role chain) — Phase 6

### Architecture

```
[Phase 4 surface, unchanged: Wazuh + Suricata + canary + threat_intel + ART + recommend_attack + SLO]
                                          |
                                          |  (NEW source pipeline, slot-in)
                                          v
                          [AWS S3 bucket: <trail-prefix>/AWSLogs/...]
                                          |
                                          v
                          [CloudTrail Poller]    every CLOUDTRAIL_POLL_SECONDS (default 60s)
                          (list_objects_v2 with StartAfter=last_s3_key
                           gunzip + parse Records[]
                           cursor in cloudtrail_progress table)
                                          |
                                          v
                          [parse_cloudtrail_event]      (agent/sources/cloudtrail.py)
                          (event → shared alert dict, source='cloudtrail',
                           rule_id = "cloudtrail:{eventSource}:{eventName}",
                           severity heuristic table)
                                          |
                                          v
                          [Alert Normaliser → existing clusterer]      (zero changes)
                          key = ('cloudtrail', src_ip, rule_id)
                                          |
                          +---------------+---------------+
                          |                               |
                          v                               v
                 [Triage Queue]                 [Cloud Findings Detector]
                 (existing Phase 1)             (agent/cloud_findings.py)
                          |                     deterministic patterns:
                          v                       - root_account_use
                 [Orchestrator: 9 tools]          - mfa_disable
                  (8 prior + lookup_cloud_         - anomalous_assume_role
                  identity, registered via          - console_login_new_ip
                  register_tool per DEC-ORCH-006) |
                          |                       v
                          v                  [cloud_audit_findings table]
                 [Policy Gate → /rules/]         (status: pending|ack|investigating)
                          |                       |
                          v                       v
                 [posture_runs join]      [GET /cloud/findings — operator review]
                  (existing Phase 4
                   weighted_score)               |
                          |                      v
                          v               [POST /cloud/findings/{id}/ack]
                 [Posture SLO + webhook]    (operator gating; no auto-action in P5)
                          |
                          v
                 [/health adds cloud.* keys; /metrics adds per-event-type breakdown]
```

### Stack Delta vs Phase 4

- **No new containers in production.** CloudTrail is an external AWS surface, not a sidecar. The `shaferhund-agent` container gains an AWS SDK client and a new asyncio task in `lifespan`.
- **New container in test only:** `localstack/localstack:3` for integration tests under `tests/integration/` (free; ~200MB image; runs only in CI/local dev, never in `compose.yaml`).
- **New Python libraries:** `boto3` (AWS SDK), `aiobotocore` (async S3 client to fit the existing asyncio model), `moto` (test-only fake S3 for unit tests; LocalStack for integration). No new system packages.
- **New env vars:** `CLOUDTRAIL_ENABLED` (default `false` — fail-closed; the source is opt-in), `CLOUDTRAIL_S3_BUCKET`, `CLOUDTRAIL_S3_PREFIX` (default `AWSLogs/`), `CLOUDTRAIL_POLL_SECONDS` (default 60), `CLOUDTRAIL_AWS_REGION` (default `us-east-1`), `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` / `AWS_SESSION_TOKEN` (standard SDK env; document the IAM policy in `docs/cloudtrail-iam-policy.json`).
- **New tables:** `cloudtrail_progress (id, prefix, last_s3_key, updated_at)` and `cloud_audit_findings (id, alert_id, finding_type, principal, source_ip, severity, raw_summary, created_at, status)`. Both via idempotent `ALTER TABLE` per DEC-SCHEMA-002.

### Eng Review Decisions

1. **S3 polling, not EventBridge / Kinesis Firehose.** S3 polling is dirt-cheap (LIST + GET on new objects only), survives operator restarts trivially via the `cloudtrail_progress` cursor, and matches the file-tail pattern that runs Wazuh and Suricata. Real-time ingestion adds operational surface (Kinesis stream, EventBridge rule, Lambda) that is unjustified for a solo-dev tool with a 60-second poll cadence — the 5-15 min CloudTrail-to-S3 lag dominates anyway. EventBridge stays deferred to Phase 7 if ever.
2. **One cloud provider only.** AWS CloudTrail is the most-deployed cloud audit source by an enormous margin and the only one with a stable, public, well-documented log shape since 2014. Forcing GCP Audit + Azure Monitor into the same phase doubles the schema-shape and IAM-policy work without doubling the value. Phase 6 picks up the next provider using the exact same pattern — the source-pipeline abstraction is now battle-tested.
3. **`source='cloudtrail'` reuses the shared `alerts` table.** No `cloud_alerts` table, no new clusterer key extension. `rule_id = "cloudtrail:{eventSource}:{eventName}"` is unique enough to keep clusters disjoint from Wazuh rule_id integers and Suricata signature_ids; the `source` column is the actual disambiguator. This continues the Phase 2 pattern (REQ-P0-P2-003 / DEC-CLUSTER-002) and is why a third source costs <600 LOC.
4. **Severity heuristic table, not Claude.** The CloudTrail parser assigns `normalized_severity` deterministically via a small lookup table (root-account use → Critical, MFA disable → High, etc.). Claude does the *contextual* triage downstream — but the *initial* severity has to be deterministic so the clusterer's ordering and the policy gate's thresholds work without an LLM in the hot path. Same reasoning as Phase 1's `level >= 7` Wazuh prefilter — the LLM is for nuance, not for priority queue ordering.
5. **`cloud_audit_findings` is additive to `clusters`, not a replacement.** The same CloudTrail event populates both: a row in `clusters` (so Claude triages it like any other alert) and possibly a row in `cloud_audit_findings` (when it matches a deterministic pattern). The findings table is operator-facing, lossless, and idempotent on `alert_id`. This is the same shape as Phase 4's `attack_recommendations` — a side channel for human review that does not interfere with the automated loop.
6. **LocalStack for integration tests, `moto` for unit tests.** `moto` runs in-process and is fast (sub-second); LocalStack runs as a container and is slow (~30s spin-up) but covers the realistic IAM evaluation. Unit tests use `moto`; the single integration test that asserts the end-to-end pipeline uses LocalStack and is gated by an `AWS_INTEGRATION=1` env var so contributors without Docker can still run unit tests. Real AWS validation happens manually in the operator's actual account before P5 closes — this is what unblocks the "fixture-only testing is insufficient" concern that has been paused since Phase 2.5.
7. **`lookup_cloud_identity` is the 9th tool, registered via `register_tool` per DEC-ORCH-006.** No dynamic-loading change, no schema change to `register_tool` — Phase 4's API was designed for exactly this. The tool reads from the existing `alerts` table (no new index needed; the existing `alerts(source, rule_id)` index covers the common case; we add `alerts(source, raw_json -> '$.userIdentity.arn')` only if benchmarks show the need — measure first).
8. **Auth/RBAC stays single-user; CloudTrail uses one IAM role.** Multi-user auth is REQ-NOGO-P5-003. The Phase 5 agent uses one AWS IAM role (`s3:ListBucket` + `s3:GetObject` on a single prefix). Multi-account / Organization Trail support is REQ-P2-P5-006. Pairing auth with rule-fleet-distribution in Phase 6 keeps Phase 5 scoped — operators sharing the manager today already share the `SHAFERHUND_TOKEN`; CloudTrail does not change that calculus.
9. **Cursor in DB, not in memory.** `cloudtrail_progress` table holds `last_s3_key` per prefix. Restart-safe, audit-friendly, operator-debuggable (`SELECT * FROM cloudtrail_progress`). Same shape as the in-DB state used for `slo_breaches` and `deploy_events` in Phase 4 — consistency over convenience.
10. **CloudTrail S3 keys are time-ordered; `StartAfter` is sufficient.** AWS publishes CloudTrail objects with keys like `AWSLogs/<account>/CloudTrail/<region>/<YYYY>/<MM>/<DD>/<account>_CloudTrail_<region>_<YYYYMMDDTHHMMZ>_<uuid>.json.gz`. `list_objects_v2(StartAfter=last_s3_key)` returns objects strictly after the cursor in lex order — which is also chronological order for this key shape. No need for an inventory or a manifest. We document this assumption in `agent/sources/cloudtrail.py` and add a sanity test that breaks if AWS ever changes the key format (the CI test fixtures are real captured paths from the operator's account, redacted).
11. **Cloud findings detector runs in-process after the clusterer, not as a separate task.** Cloud findings are deterministic (no LLM), cheap (single-row DB lookup for the "anomalous AssumeRole" pattern), and benefit from running synchronously so a finding is visible by the time the cluster lands. Pulling them into a background task would add complexity without reducing latency — the clusterer already runs on the same loop. `agent/cloud_findings.py` exposes one pure function `evaluate(alert: dict, conn) -> Optional[Finding]`; called once per CloudTrail-source alert from `_persist_and_enqueue`.
12. **`finding_type` enum is a code-resident frozenset, not a config table.** Same reasoning as Phase 4's `DESTRUCTIVE_TECHNIQUES` (DEC-RECOMMEND-002): the set of detected patterns is reviewed at code-review time, not runtime. Operators add a finding type via PR. New patterns are intentional, audited, and migration-free.

### Files to Create / Update

```
shaferhund/
  compose.yaml                          # (UPDATE) document CLOUDTRAIL_* env vars in agent service block; no new containers in prod
  requirements.txt                      # (UPDATE) add boto3, aiobotocore, moto (dev-only)
  .env.example                          # (UPDATE) document Phase 5 env vars + IAM policy reference
  docs/
    cloudtrail-iam-policy.json          # (NEW) least-privilege IAM policy for the agent's read role
    PHASE5_OPERATOR_GUIDE.md            # (NEW) operator setup: trail config, IAM role, env vars
  agent/
    sources/
      cloudtrail.py                     # (NEW) S3 poller + parse_cloudtrail_event + severity heuristic
    cloud_findings.py                   # (NEW) deterministic finding detector + frozenset of finding_type values
    orchestrator.py                     # (UPDATE) register lookup_cloud_identity tool via existing register_tool API
    models.py                           # (UPDATE) cloudtrail_progress + cloud_audit_findings tables; CRUD helpers
    main.py                             # (UPDATE) /cloud/findings, /cloud/findings/{id}/ack routes; CloudTrail poller task in lifespan; /health additions
    config.py                           # (UPDATE) CLOUDTRAIL_* env fields + AWS credential resolution
    triage.py                           # (no change expected — verify integration)
    templates/
      cloud_findings.html               # (NEW, P1) pending findings list + ack action
  tests/
    test_cloudtrail_parser.py           # (NEW) parse_cloudtrail_event matrix (AssumeRole, ConsoleLogin, malformed)
    test_cloudtrail_poller.py           # (NEW) moto-backed S3 poller unit tests + cursor advancement
    test_cloud_findings.py              # (NEW) deterministic detector matrix per finding_type
    test_lookup_cloud_identity.py       # (NEW) tool transcript + DB filter + 25-event cap
    test_orchestrator_9_tools.py        # (NEW) regression: 9 tools registered, all dispatchable
    integration/
      test_cloudtrail_localstack.py     # (NEW) end-to-end pipeline behind AWS_INTEGRATION=1 env gate
    fixtures/
      cloudtrail_assume_role.json       # (NEW) golden CloudTrail event
      cloudtrail_console_login.json     # (NEW) golden CloudTrail event
      cloudtrail_mfa_disable.json       # (NEW) triggers cloud_audit_finding
      cloudtrail_root_account.json      # (NEW) triggers cloud_audit_finding
      cloudtrail_malformed.json         # (NEW) parser-resilience fixture
```

### Success Criteria

- `podman compose up` with `CLOUDTRAIL_ENABLED=true` and valid AWS creds brings up the existing 5-service stack; container logs show `cloudtrail-poller` task running alongside `wazuh-tailer` / `suricata-tailer` / `urlhaus-poller`
- A real (or LocalStack-backed) CloudTrail bucket with an AssumeRole + MFA-disable event produces: a row in `alerts` with `source='cloudtrail'`, a cluster with key `('cloudtrail', src_ip, 'cloudtrail:iam.amazonaws.com:DeactivateMFADevice')`, a `cloud_audit_findings` row with `finding_type='mfa_disable'`, a triage result with Claude-assigned severity and ai_analysis
- Orchestrator transcript on a synthetic CloudTrail cluster shows `lookup_cloud_identity` called and returns 25-event-grouped principal history
- `/health` reports `cloudtrail.poller_running=true`, non-null `last_poll_at`, plausible `lag_seconds`; `/cloud/findings` lists the pending finding
- `grep -rn "_REGISTRY\|register_tool" agent/orchestrator.py | wc -l` shows the 9th tool registered with no manual mutation of `_REGISTRY` or `TOOLS`
- LocalStack integration test passes locally and in CI (gated by `AWS_INTEGRATION=1`); IAM policy file passes shape validation
- Phase 1 / Phase 2 / Phase 2.5 / Phase 3 / Phase 4 tests pass unchanged; all new Phase 5 tests pass

### GitHub Issues

- **Wave A (parallel — no inter-dependencies):**
  - REQ-P0-P5-001 + REQ-P0-P5-002 — `agent/sources/cloudtrail.py`: S3 poller + `parse_cloudtrail_event` + severity heuristic + `cloudtrail_progress` table (`feature/phase5-cloudtrail-source`) — issue #53
  - REQ-P0-P5-005 — `cloud_audit_findings` table + `agent/cloud_findings.py` deterministic detector + `/cloud/findings` route (`feature/phase5-cloud-findings`) — issue #54
  - REQ-P0-P5-006 — `/health` and `/metrics` additions for CloudTrail observability (`feature/phase5-cloudtrail-observability`) — issue #55
- **Wave B (depends on Wave A `cloudtrail.py`):**
  - REQ-P0-P5-003 — `lookup_cloud_identity` 9th orchestrator tool registered via `register_tool` (`feature/phase5-lookup-cloud-identity`) — issue #56
  - REQ-P0-P5-004 — LocalStack integration test + IAM policy file + operator guide (`feature/phase5-cloudtrail-integration`) — issue #57
- **Wave C (gate, blocked by Wave A + B):**
  - REQ-P0-P5-007 — zero-regression gate across all prior phases; final integration smoke (`feature/phase5-regression-gate`) — issue #58
- **Wave D (P1, parallelizable after Wave B; only if timebox allows):**
  - REQ-P1-P5-001 — `/cloud/findings` HTMX dashboard (`feature/phase5-findings-dashboard`)
  - REQ-P1-P5-002 — `lookup_cloud_identity` consults threat_intel for IOC overlap (`feature/phase5-lookup-threat-intel`)
  - REQ-P1-P5-003 — `recommend_attack` cloud-technique awareness (`feature/phase5-recs-cloud`)
  - REQ-P1-P5-004 — `from_timestamp` cursor backfill mode (`feature/phase5-poller-backfill`)
  - REQ-P1-P5-005 — Source filter chip on `/` extended with `cloudtrail` (`feature/phase5-source-chip-cloud`)

### Decision Log

| ID | Title | Status |
|----|-------|--------|
| DEC-CLOUD-001 | AWS CloudTrail as the first cloud provider; one-provider-only Phase 5; GCP/Azure deferred to Phase 6 with same pattern | accepted |
| DEC-CLOUD-002 | S3 polling (not EventBridge/Kinesis); 60s default cadence; cursor-in-DB via `cloudtrail_progress` table | accepted |
| DEC-CLOUD-003 | `source='cloudtrail'` reuses shared `alerts` table; clusterer/orchestrator/policy gate require zero changes | accepted |
| DEC-CLOUD-004 | Severity assigned by deterministic heuristic table at parse time; LLM does contextual triage downstream | accepted |
| DEC-CLOUD-005 | `cloud_audit_findings` is additive to clusters; deterministic detector runs synchronously after clusterer | accepted |
| DEC-CLOUD-006 | LocalStack for integration tests + moto for unit tests; real AWS validation manual before phase close | accepted |
| DEC-CLOUD-007 | `lookup_cloud_identity` is the 9th tool via existing `register_tool` API; no dispatch refactor | accepted |
| DEC-CLOUD-008 | Single IAM role / single-user auth retained; multi-user RBAC explicitly deferred to Phase 6 with rule fleet | accepted |
| DEC-CLOUD-009 | `finding_type` enum is a code-resident frozenset (per DEC-RECOMMEND-002 pattern); new types via PR, not config | accepted |
| DEC-CLOUD-010 | CloudTrail S3 key shape is time-ordered; `StartAfter` is sufficient; documented assumption + sanity test guards future drift | accepted |
| DEC-CLOUD-011 | New tables (`cloudtrail_progress`, `cloud_audit_findings`) follow DEC-SCHEMA-002 idempotent ALTER pattern | accepted |
| DEC-CLOUD-012 | `CLOUDTRAIL_ENABLED` defaults to `false`; the source is opt-in; absent AWS creds is a clean degraded mode, not a startup failure | accepted |
| DEC-CLOUD-013 | LocalStack integration tests use a skip-if-not-running pattern (`requests.get` health check on `:4566/_localstack/health`); CI stays green when LocalStack is absent, operators opt in via `compose.localstack.yaml`. Closes the long-standing "fixture-only testing is insufficient" loophole that was paused since Phase 2.5 — mocked boto3 cannot catch credential-flow bugs, endpoint-URL misconfigurations, or S3 pagination edge cases. Surfaced empirically by the V7 live-integration check during #54 verification, where 25 unit tests passed but a runtime `ImportError` from a function-local boto3 import only fired against real S3 — same DEC-SLO-004 pattern of unit-tests-pass-but-live-integration-catches-it, now applied as the standing rule for cloud sources | accepted |

## TODOs
- [ ] Convert `hund` to `ROADMAP.md` (map 25 domains to phases) — DEFER: the per-phase plans now serve as the de facto roadmap; surface as a real backlog item or close. Recommend closing.
- [ ] Phase 6+ scoping: GCP Audit Logs + Azure Monitor (multi-cloud, same source-pipeline pattern as Phase 5 CloudTrail, REQ-NOGO-P5-001 carry-forward); rule fleet distribution to remote Wazuh agents (signed pull, multi-agent rollout) paired with multi-user auth / RBAC / signed audit logs (REQ-NOGO-P2-006 / REQ-NOGO-P4-007 / REQ-NOGO-P5-002 / REQ-NOGO-P5-003 carry-forward); CloudTrail Lake / Athena query backend for `lookup_cloud_identity` at scale (REQ-NOGO-P5-007 / REQ-P2-P5-004); real-time CloudTrail via EventBridge → SQS (REQ-NOGO-P5-008 / REQ-P2-P5-003); multi-account / Organization Trail support (REQ-P2-P5-006); containerised service honeypots (SSH/MySQL/Redis, REQ-NOGO-P5-005); STIX/TAXII threat-intel federation (REQ-NOGO-P5-004); adversarial rule-effectiveness scoring including cloud techniques T1078.004 / T1098.x (REQ-NOGO-P5-010); multi-tenant posture / per-team scoring (REQ-NOGO-P5-006); cloud-native rule deploy (push to AWS GuardDuty / Security Hub, REQ-NOGO-P5-009 / REQ-P2-P5-005)
- [x] Backlog item #5 "fixture-only testing is insufficient" — CLOSED 2026-04-25 by Phase 5 Wave B2 (PR #65 / issue #58): LocalStack integration harness in `tests/integration/test_cloudtrail_localstack.py` exercises real boto3 against an AWS-API-compatible S3 service, gated by skip-if-not-running. Standing rule via DEC-CLOUD-013.
