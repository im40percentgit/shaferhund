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

**Status:** in-progress
**Started:** 2026-04-22 (planner trace `planner-20260422-201536-956a04`, plan-only PR on `docs/plan-phase-2.5-start`)
**Timebox:** 3–4 days

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
| DEC-SIGMA-CONVERT-001 | sigmac invoked via subprocess (sigma-cli), not Python API | planned |
| DEC-AUTODEPLOY-003 | Sigma auto-deploy via extended policy gate + sigmac_available check | planned |
| DEC-SIGMA-DEGRADE-001 | Graceful degradation when sigmac missing — warn and disable, don't crash | planned |
| DEC-CLOUDLOG-001 | Cloud log source ingestion deferred to Phase 4 — needs real footprint to test, not fixtures | planned |

> Note: `DEC-AUTODEPLOY-002` is **already taken** by the CSO-audit None-guard decision at `agent/policy.py:82` (accepted). The original Phase 2.5 plan pre-reserved that ID for the Sigma gate; reassigned to `DEC-AUTODEPLOY-003` during the 2026-04-22 planner pass. Similarly `DEC-SIGMA-002`/`DEC-SIGMA-003` are renamed to `DEC-SIGMA-CONVERT-001`/`DEC-SIGMA-DEGRADE-001` so the IDs name the concept rather than the number.

## Phase 3: Immune System (2–3 weeks after Phase 2.5)

**Status:** planned
**Timebox:** 2–3 weeks

### Intent

Phase 2 gave the agent eyes (unified Wazuh + Suricata ingestion), a brain (Claude tool-use orchestrator), and hands (policy-gated auto-deploy). Phase 2.5 will finish the hands — once shipped, Sigma rules will auto-deploy too, via sigmac conversion. **Phase 3 gives it an immune system.** The agent attacks its own infrastructure on a schedule via Atomic Red Team, measures whether its deployed rules detect those attacks, and uses the resulting pass rate as a **single posture score**. An auto-spawnable canary network (DNS and HTTP tokens) traps opportunistic probing and feeds the same pipeline. A light-touch threat-intel feed (Abuse.ch URLhaus) adds indicator context to the orchestrator's reasoning. The platform becomes self-evaluating — when the posture score drops, the agent knows before the operator does.

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
| DEC-REDTEAM-001 | External scheduled ART harness (not Claude-driven) | planned |
| DEC-POSTURE-001 | Posture score = ART pass rate (deployed-rule coverage over total tests) | planned |
| DEC-CANARY-001 | DNS + HTTP canary tokens only; service honeypots deferred to Phase 4 | planned |
| DEC-THREATINTEL-001 | URLhaus only; STIX/TAXII federation deferred | planned |
| DEC-ORCH-004 | `check_threat_intel` added via direct TOOLS patch (no dynamic registration refactor) | planned |
| DEC-REDTEAM-002 | Declarative `atomic_tests.yaml`; no full ART auto-discovery | planned |
| DEC-CANARY-002 | Canary events enter via existing `_persist_and_enqueue`; `source='canary'` | planned |
| DEC-POSTURE-002 | Phase 3 P0 ships even if Phase 2.5 Sigma slips; YARA-biased score acceptable as interim | planned |

## TODOs
- [ ] Convert `hund` to `ROADMAP.md` (map 25 domains to phases)
- [ ] Phase 4 scoping: agent-driven red team, containerised honeypots, threat-intel federation, rule fleet distribution, cloud log source ingestion (first provider) + multi-cloud coverage, dynamic orchestrator tool registration, posture SLO with paging
