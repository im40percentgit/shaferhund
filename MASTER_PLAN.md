# Shaferhund — Master Plan

## Original Intent

Build a fully automated, agentic blue-team cybersecurity defense platform. The user's vision (from the `hund` spec) covers 25 capability domains: real-time network traffic analysis, EDR, SIEM, UEBA, vulnerability management, IAM, cloud security, compliance, threat intelligence, automated incident response, phishing defense, DNS filtering, DLP, encryption management, container security, and more. The ultimate goal is a self-evolving offensive-defensive loop that attacks its own infrastructure, finds gaps, writes rules, and retests... an immune system, not a tool.

The user is having fun building this while also thinking about it as a potential startup. They chose the name "Shaferhund" (German Shepherd, a guard dog).

## Project Overview

Agentic blue-team cybersecurity defense platform for solo security engineers at startups. AI-powered alert triage that ingests Wazuh alerts, clusters them, sends to Claude API for severity classification / IOC detection / YARA rule generation.

**Target user:** Solo security engineer, <100 endpoints, no SIEM budget.
**Design doc:** `~/.gstack/projects/shaferhund/j-unknown-design-20260403-113500.md`

## Phase 1: Alert Triage Agent (Weekend Prototype)

**Status:** planned

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

## Phase 2: Unified Defense Agent (Weeks 2-4)

**Status:** planned
- Add Suricata as second alert source
- Add Sigma rule generation
- Agent orchestration via Claude tool-use state machine
- Auto-deploy rules to Wazuh/Suricata
- Cloud log ingestion (AWS CloudTrail, GCP Audit)
- OpenSearch for historical queries
- Real-time posture scoring dashboard

## Phase 3: Immune System (Month 2+)

**Status:** planned
- Atomic Red Team integration for continuous self-testing
- Offensive-defensive loop
- Auto-generated honeypots and canary tokens
- Threat intel mesh (requires separate design)

## TODOs
- [ ] Convert hund to ROADMAP.md (map 25 domains to phases)
