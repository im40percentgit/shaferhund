# Shaferhund — Alert Triage Agent

AI-powered Wazuh alert triage for solo security engineers.

## Quick Start

```bash
cp .env.example .env
# Edit .env — set ANTHROPIC_API_KEY
docker compose up -d
# Dashboard: http://localhost:8000
```

## Requirements

- Docker or Podman with compose support
- Anthropic API key (`claude-opus-4-5` model access)

## Architecture

```
Wazuh Manager (4.9.2) → alerts.json (volume) → File Tailer
  → Clusterer (5-min window, src_ip+rule_id)
  → Triage Queue (hourly budget, exp backoff)
  → Claude API (severity / IOCs / YARA)
  → SQLite → FastAPI + HTMX Dashboard
```

## Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `ANTHROPIC_API_KEY` | required | Claude API key |
| `TRIAGE_HOURLY_BUDGET` | `20` | Max Claude calls per hour |
| `SEVERITY_MIN_LEVEL` | `7` | Minimum Wazuh rule level to triage |
| `SHAFERHUND_TOKEN` | unset | Bearer token; unset = localhost-only |
| `ALERTS_FILE` | `/var/ossec/logs/alerts/alerts.json` | Path to Wazuh alerts file |
| `DB_PATH` | `/data/shaferhund.db` | SQLite database path |
| `RULES_DIR` | `/rules` | YARA rules output directory |

## Development

```bash
pip install -r requirements.txt
ANTHROPIC_API_KEY=test pytest tests/
```

## Endpoints

- `GET /` — HTMX dashboard (cluster list, auto-refresh 10s)
- `GET /clusters/{id}` — Cluster detail + YARA rule
- `POST /rules/{id}/deploy` — Write YARA rule to `/rules/` volume
- `GET /health` — Poller status, queue depth, last triage timestamp
