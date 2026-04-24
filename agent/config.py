"""
Shaferhund agent configuration.

Loaded via pydantic-settings from environment variables.
Missing required vars (ANTHROPIC_API_KEY) raise ValidationError at startup —
fail fast rather than silently degrading.

@decision DEC-CONFIG-001
@title pydantic-settings for env var validation
@status accepted
@rationale Eng review mandated fail-fast on missing env vars. pydantic-settings
           provides typed validation, default handling, and clear error messages
           without additional boilerplate. SHAFERHUND_TOKEN unset binds to
           localhost only (see main.py host selection).
"""

import json
from typing import Optional

from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import field_validator


class Settings(BaseSettings):
    """All runtime configuration read from environment variables."""

    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8")

    # Required — missing value raises ValidationError at import time
    anthropic_api_key: str

    # File paths
    alerts_file: str = "/var/ossec/logs/alerts/alerts.json"
    suricata_eve_file: str = "/var/log/suricata/eve.json"
    db_path: str = "/data/shaferhund.db"
    rules_dir: str = "/rules"

    # Triage tuning
    triage_hourly_budget: int = 20
    poll_interval_seconds: int = 60
    suricata_poll_seconds: int = 60
    severity_min_level: int = 7

    # Queue limits
    queue_max_depth: int = 100
    cluster_max_alerts: int = 50
    cluster_window_seconds: int = 300  # 5 minutes

    # Auth — if unset, main.py binds to 127.0.0.1 only
    shaferhund_token: str = ""

    # Claude model
    claude_model: str = "claude-opus-4-5"

    # Orchestrator caps (Phase 2)
    orch_max_tool_calls: int = 5
    orch_wall_timeout_seconds: float = 10.0

    # Sigma-cli availability — populated by the lifespan startup probe
    # (REQ-P0-P25-003). Defaults to False so a misconfigured container can
    # never accidentally auto-deploy Sigma rules before the probe confirms
    # sigma-cli is usable. Set by _probe_sigmac() in main.py lifespan.
    sigmac_available: bool = False
    sigmac_version: Optional[str] = None

    # Phase 3 — Threat Intel (REQ-P0-P3-005)
    # URLhaus online-URL CSV feed endpoint. Override for air-gapped deployments
    # or to pin a specific feed variant. The default points to the live feed.
    urlhaus_feed_url: str = "https://urlhaus.abuse.ch/downloads/csv_online/"
    # How often (in seconds) the URLhaus poller refreshes the local threat_intel
    # table. Defaults to 3600 (hourly) per MASTER_PLAN.md Phase 3 spec.
    urlhaus_fetch_interval_seconds: int = 3600

    # Auto-deploy policy gate (Phase 2, REQ-P0-P2-006, DEC-AUTODEPLOY-001)
    # Default OFF — operator must explicitly enable via env var.
    AUTO_DEPLOY_ENABLED: bool = False
    AUTO_DEPLOY_CONF_THRESHOLD: float = 0.85
    AUTO_DEPLOY_DEDUP_WINDOW_SECONDS: int = 3600
    # JSON-encoded list in env: AUTO_DEPLOY_SEVERITIES='["Critical","High"]'
    # Falls back to the default list when the env var is absent.
    AUTO_DEPLOY_SEVERITIES: list[str] = ["Critical", "High"]

    @field_validator("AUTO_DEPLOY_SEVERITIES", mode="before")
    @classmethod
    def parse_severities(cls, v: object) -> list[str]:
        """Accept a JSON-encoded string (env var) or a plain list."""
        if isinstance(v, str):
            parsed = json.loads(v)
            if not isinstance(parsed, list):
                raise ValueError("AUTO_DEPLOY_SEVERITIES must be a JSON list of strings")
            return parsed
        return v  # type: ignore[return-value]

    @field_validator("triage_hourly_budget")
    @classmethod
    def budget_positive(cls, v: int) -> int:
        if v < 1:
            raise ValueError("TRIAGE_HOURLY_BUDGET must be >= 1")
        return v

    @field_validator("severity_min_level")
    @classmethod
    def severity_in_range(cls, v: int) -> int:
        if not (0 <= v <= 15):
            raise ValueError("severity_min_level must be 0-15")
        return v


def get_settings() -> Settings:
    """Return a validated Settings instance.

    Raises pydantic.ValidationError if required env vars are missing.
    Called once at application startup so failures surface immediately.
    """
    return Settings()
