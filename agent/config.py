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
