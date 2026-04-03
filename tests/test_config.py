"""
Config validation tests (2 tests).

Tests:
  1. Valid env vars produce a Settings instance with correct values.
  2. Missing ANTHROPIC_API_KEY raises ValidationError at construction.
"""

import pytest
from pydantic import ValidationError


def test_valid_config(monkeypatch):
    """Settings instantiates correctly when all required vars are present."""
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key-abc123")
    monkeypatch.setenv("TRIAGE_HOURLY_BUDGET", "10")
    monkeypatch.setenv("SEVERITY_MIN_LEVEL", "7")

    # Import after monkeypatch so pydantic-settings picks up the env vars
    from agent.config import Settings
    s = Settings()

    assert s.anthropic_api_key == "test-key-abc123"
    assert s.triage_hourly_budget == 10
    assert s.severity_min_level == 7
    assert s.cluster_max_alerts == 50
    assert s.queue_max_depth == 100


def test_missing_api_key_raises(monkeypatch):
    """ValidationError is raised when ANTHROPIC_API_KEY is not set."""
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)

    from agent.config import Settings
    with pytest.raises(ValidationError) as exc_info:
        Settings()

    errors = exc_info.value.errors()
    fields = [e["loc"][0] for e in errors]
    assert "anthropic_api_key" in fields
