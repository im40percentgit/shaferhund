"""
Tests for the sigma-cli startup probe (REQ-P0-P25-003).

Verifies:
  1. Successful sigma --version → sigmac_available=True, sigmac_version set.
  2. FileNotFoundError (sigma not on PATH) → sigmac_available=False, WARNING logged.
  3. Non-zero exit code → sigmac_available=False, WARNING logged.
  4. TimeoutExpired → sigmac_available=False, WARNING logged.
  5. /metrics endpoint exposes sigmac.available and sigmac.version fields.

@decision DEC-SIGMA-DEGRADE-001
@title Startup probe flips settings.sigmac_available once; downstream reads the bool
@status accepted
@rationale Tests confirm fail-safe default (False) and that all failure modes
           produce one WARNING rather than raising. The probe runs once per
           startup; re-probing on every triage would add 50-100ms latency per rule.
           Mocking subprocess.run is acceptable here — it IS the external boundary
           (a subprocess exec to sigma-cli, an external binary).

# @mock-exempt: subprocess.run is an external process boundary — spawning the
# sigma-cli binary. We cannot install sigma-cli in CI, so mocking the OS-level
# call is the only viable strategy. This is exactly the pattern the Sacred
# Practice exemption covers (external boundary = HTTP APIs, third-party
# services, OS process exec).
"""

import logging
import subprocess
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest
from fastapi.testclient import TestClient

import agent.main as main_module
from agent.config import Settings
from agent.main import _probe_sigmac
from agent.models import init_db


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _fresh_settings() -> SimpleNamespace:
    """Minimal settings namespace with sigmac fields at their defaults."""
    return SimpleNamespace(
        sigmac_available=False,
        sigmac_version=None,
        shaferhund_token="",
        rules_dir="/tmp/rules-probe-test",
        db_path=":memory:",
        alerts_file="/dev/null",
        suricata_eve_file="/dev/null",
        triage_hourly_budget=20,
        AUTO_DEPLOY_ENABLED=False,
    )


def _make_completed_process(returncode: int, stdout: str) -> MagicMock:
    cp = MagicMock()
    cp.returncode = returncode
    cp.stdout = stdout
    return cp


def _make_metrics_client(tmp_path):
    """Return a TestClient with module singletons patched for /metrics tests."""
    conn = init_db(":memory:")
    settings = _fresh_settings()

    main_module._db = conn
    main_module._settings = settings
    main_module._triage_queue = None
    main_module._poller_healthy = False
    main_module._last_poll_at = None

    client = TestClient(main_module.app, raise_server_exceptions=True)
    return client, conn


# ---------------------------------------------------------------------------
# Probe unit tests
# ---------------------------------------------------------------------------

def test_probe_sets_available_true_on_success():
    """Successful sigma --version → sigmac_available=True, sigmac_version populated."""
    settings = _fresh_settings()
    mock_result = _make_completed_process(0, "sigma-cli, version 1.0.4\n")

    with patch("agent.main.subprocess.run", return_value=mock_result) as mock_run:
        _probe_sigmac(settings)

    mock_run.assert_called_once_with(
        ["sigma", "--version"],
        capture_output=True,
        text=True,
        timeout=5,
    )
    assert settings.sigmac_available is True
    assert settings.sigmac_version == "sigma-cli, version 1.0.4"


def test_probe_sets_available_false_on_filenotfound(caplog):
    """FileNotFoundError (sigma not on PATH) → sigmac_available=False, one WARNING."""
    settings = _fresh_settings()

    with caplog.at_level(logging.WARNING, logger="agent.main"):
        with patch("agent.main.subprocess.run", side_effect=FileNotFoundError()):
            _probe_sigmac(settings)

    assert settings.sigmac_available is False
    assert settings.sigmac_version is None
    warnings = [r for r in caplog.records if r.levelno == logging.WARNING]
    assert len(warnings) == 1
    assert "sigma-cli not available" in warnings[0].message


def test_probe_sets_available_false_on_nonzero_exit(caplog):
    """Non-zero exit from sigma --version → sigmac_available=False, one WARNING."""
    settings = _fresh_settings()
    mock_result = _make_completed_process(1, "")

    with caplog.at_level(logging.WARNING, logger="agent.main"):
        with patch("agent.main.subprocess.run", return_value=mock_result):
            _probe_sigmac(settings)

    assert settings.sigmac_available is False
    assert settings.sigmac_version is None
    warnings = [r for r in caplog.records if r.levelno == logging.WARNING]
    assert len(warnings) == 1
    assert "sigma-cli not available" in warnings[0].message


def test_probe_sets_available_false_on_timeout(caplog):
    """TimeoutExpired → sigmac_available=False, one WARNING."""
    settings = _fresh_settings()

    with caplog.at_level(logging.WARNING, logger="agent.main"):
        with patch(
            "agent.main.subprocess.run",
            side_effect=subprocess.TimeoutExpired(cmd=["sigma", "--version"], timeout=5),
        ):
            _probe_sigmac(settings)

    assert settings.sigmac_available is False
    assert settings.sigmac_version is None
    warnings = [r for r in caplog.records if r.levelno == logging.WARNING]
    assert len(warnings) == 1
    assert "sigma-cli not available" in warnings[0].message


# ---------------------------------------------------------------------------
# /metrics endpoint — sigmac block
# ---------------------------------------------------------------------------

def test_metrics_endpoint_exposes_sigmac_fields(tmp_path):
    """/metrics response contains sigmac.available and sigmac.version."""
    client, conn = _make_metrics_client(tmp_path)

    resp = client.get("/metrics")
    assert resp.status_code == 200

    data = resp.json()
    assert "sigmac" in data, "'sigmac' key missing from /metrics response"

    sigmac = data["sigmac"]
    assert "available" in sigmac, "'sigmac.available' missing"
    assert "version" in sigmac, "'sigmac.version' missing"
    # Default state: sigma-cli was not probed in this test (settings patched directly)
    assert sigmac["available"] is False
    assert sigmac["version"] is None

    conn.close()
