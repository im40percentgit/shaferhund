"""
Unit tests for agent/fleet_client.py (Phase 6 Wave B2, REQ-P0-P6-002).

Tests cover: fetch_manifest, verify_and_apply, run_once, run_loop,
FleetClientSettings.from_env.

All tests run without an external server — httpx is mocked via
unittest.mock.patch for the fetch_manifest tests.  verify_and_apply and
run_once use real HMAC keys and real file I/O against tmp_path.

# @mock-exempt: httpx.Client is an external HTTP boundary — mocking it is the
# appropriate approach for unit tests. All internal logic (HMAC verification,
# file writes, stale cleanup) is tested with real I/O.
"""

import asyncio
import os
import unittest.mock as mock
from pathlib import Path

import httpx
import pytest

from agent.fleet import build_manifest, sign_manifest, canonical_manifest_body
from agent.fleet_client import (
    FleetClientSettings,
    fetch_manifest,
    run_loop,
    run_once,
    verify_and_apply,
)
from agent.models import init_db, insert_rule, tag_rule

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_KEY = bytes.fromhex("aa" * 32)
_WRONG_KEY = bytes.fromhex("bb" * 32)
_FIXED_TS = "2026-04-25T16:30:00+00:00"
_MANIFEST_URL = "http://manager:8000/fleet/manifest/edr-prod"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_valid_manifest(rules: list[dict] | None = None) -> dict:
    """Build a properly signed manifest dict without a real DB."""
    if rules is None:
        rules = []
    canon = canonical_manifest_body(1, "edr-prod", _FIXED_TS, rules)
    sig = sign_manifest(_KEY, canon)
    import hashlib
    manifest_id = hashlib.sha256(canon).hexdigest()
    return {
        "version": 1,
        "manifest_id": manifest_id,
        "tag": "edr-prod",
        "generated_at": _FIXED_TS,
        "rules": rules,
        "signature": sig,
    }


def _make_db_manifest(conn, tag: str = "edr-prod") -> dict:
    """Build a signed manifest from a real DB connection."""
    return build_manifest(conn, tag, _KEY, generated_at=_FIXED_TS)


@pytest.fixture()
def conn(tmp_path):
    db = init_db(str(tmp_path / "test.db"))
    yield db
    db.close()


def _seed_rule(conn, rule_id: str = "rule-001", tag: str = "edr-prod", rule_type: str = "yara") -> str:
    insert_rule(
        conn,
        rule_id=rule_id,
        cluster_id=None,
        rule_type=rule_type,
        rule_content=f"rule {rule_id} {{}}",
        syntax_valid=True,
    )
    conn.execute("UPDATE rules SET deployed = 1 WHERE id = ?", (rule_id,))
    conn.commit()
    tag_rule(conn, rule_id, tag)
    return rule_id


@pytest.fixture()
def settings(tmp_path) -> FleetClientSettings:
    return FleetClientSettings(
        manifest_url=_MANIFEST_URL,
        hmac_key=_KEY,
        rules_dir=str(tmp_path / "rules"),
    )


# ---------------------------------------------------------------------------
# fetch_manifest
# ---------------------------------------------------------------------------

def test_fetch_manifest_success():
    """Mock 200 response — returns parsed dict."""
    expected = {"version": 1, "rules": [], "signature": "abc"}
    with mock.patch("agent.fleet_client.httpx.Client") as mock_client_cls:
        mock_resp = mock.MagicMock()
        mock_resp.json.return_value = expected
        mock_resp.raise_for_status = mock.MagicMock()
        mock_client_cls.return_value.__enter__.return_value.get.return_value = mock_resp

        result = fetch_manifest(_MANIFEST_URL)

    assert result == expected
    mock_resp.raise_for_status.assert_called_once()


def test_fetch_manifest_with_bearer_token():
    """Bearer token is sent as Authorization header."""
    with mock.patch("agent.fleet_client.httpx.Client") as mock_client_cls:
        mock_resp = mock.MagicMock()
        mock_resp.json.return_value = {}
        mock_resp.raise_for_status = mock.MagicMock()
        mock_get = mock_client_cls.return_value.__enter__.return_value.get
        mock_get.return_value = mock_resp

        fetch_manifest(_MANIFEST_URL, bearer_token="my-secret-token")

    _call_kwargs = mock_get.call_args
    sent_headers = _call_kwargs.kwargs.get("headers") or _call_kwargs.args[1] if len(_call_kwargs.args) > 1 else {}
    # Verify the Authorization header was passed (either via positional or keyword)
    all_kwargs = mock_get.call_args[1] if mock_get.call_args[1] else {}
    headers = all_kwargs.get("headers", {})
    assert headers.get("Authorization") == "Bearer my-secret-token"


def test_fetch_manifest_4xx_raises():
    """4xx response raises httpx.HTTPStatusError."""
    with mock.patch("agent.fleet_client.httpx.Client") as mock_client_cls:
        mock_resp = mock.MagicMock()
        mock_resp.raise_for_status.side_effect = httpx.HTTPStatusError(
            "401 Unauthorized",
            request=mock.MagicMock(),
            response=mock.MagicMock(),
        )
        mock_client_cls.return_value.__enter__.return_value.get.return_value = mock_resp

        with pytest.raises(httpx.HTTPStatusError):
            fetch_manifest(_MANIFEST_URL)


# ---------------------------------------------------------------------------
# verify_and_apply
# ---------------------------------------------------------------------------

def test_verify_and_apply_invalid_signature_raises(tmp_path):
    """Tampered signature → ValueError before any file is written."""
    manifest = _make_valid_manifest()
    manifest["signature"] = "0" * 64  # corrupt

    rules_dir = str(tmp_path / "rules")
    with pytest.raises(ValueError, match="signature verification failed"):
        verify_and_apply(manifest, _KEY, rules_dir)

    # No files should have been written
    assert not Path(rules_dir).exists() or list(Path(rules_dir).iterdir()) == []


def test_verify_and_apply_wrong_key_raises(tmp_path):
    """Wrong key → ValueError, no files written."""
    manifest = _make_valid_manifest()
    rules_dir = str(tmp_path / "rules")
    with pytest.raises(ValueError, match="signature verification failed"):
        verify_and_apply(manifest, _WRONG_KEY, rules_dir)


def test_verify_and_apply_writes_rule_files(tmp_path):
    """Valid manifest with 2 rules → 2 files with correct extensions."""
    rules = [
        {"id": "rule-yara-001", "rule_type": "yara", "name": "c1", "content": "rule yara_001 {}", "syntax_valid": 1},
        {"id": "rule-sigma-002", "rule_type": "sigma", "name": "c2", "content": "title: Sigma", "syntax_valid": 1},
    ]
    manifest = _make_valid_manifest(rules)
    rules_dir = str(tmp_path / "rules")

    summary = verify_and_apply(manifest, _KEY, rules_dir)

    assert summary["rules_written"] == 2
    assert summary["rules_removed"] == 0
    assert Path(rules_dir, "rule-yara-001.yar").exists()
    assert Path(rules_dir, "rule-sigma-002.yml").exists()
    assert Path(rules_dir, "rule-yara-001.yar").read_text() == "rule yara_001 {}"
    assert Path(rules_dir, "rule-sigma-002.yml").read_text() == "title: Sigma"


def test_verify_and_apply_removes_stale_files(tmp_path):
    """Stale file in rules_dir not in manifest → removed after apply."""
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    stale = rules_dir / "stale-rule.yar"
    stale.write_text("rule stale {}")

    manifest = _make_valid_manifest()  # empty rules list
    summary = verify_and_apply(manifest, _KEY, str(rules_dir))

    assert summary["rules_removed"] == 1
    assert not stale.exists()


def test_verify_and_apply_returns_summary(tmp_path):
    """Summary dict has required keys with correct types."""
    manifest = _make_valid_manifest()
    summary = verify_and_apply(manifest, _KEY, str(tmp_path / "rules"))

    assert "rules_written" in summary
    assert "rules_removed" in summary
    assert "manifest_id" in summary
    assert isinstance(summary["rules_written"], int)
    assert isinstance(summary["rules_removed"], int)
    assert isinstance(summary["manifest_id"], str)


def test_verify_and_apply_creates_rules_dir(tmp_path):
    """rules_dir is created if it does not exist."""
    rules_dir = str(tmp_path / "nested" / "rules")
    manifest = _make_valid_manifest()
    verify_and_apply(manifest, _KEY, rules_dir)
    assert Path(rules_dir).exists()


def test_verify_and_apply_wazuh_extension(tmp_path):
    """Wazuh rule type gets .xml extension."""
    rules = [{"id": "rule-wazuh-001", "rule_type": "wazuh", "name": "", "content": "<rule/>", "syntax_valid": 1}]
    manifest = _make_valid_manifest(rules)
    summary = verify_and_apply(manifest, _KEY, str(tmp_path / "rules"))
    assert Path(tmp_path / "rules" / "rule-wazuh-001.xml").exists()
    assert summary["rules_written"] == 1


def test_verify_and_apply_unknown_rule_type_extension(tmp_path):
    """Unknown rule type gets default .rule extension."""
    rules = [{"id": "rule-unknown-001", "rule_type": "custom", "name": "", "content": "data", "syntax_valid": 0}]
    manifest = _make_valid_manifest(rules)
    summary = verify_and_apply(manifest, _KEY, str(tmp_path / "rules"))
    assert Path(tmp_path / "rules" / "rule-unknown-001.rule").exists()
    assert summary["rules_written"] == 1


def test_verify_and_apply_only_removes_managed_extensions(tmp_path):
    """Non-managed files (e.g. .conf) in rules_dir are not removed."""
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    conf_file = rules_dir / "local_rules.conf"
    conf_file.write_text("# keep me")

    manifest = _make_valid_manifest()  # empty rules list
    summary = verify_and_apply(manifest, _KEY, str(rules_dir))

    assert conf_file.exists(), "Non-managed .conf file should not be removed"
    assert summary["rules_removed"] == 0


# ---------------------------------------------------------------------------
# run_once
# ---------------------------------------------------------------------------

def test_run_once_full_path(tmp_path, conn):
    """run_once fetches and applies; rule file appears in rules_dir."""
    _seed_rule(conn, "rule-001", "edr-prod", "yara")
    manifest = _make_db_manifest(conn, "edr-prod")

    with mock.patch("agent.fleet_client.fetch_manifest", return_value=manifest):
        settings = FleetClientSettings(
            manifest_url=_MANIFEST_URL,
            hmac_key=_KEY,
            rules_dir=str(tmp_path / "rules"),
        )
        summary = run_once(settings)

    assert summary["rules_written"] == 1
    assert Path(tmp_path / "rules" / "rule-001.yar").exists()


# ---------------------------------------------------------------------------
# run_loop
# ---------------------------------------------------------------------------

def test_run_loop_cancellation(tmp_path):
    """Task cancellation exits cleanly — no unhandled exceptions."""
    manifest = _make_valid_manifest()

    async def _run():
        with mock.patch("agent.fleet_client.fetch_manifest", return_value=manifest):
            settings = FleetClientSettings(
                manifest_url=_MANIFEST_URL,
                hmac_key=_KEY,
                rules_dir=str(tmp_path / "rules"),
            )
            task = asyncio.create_task(run_loop(settings, interval_seconds=10))
            # Let one iteration start then cancel
            await asyncio.sleep(0.05)
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass  # expected — clean exit

    asyncio.run(_run())


def test_run_loop_handles_fetch_error_gracefully(tmp_path):
    """Fetch error on first iteration — loop survives and second iteration succeeds."""
    manifest = _make_valid_manifest()
    call_count = 0

    def _fetch_side_effect(*args, **kwargs):
        nonlocal call_count
        call_count += 1
        if call_count == 1:
            raise httpx.ConnectError("connection refused")
        return manifest

    async def _run():
        with mock.patch("agent.fleet_client.fetch_manifest", side_effect=_fetch_side_effect):
            settings = FleetClientSettings(
                manifest_url=_MANIFEST_URL,
                hmac_key=_KEY,
                rules_dir=str(tmp_path / "rules"),
            )
            task = asyncio.create_task(run_loop(settings, interval_seconds=0))
            # Wait long enough for 2 iterations at 0s interval
            await asyncio.sleep(0.2)
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass

    asyncio.run(_run())
    assert call_count >= 2, f"Expected >=2 fetch calls, got {call_count}"


# ---------------------------------------------------------------------------
# FleetClientSettings.from_env
# ---------------------------------------------------------------------------

def test_settings_from_env_success(monkeypatch, tmp_path):
    """from_env reads all required + optional vars correctly."""
    monkeypatch.setenv("FLEET_MANIFEST_URL", "http://manager:8000/fleet/manifest/edr-prod")
    monkeypatch.setenv("FLEET_HMAC_KEY", "aa" * 32)
    monkeypatch.setenv("FLEET_RULES_DIR", str(tmp_path / "rules"))
    monkeypatch.setenv("FLEET_BEARER_TOKEN", "tok-123")

    settings = FleetClientSettings.from_env()

    assert settings.manifest_url == "http://manager:8000/fleet/manifest/edr-prod"
    assert settings.hmac_key == bytes.fromhex("aa" * 32)
    assert settings.rules_dir == str(tmp_path / "rules")
    assert settings.bearer_token == "tok-123"


def test_settings_from_env_missing_required(monkeypatch):
    """Missing required env vars → EnvironmentError with clear message."""
    monkeypatch.delenv("FLEET_MANIFEST_URL", raising=False)
    monkeypatch.delenv("FLEET_HMAC_KEY", raising=False)

    with pytest.raises(EnvironmentError, match="FLEET_MANIFEST_URL"):
        FleetClientSettings.from_env()


def test_settings_from_env_invalid_hex(monkeypatch):
    """Invalid hex in FLEET_HMAC_KEY → EnvironmentError."""
    monkeypatch.setenv("FLEET_MANIFEST_URL", "http://manager/fleet/manifest/edr-prod")
    monkeypatch.setenv("FLEET_HMAC_KEY", "not-valid-hex!")

    with pytest.raises(EnvironmentError, match="not valid hex"):
        FleetClientSettings.from_env()


def test_settings_from_env_optional_bearer_none(monkeypatch):
    """Missing FLEET_BEARER_TOKEN → bearer_token is None (not empty string)."""
    monkeypatch.setenv("FLEET_MANIFEST_URL", "http://manager/fleet/manifest/edr-prod")
    monkeypatch.setenv("FLEET_HMAC_KEY", "aa" * 32)
    monkeypatch.delenv("FLEET_BEARER_TOKEN", raising=False)

    settings = FleetClientSettings.from_env()
    assert settings.bearer_token is None
