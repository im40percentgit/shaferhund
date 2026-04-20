"""
Auto-deploy integration tests — verifies that _run_auto_deploy wires correctly
through the policy gate, file system, and deploy_events audit table.

All tests use an in-memory SQLite DB (agent.models.init_db(':memory:')) and
tmp_path for RULES_DIR so no real filesystem paths are touched.

# @mock-exempt: claude_client is the Anthropic HTTP API — an external boundary.
# No internal modules are mocked; policy, DB helpers, and the orchestrator
# function are exercised against real implementations.

Test cases:
  1. test_auto_deploy_disabled        — AUTO_DEPLOY_ENABLED=False → no file,
                                        deploy_events row with action='skipped',
                                        reason='auto-deploy disabled'.
  2. test_auto_deploy_happy_path      — enabled, conf=0.9, Critical, yara, valid,
                                        no prior deploys → file written at
                                        RULES_DIR/<rule_id>.yar AND
                                        deploy_events row action='auto-deploy'.
  3. test_auto_deploy_rejected_medium — enabled but severity=Medium → no file,
                                        deploy_events row action='skipped' with
                                        severity reason.
  4. test_auto_deploy_dedup           — enabled, pre-seeded matching deploy_events
                                        row within the window → no new file,
                                        deploy_events row action='skipped' with
                                        dedup reason.

@decision DEC-AUTODEPLOY-001
@title Policy-gated auto-deploy, conservative defaults, default OFF
@status accepted
@rationale Tests verify the full integration path from orchestrator through
           policy gate to filesystem and audit table, using real DB and real
           policy function. No internal mocking — the only external boundary
           (the Claude API client) is mocked in test_orchestrator.py; these
           tests call _run_auto_deploy directly.
"""

import time
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from agent.models import (
    init_db,
    insert_rule,
    list_deploy_events,
    record_deploy_event,
    update_cluster_ai,
    upsert_cluster,
)
from agent.orchestrator import _run_auto_deploy


# ---------------------------------------------------------------------------
# Shared fixtures
# ---------------------------------------------------------------------------


def _make_db():
    """Return a fresh in-memory SQLite connection with the full schema."""
    return init_db(":memory:")


def _make_settings(
    *,
    enabled: bool = True,
    conf_threshold: float = 0.85,
    dedup_window: int = 3600,
    severities: list[str] | None = None,
    rules_dir: str | Path = "/rules",
) -> SimpleNamespace:
    """Return a minimal settings object for auto-deploy tests."""
    return SimpleNamespace(
        AUTO_DEPLOY_ENABLED=enabled,
        AUTO_DEPLOY_CONF_THRESHOLD=conf_threshold,
        AUTO_DEPLOY_DEDUP_WINDOW_SECONDS=dedup_window,
        AUTO_DEPLOY_SEVERITIES=severities if severities is not None else ["Critical", "High"],
        rules_dir=str(rules_dir),
    )


def _seed_cluster(
    conn,
    cluster_id: str,
    src_ip: str = "10.0.0.42",
    rule_id: int = 5501,
    ai_severity: str = "Critical",
    ai_confidence: float = 0.9,
) -> None:
    """Insert a cluster row with AI triage results already committed."""
    upsert_cluster(
        conn,
        cluster_id=cluster_id,
        src_ip=src_ip,
        rule_id=rule_id,
        window_start="2026-01-01T00:00:00",
        window_end="2026-01-01T00:05:00",
        alert_count=3,
        source="wazuh",
    )
    # Simulate finalize_triage having committed the verdict (including confidence).
    update_cluster_ai(conn, cluster_id, ai_severity, "Test analysis.", ai_confidence)


def _seed_yara_rule(
    conn,
    cluster_id: str,
    rule_id: str = "rule-uuid-001",
    syntax_valid: bool = True,
    content: str = 'rule TestRule { strings: $s = "malware" condition: $s }',
) -> str:
    """Insert a YARA rule row and return its rule_id."""
    insert_rule(
        conn,
        rule_id=rule_id,
        cluster_id=cluster_id,
        rule_type="yara",
        rule_content=content,
        syntax_valid=syntax_valid,
    )
    return rule_id


# ---------------------------------------------------------------------------
# Case 1: AUTO_DEPLOY_ENABLED=False (default) → skipped
# ---------------------------------------------------------------------------


def test_auto_deploy_disabled(tmp_path):
    """When AUTO_DEPLOY_ENABLED=False, no file is written and a 'skipped' event is recorded."""
    conn = _make_db()
    cluster_id = "cluster-disabled"
    _seed_cluster(conn, cluster_id)
    rule_id = _seed_yara_rule(conn, cluster_id, rule_id="rule-disabled-001")

    config = _make_settings(enabled=False, rules_dir=tmp_path)

    _run_auto_deploy(conn, cluster_id, config)

    # No file written
    assert not any(tmp_path.iterdir()), "Expected RULES_DIR to be empty when auto-deploy is disabled"

    # deploy_events row with action='skipped', reason='auto-deploy disabled'
    events = [dict(e) for e in list_deploy_events(conn)]
    assert len(events) == 1, f"Expected 1 deploy event, got {len(events)}: {events}"
    evt = events[0]
    assert evt["action"] == "skipped"
    assert evt["reason"] == "auto-deploy disabled"
    assert evt["actor"] == "orchestrator"
    assert evt["rule_type"] == "yara"

    conn.close()


# ---------------------------------------------------------------------------
# Case 2: Happy path → file written + 'auto-deploy' event
# ---------------------------------------------------------------------------


def test_auto_deploy_happy_path(tmp_path):
    """Enabled + conf=0.9 + Critical + yara + valid + no prior deploys → file deployed."""
    conn = _make_db()
    cluster_id = "cluster-happy"
    rule_content = 'rule HappyRule { strings: $s = "evil" condition: $s }'
    _seed_cluster(conn, cluster_id, ai_severity="Critical", ai_confidence=0.9)
    rule_id = _seed_yara_rule(
        conn, cluster_id, rule_id="rule-happy-001",
        syntax_valid=True, content=rule_content,
    )

    config = _make_settings(enabled=True, conf_threshold=0.85, rules_dir=tmp_path)

    _run_auto_deploy(conn, cluster_id, config)

    # File must exist at RULES_DIR/<rule_id>.yar
    rule_file = tmp_path / f"{rule_id}.yar"
    assert rule_file.exists(), f"Expected rule file at {rule_file}"
    assert rule_file.read_text(encoding="utf-8") == rule_content

    # deploy_events row with action='auto-deploy', reason='ok'
    events = [dict(e) for e in list_deploy_events(conn)]
    assert len(events) == 1, f"Expected 1 deploy event, got {len(events)}: {events}"
    evt = events[0]
    assert evt["action"] == "auto-deploy"
    assert evt["reason"] == "ok"
    assert evt["actor"] == "orchestrator"
    assert evt["rule_type"] == "yara"
    assert evt["src_ip"] == "10.0.0.42"

    conn.close()


# ---------------------------------------------------------------------------
# Case 3: Rejected — severity=Medium not in allowlist
# ---------------------------------------------------------------------------


def test_auto_deploy_rejected_medium(tmp_path):
    """Severity=Medium is not in {Critical, High} → skipped, no file written."""
    conn = _make_db()
    cluster_id = "cluster-medium"
    _seed_cluster(conn, cluster_id, ai_severity="Medium", ai_confidence=0.95)
    rule_id = _seed_yara_rule(conn, cluster_id, rule_id="rule-medium-001", syntax_valid=True)

    config = _make_settings(
        enabled=True,
        severities=["Critical", "High"],
        rules_dir=tmp_path,
    )

    _run_auto_deploy(conn, cluster_id, config)

    # No file written
    assert not any(tmp_path.iterdir()), "No file should be written for Medium severity"

    # deploy_events row with action='skipped', severity reason
    events = [dict(e) for e in list_deploy_events(conn)]
    assert len(events) == 1, f"Expected 1 deploy event, got {len(events)}: {events}"
    evt = events[0]
    assert evt["action"] == "skipped"
    assert "severity" in evt["reason"], f"Expected severity in reason, got: {evt['reason']!r}"

    conn.close()


# ---------------------------------------------------------------------------
# Case 4: Dedup — matching deploy within window → skipped
# ---------------------------------------------------------------------------


def test_auto_deploy_dedup(tmp_path):
    """A recent matching deploy_events row blocks a second deploy for the same cluster."""
    conn = _make_db()
    cluster_id = "cluster-dedup"
    src_ip = "10.0.0.42"
    wazuh_rule_id = 5501

    _seed_cluster(
        conn, cluster_id, src_ip=src_ip, rule_id=wazuh_rule_id,
        ai_severity="Critical", ai_confidence=0.92,
    )
    rule_id = _seed_yara_rule(conn, cluster_id, rule_id="rule-dedup-001", syntax_valid=True)

    # Pre-seed a deploy_events row within the window that matches
    # (rule_type='yara', src_ip=src_ip, rule_id=wazuh_rule_id).
    # get_recent_deploys joins deploy_events -> rules -> clusters to resolve
    # the cluster's rule_id; we pre-seed via record_deploy_event so the
    # rule_uuid -> cluster join path is exercised.
    record_deploy_event(
        conn,
        rule_id=rule_id,
        action="auto-deploy",
        reason="ok",
        actor="orchestrator",
        rule_type="yara",
        src_ip=src_ip,
    )

    config = _make_settings(
        enabled=True,
        dedup_window=3600,
        rules_dir=tmp_path,
    )

    _run_auto_deploy(conn, cluster_id, config)

    # No NEW file written (the first deploy would have written one, but we
    # didn't call _run_auto_deploy for the first deploy — we pre-seeded it).
    rule_file = tmp_path / f"{rule_id}.yar"
    assert not rule_file.exists(), "No new file should be written when dedup fires"

    # The new call should have added a 'skipped' event (in addition to the
    # pre-seeded 'auto-deploy' event).
    events = [dict(e) for e in list_deploy_events(conn)]
    skipped = [e for e in events if e["action"] == "skipped"]
    assert len(skipped) == 1, f"Expected 1 skipped event, got: {events}"
    assert "dedup" in skipped[0]["reason"], (
        f"Expected dedup in reason, got: {skipped[0]['reason']!r}"
    )

    conn.close()
