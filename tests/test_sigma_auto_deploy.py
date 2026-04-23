"""
Sigma auto-deploy integration tests — verifies that _run_auto_deploy routes
Sigma rules through sigmac.convert and handles conversion failures correctly.

Uses an in-memory SQLite DB and tmp_path for RULES_DIR.  sigmac.convert is
mocked because it is an external subprocess boundary (sigma-cli); all other
internal modules (policy gate, DB helpers, orchestrator loop logic) are
exercised against real implementations.

# @mock-exempt: sigmac.convert shells out to sigma-cli — an external process
# boundary.  This is the only mock in the file; all internal logic is real.

@decision DEC-AUTODEPLOY-003
@title Sigma now auto-deploys when sigmac_available=True
@status accepted
@rationale These integration tests exercise the full _run_auto_deploy path for
           Sigma rules: happy-path conversion produces an XML file + audit row;
           SigmaConversionError records a 'skipped' row before propagating so
           the failure is always auditable.  The skipped-row-before-exception
           contract is critical — the outer try/except in _run_auto_deploy would
           otherwise swallow a conversion failure with no audit trail.

Test cases:
  1. test_sigma_auto_deploy_happy_path       — sigmac.convert succeeds →
       XML file written, mark_rule_deployed called, deploy_events action='auto-deploy'.
  2. test_sigma_auto_deploy_records_skipped_on_conversion_failure — sigmac.convert
       raises SigmaConversionError → no file written, no mark_rule_deployed,
       deploy_events action='skipped' with reason containing 'sigmac conversion failed',
       WARNING logged, loop continues to next rule.
"""

import logging
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

from agent.models import (
    init_db,
    insert_rule,
    list_deploy_events,
    update_cluster_ai,
    upsert_cluster,
)
from agent.orchestrator import _run_auto_deploy
from agent.sigmac import SigmaConversionError


# ---------------------------------------------------------------------------
# Shared helpers
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
    sigmac_available: bool = True,
) -> SimpleNamespace:
    return SimpleNamespace(
        AUTO_DEPLOY_ENABLED=enabled,
        AUTO_DEPLOY_CONF_THRESHOLD=conf_threshold,
        AUTO_DEPLOY_DEDUP_WINDOW_SECONDS=dedup_window,
        AUTO_DEPLOY_SEVERITIES=severities if severities is not None else ["Critical", "High"],
        rules_dir=str(rules_dir),
        sigmac_available=sigmac_available,
    )


def _seed_cluster(
    conn,
    cluster_id: str,
    src_ip: str = "10.0.0.42",
    rule_id: int = 5501,
    ai_severity: str = "Critical",
    ai_confidence: float = 0.9,
) -> None:
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
    update_cluster_ai(conn, cluster_id, ai_severity, "Test analysis.", ai_confidence)


def _seed_sigma_rule(
    conn,
    cluster_id: str,
    rule_id: str = "sigma-rule-001",
    syntax_valid: bool = True,
    content: str = "title: Test\nstatus: test\ndetection:\n  selection:\n    EventID: 4625\n  condition: selection\n",
) -> str:
    insert_rule(
        conn,
        rule_id=rule_id,
        cluster_id=cluster_id,
        rule_type="sigma",
        rule_content=content,
        syntax_valid=syntax_valid,
    )
    return rule_id


# ---------------------------------------------------------------------------
# Case 1: Happy path — sigmac.convert succeeds
# ---------------------------------------------------------------------------


def test_sigma_auto_deploy_happy_path(tmp_path):
    """When sigmac.convert succeeds, the XML file is written and audit row recorded."""
    conn = _make_db()
    cluster_id = "cluster-sigma-happy"
    rule_id = "sigma-rule-happy-001"
    sigma_yaml = "title: HappyTest\nstatus: test\ndetection:\n  selection:\n    EventID: 4625\n  condition: selection\n"
    xml_content = "<group name='test'><rule id='100001' level='12'><description>HappyTest</description></rule></group>"

    _seed_cluster(conn, cluster_id, ai_severity="Critical", ai_confidence=0.9)
    _seed_sigma_rule(conn, cluster_id, rule_id=rule_id, syntax_valid=True, content=sigma_yaml)

    config = _make_settings(enabled=True, conf_threshold=0.85, rules_dir=tmp_path, sigmac_available=True)

    # Mock sigmac.convert to write the XML and return the path, as the real impl does.
    expected_xml_path = tmp_path / f"sigma_{rule_id}.xml"

    def fake_convert(yaml_content, rid, rdir):
        out = Path(rdir) / f"sigma_{rid}.xml"
        out.write_text(xml_content, encoding="utf-8")
        return out

    with patch("agent.orchestrator._sigmac.convert", side_effect=fake_convert) as mock_convert:
        _run_auto_deploy(conn, cluster_id, config)

    # sigmac.convert was called once with correct args
    mock_convert.assert_called_once_with(sigma_yaml, rule_id, tmp_path)

    # XML file written at RULES_DIR/sigma_<rule_id>.xml
    assert expected_xml_path.exists(), f"Expected XML at {expected_xml_path}"
    assert expected_xml_path.read_text(encoding="utf-8") == xml_content

    # deploy_events row: action='auto-deploy', rule_type='sigma'
    events = [dict(e) for e in list_deploy_events(conn)]
    assert len(events) == 1, f"Expected 1 deploy event, got {len(events)}: {events}"
    evt = events[0]
    assert evt["action"] == "auto-deploy", f"Expected action='auto-deploy', got {evt['action']!r}"
    assert evt["rule_type"] == "sigma", f"Expected rule_type='sigma', got {evt['rule_type']!r}"
    assert evt["reason"] == "ok"
    assert evt["actor"] == "orchestrator"

    conn.close()


# ---------------------------------------------------------------------------
# Case 2: Conversion failure — skipped row written, loop continues
# ---------------------------------------------------------------------------


def test_sigma_auto_deploy_records_skipped_on_conversion_failure(tmp_path, caplog):
    """SigmaConversionError → skipped row written BEFORE exception propagates; loop continues.

    This test uses two rules: rule-fail (conversion raises) and rule-yara (YARA,
    should deploy normally).  Verifies:
      - No file for rule-fail
      - deploy_events action='skipped' with 'sigmac conversion failed' in reason for rule-fail
      - WARNING logged containing rule-fail's ID
      - YARA rule-yara is still evaluated and deployed (loop continued)
    """
    conn = _make_db()
    cluster_id = "cluster-sigma-fail"

    _seed_cluster(conn, cluster_id, ai_severity="Critical", ai_confidence=0.9)

    # Rule 1: Sigma rule whose conversion will fail
    sigma_rule_id = "sigma-rule-fail-001"
    _seed_sigma_rule(conn, cluster_id, rule_id=sigma_rule_id, syntax_valid=True)

    # Rule 2: YARA rule that should still deploy after the Sigma failure
    yara_rule_id = "yara-rule-continue-001"
    yara_content = 'rule ContinueRule { strings: $s = "continue" condition: $s }'
    insert_rule(
        conn,
        rule_id=yara_rule_id,
        cluster_id=cluster_id,
        rule_type="yara",
        rule_content=yara_content,
        syntax_valid=True,
    )

    config = _make_settings(enabled=True, conf_threshold=0.85, rules_dir=tmp_path, sigmac_available=True)

    with patch(
        "agent.orchestrator._sigmac.convert",
        side_effect=SigmaConversionError("sigma-cli not found"),
    ):
        with caplog.at_level(logging.WARNING, logger="agent.orchestrator"):
            _run_auto_deploy(conn, cluster_id, config)

    # No XML file for the failed Sigma rule
    sigma_xml = tmp_path / f"sigma_{sigma_rule_id}.xml"
    assert not sigma_xml.exists(), f"No XML file expected for failed conversion: {sigma_xml}"

    events = [dict(e) for e in list_deploy_events(conn)]

    # Skipped row for the Sigma rule
    skipped = [e for e in events if e["action"] == "skipped" and e["rule_type"] == "sigma"]
    assert len(skipped) == 1, f"Expected 1 skipped sigma event, got: {events}"
    assert "sigmac conversion failed" in skipped[0]["reason"], (
        f"Expected 'sigmac conversion failed' in reason, got: {skipped[0]['reason']!r}"
    )

    # WARNING logged with the rule_id
    warning_msgs = [r.message for r in caplog.records if r.levelno == logging.WARNING]
    assert any(sigma_rule_id in msg for msg in warning_msgs), (
        f"Expected WARNING containing {sigma_rule_id!r}, got: {warning_msgs}"
    )

    # Loop continued: YARA rule was evaluated and deployed
    yara_deployed = [e for e in events if e["action"] == "auto-deploy" and e["rule_type"] == "yara"]
    assert len(yara_deployed) == 1, (
        f"Expected YARA rule to deploy after Sigma failure, got events: {events}"
    )
    yara_file = tmp_path / f"{yara_rule_id}.yar"
    assert yara_file.exists(), f"Expected YARA file at {yara_file}"

    conn.close()
