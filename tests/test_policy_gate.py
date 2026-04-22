"""
Policy gate tests — pure unit tests, no I/O, no DB.

Tests verify every rejection branch and the happy path of
should_auto_deploy(rule, cluster, recent_deploys, settings).

Fixtures use dataclasses to match the shape that the orchestrator
produces after a tool-use loop (rule from DB row, cluster from DB row).
No ORM models are imported — same pattern as test_orchestrator.py which
uses SimpleNamespace / dicts throughout.

@decision DEC-AUTODEPLOY-001
@title Policy-gated auto-deploy, conservative defaults, default OFF
@status accepted
@rationale Tests cover all 7 rejection branches (disabled, rule_type, syntax,
           confidence, severity, dedup, happy path) using plain dataclasses.
           The function under test is pure — no DB connections, no file I/O —
           so tests are fast and deterministic regardless of environment.
"""

import time
from dataclasses import dataclass, field
from types import SimpleNamespace

import pytest

from agent.policy import should_auto_deploy


# ---------------------------------------------------------------------------
# Fixture helpers
# ---------------------------------------------------------------------------

@dataclass
class FakeRule:
    rule_type: str = "yara"
    syntax_valid: bool = True
    rule_id: str = "rule-001"


@dataclass
class FakeCluster:
    src_ip: str = "10.0.0.42"
    rule_id: int = 5501
    ai_confidence: float = 0.9
    ai_severity: str = "Critical"


def _make_settings(
    *,
    enabled: bool = True,
    conf_threshold: float = 0.85,
    dedup_window: int = 3600,
    severities: list[str] | None = None,
) -> SimpleNamespace:
    return SimpleNamespace(
        AUTO_DEPLOY_ENABLED=enabled,
        AUTO_DEPLOY_CONF_THRESHOLD=conf_threshold,
        AUTO_DEPLOY_DEDUP_WINDOW_SECONDS=dedup_window,
        AUTO_DEPLOY_SEVERITIES=severities if severities is not None else ["Critical", "High"],
    )


def _recent_deploy(
    rule_type: str = "yara",
    src_ip: str = "10.0.0.42",
    rule_id: int = 5501,
    age_seconds: float = 60,
) -> dict:
    """Build a recent_deploy entry as would be returned from a DB query."""
    return {
        "rule_type": rule_type,
        "src_ip": src_ip,
        "rule_id": rule_id,
        "deployed_at_ts": time.time() - age_seconds,
    }


# ---------------------------------------------------------------------------
# Test 1: AUTO_DEPLOY_ENABLED=False (default) → disabled
# ---------------------------------------------------------------------------

def test_disabled_returns_false():
    """When AUTO_DEPLOY_ENABLED is False, return (False, 'auto-deploy disabled')."""
    settings = _make_settings(enabled=False)
    decision, reason = should_auto_deploy(
        FakeRule(), FakeCluster(), [], settings
    )
    assert decision is False
    assert reason == "auto-deploy disabled"


# ---------------------------------------------------------------------------
# Test 2: rule_type='sigma' → not eligible
# ---------------------------------------------------------------------------

def test_sigma_rule_type_rejected():
    """Sigma rules are excluded from auto-deploy in Phase 2."""
    settings = _make_settings(enabled=True)
    rule = FakeRule(rule_type="sigma")
    decision, reason = should_auto_deploy(rule, FakeCluster(), [], settings)
    assert decision is False
    assert "rule_type" in reason


# ---------------------------------------------------------------------------
# Test 3: syntax_valid=False → syntax invalid
# ---------------------------------------------------------------------------

def test_syntax_invalid_rejected():
    """A rule with syntax_valid=False is rejected."""
    settings = _make_settings(enabled=True)
    rule = FakeRule(rule_type="yara", syntax_valid=False)
    decision, reason = should_auto_deploy(rule, FakeCluster(), [], settings)
    assert decision is False
    assert "syntax" in reason


# ---------------------------------------------------------------------------
# Test 4: ai_confidence=0.6 → below threshold
# ---------------------------------------------------------------------------

def test_low_confidence_rejected():
    """A cluster with ai_confidence below the threshold is rejected."""
    settings = _make_settings(enabled=True, conf_threshold=0.85)
    cluster = FakeCluster(ai_confidence=0.6)
    decision, reason = should_auto_deploy(FakeRule(), cluster, [], settings)
    assert decision is False
    assert "confidence" in reason


# ---------------------------------------------------------------------------
# Test 5: ai_severity='Medium' → not in allowlist
# ---------------------------------------------------------------------------

def test_medium_severity_rejected():
    """A cluster with severity 'Medium' is not in the {Critical, High} allowlist."""
    settings = _make_settings(enabled=True)
    cluster = FakeCluster(ai_severity="Medium")
    decision, reason = should_auto_deploy(FakeRule(), cluster, [], settings)
    assert decision is False
    assert "severity" in reason


# ---------------------------------------------------------------------------
# Test 6: dedup window hit — same (rule_type, src_ip, rule_id) within window
# ---------------------------------------------------------------------------

def test_dedup_window_hit_rejected():
    """A recent deploy with matching (rule_type, src_ip, rule_id) within window → rejected."""
    settings = _make_settings(enabled=True, dedup_window=3600)
    rule = FakeRule(rule_type="yara")
    cluster = FakeCluster(src_ip="10.0.0.42", rule_id=5501)

    # This deploy happened 60 seconds ago — well within the 3600s window
    recent = _recent_deploy(
        rule_type="yara",
        src_ip="10.0.0.42",
        rule_id=5501,
        age_seconds=60,
    )

    decision, reason = should_auto_deploy(rule, cluster, [recent], settings)
    assert decision is False
    assert "dedup" in reason


# ---------------------------------------------------------------------------
# Test 7: Happy path — all checks pass → (True, 'ok')
# ---------------------------------------------------------------------------

def test_happy_path_deploys():
    """All checks pass: enabled + yara + valid + confidence≥0.85 + Critical + no dedup."""
    settings = _make_settings(enabled=True, conf_threshold=0.85)
    rule = FakeRule(rule_type="yara", syntax_valid=True)
    cluster = FakeCluster(ai_confidence=0.9, ai_severity="Critical")

    decision, reason = should_auto_deploy(rule, cluster, [], settings)
    assert decision is True
    assert reason == "ok"


# ---------------------------------------------------------------------------
# Bonus: dedup entry outside the window should NOT block deployment
# ---------------------------------------------------------------------------

def test_dedup_expired_entry_allows_deploy():
    """A recent_deploy entry older than the dedup window does not block deploy."""
    settings = _make_settings(enabled=True, dedup_window=3600)
    rule = FakeRule(rule_type="yara")
    cluster = FakeCluster(src_ip="10.0.0.42", rule_id=5501)

    # Deploy happened 4000 seconds ago — outside the 3600s window
    expired = _recent_deploy(
        rule_type="yara",
        src_ip="10.0.0.42",
        rule_id=5501,
        age_seconds=4000,
    )

    decision, reason = should_auto_deploy(rule, cluster, [expired], settings)
    assert decision is True
    assert reason == "ok"


# ---------------------------------------------------------------------------
# F4 / DEC-AUTODEPLOY-002: ai_confidence=None must not raise TypeError
# ---------------------------------------------------------------------------

def test_none_confidence_returns_false_not_raise():
    """cluster.ai_confidence=None returns (False, 'confidence not set'), not TypeError.

    Pre-F4 this raised TypeError: '<' not supported between instances of
    'NoneType' and 'float'. The explicit None guard in Check 4 fixes this.
    """
    settings = _make_settings(enabled=True)
    cluster = FakeCluster(ai_confidence=None)

    # Must not raise
    decision, reason = should_auto_deploy(FakeRule(), cluster, [], settings)

    assert decision is False
    assert reason == "confidence not set", (
        f"Expected 'confidence not set', got {reason!r}"
    )


# ---------------------------------------------------------------------------
# Purity check: function raises no exceptions on empty/minimal inputs
# ---------------------------------------------------------------------------

def test_purity_no_side_effects():
    """should_auto_deploy does not mutate its inputs and returns consistent results."""
    settings = _make_settings(enabled=True)
    rule = FakeRule()
    cluster = FakeCluster()
    recent: list[dict] = []

    # Call twice — result must be identical
    r1 = should_auto_deploy(rule, cluster, recent, settings)
    r2 = should_auto_deploy(rule, cluster, recent, settings)
    assert r1 == r2

    # Inputs must not be mutated
    assert recent == []
