"""
Policy gate for auto-deploy decisions.

Pure decision function — no I/O, no DB queries.
Callers are responsible for supplying recent_deploys as a list.

@decision DEC-AUTODEPLOY-001
@title Policy-gated auto-deploy, conservative defaults, default OFF
@status accepted
@rationale Auto-deploy mistakes are cheap to reverse (undo endpoint exists) but
           the *consequences* of a bad rule deploying — false positives causing
           alert fatigue, or a broken YARA rule crashing the scanner — are
           operationally painful. Conservative defaults address this in two ways:
           (1) AUTO_DEPLOY_ENABLED defaults to False so a misconfigured deployment
               never silently auto-deploys on first run.
           (2) Every check is a hard gate with a named failure reason so the audit
               log tells operators exactly why a rule was or was not deployed.
           Sigma rules are excluded in Phase 2 because there is no deploy path
           without a sigmac conversion step (deferred to Phase 3). Only YARA
           rules have a well-defined file-drop deploy path today.
           The dedup window prevents duplicate rules from being deployed when
           the same threat pattern triggers multiple overlapping clusters within
           a short window — the first deploy wins and subsequent ones are skipped.
"""

import time
from typing import Any

# Type aliases — callers may pass dataclasses, sqlite3.Row dicts, or SimpleNamespace.
# The function only accesses attributes, so any object with the right attributes works.
_RuleLike = Any
_ClusterLike = Any
_SettingsLike = Any


def should_auto_deploy(
    rule: _RuleLike,
    cluster: _ClusterLike,
    recent_deploys: list[dict],
    settings: _SettingsLike,
) -> tuple[bool, str]:
    """Decide whether a rule should be automatically deployed.

    Checks are ordered: first failure wins and returns immediately so the
    audit reason always reflects the most fundamental blocker.

    Args:
        rule: Object with attributes rule_type (str), syntax_valid (bool).
              Typically a sqlite3.Row dict or a dataclass from the rules table.
        cluster: Object with attributes ai_confidence (float), ai_severity (str).
                 Typically a sqlite3.Row dict or a dataclass from the clusters table.
        recent_deploys: List of dicts, each with keys:
                          rule_type (str), src_ip (str), rule_id (int|str),
                          deployed_at_ts (float, Unix timestamp).
                        Callers query the DB and pass the result; this function
                        performs no I/O.
        settings: Config object (pydantic Settings or SimpleNamespace) with:
                    AUTO_DEPLOY_ENABLED (bool)
                    AUTO_DEPLOY_CONF_THRESHOLD (float)
                    AUTO_DEPLOY_DEDUP_WINDOW_SECONDS (int)
                    AUTO_DEPLOY_SEVERITIES (list[str])

    Returns:
        (True, 'ok') when all checks pass.
        (False, <reason>) on the first failing check, where <reason> is a
        short human-readable string suitable for audit logging.
    """
    # Check 1: feature flag — default OFF
    if not settings.AUTO_DEPLOY_ENABLED:
        return False, "auto-deploy disabled"

    # Check 2: only YARA rules have a deploy path in Phase 2
    if rule.rule_type != "yara":
        return False, "rule_type not eligible for auto-deploy"

    # Check 3: syntax must be valid
    if rule.syntax_valid is not True:
        return False, "rule syntax invalid"

    # Check 4: AI confidence must meet the threshold
    #
    # @decision DEC-AUTODEPLOY-002
    # @title Explicit None guard on ai_confidence; defaults to 0.0 in finalize_triage
    # @status accepted
    # @rationale Pre-F4 the pipeline passed None from finalize_triage (the
    #            finalize_triage tool schema had no confidence field, so
    #            update_cluster_ai was called without ai_confidence, leaving
    #            the DB column NULL). That caused TypeError: '<' not supported
    #            between instances of 'NoneType' and 'float' here. Now
    #            finalize_triage always writes a float (default 0.0) and the
    #            gate returns a clean (False, reason) on missing confidence
    #            rather than raising.
    if cluster.ai_confidence is None:
        return False, "confidence not set"
    if cluster.ai_confidence < settings.AUTO_DEPLOY_CONF_THRESHOLD:
        return False, "confidence below threshold"

    # Check 5: severity must be in the allowlist
    if cluster.ai_severity not in settings.AUTO_DEPLOY_SEVERITIES:
        return False, "severity not in allowlist"

    # Check 6: dedup — reject if a matching deploy exists within the window
    now = time.time()
    cutoff = now - settings.AUTO_DEPLOY_DEDUP_WINDOW_SECONDS
    for deploy in recent_deploys:
        if deploy.get("deployed_at_ts", 0) < cutoff:
            # Expired — outside the dedup window
            continue
        if (
            deploy.get("rule_type") == rule.rule_type
            and deploy.get("src_ip") == cluster.src_ip
            and deploy.get("rule_id") == cluster.rule_id
        ):
            return False, "dedup window hit"

    # All checks passed
    return True, "ok"
