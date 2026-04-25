"""
Deterministic cloud-audit finding detector for Shaferhund Phase 5 Wave A2.

Implements REQ-P0-P5-005: a small, fast, side-effect-free module that runs
every CloudTrail alert through a list of code-resident detector rules and
persists findings to cloud_audit_findings via the models layer.

Design decisions captured here:

@decision DEC-CLOUD-005
@title Detection rules are code-resident, not loaded from env or DB
@status accepted
@rationale Storing detection patterns in code (not .env, not a DB table, not a
           YAML file loaded at startup) means:
           1. A compromised environment cannot disable critical detections by
              unsetting env vars or truncating a config table.
           2. Every rule change goes through code review — the audit trail is
              the git log, not a DB mutation.
           3. The rule set is visible to any reader of this file without DB
              access — operators can reason about what fires without querying.
           Same rationale as DEC-RECOMMEND-002 (DESTRUCTIVE_TECHNIQUES frozenset)
           and DEC-RECOMMEND-005 (Phase 4 safety surfaces). Rules are a list of
           dicts (not a frozenset) because each rule carries a callable matcher
           and string templates — frozenset requires hashable members.

@decision DEC-CLOUD-007
@title evaluate_event is synchronous and called in-process after each alert insert
@status accepted
@rationale Cloud findings are deterministic (no LLM), cheap (dict key access +
           one DB INSERT), and benefit from running synchronously so a finding
           is visible by the time the cluster lands. A background task would add
           complexity without reducing latency — the caller already runs on the
           asyncio loop. See MASTER_PLAN.md Phase 5 Engineering Decision 11.

@decision DEC-CLOUD-008
@title Rule matchers are pure functions (event: dict) -> bool
@status accepted
@rationale Pure functions are trivially testable, composable, and have no
           hidden dependencies. Each rule's 'matches' key holds a lambda or
           named function. No shared state, no DB access inside matchers.
           evaluate_event() handles all DB writes after the match check.

Public API:
    RULES  — list of rule dicts (module-level constant, code-resident)
    evaluate_event(conn, alert_id, event) -> list[int]
"""

import json
import logging
import sqlite3
from typing import Optional

from .models import insert_cloud_finding

log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Helper: extract principal string from userIdentity
# ---------------------------------------------------------------------------


def _principal(event: dict) -> str:
    """Extract a human-readable principal from a CloudTrail userIdentity block.

    Tries userName, then arn, then type as fallbacks. Returns 'unknown' when
    the event has no userIdentity block at all.
    """
    uid = event.get("userIdentity") or {}
    return (
        uid.get("userName")
        or uid.get("arn")
        or uid.get("type", "unknown")
    )


def _src_ip(event: dict) -> str:
    """Return sourceIPAddress or 'unknown'."""
    return event.get("sourceIPAddress") or "unknown"


def _event_name(event: dict) -> str:
    return event.get("eventName", "")


def _event_source(event: dict) -> str:
    return event.get("eventSource", "")


def _req(event: dict) -> dict:
    """Return requestParameters dict, or {} when absent/null."""
    return event.get("requestParameters") or {}


# ---------------------------------------------------------------------------
# Code-resident rule list (DEC-CLOUD-005)
# ---------------------------------------------------------------------------
#
# Each rule is a dict with:
#   name            — machine-readable rule identifier (used as rule_name in DB)
#   severity        — one of 'Low', 'Medium', 'High', 'Critical'
#   title_template  — str.format_map()-compatible template for the finding title
#   description     — static description of why this matters
#   matches         — callable(event: dict) -> bool
#
# title_template keys: {src_ip}, {principal}, {event_name}, {event_source},
#                      {bucket_name}, {user_name}, {target_user}
# Extra keys are ignored by format_map (we use a defaultdict-style fallback).
#

class _SafeDict(dict):
    """dict subclass that returns '{key}' for missing keys in format_map.

    Prevents KeyError when a title_template references a field absent from
    the event (e.g. 'requestParameters.bucketName' on an IAM event).
    """
    def __missing__(self, key: str) -> str:
        return f"{{{key}}}"


def _make_title(template: str, event: dict) -> str:
    """Render a title_template with event-derived values, never raising KeyError."""
    ctx = _SafeDict(
        src_ip=_src_ip(event),
        principal=_principal(event),
        event_name=_event_name(event),
        event_source=_event_source(event),
        bucket_name=_req(event).get("bucketName", "unknown"),
        user_name=_req(event).get("userName", "unknown"),
        target_user=_req(event).get("userName", "unknown"),
    )
    return template.format_map(ctx)


RULES: list[dict] = [
    # ------------------------------------------------------------------
    # Rule 1: root_console_login (Critical)
    # Root user should never log in via the console directly.
    # AWS best practice: root account is for emergency break-glass only,
    # never daily use, and never console login.
    # ------------------------------------------------------------------
    {
        "name": "root_console_login",
        "severity": "Critical",
        "title_template": "Root user console login from {src_ip}",
        "description": (
            "The AWS root account logged in via the management console. "
            "Root account use is a high-severity event: the root user bypasses "
            "all IAM policies and has unrestricted access to every AWS resource. "
            "This should be investigated immediately. If the login was unexpected, "
            "rotate root credentials and enable MFA."
        ),
        "matches": lambda e: (
            e.get("eventName") == "ConsoleLogin"
            and (e.get("userIdentity") or {}).get("type") == "Root"
        ),
    },

    # ------------------------------------------------------------------
    # Rule 2: mfa_disabled_for_user (High)
    # Disabling MFA weakens authentication for the affected principal.
    # Common attacker tactic: disable MFA on a compromised account to
    # prevent the legitimate owner from regaining access easily.
    # ------------------------------------------------------------------
    {
        "name": "mfa_disabled_for_user",
        "severity": "High",
        "title_template": "MFA deactivated for {principal}",
        "description": (
            "Multi-factor authentication was deactivated for an IAM user. "
            "MFA disabling is a common post-compromise step — an attacker who "
            "gains API access to an account may disable MFA to lock the legitimate "
            "owner out of recovery paths. Verify whether this change was authorised "
            "and re-enable MFA immediately if not."
        ),
        "matches": lambda e: e.get("eventName") == "DeactivateMFADevice",
    },

    # ------------------------------------------------------------------
    # Rule 3: iam_user_created (Medium)
    # New IAM users created outside provisioning pipelines are a red flag.
    # Attackers persist in AWS accounts by creating backdoor IAM users.
    # ------------------------------------------------------------------
    {
        "name": "iam_user_created",
        "severity": "Medium",
        "title_template": "IAM user created: {user_name} by {principal}",
        "description": (
            "A new IAM user was created. Unexpected IAM user creation is a "
            "persistence tactic — attackers create backdoor accounts to maintain "
            "access after their initial entry vector is closed. Verify that the "
            "creating principal is an authorised provisioning pipeline or operator, "
            "and that the new user follows the least-privilege naming convention."
        ),
        "matches": lambda e: (
            e.get("eventName") == "CreateUser"
            and e.get("eventSource") == "iam.amazonaws.com"
        ),
    },

    # ------------------------------------------------------------------
    # Rule 4: s3_bucket_policy_changed (Medium)
    # Bucket policy changes can expose data publicly or grant cross-account
    # access — a common exfiltration setup.
    # ------------------------------------------------------------------
    {
        "name": "s3_bucket_policy_changed",
        "severity": "Medium",
        "title_template": "S3 bucket policy changed on {bucket_name}",
        "description": (
            "An S3 bucket policy was modified. Bucket policy changes can make "
            "data publicly accessible, grant access to external AWS accounts, or "
            "remove protective controls (e.g. denying non-encrypted uploads). "
            "Review the new policy to confirm it follows the principle of least "
            "privilege and does not introduce unintended public access."
        ),
        "matches": lambda e: (
            e.get("eventName") == "PutBucketPolicy"
            and e.get("eventSource") == "s3.amazonaws.com"
        ),
    },

    # ------------------------------------------------------------------
    # Rule 5: access_key_created (Medium)
    # Long-lived access keys are a persistent credential risk.
    # Attackers create access keys on compromised accounts to maintain
    # API-level access independently of console password rotation.
    # ------------------------------------------------------------------
    {
        "name": "access_key_created",
        "severity": "Medium",
        "title_template": "Access key created for {target_user}",
        "description": (
            "A new IAM access key was created. Long-lived access keys are a "
            "persistent credential risk: they do not expire automatically, are "
            "not subject to MFA, and are frequently leaked via code commits or "
            "misconfigured services. Attackers create access keys on compromised "
            "accounts to maintain API-level access even after console passwords "
            "are rotated. Verify that the key creation was intentional and that "
            "the key will be rotated per your organisation's policy."
        ),
        "matches": lambda e: (
            e.get("eventName") == "CreateAccessKey"
            and e.get("eventSource") == "iam.amazonaws.com"
        ),
    },
]

# Sanity check at import time: each rule has the required keys and a callable matcher.
# This is a development-time guard — it fires on import, not in tests.
_REQUIRED_RULE_KEYS = {"name", "severity", "title_template", "description", "matches"}
for _rule in RULES:
    _missing = _REQUIRED_RULE_KEYS - _rule.keys()
    if _missing:
        raise ValueError(
            f"cloud_findings rule {_rule.get('name', '?')} is missing keys: {_missing}"
        )
    if not callable(_rule["matches"]):
        raise ValueError(
            f"cloud_findings rule {_rule['name']}: 'matches' must be callable"
        )


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def evaluate_event(
    conn: sqlite3.Connection,
    alert_id: Optional[str],
    event: dict,
) -> list[int]:
    """Run every detector rule against a CloudTrail event dict.

    For each rule whose matches() returns True, inserts a row into
    cloud_audit_findings via insert_cloud_finding() and collects the
    resulting finding ID.

    This function is synchronous and side-effect-bearing (writes to DB).
    It is designed to be called immediately after insert_cloudtrail_alert()
    in the ingestion path (DEC-CLOUD-007).

    Args:
        conn:     Open SQLite connection (real connection, not a factory —
                  per DEC-SLO-004, isinstance checks are used by callers;
                  this function accepts a raw conn only).
        alert_id: The alert ID string returned by insert_cloudtrail_alert(),
                  or None for standalone evaluation (tests / re-processing).
        event:    A single CloudTrail event record dict (one element of
                  Records[]). Must contain at least 'eventName';
                  other fields are extracted with safe .get() fallbacks.

    Returns:
        List of integer finding IDs created during this call. Empty list
        when no rules match.
    """
    finding_ids: list[int] = []
    principal = _principal(event)
    src_ip = _src_ip(event)
    event_name = _event_name(event)
    event_source = _event_source(event)
    raw_event_json = json.dumps(event)

    for rule in RULES:
        try:
            matched = rule["matches"](event)
        except Exception as exc:  # noqa: BLE001
            log.warning(
                "cloud_findings: rule %s matcher raised %s — skipping",
                rule["name"], exc,
            )
            matched = False

        if not matched:
            continue

        title = _make_title(rule["title_template"], event)

        try:
            finding_id = insert_cloud_finding(
                conn=conn,
                alert_id=alert_id,
                rule_name=rule["name"],
                rule_severity=rule["severity"],
                title=title,
                description=rule["description"],
                principal=principal,
                src_ip=src_ip,
                event_name=event_name,
                event_source=event_source,
                raw_event=raw_event_json,
            )
            finding_ids.append(finding_id)
            log.debug(
                "cloud_findings: rule=%s alert_id=%s finding_id=%d",
                rule["name"], alert_id, finding_id,
            )
        except Exception as exc:  # noqa: BLE001
            log.error(
                "cloud_findings: failed to persist finding for rule %s: %s",
                rule["name"], exc, exc_info=True,
            )

    return finding_ids
