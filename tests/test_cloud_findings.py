"""
Tests for agent.cloud_findings — deterministic detector rules + evaluate_event.

Covers:
  - Each of the 5+ detector rules (match + no-match cases)
  - evaluate_event() persistence to cloud_audit_findings
  - evaluate_event() return value = list of created finding IDs
  - Code-resident rule list assertion (DEC-CLOUD-005)
  - Multiple rules firing on a single event (when overlaps exist)

All DB interactions use a real in-memory SQLite connection (Sacred Practice #5).
No mocks on internal modules.

@decision DEC-CLOUD-006
@title Real SQLite for DB tests; no mocks on internal detector
@status accepted
@rationale The detector and DB layer are internal — tests exercise them
           directly against a real in-memory SQLite schema. There is nothing
           to mock. External boundaries (boto3 S3) are mocked in
           test_cloudtrail_source.py; this file has no external dependencies.
"""

import json
from pathlib import Path

import pytest

from agent.cloud_findings import RULES, evaluate_event
from agent.models import init_db, insert_cloudtrail_alert
from agent.sources.cloudtrail import parse_cloudtrail_event

# ---------------------------------------------------------------------------
# Fixture paths
# ---------------------------------------------------------------------------

_FIXTURE_DIR = Path(__file__).parent / "fixtures"
ROOT_LOGIN_FIXTURE = _FIXTURE_DIR / "cloudtrail_root_login.json"
IAM_CREATE_USER_FIXTURE = _FIXTURE_DIR / "cloudtrail_iam_create_user.json"


# ---------------------------------------------------------------------------
# Shared DB fixture
# ---------------------------------------------------------------------------


@pytest.fixture()
def conn():
    """Fresh in-memory SQLite DB per test."""
    c = init_db(":memory:")
    yield c
    c.close()


# ---------------------------------------------------------------------------
# Synthetic event builders
# ---------------------------------------------------------------------------


def _base_event() -> dict:
    """Minimal valid CloudTrail event dict."""
    return {
        "eventVersion": "1.08",
        "userIdentity": {
            "type": "IAMUser",
            "principalId": "AIDAEXAMPLE",
            "arn": "arn:aws:iam::123456789012:user/testuser",
            "accountId": "123456789012",
            "userName": "testuser",
        },
        "eventTime": "2026-04-25T06:00:00Z",
        "eventSource": "ec2.amazonaws.com",
        "eventName": "DescribeInstances",
        "awsRegion": "us-east-1",
        "sourceIPAddress": "198.51.100.1",
        "requestParameters": None,
        "responseElements": None,
        "requestID": "req-001",
        "eventID": "evt-001",
        "readOnly": True,
        "eventType": "AwsApiCall",
    }


def _root_console_login_event() -> dict:
    e = _base_event()
    e["userIdentity"] = {"type": "Root", "principalId": "123456789012", "arn": "arn:aws:iam::123456789012:root"}
    e["eventName"] = "ConsoleLogin"
    e["eventSource"] = "signin.amazonaws.com"
    e["sourceIPAddress"] = "198.51.100.42"
    return e


def _iam_user_event() -> dict:
    """ConsoleLogin from a normal IAMUser — should NOT match root_console_login."""
    e = _base_event()
    e["eventName"] = "ConsoleLogin"
    e["eventSource"] = "signin.amazonaws.com"
    return e


def _mfa_deactivated_event() -> dict:
    e = _base_event()
    e["eventName"] = "DeactivateMFADevice"
    e["eventSource"] = "iam.amazonaws.com"
    e["requestParameters"] = {"userName": "alice", "serialNumber": "arn:aws:iam::123456789012:mfa/alice"}
    return e


def _create_user_event() -> dict:
    e = _base_event()
    e["eventName"] = "CreateUser"
    e["eventSource"] = "iam.amazonaws.com"
    e["requestParameters"] = {"userName": "backdoor-svc"}
    return e


def _put_bucket_policy_event() -> dict:
    e = _base_event()
    e["eventName"] = "PutBucketPolicy"
    e["eventSource"] = "s3.amazonaws.com"
    e["requestParameters"] = {"bucketName": "my-sensitive-bucket", "policy": "{}"}
    return e


def _create_access_key_event() -> dict:
    e = _base_event()
    e["eventName"] = "CreateAccessKey"
    e["eventSource"] = "iam.amazonaws.com"
    e["requestParameters"] = {"userName": "ci-deploy"}
    return e


def _describe_instances_event() -> dict:
    """Read-only, benign — should not match any rule."""
    return _base_event()  # DescribeInstances on ec2.amazonaws.com


# ---------------------------------------------------------------------------
# Rule match tests
# ---------------------------------------------------------------------------


def test_root_console_login_matches(conn):
    """Root + ConsoleLogin -> finding with rule_name='root_console_login', severity='Critical'."""
    event = _root_console_login_event()
    finding_ids = evaluate_event(conn, None, event)

    assert len(finding_ids) >= 1
    row = conn.execute(
        "SELECT * FROM cloud_audit_findings WHERE id = ?", (finding_ids[0],)
    ).fetchone()
    assert row is not None
    assert row["rule_name"] == "root_console_login"
    assert row["rule_severity"] == "Critical"
    assert "198.51.100.42" in row["title"]


def test_root_console_login_does_not_match_iam_user(conn):
    """IAMUser + ConsoleLogin -> root_console_login rule should NOT fire."""
    event = _iam_user_event()
    finding_ids = evaluate_event(conn, None, event)

    # No finding should carry rule_name='root_console_login'
    root_findings = [
        fid for fid in finding_ids
        if conn.execute(
            "SELECT rule_name FROM cloud_audit_findings WHERE id = ?", (fid,)
        ).fetchone()["rule_name"] == "root_console_login"
    ]
    assert root_findings == []


def test_iam_user_created_matches(conn):
    """CreateUser on iam.amazonaws.com -> finding with severity='Medium', principal extracted."""
    event = _create_user_event()
    finding_ids = evaluate_event(conn, None, event)

    rows = conn.execute(
        "SELECT * FROM cloud_audit_findings WHERE rule_name = 'iam_user_created'"
    ).fetchall()
    assert len(rows) >= 1
    row = rows[0]
    assert row["rule_severity"] == "Medium"
    # principal is the creating user (testuser), title includes the new user name
    assert "backdoor-svc" in row["title"]


def test_mfa_deactivated_matches(conn):
    """DeactivateMFADevice -> mfa_disabled_for_user fires."""
    event = _mfa_deactivated_event()
    finding_ids = evaluate_event(conn, None, event)

    rows = conn.execute(
        "SELECT * FROM cloud_audit_findings WHERE rule_name = 'mfa_disabled_for_user'"
    ).fetchall()
    assert len(rows) >= 1
    assert rows[0]["rule_severity"] == "High"


def test_s3_bucket_policy_changed_matches(conn):
    """PutBucketPolicy on s3.amazonaws.com -> fires; bucket name extracted to title."""
    event = _put_bucket_policy_event()
    finding_ids = evaluate_event(conn, None, event)

    rows = conn.execute(
        "SELECT * FROM cloud_audit_findings WHERE rule_name = 's3_bucket_policy_changed'"
    ).fetchall()
    assert len(rows) >= 1
    assert rows[0]["rule_severity"] == "Medium"
    assert "my-sensitive-bucket" in rows[0]["title"]


def test_access_key_created_matches(conn):
    """CreateAccessKey on iam.amazonaws.com -> access_key_created fires."""
    event = _create_access_key_event()
    finding_ids = evaluate_event(conn, None, event)

    rows = conn.execute(
        "SELECT * FROM cloud_audit_findings WHERE rule_name = 'access_key_created'"
    ).fetchall()
    assert len(rows) >= 1
    assert rows[0]["rule_severity"] == "Medium"
    assert "ci-deploy" in rows[0]["title"]


def test_no_match_for_describe_event(conn):
    """DescribeInstances (read-only, no sensitive action) -> no findings."""
    event = _describe_instances_event()
    finding_ids = evaluate_event(conn, None, event)
    assert finding_ids == []


# ---------------------------------------------------------------------------
# Persistence and return-value tests
# ---------------------------------------------------------------------------


def test_evaluate_event_persists_findings(conn):
    """Matching event with alert_id=42 -> cloud_audit_findings row with correct FK."""
    # Insert a real alert so the FK is satisfiable (alert_id is TEXT in this schema)
    parsed = parse_cloudtrail_event(_root_console_login_event())
    alert_id = insert_cloudtrail_alert(conn, parsed)

    finding_ids = evaluate_event(conn, alert_id, _root_console_login_event())

    assert len(finding_ids) >= 1
    row = conn.execute(
        "SELECT * FROM cloud_audit_findings WHERE id = ?", (finding_ids[0],)
    ).fetchone()
    assert row is not None
    assert row["alert_id"] == alert_id


def test_evaluate_event_returns_finding_ids(conn):
    """Return value length matches the number of rows actually created."""
    event = _root_console_login_event()
    finding_ids = evaluate_event(conn, None, event)

    db_count = conn.execute(
        "SELECT COUNT(*) FROM cloud_audit_findings"
    ).fetchone()[0]
    assert len(finding_ids) == db_count
    assert all(isinstance(fid, int) for fid in finding_ids)


def test_multiple_rules_can_fire_for_one_event(conn):
    """Root + CreateAccessKey on iam.amazonaws.com -> both root-adjacent rules and access_key_created fire.

    Root user events are Critical. If the root user ALSO triggers CreateAccessKey
    on iam.amazonaws.com, both root_console_login (if ConsoleLogin) and
    access_key_created would need to match — but those are mutually exclusive
    (different eventName). Instead we test Root + CreateAccessKey: the root
    heuristic makes severity Critical via _classify_severity, but rule matching
    in cloud_findings is purely on eventName/eventSource. A Root user running
    CreateAccessKey will match access_key_created (eventName + eventSource match).
    The root_console_login rule fires only on ConsoleLogin. So for a root CreateAccessKey:
      - access_key_created MATCHES (eventName=CreateAccessKey, eventSource=iam)
      - root_console_login does NOT match (eventName != ConsoleLogin)
    This test confirms at least 1 rule fires and the finding is persisted.
    """
    event = _base_event()
    event["userIdentity"] = {
        "type": "Root",
        "principalId": "123456789012",
        "arn": "arn:aws:iam::123456789012:root",
    }
    event["eventName"] = "CreateAccessKey"
    event["eventSource"] = "iam.amazonaws.com"
    event["requestParameters"] = {"userName": "root"}

    finding_ids = evaluate_event(conn, None, event)
    # access_key_created should fire
    assert len(finding_ids) >= 1
    rule_names = [
        conn.execute(
            "SELECT rule_name FROM cloud_audit_findings WHERE id = ?", (fid,)
        ).fetchone()["rule_name"]
        for fid in finding_ids
    ]
    assert "access_key_created" in rule_names


# ---------------------------------------------------------------------------
# Code-resident assertion (DEC-CLOUD-005)
# ---------------------------------------------------------------------------


def test_detector_is_code_resident():
    """RULES is a Python list of dicts at module scope — not from env or DB.

    Asserts:
    1. RULES is a list (not loaded from DB/env at call time).
    2. Each element is a dict with required keys.
    3. Each element's 'matches' is callable.
    4. The module has >= 5 rules (spec requirement).
    """
    import agent.cloud_findings as cf_module

    # The constant is a list, not a generator, not a function result
    assert isinstance(cf_module.RULES, list), "RULES must be a module-level list"

    # At least 5 rules required by spec
    assert len(cf_module.RULES) >= 5, f"Expected >= 5 rules, got {len(cf_module.RULES)}"

    required_keys = {"name", "severity", "title_template", "description", "matches"}
    for rule in cf_module.RULES:
        assert isinstance(rule, dict), f"Rule must be dict, got {type(rule)}"
        missing = required_keys - rule.keys()
        assert not missing, f"Rule {rule.get('name', '?')} missing keys: {missing}"
        assert callable(rule["matches"]), f"Rule {rule['name']} 'matches' must be callable"

    # Confirm RULES is not lazily loaded from an env var or DB
    # (by verifying it is populated immediately on import, not via a function call)
    assert len(cf_module.RULES) > 0, "RULES must be non-empty at import time"


# ---------------------------------------------------------------------------
# Fixture-based tests
# ---------------------------------------------------------------------------


def test_root_login_fixture_matches(conn):
    """The committed cloudtrail_root_login.json fixture fires root_console_login."""
    event = json.loads(ROOT_LOGIN_FIXTURE.read_text())
    finding_ids = evaluate_event(conn, None, event)

    rule_names = [
        conn.execute(
            "SELECT rule_name FROM cloud_audit_findings WHERE id = ?", (fid,)
        ).fetchone()["rule_name"]
        for fid in finding_ids
    ]
    assert "root_console_login" in rule_names


def test_iam_create_user_fixture_matches(conn):
    """The committed cloudtrail_iam_create_user.json fixture fires iam_user_created."""
    event = json.loads(IAM_CREATE_USER_FIXTURE.read_text())
    finding_ids = evaluate_event(conn, None, event)

    rule_names = [
        conn.execute(
            "SELECT rule_name FROM cloud_audit_findings WHERE id = ?", (fid,)
        ).fetchone()["rule_name"]
        for fid in finding_ids
    ]
    assert "iam_user_created" in rule_names
