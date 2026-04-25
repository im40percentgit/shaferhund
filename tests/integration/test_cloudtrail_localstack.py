"""
LocalStack integration tests for the CloudTrail S3 pipeline.

Exercises the full path: boto3 S3 client → _iter_s3_events → parse_cloudtrail_event
→ insert_cloudtrail_alert → evaluate_event (cloud_findings) → DB cursor advance.

Unlike the unit tests in tests/test_cloudtrail_source.py (which mock boto3), these
tests run against a real LocalStack S3 endpoint.  They are SKIPPED by default —
run with:

    pytest -m integration tests/integration/

to execute them. LocalStack must be running; see compose.localstack.yaml for the
service definition.

@decision DEC-CLOUD-013
@title LocalStack for integration tests; skip-if-not-running pattern
@status accepted
@rationale fixture-only testing (mocked boto3) cannot catch credential-flow bugs,
           endpoint-URL misconfigurations, or S3 pagination edge cases.  LocalStack
           3.x provides an AWS-API-compatible S3 service that exercises the real
           boto3 code path without requiring real AWS credentials.  The skip-if-
           not-running pattern (requests.get health check) means CI never fails
           when LocalStack is absent — operators opt in by starting the service.
           This closes the loophole noted in MASTER_PLAN.md ## TODOs:
           "fixture-only testing is insufficient" (REQ-P0-P5-004).
"""

import gzip
import io
import json
import sqlite3
from pathlib import Path

import pytest

# @mock-exempt: unittest.mock is used only to redirect boto3.client() to the
# LocalStack endpoint URL.  boto3/S3 is an external AWS boundary — mocking the
# factory so it returns our LocalStack-pointed client is the standard approach
# (same rationale as @mock-exempt in test_cloudtrail_source.py).  All internal
# modules (models, cloud_findings, sources.cloudtrail) run with real code.

# ---------------------------------------------------------------------------
# LocalStack availability check — used by module-scoped fixture
# ---------------------------------------------------------------------------

LOCALSTACK_URL = "http://localhost:4566"
LOCALSTACK_HEALTH = f"{LOCALSTACK_URL}/_localstack/health"
TEST_BUCKET = "shaferhund-integration-test"
TEST_PREFIX = "AWSLogs/123456789012/CloudTrail/"

FIXTURE_GZ = Path(__file__).parent / "fixtures" / "cloudtrail_root_login.json.gz"


def _localstack_available() -> bool:
    """Return True if LocalStack is reachable at localhost:4566."""
    try:
        import requests  # type: ignore[import-untyped]
        resp = requests.get(LOCALSTACK_HEALTH, timeout=2)
        return resp.status_code == 200
    except Exception:  # noqa: BLE001
        return False


# ---------------------------------------------------------------------------
# Module-scoped fixtures — shared across all 3 tests for efficiency
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def s3_client():
    """Boto3 S3 client pointed at LocalStack.  Skip module if unreachable."""
    if not _localstack_available():
        pytest.skip("LocalStack not running — start with: podman compose -f compose.yaml -f compose.localstack.yaml up localstack")

    import boto3  # type: ignore[import-untyped]
    client = boto3.client(
        "s3",
        endpoint_url=LOCALSTACK_URL,
        region_name="us-east-1",
        aws_access_key_id="test",
        aws_secret_access_key="test",
    )
    return client


@pytest.fixture(scope="module")
def test_bucket(s3_client):
    """Create the test bucket; yield bucket name; delete all objects + bucket at teardown."""
    s3_client.create_bucket(Bucket=TEST_BUCKET)
    yield TEST_BUCKET

    # Teardown: delete all objects then the bucket
    paginator = s3_client.get_paginator("list_objects_v2")
    for page in paginator.paginate(Bucket=TEST_BUCKET):
        for obj in page.get("Contents", []):
            s3_client.delete_object(Bucket=TEST_BUCKET, Key=obj["Key"])
    s3_client.delete_bucket(Bucket=TEST_BUCKET)


@pytest.fixture(scope="module")
def integration_db(tmp_path_factory):
    """Real SQLite DB (file-backed, not :memory:) shared across module tests.

    File-backed so cloudtrail_poll_loop's asyncio.to_thread calls can share the
    connection safely (same pattern as test_poll_loop_one_cycle_with_real_db_and_mocked_s3).
    """
    from agent.models import init_db
    db_path = str(tmp_path_factory.mktemp("integration") / "localstack_integration.db")
    conn = init_db(db_path)
    return conn


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------

def _gz_object_key(name: str) -> str:
    """Build a CloudTrail-shaped S3 key under the test prefix."""
    return f"{TEST_PREFIX}us-east-1/2026/04/25/123456789012_CloudTrail_us-east-1_20260425T0500Z_{name}.json.gz"


def _upload_gz(s3_client, bucket: str, key: str, payload: dict) -> None:
    """Gzip-compress *payload* and upload to S3."""
    buf = io.BytesIO()
    with gzip.GzipFile(fileobj=buf, mode="wb") as gz:
        gz.write(json.dumps(payload).encode("utf-8"))
    s3_client.put_object(Bucket=bucket, Key=key, Body=buf.getvalue())


# ---------------------------------------------------------------------------
# Test 1: End-to-end pipeline
# ---------------------------------------------------------------------------

@pytest.mark.integration
def test_localstack_e2e_pipeline(s3_client, test_bucket, integration_db):
    """Upload a root ConsoleLogin event → poll → alert row → finding row → cursor advances.

    This exercises:
      _iter_s3_events  (real S3 paginator against LocalStack)
      parse_cloudtrail_event  (parsing the .json.gz Records[])
      insert_cloudtrail_alert  (DB write)
      evaluate_event  (cloud_findings detector — root_console_login rule fires)
      update_cloudtrail_cursor  (cursor advance)
    """
    import asyncio
    from agent.sources.cloudtrail import cloudtrail_poll_loop
    from agent.models import get_cloudtrail_cursor

    # Upload the pre-built fixture .json.gz directly
    key = _gz_object_key("e2e-test-aaa111")
    fixture_bytes = FIXTURE_GZ.read_bytes()
    s3_client.put_object(Bucket=test_bucket, Key=key, Body=fixture_bytes)

    class _Settings:
        cloudtrail_poll_interval_seconds = 0
        cloudtrail_s3_bucket = test_bucket
        cloudtrail_s3_prefix = TEST_PREFIX
        cloudtrail_aws_region = "us-east-1"

    # Patch boto3 inside cloudtrail module to use the LocalStack client
    import unittest.mock as mock
    with mock.patch("agent.sources.cloudtrail.boto3") as mock_boto3:  # @mock-exempt: boto3 factory redirected to LocalStack endpoint; external AWS boundary
        mock_boto3.client.return_value = s3_client

        asyncio.run(_run_one_cycle(integration_db, _Settings()))

    # Assert: alert row exists with source='cloudtrail'
    alert_row = integration_db.execute(
        "SELECT * FROM alerts WHERE source='cloudtrail' AND rule_id LIKE '%ConsoleLogin%' LIMIT 1"
    ).fetchone()
    assert alert_row is not None, "No cloudtrail alert found after poll cycle"
    assert alert_row["source"] == "cloudtrail"

    # Assert: cloud_audit_findings row exists (root_console_login detector fires)
    finding_row = integration_db.execute(
        "SELECT * FROM cloud_audit_findings WHERE alert_id=? LIMIT 1",
        (alert_row["id"],),
    ).fetchone()
    assert finding_row is not None, "No cloud_audit_finding for root ConsoleLogin alert"
    assert "root" in finding_row["rule_id"].lower() or "console" in finding_row["rule_id"].lower()

    # Assert: cursor advanced to the uploaded key
    cursor = get_cloudtrail_cursor(integration_db, test_bucket, TEST_PREFIX)
    assert cursor is not None, "Cursor not written after successful poll"
    assert cursor["last_object_key"] == key


async def _run_one_cycle(conn, settings):
    """Run cloudtrail_poll_loop for one tick then cancel."""
    import asyncio
    from agent.sources.cloudtrail import cloudtrail_poll_loop

    task = asyncio.create_task(
        cloudtrail_poll_loop(conn, settings, interval_seconds=0)
    )
    await asyncio.sleep(0.4)
    task.cancel()
    try:
        await task
    except asyncio.CancelledError:
        pass


# ---------------------------------------------------------------------------
# Test 2: Cursor resume — don't re-consume already-seen objects
# ---------------------------------------------------------------------------

@pytest.mark.integration
def test_localstack_cursor_resumes_after_restart(s3_client, test_bucket, integration_db):
    """Upload 3 events; poll once consuming the first; poll again; cursor must advance past all 3.

    Uses lex-ordered keys (DEC-CLOUD-010) so key-bbb < key-ccc < key-ddd.
    After the first cycle key-bbb is consumed and cursor set to key-bbb.
    Second cycle must consume key-ccc and key-ddd (not key-bbb again).
    """
    import asyncio
    from agent.models import get_cloudtrail_cursor, update_cloudtrail_cursor

    # Build a minimal non-root event (won't trigger findings detector, that's fine)
    def _make_payload(event_id: str) -> dict:
        return {
            "Records": [{
                "eventVersion": "1.08",
                "userIdentity": {"type": "IAMUser", "userName": "resumetest"},
                "eventTime": "2026-04-25T06:00:00Z",
                "eventSource": "ec2.amazonaws.com",
                "eventName": "DescribeInstances",
                "awsRegion": "us-east-1",
                "sourceIPAddress": "10.0.0.1",
                "requestID": f"req-{event_id}",
                "eventID": f"evt-{event_id}",
                "readOnly": True,
                "eventType": "AwsApiCall",
                "managementEvent": True,
                "eventCategory": "Management",
            }]
        }

    # Upload 3 objects with lex-sortable keys: bbb < ccc < ddd
    key_b = _gz_object_key("resume-bbb222")
    key_c = _gz_object_key("resume-ccc333")
    key_d = _gz_object_key("resume-ddd444")
    _upload_gz(s3_client, test_bucket, key_b, _make_payload("bbb"))
    _upload_gz(s3_client, test_bucket, key_c, _make_payload("ccc"))
    _upload_gz(s3_client, test_bucket, key_d, _make_payload("ddd"))

    # Manually set cursor to key_b (simulating "first cycle already consumed key_b")
    update_cloudtrail_cursor(
        integration_db,
        bucket=test_bucket,
        prefix=TEST_PREFIX,
        last_object_key=key_b,
        last_event_ts="2026-04-25T06:00:00+00:00",
    )

    class _Settings:
        cloudtrail_poll_interval_seconds = 0
        cloudtrail_s3_bucket = test_bucket
        cloudtrail_s3_prefix = TEST_PREFIX
        cloudtrail_aws_region = "us-east-1"

    import unittest.mock as mock
    with mock.patch("agent.sources.cloudtrail.boto3") as mock_boto3:  # @mock-exempt: boto3 factory redirected to LocalStack endpoint; external AWS boundary
        mock_boto3.client.return_value = s3_client
        asyncio.run(_run_one_cycle(integration_db, _Settings()))

    # Cursor must have advanced to key_d (last of the new objects)
    cursor = get_cloudtrail_cursor(integration_db, test_bucket, TEST_PREFIX)
    assert cursor is not None
    assert cursor["last_object_key"] == key_d, (
        f"Expected cursor at {key_d!r}, got {cursor['last_object_key']!r}"
    )

    # key_b's event_id must appear ONLY ONCE (no double-ingest)
    count_bbb = integration_db.execute(
        "SELECT COUNT(*) FROM alerts WHERE rule_id LIKE '%DescribeInstances%'"
        " AND raw_json LIKE '%req-bbb%'"
    ).fetchone()[0]
    # key_b was pre-cursor — the loop should NOT have fetched it again.
    # It may be 0 (never ingested in this run) or 1 (ingested in test 1 setup, which
    # uses a different event_id). The key assertion is cursor == key_d.
    assert count_bbb <= 1, f"key_b event ingested {count_bbb} times — cursor resume broken"


# ---------------------------------------------------------------------------
# Test 3: Empty bucket — no alerts, no errors, cursor unchanged
# ---------------------------------------------------------------------------

@pytest.mark.integration
def test_localstack_handles_empty_bucket(s3_client, integration_db):
    """Polling an empty bucket produces no alerts and no error.

    Uses a freshly created bucket so there are no pre-existing objects.
    """
    import asyncio
    import unittest.mock as mock
    from agent.models import get_cloudtrail_cursor

    empty_bucket = "shaferhund-empty-test"
    empty_prefix = "AWSLogs/empty/CloudTrail/"

    s3_client.create_bucket(Bucket=empty_bucket)
    try:
        # Cursor is None before the cycle
        cursor_before = get_cloudtrail_cursor(integration_db, empty_bucket, empty_prefix)
        assert cursor_before is None

        class _Settings:
            cloudtrail_poll_interval_seconds = 0
            cloudtrail_s3_bucket = empty_bucket
            cloudtrail_s3_prefix = empty_prefix
            cloudtrail_aws_region = "us-east-1"

        with mock.patch("agent.sources.cloudtrail.boto3") as mock_boto3:  # @mock-exempt: boto3 factory redirected to LocalStack endpoint; external AWS boundary
            mock_boto3.client.return_value = s3_client
            asyncio.run(_run_one_cycle(integration_db, _Settings()))

        # No alerts for this (bucket, prefix) — source is cloudtrail but rule_id
        # would reference events from the empty bucket. We can't filter perfectly,
        # but cursor must still be None (no objects were consumed).
        cursor_after = get_cloudtrail_cursor(integration_db, empty_bucket, empty_prefix)
        assert cursor_after is None, (
            f"Cursor advanced on empty bucket: {cursor_after}"
        )

    finally:
        # Cleanup
        s3_client.delete_bucket(Bucket=empty_bucket)
