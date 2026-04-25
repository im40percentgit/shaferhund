"""
Tests for agent.sources.cloudtrail — CloudTrail S3 poller and event parser.

Covers:
  - parse_cloudtrail_event() output shape matches shared alert dict
  - _classify_severity() heuristic rules (root, IAM, S3 policy, console, default)
  - _iter_s3_events() S3 cursor logic and gzip decompression
  - cloudtrail_progress CRUD (get/update cursor, uniqueness per bucket+prefix)
  - insert_cloudtrail_alert() round-trip and dedup
  - cloudtrail_poll_loop() error resilience

All S3 interactions use a mock boto3 client — no real AWS calls.
DB interactions use a real in-memory SQLite connection (Sacred Practice #5).

@decision DEC-CLOUD-006
@title moto/mock for S3 unit tests; real SQLite for DB tests
@status accepted
@rationale boto3 S3 calls are an external boundary — mocking is appropriate
           and matches Sacred Practice #5 (mock only external boundaries).
           The DB layer is internal — tests use a real in-memory SQLite
           connection initialised by init_db, exercising the full schema
           path including the cloudtrail_progress table migration.
"""

import gzip
import io
import json
import sqlite3
from pathlib import Path
from typing import Optional
from unittest.mock import MagicMock, patch  # @mock-exempt: boto3 S3 is an external AWS boundary

import pytest

from agent.sources.cloudtrail import (
    _classify_severity,
    _iter_s3_events,
    parse_cloudtrail_event,
)
from agent.models import (
    get_cloudtrail_cursor,
    insert_cloudtrail_alert,
    init_db,
    update_cloudtrail_cursor,
)

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

FIXTURE_PATH = Path(__file__).parent / "fixtures" / "cloudtrail_sample_event.json"


def load_fixture_event() -> dict:
    """Load the canonical CloudTrail fixture event."""
    return json.loads(FIXTURE_PATH.read_text(encoding="utf-8"))


def _make_root_event() -> dict:
    """CloudTrail event with Root userIdentity."""
    evt = load_fixture_event()
    evt["userIdentity"] = {"type": "Root", "principalId": "123456789012"}
    evt["eventName"] = "CreateAccessKey"
    evt["eventSource"] = "iam.amazonaws.com"
    return evt


def _make_iam_mutation_event() -> dict:
    """CloudTrail event: IAM CreateRole — triggers High severity."""
    evt = load_fixture_event()
    evt["userIdentity"] = {"type": "IAMUser", "userName": "alice"}
    evt["eventName"] = "CreateRole"
    evt["eventSource"] = "iam.amazonaws.com"
    return evt


def _make_console_login_event() -> dict:
    """CloudTrail ConsoleLogin event — triggers Medium severity."""
    evt = load_fixture_event()
    evt["eventName"] = "ConsoleLogin"
    evt["eventSource"] = "signin.amazonaws.com"
    return evt


def _make_s3_bucket_policy_event() -> dict:
    """CloudTrail PutBucketPolicy event — triggers Medium-High severity."""
    evt = load_fixture_event()
    evt["eventName"] = "PutBucketPolicy"
    evt["eventSource"] = "s3.amazonaws.com"
    return evt


@pytest.fixture
def mem_db() -> sqlite3.Connection:
    """Return an in-memory SQLite connection with full Phase 5 schema applied."""
    conn = init_db(":memory:")
    yield conn
    conn.close()


def _make_gz_object(events: list[dict]) -> bytes:
    """Return a gzip-compressed CloudTrail JSON blob for the given events."""
    payload = json.dumps({"Records": events}).encode("utf-8")
    buf = io.BytesIO()
    with gzip.GzipFile(fileobj=buf, mode="wb") as gz:
        gz.write(payload)
    return buf.getvalue()


def _make_mock_s3(objects: list[tuple[str, bytes]]) -> MagicMock:
    """Build a mock boto3 S3 client.

    Args:
        objects: List of (key, gzip_bytes) pairs to return from list_objects_v2.

    Returns:
        MagicMock with get_paginator() and get_object() wired up.
    """
    s3 = MagicMock()
    contents = [{"Key": key} for key, _ in objects]
    page = {"Contents": contents}
    paginator = MagicMock()
    paginator.paginate.return_value = [page]
    s3.get_paginator.return_value = paginator

    key_to_bytes = {key: data for key, data in objects}

    def get_object(Bucket, Key):  # noqa: N803
        return {"Body": MagicMock(read=lambda: key_to_bytes[Key])}

    s3.get_object.side_effect = get_object
    return s3


# ---------------------------------------------------------------------------
# parse_cloudtrail_event — shared alert shape
# ---------------------------------------------------------------------------

def test_parse_cloudtrail_event_normalizes_to_alert_shape():
    """Fixture DescribeInstances event → all required alert fields present."""
    evt = load_fixture_event()
    result = parse_cloudtrail_event(evt)

    assert result["source"] == "cloudtrail"
    assert result["src_ip"] == "198.51.100.42"
    assert result["dest_ip"] is None
    assert result["protocol"] == "https"
    assert result["rule_id"] == "cloudtrail:ec2.amazonaws.com:DescribeInstances"
    assert "rule_description" in result
    assert "normalized_severity" in result
    assert isinstance(result["severity"], int)
    assert "timestamp" in result
    # timestamp must be a parseable ISO string with UTC offset
    assert "2026-04-24" in result["timestamp"]
    # raw_json must be the full event JSON
    raw = json.loads(result["raw_json"])
    assert raw["eventID"] == evt["eventID"]


def test_parse_cloudtrail_event_source_is_cloudtrail():
    """source field is always 'cloudtrail' regardless of eventSource."""
    for event_source in ["iam.amazonaws.com", "s3.amazonaws.com", "ec2.amazonaws.com"]:
        evt = load_fixture_event()
        evt["eventSource"] = event_source
        result = parse_cloudtrail_event(evt)
        assert result["source"] == "cloudtrail"


def test_parse_cloudtrail_event_rule_id_format():
    """rule_id is 'cloudtrail:{eventSource}:{eventName}'."""
    evt = load_fixture_event()
    evt["eventSource"] = "iam.amazonaws.com"
    evt["eventName"] = "CreateRole"
    result = parse_cloudtrail_event(evt)
    assert result["rule_id"] == "cloudtrail:iam.amazonaws.com:CreateRole"


def test_parse_cloudtrail_event_missing_timestamp_uses_now():
    """Missing eventTime doesn't raise — timestamp defaults to now()."""
    evt = load_fixture_event()
    del evt["eventTime"]
    result = parse_cloudtrail_event(evt)
    # Must still return a parseable timestamp
    assert "T" in result["timestamp"]


# ---------------------------------------------------------------------------
# _classify_severity — heuristic rules
# ---------------------------------------------------------------------------

def test_classify_severity_root_user():
    """Root user activity → 12 (Critical)."""
    assert _classify_severity(_make_root_event()) == 12


def test_classify_severity_iam_mutation_create():
    """IAM CreateRole → 10 (High)."""
    evt = _make_iam_mutation_event()
    evt["eventName"] = "CreateRole"
    assert _classify_severity(evt) == 10


def test_classify_severity_iam_mutation_delete():
    """IAM DeleteUser → 10 (High)."""
    evt = load_fixture_event()
    evt["userIdentity"] = {"type": "IAMUser", "userName": "alice"}
    evt["eventSource"] = "iam.amazonaws.com"
    evt["eventName"] = "DeleteUser"
    assert _classify_severity(evt) == 10


def test_classify_severity_iam_mutation_put_policy():
    """IAM PutRolePolicy → 10 (High)."""
    evt = load_fixture_event()
    evt["userIdentity"] = {"type": "IAMUser", "userName": "alice"}
    evt["eventSource"] = "iam.amazonaws.com"
    evt["eventName"] = "PutRolePolicy"
    assert _classify_severity(evt) == 10


def test_classify_severity_s3_bucket_policy():
    """S3 PutBucketPolicy → 9 (Medium-High)."""
    assert _classify_severity(_make_s3_bucket_policy_event()) == 9


def test_classify_severity_console_login():
    """ConsoleLogin → 8 (Medium)."""
    assert _classify_severity(_make_console_login_event()) == 8


def test_classify_severity_default_low():
    """Read-only DescribeInstances → 5 (Low)."""
    evt = load_fixture_event()
    # Fixture is DescribeInstances on ec2.amazonaws.com — default bucket
    assert _classify_severity(evt) == 5


def test_classify_severity_root_beats_iam():
    """Root user doing IAM mutation → 12 (root rule wins, not IAM rule)."""
    evt = _make_root_event()
    evt["eventSource"] = "iam.amazonaws.com"
    evt["eventName"] = "CreateRole"
    # Root rule is priority 1 → 12
    assert _classify_severity(evt) == 12


# ---------------------------------------------------------------------------
# _iter_s3_events — S3 cursor + gzip decompression
# ---------------------------------------------------------------------------

def test_iter_s3_events_yields_events_from_gzipped_json():
    """Single .json.gz object with 2 events → 2 (key, event) tuples yielded."""
    evt = load_fixture_event()
    gz_data = _make_gz_object([evt, evt])
    key = "AWSLogs/123/CloudTrail/us-east-1/2026/04/24/123_CloudTrail_us-east-1_20260424T1200Z_abc.json.gz"
    s3 = _make_mock_s3([(key, gz_data)])

    results = list(_iter_s3_events(s3, "my-bucket", "AWSLogs/", None))

    assert len(results) == 2
    for obj_key, event_dict in results:
        assert obj_key == key
        assert event_dict["eventName"] == "DescribeInstances"


def test_iter_s3_events_uses_cursor_as_start_after():
    """Cursor is passed as StartAfter to list_objects_v2."""
    s3 = _make_mock_s3([])
    cursor = "AWSLogs/123/CloudTrail/us-east-1/2026/04/23/last-seen.json.gz"

    list(_iter_s3_events(s3, "my-bucket", "AWSLogs/", cursor))

    paginator = s3.get_paginator.return_value
    call_kwargs = paginator.paginate.call_args[1]
    assert call_kwargs["StartAfter"] == cursor


def test_iter_s3_events_no_cursor_omits_start_after():
    """When cursor is None, StartAfter is not passed to paginate."""
    s3 = _make_mock_s3([])

    list(_iter_s3_events(s3, "my-bucket", "AWSLogs/", None))

    paginator = s3.get_paginator.return_value
    call_kwargs = paginator.paginate.call_args[1]
    assert "StartAfter" not in call_kwargs


def test_iter_s3_events_skips_non_gz_objects():
    """Objects without .json.gz suffix are skipped silently."""
    digest_key = "AWSLogs/123/CloudTrail-Digest/us-east-1/2026/04/24/digest.json"
    gz_key = "AWSLogs/123/CloudTrail/us-east-1/2026/04/24/real.json.gz"
    evt = load_fixture_event()
    gz_data = _make_gz_object([evt])

    # Only the gz object has data; digest_key would blow up if fetched
    s3 = MagicMock()
    paginator = MagicMock()
    paginator.paginate.return_value = [
        {"Contents": [{"Key": digest_key}, {"Key": gz_key}]}
    ]
    s3.get_paginator.return_value = paginator
    s3.get_object.return_value = {"Body": MagicMock(read=lambda: gz_data)}

    results = list(_iter_s3_events(s3, "my-bucket", "AWSLogs/", None))

    # Only gz_key events are yielded; digest_key is skipped before get_object
    assert len(results) == 1
    assert results[0][0] == gz_key
    # get_object should only have been called once (for gz_key)
    assert s3.get_object.call_count == 1


def test_iter_s3_events_handles_aws_error_gracefully():
    """S3 get_object failure → warning logged, iteration continues."""
    good_key = "AWSLogs/123/CloudTrail/us-east-1/2026/04/24/good.json.gz"
    bad_key = "AWSLogs/123/CloudTrail/us-east-1/2026/04/24/bad.json.gz"
    evt = load_fixture_event()
    gz_data = _make_gz_object([evt])

    s3 = MagicMock()
    paginator = MagicMock()
    paginator.paginate.return_value = [
        {"Contents": [{"Key": bad_key}, {"Key": good_key}]}
    ]
    s3.get_paginator.return_value = paginator

    call_count = [0]

    def get_object(Bucket, Key):  # noqa: N803
        call_count[0] += 1
        if Key == bad_key:
            raise RuntimeError("S3 access denied")
        return {"Body": MagicMock(read=lambda: gz_data)}

    s3.get_object.side_effect = get_object

    # Must not raise — bad_key is skipped, good_key is yielded
    results = list(_iter_s3_events(s3, "my-bucket", "AWSLogs/", None))
    assert len(results) == 1
    assert results[0][0] == good_key


# ---------------------------------------------------------------------------
# cloudtrail_progress CRUD — cursor persistence
# ---------------------------------------------------------------------------

def test_cursor_initially_none(mem_db):
    """Before any update, get_cloudtrail_cursor returns None."""
    result = get_cloudtrail_cursor(mem_db, "my-bucket", "AWSLogs/")
    assert result is None


def test_cursor_persistence_round_trip(mem_db):
    """update then get returns the written values."""
    update_cloudtrail_cursor(
        mem_db,
        bucket="my-bucket",
        prefix="AWSLogs/123/",
        last_object_key="AWSLogs/123/CloudTrail/us-east-1/2026/04/24/foo.json.gz",
        last_event_ts="2026-04-24T12:34:56+00:00",
    )
    row = get_cloudtrail_cursor(mem_db, "my-bucket", "AWSLogs/123/")
    assert row is not None
    assert row["last_object_key"] == "AWSLogs/123/CloudTrail/us-east-1/2026/04/24/foo.json.gz"
    assert row["last_event_ts"] == "2026-04-24T12:34:56+00:00"
    assert row["bucket"] == "my-bucket"
    assert row["prefix"] == "AWSLogs/123/"


def test_cursor_upsert_advances_key(mem_db):
    """Second update overwrites last_object_key — no duplicate rows."""
    update_cloudtrail_cursor(mem_db, "b", "p/", "key-1.json.gz", "2026-04-24T10:00:00+00:00")
    update_cloudtrail_cursor(mem_db, "b", "p/", "key-2.json.gz", "2026-04-24T11:00:00+00:00")

    row = get_cloudtrail_cursor(mem_db, "b", "p/")
    assert row["last_object_key"] == "key-2.json.gz"

    # Exactly one row for this (bucket, prefix)
    count = mem_db.execute(
        "SELECT COUNT(*) FROM cloudtrail_progress WHERE bucket='b' AND prefix='p/'"
    ).fetchone()[0]
    assert count == 1


def test_cursor_is_unique_per_bucket_prefix(mem_db):
    """Two different (bucket, prefix) pairs yield independent cursor rows."""
    update_cloudtrail_cursor(mem_db, "bucket-a", "prefix-a/", "key-a.json.gz", None)
    update_cloudtrail_cursor(mem_db, "bucket-b", "prefix-b/", "key-b.json.gz", None)

    row_a = get_cloudtrail_cursor(mem_db, "bucket-a", "prefix-a/")
    row_b = get_cloudtrail_cursor(mem_db, "bucket-b", "prefix-b/")

    assert row_a is not None
    assert row_b is not None
    assert row_a["last_object_key"] == "key-a.json.gz"
    assert row_b["last_object_key"] == "key-b.json.gz"
    # Different rows — different IDs
    assert row_a["id"] != row_b["id"]


# ---------------------------------------------------------------------------
# insert_cloudtrail_alert — DB persistence + dedup
# ---------------------------------------------------------------------------

def test_insert_cloudtrail_alert_writes_to_alerts_table(mem_db):
    """Parsed CloudTrail event writes a row to alerts with source='cloudtrail'."""
    evt = load_fixture_event()
    parsed = parse_cloudtrail_event(evt)
    alert_id = insert_cloudtrail_alert(mem_db, parsed)

    row = mem_db.execute(
        "SELECT * FROM alerts WHERE id = ?", (alert_id,)
    ).fetchone()
    assert row is not None
    assert row["source"] == "cloudtrail"
    assert row["src_ip"] == "198.51.100.42"
    assert row["severity"] == 5  # DescribeInstances → default Low


def test_insert_cloudtrail_alert_deduplicates(mem_db):
    """Inserting the same event twice produces exactly one alerts row."""
    evt = load_fixture_event()
    parsed = parse_cloudtrail_event(evt)
    id1 = insert_cloudtrail_alert(mem_db, parsed)
    id2 = insert_cloudtrail_alert(mem_db, parsed)

    assert id1 == id2
    count = mem_db.execute(
        "SELECT COUNT(*) FROM alerts WHERE id = ?", (id1,)
    ).fetchone()[0]
    assert count == 1


def test_insert_cloudtrail_alert_writes_raw_json(mem_db):
    """alert_details row contains the full event JSON."""
    evt = load_fixture_event()
    parsed = parse_cloudtrail_event(evt)
    alert_id = insert_cloudtrail_alert(mem_db, parsed)

    detail = mem_db.execute(
        "SELECT raw_json FROM alert_details WHERE alert_id = ?", (alert_id,)
    ).fetchone()
    assert detail is not None
    raw = json.loads(detail["raw_json"])
    assert raw["eventID"] == evt["eventID"]


# ---------------------------------------------------------------------------
# cloudtrail_poll_loop — error resilience
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_poll_loop_handles_aws_error_gracefully(mem_db):
    """Loop logs warning and continues when boto3 raises — no crash."""
    import asyncio
    from agent.sources.cloudtrail import cloudtrail_poll_loop

    class _FakeSettings:
        cloudtrail_poll_interval_seconds = 0  # immediate tick
        cloudtrail_s3_bucket = "test-bucket"
        cloudtrail_s3_prefix = "AWSLogs/"
        cloudtrail_aws_region = "us-east-1"

    call_count = [0]

    def _boom(*args, **kwargs):
        raise RuntimeError("No AWS credentials")

    # Patch boto3.client inside cloudtrail module to raise on use
    with patch("agent.sources.cloudtrail.boto3") as mock_boto3:
        mock_boto3.client.side_effect = _boom

        # Run the loop for one iteration then cancel
        task = asyncio.create_task(
            cloudtrail_poll_loop(mem_db, _FakeSettings(), interval_seconds=0)
        )
        await asyncio.sleep(0.05)
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass

    # If we reach here without exception the loop handled the error gracefully
    assert True


# ---------------------------------------------------------------------------
# Regression: broken relative import in cloudtrail_poll_loop
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_poll_loop_one_cycle_with_real_db_and_mocked_s3(tmp_path):
    """Regression for the broken single-dot relative import in cloudtrail_poll_loop.

    Prior to fix, 'from .models import ...' inside the loop body resolved to
    agent.sources.models (does not exist). The ModuleNotFoundError was caught by
    the broad except and silently swallowed every cycle, leaving the feature
    inert at runtime despite all unit tests passing (boto3 mocking sidestepped
    the broken path).

    This test runs ONE poll cycle with a real in-process SQLite connection
    (Sacred Practice #5) + a mocked S3 client that returns one .json.gz
    containing one event, then asserts both the alert row and the cursor row
    landed in the DB. It would have FAILED on the buggy code.

    Same lesson as DEC-SLO-004 (#44): unit tests miss integration bugs when
    they mock too much.
    """
    import asyncio
    from agent.models import init_db
    from agent.sources.cloudtrail import cloudtrail_poll_loop

    # Real SQLite DB backed by a tmp file (not :memory: so conn is shareable
    # across threads used by asyncio.to_thread inside the poll loop).
    db_path = str(tmp_path / "regression.db")
    conn = init_db(db_path)

    # Build one fake CloudTrail event matching the fixture shape
    fake_event = {
        "eventID": "regression-test-event-id-001",
        "eventName": "DescribeInstances",
        "eventSource": "ec2.amazonaws.com",
        "eventTime": "2026-04-25T10:00:00Z",
        "userIdentity": {"type": "IAMUser", "userName": "alice"},
        "sourceIPAddress": "203.0.113.10",
        "awsRegion": "us-east-1",
    }
    gz_bytes = _make_gz_object([fake_event])
    obj_key = "AWSLogs/123/CloudTrail/us-east-1/2026/04/25/file.json.gz"

    class _Settings:
        cloudtrail_poll_interval_seconds = 0
        cloudtrail_s3_bucket = "fake-bucket"
        cloudtrail_s3_prefix = "AWSLogs/123/CloudTrail/"
        cloudtrail_aws_region = "us-east-1"

    with patch("agent.sources.cloudtrail.boto3") as mock_boto3:
        mock_s3 = _make_mock_s3([(obj_key, gz_bytes)])
        mock_boto3.client.return_value = mock_s3

        task = asyncio.create_task(
            cloudtrail_poll_loop(conn, _Settings(), interval_seconds=0)
        )
        await asyncio.sleep(0.3)
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass

    # Alert must have landed — this fails when the import is broken
    alerts = conn.execute(
        "SELECT source, src_ip FROM alerts WHERE source='cloudtrail'"
    ).fetchall()
    assert len(alerts) == 1, (
        f"expected 1 cloudtrail alert, got {len(alerts)}. "
        "If 0 alerts landed this is likely the broken-import regression."
    )
    assert alerts[0]["src_ip"] == "203.0.113.10"

    # Cursor must have advanced — proves the full happy path ran
    cursor = conn.execute(
        "SELECT last_object_key FROM cloudtrail_progress WHERE bucket='fake-bucket'"
    ).fetchone()
    assert cursor is not None, "cursor row missing — poll loop did not advance"
    assert obj_key in cursor["last_object_key"]

    conn.close()
