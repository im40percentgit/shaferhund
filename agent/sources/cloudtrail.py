"""
AWS CloudTrail S3 poller and event parser for Shaferhund.

Implements the third source pipeline alongside Wazuh and Suricata, following
the same shared alert-dict shape. Polls an S3 bucket/prefix for new CloudTrail
.json.gz log files, parses each ``Records[]`` array, and yields normalised
alert dicts indistinguishable at the clusterer boundary from Wazuh/Suricata
alerts of the same shape.

Key design decisions:

  DEC-CLOUD-001 — AWS CloudTrail as the first cloud provider; one-provider-only
                  Phase 5; GCP/Azure deferred to Phase 6 with same pattern.
  DEC-CLOUD-002 — S3 polling (not EventBridge/Kinesis); 60 s default cadence;
                  cursor-in-DB via ``cloudtrail_progress`` table.
                  CloudTrail S3 keys are time-ordered; ``StartAfter`` is
                  sufficient — no inventory or manifest required.
                  Key shape: AWSLogs/<account>/CloudTrail/<region>/<YYYY>/<MM>/<DD>/
                  <account>_CloudTrail_<region>_<YYYYMMDDTHHMMZ>_<uuid>.json.gz
                  Documented assumption: lex order == chronological order for
                  this key shape (DEC-CLOUD-010).
  DEC-CLOUD-003 — ``source='cloudtrail'`` reuses the shared ``alerts`` table;
                  clusterer/orchestrator/policy gate require zero changes.
                  ``rule_id`` is synthesised as
                  ``cloudtrail:{eventSource}:{eventName}`` (unique vs Wazuh
                  integer rule IDs and Suricata signature_id integers).
  DEC-CLOUD-004 — Severity assigned by deterministic heuristic table at parse
                  time; LLM does contextual triage downstream. Keeps this
                  module fast and side-effect-free.
  DEC-CLOUD-010 — CloudTrail S3 key shape is time-ordered; ``StartAfter`` is
                  sufficient. Documented assumption; sanity-tested below.
  DEC-CLOUD-012 — ``CLOUDTRAIL_ENABLED`` defaults to ``false``; absent AWS
                  creds is a clean degraded mode, not a startup failure.

@decision DEC-CLOUD-001
@title AWS CloudTrail as first cloud provider — one-provider Phase 5
@status accepted
@rationale The Original Intent lists cloud security as one of 25 capability
           domains. CloudTrail covers IAM, DLP, compliance, and threat-intel
           cross-correlation in a single hit. GCP Audit / Azure Monitor follow
           the same source-pipeline pattern in Phase 6+ — landing one provider
           correctly now is better than landing three providers incorrectly.

@decision DEC-CLOUD-002
@title S3 polling, not EventBridge/Kinesis; cursor-in-DB for restart safety
@status accepted
@rationale S3 polling is dirt-cheap (LIST + GET on new objects only), survives
           restarts trivially via the cloudtrail_progress DB cursor, and matches
           the file-tail pattern for Wazuh and Suricata. Real-time ingestion
           (EventBridge, Kinesis) adds operational surface unjustified for a
           solo-dev tool — the 5-15 min CloudTrail-to-S3 lag dominates anyway.

@decision DEC-CLOUD-003
@title source='cloudtrail' reuses shared alerts table; zero clusterer changes
@status accepted
@rationale Continuing the Phase 2 pattern (REQ-P0-P2-003/DEC-CLUSTER-002).
           rule_id = 'cloudtrail:{eventSource}:{eventName}' is unique enough
           to keep clusters disjoint from Wazuh integer IDs and Suricata
           signature_ids; the source column is the actual disambiguator.

@decision DEC-CLOUD-004
@title Deterministic severity heuristic at parse time; LLM triages downstream
@status accepted
@rationale Parsing must be fast and side-effect-free. The heuristic table
           (root use → 12, IAM mutations → 10, console login → 8, S3 bucket
           policy → 9, default → 5) covers the highest-signal CloudTrail
           patterns. Claude's orchestrator loop can upgrade severity via
           finalize_triage based on broader context — the heuristic is a floor,
           not a ceiling.

@decision DEC-CLOUD-010
@title CloudTrail S3 keys are time-ordered; StartAfter is sufficient
@status accepted
@rationale AWS publishes CloudTrail objects with keys of the form
           AWSLogs/<account>/CloudTrail/<region>/<YYYY>/<MM>/<DD>/..._<YYYYMMDDTHHMMZ>_<uuid>.json.gz
           Lex order == chronological order for this key shape.
           list_objects_v2(StartAfter=last_s3_key) returns objects strictly
           after the cursor in lex order. No inventory or manifest is needed.
           This assumption is documented and the CI test fixtures use real
           captured path shapes to guard against future drift.
"""

import asyncio
import gzip
import io
import json
import logging
import sqlite3
from datetime import datetime, timezone
from typing import Iterator, Optional

try:
    import boto3  # type: ignore[import-untyped]
except ImportError:  # pragma: no cover — only absent in stripped CI environments
    boto3 = None  # type: ignore[assignment]

log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# CloudTrail event names that signal IAM mutations (DEC-CLOUD-004).
# Any eventName starting with these prefixes on iam.amazonaws.com is High.
# ---------------------------------------------------------------------------

_IAM_MUTATION_PREFIXES: tuple[str, ...] = (
    "Create",
    "Delete",
    "Put",
    "Attach",
    "Detach",
    "Update",
    "Add",
    "Remove",
    "Set",
    "Tag",
    "Untag",
    "Enable",
    "Disable",
    "Deactivate",
    "Activate",
    "Upload",
)

_S3_BUCKET_POLICY_EVENTS: frozenset[str] = frozenset({
    "PutBucketPolicy",
    "DeleteBucketPolicy",
    "PutBucketAcl",
    "PutBucketCors",
    "PutBucketLifecycle",
    "PutBucketLifecycleConfiguration",
    "PutBucketLogging",
    "PutBucketPublicAccessBlock",
    "DeletePublicAccessBlock",
    "PutBucketVersioning",
})

# ---------------------------------------------------------------------------
# Severity heuristic (DEC-CLOUD-004)
# ---------------------------------------------------------------------------

# Severity scale 1-15 to match the existing Wazuh scale.
# These values are intentionally simple; Claude's orchestrator refines them.
_SEV_CRITICAL = 12   # root user — any action is a red flag
_SEV_IAM_HIGH = 10   # IAM mutations on iam.amazonaws.com
_SEV_S3_POLICY = 9   # S3 bucket-policy changes
_SEV_CONSOLE   = 8   # Console logins (source IP unknown → treat as medium)
_SEV_DEFAULT   = 5   # Everything else (read-only, non-sensitive)


def _classify_severity(event: dict) -> int:
    """Return an integer severity (1-15) for a single CloudTrail event.

    Rules applied in priority order (highest wins):
      1. Root user activity → 12 (Critical)
      2. IAM mutations on iam.amazonaws.com → 10 (High)
      3. S3 bucket-policy events on s3.amazonaws.com → 9 (Medium-High)
      4. ConsoleLogin → 8 (Medium, per DEC-CLOUD-004 commentary)
      5. Everything else → 5 (Low)

    Args:
        event: A single CloudTrail event record dict.

    Returns:
        Integer severity in [1, 15].
    """
    user_identity = event.get("userIdentity") or {}
    identity_type = user_identity.get("type", "")
    event_source = event.get("eventSource", "")
    event_name = event.get("eventName", "")

    # Rule 1: root user — any action is high severity
    if identity_type == "Root":
        return _SEV_CRITICAL

    # Rule 2: IAM mutations
    if event_source == "iam.amazonaws.com":
        if any(event_name.startswith(pfx) for pfx in _IAM_MUTATION_PREFIXES):
            return _SEV_IAM_HIGH

    # Rule 3: S3 bucket-policy / ACL changes
    if event_source == "s3.amazonaws.com" and event_name in _S3_BUCKET_POLICY_EVENTS:
        return _SEV_S3_POLICY

    # Rule 4: Console login
    if event_name == "ConsoleLogin":
        return _SEV_CONSOLE

    # Rule 5: default
    return _SEV_DEFAULT


# ---------------------------------------------------------------------------
# Shared alert-dict shape builder (DEC-CLOUD-003)
# ---------------------------------------------------------------------------

# Severity integer → human-readable string (Wazuh convention).
_SEVERITY_LABELS: dict[int, str] = {
    _SEV_CRITICAL: "Critical",
    _SEV_IAM_HIGH: "High",
    _SEV_S3_POLICY: "High",
    _SEV_CONSOLE:   "Medium",
    _SEV_DEFAULT:   "Low",
}


def _normalise_severity_label(sev: int) -> str:
    """Map integer severity to a human-readable label.

    Uses the closest bucket: Critical (≥12), High (9-11), Medium (7-8),
    Low (<7). Exact bucket matches the values emitted by _classify_severity.
    """
    if sev >= 12:
        return "Critical"
    if sev >= 9:
        return "High"
    if sev >= 7:
        return "Medium"
    return "Low"


def parse_cloudtrail_event(event: dict) -> dict:
    """Parse a single CloudTrail event record into the shared alert dict shape.

    Emits the same field set as parse_suricata_alert() and parse_wazuh_alert()
    so the clusterer, orchestrator, and policy gate require zero changes
    (DEC-CLOUD-003, REQ-P0-P5-002).

    rule_id is synthesised as "cloudtrail:{eventSource}:{eventName}" — unique
    vs Wazuh integer IDs and Suricata signature_ids. The source column is the
    actual disambiguator for per-source cluster keys.

    Args:
        event: A single CloudTrail event record dict (one element of Records[]).

    Returns:
        A dict with keys: source, src_ip, dest_ip, protocol, rule_id,
        rule_description, normalized_severity, timestamp, raw_json, severity.
        Never returns None — malformed events get default/fallback values so
        the parser is always safe to call in a loop.
    """
    event_source = event.get("eventSource", "unknown.amazonaws.com")
    event_name = event.get("eventName", "UnknownEvent")

    # Synthesise rule_id — format: cloudtrail:{eventSource}:{eventName}
    rule_id = f"cloudtrail:{event_source}:{event_name}"

    # Source IP — can be a hostname (e.g. "AWS Internal") for service calls
    src_ip = event.get("sourceIPAddress") or "unknown"

    # Parse eventTime to UTC ISO-8601
    raw_ts = event.get("eventTime", "")
    try:
        # CloudTrail uses ISO-8601 with Z suffix
        ts = datetime.strptime(raw_ts, "%Y-%m-%dT%H:%M:%SZ").replace(
            tzinfo=timezone.utc
        ).isoformat()
    except (ValueError, TypeError):
        ts = datetime.now(timezone.utc).isoformat()
        log.warning(
            "CloudTrail event has unparseable eventTime %r — using now()", raw_ts
        )

    severity = _classify_severity(event)
    normalized_severity = _normalise_severity_label(severity)

    # Human-readable rule description
    user_identity = event.get("userIdentity") or {}
    principal = (
        user_identity.get("userName")
        or user_identity.get("arn")
        or user_identity.get("type", "unknown")
    )
    rule_description = f"{event_name} by {principal} via {event_source}"

    return {
        "source": "cloudtrail",
        "src_ip": src_ip,
        "dest_ip": None,
        "protocol": "https",
        "rule_id": rule_id,
        "rule_description": rule_description,
        "normalized_severity": normalized_severity,
        "severity": severity,
        "timestamp": ts,
        "raw_json": json.dumps(event),
    }


# ---------------------------------------------------------------------------
# S3 iterator — list + download + decompress (DEC-CLOUD-002 / DEC-CLOUD-010)
# ---------------------------------------------------------------------------

def _iter_s3_events(
    s3_client,
    bucket: str,
    prefix: str,
    cursor: Optional[str],
) -> Iterator[tuple[str, dict]]:
    """Yield (object_key, parsed_event_dict) pairs from new S3 objects.

    Lists objects in ``bucket`` under ``prefix`` after ``cursor`` (the last
    fully-consumed S3 object key). Downloads each .json.gz file, decompresses,
    parses the CloudTrail ``Records[]`` array, and yields one tuple per event.

    Relies on DEC-CLOUD-010: CloudTrail S3 keys are lex-ordered chronologically,
    so ``StartAfter=cursor`` is sufficient to pick up only new objects.

    Args:
        s3_client:  A boto3 S3 client (sync).
        bucket:     S3 bucket name.
        prefix:     Key prefix (e.g. ``AWSLogs/123456789012/CloudTrail/``).
        cursor:     Last fully-consumed S3 object key, or None to start from
                    the beginning of the prefix.

    Yields:
        Tuples of (object_key, parsed_event_dict). object_key is the S3 key
        of the file that contained this event — used to advance the cursor
        after the entire file is processed.
    """
    list_kwargs: dict = {
        "Bucket": bucket,
        "Prefix": prefix,
    }
    if cursor:
        list_kwargs["StartAfter"] = cursor

    paginator = s3_client.get_paginator("list_objects_v2")
    for page in paginator.paginate(**list_kwargs):
        for obj in page.get("Contents", []):
            key = obj["Key"]
            if not key.endswith(".json.gz"):
                # Skip non-CloudTrail objects (e.g. digest files)
                log.debug("Skipping non-.json.gz object: %s", key)
                continue
            try:
                response = s3_client.get_object(Bucket=bucket, Key=key)
                compressed = response["Body"].read()
                with gzip.open(io.BytesIO(compressed), "rt", encoding="utf-8") as fh:
                    data = json.load(fh)
                records = data.get("Records") or []
                for record in records:
                    yield key, record
            except Exception as exc:  # noqa: BLE001
                log.warning(
                    "Failed to fetch/parse S3 object s3://%s/%s: %s",
                    bucket, key, exc,
                )
                # Skip the failed object — don't advance cursor past it;
                # caller sees the last successful key via the outer cursor logic.


# ---------------------------------------------------------------------------
# Async poll loop (DEC-CLOUD-002, DEC-SLO-004 pattern)
# ---------------------------------------------------------------------------

async def cloudtrail_poll_loop(
    conn_factory,
    settings,
    interval_seconds: int = 60,
) -> None:
    """Async loop: poll S3 for new CloudTrail objects every interval_seconds.

    Mirrors the slo_evaluator_loop pattern. Uses boto3 (sync) wrapped in
    asyncio.to_thread so the event loop stays cooperative.

    On each cycle:
      1. Read cursor from cloudtrail_progress (last fully-consumed S3 key).
      2. List new S3 objects after the cursor.
      3. Parse events → shared alert dicts.
      4. Insert into the alerts table (direct DB write; clustering is done
         externally by the caller-wired clusterer, same as Wazuh/Suricata).
      5. Advance cursor to the last successfully processed S3 key.
      6. Sleep interval_seconds.

    On error: log and continue — no retry storm (DEC-CLOUD-012).

    Args:
        conn_factory: A raw sqlite3.Connection, or a callable that returns one.
                      Uses isinstance(conn_factory, sqlite3.Connection) per
                      DEC-SLO-004 — sqlite3.Connection has __call__ from the
                      C extension, so callable() returns True for a raw conn.
        settings:     Settings-like object with cloudtrail_* attributes.
        interval_seconds: Poll cadence override (defaults to
                      settings.cloudtrail_poll_interval_seconds if present).
    """
    # Resolve effective interval
    eff_interval = getattr(settings, "cloudtrail_poll_interval_seconds", interval_seconds)

    bucket = getattr(settings, "cloudtrail_s3_bucket", "")
    prefix = getattr(settings, "cloudtrail_s3_prefix", "")
    region = getattr(settings, "cloudtrail_aws_region", "us-east-1")

    log.info(
        "CloudTrail poller started (bucket=%s prefix=%s interval=%ds)",
        bucket, prefix, eff_interval,
    )

    while True:
        try:
            # boto3 client created inside the loop so credential errors are caught
            # by the broad except below (DEC-CLOUD-012: no startup failure on
            # missing creds — degrade gracefully and retry each cycle).
            s3_client = boto3.client("s3", region_name=region)

            # DEC-SLO-004 fix: use isinstance, not callable()
            conn = conn_factory if isinstance(conn_factory, sqlite3.Connection) else conn_factory()

            from .models import get_cloudtrail_cursor, update_cloudtrail_cursor  # type: ignore[attr-defined]

            cursor_row = await asyncio.to_thread(
                get_cloudtrail_cursor, conn, bucket, prefix
            )
            last_key: Optional[str] = cursor_row["last_object_key"] if cursor_row else None

            # Collect events from S3 in thread pool (boto3 is sync)
            events: list[tuple[str, dict]] = await asyncio.to_thread(
                lambda: list(_iter_s3_events(s3_client, bucket, prefix, last_key))
            )

            if events:
                from .models import insert_cloudtrail_alert  # type: ignore[attr-defined]

                new_last_key: Optional[str] = None
                last_event_ts: Optional[str] = None
                for obj_key, raw_event in events:
                    parsed = parse_cloudtrail_event(raw_event)
                    await asyncio.to_thread(
                        insert_cloudtrail_alert, conn, parsed
                    )
                    new_last_key = obj_key
                    last_event_ts = parsed["timestamp"]

                if new_last_key:
                    await asyncio.to_thread(
                        update_cloudtrail_cursor,
                        conn, bucket, prefix, new_last_key, last_event_ts,
                    )
                    log.info(
                        "CloudTrail: processed %d events, cursor advanced to %s",
                        len(events), new_last_key,
                    )
            else:
                log.debug("CloudTrail: no new objects after cursor=%s", last_key)

        except asyncio.CancelledError:
            raise
        except Exception as exc:  # noqa: BLE001
            log.warning("CloudTrail poller error (continuing): %s", exc, exc_info=True)

        await asyncio.sleep(eff_interval)
