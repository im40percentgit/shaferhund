# CloudTrail IAM Policy + Operator Guide (Phase 5)

<!--
@decision DEC-CLOUD-001
@title S3 polling architecture for CloudTrail ingestion
@status accepted
@rationale shaferhund reads CloudTrail logs from S3 rather than streaming
  directly from the CloudTrail API.  S3-based delivery is the standard AWS
  CloudTrail pattern: CloudTrail writes .json.gz objects to a designated
  bucket; shaferhund polls that bucket with a lexicographic cursor.  This
  decouples shaferhund from the CloudTrail API rate limits and allows replay
  of historical events.  See DEC-CLOUD-002 for cursor design.

@decision DEC-CLOUD-002
@title Lexicographic cursor for S3 polling (no re-ingestion on restart)
@status accepted
@rationale CloudTrail delivers objects with time-ordered, lex-sortable keys.
  The cursor stores the last-consumed key; on restart the poller resumes from
  where it left off (exclusive).  This avoids re-ingesting already-seen events
  without requiring a distributed lock or external state store.
-->

This document covers what AWS permissions shaferhund needs, three deployment
modes for credential delivery, a 5-step real-AWS validation checklist, and a
troubleshooting table.  Use it when deploying shaferhund against a real AWS
account.  For local development against LocalStack, see the last section.

---

## What shaferhund needs from AWS

shaferhund's CloudTrail source pipeline polls an S3 bucket that contains
CloudTrail log objects.  The pipeline needs exactly two permissions:

| Permission | Scope | Why |
|---|---|---|
| `s3:GetObject` | CloudTrail log objects (`AWSLogs/.../CloudTrail/*`) | Download and parse each `.json.gz` log file |
| `s3:ListBucket` | The CloudTrail bucket, scoped to the CloudTrail prefix | Enumerate new objects since the last cursor position |

Nothing else is required:

- **No IAM permissions** — shaferhund reads CloudTrail's *record* of IAM events; it never queries IAM directly.
- **No STS permissions** — only needed if you use cross-account AssumeRole (Mode 3 below).
- **No write actions of any kind** — shaferhund is a read-only consumer.

---

## Minimum IAM policy (read-only)

Replace `EXAMPLE-cloudtrail-bucket` with your CloudTrail delivery bucket name
and `EXAMPLE-account-id` with the 12-digit AWS account ID whose CloudTrail
logs shaferhund should read.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "ShaferhundReadCloudTrailObjects",
      "Effect": "Allow",
      "Action": ["s3:GetObject"],
      "Resource": "arn:aws:s3:::EXAMPLE-cloudtrail-bucket/AWSLogs/EXAMPLE-account-id/CloudTrail/*"
    },
    {
      "Sid": "ShaferhundListCloudTrailBucket",
      "Effect": "Allow",
      "Action": ["s3:ListBucket"],
      "Resource": "arn:aws:s3:::EXAMPLE-cloudtrail-bucket",
      "Condition": {
        "StringLike": {"s3:prefix": ["AWSLogs/EXAMPLE-account-id/CloudTrail/*"]}
      }
    }
  ]
}
```

### Deliberately excluded

The following actions are intentionally absent from this policy.  If a code
change or misconfiguration ever tries to request them, AWS will return
`AccessDenied` and the operator should treat that as a bug report.

| Excluded action | Reason |
|---|---|
| `s3:PutObject`, `s3:DeleteObject` | The agent must never write or delete CloudTrail logs |
| `iam:*` | The agent reads CloudTrail's record of IAM events; it never queries IAM resources directly |
| `sts:AssumeRole` | Only needed for cross-account use (Mode 3 below); excluded from the base policy |
| All other AWS services | shaferhund operates on CloudTrail S3 only; no EC2, RDS, SNS, SQS, etc. |

---

## Three deployment modes

### Mode 1 — Static IAM user keys (simplest, least secure)

Suitable for development, demo deployments, or accounts where instance roles
are not available.

1. Create a dedicated IAM user named `shaferhund-cloudtrail-reader`.
2. Attach the policy above to that user (as an inline or managed policy).
3. Generate an access key pair for the user.
4. Set the following environment variables on the shaferhund-agent container:

   ```
   AWS_ACCESS_KEY_ID=AKIA...
   AWS_SECRET_ACCESS_KEY=...
   AWS_DEFAULT_REGION=us-east-1
   CLOUDTRAIL_ENABLED=true
   CLOUDTRAIL_S3_BUCKET=my-cloudtrail-bucket
   CLOUDTRAIL_S3_PREFIX=AWSLogs/123456789012/CloudTrail/
   ```

5. Restart the container — the CloudTrail poller will start on the next poll cycle.

**Caveats:**

- Static keys must be rotated at least every 90 days.  Use IAM access advisor
  to confirm last-used dates before rotation.
- Deliver keys via a secret manager or environment-injection mechanism — never
  commit them to a repository or bake them into a container image.

---

### Mode 2 — EC2 instance role (preferred for AWS-hosted deployments)

When shaferhund runs on EC2, ECS, EKS, or Fargate, use an instance/task role
instead of static keys.  boto3 picks up credentials automatically from IMDS
(Instance Metadata Service) — no `AWS_*` key variables needed.

1. Create an IAM role named `shaferhund-cloudtrail-reader-role`.
2. Attach the policy above to that role.
3. Attach the role to the EC2 instance (or ECS task definition / EKS service
   account) running shaferhund.
4. Set only the CloudTrail-specific env vars (no `AWS_ACCESS_KEY_ID` needed):

   ```
   CLOUDTRAIL_ENABLED=true
   CLOUDTRAIL_S3_BUCKET=my-cloudtrail-bucket
   CLOUDTRAIL_S3_PREFIX=AWSLogs/123456789012/CloudTrail/
   AWS_DEFAULT_REGION=us-east-1
   ```

5. Restart the container.

**Why this is preferred:**

- No long-lived keys to rotate or accidentally leak.
- AWS rotates the underlying credentials automatically.
- Works with EKS pod identity, ECS task roles, and Fargate task roles with no
  code changes — boto3's credential chain handles all of them.

---

### Mode 3 — AssumeRole / cross-account (multi-account orgs)

Use this when CloudTrail logs live in a separate "audit" account from the
account where the shaferhund agent runs.  This is common in AWS Organizations
deployments where a central Security account aggregates all CloudTrail logs.

**In the audit account:**

1. Create a role `shaferhund-cloudtrail-reader-cross-account`.
2. Attach the read-only policy above.
3. Configure a trust policy on that role allowing assumption from the agent's
   account principal:

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": {"AWS": "arn:aws:iam::AGENT-ACCOUNT-ID:role/shaferhund-agent-role"},
    "Action": "sts:AssumeRole"
  }]
}
```

**In the agent's account:**

4. Grant the agent's role/user permission to call `sts:AssumeRole` on the
   cross-account role:

```json
{
  "Effect": "Allow",
  "Action": "sts:AssumeRole",
  "Resource": "arn:aws:iam::AUDIT-ACCOUNT-ID:role/shaferhund-cloudtrail-reader-cross-account"
}
```

5. Configure boto3 to assume the role.  The simplest approach is an AWS
   config profile or environment variable:

   ```
   AWS_ROLE_ARN=arn:aws:iam::AUDIT-ACCOUNT-ID:role/shaferhund-cloudtrail-reader-cross-account
   ```

   For EKS with IRSA (IAM Roles for Service Accounts), additionally set:

   ```
   AWS_WEB_IDENTITY_TOKEN_FILE=/var/run/secrets/eks.amazonaws.com/serviceaccount/token
   ```

---

## Real-AWS validation (5-step checklist)

After deployment, run through this checklist to confirm CloudTrail ingestion
is live:

1. **Apply the IAM policy** — via Terraform, CDK, console, or CLI.  Confirm
   attachment with:

   ```bash
   # For a managed policy attached to a user:
   aws iam list-attached-user-policies --user-name shaferhund-cloudtrail-reader

   # For an inline policy:
   aws iam get-user-policy --user-name shaferhund-cloudtrail-reader --policy-name ShaferhundCloudTrailPolicy
   ```

2. **Configure env vars** — set `CLOUDTRAIL_ENABLED=true`, `CLOUDTRAIL_S3_BUCKET`,
   `CLOUDTRAIL_S3_PREFIX`, and `AWS_DEFAULT_REGION` on the container.

3. **Restart the shaferhund-agent container:**

   ```bash
   podman compose restart shaferhund-agent
   # or: docker compose restart shaferhund-agent
   ```

4. **Check logs for "CloudTrail poller started":**

   ```bash
   podman compose logs shaferhund-agent | grep -i cloudtrail
   ```

   You should see the poller register without any `AccessDenied` errors.

5. **Hit `/health` within 60 seconds:**

   ```bash
   curl http://localhost:8000/health
   ```

   The response's `cloudtrail` block should show `"enabled": true` and
   `"last_poll_at"` should be non-null.  After CloudTrail delivers events to
   the bucket, `events_ingested_24h` should increase on subsequent polls.

---

## Troubleshooting

| Symptom | Diagnosis | Fix |
|---|---|---|
| `AccessDenied: Not authorized to perform s3:ListBucket` | The `s3:prefix` Condition in the policy does not match your prefix | Update the policy's `s3:prefix` to match `CLOUDTRAIL_S3_PREFIX` exactly (trailing slash matters) |
| `NoSuchBucket: The specified bucket does not exist` | Wrong bucket name in env var | Confirm `CLOUDTRAIL_S3_BUCKET` matches the bucket receiving CloudTrail delivery |
| `events_ingested_24h: 0` despite `last_poll_at` being non-null | CloudTrail is not delivering to this bucket, or the prefix is wrong | Verify the CloudTrail trail's S3 destination matches `CLOUDTRAIL_S3_BUCKET` and `CLOUDTRAIL_S3_PREFIX` |
| `last_poll_at` is null after 60 seconds | Poller has not started — usually a missing or wrong env var | Check `CLOUDTRAIL_ENABLED=true` is set; inspect container logs for startup errors |
| `NoCredentialsError` | boto3 cannot find AWS credentials | Mode 1: confirm `AWS_ACCESS_KEY_ID` and `AWS_SECRET_ACCESS_KEY` are set.  Mode 2: confirm IMDS is reachable and the instance role is attached.  Mode 3: confirm `AWS_ROLE_ARN` is set and the trust policy is correct. |
| `InvalidClientTokenId` or `SignatureDoesNotMatch` | Credentials are present but invalid (wrong key, typo, or key has been deactivated) | Regenerate the access key (Mode 1) or verify the role ARN (Mode 3) |

---

## Security considerations

- **Read-only by design** — the policy explicitly excludes all write actions.
  shaferhund's threat model assumes a compromised agent must not be able to
  pivot through cloud credentials to delete evidence or escalate privileges.
- **Rotate static keys regularly** (Mode 1) — at least every 90 days.  Use
  `aws iam generate-credential-report` and IAM access advisor to confirm
  last-used dates before rotation.
- **Prefer instance role / IRSA over static keys** (Mode 2) when running on
  AWS infrastructure — no long-lived secrets to manage.
- **Audit periodically** with IAM policy simulation to confirm the policy
  does not accidentally grant write or privileged actions:

  ```bash
  aws iam simulate-principal-policy \
    --policy-source-arn arn:aws:iam::ACCOUNT-ID:user/shaferhund-cloudtrail-reader \
    --action-names s3:DeleteObject iam:CreateUser sts:AssumeRole \
    --query 'EvaluationResults[*].{Action:EvalActionName,Decision:EvalDecision}'
  ```

  Expected output: all three actions return `implicitDeny` or `explicitDeny`.

- **Network egress** — the agent only needs outbound HTTPS to
  `s3.<region>.amazonaws.com` (and `sts.<region>.amazonaws.com` for Mode 3).
  Lock down container egress rules accordingly.

---

## LocalStack development testing

For local development, the repo ships a LocalStack compose overlay that
provides an AWS-API-compatible S3 endpoint without requiring real AWS
credentials.

```bash
# Start LocalStack alongside shaferhund:
podman compose -f compose.yaml -f compose.localstack.yaml up

# Run the integration test suite (skipped by default; opt-in via -m integration):
pytest -m integration tests/integration/

# The integration tests skip cleanly if LocalStack is not running —
# CI never fails because of a missing LocalStack instance.
```

The integration tests cover three scenarios against real LocalStack S3:

1. **End-to-end pipeline** — upload a root ConsoleLogin `.json.gz` fixture,
   poll, confirm an alert row and a `cloud_audit_findings` row appear, and
   verify the cursor advances.
2. **Cursor resume after restart** — confirm the poller does not re-ingest
   objects that were consumed before a simulated restart.
3. **Empty bucket** — confirm polling an empty bucket produces no errors and
   leaves the cursor unchanged.

This closes the "fixture-only testing is insufficient" loophole that
previously deferred cloud log source ingestion validation
(REQ-NOGO-P25-001 from Phase 2.5, addressed here as REQ-P0-P5-004).
