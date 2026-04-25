# Fleet Client Deployment Guide

The Shaferhund fleet client is a minimal container that polls the manager's
manifest endpoint, verifies the HMAC signature, and writes rule files to a
local mount. The host's Wazuh or Suricata agent picks up the files from that
mount without any manual YAML copying.

This is the client side of the fleet distribution system introduced in Phase 6
(REQ-P0-P6-002). The server side — the signed manifest endpoint — is built into
the existing `shaferhund-agent` container.

---

## What the fleet client does

1. Every `FLEET_POLL_INTERVAL_SECONDS` (default 300), it sends a GET request to
   `FLEET_MANIFEST_URL`.
2. It verifies the HMAC-SHA256 signature on the manifest using `FLEET_HMAC_KEY`.
   A tampered or wrong-key manifest is rejected and no files are touched.
3. For each rule in the manifest it writes `<rules_dir>/<rule_uuid>.<ext>` where
   the extension matches the rule type (`.yar` for YARA, `.yml` for Sigma, `.xml`
   for Wazuh).
4. Any file in `rules_dir` that is NOT in the current manifest is deleted (stale
   cleanup — when a rule is untagged on the manager, the client removes it locally
   on the next pull).
5. Every apply cycle is logged to stdout with the manifest ID, rules written, and
   rules removed. Errors are logged and retried on the next interval.

---

## Required environment variables

| Variable | Description |
|----------|-------------|
| `FLEET_MANIFEST_URL` | Full URL to the manager's manifest endpoint, e.g. `http://shaferhund-agent:8000/fleet/manifest/edr-prod` |
| `FLEET_HMAC_KEY` | Hex-encoded HMAC key. Must match the manager's `SHAFERHUND_AUDIT_KEY`. Generate with: `openssl rand -hex 32` |
| `FLEET_BEARER_TOKEN` | Bearer token for the manager's auth-gated endpoint. Obtain via `POST /auth/login` or `POST /auth/tokens` on the manager. |

## Optional environment variables

| Variable | Default | Description |
|----------|---------|-------------|
| `FLEET_RULES_DIR` | `/rules` | Local directory where rule files are written |
| `FLEET_POLL_INTERVAL_SECONDS` | `300` | Seconds between manifest polls |

---

## HMAC key generation

The HMAC key must match the key configured on the manager (`SHAFERHUND_AUDIT_KEY`).
Generate a 32-byte key and distribute it out-of-band (Kubernetes secret, Vault, etc.):

```bash
openssl rand -hex 32
# example output: a3f1b2c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2
```

Set this value as `SHAFERHUND_AUDIT_KEY` on the manager and as `FLEET_HMAC_KEY` on
each fleet client. A mismatched key causes every manifest fetch to fail signature
verification — the client logs the error and retries on the next interval.

---

## Deployment with compose.fleet.yaml

The fleet client is an opt-in overlay, separate from the main `compose.yaml`
(which stays at 5 services). Run it alongside the default stack:

```bash
# Start the manager stack (if not already running)
podman compose -f compose.yaml up -d

# Start the fleet client overlay
podman compose -f compose.yaml -f compose.fleet.yaml up -d fleet-client
```

Set required env vars in your `.env` file (never commit this file):

```bash
FLEET_MANIFEST_URL=http://shaferhund-agent:8000/fleet/manifest/edr-prod
FLEET_HMAC_KEY=<output of openssl rand -hex 32>
FLEET_BEARER_TOKEN=<token from POST /auth/login or POST /auth/tokens>
```

The `shaferhund_rules_fleet` named volume holds the rule files. In production,
replace it with a bind mount to your Wazuh rules directory:

```yaml
# in compose.fleet.yaml or a local override:
services:
  fleet-client:
    volumes:
      - /var/ossec/etc/rules:/rules
```

---

## How to scope a remote endpoint (FLEET_TAG)

`FLEET_TAG` is the tag segment of the manifest URL. Tags are applied on the
manager via `POST /rules/{rule_id}/tag` (operator role required). For example,
to scope rules for the EDR production group:

```bash
# On the manager — tag a deployed rule for the edr-prod group
curl -X POST http://manager:8000/rules/<rule-id>/tag \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{"tag": "edr-prod"}'

# On the fleet client — set the URL to match the tag
FLEET_MANIFEST_URL=http://shaferhund-agent:8000/fleet/manifest/edr-prod
```

The manifest endpoint filters to only deployed rules carrying that tag. Rules
untagged from the group disappear from the next manifest and the client removes
their files on the next poll.

---

## Standalone container (without compose)

```bash
podman run -d --name shaferhund-fleet-client \
  -e FLEET_MANIFEST_URL=http://manager:8000/fleet/manifest/edr-prod \
  -e FLEET_HMAC_KEY=$(cat /etc/shaferhund/fleet.key) \
  -e FLEET_BEARER_TOKEN=<token> \
  -e FLEET_POLL_INTERVAL_SECONDS=60 \
  -v /var/ossec/etc/rules:/rules \
  --restart unless-stopped \
  shaferhund-fleet-client:latest
```

---

## Troubleshooting

**Signature failures**
```
Fleet apply error: Manifest signature verification failed for manifest_id='abc123...'
```
Cause: `FLEET_HMAC_KEY` does not match the manager's `SHAFERHUND_AUDIT_KEY`.
Fix: Ensure both values are identical hex strings. Regenerate and redistribute
if the key has been rotated on the manager.

**Network errors / connection refused**
```
Fleet apply error: httpx.ConnectError: ...
```
Cause: The manager is unreachable at `FLEET_MANIFEST_URL`.
Fix: Check network connectivity, DNS resolution, and that the manager container
is running. The client retries automatically after `FLEET_POLL_INTERVAL_SECONDS`.

**401 / 403 from manifest endpoint**
```
Fleet apply error: httpx.HTTPStatusError: 401 ...
```
Cause: `FLEET_BEARER_TOKEN` is missing, expired, or insufficient role.
Fix: Issue a new token on the manager (`POST /auth/login` or `POST /auth/tokens`
with operator role). Tokens issued via `/auth/tokens` can have longer expiry
for service accounts.

**Rules directory permission denied**
```
Fleet apply error: PermissionError: [Errno 13] Permission denied: '/rules/...'
```
Cause: The `fleet` user (uid 1000) cannot write to the mounted rules directory.
Fix: Ensure the host directory is writable by uid 1000, or run the container
with `--user root` (not recommended in production).

**No rules written despite manifest showing rules**
Check that the rules on the manager are both **deployed** (`POST /rules/{id}/deploy`)
AND **tagged** with the correct tag (`POST /rules/{id}/tag` with the matching tag
string). Draft rules (deployed=0) never appear in manifests per DEC-FLEET-P6-002.
