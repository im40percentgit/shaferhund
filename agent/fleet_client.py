"""
Shaferhund Phase 6 Wave B2 — Fleet client (REQ-P0-P6-002).

Standalone polling client that fetches a signed rule manifest from the
Shaferhund manager, verifies the HMAC signature, and writes rule files to
a local directory so the host's Wazuh/Suricata agent can pick them up.

This module is the *client* counterpart to agent/fleet.py (the server side).
It is intentionally free of FastAPI, SQLite, and all other server-side
dependencies so it can be packaged in a minimal container image alongside
the remote Wazuh agent.

Design decisions:

@decision DEC-FLEET-P6-001
@title HMAC-signed manifests over per-agent shared secret; real crypto signing is Phase 7
@status accepted
@rationale The pre-shared HMAC key model provides integrity + authenticity for
           the manifest pull without a PKI. The manager signs the canonical
           manifest body; the client re-derives the signature and compares with
           hmac.compare_digest (constant-time). Tampered or wrong-key manifests
           are rejected before any file is touched. Real cryptographic signing
           (cosign/minisign) is REQ-NOGO-P6-007 — follow-up once the contract
           is operational.

@decision DEC-FLEET-P6-003
@title Fleet client is a separate minimal module + container; verify_manifest reused from agent.fleet
@status accepted
@rationale The client only needs httpx + the HMAC verification function. Copying
           verify_manifest into a second module would create a second source of
           truth for the signature algorithm — a drift hazard. Instead, the client
           imports agent.fleet.verify_manifest directly. The Dockerfile copies only
           agent/__init__.py, agent/models.py, agent/fleet.py, and this module,
           keeping the image surface small. agent/models.py is pulled in transitively
           by agent/fleet.py (list_rules_for_tag import) but models.py itself is
           stdlib-only so it costs nothing in extra dependencies.

@decision DEC-FLEET-P6-005
@title LocalStack-style integration test gated by FLEET_INTEGRATION=1; honours DEC-CLOUD-013
@status accepted
@rationale Consistent with the CloudTrail LocalStack gate (DEC-CLOUD-013). The default
           pytest suite (addopts = -m "not integration") never runs the fleet client
           integration test. Operators opt in by running:
               pytest -m integration tests/integration/test_fleet_client_integration.py
           This keeps CI green when the manager is not reachable.

Public interface
----------------
fetch_manifest(url, bearer_token, timeout) -> dict
    HTTP GET the manifest URL. Returns parsed JSON. Raises httpx.HTTPError on 4xx/5xx.

verify_and_apply(manifest, key, rules_dir) -> dict
    Verify HMAC signature (raises ValueError on invalid). Write rule files.
    Remove stale files not present in the manifest. Returns summary dict.

run_once(settings) -> dict
    Fetch + verify + apply in one call.

run_loop(settings, interval_seconds)
    Async polling loop. Broad-except + log on error; never crashes.
"""

import asyncio
import logging
import os
from pathlib import Path
from typing import Optional

import httpx

from agent.fleet import verify_manifest

log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Rule type → file extension mapping
# ---------------------------------------------------------------------------

_EXT_MAP = {
    "yara": ".yar",
    "sigma": ".yml",
    "wazuh": ".xml",
}

_DEFAULT_EXT = ".rule"


def _ext_for(rule_type: str) -> str:
    """Return the file extension for a given rule type string."""
    return _EXT_MAP.get((rule_type or "").lower().strip(), _DEFAULT_EXT)


# ---------------------------------------------------------------------------
# Manifest fetch
# ---------------------------------------------------------------------------


def fetch_manifest(
    url: str,
    bearer_token: Optional[str] = None,
    timeout: float = 30.0,
) -> dict:
    """Fetch a signed rule manifest from the Shaferhund manager.

    Performs a synchronous HTTP GET.  If *bearer_token* is provided it is sent
    as an ``Authorization: Bearer <token>`` header.  The response body is
    expected to be a JSON object matching the manifest shape produced by
    ``agent.fleet.build_manifest``.

    Args:
        url:          Full URL of the manifest endpoint, e.g.
                      ``http://manager:8000/fleet/manifest/edr-prod``.
        bearer_token: Optional bearer token for auth-gated endpoints.
        timeout:      Request timeout in seconds (default 30).

    Returns:
        Parsed JSON dict from the response body.

    Raises:
        httpx.HTTPStatusError: On 4xx / 5xx responses (raised by
                               ``response.raise_for_status()``).
        httpx.RequestError:    On connection failures, timeouts, etc.
    """
    headers: dict[str, str] = {}
    if bearer_token:
        headers["Authorization"] = f"Bearer {bearer_token}"

    with httpx.Client(timeout=timeout) as client:
        response = client.get(url, headers=headers)
        response.raise_for_status()
        return response.json()


# ---------------------------------------------------------------------------
# Verify and apply
# ---------------------------------------------------------------------------


def verify_and_apply(
    manifest: dict,
    key: bytes,
    rules_dir: str,
) -> dict:
    """Verify a manifest's HMAC signature and apply the rule files to disk.

    Signature verification happens first — if it fails a ``ValueError`` is
    raised and no files are touched.  On success:

    1. For each rule in the manifest, write ``<rules_dir>/<rule_uuid>.<ext>``
       where *ext* is derived from ``rule_type`` (``.yar`` / ``.yml`` /
       ``.xml``).  Existing files are overwritten atomically.
    2. Remove any files in ``rules_dir`` that were not present in the manifest
       (stale cleanup — when a rule is untagged on the manager, the client
       removes it locally on the next pull).

    ``rules_dir`` is created if it does not exist.

    Args:
        manifest:  Full manifest dict as returned by ``fetch_manifest`` /
                   ``agent.fleet.build_manifest``.
        key:       Raw HMAC key bytes (hex-decoded from ``FLEET_HMAC_KEY``).
        rules_dir: Local directory path where rule files are written.

    Returns:
        ``{rules_written: int, rules_removed: int, manifest_id: str}``

    Raises:
        ValueError: If ``verify_manifest`` returns False (invalid HMAC or
                    missing fields).  The manifest_id is included in the
                    message so operators can correlate without exposing the key.
    """
    manifest_id = manifest.get("manifest_id", "<unknown>")

    if not verify_manifest(manifest, key):
        raise ValueError(
            f"Manifest signature verification failed for manifest_id={manifest_id!r}. "
            "Check that FLEET_HMAC_KEY matches the key configured on the manager."
        )

    rules_path = Path(rules_dir)
    rules_path.mkdir(parents=True, exist_ok=True)

    rules_in_manifest: set[str] = set()
    rules_written = 0

    for rule in manifest.get("rules", []):
        rule_id = rule.get("id", "")
        rule_type = rule.get("rule_type", "")
        content = rule.get("content", "")

        if not rule_id:
            log.warning("Manifest rule missing 'id' field — skipping")
            continue

        ext = _ext_for(rule_type)
        filename = f"{rule_id}{ext}"
        rules_in_manifest.add(filename)

        file_path = rules_path / filename
        # Atomic write: write to tmp then rename so the rule file is never
        # partially written from the perspective of the rule engine reader.
        tmp_path = rules_path / f".tmp_{filename}"
        try:
            tmp_path.write_text(content, encoding="utf-8")
            tmp_path.rename(file_path)
            rules_written += 1
            log.debug("Wrote rule file: %s", file_path)
        except OSError as exc:
            log.error("Failed to write rule file %s: %s", file_path, exc)
            # Re-raise so the caller knows the apply was partial
            raise

    # Remove stale files — anything in rules_dir that is NOT in the manifest.
    # Only files matching the known extensions are considered managed.
    managed_exts = set(_EXT_MAP.values()) | {_DEFAULT_EXT}
    rules_removed = 0

    for existing in list(rules_path.iterdir()):
        if existing.is_file() and existing.suffix in managed_exts:
            if existing.name not in rules_in_manifest:
                try:
                    existing.unlink()
                    rules_removed += 1
                    log.debug("Removed stale rule file: %s", existing)
                except OSError as exc:
                    log.warning("Could not remove stale file %s: %s", existing, exc)

    log.info(
        "Applied manifest %s: %d rules written, %d stale files removed",
        manifest_id,
        rules_written,
        rules_removed,
    )

    return {
        "rules_written": rules_written,
        "rules_removed": rules_removed,
        "manifest_id": manifest_id,
    }


# ---------------------------------------------------------------------------
# Settings helper (used by run_once and run_loop)
# ---------------------------------------------------------------------------


class FleetClientSettings:
    """Thin settings bag populated from env vars.

    Attributes:
        manifest_url:    Full URL to the manifest endpoint.
        hmac_key:        Raw HMAC key bytes (hex-decoded from FLEET_HMAC_KEY).
        rules_dir:       Local path where rule files are written.
        bearer_token:    Optional bearer token for the manifest endpoint.
    """

    def __init__(
        self,
        manifest_url: str,
        hmac_key: bytes,
        rules_dir: str,
        bearer_token: Optional[str] = None,
    ) -> None:
        self.manifest_url = manifest_url
        self.hmac_key = hmac_key
        self.rules_dir = rules_dir
        self.bearer_token = bearer_token

    @classmethod
    def from_env(cls) -> "FleetClientSettings":
        """Build settings from environment variables.

        Required env vars:
            FLEET_MANIFEST_URL   — full URL to the manifest endpoint
            FLEET_HMAC_KEY       — hex-encoded HMAC key (32+ bytes recommended)
            FLEET_RULES_DIR      — local directory for rule files (default /rules)

        Optional:
            FLEET_BEARER_TOKEN   — bearer token for auth-gated manager endpoints

        Raises:
            EnvironmentError: If required vars are missing or FLEET_HMAC_KEY
                              is not valid hex.
        """
        missing = []

        manifest_url = os.environ.get("FLEET_MANIFEST_URL", "")
        if not manifest_url:
            missing.append("FLEET_MANIFEST_URL")

        hmac_key_hex = os.environ.get("FLEET_HMAC_KEY", "")
        if not hmac_key_hex:
            missing.append("FLEET_HMAC_KEY")

        if missing:
            raise EnvironmentError(
                f"Missing required env vars: {', '.join(missing)}. "
                "Set FLEET_MANIFEST_URL and FLEET_HMAC_KEY before starting the fleet client."
            )

        try:
            hmac_key = bytes.fromhex(hmac_key_hex)
        except ValueError as exc:
            raise EnvironmentError(
                f"FLEET_HMAC_KEY is not valid hex: {exc}"
            ) from exc

        rules_dir = os.environ.get("FLEET_RULES_DIR", "/rules")
        bearer_token = os.environ.get("FLEET_BEARER_TOKEN") or None

        return cls(
            manifest_url=manifest_url,
            hmac_key=hmac_key,
            rules_dir=rules_dir,
            bearer_token=bearer_token,
        )


# ---------------------------------------------------------------------------
# run_once and run_loop
# ---------------------------------------------------------------------------


def run_once(settings: FleetClientSettings) -> dict:
    """Fetch, verify, and apply the manifest in one synchronous call.

    Args:
        settings: A populated ``FleetClientSettings`` instance.

    Returns:
        Summary dict from ``verify_and_apply``.

    Raises:
        httpx.HTTPError:  On network or HTTP-level errors during fetch.
        ValueError:       On HMAC signature failure.
        OSError:          On file system errors during rule write.
    """
    manifest = fetch_manifest(
        settings.manifest_url,
        bearer_token=settings.bearer_token,
    )
    return verify_and_apply(manifest, settings.hmac_key, settings.rules_dir)


async def run_loop(
    settings: FleetClientSettings,
    interval_seconds: int = 300,
) -> None:
    """Async polling loop that calls ``run_once`` every *interval_seconds*.

    Errors (network, signature, I/O) are caught and logged; the loop
    continues.  Cancellation (asyncio.CancelledError) propagates cleanly
    so the caller can shut down via ``task.cancel()``.

    Args:
        settings:         Fleet client settings.
        interval_seconds: Seconds between poll cycles (default 300 / 5 min).
    """
    log.info(
        "Fleet client loop starting: url=%s rules_dir=%s interval=%ds",
        settings.manifest_url,
        settings.rules_dir,
        interval_seconds,
    )

    while True:
        try:
            summary = run_once(settings)
            log.info(
                "Fleet apply OK — manifest_id=%s written=%d removed=%d",
                summary["manifest_id"],
                summary["rules_written"],
                summary["rules_removed"],
            )
        except asyncio.CancelledError:
            # CancelledError must propagate — do NOT catch it here
            raise
        except Exception as exc:  # noqa: BLE001
            log.error(
                "Fleet apply error (will retry in %ds): %s: %s",
                interval_seconds,
                type(exc).__name__,
                exc,
            )

        try:
            await asyncio.sleep(interval_seconds)
        except asyncio.CancelledError:
            log.info("Fleet client loop cancelled during sleep — exiting cleanly")
            raise
