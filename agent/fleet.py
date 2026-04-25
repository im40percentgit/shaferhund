"""
Shaferhund Phase 6 Wave A4 — Fleet manifest server.

Builds HMAC-signed rule manifests scoped by tag.  The manifest is consumed
by the fleet agent (Wave B2, REQ-P0-P6-002) which verifies the signature
before applying rules to the local Wazuh agent's rules directory.

Design decisions:

@decision DEC-FLEET-P6-001
@title HMAC-signed manifests over per-agent shared secret; real crypto signing is Phase 7
@status accepted
@rationale HMAC over the manifest body (using the same SHAFERHUND_AUDIT_KEY
           as the audit chain — DEC-AUDIT-P6-001) provides integrity +
           authenticity given a pre-shared secret. This is the relevant
           property for a manager-pushes-to-known-agent model. Real
           cryptographic signing (cosign/minisign) is REQ-NOGO-P6-007 /
           REQ-P2-P6-002 — a worthwhile follow-up once the contract is
           operational. HMAC cost is one SHA-256 computation per manifest
           fetch — negligible. The key reuses SHAFERHUND_AUDIT_KEY (one key,
           two uses in Phase 6) as specified; a separate fleet key is a
           Phase 7 addition if operational signal demands it.

@decision DEC-FLEET-P6-002
@title Only deployed=1 rules appear in fleet manifests; draft/pending rules never leak
@status accepted
@rationale Rule content may be partially written or untested while deployed=0.
           Leaking draft YARA/Sigma rule content to fleet agents would expose
           internal detection logic before it is ready. The manifest builder
           passes deployed_only=True to list_rules_for_tag so the schema-level
           deployed flag is the gate — there is no second application-level
           check to drift from. Operators must explicitly deploy (POST
           /rules/{id}/deploy) before a rule appears in any manifest.

Canonical manifest body encoding:

The body fields are encoded as a UTF-8 JSON array in fixed field order:

    [version, tag, generated_at, rules]

where ``rules`` is a list of rule dicts each containing:

    {id, rule_type, name, content, syntax_valid}

Using a positional JSON array (not a dict) guarantees that field order is
part of the canonical encoding — any re-ordering of the top-level fields
produces different bytes.  This is the same strategy as agent/audit.py's
canonical_row encoding (DEC-AUDIT-P6-001).

The ``manifest_id`` and ``signature`` fields are NOT part of the canonical
body so they can be computed from it without circularity.  ``manifest_id``
is the SHA-256 hex of the canonical bytes (content-addressing).

HMAC computation:

    signature = HMAC-SHA256(key_bytes, canonical_bytes).hexdigest()

Same primitive as ``compute_row_hmac`` in agent/audit.py.
"""

import hashlib
import hmac as _hmac
import json
import logging
import sqlite3
from datetime import datetime, timezone
from typing import Optional

from .models import list_rules_for_tag

log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Canonical body encoding (DEC-FLEET-P6-001)
# ---------------------------------------------------------------------------


def canonical_manifest_body(
    version: int,
    tag: str,
    generated_at: str,
    rules: list[dict],
) -> bytes:
    """Return the deterministic canonical bytes for signing.

    Encodes the four body fields in fixed order as a UTF-8 JSON array:

        [version, tag, generated_at, rules]

    The ``rules`` list must already be in the stable order (e.g. sorted by
    rule id or created_at) that ``build_manifest`` produces — callers should
    not re-order after this call.

    The encoding is identical in spirit to ``canonical_row`` in audit.py:
    a positional JSON array with ``separators=(',', ':')`` and
    ``ensure_ascii=False`` so the result is compact and unambiguous.

    Args:
        version:      Integer manifest version (currently 1).
        tag:          Scoping tag string (e.g. 'group:web').
        generated_at: ISO-8601 UTC timestamp string.
        rules:        List of rule dicts (keys: id, rule_type, name, content,
                      syntax_valid).  Field order within each rule dict is
                      preserved as passed.

    Returns:
        UTF-8-encoded JSON bytes.  Same inputs always produce same bytes.
    """
    payload = [version, tag, generated_at, rules]
    return json.dumps(
        payload,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


# ---------------------------------------------------------------------------
# HMAC signing and verification (DEC-FLEET-P6-001)
# ---------------------------------------------------------------------------


def sign_manifest(key: bytes, canonical: bytes) -> str:
    """Compute HMAC-SHA256 over canonical manifest bytes.

    Returns a lowercase hex string (64 characters).  Same primitive as
    ``compute_row_hmac`` in agent/audit.py — one HMAC function, two uses.

    Args:
        key:       Raw key bytes (from SHAFERHUND_AUDIT_KEY hex-decoded).
        canonical: Output of ``canonical_manifest_body()``.

    Returns:
        Hex digest string, e.g. ``'a3f1...9b2d'``.
    """
    return _hmac.new(key, canonical, hashlib.sha256).hexdigest()


def verify_manifest(manifest: dict, key: bytes) -> bool:
    """Verify a manifest's HMAC signature against the provided key.

    Re-derives the canonical bytes from the manifest's body fields and
    computes the expected HMAC.  Uses ``hmac.compare_digest`` for
    constant-time comparison to prevent timing side-channels.

    Args:
        manifest: Full manifest dict as returned by ``build_manifest()``.
                  Must contain keys: version, tag, generated_at, rules,
                  signature.
        key:      Raw key bytes to verify against.

    Returns:
        True if the signature is valid; False if tampered or wrong key.
        Never raises — callers can treat the bool directly.
    """
    try:
        version = manifest["version"]
        tag = manifest["tag"]
        generated_at = manifest["generated_at"]
        rules = manifest["rules"]
        stored_sig = manifest["signature"]
    except (KeyError, TypeError):
        log.debug("verify_manifest: missing required field in manifest")
        return False

    try:
        canon = canonical_manifest_body(version, tag, generated_at, rules)
        expected = sign_manifest(key, canon)
        return _hmac.compare_digest(expected, stored_sig)
    except Exception:
        log.debug("verify_manifest: exception during recomputation", exc_info=True)
        return False


# ---------------------------------------------------------------------------
# Manifest builder (DEC-FLEET-P6-001, DEC-FLEET-P6-002)
# ---------------------------------------------------------------------------


def build_manifest(
    conn: sqlite3.Connection,
    tag: str,
    key: bytes,
    generated_at: Optional[str] = None,
) -> dict:
    """Build a signed rule manifest for all deployed rules carrying *tag*.

    Queries the DB for deployed rules with this tag (deployed_only=True per
    DEC-FLEET-P6-002), encodes the canonical body, computes the HMAC
    signature and SHA-256 manifest_id, and returns the full manifest dict.

    The returned dict has this shape::

        {
            "version":      1,
            "manifest_id":  "<sha256hex of canonical body>",
            "tag":          "group:web",
            "generated_at": "2026-04-25T16:30:00+00:00",
            "rules": [
                {
                    "id":           "<rule UUID>",
                    "rule_type":    "yara|sigma|wazuh",
                    "name":         "<cluster_id or empty>",
                    "content":      "<rule content>",
                    "syntax_valid": 1,
                }
            ],
            "signature": "<HMAC-SHA256 hex>",
        }

    An empty ``rules`` list is valid — the manifest is still signed so
    fleet agents can detect an intentionally-empty scoped set vs. a
    network failure (no response at all).

    Args:
        conn:         Open SQLite connection.
        tag:          Scoping tag to filter rules by.
        key:          Raw HMAC key bytes (SHAFERHUND_AUDIT_KEY).
        generated_at: Optional ISO-8601 timestamp override; defaults to
                      current UTC time.  Useful for deterministic tests.

    Returns:
        Signed manifest dict.
    """
    if generated_at is None:
        generated_at = datetime.now(timezone.utc).isoformat()

    rule_rows = list_rules_for_tag(conn, tag, deployed_only=True)

    rules_list = [
        {
            "id":           str(row["id"]),
            "rule_type":    row["rule_type"] or "",
            "name":         row["cluster_id"] or "",
            "content":      row["rule_content"] or "",
            "syntax_valid": int(row["syntax_valid"]) if row["syntax_valid"] is not None else 0,
        }
        for row in rule_rows
    ]

    version = 1
    canon = canonical_manifest_body(version, tag, generated_at, rules_list)
    manifest_id = hashlib.sha256(canon).hexdigest()
    signature = sign_manifest(key, canon)

    return {
        "version":      version,
        "manifest_id":  manifest_id,
        "tag":          tag,
        "generated_at": generated_at,
        "rules":        rules_list,
        "signature":    signature,
    }
