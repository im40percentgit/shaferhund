"""
Unit tests for Phase 6 Wave A4 fleet manifest pure functions.

Tests cover: canonical_manifest_body, sign_manifest, verify_manifest,
build_manifest.  All tests run against a real SQLite DB — no mocks.

REQ-P0-P6-001 / DEC-FLEET-P6-001 / DEC-FLEET-P6-002
"""
import pytest

from agent.fleet import (
    build_manifest,
    canonical_manifest_body,
    sign_manifest,
    verify_manifest,
)
from agent.models import (
    init_db,
    insert_rule,
    tag_rule,
)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_KEY_A = bytes.fromhex("aa" * 32)
_KEY_B = bytes.fromhex("bb" * 32)
_FIXED_TS = "2026-04-25T16:30:00+00:00"


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture()
def conn(tmp_path):
    db = init_db(str(tmp_path / "test.db"))
    yield db
    db.close()


def _seed_deployed_rule(conn, rule_id="rule-001", tag="group:web", rule_type="yara"):
    """Insert a deployed rule and tag it.

    cluster_id=None avoids FK constraint — NULL is always valid for nullable
    FK columns in SQLite even with foreign_keys=ON.
    """
    insert_rule(
        conn,
        rule_id=rule_id,
        cluster_id=None,
        rule_type=rule_type,
        rule_content=f"rule {rule_id} {{}}",
        syntax_valid=True,
    )
    conn.execute("UPDATE rules SET deployed = 1 WHERE id = ?", (rule_id,))
    conn.commit()
    tag_rule(conn, rule_id, tag)
    return rule_id


def _seed_undeployed_rule(conn, rule_id="rule-draft", tag="group:web"):
    """Insert a rule with deployed=0 and tag it."""
    insert_rule(
        conn,
        rule_id=rule_id,
        cluster_id=None,
        rule_type="yara",
        rule_content="rule draft {}",
        syntax_valid=False,
    )
    # deployed stays 0 (default)
    tag_rule(conn, rule_id, tag)
    return rule_id


# ---------------------------------------------------------------------------
# canonical_manifest_body
# ---------------------------------------------------------------------------

def test_canonical_body_is_bytes():
    body = canonical_manifest_body(1, "group:web", _FIXED_TS, [])
    assert isinstance(body, bytes)


def test_canonical_body_same_inputs_same_output():
    rules = [{"id": "r1", "rule_type": "yara", "name": "c1", "content": "x", "syntax_valid": 1}]
    b1 = canonical_manifest_body(1, "group:web", _FIXED_TS, rules)
    b2 = canonical_manifest_body(1, "group:web", _FIXED_TS, rules)
    assert b1 == b2


def test_canonical_body_field_order_matters():
    """Swapping version and tag (different field positions) must produce different bytes."""
    body_v1 = canonical_manifest_body(1, "group:web", _FIXED_TS, [])
    body_v2 = canonical_manifest_body(2, "group:web", _FIXED_TS, [])
    assert body_v1 != body_v2


def test_canonical_body_tag_change_produces_different_bytes():
    b1 = canonical_manifest_body(1, "group:web", _FIXED_TS, [])
    b2 = canonical_manifest_body(1, "group:db", _FIXED_TS, [])
    assert b1 != b2


def test_canonical_body_empty_rules_is_valid():
    body = canonical_manifest_body(1, "group:web", _FIXED_TS, [])
    assert len(body) > 0


# ---------------------------------------------------------------------------
# sign_manifest
# ---------------------------------------------------------------------------

def test_sign_manifest_returns_hex_string():
    body = canonical_manifest_body(1, "group:web", _FIXED_TS, [])
    sig = sign_manifest(_KEY_A, body)
    assert isinstance(sig, str)
    assert len(sig) == 64  # SHA-256 hex digest


def test_sign_manifest_deterministic():
    body = canonical_manifest_body(1, "group:web", _FIXED_TS, [])
    sig1 = sign_manifest(_KEY_A, body)
    sig2 = sign_manifest(_KEY_A, body)
    assert sig1 == sig2


def test_sign_manifest_different_keys_different_sigs():
    body = canonical_manifest_body(1, "group:web", _FIXED_TS, [])
    sig_a = sign_manifest(_KEY_A, body)
    sig_b = sign_manifest(_KEY_B, body)
    assert sig_a != sig_b


# ---------------------------------------------------------------------------
# verify_manifest
# ---------------------------------------------------------------------------

def test_verify_manifest_round_trip_valid(conn):
    """sign then verify with same key → True."""
    _seed_deployed_rule(conn)
    manifest = build_manifest(conn, "group:web", _KEY_A, generated_at=_FIXED_TS)
    assert verify_manifest(manifest, _KEY_A) is True


def test_verify_manifest_wrong_key(conn):
    """Verify with a different key → False."""
    _seed_deployed_rule(conn)
    manifest = build_manifest(conn, "group:web", _KEY_A, generated_at=_FIXED_TS)
    assert verify_manifest(manifest, _KEY_B) is False


def test_verify_manifest_tampered_rule_content(conn):
    """Mutate a rule's content field after signing → verify returns False."""
    _seed_deployed_rule(conn)
    manifest = build_manifest(conn, "group:web", _KEY_A, generated_at=_FIXED_TS)
    # Tamper: change first rule's content
    tampered = dict(manifest)
    tampered["rules"] = [dict(r) for r in manifest["rules"]]
    tampered["rules"][0]["content"] = "TAMPERED"
    assert verify_manifest(tampered, _KEY_A) is False


def test_verify_manifest_tampered_signature(conn):
    """Flip a hex char in the stored signature → verify returns False."""
    _seed_deployed_rule(conn)
    manifest = build_manifest(conn, "group:web", _KEY_A, generated_at=_FIXED_TS)
    tampered = dict(manifest)
    # Flip the first character of the hex signature
    original_sig = manifest["signature"]
    flipped_char = "0" if original_sig[0] != "0" else "1"
    tampered["signature"] = flipped_char + original_sig[1:]
    assert verify_manifest(tampered, _KEY_A) is False


def test_verify_manifest_missing_field():
    """verify_manifest with a dict missing required fields → False (no exception)."""
    bad = {"version": 1, "tag": "x"}  # missing signature, rules, generated_at
    assert verify_manifest(bad, _KEY_A) is False


def test_verify_manifest_empty_rules_valid():
    """Empty-rules manifest (no deployed rules for tag) still verifies correctly."""
    body = canonical_manifest_body(1, "group:empty", _FIXED_TS, [])
    sig = sign_manifest(_KEY_A, body)
    manifest = {
        "version": 1,
        "manifest_id": "x",
        "tag": "group:empty",
        "generated_at": _FIXED_TS,
        "rules": [],
        "signature": sig,
    }
    assert verify_manifest(manifest, _KEY_A) is True


# ---------------------------------------------------------------------------
# build_manifest
# ---------------------------------------------------------------------------

def test_build_manifest_empty_tag(conn):
    """No rules tagged → manifest has empty rules array; signature is valid."""
    manifest = build_manifest(conn, "group:nonexistent", _KEY_A, generated_at=_FIXED_TS)
    assert manifest["version"] == 1
    assert manifest["tag"] == "group:nonexistent"
    assert manifest["rules"] == []
    assert "signature" in manifest
    assert "manifest_id" in manifest
    assert verify_manifest(manifest, _KEY_A) is True


def test_build_manifest_excludes_undeployed(conn):
    """An undeployed rule tagged for the group must not appear in the manifest."""
    _seed_undeployed_rule(conn, "rule-draft", "group:web")
    manifest = build_manifest(conn, "group:web", _KEY_A, generated_at=_FIXED_TS)
    assert manifest["rules"] == []


def test_build_manifest_includes_deployed(conn):
    """A deployed rule tagged for the group appears in the manifest."""
    _seed_deployed_rule(conn, "rule-001", "group:web")
    manifest = build_manifest(conn, "group:web", _KEY_A, generated_at=_FIXED_TS)
    assert len(manifest["rules"]) == 1
    assert manifest["rules"][0]["id"] == "rule-001"


def test_build_manifest_excludes_undeployed_includes_deployed(conn):
    """Mixed deployed/undeployed: only deployed rule appears."""
    _seed_deployed_rule(conn, "rule-deployed", "group:web")
    _seed_undeployed_rule(conn, "rule-draft", "group:web")
    manifest = build_manifest(conn, "group:web", _KEY_A, generated_at=_FIXED_TS)
    assert len(manifest["rules"]) == 1
    assert manifest["rules"][0]["id"] == "rule-deployed"


def test_build_manifest_signature_deterministic(conn):
    """Same DB state and same generated_at → identical signature."""
    _seed_deployed_rule(conn)
    m1 = build_manifest(conn, "group:web", _KEY_A, generated_at=_FIXED_TS)
    m2 = build_manifest(conn, "group:web", _KEY_A, generated_at=_FIXED_TS)
    assert m1["signature"] == m2["signature"]
    assert m1["manifest_id"] == m2["manifest_id"]


def test_manifest_id_changes_with_content(conn):
    """Two different rule sets → different manifest_ids."""
    _seed_deployed_rule(conn, "rule-001", "group:web")
    m1 = build_manifest(conn, "group:web", _KEY_A, generated_at=_FIXED_TS)

    _seed_deployed_rule(conn, "rule-002", "group:web")
    m2 = build_manifest(conn, "group:web", _KEY_A, generated_at=_FIXED_TS)

    assert m1["manifest_id"] != m2["manifest_id"]


def test_build_manifest_required_fields(conn):
    """Manifest dict contains all required top-level fields."""
    manifest = build_manifest(conn, "group:web", _KEY_A, generated_at=_FIXED_TS)
    for field in ("version", "manifest_id", "tag", "generated_at", "rules", "signature"):
        assert field in manifest, f"missing field: {field}"


def test_build_manifest_rule_entry_fields(conn):
    """Each rule entry contains the required fields."""
    _seed_deployed_rule(conn, "rule-001", "group:web", rule_type="sigma")
    manifest = build_manifest(conn, "group:web", _KEY_A, generated_at=_FIXED_TS)
    assert len(manifest["rules"]) == 1
    rule = manifest["rules"][0]
    for field in ("id", "rule_type", "name", "content", "syntax_valid"):
        assert field in rule, f"rule entry missing field: {field}"
    assert rule["rule_type"] == "sigma"


def test_build_manifest_scoped_by_tag(conn):
    """Rules tagged for 'group:db' do not appear in 'group:web' manifest."""
    _seed_deployed_rule(conn, "web-rule", "group:web")
    _seed_deployed_rule(conn, "db-rule", "group:db")

    web_manifest = build_manifest(conn, "group:web", _KEY_A, generated_at=_FIXED_TS)
    db_manifest = build_manifest(conn, "group:db", _KEY_A, generated_at=_FIXED_TS)

    web_ids = {r["id"] for r in web_manifest["rules"]}
    db_ids = {r["id"] for r in db_manifest["rules"]}

    assert "web-rule" in web_ids
    assert "db-rule" not in web_ids
    assert "db-rule" in db_ids
    assert "web-rule" not in db_ids
