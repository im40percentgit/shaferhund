"""
Integration tests for the fleet client end-to-end path (Phase 6 Wave B2).

Exercises the full path: manager manifest endpoint → fetch_manifest →
verify_and_apply → rule files on disk. Uses a FastAPI TestClient against the
real agent.main app so no external process is required.

Unlike the LocalStack integration tests (test_cloudtrail_localstack.py), this
test is self-contained — it does not require any running service. The only
"integration" aspect is that it exercises the real HTTP layer (TestClient)
rather than mocking httpx.

Gated by -m integration so the default pytest suite never runs this:
    pytest -m integration tests/integration/

@decision DEC-FLEET-P6-005
@title LocalStack-style integration test; gated by -m integration; no external service needed
@status accepted
@rationale The fleet client's unit tests mock httpx. This integration test uses a real
           FastAPI TestClient so it exercises the full request → response path including
           auth, HMAC signing, and the manifest route. It is in tests/integration/ and
           marked with @pytest.mark.integration so the default suite (addopts = -m
           "not integration") never picks it up. Consistent with DEC-CLOUD-013.
"""

import os
import sqlite3
import tempfile
from pathlib import Path

import pytest

# ---------------------------------------------------------------------------
# Integration marker — guards for skip when running default suite
# ---------------------------------------------------------------------------

pytestmark = pytest.mark.integration

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_HMAC_KEY_HEX = "aa" * 32
_HMAC_KEY = bytes.fromhex(_HMAC_KEY_HEX)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def fleet_env(tmp_path_factory):
    """Set env vars + bootstrap a TestClient against agent.main.

    Yields (client, admin_token, rules_dir_path).
    """
    db_path = str(tmp_path_factory.mktemp("fleet_int") / "integration.db")

    # Remove any stale DB from a previous run
    if os.path.exists(db_path):
        os.remove(db_path)

    # Set env BEFORE importing agent.main so Settings picks them up
    os.environ["DB_PATH"] = db_path
    os.environ["ANTHROPIC_API_KEY"] = "sk-ant-test-dummy"
    os.environ["SHAFERHUND_AUTH_MODE"] = "multi"
    os.environ["SHAFERHUND_AUDIT_KEY"] = _HMAC_KEY_HEX
    os.environ["SHAFERHUND_BOOTSTRAP_ADMIN_USERNAME"] = "admin"
    os.environ["SHAFERHUND_BOOTSTRAP_ADMIN_PASSWORD"] = "adminpw123"

    from fastapi.testclient import TestClient
    from agent.main import app

    with TestClient(app) as client:
        # Login as bootstrap admin
        resp = client.post(
            "/auth/login",
            json={"username": "admin", "password": "adminpw123"},
        )
        assert resp.status_code == 200, f"Login failed: {resp.text}"
        admin_token = resp.json()["token"]

        rules_dir = tmp_path_factory.mktemp("rules")
        yield client, admin_token, rules_dir


# ---------------------------------------------------------------------------
# Helper: seed a deployed+tagged rule via the DB directly
# ---------------------------------------------------------------------------

def _seed_rule_direct(db_path: str, rule_id: str, tag: str, rule_type: str = "yara") -> None:
    """Insert a deployed rule + tag it directly in the DB."""
    from agent.models import insert_rule, tag_rule
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    # Idempotent — skip if already exists
    existing = conn.execute("SELECT id FROM rules WHERE id=?", (rule_id,)).fetchone()
    if existing is None:
        conn.execute(
            "INSERT INTO rules (id, cluster_id, rule_type, rule_content, syntax_valid, deployed)"
            " VALUES (?, NULL, ?, ?, 1, 1)",
            (rule_id, rule_type, f"rule {rule_id} {{}}"),
        )
        conn.commit()
    tag_rule(conn, rule_id, tag)
    conn.close()


# ---------------------------------------------------------------------------
# Test 1: run_once writes rule file for a tagged+deployed rule
# ---------------------------------------------------------------------------

@pytest.mark.integration
def test_fleet_client_run_once_writes_rule(fleet_env):
    """Seed a deployed YARA rule, fetch manifest via TestClient, verify+apply.

    Asserts: rule file written to tmp rules_dir with .yar extension.
    """
    client, admin_token, rules_dir = fleet_env
    db_path = os.environ["DB_PATH"]
    rule_id = "integ-test-rule-001"
    tag = "edr-prod"

    # Seed rule directly in DB
    _seed_rule_direct(db_path, rule_id, tag, rule_type="yara")

    # Fetch the manifest via the TestClient URL
    manifest_resp = client.get(
        f"/fleet/manifest/{tag}",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert manifest_resp.status_code == 200, f"Manifest fetch failed: {manifest_resp.text}"
    manifest = manifest_resp.json()

    # Verify the rule is in the manifest
    rule_ids = [r["id"] for r in manifest.get("rules", [])]
    assert rule_id in rule_ids, f"Expected {rule_id!r} in manifest rules; got {rule_ids}"

    # verify_and_apply against the tmp rules_dir
    from agent.fleet_client import verify_and_apply
    summary = verify_and_apply(manifest, _HMAC_KEY, str(rules_dir))

    assert summary["rules_written"] >= 1
    assert summary["manifest_id"] == manifest["manifest_id"]
    assert Path(rules_dir / f"{rule_id}.yar").exists(), (
        f"Expected {rule_id}.yar in {list(rules_dir.iterdir())}"
    )


# ---------------------------------------------------------------------------
# Test 2: Untagged rule is removed from rules_dir on next pull
# ---------------------------------------------------------------------------

@pytest.mark.integration
def test_fleet_client_stale_rule_removed_when_untagged(fleet_env):
    """After a rule is untagged on the manager, the next apply removes the file.

    Sequence:
    1. Seed rule-002 tagged edr-prod2 — verify_and_apply writes it.
    2. Untag rule-002 from edr-prod2 — manifest becomes empty.
    3. verify_and_apply again — file for rule-002 is removed.
    """
    client, admin_token, rules_dir = fleet_env
    db_path = os.environ["DB_PATH"]
    rule_id = "integ-test-rule-002"
    tag = "edr-prod2"

    # Step 1: seed + apply
    _seed_rule_direct(db_path, rule_id, tag, rule_type="sigma")

    manifest_resp = client.get(
        f"/fleet/manifest/{tag}",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert manifest_resp.status_code == 200
    manifest = manifest_resp.json()
    assert any(r["id"] == rule_id for r in manifest.get("rules", [])), (
        "Rule should appear in manifest before untagging"
    )

    from agent.fleet_client import verify_and_apply

    # Write the rule file
    local_rules = rules_dir / "stale_test"
    local_rules.mkdir(exist_ok=True)
    verify_and_apply(manifest, _HMAC_KEY, str(local_rules))
    assert Path(local_rules / f"{rule_id}.yml").exists()

    # Step 2: untag via DB directly (no untag route exists yet — model layer)
    conn = sqlite3.connect(db_path)
    conn.execute("DELETE FROM rule_tags WHERE rule_id=? AND tag=?", (rule_id, tag))
    conn.commit()
    conn.close()

    # Step 3: fetch manifest again — rule should be gone; apply removes file
    manifest_resp2 = client.get(
        f"/fleet/manifest/{tag}",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert manifest_resp2.status_code == 200
    manifest2 = manifest_resp2.json()
    assert not any(r["id"] == rule_id for r in manifest2.get("rules", [])), (
        "Untagged rule should not appear in manifest"
    )

    summary2 = verify_and_apply(manifest2, _HMAC_KEY, str(local_rules))
    assert summary2["rules_removed"] >= 1
    assert not Path(local_rules / f"{rule_id}.yml").exists(), (
        "Stale rule file should have been removed after untagging"
    )


# ---------------------------------------------------------------------------
# Test 3: Tampered manifest is rejected; no files are written
# ---------------------------------------------------------------------------

@pytest.mark.integration
def test_fleet_client_tampered_manifest_rejected(fleet_env):
    """Manifest with corrupted signature is rejected before any file write."""
    client, admin_token, rules_dir = fleet_env
    db_path = os.environ["DB_PATH"]
    _seed_rule_direct(db_path, "integ-test-rule-003", "tamper-tag", rule_type="yara")

    manifest_resp = client.get(
        "/fleet/manifest/tamper-tag",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert manifest_resp.status_code == 200
    manifest = manifest_resp.json()

    # Tamper the signature
    manifest["signature"] = "0" * 64

    local_rules = rules_dir / "tamper_test"
    local_rules.mkdir(exist_ok=True)

    from agent.fleet_client import verify_and_apply
    with pytest.raises(ValueError, match="signature verification failed"):
        verify_and_apply(manifest, _HMAC_KEY, str(local_rules))

    # No files should have been written
    written = list(local_rules.iterdir())
    assert written == [], f"No files should be written after rejection; got {written}"
