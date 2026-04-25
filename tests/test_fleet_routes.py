"""
Integration tests for Phase 6 Wave A4 fleet manifest routes.

Tests use FastAPI TestClient against a real SQLite DB.  Auth is exercised
via real user/token rows — no mocks for internal auth (Sacred Practice #5).

Routes under test:
  GET  /fleet/manifest/{tag}        — operator
  POST /rules/{rule_id}/tag         — operator
  DELETE /rules/{rule_id}/tag/{tag} — operator
  GET  /rules/{rule_id}/tags        — viewer
  GET  /tags                        — viewer

REQ-P0-P6-001 / DEC-FLEET-P6-001 / DEC-FLEET-P6-002
"""
import os
import pytest

from fastapi.testclient import TestClient

from agent.auth import generate_token, hash_password
from agent.fleet import verify_manifest
from agent.models import (
    init_db,
    insert_rule,
    insert_user,
    insert_user_token,
    tag_rule,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

AUDIT_KEY_HEX = "aa" * 32  # 32-byte key as hex string


@pytest.fixture()
def db_path(tmp_path):
    return str(tmp_path / "fleet_routes.db")


@pytest.fixture()
def test_client(db_path, monkeypatch):
    """Return a TestClient with multi-mode auth and a real DB.

    Sets environment before importing app so Settings picks up the values.
    """
    monkeypatch.setenv("DB_PATH", db_path)
    monkeypatch.setenv("SHAFERHUND_AUTH_MODE", "multi")
    monkeypatch.setenv("SHAFERHUND_AUDIT_KEY", AUDIT_KEY_HEX)
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-test-dummy")
    monkeypatch.delenv("SHAFERHUND_TOKEN", raising=False)

    from agent.main import app
    with TestClient(app, raise_server_exceptions=True) as client:
        yield client


@pytest.fixture()
def db(db_path):
    """Direct DB connection for seeding data outside the app."""
    conn = init_db(db_path)
    yield conn
    conn.close()


def _create_user_with_token(db, username, role):
    """Create a user + token, return the raw bearer string."""
    uid = insert_user(db, username=username, password_hash=hash_password("pass"), role=role)
    raw, token_hash = generate_token()
    insert_user_token(db, user_id=uid, token_hash=token_hash, name=f"{username}-token", expires_at=None)
    return raw


def _seed_deployed_rule(db, rule_id="rule-001", tag="group:web"):
    """Insert a deployed rule and tag it, return rule_id.

    cluster_id=None avoids FK constraint — NULL is always valid for nullable
    FK columns in SQLite even with foreign_keys=ON.
    """
    insert_rule(
        db,
        rule_id=rule_id,
        cluster_id=None,
        rule_type="yara",
        rule_content=f"rule {rule_id} {{}}",
        syntax_valid=True,
    )
    db.execute("UPDATE rules SET deployed = 1 WHERE id = ?", (rule_id,))
    db.commit()
    if tag:
        tag_rule(db, rule_id, tag)
    return rule_id


def _seed_undeployed_rule(db, rule_id="rule-draft", tag="group:web"):
    insert_rule(
        db,
        rule_id=rule_id,
        cluster_id=None,
        rule_type="yara",
        rule_content="rule draft {}",
        syntax_valid=False,
    )
    # deployed stays 0 (default)
    if tag:
        tag_rule(db, rule_id, tag)
    return rule_id


# ---------------------------------------------------------------------------
# GET /fleet/manifest/{tag} — auth gate
# ---------------------------------------------------------------------------

def test_fleet_manifest_no_auth(test_client):
    r = test_client.get("/fleet/manifest/group:web")
    assert r.status_code == 401


def test_fleet_manifest_viewer_is_forbidden(test_client, db):
    viewer_token = _create_user_with_token(db, "viewer1", "viewer")
    r = test_client.get(
        "/fleet/manifest/group:web",
        headers={"Authorization": f"Bearer {viewer_token}"},
    )
    assert r.status_code == 403


def test_fleet_manifest_operator_allowed(test_client, db):
    op_token = _create_user_with_token(db, "op1", "operator")
    r = test_client.get(
        "/fleet/manifest/group:web",
        headers={"Authorization": f"Bearer {op_token}"},
    )
    assert r.status_code == 200


def test_fleet_manifest_admin_allowed(test_client, db):
    admin_token = _create_user_with_token(db, "admin1", "admin")
    r = test_client.get(
        "/fleet/manifest/group:web",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert r.status_code == 200


# ---------------------------------------------------------------------------
# GET /fleet/manifest/{tag} — content
# ---------------------------------------------------------------------------

def test_fleet_manifest_empty_tag_returns_valid_manifest(test_client, db):
    """Empty tag → valid manifest with empty rules list and valid signature."""
    op_token = _create_user_with_token(db, "op2", "operator")
    r = test_client.get(
        "/fleet/manifest/group:empty",
        headers={"Authorization": f"Bearer {op_token}"},
    )
    assert r.status_code == 200
    m = r.json()
    assert m["version"] == 1
    assert m["tag"] == "group:empty"
    assert m["rules"] == []
    assert "signature" in m
    assert "manifest_id" in m


def test_fleet_manifest_includes_deployed_rule(test_client, db):
    """Tagged deployed rule appears in manifest response."""
    _seed_deployed_rule(db, "rule-001", "group:web")
    op_token = _create_user_with_token(db, "op3", "operator")

    r = test_client.get(
        "/fleet/manifest/group:web",
        headers={"Authorization": f"Bearer {op_token}"},
    )
    assert r.status_code == 200
    m = r.json()
    assert len(m["rules"]) == 1
    assert m["rules"][0]["id"] == "rule-001"


def test_fleet_manifest_excludes_undeployed_rule(test_client, db):
    """Tagged but undeployed rule must NOT appear in manifest (DEC-FLEET-P6-002)."""
    _seed_undeployed_rule(db, "rule-draft", "group:web")
    op_token = _create_user_with_token(db, "op4", "operator")

    r = test_client.get(
        "/fleet/manifest/group:web",
        headers={"Authorization": f"Bearer {op_token}"},
    )
    assert r.status_code == 200
    assert r.json()["rules"] == []


def test_fleet_manifest_signature_verifies(test_client, db):
    """Manifest signature verifies correctly using the audit key."""
    _seed_deployed_rule(db, "rule-001", "group:web")
    op_token = _create_user_with_token(db, "op5", "operator")

    r = test_client.get(
        "/fleet/manifest/group:web",
        headers={"Authorization": f"Bearer {op_token}"},
    )
    assert r.status_code == 200
    manifest = r.json()
    key_bytes = bytes.fromhex(AUDIT_KEY_HEX)
    assert verify_manifest(manifest, key_bytes) is True


def test_fleet_manifest_signature_fails_wrong_key(test_client, db):
    """Manifest signature does not verify with a different key."""
    _seed_deployed_rule(db, "rule-001", "group:web")
    op_token = _create_user_with_token(db, "op6", "operator")

    r = test_client.get(
        "/fleet/manifest/group:web",
        headers={"Authorization": f"Bearer {op_token}"},
    )
    manifest = r.json()
    wrong_key = bytes.fromhex("bb" * 32)
    assert verify_manifest(manifest, wrong_key) is False


# ---------------------------------------------------------------------------
# POST /rules/{rule_id}/tag — round-trip
# ---------------------------------------------------------------------------

def test_tag_route_no_auth(test_client):
    r = test_client.post("/rules/rule-001/tag", json={"tag": "group:web"})
    assert r.status_code == 401


def test_tag_route_viewer_is_forbidden(test_client, db):
    viewer_token = _create_user_with_token(db, "viewer2", "viewer")
    r = test_client.post(
        "/rules/rule-001/tag",
        json={"tag": "group:web"},
        headers={"Authorization": f"Bearer {viewer_token}"},
    )
    assert r.status_code == 403


def test_tag_route_operator_can_tag(test_client, db):
    _seed_deployed_rule(db, "rule-001", tag=None)
    op_token = _create_user_with_token(db, "op7", "operator")

    r = test_client.post(
        "/rules/rule-001/tag",
        json={"tag": "group:web"},
        headers={"Authorization": f"Bearer {op_token}"},
    )
    assert r.status_code == 200
    body = r.json()
    assert "group:web" in body["tags"]


def test_tag_then_manifest_roundtrip(test_client, db):
    """POST /rules/{id}/tag → GET /fleet/manifest/{tag} returns the rule."""
    _seed_deployed_rule(db, "rule-rt", tag=None)
    op_token = _create_user_with_token(db, "op8", "operator")
    auth = {"Authorization": f"Bearer {op_token}"}

    # Tag the rule
    r = test_client.post("/rules/rule-rt/tag", json={"tag": "group:roundtrip"}, headers=auth)
    assert r.status_code == 200

    # Manifest should now include the rule
    r2 = test_client.get("/fleet/manifest/group:roundtrip", headers=auth)
    assert r2.status_code == 200
    ids = {rule["id"] for rule in r2.json()["rules"]}
    assert "rule-rt" in ids


def test_tag_route_missing_tag_field(test_client, db):
    op_token = _create_user_with_token(db, "op9", "operator")
    r = test_client.post(
        "/rules/rule-001/tag",
        json={"wrong_field": "x"},
        headers={"Authorization": f"Bearer {op_token}"},
    )
    assert r.status_code == 400


# ---------------------------------------------------------------------------
# DELETE /rules/{rule_id}/tag/{tag}
# ---------------------------------------------------------------------------

def test_untag_route_no_auth(test_client):
    r = test_client.delete("/rules/rule-001/tag/group:web")
    assert r.status_code == 401


def test_untag_route_viewer_is_forbidden(test_client, db):
    viewer_token = _create_user_with_token(db, "viewer3", "viewer")
    r = test_client.delete(
        "/rules/rule-001/tag/group:web",
        headers={"Authorization": f"Bearer {viewer_token}"},
    )
    assert r.status_code == 403


def test_untag_then_manifest_roundtrip(test_client, db):
    """DELETE /rules/{id}/tag/{tag} → rule no longer in manifest."""
    _seed_deployed_rule(db, "rule-ut", "group:untag")
    op_token = _create_user_with_token(db, "op10", "operator")
    auth = {"Authorization": f"Bearer {op_token}"}

    # Confirm rule is in manifest before untag
    r = test_client.get("/fleet/manifest/group:untag", headers=auth)
    assert any(rule["id"] == "rule-ut" for rule in r.json()["rules"])

    # Untag
    r2 = test_client.delete("/rules/rule-ut/tag/group:untag", headers=auth)
    assert r2.status_code == 200
    assert r2.json()["tags"] == []

    # Manifest should no longer contain the rule
    r3 = test_client.get("/fleet/manifest/group:untag", headers=auth)
    assert r3.json()["rules"] == []


# ---------------------------------------------------------------------------
# GET /rules/{rule_id}/tags
# ---------------------------------------------------------------------------

def test_get_rule_tags_no_auth(test_client):
    r = test_client.get("/rules/rule-001/tags")
    assert r.status_code == 401


def test_get_rule_tags_viewer_allowed(test_client, db):
    _seed_deployed_rule(db, "rule-001", "group:web")
    viewer_token = _create_user_with_token(db, "viewer4", "viewer")

    r = test_client.get(
        "/rules/rule-001/tags",
        headers={"Authorization": f"Bearer {viewer_token}"},
    )
    assert r.status_code == 200
    assert "group:web" in r.json()["tags"]


def test_get_rule_tags_empty(test_client, db):
    _seed_deployed_rule(db, "rule-notag", tag=None)
    viewer_token = _create_user_with_token(db, "viewer5", "viewer")

    r = test_client.get(
        "/rules/rule-notag/tags",
        headers={"Authorization": f"Bearer {viewer_token}"},
    )
    assert r.status_code == 200
    assert r.json()["tags"] == []


# ---------------------------------------------------------------------------
# GET /tags
# ---------------------------------------------------------------------------

def test_get_all_tags_no_auth(test_client):
    r = test_client.get("/tags")
    assert r.status_code == 401


def test_get_all_tags_viewer_allowed(test_client, db):
    _seed_deployed_rule(db, "rule-001", "group:web")
    _seed_deployed_rule(db, "rule-002", "group:db")
    viewer_token = _create_user_with_token(db, "viewer6", "viewer")

    r = test_client.get(
        "/tags",
        headers={"Authorization": f"Bearer {viewer_token}"},
    )
    assert r.status_code == 200
    tags_by_name = {t["tag"]: t["rule_count"] for t in r.json()["tags"]}
    assert "group:web" in tags_by_name
    assert "group:db" in tags_by_name


def test_get_all_tags_empty(test_client, db):
    viewer_token = _create_user_with_token(db, "viewer7", "viewer")

    r = test_client.get(
        "/tags",
        headers={"Authorization": f"Bearer {viewer_token}"},
    )
    assert r.status_code == 200
    assert r.json()["tags"] == []
