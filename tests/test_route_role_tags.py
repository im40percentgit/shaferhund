"""
Per-route RBAC matrix tests — REQ-P0-P6-004.

For each role-tagged route, verify:
  - insufficient role → 403
  - sufficient role → not 401/403 (role check passes; downstream may 503/422/404)

Routes covered (per Wave A2 RBAC table in main.py module docstring):
  viewer-required:  GET /metrics, GET /recommendations, GET /cloud/findings
  operator-required: POST /posture/run, POST /recommendations/{id}/execute,
                     POST /canary/spawn, POST /rules/{id}/deploy,
                     POST /rules/{id}/undo-deploy

Public routes (/health, /canary/hit/{token}) are not tested here — they need
no auth and are covered by existing test_health.py / test_canary.py.

# @mock-exempt: patch.object targets _settings and _db — module-level singletons
# in main.py. auth.py and role_satisfies() run against a real in-memory SQLite
# connection with no mocks.
"""

import pytest
from unittest.mock import patch
from fastapi.testclient import TestClient

from agent.auth import generate_token, hash_password
from agent.models import init_db, insert_user, insert_user_token


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def db(tmp_path):
    conn = init_db(str(tmp_path / "test.db"))
    yield conn
    conn.close()


@pytest.fixture()
def tokens(db):
    """Return {role: raw_bearer_token} for viewer, operator, admin."""
    result = {}
    for role in ("viewer", "operator", "admin"):
        ph = hash_password("hunter2")
        uid = insert_user(db, f"user_{role}", ph, role)
        raw, h = generate_token()
        insert_user_token(db, uid, h, f"{role}-tok")
        result[role] = raw
    return result


def _multi_client(db):
    """Context managers to patch _settings and _db for multi-auth mode."""
    import agent.main as main_mod
    from agent.config import Settings

    settings = Settings(
        anthropic_api_key="test-key",
        shaferhund_token="",
        shaferhund_auth_mode="multi",
    )
    return (
        patch.object(main_mod, "_settings", settings),
        patch.object(main_mod, "_db", db),
    )


def _get(client, path, token):
    return client.get(path, headers={"Authorization": f"Bearer {token}"})


def _post(client, path, token, json=None):
    return client.post(path, headers={"Authorization": f"Bearer {token}"}, json=json or {})


# ---------------------------------------------------------------------------
# viewer-required routes
# ---------------------------------------------------------------------------


class TestGetMetrics:
    def test_viewer_ok(self, db, tokens):
        import agent.main as main_mod
        p1, p2 = _multi_client(db)
        with p1, p2:
            c = TestClient(main_mod.app, raise_server_exceptions=True)
            assert _get(c, "/metrics", tokens["viewer"]).status_code == 200

    def test_operator_ok(self, db, tokens):
        import agent.main as main_mod
        p1, p2 = _multi_client(db)
        with p1, p2:
            c = TestClient(main_mod.app, raise_server_exceptions=True)
            assert _get(c, "/metrics", tokens["operator"]).status_code == 200

    def test_admin_ok(self, db, tokens):
        import agent.main as main_mod
        p1, p2 = _multi_client(db)
        with p1, p2:
            c = TestClient(main_mod.app, raise_server_exceptions=True)
            assert _get(c, "/metrics", tokens["admin"]).status_code == 200


class TestGetRecommendations:
    def test_viewer_ok(self, db, tokens):
        import agent.main as main_mod
        p1, p2 = _multi_client(db)
        with p1, p2:
            c = TestClient(main_mod.app, raise_server_exceptions=True)
            resp = _get(c, "/recommendations", tokens["viewer"])
            assert resp.status_code == 200

    def test_no_token_401(self, db, tokens):
        import agent.main as main_mod
        p1, p2 = _multi_client(db)
        with p1, p2:
            c = TestClient(main_mod.app, raise_server_exceptions=True)
            assert c.get("/recommendations").status_code == 401


class TestGetCloudFindings:
    def test_viewer_ok(self, db, tokens):
        import agent.main as main_mod
        p1, p2 = _multi_client(db)
        with p1, p2:
            c = TestClient(main_mod.app, raise_server_exceptions=True)
            resp = _get(c, "/cloud/findings", tokens["viewer"])
            assert resp.status_code == 200

    def test_operator_ok(self, db, tokens):
        import agent.main as main_mod
        p1, p2 = _multi_client(db)
        with p1, p2:
            c = TestClient(main_mod.app, raise_server_exceptions=True)
            resp = _get(c, "/cloud/findings", tokens["operator"])
            assert resp.status_code == 200

    def test_no_token_401(self, db, tokens):
        import agent.main as main_mod
        p1, p2 = _multi_client(db)
        with p1, p2:
            c = TestClient(main_mod.app, raise_server_exceptions=True)
            assert c.get("/cloud/findings").status_code == 401


# ---------------------------------------------------------------------------
# operator-required routes
# ---------------------------------------------------------------------------


class TestPostPostureRun:
    def test_viewer_403(self, db, tokens):
        import agent.main as main_mod
        p1, p2 = _multi_client(db)
        with p1, p2:
            c = TestClient(main_mod.app, raise_server_exceptions=True)
            resp = _post(c, "/posture/run", tokens["viewer"])
            assert resp.status_code == 403, (
                f"viewer on /posture/run: expected 403, got {resp.status_code}"
            )

    def test_operator_role_passes(self, db, tokens):
        import agent.main as main_mod
        p1, p2 = _multi_client(db)
        with p1, p2:
            c = TestClient(main_mod.app, raise_server_exceptions=True)
            resp = _post(c, "/posture/run", tokens["operator"])
            assert resp.status_code not in (401, 403), (
                f"operator on /posture/run: expected role to pass, got {resp.status_code}"
            )

    def test_admin_role_passes(self, db, tokens):
        import agent.main as main_mod
        p1, p2 = _multi_client(db)
        with p1, p2:
            c = TestClient(main_mod.app, raise_server_exceptions=True)
            resp = _post(c, "/posture/run", tokens["admin"])
            assert resp.status_code not in (401, 403), (
                f"admin on /posture/run: expected role to pass, got {resp.status_code}"
            )

    def test_no_token_401(self, db, tokens):
        import agent.main as main_mod
        p1, p2 = _multi_client(db)
        with p1, p2:
            c = TestClient(main_mod.app, raise_server_exceptions=True)
            assert _post(c, "/posture/run", "bad-token").status_code == 401


class TestPostRecommendationExecute:
    """operator-required: POST /recommendations/{id}/execute"""

    def test_viewer_403(self, db, tokens):
        import agent.main as main_mod
        p1, p2 = _multi_client(db)
        with p1, p2:
            c = TestClient(main_mod.app, raise_server_exceptions=True)
            resp = _post(c, "/recommendations/1/execute", tokens["viewer"])
            assert resp.status_code == 403

    def test_operator_role_passes(self, db, tokens):
        import agent.main as main_mod
        p1, p2 = _multi_client(db)
        with p1, p2:
            c = TestClient(main_mod.app, raise_server_exceptions=True)
            resp = _post(c, "/recommendations/1/execute", tokens["operator"])
            # Role passes; 404 (rec not found) or 503 (db) is fine — not 401/403
            assert resp.status_code not in (401, 403), (
                f"operator on execute: expected role to pass, got {resp.status_code}"
            )

    def test_admin_role_passes(self, db, tokens):
        import agent.main as main_mod
        p1, p2 = _multi_client(db)
        with p1, p2:
            c = TestClient(main_mod.app, raise_server_exceptions=True)
            resp = _post(c, "/recommendations/1/execute", tokens["admin"])
            assert resp.status_code not in (401, 403)


class TestPostCanarySpawn:
    """operator-required: POST /canary/spawn"""

    def test_viewer_403(self, db, tokens):
        import agent.main as main_mod
        p1, p2 = _multi_client(db)
        with p1, p2:
            c = TestClient(main_mod.app, raise_server_exceptions=True)
            resp = _post(c, "/canary/spawn", tokens["viewer"], json={"type": "http", "name": "t"})
            assert resp.status_code == 403

    def test_operator_role_passes(self, db, tokens):
        import agent.main as main_mod
        p1, p2 = _multi_client(db)
        with p1, p2:
            c = TestClient(main_mod.app, raise_server_exceptions=True)
            resp = _post(c, "/canary/spawn", tokens["operator"], json={"type": "http", "name": "t"})
            assert resp.status_code not in (401, 403)


class TestPostRulesDeploy:
    """operator-required: POST /rules/{rule_id}/deploy"""

    def test_viewer_403(self, db, tokens):
        import agent.main as main_mod
        p1, p2 = _multi_client(db)
        with p1, p2:
            c = TestClient(main_mod.app, raise_server_exceptions=True)
            resp = _post(c, "/rules/nonexistent-rule/deploy", tokens["viewer"])
            assert resp.status_code == 403

    def test_operator_role_passes(self, db, tokens):
        import agent.main as main_mod
        p1, p2 = _multi_client(db)
        with p1, p2:
            c = TestClient(main_mod.app, raise_server_exceptions=True)
            resp = _post(c, "/rules/nonexistent-rule/deploy", tokens["operator"])
            # Role passes → 404 (rule not found) is fine
            assert resp.status_code not in (401, 403)


class TestPostRulesUndoDeploy:
    """operator-required: POST /rules/{rule_id}/undo-deploy"""

    def test_viewer_403(self, db, tokens):
        import agent.main as main_mod
        p1, p2 = _multi_client(db)
        with p1, p2:
            c = TestClient(main_mod.app, raise_server_exceptions=True)
            resp = _post(c, "/rules/nonexistent-rule/undo-deploy", tokens["viewer"])
            assert resp.status_code == 403

    def test_operator_role_passes(self, db, tokens):
        import agent.main as main_mod
        p1, p2 = _multi_client(db)
        with p1, p2:
            c = TestClient(main_mod.app, raise_server_exceptions=True)
            resp = _post(c, "/rules/nonexistent-rule/undo-deploy", tokens["operator"])
            # Role passes → 404 (file not found on disk) is fine
            assert resp.status_code not in (401, 403)


# ---------------------------------------------------------------------------
# Public routes stay public (DEC-HEALTH-002)
# ---------------------------------------------------------------------------


def test_health_public_no_auth_needed(db):
    """GET /health requires no token — always 200 regardless of auth state."""
    import agent.main as main_mod
    p1, p2 = _multi_client(db)
    with p1, p2:
        c = TestClient(main_mod.app, raise_server_exceptions=True)
        assert c.get("/health").status_code == 200


def test_canary_hit_public_no_auth_needed(db):
    """GET /canary/hit/{token} requires no token — public trap endpoint."""
    import agent.main as main_mod
    p1, p2 = _multi_client(db)
    with p1, p2:
        c = TestClient(main_mod.app, raise_server_exceptions=True)
        assert c.get("/canary/hit/sometoken").status_code == 200
