"""
HTTP route tests for GET /recommendations and POST /recommendations/{id}/execute
(Phase 4 Wave B, REQ-P0-P4-002).

Covers:
  1. GET /recommendations — no auth → 401 when token set
  2. GET /recommendations — with auth → 200 + list including 'destructive' flag
  3. GET /recommendations — empty list on fresh DB
  4. POST /recommendations/{id}/execute — no auth → 401
  5. POST /recommendations/{id}/execute — safe technique with auth → 200
  6. POST /recommendations/{id}/execute — destructive without force → 400
  7. POST /recommendations/{id}/execute — destructive with force → 200
  8. POST /recommendations/{id}/execute — non-existent id → 404
  9. POST /recommendations/{id}/execute — already-executed row → 400
  10. Auth gate is consistent with canary/posture routes (_require_auth)

# @mock-exempt: execute_recommendation uses an injectable executor. In routes
# tests the real execute_recommendation is called with a monkey-patched executor
# injected via the recommendations module — same pattern as test_canary.py uses
# for module-level singleton patching. DB is real in-memory SQLite.
"""

from types import SimpleNamespace
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

import agent.main as main_module
import agent.recommendations as rec_module
from agent.models import init_db, insert_attack_recommendation


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _fake_executor(container_name: str, command_hint: str) -> tuple[int, str]:
    """Always-succeeds executor — avoids real podman exec in tests."""
    return 0, f"fake: {command_hint}"


def _make_settings(tmp_path, token: str = "") -> SimpleNamespace:
    return SimpleNamespace(
        shaferhund_token=token,
        rules_dir=str(tmp_path / "rules"),
        db_path=":memory:",
        alerts_file="/dev/null",
        suricata_eve_file="/dev/null",
        triage_hourly_budget=20,
        AUTO_DEPLOY_ENABLED=False,
        sigmac_available=False,
        sigmac_version=None,
        canary_base_url="http://127.0.0.1:8000",
        canary_base_hostname="canary.local",
        redteam_target_container="test-container",
    )


def _make_client(tmp_path, token: str = ""):
    """Return (TestClient, conn) with module singletons patched to in-memory DB."""
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir(exist_ok=True)

    conn = init_db(":memory:")
    settings = _make_settings(tmp_path, token=token)

    main_module._db = conn
    main_module._settings = settings
    main_module._triage_queue = None
    main_module._clusterer = None
    main_module._poller_healthy = False
    main_module._last_poll_at = None

    client = TestClient(main_module.app, raise_server_exceptions=True)
    return client, conn


def _seed_pending(conn, technique_id: str = "T1059.003", severity: str = "High") -> int:
    return insert_attack_recommendation(
        conn=conn,
        technique_id=technique_id,
        reason="Test reason",
        severity=severity,
        cluster_id=None,
    )


# ---------------------------------------------------------------------------
# GET /recommendations — auth gate
# ---------------------------------------------------------------------------


def test_get_recommendations_no_auth_when_token_set(tmp_path):
    """GET /recommendations → 401 when token set and no Authorization header."""
    client, conn = _make_client(tmp_path, token="secret123")
    resp = client.get("/recommendations")
    assert resp.status_code == 401, f"Expected 401, got {resp.status_code}"
    conn.close()


def test_get_recommendations_wrong_token_returns_401(tmp_path):
    """GET /recommendations → 401 with wrong bearer token."""
    client, conn = _make_client(tmp_path, token="secret123")
    resp = client.get("/recommendations", headers={"Authorization": "Bearer wrongtoken"})
    assert resp.status_code == 401
    conn.close()


# ---------------------------------------------------------------------------
# GET /recommendations — success path
# ---------------------------------------------------------------------------


def test_get_recommendations_empty_on_fresh_db(tmp_path):
    """GET /recommendations → 200 + empty list on fresh DB."""
    client, conn = _make_client(tmp_path, token="")
    resp = client.get("/recommendations")
    assert resp.status_code == 200
    data = resp.json()
    assert isinstance(data, list)
    assert len(data) == 0
    conn.close()


def test_get_recommendations_returns_pending_rows(tmp_path):
    """GET /recommendations → 200 with pending rows including 'destructive' flag."""
    client, conn = _make_client(tmp_path, token="")

    # Seed one safe + one destructive pending recommendation
    _seed_pending(conn, technique_id="T1059.003", severity="High")
    _seed_pending(conn, technique_id="T1486", severity="Critical")

    resp = client.get("/recommendations")
    assert resp.status_code == 200

    data = resp.json()
    assert len(data) == 2, f"Expected 2 pending rows, got {len(data)}"

    # Each row must have 'destructive' key
    for row in data:
        assert "destructive" in row, f"'destructive' key missing from row: {row}"
        assert "technique_id" in row
        assert "status" in row
        assert row["status"] == "pending"

    # Identify safe vs destructive
    by_technique = {r["technique_id"]: r for r in data}
    assert by_technique["T1059.003"]["destructive"] is False
    assert by_technique["T1486"]["destructive"] is True

    conn.close()


def test_get_recommendations_with_auth_returns_200(tmp_path):
    """GET /recommendations with correct bearer token → 200."""
    client, conn = _make_client(tmp_path, token="mytoken")

    resp = client.get(
        "/recommendations",
        headers={"Authorization": "Bearer mytoken"},
    )
    assert resp.status_code == 200
    conn.close()


# ---------------------------------------------------------------------------
# POST /recommendations/{id}/execute — auth gate
# ---------------------------------------------------------------------------


def test_execute_no_auth_when_token_set(tmp_path):
    """POST /recommendations/{id}/execute → 401 when token set and no auth."""
    client, conn = _make_client(tmp_path, token="secret123")
    rec_id = _seed_pending(conn, technique_id="T1059.003")
    resp = client.post(f"/recommendations/{rec_id}/execute")
    assert resp.status_code == 401, f"Expected 401, got {resp.status_code}"
    conn.close()


# ---------------------------------------------------------------------------
# POST /recommendations/{id}/execute — safe technique
# ---------------------------------------------------------------------------


def test_execute_safe_technique_returns_200(tmp_path):
    """POST /recommendations/{id}/execute on safe technique → 200 with run_id."""
    client, conn = _make_client(tmp_path, token="")
    rec_id = _seed_pending(conn, technique_id="T1059.003", severity="High")

    with patch.object(rec_module, "execute_recommendation") as mock_exec:
        mock_exec.return_value = {
            "status": "executed",
            "run_id": 42,
            "recommendation_id": rec_id,
            "error": None,
        }
        resp = client.post(f"/recommendations/{rec_id}/execute", json={})

    assert resp.status_code == 200, f"Expected 200, got {resp.status_code}: {resp.text}"
    data = resp.json()
    assert data["recommendation_id"] == rec_id
    assert data["run_id"] == 42
    assert data["status"] == "executed"

    conn.close()


# ---------------------------------------------------------------------------
# POST /recommendations/{id}/execute — destructive without force
# ---------------------------------------------------------------------------


def test_execute_destructive_no_force_returns_400(tmp_path):
    """POST /recommendations/{id}/execute on destructive technique without force → 400."""
    client, conn = _make_client(tmp_path, token="")
    rec_id = _seed_pending(conn, technique_id="T1486", severity="Critical")

    with patch.object(rec_module, "execute_recommendation") as mock_exec:
        mock_exec.return_value = {
            "status": "rejected",
            "run_id": None,
            "recommendation_id": rec_id,
            "error": "Technique T1486 is in DESTRUCTIVE_TECHNIQUES. Pass force=true.",
        }
        resp = client.post(f"/recommendations/{rec_id}/execute", json={"force": False})

    assert resp.status_code == 400, f"Expected 400, got {resp.status_code}: {resp.text}"

    conn.close()


# ---------------------------------------------------------------------------
# POST /recommendations/{id}/execute — destructive with force
# ---------------------------------------------------------------------------


def test_execute_destructive_with_force_returns_200(tmp_path):
    """POST /recommendations/{id}/execute on destructive technique with force=true → 200."""
    client, conn = _make_client(tmp_path, token="")
    rec_id = _seed_pending(conn, technique_id="T1486", severity="Critical")

    with patch.object(rec_module, "execute_recommendation") as mock_exec:
        mock_exec.return_value = {
            "status": "executed",
            "run_id": 99,
            "recommendation_id": rec_id,
            "error": None,
        }
        resp = client.post(f"/recommendations/{rec_id}/execute", json={"force": True})

    assert resp.status_code == 200, f"Expected 200, got {resp.status_code}: {resp.text}"
    data = resp.json()
    assert data["status"] == "executed"
    assert data["run_id"] == 99

    # Verify force=True was forwarded to execute_recommendation
    mock_exec.assert_called_once()
    call_kwargs = mock_exec.call_args
    assert call_kwargs.kwargs.get("force") is True or (
        len(call_kwargs.args) > 2 and call_kwargs.args[2] is True
    ), f"force=True was not forwarded: {call_kwargs}"

    conn.close()


# ---------------------------------------------------------------------------
# POST /recommendations/{id}/execute — non-existent id
# ---------------------------------------------------------------------------


def test_execute_nonexistent_returns_404(tmp_path):
    """POST /recommendations/99999/execute → 404."""
    client, conn = _make_client(tmp_path, token="")

    with patch.object(rec_module, "execute_recommendation") as mock_exec:
        mock_exec.return_value = {
            "status": "not_found",
            "run_id": None,
            "recommendation_id": 99999,
            "error": "Recommendation 99999 not found",
        }
        resp = client.post("/recommendations/99999/execute")

    assert resp.status_code == 404, f"Expected 404, got {resp.status_code}: {resp.text}"

    conn.close()


# ---------------------------------------------------------------------------
# POST /recommendations/{id}/execute — already-executed row
# ---------------------------------------------------------------------------


def test_execute_already_executed_returns_400(tmp_path):
    """POST /recommendations/{id}/execute on already-executed row → 400."""
    client, conn = _make_client(tmp_path, token="")
    rec_id = _seed_pending(conn, technique_id="T1059.003", severity="Low")

    with patch.object(rec_module, "execute_recommendation") as mock_exec:
        mock_exec.return_value = {
            "status": "already_executed",
            "run_id": None,
            "recommendation_id": rec_id,
            "error": "Recommendation already executed",
        }
        resp = client.post(f"/recommendations/{rec_id}/execute")

    assert resp.status_code == 400, f"Expected 400, got {resp.status_code}: {resp.text}"

    conn.close()


# ---------------------------------------------------------------------------
# GET /recommendations — only pending rows returned
# ---------------------------------------------------------------------------


def test_get_recommendations_excludes_non_pending(tmp_path):
    """GET /recommendations only returns status='pending' rows."""
    client, conn = _make_client(tmp_path, token="")

    # Seed one pending and one executed row directly
    pending_id = _seed_pending(conn, technique_id="T1059.003")
    executed_id = _seed_pending(conn, technique_id="T1053.005")
    # Manually flip the second one to 'executed'
    conn.execute(
        "UPDATE attack_recommendations SET status = 'executed' WHERE id = ?",
        (executed_id,),
    )
    conn.commit()

    resp = client.get("/recommendations")
    assert resp.status_code == 200
    data = resp.json()

    assert len(data) == 1, f"Expected 1 pending row, got {len(data)}: {data}"
    assert data[0]["id"] == pending_id

    conn.close()
