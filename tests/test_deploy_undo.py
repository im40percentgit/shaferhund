"""
Tests for POST /rules/{rule_id}/undo-deploy.

All tests use FastAPI TestClient with an in-memory SQLite DB and tmp_path
for the RULES_DIR so no real filesystem paths are touched outside of tmp_path.

Test cases:
  1. Happy path — file exists + deploy event → file deleted, reverted_at set.
  2. Auth required — missing token → 401, no state change.
  3. No file on disk — deploy event exists but file absent → 404, DB unchanged.
  4. Already reverted — pre-seeded reverted event + file present → 200 deletes
     file but returns 409 (no un-reverted event to stamp). Documented choice:
     409 signals "file was present and deleted but no audit row to update" so
     callers know the state is partially inconsistent and can investigate.
  5. Query-param token rejected — ?token=<correct> with no Authorization header
     → 401 (DEC-AUTH-002: query-param fallback removed to prevent token leakage
     via logs, browser history, and Referer headers).

@decision DEC-UNDO-002
@title test_deploy_undo covers happy path, auth, missing-file, already-reverted, query-param-rejected
@status accepted
@rationale Real DB (in-memory), real file I/O via tmp_path, no internal mocks.
           External boundary (auth dependency) exercised via HTTP headers.
           Five cases cover the four observable states of the undo endpoint plus
           regression coverage for the removed ?token= query-param fallback.
"""

from pathlib import Path
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient

from agent.models import (
    init_db,
    insert_rule,
    mark_rule_deployed,
    record_deploy_event,
    list_deploy_events,
    upsert_cluster,
)


# ---------------------------------------------------------------------------
# App fixture — override settings so routes use our tmp DB + rules dir
# ---------------------------------------------------------------------------


def _make_app(db_path: str, rules_dir: str, token: str = ""):
    """Return a TestClient for the Shaferhund FastAPI app with overridden settings.

    Uses SimpleNamespace instead of Settings to avoid requiring ANTHROPIC_API_KEY
    in CI — routes only read shaferhund_token and rules_dir from _settings.
    Pattern mirrors test_auto_deploy_integration.py.
    """
    import agent.main as main_module

    settings = SimpleNamespace(
        shaferhund_token=token,
        rules_dir=rules_dir,
        db_path=db_path,
        alerts_file="/dev/null",
        suricata_eve_file="/dev/null",
    )
    conn = init_db(db_path)

    original_db = main_module._db
    original_settings = main_module._settings

    main_module._db = conn
    main_module._settings = settings

    client = TestClient(main_module.app, raise_server_exceptions=True)

    return client, conn, settings, (original_db, original_settings, main_module)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _seed_cluster(conn, cluster_id: str = "cluster-undo-001") -> None:
    upsert_cluster(
        conn,
        cluster_id=cluster_id,
        src_ip="10.0.0.1",
        rule_id=9999,
        window_start="2026-01-01T00:00:00",
        window_end="2026-01-01T00:05:00",
        alert_count=1,
        source="wazuh",
    )


def _seed_rule(conn, rule_id: str, cluster_id: str = "cluster-undo-001") -> None:
    insert_rule(
        conn,
        rule_id=rule_id,
        cluster_id=cluster_id,
        rule_type="yara",
        rule_content='rule Test { strings: $s = "x" condition: $s }',
        syntax_valid=True,
    )
    mark_rule_deployed(conn, rule_id)


def _seed_deploy_event(conn, rule_id: str, already_reverted: bool = False) -> int:
    event_id = record_deploy_event(
        conn,
        rule_id=rule_id,
        action="auto-deploy",
        reason="ok",
        actor="orchestrator",
        rule_type="yara",
        src_ip="10.0.0.1",
    )
    if already_reverted:
        from agent.models import mark_deploy_reverted_by_rule
        mark_deploy_reverted_by_rule(conn, rule_id)
    return event_id


# ---------------------------------------------------------------------------
# Case 1: Happy path — file + deploy event present → 200, file gone, reverted_at set
# ---------------------------------------------------------------------------


def test_undo_deploy_happy_path(tmp_path):
    """Valid token + file present + un-reverted deploy event → 200, file deleted, DB updated."""
    db_path = str(tmp_path / "test.db")
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    token = "secret-token"
    rule_id = "rule-undo-happy-001"

    client, conn, _settings, (orig_db, orig_settings, main_module) = _make_app(
        db_path, str(rules_dir), token=token
    )

    _seed_cluster(conn)
    _seed_rule(conn, rule_id)
    _seed_deploy_event(conn, rule_id)

    # Write the rule file to disk
    rule_file = rules_dir / f"{rule_id}.yar"
    rule_file.write_text('rule Test { strings: $s = "x" condition: $s }')
    assert rule_file.exists()

    resp = client.post(
        f"/rules/{rule_id}/undo-deploy",
        headers={"Authorization": f"Bearer {token}"},
    )

    assert resp.status_code == 200, f"Expected 200, got {resp.status_code}: {resp.text}"
    body = resp.json()
    assert body["reverted"] is True
    assert rule_id in body["path"]

    # File must be gone
    assert not rule_file.exists(), "Rule file should be deleted after undo"

    # deploy_events.reverted_at must be set
    events = [dict(e) for e in list_deploy_events(conn)]
    auto_deploys = [e for e in events if e["action"] == "auto-deploy"]
    assert len(auto_deploys) == 1
    assert auto_deploys[0]["reverted_at"] is not None, "reverted_at should be set"

    main_module._db = orig_db
    main_module._settings = orig_settings
    conn.close()


# ---------------------------------------------------------------------------
# Case 2: Auth required — missing token → 401, no state change
# ---------------------------------------------------------------------------


def test_undo_deploy_requires_auth(tmp_path):
    """When SHAFERHUND_TOKEN is set, missing token → 401 and no state change."""
    db_path = str(tmp_path / "test.db")
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    token = "secret-token"
    rule_id = "rule-undo-auth-001"

    client, conn, _settings, (orig_db, orig_settings, main_module) = _make_app(
        db_path, str(rules_dir), token=token
    )

    _seed_cluster(conn)
    _seed_rule(conn, rule_id)
    _seed_deploy_event(conn, rule_id)

    rule_file = rules_dir / f"{rule_id}.yar"
    rule_file.write_text("content")

    # POST without Authorization header
    resp = client.post(f"/rules/{rule_id}/undo-deploy")

    assert resp.status_code == 401, f"Expected 401, got {resp.status_code}: {resp.text}"

    # File must still exist
    assert rule_file.exists(), "File should not be deleted when auth fails"

    # DB unchanged — no reverted_at
    events = [dict(e) for e in list_deploy_events(conn)]
    auto_deploys = [e for e in events if e["action"] == "auto-deploy"]
    assert all(e["reverted_at"] is None for e in auto_deploys)

    main_module._db = orig_db
    main_module._settings = orig_settings
    conn.close()


# ---------------------------------------------------------------------------
# Case 3: No file on disk → 404, DB NOT changed
# ---------------------------------------------------------------------------


def test_undo_deploy_no_file(tmp_path):
    """Deploy event exists but rule file is absent → 404, DB unchanged."""
    db_path = str(tmp_path / "test.db")
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    rule_id = "rule-undo-nofile-001"

    client, conn, _settings, (orig_db, orig_settings, main_module) = _make_app(
        db_path, str(rules_dir)
    )

    _seed_cluster(conn)
    _seed_rule(conn, rule_id)
    _seed_deploy_event(conn, rule_id)
    # Deliberately do NOT create the file on disk

    resp = client.post(f"/rules/{rule_id}/undo-deploy")

    assert resp.status_code == 404, f"Expected 404, got {resp.status_code}: {resp.text}"

    # DB must be unchanged — reverted_at still None
    events = [dict(e) for e in list_deploy_events(conn)]
    auto_deploys = [e for e in events if e["action"] == "auto-deploy"]
    assert all(e["reverted_at"] is None for e in auto_deploys), (
        "reverted_at should not be set when file was missing"
    )

    main_module._db = orig_db
    main_module._settings = orig_settings
    conn.close()


# ---------------------------------------------------------------------------
# Case 4: Already reverted — file present but no un-reverted event → 409
# ---------------------------------------------------------------------------


def test_undo_deploy_already_reverted(tmp_path):
    """File exists but deploy event already has reverted_at → file deleted, 409 returned.

    Design choice: 409 signals the file was deleted but no un-reverted audit
    row was found — the state is partially inconsistent (file existed on disk
    even though the audit said reverted).  Callers can inspect the audit log.
    The file is removed because leaving a 'should-be-reverted' file on disk
    is the more dangerous outcome.
    """
    db_path = str(tmp_path / "test.db")
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    rule_id = "rule-undo-already-001"

    client, conn, _settings, (orig_db, orig_settings, main_module) = _make_app(
        db_path, str(rules_dir)
    )

    _seed_cluster(conn)
    _seed_rule(conn, rule_id)
    _seed_deploy_event(conn, rule_id, already_reverted=True)

    rule_file = rules_dir / f"{rule_id}.yar"
    rule_file.write_text("content")

    resp = client.post(f"/rules/{rule_id}/undo-deploy")

    # File present but no un-reverted event → 409
    assert resp.status_code == 409, f"Expected 409, got {resp.status_code}: {resp.text}"
    # File should be gone (we delete before checking the audit row)
    assert not rule_file.exists(), "File should still be deleted in the 409 path"

    main_module._db = orig_db
    main_module._settings = orig_settings
    conn.close()


# ---------------------------------------------------------------------------
# Case 5: Query-param token rejected — ?token=<correct> → 401 (DEC-AUTH-002)
# ---------------------------------------------------------------------------


def test_query_param_token_rejected(tmp_path):
    """?token=<correct-token> with no Authorization header must return 401.

    The former query-param fallback was removed (DEC-AUTH-002) to prevent token
    leakage via uvicorn access logs, browser history, and Referer headers.
    Only Authorization: Bearer <token> is accepted.
    """
    db_path = str(tmp_path / "test.db")
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    token = "secret-token"
    rule_id = "rule-qp-reject-001"

    client, conn, _settings, (orig_db, orig_settings, main_module) = _make_app(
        db_path, str(rules_dir), token=token
    )

    _seed_cluster(conn)
    _seed_rule(conn, rule_id)
    _seed_deploy_event(conn, rule_id)

    rule_file = rules_dir / f"{rule_id}.yar"
    rule_file.write_text("content")

    # Correct token supplied only as a query param — must be rejected
    resp = client.post(
        f"/rules/{rule_id}/undo-deploy",
        params={"token": token},
    )

    assert resp.status_code == 401, (
        f"Expected 401 when token is in query param only, got {resp.status_code}: {resp.text}"
    )
    # No state change — file must still exist
    assert rule_file.exists(), "Rule file must not be deleted when auth via query-param is rejected"

    main_module._db = orig_db
    main_module._settings = orig_settings
    conn.close()
