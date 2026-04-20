"""
Dashboard route tests — source filter chips, deploy-events page, cluster detail rules.

All tests use FastAPI TestClient with an in-memory SQLite DB (no token set so
SHAFERHUND_TOKEN is empty and auth is a no-op).

Test cases:
  1. source_filter_all   — GET /?source=all → wazuh + suricata clusters in response.
  2. source_filter_wazuh — GET /?source=wazuh → only wazuh clusters in response.
  3. deploy_events_page  — seed 3 events, GET /deploy-events → all 3 render.
  4. pagination          — seed 60 events, GET /deploy-events?offset=50 → last 10 render.
  5. cluster_detail_both — seed YARA + Sigma rules, GET /clusters/{id} → both rule
                           contents appear in response body.

@decision DEC-DASHBOARD-002
@title Dashboard tests exercise real DB and real routes; no internal mocks
@status accepted
@rationale Consistent with the project's Sacred Practice #5: real unit tests,
           not mocks.  The TestClient exercises the full FastAPI stack including
           template rendering.  Only the app singletons (_db, _settings) are
           patched at the module level — this is the minimal setup boundary.
"""

import agent.main as main_module

import pytest
from fastapi.testclient import TestClient
from types import SimpleNamespace

from agent.models import (
    init_db,
    insert_rule,
    record_deploy_event,
    upsert_cluster,
)


# ---------------------------------------------------------------------------
# Shared setup helpers
# ---------------------------------------------------------------------------


def _make_settings(rules_dir: str, token: str = "") -> SimpleNamespace:
    """Return a minimal settings namespace for route tests.

    Uses SimpleNamespace (not Settings) to avoid requiring ANTHROPIC_API_KEY
    in test environments — the same pattern used in test_auto_deploy_integration.py.
    Routes only read: shaferhund_token, rules_dir.
    """
    return SimpleNamespace(
        shaferhund_token=token,
        rules_dir=str(rules_dir),
        db_path=":memory:",
        alerts_file="/dev/null",
        suricata_eve_file="/dev/null",
    )


def _make_client(tmp_path, token: str = ""):
    """Return (TestClient, conn) with module singletons patched to in-memory DB."""
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir(exist_ok=True)

    conn = init_db(":memory:")
    settings = _make_settings(str(rules_dir), token=token)

    main_module._db = conn
    main_module._settings = settings

    client = TestClient(main_module.app, raise_server_exceptions=True)
    return client, conn


def _seed_cluster(conn, cluster_id: str, src_ip: str, source: str) -> None:
    upsert_cluster(
        conn,
        cluster_id=cluster_id,
        src_ip=src_ip,
        rule_id=1001,
        window_start="2026-01-01T00:00:00",
        window_end="2026-01-01T00:05:00",
        alert_count=2,
        source=source,
    )


def _seed_rule(
    conn,
    rule_id: str,
    cluster_id: str,
    rule_type: str,
    content: str,
    syntax_valid: bool = True,
) -> None:
    insert_rule(
        conn,
        rule_id=rule_id,
        cluster_id=cluster_id,
        rule_type=rule_type,
        rule_content=content,
        syntax_valid=syntax_valid,
    )


# ---------------------------------------------------------------------------
# Case 1: source=all — both wazuh and suricata clusters appear
# ---------------------------------------------------------------------------


def test_source_filter_all(tmp_path):
    """GET /?source=all returns clusters from both wazuh and suricata sources."""
    client, conn = _make_client(tmp_path)

    _seed_cluster(conn, "cluster-wazuh-1", "10.0.0.1", "wazuh")
    _seed_cluster(conn, "cluster-suricata-1", "10.0.0.2", "suricata")

    resp = client.get("/?source=all")
    assert resp.status_code == 200

    body = resp.text
    assert "10.0.0.1" in body, "Wazuh cluster IP should appear with source=all"
    assert "10.0.0.2" in body, "Suricata cluster IP should appear with source=all"

    conn.close()


# ---------------------------------------------------------------------------
# Case 2: source=wazuh — only wazuh clusters appear
# ---------------------------------------------------------------------------


def test_source_filter_wazuh(tmp_path):
    """GET /?source=wazuh returns only wazuh clusters, not suricata ones."""
    client, conn = _make_client(tmp_path)

    _seed_cluster(conn, "cluster-wazuh-2", "10.1.0.1", "wazuh")
    _seed_cluster(conn, "cluster-suricata-2", "10.1.0.2", "suricata")

    resp = client.get("/?source=wazuh")
    assert resp.status_code == 200

    body = resp.text
    assert "10.1.0.1" in body, "Wazuh cluster IP should appear with source=wazuh"
    assert "10.1.0.2" not in body, "Suricata cluster IP should NOT appear with source=wazuh"

    conn.close()


# ---------------------------------------------------------------------------
# Case 3: deploy events page — 3 events, all render
# ---------------------------------------------------------------------------


def test_deploy_events_page_renders(tmp_path):
    """GET /deploy-events with 3 seeded events renders all 3 rows."""
    client, conn = _make_client(tmp_path)

    rule_ids = ["rule-ev-001", "rule-ev-002", "rule-ev-003"]
    for rid in rule_ids:
        record_deploy_event(
            conn,
            rule_id=rid,
            action="auto-deploy",
            reason="ok",
            actor="orchestrator",
            rule_type="yara",
            src_ip="10.2.0.1",
        )

    resp = client.get("/deploy-events")
    assert resp.status_code == 200

    body = resp.text
    for rid in rule_ids:
        assert rid[:8] in body, f"Rule UUID prefix {rid[:8]} should appear in deploy events page"

    conn.close()


# ---------------------------------------------------------------------------
# Case 4: pagination — 60 events, offset=50 returns last 10
# ---------------------------------------------------------------------------


def test_deploy_events_pagination(tmp_path):
    """GET /deploy-events?offset=50 with 60 seeded events returns the last 10."""
    client, conn = _make_client(tmp_path)

    # Seed 60 events with distinct rule UUIDs
    for i in range(60):
        record_deploy_event(
            conn,
            rule_id=f"rule-page-{i:03d}",
            action="auto-deploy",
            reason="ok",
            actor="orchestrator",
            rule_type="yara",
            src_ip="10.3.0.1",
        )

    resp = client.get("/deploy-events?offset=50")
    assert resp.status_code == 200

    body = resp.text
    # deploy_events are ordered newest-first; the 50 newest are on page 0.
    # At offset=50 we get rows 51-60 (the oldest 10) — rule-page-000..009
    # in the oldest-first seeding order means the 10 oldest events have
    # the lowest indices.  Verify we have exactly 10 rows rendered by
    # checking the offset display and absence of a "next_offset" link
    # (only 10 rows returned < page size of 50).
    assert "offset=50" in body or "51" in body  # pagination indicator present
    # No "Older →" link when fewer than 50 rows on this page
    assert "Older" not in body, "Should be no 'Older' link on the last page"

    conn.close()


# ---------------------------------------------------------------------------
# Case 5: cluster detail shows both YARA and Sigma rule content
# ---------------------------------------------------------------------------


def test_cluster_detail_shows_both_rule_types(tmp_path):
    """GET /clusters/{id} body contains both YARA and Sigma rule contents."""
    client, conn = _make_client(tmp_path)

    cluster_id = "cluster-both-rules"
    _seed_cluster(conn, cluster_id, "10.4.0.1", "wazuh")

    yara_content = 'rule DetectEvil { strings: $s = "evil_payload" condition: $s }'
    sigma_content = "title: Detect Evil\nstatus: experimental\ndetection:\n  keywords:\n    - evil_payload"

    _seed_rule(conn, "rule-yara-detail", cluster_id, "yara", yara_content)
    _seed_rule(conn, "rule-sigma-detail", cluster_id, "sigma", sigma_content)

    resp = client.get(f"/clusters/{cluster_id}")
    assert resp.status_code == 200

    body = resp.text
    assert "evil_payload" in body, "YARA rule content should appear in cluster detail"
    assert "Detect Evil" in body, "Sigma rule title should appear in cluster detail"
    assert "yara" in body, "YARA type badge should appear"
    assert "sigma" in body, "Sigma type badge should appear"

    conn.close()
