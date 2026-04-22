"""
Static asset serving tests — vendored htmx (CSO Finding F3, DEC-SUPPLY-001).

Verifies that:
  1. GET /static/htmx-1.9.12.min.js returns 200 with JavaScript content.
  2. The response body is at least 10 000 bytes (htmx minified is ~48 KB).
  3. No auth token is required — static assets are public by design.
  4. No template references unpkg.com.

@decision DEC-SUPPLY-001
@title Vendor htmx into agent/static/ and serve at /static/; remove CDN dependency
@status accepted
@rationale See agent/main.py DEC-SUPPLY-001 annotation for full rationale.
           Tests here prove the mount is reachable without auth and the file
           is present and non-trivially sized.
"""

import os
from pathlib import Path

import agent.main as main_module
import pytest
from fastapi.testclient import TestClient
from types import SimpleNamespace

from agent.models import init_db


# ---------------------------------------------------------------------------
# Helpers (match test_dashboard.py pattern)
# ---------------------------------------------------------------------------


def _make_settings(tmp_path: Path, token: str = "") -> SimpleNamespace:
    return SimpleNamespace(
        shaferhund_token=token,
        rules_dir=str(tmp_path / "rules"),
        db_path=":memory:",
        alerts_file="/dev/null",
        suricata_eve_file="/dev/null",
    )


def _make_client(tmp_path: Path, token: str = "") -> TestClient:
    """Patch module singletons and return a TestClient (no lifespan)."""
    conn = init_db(":memory:")
    settings = _make_settings(tmp_path, token=token)

    main_module._db = conn
    main_module._settings = settings

    return TestClient(main_module.app, raise_server_exceptions=True)


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def test_htmx_static_served_200(tmp_path):
    """GET /static/htmx-1.9.12.min.js returns 200 with JS content, no auth needed."""
    # Explicitly unset token so we're not accidentally relying on env state
    orig = os.environ.pop("SHAFERHUND_TOKEN", None)
    try:
        client = _make_client(tmp_path, token="")
        resp = client.get("/static/htmx-1.9.12.min.js")
    finally:
        if orig is not None:
            os.environ["SHAFERHUND_TOKEN"] = orig

    assert resp.status_code == 200, f"Expected 200, got {resp.status_code}"
    content_type = resp.headers.get("content-type", "")
    assert "javascript" in content_type, (
        f"Expected javascript content-type, got: {content_type!r}"
    )
    assert len(resp.content) > 10_000, (
        f"htmx.min.js suspiciously small: {len(resp.content)} bytes"
    )


def test_htmx_static_no_auth_required(tmp_path):
    """Static assets are accessible even when a token is configured on the app."""
    client = _make_client(tmp_path, token="secret-token")
    # No Authorization header — should still get the file
    resp = client.get("/static/htmx-1.9.12.min.js")
    assert resp.status_code == 200, (
        f"Static asset should not require auth, got {resp.status_code}"
    )


def test_templates_no_cdn_references():
    """None of the three dashboard templates should reference unpkg.com."""
    templates_dir = Path(__file__).parent.parent / "agent" / "templates"
    cdn_refs = []
    for tmpl in templates_dir.glob("*.html"):
        text = tmpl.read_text(encoding="utf-8")
        if "unpkg.com" in text:
            cdn_refs.append(tmpl.name)

    assert cdn_refs == [], (
        f"These templates still load htmx from unpkg.com: {cdn_refs}"
    )
