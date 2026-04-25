"""
Tests for agent/auth.py — Argon2id hashing, token generation, and
token-based authentication (REQ-P0-P6-003, DEC-AUTH-P6-001/003).

All tests use a real in-memory SQLite connection (no mocks of internal
modules). External boundary: argon2-cffi library — we test its output
format but do not mock it.
"""

import sqlite3
from datetime import datetime, timedelta, timezone

import pytest

from agent.auth import (
    LEGACY_ADMIN_USER,
    authenticate_token,
    generate_token,
    hash_password,
    hash_token,
    verify_password,
)
from agent.models import (
    init_db,
    insert_user,
    insert_user_token,
    revoke_user_token,
    set_user_disabled,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture()
def db(tmp_path):
    """In-memory SQLite connection with Phase 6 schema applied."""
    db_path = str(tmp_path / "test.db")
    conn = init_db(db_path)
    yield conn
    conn.close()


def _make_user_and_token(db, username="alice", role="operator", raw_token=None):
    """Helper: insert a user + one token; return (user_id, raw_token, token_id)."""
    ph = hash_password("correct-horse-battery-staple")
    user_id = insert_user(db, username, ph, role)
    if raw_token is None:
        raw_token, token_hash = generate_token()
    else:
        token_hash = hash_token(raw_token)
    token_id = insert_user_token(db, user_id, token_hash, f"{username}-token")
    return user_id, raw_token, token_id


# ---------------------------------------------------------------------------
# Password hashing (DEC-AUTH-P6-001)
# ---------------------------------------------------------------------------

def test_hash_password_returns_argon2_encoded():
    """hash_password output must start with $argon2id$ (Argon2id encoded string)."""
    h = hash_password("correct horse battery staple")
    assert h.startswith("$argon2id$"), f"Expected Argon2id hash, got: {h[:30]}"


def test_hash_password_unique_per_call():
    """Same plaintext → different hashes due to random per-call salt."""
    h1 = hash_password("same-password")
    h2 = hash_password("same-password")
    assert h1 != h2, "Two hashes of the same password must differ (salt must be random)"


def test_verify_password_correct():
    """verify_password returns True for correct plaintext."""
    h = hash_password("correct-horse")
    assert verify_password("correct-horse", h) is True


def test_verify_password_wrong():
    """verify_password returns False for wrong plaintext."""
    h = hash_password("correct-horse")
    assert verify_password("wrong-password", h) is False


def test_verify_password_empty_inputs():
    """verify_password handles empty strings without raising."""
    h = hash_password("nonempty")
    assert verify_password("", h) is False
    assert verify_password("nonempty", "") is False
    assert verify_password("", "") is False


def test_hash_password_empty_raises():
    """hash_password rejects empty plaintext with ValueError."""
    with pytest.raises(ValueError):
        hash_password("")


# ---------------------------------------------------------------------------
# Token generation and hashing (DEC-AUTH-P6-003)
# ---------------------------------------------------------------------------

def test_generate_token_shape():
    """raw_token is URL-safe, ≥32 chars; token_hash is 64 hex chars (SHA-256)."""
    raw_token, token_hash = generate_token()
    # URL-safe base64: only alphanumeric + - + _
    import re
    assert re.match(r'^[A-Za-z0-9_-]+$', raw_token), f"raw_token not URL-safe: {raw_token!r}"
    assert len(raw_token) >= 32, f"raw_token too short: {len(raw_token)} chars"
    assert len(token_hash) == 64, f"token_hash must be 64 hex chars, got {len(token_hash)}"
    assert all(c in "0123456789abcdef" for c in token_hash), "token_hash must be hex"


def test_generate_token_unique():
    """Two calls produce different raw tokens."""
    r1, h1 = generate_token()
    r2, h2 = generate_token()
    assert r1 != r2
    assert h1 != h2


def test_hash_token_deterministic():
    """hash_token is a pure function — same input → same output."""
    raw = "some-fixed-token-value"
    assert hash_token(raw) == hash_token(raw)


def test_hash_token_matches_generate_token():
    """hash_token(raw) == token_hash from generate_token."""
    raw, expected_hash = generate_token()
    assert hash_token(raw) == expected_hash


# ---------------------------------------------------------------------------
# authenticate_token — happy path
# ---------------------------------------------------------------------------

def test_authenticate_token_valid(db):
    """Valid token → returns user dict; last_used_at is updated."""
    user_id, raw_token, token_id = _make_user_and_token(db, "alice", "operator")

    user = authenticate_token(db, raw_token)

    assert user is not None
    assert user["username"] == "alice"
    assert user["role"] == "operator"
    assert user["id"] == user_id
    assert user["token_id"] == token_id

    # last_used_at must be set now
    token_row = db.execute(
        "SELECT last_used_at FROM user_tokens WHERE id = ?", (token_id,)
    ).fetchone()
    assert token_row["last_used_at"] is not None


# ---------------------------------------------------------------------------
# authenticate_token — rejection cases
# ---------------------------------------------------------------------------

def test_authenticate_token_revoked(db):
    """Revoked token → returns None."""
    user_id, raw_token, token_id = _make_user_and_token(db, "bob", "viewer")
    ts = datetime.now(timezone.utc).isoformat()
    revoke_user_token(db, token_id, ts)

    assert authenticate_token(db, raw_token) is None


def test_authenticate_token_expired(db):
    """Token with expires_at in the past → returns None."""
    ph = hash_password("pw")
    user_id = insert_user(db, "carol", ph, "viewer")
    raw_token, token_hash = generate_token()
    past_ts = (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat()
    insert_user_token(db, user_id, token_hash, "expired-token", expires_at=past_ts)

    assert authenticate_token(db, raw_token) is None


def test_authenticate_token_not_yet_expired(db):
    """Token with expires_at in the future → returns user."""
    ph = hash_password("pw")
    user_id = insert_user(db, "dan", ph, "operator")
    raw_token, token_hash = generate_token()
    future_ts = (datetime.now(timezone.utc) + timedelta(hours=24)).isoformat()
    insert_user_token(db, user_id, token_hash, "valid-token", expires_at=future_ts)

    user = authenticate_token(db, raw_token)
    assert user is not None
    assert user["username"] == "dan"


def test_authenticate_token_disabled_user(db):
    """Token belonging to a disabled user → returns None."""
    user_id, raw_token, token_id = _make_user_and_token(db, "eve", "admin")
    set_user_disabled(db, user_id, True)

    assert authenticate_token(db, raw_token) is None


def test_authenticate_token_unknown(db):
    """Completely unknown raw token → returns None (no crash)."""
    assert authenticate_token(db, "totally-unknown-token-value-xyz") is None


def test_authenticate_token_empty_string(db):
    """Empty bearer → returns None."""
    assert authenticate_token(db, "") is None


# ---------------------------------------------------------------------------
# LEGACY_ADMIN_USER shape
# ---------------------------------------------------------------------------

def test_legacy_admin_user_shape():
    """LEGACY_ADMIN_USER has the expected fields and role='admin'."""
    assert LEGACY_ADMIN_USER["role"] == "admin"
    assert LEGACY_ADMIN_USER["username"] == "__legacy_token__"
    assert LEGACY_ADMIN_USER["disabled"] == 0
    assert "id" in LEGACY_ADMIN_USER
    assert "token_id" in LEGACY_ADMIN_USER
