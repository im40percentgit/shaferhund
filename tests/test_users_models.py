"""
Tests for Phase 6 Wave A1 users + user_tokens schema and CRUD helpers
in agent/models.py (REQ-P0-P6-003, DEC-SCHEMA-P6-001).

Uses real SQLite (in-memory via tmp_path) — no internal mocks.
"""

import sqlite3
from datetime import datetime, timezone

import pytest

from agent.auth import hash_password, generate_token, hash_token
from agent.models import (
    get_user_by_id,
    get_user_by_username,
    init_db,
    insert_user,
    insert_user_token,
    list_user_tokens,
    list_users,
    revoke_user_token,
    set_user_disabled,
    update_user_last_login,
    update_user_token_last_used,
    get_user_token_by_hash,
)


# ---------------------------------------------------------------------------
# Fixture
# ---------------------------------------------------------------------------

@pytest.fixture()
def db(tmp_path):
    conn = init_db(str(tmp_path / "test.db"))
    yield conn
    conn.close()


def _insert_user(db, username="alice", role="operator"):
    ph = hash_password("s3cr3t")
    return insert_user(db, username, ph, role)


# ---------------------------------------------------------------------------
# users table
# ---------------------------------------------------------------------------

def test_insert_user_returns_id(db):
    uid = _insert_user(db, "alice")
    assert isinstance(uid, int)
    assert uid >= 1


def test_insert_user_unique_username(db):
    """Second insert with same username must raise IntegrityError (UNIQUE)."""
    _insert_user(db, "alice")
    with pytest.raises(sqlite3.IntegrityError):
        _insert_user(db, "alice")


def test_get_user_by_id_returns_row(db):
    uid = _insert_user(db, "alice")
    row = get_user_by_id(db, uid)
    assert row is not None
    assert row["username"] == "alice"
    assert row["role"] == "operator"
    assert row["disabled"] == 0


def test_get_user_by_id_missing(db):
    assert get_user_by_id(db, 99999) is None


def test_get_user_by_username_returns_row(db):
    uid = _insert_user(db, "bob", "viewer")
    row = get_user_by_username(db, "bob")
    assert row is not None
    assert row["id"] == uid
    assert row["role"] == "viewer"


def test_get_user_by_username_missing(db):
    assert get_user_by_username(db, "nobody") is None


def test_set_user_disabled_toggles(db):
    """set_user_disabled flips disabled and is_active fields consistently."""
    uid = _insert_user(db, "alice")
    row = get_user_by_id(db, uid)
    assert row["disabled"] == 0
    assert row["is_active"] == 1

    set_user_disabled(db, uid, True)
    row = get_user_by_id(db, uid)
    assert row["disabled"] == 1
    assert row["is_active"] == 0

    set_user_disabled(db, uid, False)
    row = get_user_by_id(db, uid)
    assert row["disabled"] == 0
    assert row["is_active"] == 1


def test_update_user_last_login(db):
    uid = _insert_user(db, "alice")
    ts = datetime.now(timezone.utc).isoformat()
    update_user_last_login(db, uid, ts)
    row = get_user_by_id(db, uid)
    assert row["last_login_at"] == ts


def test_list_users(db):
    _insert_user(db, "alice", "admin")
    _insert_user(db, "bob", "viewer")
    rows = list_users(db)
    usernames = [r["username"] for r in rows]
    assert "alice" in usernames
    assert "bob" in usernames


def test_user_role_check_constraint(db):
    """Inserting an invalid role must raise IntegrityError (CHECK constraint)."""
    with pytest.raises(sqlite3.IntegrityError):
        insert_user(db, "hacker", hash_password("pw"), "hacker")


def test_user_created_at_is_set(db):
    uid = _insert_user(db, "alice")
    row = get_user_by_id(db, uid)
    assert row["created_at"] is not None
    # Should parse as ISO-8601
    datetime.fromisoformat(row["created_at"])


# ---------------------------------------------------------------------------
# user_tokens table
# ---------------------------------------------------------------------------

def test_insert_user_token_returns_id(db):
    uid = _insert_user(db, "alice")
    raw, h = generate_token()
    tid = insert_user_token(db, uid, h, "test-token")
    assert isinstance(tid, int)
    assert tid >= 1


def test_insert_user_token_unique_hash(db):
    """Second insert with same token_hash must raise IntegrityError (UNIQUE)."""
    uid = _insert_user(db, "alice")
    raw, h = generate_token()
    insert_user_token(db, uid, h, "first")
    with pytest.raises(sqlite3.IntegrityError):
        insert_user_token(db, uid, h, "duplicate")


def test_get_user_token_by_hash_returns_row(db):
    uid = _insert_user(db, "alice")
    raw, h = generate_token()
    tid = insert_user_token(db, uid, h, "my-token")
    row = get_user_token_by_hash(db, h)
    assert row is not None
    assert row["id"] == tid
    assert row["user_id"] == uid
    assert row["name"] == "my-token"
    assert row["revoked_at"] is None
    assert row["expires_at"] is None


def test_get_user_token_by_hash_missing(db):
    assert get_user_token_by_hash(db, "a" * 64) is None


def test_revoke_user_token_sets_revoked_at(db):
    uid = _insert_user(db, "alice")
    raw, h = generate_token()
    tid = insert_user_token(db, uid, h, "tok")
    ts = datetime.now(timezone.utc).isoformat()
    revoke_user_token(db, tid, ts)

    row = get_user_token_by_hash(db, h)
    assert row["revoked_at"] == ts


def test_update_user_token_last_used(db):
    uid = _insert_user(db, "alice")
    raw, h = generate_token()
    tid = insert_user_token(db, uid, h, "tok")

    ts = datetime.now(timezone.utc).isoformat()
    update_user_token_last_used(db, tid, ts)

    row = get_user_token_by_hash(db, h)
    assert row["last_used_at"] == ts


def test_list_user_tokens(db):
    uid = _insert_user(db, "alice")
    for i in range(3):
        raw, h = generate_token()
        insert_user_token(db, uid, h, f"token-{i}")
    rows = list_user_tokens(db, uid)
    assert len(rows) == 3
    names = {r["name"] for r in rows}
    assert names == {"token-0", "token-1", "token-2"}


def test_list_user_tokens_empty(db):
    uid = _insert_user(db, "alice")
    assert list_user_tokens(db, uid) == []


def test_user_token_created_at_set(db):
    uid = _insert_user(db, "alice")
    raw, h = generate_token()
    insert_user_token(db, uid, h, "tok")
    row = get_user_token_by_hash(db, h)
    assert row["created_at"] is not None
    datetime.fromisoformat(row["created_at"])


# ---------------------------------------------------------------------------
# Schema idempotency — calling init_db twice does not fail
# ---------------------------------------------------------------------------

def test_init_db_idempotent(tmp_path):
    """init_db on the same path twice must not raise."""
    path = str(tmp_path / "idem.db")
    conn1 = init_db(path)
    conn1.close()
    conn2 = init_db(path)  # second call — all IF NOT EXISTS must be safe
    # Verify tables exist in second connection
    tables = {
        row[0]
        for row in conn2.execute(
            "SELECT name FROM sqlite_master WHERE type='table'"
        ).fetchall()
    }
    assert "users" in tables
    assert "user_tokens" in tables
    conn2.close()


def test_users_table_columns(tmp_path):
    """users table has all required columns after init_db."""
    conn = init_db(str(tmp_path / "col.db"))
    cols = {row[1] for row in conn.execute("PRAGMA table_info(users)").fetchall()}
    required = {"id", "username", "password_hash", "role", "created_at",
                "last_login_at", "disabled", "is_active"}
    assert required <= cols, f"Missing columns: {required - cols}"
    conn.close()


def test_user_tokens_table_columns(tmp_path):
    """user_tokens table has all required columns after init_db."""
    conn = init_db(str(tmp_path / "col2.db"))
    cols = {row[1] for row in conn.execute("PRAGMA table_info(user_tokens)").fetchall()}
    required = {"id", "user_id", "token_hash", "name", "created_at",
                "last_used_at", "expires_at", "revoked_at"}
    assert required <= cols, f"Missing columns: {required - cols}"
    conn.close()
