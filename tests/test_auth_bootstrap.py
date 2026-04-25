"""
Tests for the bootstrap admin flow (Phase 6 Wave B1, REQ-P0-P6-006).

Covers _bootstrap_admin_if_needed() behaviour across all env/mode combinations.
Uses real SQLite + real Argon2id (no mocks of internal modules).

# @mock-exempt: patch.object targets _settings and _db — module-level singletons
# in main.py populated by lifespan(). Swapping them for test-controlled objects
# is equivalent to dependency injection at the app boundary. All auth logic
# (hash_password, verify_password, insert_user, count_users) runs against a
# real in-memory SQLite connection with zero mocks of internal behaviour.
# This is the established pattern in test_main_auth_modes.py.

Test matrix:
  - bootstrap creates admin when users table is empty + both env vars set
  - bootstrap is idempotent when users table already has rows
  - bootstrap is a no-op in single mode (regardless of env vars)
  - bootstrap warns and no-ops when only username is set (partial env)
  - bootstrap warns and no-ops when only password is set (partial env)
  - bootstrap no-ops when neither env var is set
  - created user's password_hash starts with $argon2id$ (DEC-AUTH-P6-001)
  - created user has role='admin' and disabled=0
"""

import logging
from unittest.mock import patch

import pytest

from agent.auth import verify_password
from agent.models import (
    count_users,
    get_user_by_username,
    init_db,
    insert_user,
)
from agent.auth import hash_password


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _run_bootstrap(db_conn, auth_mode="multi", username="", password=""):
    """Run _bootstrap_admin_if_needed with patched globals."""
    import agent.main as main_mod
    from agent.config import Settings

    settings = Settings(
        anthropic_api_key="test-key",
        shaferhund_auth_mode=auth_mode,
        shaferhund_bootstrap_admin_username=username,
        shaferhund_bootstrap_admin_password=password,
    )
    with (
        patch.object(main_mod, "_settings", settings),
        patch.object(main_mod, "_db", db_conn),
    ):
        main_mod._bootstrap_admin_if_needed()


@pytest.fixture()
def db(tmp_path):
    conn = init_db(str(tmp_path / "test.db"))
    yield conn
    conn.close()


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

def test_bootstrap_creates_admin_when_users_empty(db):
    """When users table is empty and both env vars set in multi mode, admin is created."""
    assert count_users(db) == 0

    _run_bootstrap(db, auth_mode="multi", username="admin", password="bootstrap-secret-1")

    assert count_users(db) == 1
    user_row = get_user_by_username(db, "admin")
    assert user_row is not None
    assert user_row["role"] == "admin"
    assert user_row["disabled"] == 0


def test_bootstrap_password_is_hashed(db):
    """Created admin's password_hash must start with $argon2id$ (DEC-AUTH-P6-001)."""
    _run_bootstrap(db, auth_mode="multi", username="admin", password="bootstrap-secret-1")

    user_row = get_user_by_username(db, "admin")
    assert user_row is not None
    assert user_row["password_hash"].startswith("$argon2id$"), (
        f"Expected Argon2id hash, got: {user_row['password_hash'][:40]}"
    )


def test_bootstrap_password_verifies(db):
    """The stored hash must verify correctly against the plaintext bootstrap password."""
    _run_bootstrap(db, auth_mode="multi", username="admin", password="bootstrap-secret-1")

    user_row = get_user_by_username(db, "admin")
    assert verify_password("bootstrap-secret-1", user_row["password_hash"]) is True
    assert verify_password("wrong-password", user_row["password_hash"]) is False


def test_bootstrap_idempotent_with_existing_users(db):
    """If users table is non-empty, bootstrap must not create another user."""
    # Pre-seed a user
    ph = hash_password("existing-pass")
    insert_user(db, "existing-operator", ph, "operator")
    assert count_users(db) == 1

    _run_bootstrap(db, auth_mode="multi", username="admin", password="bootstrap-secret-1")

    # No new user should have been created
    assert count_users(db) == 1
    assert get_user_by_username(db, "admin") is None


def test_bootstrap_skipped_in_single_mode(db):
    """In single mode, bootstrap must be a no-op regardless of env vars."""
    assert count_users(db) == 0

    _run_bootstrap(db, auth_mode="single", username="admin", password="bootstrap-secret-1")

    assert count_users(db) == 0


def test_bootstrap_warns_on_partial_env_username_only(db, caplog):
    """When only username is set (no password), logs WARNING and creates no user."""
    with caplog.at_level(logging.WARNING, logger="agent.main"):
        _run_bootstrap(db, auth_mode="multi", username="admin", password="")

    assert count_users(db) == 0
    assert any("both SHAFERHUND_BOOTSTRAP_ADMIN_USERNAME" in r.message for r in caplog.records), (
        f"Expected WARNING about partial env. Records: {[r.message for r in caplog.records]}"
    )


def test_bootstrap_warns_on_partial_env_password_only(db, caplog):
    """When only password is set (no username), logs WARNING and creates no user."""
    with caplog.at_level(logging.WARNING, logger="agent.main"):
        _run_bootstrap(db, auth_mode="multi", username="", password="some-pass")

    assert count_users(db) == 0
    assert any("both SHAFERHUND_BOOTSTRAP_ADMIN_USERNAME" in r.message for r in caplog.records)


def test_bootstrap_skipped_when_no_env_set(db, caplog):
    """When neither env var is set, bootstrap silently skips (no WARNING)."""
    with caplog.at_level(logging.WARNING, logger="agent.main"):
        _run_bootstrap(db, auth_mode="multi", username="", password="")

    assert count_users(db) == 0
    # Should be DEBUG, not WARNING
    assert not any("Bootstrap admin not created" in r.message for r in caplog.records)


def test_bootstrap_debug_log_single_mode(db, caplog):
    """Single mode should log at DEBUG level, not WARNING."""
    with caplog.at_level(logging.DEBUG, logger="agent.main"):
        _run_bootstrap(db, auth_mode="single", username="admin", password="secret")

    debug_msgs = [r.message for r in caplog.records if r.levelno == logging.DEBUG]
    assert any("single" in m or "Bootstrap skipped" in m for m in debug_msgs), (
        f"Expected DEBUG skip message. Debug records: {debug_msgs}"
    )
