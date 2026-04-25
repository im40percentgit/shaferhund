"""
Shaferhund Phase 6 — Authentication and token helpers.

This module owns all password hashing, bearer token generation/validation,
and the multi-user authentication resolution that `_require_auth` in main.py
delegates to when SHAFERHUND_AUTH_MODE=multi.

Design decisions encoded here:

@decision DEC-AUTH-P6-001
@title Argon2id over bcrypt for password hashing
@status accepted
@rationale Argon2id is the OWASP-current recommendation (2024+). It is
           constant-time, tunable on both memory and CPU, and `argon2-cffi`
           is a zero-system-dep drop-in (no OpenSSL linking issues on Alpine
           images that occasionally bite bcrypt wheels). For a solo-dev manager
           that authenticates a handful of operators per day the memory/time
           defaults are more than adequate and future-proof. bcrypt would also
           work; the deciding factor is operational simplicity.

@decision DEC-AUTH-P6-002
@title Role enum is code-resident frozenset; users + tokens are DB config
@status accepted
@rationale The set of valid roles (viewer, operator, admin) is reviewed at
           code-review time. Storing roles in env or DB would let a compromised
           environment silently grant or strip permissions. Same reasoning as
           DEC-RECOMMEND-002 (DESTRUCTIVE_TECHNIQUES) and DEC-CLOUD-005
           (detector rules). New roles require a PR; new users are created via
           the admin API.

@decision DEC-AUTH-P6-004
@title SHAFERHUND_TOKEN survives as admin-equivalent legacy fallback
@status accepted
@rationale The archive's working philosophy ("fail-closed on new behaviour,
           default-on for existing behaviour") demands backwards compatibility.
           Forcing operators to migrate their .env immediately would break every
           Phase 1–5 deployment. Legacy token grants synthetic admin access;
           SHAFERHUND_AUTH_MODE=multi enables the new flows; the operator guide
           documents a deliberate phase-out timeline. In single mode, _require_auth
           returns a synthetic admin user dict so downstream role checks pass
           uniformly regardless of mode.

Token shape:

@decision DEC-AUTH-P6-003
@title Tokens shown once — raw token issued once, only SHA-256 hash stored
@status accepted
@rationale Matches the industry-standard pattern (GitHub PATs, AWS IAM access
           keys, Stripe secret keys). The database stores only
           SHA-256(raw_token); a DB dump never reveals usable credentials.
           The raw token is returned to the operator in the creation response
           and is not retrievable later. At request time the presented bearer
           is hashed with the same SHA-256 and looked up by hash.
"""

import hashlib
import logging
import secrets
import sqlite3
from datetime import datetime, timezone
from typing import Optional

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError, VerificationError, InvalidHashError

from .models import (
    get_user_by_id,
    get_user_token_by_hash,
    update_user_token_last_used,
)

log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Role constants (DEC-AUTH-P6-002)
# ---------------------------------------------------------------------------

VALID_ROLES: frozenset[str] = frozenset({"viewer", "operator", "admin"})

# ---------------------------------------------------------------------------
# Role hierarchy (DEC-AUTH-P6-005)
#
# @decision DEC-AUTH-P6-005
# @title Ordered role tuple defines viewer < operator < admin hierarchy
# @status accepted
# @rationale _require_role(r) needs to answer "does user_role satisfy required_role?"
#            An ordered tuple makes this a single index-comparison (O(1)) with
#            no branching. Closed-default: any role not in the tuple returns
#            False regardless of position — unknown roles never bypass auth.
#            In single mode, LEGACY_ADMIN_USER carries role='admin' so it
#            satisfies every role check (viewer, operator, admin) automatically,
#            preserving Phase 1–5 backwards compatibility without special-casing.
# ---------------------------------------------------------------------------

ROLE_HIERARCHY: tuple[str, ...] = ("viewer", "operator", "admin")
"""Ordered role tuple from least to most privileged.

Index position encodes privilege: viewer=0, operator=1, admin=2.
A user satisfies a required role iff their role's index >= the required
role's index. Roles outside this tuple (including unknown/novel values)
return False from role_satisfies — closed-default, no bypass via novel roles.
"""


def role_satisfies(user_role: str, required_role: str) -> bool:
    """Return True iff user_role is at least required_role per ROLE_HIERARCHY.

    Closed-default: roles outside ROLE_HIERARCHY return False (unknown roles
    fail closed — no auth bypass via novel role values in the DB).

    Examples:
        role_satisfies('admin', 'viewer')   → True   (admin beats viewer)
        role_satisfies('operator', 'admin') → False  (operator < admin)
        role_satisfies('viewer', 'viewer')  → True   (exact match)
        role_satisfies('hacker', 'viewer')  → False  (unknown user role)
        role_satisfies('admin', 'hacker')   → False  (unknown required role)
    """
    if user_role not in ROLE_HIERARCHY or required_role not in ROLE_HIERARCHY:
        return False
    return ROLE_HIERARCHY.index(user_role) >= ROLE_HIERARCHY.index(required_role)

# ---------------------------------------------------------------------------
# Argon2id password hasher (DEC-AUTH-P6-001)
#
# argon2-cffi PasswordHasher defaults (as of 21.x):
#   memory_cost = 65536 KB (64 MiB)  — stronger than OWASP minimum of 12 MB
#   time_cost   = 2 iterations        — OWASP minimum is 1; default 2 is fine
#   parallelism = 2 threads
#   hash_len    = 32 bytes
#   salt_len    = 16 bytes
#
# These defaults meet OWASP's 2024 Argon2id recommendations and are stronger
# than the spec's minimum parameters (12 MB / 3 iterations / 1 thread), so
# we use the library defaults. If the host is memory-constrained you can
# lower memory_cost via env — but for a solo-dev manager running <10 logins
# per day the defaults are correct.
# ---------------------------------------------------------------------------

_ph = PasswordHasher()


def hash_password(plaintext: str) -> str:
    """Hash a plaintext password using Argon2id with library-default parameters.

    Returns an encoded string starting with ``$argon2id$`` that includes the
    salt, parameters, and hash — everything needed to verify later.

    Raises ValueError if plaintext is empty.
    """
    if not plaintext:
        raise ValueError("password must not be empty")
    return _ph.hash(plaintext)


def verify_password(plaintext: str, encoded: str) -> bool:
    """Verify a plaintext password against a stored Argon2id encoded string.

    Returns True if the password matches; False on mismatch, empty inputs,
    or a corrupted / wrong-algorithm hash. Never raises — callers can treat
    the bool directly.
    """
    if not plaintext or not encoded:
        return False
    try:
        return _ph.verify(encoded, plaintext)
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False
    except Exception:
        log.exception("Unexpected error in verify_password — treating as failure")
        return False


# ---------------------------------------------------------------------------
# Token generation and hashing (DEC-AUTH-P6-003)
# ---------------------------------------------------------------------------


def generate_token() -> tuple[str, str]:
    """Generate a cryptographically secure bearer token.

    Returns ``(raw_token, token_hash)`` where:
    - ``raw_token`` is ``secrets.token_urlsafe(32)`` — 256 bits of entropy,
      URL-safe base64-encoded, ~43 characters. Shown ONCE to the operator.
    - ``token_hash`` is the SHA-256 hex digest of the raw token. The only
      value stored in the database.

    The raw token is not retrievable after this call — only the hash persists.
    """
    raw_token = secrets.token_urlsafe(32)
    token_hash = hashlib.sha256(raw_token.encode()).hexdigest()
    return raw_token, token_hash


def hash_token(raw_token: str) -> str:
    """Return the SHA-256 hex digest of a raw bearer token.

    Used at request time: the presented ``Authorization: Bearer <raw>`` is
    hashed here and looked up in ``user_tokens.token_hash``.
    """
    return hashlib.sha256(raw_token.encode()).hexdigest()


# ---------------------------------------------------------------------------
# Token-based authentication — single source of truth
# ---------------------------------------------------------------------------


def authenticate_token(
    conn: sqlite3.Connection,
    raw_token: str,
) -> Optional[dict]:
    """Authenticate a bearer token and return the owning user.

    Looks up ``raw_token`` by its SHA-256 hash, validates:
      1. Token row exists
      2. Token is not revoked (``revoked_at IS NULL``)
      3. Token is not expired (``expires_at IS NULL`` or ``expires_at > now``)
      4. Owning user is not disabled (``disabled = 0``)

    On success, updates ``user_tokens.last_used_at`` and returns the user
    row as a plain dict with keys:
      ``id``, ``username``, ``role``, ``created_at``, ``last_login_at``,
      ``disabled``, ``token_id``, ``token_name``

    Returns ``None`` on any auth failure — callers raise 401 on None.
    """
    if not raw_token:
        return None

    token_hash = hash_token(raw_token)
    token_row = get_user_token_by_hash(conn, token_hash)

    if token_row is None:
        log.debug("authenticate_token: unknown token hash")
        return None

    # Revocation check
    if token_row["revoked_at"] is not None:
        log.debug("authenticate_token: token %d is revoked", token_row["id"])
        return None

    # Expiry check
    if token_row["expires_at"] is not None:
        try:
            expires = datetime.fromisoformat(token_row["expires_at"])
            # Normalise to UTC-aware for comparison
            if expires.tzinfo is None:
                expires = expires.replace(tzinfo=timezone.utc)
            now = datetime.now(timezone.utc)
            if now > expires:
                log.debug("authenticate_token: token %d is expired", token_row["id"])
                return None
        except ValueError:
            log.warning(
                "authenticate_token: token %d has unparseable expires_at=%r",
                token_row["id"], token_row["expires_at"],
            )
            return None

    # Load the owning user
    user_row = get_user_by_id(conn, token_row["user_id"])
    if user_row is None:
        log.warning(
            "authenticate_token: token %d references missing user %d",
            token_row["id"], token_row["user_id"],
        )
        return None

    # Disabled check
    if user_row["disabled"]:
        log.debug(
            "authenticate_token: user %d (%s) is disabled",
            user_row["id"], user_row["username"],
        )
        return None

    # Update last_used_at (best-effort — don't fail auth on write error)
    ts = datetime.now(timezone.utc).isoformat()
    try:
        update_user_token_last_used(conn, token_row["id"], ts)
    except Exception:
        log.exception("authenticate_token: failed to update last_used_at for token %d", token_row["id"])

    return {
        "id": user_row["id"],
        "username": user_row["username"],
        "role": user_row["role"],
        "created_at": user_row["created_at"],
        "last_login_at": user_row["last_login_at"],
        "disabled": user_row["disabled"],
        "token_id": token_row["id"],
        "token_name": token_row["name"],
    }


# ---------------------------------------------------------------------------
# Synthetic legacy-admin user (DEC-AUTH-P6-004)
# ---------------------------------------------------------------------------

LEGACY_ADMIN_USER: dict = {
    "id": 0,
    "username": "__legacy_token__",
    "role": "admin",
    "created_at": None,
    "last_login_at": None,
    "disabled": 0,
    "token_id": None,
    "token_name": "__shaferhund_token__",
}
"""Returned by _require_auth when SHAFERHUND_AUTH_MODE=single and the legacy
SHAFERHUND_TOKEN matches. Role is 'admin' so all downstream _require_role
checks pass — this is the "admin-equivalent fallback" promised by DEC-AUTH-P6-004.
"""
