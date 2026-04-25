"""
Unit tests for Phase 6 Wave A4 rule_tags CRUD helpers.

Tests run against a real in-memory SQLite DB (no mocks) — consistent with
Sacred Practice #5.  Each test gets a fresh DB via the ``conn`` fixture.

REQ-P0-P6-001 / DEC-FLEET-P6-002 / DEC-SCHEMA-P6-001
"""
import pytest
import sqlite3

from agent.models import (
    init_db,
    insert_rule,
    list_all_tags,
    list_rules_for_tag,
    list_tags_for_rule,
    tag_rule,
    untag_rule,
)


# ---------------------------------------------------------------------------
# Fixture helpers
# ---------------------------------------------------------------------------

@pytest.fixture()
def conn(tmp_path):
    """Fresh in-memory-style SQLite DB for each test."""
    db_file = str(tmp_path / "test.db")
    c = init_db(db_file)
    yield c
    c.close()


def _make_rule(conn, rule_id="rule-001", deployed=1):
    """Insert a minimal rule row and return rule_id.

    cluster_id=None avoids FK constraint on clusters.id — NULL is always
    allowed for nullable FK columns in SQLite regardless of foreign_keys=ON.
    """
    insert_rule(
        conn,
        rule_id=rule_id,
        cluster_id=None,
        rule_type="yara",
        rule_content="rule test {}",
        syntax_valid=True,
    )
    if deployed:
        conn.execute("UPDATE rules SET deployed = 1 WHERE id = ?", (rule_id,))
        conn.commit()
    return rule_id


# ---------------------------------------------------------------------------
# tag_rule
# ---------------------------------------------------------------------------

def test_tag_rule_basic(conn):
    """tag_rule returns 1 (rows inserted) on first application."""
    rid = _make_rule(conn)
    result = tag_rule(conn, rid, "group:web")
    assert result == 1


def test_tag_rule_unique_constraint(conn):
    """Same rule+tag applied twice inserts only one row (INSERT OR IGNORE)."""
    rid = _make_rule(conn)
    tag_rule(conn, rid, "group:web")
    second = tag_rule(conn, rid, "group:web")
    # INSERT OR IGNORE → rowcount 0 on duplicate
    assert second == 0
    rows = conn.execute(
        "SELECT COUNT(*) FROM rule_tags WHERE rule_id = ? AND tag = ?",
        (rid, "group:web"),
    ).fetchone()[0]
    assert rows == 1


def test_tag_rule_multiple_tags(conn):
    """A rule can carry multiple distinct tags."""
    rid = _make_rule(conn)
    tag_rule(conn, rid, "group:web")
    tag_rule(conn, rid, "group:db")
    tags = list_tags_for_rule(conn, rid)
    assert "group:web" in tags
    assert "group:db" in tags
    assert len(tags) == 2


# ---------------------------------------------------------------------------
# untag_rule
# ---------------------------------------------------------------------------

def test_untag_rule_deletes_row(conn):
    """untag_rule removes the tag and returns 1."""
    rid = _make_rule(conn)
    tag_rule(conn, rid, "group:web")
    deleted = untag_rule(conn, rid, "group:web")
    assert deleted == 1
    tags = list_tags_for_rule(conn, rid)
    assert tags == []


def test_untag_rule_not_present_returns_zero(conn):
    """untag_rule on a tag that was never applied returns 0 (idempotent)."""
    rid = _make_rule(conn)
    result = untag_rule(conn, rid, "group:missing")
    assert result == 0


def test_untag_rule_leaves_other_tags(conn):
    """untag_rule removes only the targeted tag; siblings survive."""
    rid = _make_rule(conn)
    tag_rule(conn, rid, "group:web")
    tag_rule(conn, rid, "group:db")
    untag_rule(conn, rid, "group:web")
    tags = list_tags_for_rule(conn, rid)
    assert tags == ["group:db"]


# ---------------------------------------------------------------------------
# list_tags_for_rule
# ---------------------------------------------------------------------------

def test_list_tags_for_rule_returns_all_tags(conn):
    """list_tags_for_rule returns every tag for the rule, sorted."""
    rid = _make_rule(conn)
    tag_rule(conn, rid, "group:web")
    tag_rule(conn, rid, "env:prod")
    tag_rule(conn, rid, "tier:dmz")
    tags = list_tags_for_rule(conn, rid)
    assert tags == sorted(["group:web", "env:prod", "tier:dmz"])


def test_list_tags_for_rule_unknown_rule(conn):
    """list_tags_for_rule returns empty list for a rule that doesn't exist."""
    tags = list_tags_for_rule(conn, "nonexistent-uuid")
    assert tags == []


def test_list_tags_for_rule_empty(conn):
    """list_tags_for_rule returns empty list for a rule with no tags."""
    rid = _make_rule(conn)
    tags = list_tags_for_rule(conn, rid)
    assert tags == []


# ---------------------------------------------------------------------------
# list_rules_for_tag
# ---------------------------------------------------------------------------

def test_list_rules_for_tag_includes_only_tagged(conn):
    """list_rules_for_tag returns only rules with that specific tag."""
    rid1 = _make_rule(conn, "rule-a")
    rid2 = _make_rule(conn, "rule-b")
    tag_rule(conn, rid1, "group:web")
    tag_rule(conn, rid2, "group:db")

    web_rules = list_rules_for_tag(conn, "group:web")
    assert len(web_rules) == 1
    assert web_rules[0]["id"] == rid1


def test_list_rules_for_tag_deployed_only_excludes_undeployed(conn):
    """deployed_only=True excludes rules with deployed=0."""
    rid = _make_rule(conn, "rule-draft", deployed=0)
    tag_rule(conn, rid, "group:web")

    deployed = list_rules_for_tag(conn, "group:web", deployed_only=True)
    assert deployed == []

    all_rules = list_rules_for_tag(conn, "group:web", deployed_only=False)
    assert len(all_rules) == 1


def test_list_rules_for_tag_empty_tag(conn):
    """list_rules_for_tag returns empty list for a tag with no rules."""
    rows = list_rules_for_tag(conn, "group:nonexistent")
    assert rows == []


# ---------------------------------------------------------------------------
# list_all_tags
# ---------------------------------------------------------------------------

def test_list_all_tags_with_counts(conn):
    """list_all_tags returns each distinct tag with its rule_count."""
    rid1 = _make_rule(conn, "rule-1")
    rid2 = _make_rule(conn, "rule-2")
    rid3 = _make_rule(conn, "rule-3")

    tag_rule(conn, rid1, "group:web")
    tag_rule(conn, rid2, "group:web")
    tag_rule(conn, rid3, "group:db")

    result = list_all_tags(conn)
    result_dict = {t: c for t, c in result}

    assert result_dict["group:web"] == 2
    assert result_dict["group:db"] == 1


def test_list_all_tags_empty(conn):
    """list_all_tags returns empty list when no tags exist."""
    result = list_all_tags(conn)
    assert result == []


def test_list_all_tags_sorted_alphabetically(conn):
    """list_all_tags returns tags in alphabetical order."""
    rid = _make_rule(conn)
    tag_rule(conn, rid, "zzz:last")
    rid2 = _make_rule(conn, "rule-2")
    tag_rule(conn, rid2, "aaa:first")
    result = list_all_tags(conn)
    tags_only = [t for t, _ in result]
    assert tags_only == sorted(tags_only)
