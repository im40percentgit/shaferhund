"""
register_tool() API tests — Phase 4 (REQ-P0-P4-004, DEC-ORCH-006, DEC-ORCH-007).

Verifies the new registration API, the derived TOOLS list, and dispatch() error
paths.  These tests complement the existing test_orchestrator.py tests which
already verify the 7 migrated tools end-to-end.

Tests:
  1. test_register_tool_rejects_duplicate_name
       register_tool() raises ValueError when a name is already in _REGISTRY.
  2. test_register_tool_validates_spec_missing_name
       register_tool() raises ValueError for a spec missing the 'name' key.
  3. test_register_tool_validates_spec_missing_input_schema
       register_tool() raises ValueError for a spec missing 'input_schema'.
  4. test_register_tool_validates_spec_bad_schema_type
       register_tool() raises ValueError when input_schema.type != 'object'.
  5. test_dispatch_raises_on_missing_conn
       dispatch() returns error JSON (not a crash) when a requires_conn tool
       is called with conn=None.
  6. test_dispatch_raises_on_missing_cluster_id_no_conn
       dispatch() returns error JSON when a requires_cluster_id tool is called
       with conn=None (and allows_no_conn=False).
  7. test_register_tool_adds_to_tools_list
       A newly registered synthetic tool appears in TOOLS after registration.
  8. test_dispatch_calls_synthetic_handler
       dispatch() correctly routes to a synthetic handler registered via register_tool.

Note: tests that mutate _REGISTRY are isolated via a fixture that restores the
original registry and TOOLS list after each test.

# @mock-exempt: no external boundaries mocked — all tests use real _REGISTRY.

@decision DEC-ORCH-006
@title register_tool() API tests — REQ-P0-P4-004
@status accepted
@rationale Acceptance criteria for issue #42 require new tests that verify
           register_tool() spec validation, duplicate rejection, and dispatch()
           error paths. These tests do not mock any internal module — they
           drive the real register_tool() and dispatch() implementations directly,
           consistent with Sacred Practice #5.
"""

import json

import pytest

import agent.orchestrator as _orch
from agent.orchestrator import TOOLS, dispatch, register_tool


# ---------------------------------------------------------------------------
# Fixture — registry isolation for tests that add synthetic tools
# ---------------------------------------------------------------------------

@pytest.fixture
def isolated_registry():
    """Snapshot _REGISTRY and TOOLS before the test; restore after.

    Tests that call register_tool() with a synthetic spec will mutate the
    module-level _REGISTRY dict.  This fixture ensures those mutations don't
    bleed into subsequent tests (e.g. the 7-tool count assertions in
    test_orchestrator.py would break if a synthetic tool persisted).
    """
    original_registry = dict(_orch._REGISTRY)
    original_tools = list(_orch.TOOLS)
    yield
    _orch._REGISTRY.clear()
    _orch._REGISTRY.update(original_registry)
    _orch.TOOLS = original_tools


# ---------------------------------------------------------------------------
# Minimal valid spec helper
# ---------------------------------------------------------------------------

def _minimal_spec(name: str = "synthetic_tool") -> dict:
    """Return a minimal valid tool spec with the given name."""
    return {
        "name": name,
        "description": "A synthetic tool for testing.",
        "input_schema": {
            "type": "object",
            "properties": {
                "value": {"type": "string", "description": "Any string."},
            },
            "required": ["value"],
        },
    }


# ---------------------------------------------------------------------------
# Test 1: Duplicate name rejected
# ---------------------------------------------------------------------------

def test_register_tool_rejects_duplicate_name(isolated_registry):
    """register_tool() raises ValueError when the tool name is already registered."""
    register_tool(
        spec=_minimal_spec("dup_tool"),
        handler=lambda ti: json.dumps({"ok": True}),
    )
    with pytest.raises(ValueError, match="Duplicate tool name"):
        register_tool(
            spec=_minimal_spec("dup_tool"),
            handler=lambda ti: json.dumps({"ok": True}),
        )


# ---------------------------------------------------------------------------
# Test 2: Spec missing 'name' key rejected
# ---------------------------------------------------------------------------

def test_register_tool_validates_spec_missing_name():
    """register_tool() raises ValueError when the spec dict has no 'name' key."""
    bad_spec = {
        "description": "Missing name.",
        "input_schema": {
            "type": "object",
            "properties": {},
            "required": [],
        },
    }
    with pytest.raises(ValueError, match="missing required keys"):
        register_tool(spec=bad_spec, handler=lambda ti: "{}")


# ---------------------------------------------------------------------------
# Test 3: Spec missing 'input_schema' key rejected
# ---------------------------------------------------------------------------

def test_register_tool_validates_spec_missing_input_schema():
    """register_tool() raises ValueError when the spec dict has no 'input_schema' key."""
    bad_spec = {
        "name": "no_schema_tool",
        "description": "Missing input_schema.",
    }
    with pytest.raises(ValueError, match="missing required keys"):
        register_tool(spec=bad_spec, handler=lambda ti: "{}")


# ---------------------------------------------------------------------------
# Test 4: input_schema.type != 'object' rejected
# ---------------------------------------------------------------------------

def test_register_tool_validates_spec_bad_schema_type():
    """register_tool() raises ValueError when input_schema.type is not 'object'."""
    bad_spec = {
        "name": "bad_type_tool",
        "description": "Wrong schema type.",
        "input_schema": {
            "type": "string",   # must be 'object'
            "properties": {},
            "required": [],
        },
    }
    with pytest.raises(ValueError, match="must be 'object'"):
        register_tool(spec=bad_spec, handler=lambda ti: "{}")


# ---------------------------------------------------------------------------
# Test 5: dispatch() returns error JSON when requires_conn tool called without conn
# ---------------------------------------------------------------------------

def test_dispatch_raises_on_missing_conn():
    """dispatch() returns error JSON (not a crash) when conn=None for a requires_conn tool.

    Uses get_cluster_context — a requires_conn, allows_no_conn=False tool.
    """
    result = dispatch("get_cluster_context", {"cluster_id": 1}, conn=None)
    parsed = json.loads(result)
    assert "error" in parsed
    assert "database connection" in parsed["error"].lower() or "conn" in parsed["error"]


# ---------------------------------------------------------------------------
# Test 6: dispatch() returns error JSON for requires_cluster_id tool without conn
# ---------------------------------------------------------------------------

def test_dispatch_raises_on_write_tool_without_conn():
    """dispatch() returns error JSON when a write tool (requires_cluster_id) gets conn=None."""
    for tool_name in ("write_yara_rule", "write_sigma_rule", "recommend_deploy"):
        result = dispatch(tool_name, {}, conn=None)
        parsed = json.loads(result)
        assert "error" in parsed, f"{tool_name}: expected error JSON with conn=None"
        assert "database connection" in parsed["error"].lower() or "conn" in parsed["error"]


# ---------------------------------------------------------------------------
# Test 7: Newly registered tool appears in TOOLS
# ---------------------------------------------------------------------------

def test_register_tool_adds_to_tools_list(isolated_registry):
    """After register_tool(), the new spec appears in the public TOOLS list."""
    baseline = len(_orch.TOOLS)
    spec = _minimal_spec("new_synthetic_tool")
    register_tool(spec=spec, handler=lambda ti: json.dumps({"synthetic": True}))

    assert len(_orch.TOOLS) == baseline + 1
    names = [t["name"] for t in _orch.TOOLS]
    assert "new_synthetic_tool" in names


# ---------------------------------------------------------------------------
# Test 8: dispatch() routes to synthetic handler
# ---------------------------------------------------------------------------

def test_dispatch_calls_synthetic_handler(isolated_registry):
    """dispatch() invokes the registered handler and returns its output."""
    calls = []

    def synthetic_handler(tool_input: dict) -> str:
        calls.append(tool_input)
        return json.dumps({"received": tool_input.get("value")})

    register_tool(
        spec=_minimal_spec("callable_synthetic"),
        handler=synthetic_handler,
        requires_conn=False,
    )

    result = dispatch("callable_synthetic", {"value": "hello"})
    assert json.loads(result) == {"received": "hello"}
    assert len(calls) == 1
    assert calls[0] == {"value": "hello"}
