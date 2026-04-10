"""
Claude tool-use orchestrator for Shaferhund Phase 2.

Replaces the single-shot call_claude with a multi-turn tool-use loop where
Claude can fetch cluster context, search related alerts, draft YARA/Sigma
rules, recommend deployment, and finalize triage — all within a single
reasoning session bounded by hard caps.

All 6 tool handlers are fully implemented and wired to the database via
closure factories. Read tools (get_cluster_context, search_related_alerts)
query existing data. Write tools (write_yara_rule, write_sigma_rule) validate
and persist detection rules. recommend_deploy records a deploy recommendation
in the deploy_events audit table. finalize_triage commits the AI verdict to
the cluster row and returns a TriageResult.

The handlers are exposed as standalone functions for direct unit-testing,
but need a DB connection to operate. run_triage_loop accepts an optional `conn`
parameter; when provided, it builds a local dispatch dict that injects the
connection (and cluster_id for write tools) via closures, overriding the
module-level stubs.

@decision DEC-ORCH-001
@title Claude tool-use loop with 6 tools, 5-call / 10s caps
@status accepted
@rationale Single-shot JSON extraction (Phase 1) can't handle multi-step
           reasoning: fetching extra context, drafting rules, deciding whether
           to deploy — all in one pass. A tool-use loop lets Claude act as an
           agent with read/write tools while hard caps (5 calls, 10s wall)
           prevent runaway API spend. The failsafe ensures a verdict always
           lands even if the loop exits abnormally.

@decision DEC-ORCH-002
@title Read handlers are standalone functions; DB connection injected via conn param
@status accepted
@rationale Keeping handlers as module-level functions (not a class) preserves
           the existing dispatch dict pattern and makes each handler independently
           testable without instantiating an orchestrator object. run_triage_loop
           receives an optional conn and builds closures locally, so no global
           state or module-level connection is required.

@decision DEC-ORCH-003
@title Write tool handlers use make_write_tool_handlers(conn, cluster_id) closure factory
@status accepted
@rationale Write tools (write_yara_rule, write_sigma_rule, recommend_deploy,
           finalize_triage) need both a DB connection and the current cluster_id.
           A closure factory parallel to make_read_tool_handlers keeps the same
           pattern: run_triage_loop builds an effective dispatch dict by merging
           read and write closures, no global state required. finalize_triage
           now calls update_cluster_ai to persist the verdict.
"""

import json
import logging
import sqlite3
import time
import uuid
from typing import Any, Optional

from .models import (
    get_alerts_by_src_ip,
    get_cluster_with_alerts,
    insert_deploy_event,
    insert_rule,
    update_cluster_ai,
)
from .triage import TriageResult

log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Tool schema — 6 tools for the orchestrator loop
# Each entry is a valid Anthropic tool definition dict.
# ---------------------------------------------------------------------------

TOOLS: list[dict] = [
    {
        "name": "get_cluster_context",
        "description": (
            "Retrieve full context for an alert cluster including all member alerts, "
            "source IP history, and associated rule details."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "cluster_id": {
                    "type": "integer",
                    "description": "The numeric ID of the cluster to retrieve.",
                },
            },
            "required": ["cluster_id"],
        },
    },
    {
        "name": "search_related_alerts",
        "description": (
            "Search for alerts from the same source IP across a time window. "
            "Surfaces cross-source correlation (Wazuh + Suricata) for the same actor."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "src_ip": {
                    "type": "string",
                    "description": "Source IP address to search for.",
                },
                "time_range_hours": {
                    "type": "integer",
                    "description": "How many hours back to search.",
                },
            },
            "required": ["src_ip", "time_range_hours"],
        },
    },
    {
        "name": "write_yara_rule",
        "description": (
            "Draft and persist a YARA detection rule for the current cluster. "
            "The rule is syntax-validated before storage. Returns the rule_id."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "content": {
                    "type": "string",
                    "description": "Complete YARA rule text.",
                },
                "description": {
                    "type": "string",
                    "description": "Human-readable description of what this rule detects.",
                },
            },
            "required": ["content", "description"],
        },
    },
    {
        "name": "write_sigma_rule",
        "description": (
            "Draft and persist a Sigma detection rule for the current cluster. "
            "The rule is validated with pysigma before storage. Returns the rule_id."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "content": {
                    "type": "string",
                    "description": "Complete Sigma rule YAML.",
                },
                "description": {
                    "type": "string",
                    "description": "Human-readable description of what this rule detects.",
                },
            },
            "required": ["content", "description"],
        },
    },
    {
        "name": "recommend_deploy",
        "description": (
            "Signal the policy gate that a rule is ready for auto-deployment. "
            "The gate evaluates confidence, severity, and dedup constraints. "
            "Does not deploy directly — sets a recommendation flag."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "rule_id": {
                    "type": "integer",
                    "description": "ID of the rule to recommend for deployment.",
                },
                "reason": {
                    "type": "string",
                    "description": "Justification for the deployment recommendation.",
                },
            },
            "required": ["rule_id", "reason"],
        },
    },
    {
        "name": "finalize_triage",
        "description": (
            "Commit the final triage verdict for this cluster and close the loop. "
            "MUST be called to produce a non-default result. Severity must be one of "
            "Critical, High, Medium, Low."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "severity": {
                    "type": "string",
                    "enum": ["Critical", "High", "Medium", "Low"],
                    "description": "Final severity classification.",
                },
                "analysis": {
                    "type": "string",
                    "description": "2-4 sentence threat assessment narrative.",
                },
                "rule_ids": {
                    "type": "array",
                    "items": {"type": "integer"},
                    "description": "IDs of rules drafted during this session (may be empty).",
                },
            },
            "required": ["severity", "analysis", "rule_ids"],
        },
    },
]

# ---------------------------------------------------------------------------
# Schema validation — called at module import
# ---------------------------------------------------------------------------

_REQUIRED_TOOL_KEYS = {"name", "description", "input_schema"}
_REQUIRED_SCHEMA_KEYS = {"type", "properties", "required"}


def _validate_tool_schema() -> None:
    """Validate that TOOLS is a well-formed list of Anthropic tool definitions.

    Called automatically at module import. Raises ValueError if any entry is
    malformed so broken schemas surface immediately rather than at runtime.
    """
    tool_names = set()
    for i, tool in enumerate(TOOLS):
        missing_keys = _REQUIRED_TOOL_KEYS - set(tool.keys())
        if missing_keys:
            raise ValueError(
                f"TOOLS[{i}] ({tool.get('name', '?')!r}) missing required keys: {missing_keys}"
            )

        schema = tool["input_schema"]
        if not isinstance(schema, dict):
            raise ValueError(
                f"TOOLS[{i}] ({tool['name']!r}) input_schema must be a dict"
            )
        if schema.get("type") != "object":
            raise ValueError(
                f"TOOLS[{i}] ({tool['name']!r}) input_schema.type must be 'object'"
            )
        if "properties" not in schema:
            raise ValueError(
                f"TOOLS[{i}] ({tool['name']!r}) input_schema missing 'properties'"
            )
        if "required" not in schema:
            raise ValueError(
                f"TOOLS[{i}] ({tool['name']!r}) input_schema missing 'required'"
            )

        if tool["name"] in tool_names:
            raise ValueError(f"Duplicate tool name: {tool['name']!r}")
        tool_names.add(tool["name"])


# Run at import time — catches schema regressions before any loop executes.
_validate_tool_schema()

# ---------------------------------------------------------------------------
# Prompt builder
# ---------------------------------------------------------------------------


def build_cluster_context_prompt(cluster: dict) -> str:
    """Format a cluster dict into a readable prompt for the orchestrator loop.

    The cluster dict is expected to have the keys produced by the existing
    _build_cluster_summary helper in triage.py (cluster_id, src_ip, rule_id,
    alert_count, window_start, window_end, sample_alerts). Missing keys are
    handled gracefully — the prompt is best-effort.
    """
    lines = [
        "You are a cybersecurity analyst operating as an agentic defender.",
        "Analyse the following alert cluster and use your available tools to:",
        "  1. Gather any additional context you need.",
        "  2. Draft detection rules (YARA and/or Sigma) if the cluster looks malicious.",
        "  3. Recommend deployment for high-confidence rules.",
        "  4. Call finalize_triage with your verdict to close the session.",
        "",
        "Alert cluster:",
        json.dumps(cluster, default=str, indent=2),
    ]
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Tool handlers — read tools (issue #8)
# ---------------------------------------------------------------------------

def _handle_get_cluster_context(tool_input: dict, conn: sqlite3.Connection) -> str:
    """Return full cluster context as a JSON string.

    Fetches the cluster row and all member alerts from the DB, then builds a
    summary dict with cluster metadata and up to 5 sample alerts. Returns an
    error JSON if the cluster is not found.

    This is a READ-ONLY handler — it never modifies DB state.

    Args:
        tool_input: Dict with key ``cluster_id`` (int or str).
        conn:       Open SQLite connection (injected by run_triage_loop).

    Returns:
        JSON string — either a cluster summary or ``{"error": "..."}`` if the
        cluster does not exist.
    """
    cluster_id = str(tool_input.get("cluster_id", ""))
    if not cluster_id:
        return json.dumps({"error": "cluster_id is required"})

    data = get_cluster_with_alerts(conn, cluster_id)
    if data is None:
        return json.dumps({"error": f"cluster '{cluster_id}' not found"})

    cluster = data["cluster"]
    alerts = data["alerts"]

    # Build sample_alerts — first 5, key fields only, to keep the context compact.
    sample_alerts = []
    for a in alerts[:5]:
        sample_alerts.append({
            "id":          a.get("id"),
            "rule_id":     a.get("rule_id"),
            "src_ip":      a.get("src_ip"),
            "severity":    a.get("severity"),
            "source":      a.get("source"),
            "ingested_at": a.get("ingested_at"),
        })

    summary = {
        "cluster_id":   cluster.get("id"),
        "src_ip":       cluster.get("src_ip"),
        "source":       cluster.get("source"),
        "rule_id":      cluster.get("rule_id"),
        "alert_count":  cluster.get("alert_count"),
        "window_start": cluster.get("window_start"),
        "window_end":   cluster.get("window_end"),
        "sample_alerts": sample_alerts,
    }
    log.debug("get_cluster_context: cluster=%s alerts=%d", cluster_id, len(alerts))
    return json.dumps(summary, default=str)


def _handle_search_related_alerts(tool_input: dict, conn: sqlite3.Connection) -> str:
    """Search for alerts from a given src_ip across a time window.

    Groups results by source (wazuh vs suricata) and returns counts plus a
    sample of rule IDs seen per source. Returns a JSON object with
    ``total_count=0`` when no alerts match — never an error for empty results.

    This is a READ-ONLY handler — it never modifies DB state.

    Args:
        tool_input: Dict with keys ``src_ip`` (str) and
                    ``time_range_hours`` (int).
        conn:       Open SQLite connection (injected by run_triage_loop).

    Returns:
        JSON string with keys: total_count, by_source, time_range_hours.
    """
    src_ip = tool_input.get("src_ip", "")
    hours = int(tool_input.get("time_range_hours", 24))

    if not src_ip:
        return json.dumps({"error": "src_ip is required"})

    alerts = get_alerts_by_src_ip(conn, src_ip, hours)

    # Group by source — collect counts and a deduplicated sample of rule_ids.
    by_source: dict[str, dict] = {}
    for alert in alerts:
        source = alert.get("source") or "unknown"
        if source not in by_source:
            by_source[source] = {"count": 0, "sample_rule_ids": []}
        by_source[source]["count"] += 1
        rule_id = alert.get("rule_id")
        if rule_id is not None and rule_id not in by_source[source]["sample_rule_ids"]:
            by_source[source]["sample_rule_ids"].append(rule_id)

    result = {
        "total_count":      len(alerts),
        "by_source":        by_source,
        "time_range_hours": hours,
    }
    log.debug(
        "search_related_alerts: src_ip=%s hours=%d total=%d",
        src_ip,
        hours,
        len(alerts),
    )
    return json.dumps(result, default=str)


# ---------------------------------------------------------------------------
# Closure factory — injects DB connection into read handlers
# ---------------------------------------------------------------------------

def make_read_tool_handlers(conn: sqlite3.Connection) -> dict:
    """Return a partial dispatch dict with DB-bound read tool handlers.

    Used by run_triage_loop to override the module-level no-conn stubs for
    get_cluster_context and search_related_alerts when a real DB connection
    is available. Write tools are handled separately by make_write_tool_handlers.

    Args:
        conn: Open SQLite connection to inject into the closures.

    Returns:
        Dict mapping tool name -> callable(tool_input: dict) -> str.
    """
    return {
        "get_cluster_context":    lambda ti: _handle_get_cluster_context(ti, conn),
        "search_related_alerts":  lambda ti: _handle_search_related_alerts(ti, conn),
    }


# ---------------------------------------------------------------------------
# Syntax validation helpers
# ---------------------------------------------------------------------------


def _check_yara_syntax(rule_content: str) -> bool:
    """Return True if the YARA rule compiles without errors.

    Gracefully returns False (rather than raising) if the yara Python
    library is not installed -- the rule is stored but marked invalid.
    """
    try:
        import yara  # type: ignore

        yara.compile(source=rule_content)
        return True
    except ImportError:
        log.debug("yara-python not installed; skipping syntax check")
        return False
    except Exception as exc:
        log.warning("YARA syntax error: %s", exc)
        return False


def _check_sigma_syntax(rule_content: str) -> bool:
    """Return True if the Sigma rule YAML is parseable and structurally valid.

    Uses pysigma's SigmaCollection.from_yaml() when available. Falls back to
    basic YAML parsing if pysigma is not installed -- the rule is stored but
    marked invalid since we cannot fully validate without pysigma.
    """
    try:
        from sigma.collection import SigmaCollection  # type: ignore

        SigmaCollection.from_yaml(rule_content)
        return True
    except ImportError:
        # pysigma not installed -- try basic YAML parse as a minimal check.
        try:
            import yaml

            parsed = yaml.safe_load(rule_content)
            # A valid Sigma rule must be a dict with at minimum a 'title' key.
            if not isinstance(parsed, dict) or "title" not in parsed:
                return False
            return True
        except Exception:
            return False
    except Exception as exc:
        log.warning("Sigma validation error: %s", exc)
        return False


# ---------------------------------------------------------------------------
# Tool handlers -- write tools
# ---------------------------------------------------------------------------


def _handle_write_yara_rule(
    tool_input: dict, conn: sqlite3.Connection, cluster_id: str
) -> str:
    """Validate, persist, and return metadata for a YARA detection rule.

    Syntax-checks the rule content via yara.compile(). Persists to the rules
    table regardless of validity (syntax_valid flag captures the result).
    Returns a JSON object with the rule_id and validation status.

    Args:
        tool_input: Dict with keys ``content`` (str) and ``description`` (str).
        conn:       Open SQLite connection (injected via closure).
        cluster_id: The cluster this rule belongs to.

    Returns:
        JSON string with keys: rule_id, syntax_valid, rule_type.
    """
    content = tool_input.get("content", "")
    description = tool_input.get("description", "")

    if not content.strip():
        return json.dumps({"error": "content is required"})

    syntax_valid = _check_yara_syntax(content)
    rule_id = str(uuid.uuid4())

    insert_rule(
        conn,
        rule_id=rule_id,
        cluster_id=cluster_id,
        rule_type="yara",
        rule_content=content,
        syntax_valid=syntax_valid,
    )

    log.info(
        "YARA rule stored: rule_id=%s cluster=%s syntax_valid=%s desc=%s",
        rule_id,
        cluster_id,
        syntax_valid,
        description[:80],
    )
    return json.dumps({
        "rule_id": rule_id,
        "rule_type": "yara",
        "syntax_valid": syntax_valid,
    })


def _handle_write_sigma_rule(
    tool_input: dict, conn: sqlite3.Connection, cluster_id: str
) -> str:
    """Validate, persist, and return metadata for a Sigma detection rule.

    Syntax-checks the rule content via pysigma (or basic YAML parse as
    fallback). Persists to the rules table regardless of validity.
    Returns a JSON object with the rule_id and validation status.

    Args:
        tool_input: Dict with keys ``content`` (str) and ``description`` (str).
        conn:       Open SQLite connection (injected via closure).
        cluster_id: The cluster this rule belongs to.

    Returns:
        JSON string with keys: rule_id, syntax_valid, rule_type.
    """
    content = tool_input.get("content", "")
    description = tool_input.get("description", "")

    if not content.strip():
        return json.dumps({"error": "content is required"})

    syntax_valid = _check_sigma_syntax(content)
    rule_id = str(uuid.uuid4())

    insert_rule(
        conn,
        rule_id=rule_id,
        cluster_id=cluster_id,
        rule_type="sigma",
        rule_content=content,
        syntax_valid=syntax_valid,
    )

    log.info(
        "Sigma rule stored: rule_id=%s cluster=%s syntax_valid=%s desc=%s",
        rule_id,
        cluster_id,
        syntax_valid,
        description[:80],
    )
    return json.dumps({
        "rule_id": rule_id,
        "rule_type": "sigma",
        "syntax_valid": syntax_valid,
    })


def _handle_recommend_deploy(
    tool_input: dict, conn: sqlite3.Connection
) -> str:
    """Record a deploy recommendation in the deploy_events audit table.

    Does not deploy directly -- records the recommendation so the policy
    gate can evaluate it. Returns the deploy_event row id.

    Args:
        tool_input: Dict with keys ``rule_id`` (int) and ``reason`` (str).
        conn:       Open SQLite connection (injected via closure).

    Returns:
        JSON string with keys: deploy_event_id, action, rule_id.
    """
    rule_id = tool_input.get("rule_id")
    reason = tool_input.get("reason", "")

    if rule_id is None:
        return json.dumps({"error": "rule_id is required"})

    deploy_event_id = insert_deploy_event(
        conn,
        rule_id=int(rule_id),
        action="recommend",
        reason=reason,
        actor="orchestrator",
    )

    log.info(
        "Deploy recommendation recorded: event_id=%d rule_id=%s reason=%s",
        deploy_event_id,
        rule_id,
        reason[:80],
    )
    return json.dumps({
        "deploy_event_id": deploy_event_id,
        "action": "recommend",
        "rule_id": rule_id,
    })


def _handle_finalize_triage(
    tool_input: dict,
    conn: Optional[sqlite3.Connection] = None,
    cluster_id: str = "",
) -> TriageResult:
    """Construct a TriageResult and persist the verdict to the cluster row.

    When conn is provided, calls update_cluster_ai to write the AI severity
    and analysis to the cluster row. When conn is None (no-DB mode, e.g.
    unit tests with mock clients), the TriageResult is still returned but
    nothing is persisted.

    Args:
        tool_input:  Dict with keys ``severity``, ``analysis``, ``rule_ids``.
        conn:        Optional SQLite connection (injected via closure).
        cluster_id:  The cluster being triaged.

    Returns:
        TriageResult with the final verdict.
    """
    severity = tool_input["severity"]
    analysis = tool_input["analysis"]

    if conn is not None and cluster_id:
        update_cluster_ai(conn, cluster_id, severity, analysis)
        log.info(
            "Cluster %s verdict persisted: severity=%s",
            cluster_id,
            severity,
        )

    return TriageResult(
        severity=severity,
        threat_assessment=analysis,
        iocs={"ips": [], "domains": [], "hashes": [], "paths": []},
        yara_rule="",
        cluster_id=cluster_id,
        raw_response=json.dumps(tool_input),
    )


# ---------------------------------------------------------------------------
# Closure factory — injects DB connection + cluster_id into write handlers
# ---------------------------------------------------------------------------


def make_write_tool_handlers(
    conn: sqlite3.Connection, cluster_id: str
) -> dict:
    """Return a partial dispatch dict with DB-bound write tool handlers.

    Used by run_triage_loop to override the module-level no-conn stubs for
    write_yara_rule, write_sigma_rule, recommend_deploy, and finalize_triage
    when a real DB connection is available.

    Args:
        conn:       Open SQLite connection to inject into the closures.
        cluster_id: The cluster being triaged (needed by rule insert and
                    finalize_triage's update_cluster_ai call).

    Returns:
        Dict mapping tool name -> callable(tool_input: dict) -> str|TriageResult.
    """
    return {
        "write_yara_rule":   lambda ti: _handle_write_yara_rule(ti, conn, cluster_id),
        "write_sigma_rule":  lambda ti: _handle_write_sigma_rule(ti, conn, cluster_id),
        "recommend_deploy":  lambda ti: _handle_recommend_deploy(ti, conn),
        "finalize_triage":   lambda ti: _handle_finalize_triage(ti, conn, cluster_id),
    }


def _no_conn_stub(tool_name: str) -> str:
    """Return an informative JSON error when a tool is called without a DB connection.

    Used as the fallback in _TOOL_DISPATCH for all DB-dependent tools when
    run_triage_loop is called without a conn. Claude receives a clear message
    and can proceed to finalize_triage.
    """
    return json.dumps({
        "error": f"Tool '{tool_name}' requires a database connection (conn=None in run_triage_loop)."
    })


# Map tool names to their handler functions.
# All DB-dependent tools use no-conn stubs here; they are replaced with real
# DB-bound closures in run_triage_loop when conn is provided via
# make_read_tool_handlers() and make_write_tool_handlers().
# finalize_triage has a special no-conn stub that still returns a TriageResult
# (without DB persistence) so the loop can always produce a verdict.
_TOOL_DISPATCH: dict[str, Any] = {
    "get_cluster_context":   lambda ti: _no_conn_stub("get_cluster_context"),
    "search_related_alerts": lambda ti: _no_conn_stub("search_related_alerts"),
    "write_yara_rule":       lambda ti: _no_conn_stub("write_yara_rule"),
    "write_sigma_rule":      lambda ti: _no_conn_stub("write_sigma_rule"),
    "recommend_deploy":      lambda ti: _no_conn_stub("recommend_deploy"),
    "finalize_triage":       lambda ti: _handle_finalize_triage(ti),
}

# Default verdict returned when the loop exits without finalize_triage.
_FAILSAFE_RESULT = TriageResult(
    severity="Unknown",
    threat_assessment="orchestrator loop exited without finalizing",
    iocs={"ips": [], "domains": [], "hashes": [], "paths": []},
    yara_rule="",
    cluster_id="",
    raw_response="",
)

# ---------------------------------------------------------------------------
# Main orchestrator loop
# ---------------------------------------------------------------------------


def run_triage_loop(
    cluster: dict,
    claude_client: Any,
    config: Any,
    conn: Optional[sqlite3.Connection] = None,
) -> TriageResult:
    """Run the Claude tool-use loop for a single alert cluster.

    Drives Claude through up to config.orch_max_tool_calls tool-use iterations
    within a config.orch_wall_timeout_seconds wall-clock budget. Returns a
    TriageResult — either from a successful finalize_triage call or the
    failsafe default.

    Args:
        cluster:       Cluster data as a dict (keys: cluster_id, src_ip, ...).
        claude_client: Anthropic client with a .messages.create() method.
                       May be synchronous (this function is sync -- async
                       integration handled by the caller).
        config:        Settings instance (must have orch_max_tool_calls and
                       orch_wall_timeout_seconds attributes).
        conn:          Optional SQLite connection. When provided, all tool
                       handlers are wired to the real DB via closures:
                       read tools query data, write tools persist rules and
                       deploy events, finalize_triage writes the verdict to
                       the cluster row. When None, DB-dependent tools return
                       a "not available" message to Claude (except
                       finalize_triage which still returns a TriageResult).

    Returns:
        TriageResult with the final verdict (from finalize_triage or failsafe).
    """
    max_calls: int = config.orch_max_tool_calls
    wall_timeout: float = config.orch_wall_timeout_seconds
    cluster_id: str = str(cluster.get("cluster_id", "unknown"))

    # Build an effective dispatch dict: start from the module-level stubs and
    # overlay with DB-bound closures when a connection is available.
    effective_dispatch: dict[str, Any] = dict(_TOOL_DISPATCH)
    if conn is not None:
        effective_dispatch.update(make_read_tool_handlers(conn))
        effective_dispatch.update(make_write_tool_handlers(conn, cluster_id))

    prompt = build_cluster_context_prompt(cluster)
    messages: list[dict] = [{"role": "user", "content": prompt}]

    wall_start = time.monotonic()
    calls_made = 0

    log.info(
        "Orchestrator starting for cluster %s (max_calls=%d, wall_timeout=%.1fs)",
        cluster_id,
        max_calls,
        wall_timeout,
    )

    for _ in range(max_calls):
        # Wall-clock check at the top of each iteration.
        elapsed = time.monotonic() - wall_start
        if elapsed >= wall_timeout:
            log.warning(
                "Orchestrator wall timeout (%.1fs >= %.1fs) for cluster %s after %d calls",
                elapsed,
                wall_timeout,
                cluster_id,
                calls_made,
            )
            return _make_failsafe(cluster_id)

        # Call Claude.
        try:
            response = claude_client.messages.create(
                model=config.claude_model,
                max_tokens=1024,
                tools=TOOLS,
                messages=messages,
            )
        except Exception as exc:
            log.error(
                "Claude API error in orchestrator for cluster %s: %s",
                cluster_id,
                exc,
                exc_info=True,
            )
            return _make_failsafe(cluster_id)

        calls_made += 1

        stop_reason = getattr(response, "stop_reason", None)
        log.debug(
            "Orchestrator call %d for cluster %s: stop_reason=%s",
            calls_made,
            cluster_id,
            stop_reason,
        )

        if stop_reason == "end_turn":
            # Claude decided it was done without calling finalize_triage.
            log.warning(
                "Orchestrator: end_turn without finalize_triage for cluster %s",
                cluster_id,
            )
            return _make_failsafe(cluster_id)

        if stop_reason != "tool_use":
            # Unexpected stop reason — treat as failsafe.
            log.warning(
                "Orchestrator: unexpected stop_reason %r for cluster %s",
                stop_reason,
                cluster_id,
            )
            return _make_failsafe(cluster_id)

        # Extract tool use blocks from the response.
        tool_use_block = _extract_tool_use_block(response)
        if tool_use_block is None:
            log.warning(
                "Orchestrator: stop_reason=tool_use but no tool_use block for cluster %s",
                cluster_id,
            )
            return _make_failsafe(cluster_id)

        tool_name = tool_use_block.get("name", "")
        tool_input = tool_use_block.get("input", {})
        tool_use_id = tool_use_block.get("id", "")

        # Append Claude's full response message to conversation.
        messages.append({"role": "assistant", "content": response.content})

        # finalize_triage is the success path -- extract result and exit.
        if tool_name == "finalize_triage":
            log.info(
                "Orchestrator: finalize_triage called for cluster %s (severity=%s)",
                cluster_id,
                tool_input.get("severity", "?"),
            )
            finalize_handler = effective_dispatch["finalize_triage"]
            result = finalize_handler(tool_input)
            result.cluster_id = cluster_id
            return result

        # Dispatch to the handler — catch NotImplementedError gracefully for stubs.
        handler = effective_dispatch.get(tool_name)
        if handler is None:
            tool_result_content = f"Error: unknown tool '{tool_name}'"
            log.error("Orchestrator: unknown tool %r for cluster %s", tool_name, cluster_id)
        else:
            try:
                tool_result_content = handler(tool_input)
                if not isinstance(tool_result_content, str):
                    tool_result_content = json.dumps(tool_result_content, default=str)
            except NotImplementedError as exc:
                # Stubs raise NotImplementedError — return a clear error to Claude
                # so it can decide what to do (likely proceed to finalize_triage).
                tool_result_content = f"Tool not yet implemented: {exc}"
                log.debug(
                    "Orchestrator: stub tool %r called for cluster %s: %s",
                    tool_name,
                    cluster_id,
                    exc,
                )

        # Append tool result to conversation for the next turn.
        messages.append(
            {
                "role": "user",
                "content": [
                    {
                        "type": "tool_result",
                        "tool_use_id": tool_use_id,
                        "content": tool_result_content,
                    }
                ],
            }
        )

    # Loop exhausted the max_calls cap without finalize_triage.
    log.warning(
        "Orchestrator: max_calls cap (%d) reached for cluster %s without finalize_triage",
        max_calls,
        cluster_id,
    )
    return _make_failsafe(cluster_id)


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _make_failsafe(cluster_id: str) -> TriageResult:
    """Return the failsafe TriageResult with the given cluster_id filled in."""
    return TriageResult(
        severity="Unknown",
        threat_assessment="orchestrator loop exited without finalizing",
        iocs={"ips": [], "domains": [], "hashes": [], "paths": []},
        yara_rule="",
        cluster_id=cluster_id,
        raw_response="",
    )


def _extract_tool_use_block(response: Any) -> dict | None:
    """Extract the first tool_use content block from a Claude response.

    Returns a dict with keys {id, name, input} or None if no tool_use block
    is present.
    """
    content = getattr(response, "content", [])
    for block in content:
        block_type = getattr(block, "type", None)
        if block_type == "tool_use":
            return {
                "id": getattr(block, "id", ""),
                "name": getattr(block, "name", ""),
                "input": getattr(block, "input", {}),
            }
    return None
