"""
Claude tool-use orchestrator for Shaferhund Phase 2.

Replaces the single-shot call_claude with a multi-turn tool-use loop where
Claude can fetch cluster context, search related alerts, draft YARA/Sigma
rules, recommend deployment, and finalize triage — all within a single
reasoning session bounded by hard caps.

The tool handlers in this file are stubs (raise NotImplementedError). Real
implementations land in Wave B (issues #7 and #8). The control flow, schema
validation, caps, and failsafe are fully operational here.

@decision DEC-ORCH-001
@title Claude tool-use loop with 6 tools, 5-call / 10s caps
@status planned
@rationale Single-shot JSON extraction (Phase 1) can't handle multi-step
           reasoning: fetching extra context, drafting rules, deciding whether
           to deploy — all in one pass. A tool-use loop lets Claude act as an
           agent with read/write tools while hard caps (5 calls, 10s wall)
           prevent runaway API spend. The failsafe ensures a verdict always
           lands even if the loop exits abnormally. Wave B fills in real
           implementations behind the same interface.
"""

import json
import logging
import time
from typing import Any

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
# Tool handler stubs
# ---------------------------------------------------------------------------

def _handle_get_cluster_context(tool_input: dict) -> str:
    """Stub: retrieve full cluster context from the database.

    Will be implemented in Wave B (issue #7).
    """
    raise NotImplementedError(
        "get_cluster_context will be implemented in issue #7"
    )


def _handle_search_related_alerts(tool_input: dict) -> str:
    """Stub: search related alerts by src_ip across a time window.

    Will be implemented in Wave B (issue #7).
    """
    raise NotImplementedError(
        "search_related_alerts will be implemented in issue #7"
    )


def _handle_write_yara_rule(tool_input: dict) -> str:
    """Stub: draft, validate, and persist a YARA rule.

    Will be implemented in Wave B (issue #8).
    """
    raise NotImplementedError(
        "write_yara_rule will be implemented in issue #8"
    )


def _handle_write_sigma_rule(tool_input: dict) -> str:
    """Stub: draft, validate, and persist a Sigma rule.

    Will be implemented in Wave B (issue #8).
    """
    raise NotImplementedError(
        "write_sigma_rule will be implemented in issue #8"
    )


def _handle_recommend_deploy(tool_input: dict) -> str:
    """Stub: signal the policy gate that a rule is ready for auto-deployment.

    Will be implemented in Wave B (issue #7).
    """
    raise NotImplementedError(
        "recommend_deploy will be implemented in issue #7"
    )


def _handle_finalize_triage(tool_input: dict) -> TriageResult:
    """Construct a TriageResult from the finalize_triage tool input.

    This is the only handler that is NOT a stub — it constructs the final
    verdict and returns it. The DB commit (update_cluster_ai) happens in
    Wave B when run_triage_loop is wired into the triage queue.
    """
    return TriageResult(
        severity=tool_input["severity"],
        threat_assessment=tool_input["analysis"],
        iocs={"ips": [], "domains": [], "hashes": [], "paths": []},
        yara_rule="",
        cluster_id=str(tool_input.get("cluster_id", "")),
        raw_response=json.dumps(tool_input),
    )


# Map tool names to their handler functions.
_TOOL_DISPATCH: dict[str, Any] = {
    "get_cluster_context": _handle_get_cluster_context,
    "search_related_alerts": _handle_search_related_alerts,
    "write_yara_rule": _handle_write_yara_rule,
    "write_sigma_rule": _handle_write_sigma_rule,
    "recommend_deploy": _handle_recommend_deploy,
    "finalize_triage": _handle_finalize_triage,
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


def run_triage_loop(cluster: dict, claude_client: Any, config: Any) -> TriageResult:
    """Run the Claude tool-use loop for a single alert cluster.

    Drives Claude through up to config.orch_max_tool_calls tool-use iterations
    within a config.orch_wall_timeout_seconds wall-clock budget. Returns a
    TriageResult — either from a successful finalize_triage call or the
    failsafe default.

    Args:
        cluster:       Cluster data as a dict (keys: cluster_id, src_ip, …).
        claude_client: Anthropic client with a .messages.create() method.
                       May be synchronous (this function is sync — async
                       integration handled by the caller in Wave B).
        config:        Settings instance (must have orch_max_tool_calls and
                       orch_wall_timeout_seconds attributes).

    Returns:
        TriageResult with the final verdict (from finalize_triage or failsafe).
    """
    max_calls: int = config.orch_max_tool_calls
    wall_timeout: float = config.orch_wall_timeout_seconds
    cluster_id: str = str(cluster.get("cluster_id", "unknown"))

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

        # finalize_triage is the success path — extract result and exit.
        if tool_name == "finalize_triage":
            log.info(
                "Orchestrator: finalize_triage called for cluster %s (severity=%s)",
                cluster_id,
                tool_input.get("severity", "?"),
            )
            result = _handle_finalize_triage(tool_input)
            result.cluster_id = cluster_id
            return result

        # Dispatch to the stub handler — catch NotImplementedError gracefully.
        handler = _TOOL_DISPATCH.get(tool_name)
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
