"""
Subprocess wrapper around the sigma-cli ``sigma convert`` command.

Converts Sigma YAML rules to Wazuh XML by invoking sigma-cli as an
external process.  This module contains no import-time side effects —
it is safe to import even when sigma-cli is not installed; failures
surface only at call time via SigmaConversionError.

@decision DEC-SIGMA-CONVERT-001
@title Subprocess wrapper over sigma-cli, not the pySigma Python API
@status accepted
@rationale sigma-cli's Wazuh backend is distributed as a separate plugin
           (``sigma plugin install wazuh``). The subprocess boundary isolates
           the main process from any exception the backend raises or crashes,
           keeps the pySigma import surface out of our dependency graph, and
           makes it trivial to swap sigma-cli versions without touching
           application code.  The trade-off is an extra process-spawn per
           conversion (~50–200 ms), which is acceptable for an async, low-
           throughput auto-deploy path.

@decision DEC-SIGMA-DEGRADE-001
@title Graceful degradation when sigma-cli is absent
@status accepted
@rationale If the ``sigma`` executable is not on PATH, ``convert()`` raises
           SigmaConversionError with a clear message instead of crashing the
           process.  The startup probe (REQ-P0-P25-003, agent/main.py) calls
           ``sigma --version`` at boot; on failure it sets
           ``settings.sigmac_available = False``, which prevents the policy
           gate from ever routing a Sigma rule into this function.  The two
           layers together mean sigma-cli is strictly optional at runtime.
"""

from __future__ import annotations

import subprocess
import xml.etree.ElementTree as ET
from pathlib import Path


class SigmaConversionError(Exception):
    """Raised when sigma-cli conversion fails for any reason.

    Callers should catch this exception and record a skipped
    ``deploy_events`` row (DEC-AUTODEPLOY-003) rather than propagating
    it upward — a failed conversion must not abort an otherwise healthy
    triage cycle.
    """


def convert(yaml_content: str, rule_id: str, rules_dir: Path) -> Path:
    """Convert a Sigma YAML rule to Wazuh XML and write it to disk.

    Invokes ``sigma convert -t wazuh`` as a subprocess, feeds the YAML
    via stdin, writes the resulting XML to
    ``<rules_dir>/sigma_<rule_id>.xml``, and returns the output path.

    Args:
        yaml_content: The raw Sigma rule YAML as a string.
        rule_id:      An identifier used to name the output file.
                      Only alphanumerics, hyphens, and underscores are
                      safe; callers are responsible for sanitisation.
        rules_dir:    Directory where the XML file will be written.
                      Must exist before calling this function.

    Returns:
        Path to the written XML file (``rules_dir / f"sigma_{rule_id}.xml"``).

    Raises:
        SigmaConversionError: On any of the following conditions —
            * the ``sigma`` executable is not found on PATH
            * sigma-cli exits with a non-zero return code
            * sigma-cli produces empty stdout (no rules converted)
            * the stdout is not well-formed XML
    """
    cmd = ["sigma", "convert", "-t", "wazuh"]

    try:
        result = subprocess.run(
            cmd,
            input=yaml_content,
            capture_output=True,
            text=True,
            timeout=30,
        )
    except FileNotFoundError:
        raise SigmaConversionError(
            "sigma executable not found on PATH. "
            "Install sigma-cli and the Wazuh backend plugin "
            "('pip install sigma-cli && sigma plugin install wazuh') "
            "or set SIGMAC_PATH to its full path."
        ) from None
    except subprocess.TimeoutExpired:
        raise SigmaConversionError(
            f"sigma convert timed out after 30 s for rule_id={rule_id!r}"
        ) from None

    if result.returncode != 0:
        stderr_snippet = (result.stderr or "").strip()[:500]
        raise SigmaConversionError(
            f"sigma convert exited with code {result.returncode} "
            f"for rule_id={rule_id!r}. stderr: {stderr_snippet}"
        )

    xml_output = result.stdout.strip()

    if not xml_output:
        raise SigmaConversionError(
            f"sigma convert produced empty output for rule_id={rule_id!r}. "
            "The rule may not match any Wazuh-compatible log fields, or the "
            "Wazuh backend plugin may not be installed "
            "('sigma plugin install wazuh')."
        )

    # Validate well-formedness before writing to disk.
    try:
        ET.fromstring(xml_output)
    except ET.ParseError as exc:
        raise SigmaConversionError(
            f"sigma convert output for rule_id={rule_id!r} is not valid XML: {exc}"
        ) from exc

    out_path = rules_dir / f"sigma_{rule_id}.xml"
    out_path.write_text(xml_output, encoding="utf-8")
    return out_path
