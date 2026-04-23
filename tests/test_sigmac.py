"""
Tests for agent/sigmac.py — the sigma-cli subprocess wrapper.

All tests except the happy-path real-invocation variant use mocks for
subprocess.run so sigma-cli does not need to be installed in CI.

# @mock-exempt: subprocess.run is an external process boundary (sigma-cli
# is a third-party CLI tool).  Mocking it here is consistent with Sacred
# Practice #5 — we are NOT mocking internal modules.  The real-invocation
# test (test_convert_real_invocation_happy_path) exercises the full stack
# when sigma-cli is present.

@decision DEC-SIGMA-CONVERT-001
@title Tests validate the subprocess contract, not sigma-cli internals
@status accepted
@rationale The wrapper's correctness is about what it does with sigma-cli's
           output (non-zero exit → raise, empty stdout → raise, invalid XML
           → raise, good XML → write file).  Mocking subprocess.run is the
           right boundary here: it is an external process, not an internal
           module.  The single real-invocation test is skipif-guarded so CI
           without sigma-cli still gets full mock coverage.
"""

from __future__ import annotations

import subprocess
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from agent.sigmac import SigmaConversionError, convert


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

MINIMAL_SIGMA_YAML = """\
title: Test Suspicious Process
id: 11111111-1111-1111-1111-111111111111
status: test
description: Minimal sigma rule for unit testing
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains: 'suspicious.exe'
    condition: selection
level: high
"""

MINIMAL_WAZUH_XML = """\
<?xml version="1.0" encoding="UTF-8"?>
<group name="sigma,windows,">
  <rule id="100001" level="12">
    <field name="CommandLine" type="pcre2">(?i)suspicious\\.exe</field>
    <description>Test Suspicious Process</description>
    <options>no_full_log</options>
  </rule>
</group>
"""


def _make_completed_process(returncode=0, stdout="", stderr=""):
    """Build a CompletedProcess-like mock."""
    mock = MagicMock(spec=subprocess.CompletedProcess)
    mock.returncode = returncode
    mock.stdout = stdout
    mock.stderr = stderr
    return mock


# ---------------------------------------------------------------------------
# Happy path — mocked subprocess returning valid XML
# ---------------------------------------------------------------------------


def test_convert_happy_path_produces_valid_xml(tmp_path):
    """convert() writes a valid XML file and returns its path."""
    with patch("agent.sigmac.subprocess.run") as mock_run:
        mock_run.return_value = _make_completed_process(
            returncode=0, stdout=MINIMAL_WAZUH_XML
        )

        out_path = convert(
            yaml_content=MINIMAL_SIGMA_YAML,
            rule_id="test-rule-001",
            rules_dir=tmp_path,
        )

    assert out_path == tmp_path / "sigma_test-rule-001.xml"
    assert out_path.exists()
    content = out_path.read_text(encoding="utf-8")
    # Must start with the XML declaration or a root tag.
    assert content.strip().startswith("<?xml") or content.strip().startswith("<")
    # Must be parseable by the stdlib XML parser (basic well-formedness).
    import xml.etree.ElementTree as ET
    tree = ET.parse(str(out_path))
    assert tree.getroot() is not None

    # Verify subprocess was called with correct arguments.
    mock_run.assert_called_once()
    call_args = mock_run.call_args
    cmd = call_args.args[0]
    assert cmd[:4] == ["sigma", "convert", "-t", "wazuh"]
    assert call_args.kwargs.get("input") == MINIMAL_SIGMA_YAML
    assert call_args.kwargs.get("capture_output") is True
    assert call_args.kwargs.get("text") is True
    assert call_args.kwargs.get("timeout") == 30


# ---------------------------------------------------------------------------
# Error paths (all mocked)
# ---------------------------------------------------------------------------


def test_convert_raises_on_nonzero_exit(tmp_path):
    """Non-zero sigma-cli exit code raises SigmaConversionError with stderr."""
    stderr_text = "Error: unsupported target platform"
    with patch("agent.sigmac.subprocess.run") as mock_run:
        mock_run.return_value = _make_completed_process(
            returncode=1, stdout="", stderr=stderr_text
        )
        with pytest.raises(SigmaConversionError) as exc_info:
            convert(MINIMAL_SIGMA_YAML, "bad-rule", tmp_path)

    assert "code 1" in str(exc_info.value)
    assert stderr_text in str(exc_info.value)


def test_convert_raises_on_empty_output(tmp_path):
    """Exit 0 with empty stdout raises SigmaConversionError."""
    with patch("agent.sigmac.subprocess.run") as mock_run:
        mock_run.return_value = _make_completed_process(
            returncode=0, stdout="", stderr=""
        )
        with pytest.raises(SigmaConversionError) as exc_info:
            convert(MINIMAL_SIGMA_YAML, "empty-rule", tmp_path)

    assert "empty output" in str(exc_info.value)


def test_convert_raises_when_sigma_executable_missing(tmp_path):
    """FileNotFoundError from subprocess.run becomes SigmaConversionError."""
    with patch("agent.sigmac.subprocess.run", side_effect=FileNotFoundError()):
        with pytest.raises(SigmaConversionError) as exc_info:
            convert(MINIMAL_SIGMA_YAML, "no-sigma", tmp_path)

    assert "sigma executable not found" in str(exc_info.value)


def test_convert_raises_on_invalid_xml(tmp_path):
    """sigma-cli returning malformed XML raises SigmaConversionError."""
    not_xml = "this is definitely not xml <broken"
    with patch("agent.sigmac.subprocess.run") as mock_run:
        mock_run.return_value = _make_completed_process(
            returncode=0, stdout=not_xml, stderr=""
        )
        with pytest.raises(SigmaConversionError) as exc_info:
            convert(MINIMAL_SIGMA_YAML, "bad-xml", tmp_path)

    assert "not valid XML" in str(exc_info.value)


def test_convert_raises_on_invalid_yaml():
    """Malformed YAML input: sigma-cli exits non-zero, wrapper raises SigmaConversionError.

    The wrapper itself does not parse YAML — it passes content to sigma-cli
    verbatim.  This test simulates sigma-cli's response to malformed input
    (non-zero exit with an error on stderr).
    """
    malformed_yaml = "title: [unclosed bracket\ndetection:\n  - bad: yaml: here:"
    stderr_text = "Error parsing sigma rule: invalid YAML"

    with tempfile.TemporaryDirectory() as tmp_dir:
        rules_dir = Path(tmp_dir)
        with patch("agent.sigmac.subprocess.run") as mock_run:
            mock_run.return_value = _make_completed_process(
                returncode=1, stdout="", stderr=stderr_text
            )
            with pytest.raises(SigmaConversionError) as exc_info:
                convert(malformed_yaml, "malformed-rule", rules_dir)

    assert "code 1" in str(exc_info.value)


# ---------------------------------------------------------------------------
# Optional: real sigma-cli invocation (skipped if sigma not on PATH)
# ---------------------------------------------------------------------------


def _sigma_on_path() -> bool:
    """Return True if sigma-cli is available."""
    try:
        subprocess.run(
            ["sigma", "--version"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        return True
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False


@pytest.mark.skipif(
    not _sigma_on_path(),
    reason="sigma-cli not installed in this environment",
)
def test_convert_real_invocation_happy_path(tmp_path):
    """Real sigma-cli invocation: verifies the subprocess contract end-to-end.

    This test is skipped in environments without sigma-cli.  When sigma-cli
    and the Wazuh backend are installed, it validates the full stack.
    """
    out_path = convert(
        yaml_content=MINIMAL_SIGMA_YAML,
        rule_id="real-test-rule",
        rules_dir=tmp_path,
    )
    assert out_path.exists()
    content = out_path.read_text(encoding="utf-8")
    assert content.strip()  # non-empty

    import xml.etree.ElementTree as ET
    tree = ET.parse(str(out_path))
    assert tree.getroot() is not None
