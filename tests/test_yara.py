"""
YARA syntax validation test (1 test).

Tests:
  1. A well-formed YARA rule compiles without error (or test is skipped if
     the yara-python library is not installed in the test environment).

No mocks — this tests the real yara.compile() call that main.py uses.

@decision DEC-YARA-001
@title Write YARA to /rules/ volume, no docker exec
@status accepted
@rationale Testing real yara.compile() is more valuable than mocking it.
           The pytest.importorskip guard handles environments without
           yara-python gracefully so CI doesn't hard-fail on a missing
           system dependency.
"""

import pytest

yara = pytest.importorskip("yara", reason="yara-python not installed")


VALID_YARA_RULE = """
rule TestMalwareDetection {
    meta:
        description = "Detects test malware pattern"
        author = "shaferhund"
        severity = "high"
    strings:
        $hex_pattern = { 58 35 4F 21 50 25 40 41 50 }
        $str_pattern = "EICAR-STANDARD-ANTIVIRUS-TEST-FILE"
    condition:
        any of them
}
"""

INVALID_YARA_RULE = """
rule BrokenRule {
    strings:
        $s = "test"
    condition:
        $s and undefined_var
"""


def test_valid_yara_rule_compiles():
    """A syntactically correct YARA rule compiles without raising an exception."""
    compiled = yara.compile(source=VALID_YARA_RULE)
    assert compiled is not None


def test_invalid_yara_rule_raises():
    """A syntactically broken YARA rule raises a yara.SyntaxError."""
    with pytest.raises(yara.SyntaxError):
        yara.compile(source=INVALID_YARA_RULE)
