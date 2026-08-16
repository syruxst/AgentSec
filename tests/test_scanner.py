"""Tests de scoring, scanner y reporter."""

from pathlib import Path

import pytest

from agentsec.models import Finding, Location, ScanOptions, ScanResult, Severity
from agentsec.reporter import render_by_format, render_sarif, render_text
from agentsec.scanner import exit_code_for, run_scan
from agentsec.scoring import compute_score, severity_distribution


def _finding(sev: Severity) -> Finding:
    return Finding(
        rule_id="X",
        name="x",
        description="d",
        severity=sev,
        location=Location(project_path="p", file="p"),
    )


def test_score_clean_is_100():
    assert compute_score([]) == 100.0


def test_score_decreases_with_severity():
    assert compute_score([_finding(Severity.critical)]) == 60.0
    assert compute_score([_finding(Severity.high)]) == 75.0
    assert compute_score([_finding(Severity.medium)]) == 90.0


def test_severity_distribution():
    findings = [_finding(Severity.high), _finding(Severity.critical), _finding(Severity.high)]
    assert severity_distribution(findings)["high"] == 2
    assert severity_distribution(findings)["critical"] == 1


def test_exit_codes():
    clean = ScanResult(project="x", score=90)
    warn = ScanResult(project="x", score=70)
    fail = ScanResult(project="x", score=50)
    assert exit_code_for(clean) == 0
    assert exit_code_for(warn) == 1
    assert exit_code_for(fail) == 2


def test_run_scan_on_example(tmp_path):
    (tmp_path / "crews.yaml").write_text(
        """
crew: demo
agents:
  - name: a
    tools:
      - name: RunShellTool
""",
        encoding="utf-8",
    )
    result = run_scan(ScanOptions(path=str(tmp_path)))
    assert result.score < 100
    assert any(f.rule_id == "AS-101" for f in result.findings)
    assert result.scanned_files == 1


def test_run_scan_missing_path():
    with pytest.raises(FileNotFoundError):
        run_scan(ScanOptions(path=str(Path("no_existe_999"))))


def test_render_text_contains_summary():
    result = ScanResult(project="p", findings=[_finding(Severity.high)], score=75)
    out = render_text(result)
    assert "AgentSec" in out
    assert "75.0" in out


def test_render_sarif_structure():
    result = ScanResult(project="p", findings=[_finding(Severity.critical)], score=60)
    sarif = render_sarif(result)
    assert '"$schema"' in sarif
    assert '"version": "2.1.0"' in sarif
    assert "AS-" not in sarif or '"ruleId"' in sarif


def test_render_json_roundtrip():
    result = ScanResult(project="p", findings=[_finding(Severity.low)], score=97, version="0.1.0")
    data = render_by_format(result, "json")
    compact = data.replace(" ", "").replace("\n", "")
    assert '"score":97.0' in compact
    assert '"rule_id":"X"' in compact
