"""Tests de modelos y utilidades base."""

from agentsec.models import Severity, severity_from_str


def test_severity_weights():
    assert Severity.critical.weight == 40.0
    assert Severity.high.weight == 25.0
    assert Severity.info.weight == 0.5


def test_severity_from_str():
    assert severity_from_str("MEDIUM") == Severity.medium
    assert severity_from_str("desconocido") == Severity.info


def test_severity_enum_values():
    assert [s.value for s in Severity] == ["critical", "high", "medium", "low", "info"]
