"""Aplica el corpus de validacion (ground-truth) como gate de CI.

A diferencia de tests/test_rules.py (unitario, contra Distribution en memoria),
esto corre el pipeline completo (parser + engine + scoring) contra los ~47
archivos reales de tests/corpus/ y falla si precision/recall binarios caen
por debajo del umbral o si alguna regla queda sin cobertura de ground-truth.
"""

from __future__ import annotations

from tests.corpus_validation import report_lines, validate_corpus

MIN_BINARY_ACCURACY = 0.95


def test_corpus_binary_classification_meets_threshold() -> None:
    report = validate_corpus()
    assert not report.errors, "\n".join(report.errors)
    assert report.accuracy() >= MIN_BINARY_ACCURACY, "\n".join(report_lines(report))


def test_every_rule_has_ground_truth_coverage() -> None:
    from agentsec.rules import load_rules

    report = validate_corpus()
    rule_ids = {r.id for r in load_rules()}
    covered = set(report.rule_metrics)
    missing = rule_ids - covered
    assert not missing, f"reglas sin caso en tests/corpus/manifest.yaml: {sorted(missing)}"
