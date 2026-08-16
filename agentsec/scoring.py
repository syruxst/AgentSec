"""Puntaje de postura de seguridad 0-100.

score = 100 - Σ(hallazgo * peso_severidad * factor_exposicion)
"""

from __future__ import annotations

from agentsec.models import Finding, Severity

EXPOSURE_FACTOR = 1.0  # agente accesible por red (defecto conservador)
CATEGORY_BONUS: dict[str, float] = {}


def compute_score(findings: list[Finding]) -> float:
    total = 0.0
    for finding in findings:
        total += finding.severity.weight * EXPOSURE_FACTOR
    return max(0.0, round(100.0 - total, 2))


def severity_distribution(findings: list[Finding]) -> dict[str, int]:
    counts = {s.value: 0 for s in Severity}
    for finding in findings:
        counts[finding.severity.value] += 1
    return counts
