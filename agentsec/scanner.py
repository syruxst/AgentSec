"""Orquestación de escaneo: parsing + reglas + scoring."""

from __future__ import annotations

import time
from pathlib import Path

from agentsec import __version__
from agentsec.models import Finding, ScanOptions, ScanResult
from agentsec.parsers.base import ParserRegistry, detect_framework
from agentsec.rules import RuleEngine
from agentsec.scoring import compute_score


def run_scan(options: ScanOptions) -> ScanResult:
    root = Path(options.path)
    if not root.exists():
        raise FileNotFoundError(f"ruta no encontrada: {root}")

    start = time.perf_counter()
    registry = ParserRegistry()
    dists = registry.distributions(root)
    framework = detect_framework([Path(d.path) for d in dists])

    engine = RuleEngine()
    findings: list[Finding] = []
    for dist in dists:
        findings.extend(engine.evaluate_distribution(dist))

    allowed = set(options.allow)
    if allowed:
        findings = [f for f in findings if f.rule_id not in allowed]

    score = compute_score(findings)
    duration_ms = int((time.perf_counter() - start) * 1000)

    return ScanResult(
        project=str(root).replace("\\", "/"),
        framework=framework,
        findings=findings,
        score=score,
        scanned_files=len(dists),
        rules_loaded=len(engine.rules),
        duration_ms=duration_ms,
        version=__version__,
    )


def exit_code_for(result: ScanResult, threshold: float = 60.0) -> int:
    """0=PASS, 1=WARN, 2=FAIL, 3=error."""
    if result.score < threshold:
        return 2
    if result.score < 80:
        return 1
    return 0
