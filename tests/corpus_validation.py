"""Caracterizacion del motor sobre el corpus: metricas de validacion.

Calcula, por regla, TP/FP/FN y precision/recall/F1, y la clasificacion
binaria por archivo (vulnerable/limpio). Usado por la suite de tests y,
para la memoria, en modo script con salida detallada.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from agentsec.models import ScanOptions
from agentsec.scanner import run_scan

CORPUS_DIR = Path(__file__).resolve().parent.parent / "tests" / "corpus"


@dataclass
class PerRuleMetrics:
    rule_id: str
    name: str
    tp: int = 0
    fp: int = 0
    fn: int = 0

    @property
    def precision(self) -> float:
        denom = self.tp + self.fp
        return self.tp / denom if denom else 0.0

    @property
    def recall(self) -> float:
        denom = self.tp + self.fn
        return self.tp / denom if denom else 0.0

    @property
    def f1(self) -> float:
        denom = self.precision + self.recall
        return 2 * self.precision * self.recall / denom if denom else 0.0


@dataclass
class ValidationReport:
    rule_metrics: dict[str, PerRuleMetrics] = field(default_factory=dict)
    binary_tp: int = 0
    binary_fp: int = 0
    binary_tn: int = 0
    binary_fn: int = 0
    errors: list[str] = field(default_factory=list)

    @property
    def binary_precision(self) -> float:
        denom = self.binary_tp + self.binary_fp
        return self.binary_tp / denom if denom else 0.0

    @property
    def binary_recall(self) -> float:
        denom = self.binary_tp + self.binary_fn
        return self.binary_tp / denom if denom else 0.0

    @property
    def binary_f1(self) -> float:
        denom = self.binary_precision + self.binary_recall
        return 2 * self.binary_precision * self.binary_recall / denom if denom else 0.0

    def accuracy(self) -> float:
        denom = self.binary_tp + self.binary_fp + self.binary_tn + self.binary_fn
        return (self.binary_tp + self.binary_tn) / denom if denom else 0.0


def load_manifest(path: Path | None = None) -> dict[str, Any]:
    manifest_path = path or (CORPUS_DIR / "manifest.yaml")
    return yaml.safe_load(manifest_path.read_text(encoding="utf-8"))


def validate_corpus(corpus_dir: Path | None = None) -> ValidationReport:
    corpus_dir = corpus_dir or CORPUS_DIR
    manifest = load_manifest()
    report = ValidationReport()

    expected_by_file: dict[str, set[str]] = {}
    for label in ("vulnerable", "clean"):
        for rel, rules in manifest[label].items():
            expected_by_file[f"{label}/{rel}"] = set(rules)

    for rel, expected in sorted(expected_by_file.items()):
        target = corpus_dir / rel
        try:
            result = run_scan(ScanOptions(path=str(target), formats=["json"]))
        except Exception as exc:  # noqa: BLE001 - reportamos en vez de abortar
            report.errors.append(f"{rel}: error de scan ({exc})")
            continue

        detected = {f.rule_id for f in result.findings}
        is_vulnerable = rel.startswith("vulnerable/")

        # clasificacion binaria
        if is_vulnerable and detected:
            report.binary_tp += 1
        elif is_vulnerable and not detected:
            report.binary_fn += 1
        elif not is_vulnerable and detected:
            report.binary_fp += 1
            for rule_id in detected:
                report.rule_metrics.setdefault(rule_id, PerRuleMetrics(rule_id, rule_id)).fp += 1
        else:
            report.binary_tn += 1

        # metricas por regla
        for rule_id in expected:
            m = report.rule_metrics.setdefault(rule_id, PerRuleMetrics(rule_id, rule_id))
            if rule_id in detected:
                m.tp += 1
            else:
                m.fn += 1
        for rule_id in detected:
            if rule_id not in expected:
                m = report.rule_metrics.setdefault(rule_id, PerRuleMetrics(rule_id, rule_id))
                m.fp += 1

    return report


def rule_name(rule_id: str) -> str:
    from agentsec.rules import load_rules

    for rule in load_rules():
        if rule.id == rule_id:
            return rule.name
    return rule_id


def report_lines(report: ValidationReport) -> list[str]:
    lines = [
        "Metricas por regla (corpus):",
        f"{'regla':<10}{'prec':>6}{'rec':>6}{'f1':>6}{'tp':>4}{'fp':>4}{'fn':>4}",
    ]
    for rule_id, m in sorted(report.rule_metrics.items()):
        lines.append(
            f"{rule_id:<10}{m.precision:>6.2f}{m.recall:>6.2f}{m.f1:>6.2f}"
            f"{m.tp:>4}{m.fp:>4}{m.fn:>4}  {rule_name(rule_id)[:38]}"
        )
    lines.append("")
    lines.append("Clasificacion binaria por archivo:")
    lines.append(
        f"  TP={report.binary_tp} FP={report.binary_fp} TN={report.binary_tn} FN={report.binary_fn}"
    )
    lines.append(
        f"  precision={report.binary_precision:.2f} recall={report.binary_recall:.2f} "
        f"f1={report.binary_f1:.2f} accuracy={report.accuracy():.2f}"
    )
    if report.errors:
        lines.append("")
        lines.append("Errores:")
        lines.extend(f"  - {e}" for e in report.errors)
    return lines


if __name__ == "__main__":
    rep = validate_corpus()
    print("\n".join(report_lines(rep)))
