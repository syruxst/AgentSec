"""Motor de reglas estáticas de AgentSec.

Carga reglas YAML y las evalúa contra cada Distribution normalizada.
Un hallazgo se emite si **alguna** de sus comprobaciones (`checks`)
coincide (semántica OR); dentro de una comprobación de colección, se
evalúa contra cada elemento (semántica ANY).
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from agentsec.models import (
    Distribution,
    Finding,
    Location,
    Severity,
    severity_from_str,
)

BUILTIN_RULES_PATH = Path(__file__).parent / "builtin"

# Keywords que identifican carga amplia o tools peligrosas.
DANGEROUS_TOOL_PATTERN = re.compile(r"\b(shell|exec|subprocess|bash|os\.system)\b", re.IGNORECASE)
BROAD_TOOL_PATTERN = re.compile(
    r"(load_all_tools|import_all_tools|get_all_tools|\*tool)", re.IGNORECASE
)


@dataclass
class Condition:
    """Condición atómica sobre un elemento (dict) de la distribución."""

    field: str
    op: str
    value: Any = None
    flags: str = ""

    def evaluate(self, item: Any) -> bool:
        node = resolve(item, self.field)
        value = self.value

        if self.op == "exists":
            return node is not None
        if self.op == "not_exists":
            return node is None

        if node is None:
            return False

        if self.op == "eq":
            return _norm(node) == _norm(value)
        if self.op == "ne":
            return _norm(node) != _norm(value)
        if self.op == "substring":
            return self._contains(str(node), value, self.flags)
        if self.op == "regex":
            flags = re.IGNORECASE | re.DOTALL if "i" in self.flags else re.DOTALL
            return re.search(str(value), str(node), flags) is not None
        if self.op == "not_regex":
            flags = re.IGNORECASE | re.DOTALL if "i" in self.flags else re.DOTALL
            return re.search(str(value), str(node), flags) is None
        if self.op == "gt":
            node_f, value_f = _to_float(node), _to_float(value)
            return node_f is not None and value_f is not None and node_f > value_f
        if self.op == "lt":
            node_f, value_f = _to_float(node), _to_float(value)
            return node_f is not None and value_f is not None and node_f < value_f
        if self.op == "in":
            return _norm(node) in (_norm(value) if isinstance(value, list) else [value])
        raise ValueError(f"operador desconocido: {self.op}")

    @staticmethod
    def _contains(haystack: str, needle: Any, flags: str = "") -> bool:
        if "i" in flags:
            return re.search(re.escape(str(needle)), haystack, re.IGNORECASE) is not None
        return re.search(re.escape(str(needle)), haystack) is not None


@dataclass
class Check:
    """Comprobación: aplica condiciones a un scope ('tools', 'agents', ...)."""

    scope: str
    conditions: list[Condition] = field(default_factory=list)
    evidence_template: str = ""

    def match(self, dist: Distribution) -> list[dict[str, Any]]:
        """Devuelve los elementos del scope que cumplen todas las condiciones."""
        elements = getattr(dist, self.scope, [])
        hits: list[dict[str, Any]] = []
        for element in elements:
            if all(cond.evaluate(element) for cond in self.conditions):
                hits.append(element)
        return hits


@dataclass
class Rule:
    """Regla carga desde YAML."""

    id: str
    name: str
    description: str
    severity: Severity
    remediation: str = ""
    cwe: str | None = None
    owasp_llm: str | None = None
    references: list[str] = field(default_factory=list)
    frameworks: list[str] = field(default_factory=lambda: ["langchain", "crewai"])
    checks: list[Check] = field(default_factory=list)
    raw: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Rule:
        checks = [_parse_check(c) for c in data.get("checks", [])]
        return cls(
            id=data["id"],
            name=data.get("name", data["id"]),
            description=data.get("description", ""),
            severity=severity_from_str(data.get("severity", "info")),
            remediation=data.get("remediation", ""),
            cwe=data.get("cwe"),
            owasp_llm=data.get("owasp_llm"),
            references=list(data.get("references", [])),
            frameworks=list(data.get("frameworks", ["langchain", "crewai"])),
            checks=checks,
            raw=data,
        )

    def applies_to(self, framework: str) -> bool:
        return framework in self.frameworks


def _parse_check(data: dict[str, Any]) -> Check:
    scope = data.get("scope", "tools")
    conditions = [_parse_condition(c) for c in data.get("conditions", [])]
    return Check(scope=scope, conditions=conditions, evidence_template=data.get("evidence", ""))


def _parse_condition(data: dict[str, Any]) -> Condition:
    return Condition(
        field=data.get("field", ""),
        op=data.get("op", "exists"),
        value=data.get("value"),
        flags=data.get("flags", ""),
    )


def resolve(item: Any, field: str) -> Any:
    """Resuelve una ruta de campo con comodines básicos (p. ej. '*.type')."""
    parts = [p for p in field.split(".") if p]
    current = item
    for part in parts:
        if isinstance(current, dict):
            if part == "*":
                continue
            current = current.get(part)
        elif isinstance(current, list):
            found: list[Any] = []
            for element in current:
                if isinstance(element, dict):
                    found.append(element.get(part))
            current = found
        else:
            return None
    return current


def _norm(value: Any) -> Any:
    if isinstance(value, bool):
        return str(value).lower()
    if value is None:
        return None
    return str(value).strip().lower()


def _to_float(value: Any) -> float | None:
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


class RuleEngine:
    """Evalúa reglas cargadas contra distribuciones y genera hallazgos."""

    def __init__(self, rules: list[Rule] | None = None) -> None:
        self.rules = rules if rules is not None else load_rules()

    def evaluate(self, dists: list[Distribution]) -> list[Finding]:
        findings: list[Finding] = []
        for dist in dists:
            findings.extend(self.evaluate_distribution(dist))
        return findings

    def evaluate_distribution(self, dist: Distribution) -> list[Finding]:
        findings: list[Finding] = []
        for rule in self.rules:
            if not rule.applies_to(dist.framework):
                continue
            for check in rule.checks:
                hits = check.match(dist)
                for hit in hits:
                    evidence = self._build_evidence(rule, check, hit)
                    findings.append(
                        Finding(
                            rule_id=rule.id,
                            name=rule.name,
                            description=rule.description,
                            severity=rule.severity,
                            cwe=rule.cwe,
                            owasp_llm=rule.owasp_llm,
                            location=self._locate(dist, hit, evidence),
                            category="static",
                            evidence=evidence,
                            remediation=rule.remediation,
                            references=rule.references,
                        )
                    )
                    break  # una coincidencia por check basta
        return findings

    def _build_evidence(self, rule: Rule, check: Check, hit: dict[str, Any]) -> str:
        if check.evidence_template:
            try:
                return check.evidence_template.format(**hit)
            except (KeyError, IndexError):
                return yaml.safe_dump(hit, default_flow_style=False) or ""
        return yaml.safe_dump(hit, default_flow_style=False) or ""

    @staticmethod
    def _locate(dist: Distribution, hit: dict[str, Any], evidence: str) -> Location:
        file = Path(dist.path)
        line = RuleEngine._estimate_line(file, evidence or str(hit))
        return Location(project_path=dist.path, file=dist.path, start_line=line, end_line=line)

    @staticmethod
    def _estimate_line(path: Path, needle: str) -> int | None:
        if not path.is_file():
            return None
        if len(needle) > 200:
            needle = needle[:200]
        try:
            lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            return None
        needle_lower = needle.lower()
        for i, line in enumerate(lines, start=1):
            if needle_lower in line.lower():
                return i
        return None


# --------------------------------------------------------------------------- #
# carga de reglas
# --------------------------------------------------------------------------- #


def load_rules(path: Path | None = None) -> list[Rule]:
    """Carga todas las reglas *.yaml del directorio (default: builtin)."""
    rules_dir = path or BUILTIN_RULES_PATH
    rules: list[Rule] = []
    if not rules_dir.is_dir():
        return rules
    for rule_file in sorted(rules_dir.glob("*.yaml")):
        data = yaml.safe_load(rule_file.read_text(encoding="utf-8"))
        if not data:
            continue
        rules_seq = data if isinstance(data, list) else [data]
        for item in rules_seq:
            if isinstance(item, dict) and item.get("id"):
                rules.append(Rule.from_dict(item))
    return rules
