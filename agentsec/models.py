"""Modelo de datos de AgentSec: distribución, hallazgos, reporte y resultados de scan."""

from __future__ import annotations

from enum import StrEnum
from typing import Any, Literal

from pydantic import BaseModel, Field

ProjectPath = str
Framework = Literal["langchain", "crewai", "assistant"]


class Severity(StrEnum):
    """Severidad de un hallazgo, alineada con el peso de scoring."""

    critical = "critical"
    high = "high"
    medium = "medium"
    low = "low"
    info = "info"

    @property
    def weight(self) -> float:
        return {
            Severity.critical: 40.0,
            Severity.high: 25.0,
            Severity.medium: 10.0,
            Severity.low: 3.0,
            Severity.info: 0.5,
        }[self]


class Distribution(BaseModel):
    """Un archivo de configuración normalizado para el motor de reglas."""

    framework: Framework
    path: ProjectPath
    data: dict[str, Any] = Field(default_factory=dict)
    tools: list[dict[str, Any]] = Field(default_factory=list)
    agents: list[dict[str, Any]] = Field(default_factory=list)
    sources: list[dict[str, Any]] = Field(default_factory=list)
    memory: list[dict[str, Any]] = Field(default_factory=list)
    credentials: list[dict[str, Any]] = Field(default_factory=list)
    dependencies: list[dict[str, Any]] = Field(default_factory=list)


class Location(BaseModel):
    """Ubicación de un hallazgo para reportes SARIF."""

    project_path: ProjectPath
    file: str
    start_line: int | None = None
    end_line: int | None = None


class Finding(BaseModel):
    """Un hallazgo único producido por el motor de reglas o el prober."""

    rule_id: str
    name: str
    description: str
    severity: Severity
    cwe: str | None = None
    owasp_llm: str | None = None
    location: Location
    category: str = "static"
    evidence: str = ""
    remediation: str = ""
    references: list[str] = Field(default_factory=list)

    @property
    def weighted(self) -> float:
        return self.severity.weight


class ScanResult(BaseModel):
    """Resultado de un escaneo completo de un proyecto."""

    project: ProjectPath
    framework: Framework | None = None
    findings: list[Finding] = Field(default_factory=list)
    score: float = 100.0
    scanned_files: int = 0
    rules_loaded: int = 0
    duration_ms: int = 0
    version: str = "0.1.0"

    def affected_by(self, rule_id: str) -> list[Finding]:
        return [f for f in self.findings if f.rule_id == rule_id]


class ScanOptions(BaseModel):
    """Opciones de un escaneo."""

    path: ProjectPath
    formats: list[str] = Field(default_factory=lambda: ["text"])
    allow: list[str] = Field(default_factory=list)
    threshold: float = 60.0
    verbose: bool = False
    max_files: int = 500


class Healthcheck(BaseModel):
    """Resultado de una prueba de inyección indirecta (prober)."""

    payload_id: str
    name: str
    category: str
    target: str
    triggered: bool
    output_snippet: str = ""
    severity: Severity = Severity.low
    description: str = ""


def severity_from_str(value: str) -> Severity:
    try:
        return Severity(value.lower())
    except ValueError:
        return Severity.info
