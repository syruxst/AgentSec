"""Generacion de reportes: texto, JSON, SARIF v2.1.0 y HTML autocontenido."""

from __future__ import annotations

import json
from html import escape

from agentsec.models import ScanResult


def render_text(result: ScanResult) -> str:
    base = ["=" * 70, f"AgentSec {result.version} - Analisis de agentes de IA", "=" * 70, ""]
    base.append(f"Proyecto : {result.project}")
    base.append(f"Framework: {result.framework or 'no detectado'}")
    base.append(f"Archivos : {result.scanned_files}")
    base.append(f"Reglas   : {result.rules_loaded}")
    base.append(f"Duracion : {result.duration_ms} ms")
    base.append(f"Puntaje  : {result.score:.1f}/100")
    base.append("")
    if not result.findings:
        base.append("No se detectaron hallazgos.")
        return "\n".join(base)

    base.append(f"Hallazgos ({len(result.findings)}):")
    by_rule: dict[str, list] = {}
    for finding in result.findings:
        by_rule.setdefault(finding.rule_id, []).append(finding)

    for rule_id, findings in sorted(by_rule.items()):
        first = findings[0]
        base.append("")
        base.append(f"[{rule_id}] {first.name}  ({first.severity.value.upper()})")
        base.append(f"  {first.description[:140]}")
        base.append(f"  Evidencia : {first.evidence[:200]}")
        base.append(f"  Ubicacion : {first.location.file}")
        if first.location.start_line:
            base[-1] += f":{first.location.start_line}"
        base.append(f"  Remediar  : {first.remediation[:200]}")
    base.append("")
    return "\n".join(base)


def render_json(result: ScanResult) -> str:
    return json.dumps(result.model_dump(mode="json"), indent=2, ensure_ascii=False)


def render_sarif(result: ScanResult) -> str:
    """SARIF v2.1.0 con reglas como tool rui."""
    rules: dict[str, dict] = {}
    for finding in result.findings:
        rules.setdefault(
            finding.rule_id,
            {
                "id": finding.rule_id,
                "name": finding.name,
                "helpUri": finding.references[0] if finding.references else None,
                "shortDescription": {"text": finding.name},
                "fullDescription": {"text": finding.description},
                "properties": {
                    "security-severity": _sarif_severity(finding.severity.value),
                    "owasp-llm": finding.owasp_llm,
                    "cwe": finding.cwe,
                },
            },
        )

    results = []
    for finding in result.findings:
        sarif_result = {
            "ruleId": finding.rule_id,
            "level": _sarif_level(finding.severity.value),
            "message": {"text": f"{finding.name}: {finding.evidence[:300]}"},
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": finding.location.file.replace("\\", "/")},
                        "region": _sarif_region(finding.location.start_line),
                    }
                }
            ],
        }
        if finding.references:
            sarif_result["relatedLocations"] = []
        results.append(sarif_result)

    sarif = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "AgentSec",
                        "informationUri": "https://example.local/agentsec",
                        "version": result.version,
                        "rules": list(rules.values()),
                    }
                },
                "results": results,
            }
        ],
    }
    return json.dumps(sarif, indent=2, ensure_ascii=False)


def render_html(result: ScanResult) -> str:
    rows = "\n".join(_html_row(f) for f in sorted(result.findings, key=lambda x: -x.weighted))
    severity_rows = "".join(_html_severity(result))
    return html_template().format(
        score=result.score,
        project=escape(result.project),
        framework=escape(result.framework or "no detectado"),
        files=result.scanned_files,
        rules=result.rules_loaded,
        duration=result.duration_ms,
        findings=len(result.findings),
        severity_rows=severity_rows,
        rows=rows or "<tr><td colspan=7>Sin hallazgos.</td></tr>",
        version=result.version,
    )


def _sarif_severity(sev: str) -> str:
    mapping = {"critical": "10.0", "high": "8.0", "medium": "5.0", "low": "2.0", "info": "0.0"}
    return mapping.get(sev, "2.0")


def _sarif_level(sev: str) -> str:
    mapping = {
        "critical": "error",
        "high": "error",
        "medium": "warning",
        "low": "note",
        "info": "note",
    }
    return mapping.get(sev, "note")


def _sarif_region(line: int | None) -> dict | None:
    if line is None:
        return None
    return {"startLine": line}


def _html_row(f) -> str:
    return (
        "<tr>"
        f"<td>{escape(f.rule_id)}</td>"
        f"<td>{escape(f.name)}</td>"
        f"<td><span class='sev {f.severity.value}'>{f.severity.value}</span></td>"
        f"<td>{escape(f.cwe or '-')}</td>"
        f"<td>{escape(f.location.file.split('/')[-1])}"
        f"{':' + str(f.location.start_line) if f.location.start_line else ''}</td>"
        f"<td title='{escape(f.evidence)}'>{escape(f.evidence[:80])}</td>"
        f"<td>{escape(f.remediation[:60])}</td>"
        "</tr>"
    )


def _html_severity(result: ScanResult) -> str:
    distribution = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for finding in result.findings:
        if finding.severity.value in distribution:
            distribution[finding.severity.value] += 1
    return "".join(
        f"<li><span class='sev {sev}'>{sev}: {count}</span></li>"
        for sev, count in distribution.items()
    )


def html_template() -> str:
    return """<!doctype html>
<html lang="es"><head><meta charset="utf-8">
<title>AgentSec - Reporte de seguridad</title>
<style>
 body {{ font-family: system-ui, sans-serif; margin: 2rem auto; max-width: 1000px; color: #1f2933; }}
 h1 {{ font-size: 1.5rem; }} .grid {{ display: grid; grid-template-columns: repeat(5, 1fr); gap: 1rem; }}
 .card {{ border: 1px solid #e4e7eb; border-radius: 8px; padding: 1rem; }}
 .score {{ font-size: 2rem; font-weight: 700; }}
 table {{ width: 100%; border-collapse: collapse; margin-top: 1rem; font-size: .85rem; }}
 th, td {{ text-align: left; padding: .5rem; border-bottom: 1px solid #e4e7eb; }}
 th {{ background: #f5f7fa; }}
 .sev {{ padding: 2px 8px; border-radius: 4px; color: #fff; font-size: .75rem; text-transform: capitalize;}}
 .critical {{ background: #b71c1c; }} .high {{ background: #e65100; }} .medium {{ background: #f9a825; }}
 .low {{ background: #558b2f; }} .info {{ background: #546e7a; }}
 ul {{ list-style: none; padding: 0; }}
</style></head><body>
<h1>AgentSec - Reporte de seguridad de agente de IA</h1>
<div class="grid">
  <div class="card"><div class="score">{score}</div><small>puntaje / 100</small></div>
  <div class="card"><b>{findings}</b><small>hallazgos</small></div>
  <div class="card"><b>{files}</b><small>archivos</small></div>
  <div class="card"><b>{rules}</b><small>reglas</small></div>
  <div class="card"><b>{duration} ms</b><small>duracion</small></div>
</div>
<p><b>Proyecto:</b> {project} &nbsp; <b>Framework:</b> {framework}</p>
<h2>Distribucion de severidad</h2><ul>{severity_rows}</ul>
<h2>Hallazgos</h2>
<table><thead><tr><th>ID</th><th>Nombre</th><th>Severidad</th><th>CWE</th>
<th>Archivo</th><th>Evidencia</th><th>Remediacion</th></tr></thead>
<tbody>{rows}</tbody></table>
<p style="margin-top:2rem;color:#888">Generado con AgentSec {version}.</p>
</body></html>"""


def render_by_format(result: ScanResult, fmt: str) -> str:
    renderers = {
        "text": render_text,
        "json": render_json,
        "sarif": render_sarif,
        "html": render_html,
    }
    if fmt == "text":
        return render_text(result)
    try:
        return renderers[fmt](result)
    except KeyError:
        raise ValueError(f"formato no soportado: {fmt}") from None
