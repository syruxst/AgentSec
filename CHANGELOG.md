# Changelog

Formato basado en [Keep a Changelog](https://keepachangelog.com/es-ES/1.1.0/),
y este proyecto sigue [Semantic Versioning](https://semver.org/lang/es/).

## [Unreleased]

### Added
- `LICENSE` (MIT), `CONTRIBUTING.md` y plantillas de issues/PR.
- Workflow de CI (`ci.yml`) que corre `ruff`, `mypy` y `pytest` en cada push/PR,
  independiente del auto-escaneo de `agentsec-ci.yml`.
- `docs/reglas.md`: catálogo de referencia completo de las 17 reglas (AS-101..AS-110,
  AS-201..AS-207).
- Metadatos de `pyproject.toml`: `classifiers`, `keywords`, `[project.urls]`.
- `.gitattributes` y `.editorconfig` para normalizar finales de línea entre editores/SO.

### Fixed
- Error de tipos en `agentsec/parsers/base.py` (`detect_framework`) reportado por mypy.
- Advertencias de `ruff` por falta de newline final en `demo/demo_agent.py` y
  `scripts/capturar_panel.py`.

### Removed
- `CATEGORY_BONUS` en `agentsec/scoring.py`: diccionario declarado pero nunca usado.

## [0.1.0] - 2026-08-16

### Added
- Núcleo del motor: parsers de LangChain y CrewAI, motor de reglas YAML declarativo,
  scoring 0-100, reportes text/json/sarif/html.
- Reglas de exceso de agencia y datos: AS-101..AS-110.
- Framework `assistant`: audita `opencode.json(c)`, `.claude/settings.json`,
  `claude.json` y `mcp.json` (permisos de herramientas, MCP remotos/locales, skills).
- Reglas AS-201..AS-207: bash/shell sin restricción, escritura amplia, MCP remoto sin
  verificación, credenciales en env de MCP, skills sin versión, secretos literales,
  delegación sin validación.
- Manejo de falsos positivos en MCP: los `.mcp.json` del catálogo del marketplace solo
  se consideran activos si su plugin está habilitado (`enabledPlugins` /
  `installed_plugins.json`); AS-203/AS-204 operan solo sobre MCP habilitados.
- Soporte de `.jsonc` y esquema "bare" de MCP (`"server": {url/command}` en raíz).
- Prober dinámico de inyección de prompt indirecta (suite `indirect`, 8 payloads).
- Panel web (FastAPI + Jinja2 + SQLite): dashboard, historial de scans, formulario
  "Nuevo escaneo", reporte HTML autocontenido por scan.
- GitHub Action reutilizable (`.github/actions/agentsec`) y workflow de ejemplo.
- Corpus de validación (31 configs LangChain/CrewAI etiquetadas) y suite de métricas
  por regla (precisión/recall/F1) en `tests/corpus_validation.py`.

[Unreleased]: https://github.com/syruxst/AgentSec/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/syruxst/AgentSec/releases/tag/v0.1.0
