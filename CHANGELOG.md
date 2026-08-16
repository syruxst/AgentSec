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
- **Corpus de validación para el dominio `assistant`**: 16 casos nuevos
  (`tests/corpus/{vulnerable,clean}/assistant/`) que cubren AS-201..AS-207, antes sin
  ninguna cobertura de ground-truth. El corpus total pasa de 31 a 47 configs.
- Caso adversarial de MCP de catálogo no habilitado, que verifica de punta a punta
  (no solo con mocks unitarios) que AS-203/AS-204 se suprimen correctamente mientras
  AS-206 se sigue detectando.
- `tests/test_corpus_validation.py`: aplica el corpus de validación como gate de
  pytest/CI (antes `tests/corpus_validation.py` era un script manual que nadie corría
  automáticamente).
- Sección "Limitaciones metodológicas conocidas" en `docs/arquitectura.md`.

### Fixed
- **`agentsec/parsers/assistant.py`**: el campo `verified` de un servidor MCP remoto
  nunca se propagaba al `Distribution`, por lo que la mitigación documentada de AS-203
  (`"verified": true`) no tenía ningún efecto — la regla siempre se disparaba para
  cualquier MCP con `url`. Encontrado al construir el corpus de ground-truth para
  AS-201..AS-207.
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
