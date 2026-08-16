# AgentSec

[![CI](https://github.com/syruxst/AgentSec/actions/workflows/ci.yml/badge.svg)](https://github.com/syruxst/AgentSec/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue.svg)](pyproject.toml)

Auditor **shift-left** de seguridad para agentes de IA.

Cubre dos dominios:

1. **Agentes declarativos** (LangChain, CrewAI): configs como `crews.yaml`, `chain.yaml`.
2. **Asistentes de código agénticos** (opencode, Claude Code/Desktop): `opencode.json(c)`,
   `.claude/settings.json`, `claude.json`, `mcp.json`.

Detecta dos clases de vulnerabilidad que las herramientas existentes no cubren:

1. **Excessive agency**: herramientas con permisos demasiado amplios (`shell`, `load_all_tools`,
   acceso sin restricción a filesystem/red, credenciales sobre-scoped, permisos `bash:*`/`edit`
   en asistentes, MCP remotos de plugins habilitados).
2. **Inyección de prompt indirecta**: ataques que viajan *dentro de los datos* que el agente
   consume (HTML/XML oculto, markdown, unicode, entity-encoding, JSON anidado).

Se integra en el flujo CI/CD **antes de desplegar** el agente, en lugar de detectar en runtime.

## Quickstart

```bash
# crear entorno e instalar
python -m venv .venv
.venv\Scripts\python -m pip install -e ".[dev]"

# analizar un directorio de configs (LangChain, CrewAI o asistentes)
agentsec scan ruta/al/proyecto --format sarif

# probar endpoints dinámicamente con payloads de inyección indirecta
agentsec probe http://localhost:8000/invoke --suite indirect

# puntaje de postura (0-100) y umbral
agentsec scan ruta/al/proyecto --format json | jq .score
```

## Ejemplos listos

```bash
agentsec scan examples/vulnerable            # CrewAI vulnerable    -> 0/100
agentsec scan examples/clean                 # CrewAI limpio        -> 100/100
agentsec scan examples/assistant_vulnerable  # opencode vulnerable  -> 0/100
agentsec scan examples/assistant_clean       # opencode limpio      -> 100/100
agentsec scan C:\Users\danie\.config\opencode
```

## Exit code

- `0` → PASS (score >= 80)
- `1` → WARN (score 60-79)
- `2` → FAIL (score < 60 o hallazgo severidad >= high salvo `--allow`)
- `3` → error interno

## Documentación

- `docs/arquitectura.md` — diseño, componentes, reglas y manejo de falsos positivos
- `docs/uso.md` — manual de uso (CLI, panel web, CI, demo)
- `docs/reglas.md` — catálogo de referencia de las 17 reglas (severidad, CWE, OWASP LLM)
- [`CONTRIBUTING.md`](CONTRIBUTING.md) — entorno de desarrollo y cómo agregar una regla
- [`CHANGELOG.md`](CHANGELOG.md) — historial de versiones

## Estructura

```
agentsec/       núcleo (CLI + parsing + reglas + payloads + scoring + reportes)
  parsers/      langchain.py · crewai.py · assistant.py (opencode/claude/MCP)
  rules/builtin agency.yaml · data.yaml · assistant.yaml (AS-101..AS-110, AS-201..AS-207)
app/            API REST + panel web (FastAPI + Jinja2 + SQLite)
tests/          corpus de validación + suite pytest
examples/       configs clean/vulnerable para los dos dominios
.github/        GitHub Action
```

## Changelog

Ver [`CHANGELOG.md`](CHANGELOG.md) para el historial de versiones.

## Licencia

[MIT](LICENSE)