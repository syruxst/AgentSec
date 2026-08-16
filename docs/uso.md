# Manual de uso de AgentSec

AgentSec audita dos dominios: agentes declarativos (LangChain/CrewAI) y asistentes
de código agénticos (opencode, Claude Code/Desktop).

## Instalacion

```bash
python -m venv .venv
# Windows
.venv\Scripts\python -m pip install -e ".[dev]"
# Linux/macOS
source .venv/bin/activate && pip install -e ".[dev]"

# con panel web (extra opcional)
.venv\Scripts\python -m pip install -e ".[web]"
```

## Analisis estatico (scan)

```bash
# texto (por defecto)
agentsec scan ruta/al/proyecto

# otros formatos
agentsec scan ruta/al/proyecto --format sarif
agentsec scan ruta/al/proyecto --format json
agentsec scan ruta/al/proyecto --format html --out reporte.html

# ignorar reglas concretas y ajustar umbral
agentsec scan ruta/al/proyecto --allow AS-101 --allow AS-104 --threshold 60
```

### Ejemplos rápidos del repositorio

```bash
agentsec scan examples/vulnerable            # CrewAI vulnerable    -> 0/100
agentsec scan examples/clean                 # CrewAI limpio        -> 100/100
agentsec scan examples/assistant_vulnerable  # opencode vulnerable  -> 0/100, 7 hallazgos
agentsec scan examples/assistant_clean       # opencode limpio      -> 100/100
agentsec scan C:\Users\danie\.config\opencode
```

### Exit codes

| Codigo | Significado |
|---|---|
| 0 | PASS (score >= 80) |
| 1 | WARN (score 60-79) |
| 2 | FAIL (score < 60), bloquea CI |

### Que detecta (analisis estatico, agentes declarativos)

- **AS-101** ejecucion de comandos del sistema sin restriccion (Critical).
  Permite `sandbox: true` o `allowed_commands` como mitigacion valida.
- **AS-102** carga amplia de herramientas (`load_all_tools`, `import_all_tools`)
- **AS-103** acceso a filesystem sin allowlist de rutas
- **AS-104** secretos hardcodeados en configuracion (Critical)
- **AS-105** tools de egress (HTTP/correo/SQL) sin restriccion de destinos
- **AS-106** fuentes de datos sin sanitizacion (riesgo de inyeccion indirecta)
- **AS-107** memoria/embeddings sin scoping por agente
- **AS-108** dependencias/plugins sin version fijada ni origen verificado
- **AS-109** credenciales sobre-scoped o sin permisos declarados en produccion
- **AS-110** delegacion agente-a-agente sin validacion de origen

### Que detecta (asistentes de codigo: opencode, Claude Code/Desktop)

- **AS-201** permiso `bash`/`shell`/`exec` genérico o `bash:*` (Critical); comandos concretos
  como `bash:git status` NO disparan (allowlist valida)
- **AS-202** escritura/edicion amplia (`edit`, `write:*`) sin restriccion a directorios
- **AS-203** MCP remoto (URL) de un plugin **habilitado** sin validacion de origen (High)
- **AS-204** credenciales embebidas en `env` de un MCP local (refs `env:`/`${}` no disparan)
- **AS-205** skill/plugin externo habilitado sin version fijada
- **AS-206** secreto literal en config del asistente (Critical)
- **AS-207** delegacion agente-a-agente sin validacion de origen

> Catálogo completo (severidad, CWE, OWASP LLM, remediación detallada de cada regla):
> [`docs/reglas.md`](reglas.md).

> **MCP del catalogo (falsos positivos):** los `.mcp.json` bajo
> `plugins/marketplaces/.../external_plugins/` declaran MCPs de plugins *disponibles*.
> El parser los marca `enabled: false` salvo que el plugin figure en `enabledPlugins`
> (`settings.json`) o en `installed_plugins.json`; AS-203/AS-204 solo operan sobre
> MCP habilitados. Un `.mcp.json` de un proyecto se considera siempre activo.

## Prueba dinamica de inyeccion indirecta (probe)

```bash
# contra un endpoint de agente (los payloads viajan como DATOS, no instrucciones)
agentsec probe http://localhost:8787/invoke

# con mayor detalle
agentsec probe http://localhost:8787/invoke -v
```

Salida: por cada payload, `DETONADO` / `limpio` / `ERROR`, con marcadores detectados
y fragmento de la respuesta. Exit `2` si alguno detono, `3` si hubo errores de conexion.

## Panel web (API REST + dashboard)

```bash
.venv\Scripts\python -m uvicorn app.main:app --host 127.0.0.1 --port 8000
```

- `GET /` dashboard: tarjetas, historial de scans y formulario **"Nuevo escaneo"**
  (pega una ruta y pulsa Escanear; llama a `POST /api/scan` y recarga la tabla)
- `POST /api/scan {"path": "..."}` ejecuta un scan
- `GET /api/scans`, `GET /api/scans/{id}`, `GET /api/reports/{id}`, `GET /api/stats`
- `GET /api/rules` catalogo de reglas activas
- `GET /scan/{id}` detalle, `GET /report/{id}` reporte HTML autocontenido
- Documentacion interactiva en `/docs`

> En Windows con XAMPP, usa el entorno del proyecto (el `python` global puede no tener
> FastAPI): `& C:\xampp\htdocs\proyecto_de_titulo\.venv\Scripts\python -m uvicorn ...`
>
> Atajos: `scripts\escanear.bat [ruta]` (doble-clic) o `scripts\escanear.ps1 [ruta]`.

## Integracion CI (GitHub Actions)

```yaml
- uses: ./.github/actions/agentsec
  with:
    path: examples/vulnerable
    threshold: '60'
    format: sarif
    report_path: agentsec.sarif
```

Fallara el job si el puntaje baja del umbral (exit >= 1).

## Demo end-to-end

```bash
# 1) config de agente vulnerable en analisis estatico
agentsec scan examples/vulnerable
agentsec scan examples/assistant_vulnerable

# 2) agente HTTP vulnerable a inyeccion indirecta
.venv\Scripts\python -m uvicorn demo.demo_agent:app --port 8787

# 3) prueba dinamica (en otra terminal)
agentsec probe http://127.0.0.1:8787/invoke -v

# 4) corpus de validacion (metricas para la memoria)
python tests/corpus_validation.py
```

## Tests, lint y tipos

```bash
.venv\Scripts\python -m pytest tests
.venv\Scripts\python -m ruff check agentsec app tests
.venv\Scripts\python -m ruff format --check agentsec app tests
.venv\Scripts\python -m mypy agentsec app
```