# Arquitectura de AgentSec

## 1. Principio de diseno

AgentSec aplica el paradigma **shift-left** (DevSecOps): audita la seguridad de un agente
de IA **antes de desplegarlo**, dentro de CI/CD, en lugar de detectar ataques en runtime.
Esta es la brecha que las herramientas existentes no cubren:

| Capa | Herramientas existentes | AgentSec |
|---|---|---|
| Runtime (gateways, firewalls) | Lakera, PromptArmor, Vorlon | no compite |
| Testeo del **modelo** (LLM) | Garak, Promptfoo | complementa |
| Auditoria de la **arquitectura** del agente | — (vacio) | **aqui trabaja** |

El corpus de validacion del proyecto demuestra esta especializacion: AgentSec opera
sobre la configuracion declarativa (YAML/JSON/JSONC/TOML), no sobre el modelo.

Dominios cubiertos:
1. **Agentes declarativos** (LangChain, CrewAI): configs como `crews.yaml`, `chain.yaml`.
2. **Asistentes de codigo agenciicos** (opencode, Claude Code/Desktop): `opencode.json(c)`,
   `.claude/settings.json`, `claude.json`, `mcp.json`. Audita permisos de herramientas,
   servidores MCP (remotos y locales) y skills/plugins.

**Gestion de falsos positivos (MCP del catalogo):** los `.mcp.json` bajo
`plugins/marketplaces/` declaran MCPs de plugins *disponibles*, no activos. El parser
cruza cada MCP con `settings.json` (`enabledPlugins`) e `installed_plugins.json` y le
marca `enabled: true/false`; las reglas AS-203/AS-204 solo operan sobre MCP habilitados.
Un `.mcp.json` fuera del catalogo (proyecto) se considera siempre activo.

## 2. Flujo de escaneo

```
Configs del agente            CLI / API
(LangChain, CrewAI,
 assistant)
        │                          │
        ▼                          ▼
  Parser normaliza          ┌──────────────┐
  a Distribution            │ Repore / config│
        │                   └──────────────┘
        ▼                          │
  Motor de reglas  ──────────►  Hallazgos
  (AS-101..AS-110,               (Finding)
   AS-201..AS-207)
        │                          │
        ▼                          ▼
  Scoring 0-100               Reportes: text / json / sarif / html
        │                          │
        ▼                          ▼
  exit-code (0/1/2)           API REST + panel web / GitHub Action
```

## 3. Componentes

| Modulo | Responsabilidad | Archivo |
|---|---|---|
| `models.py` | Tipos Pydantic: `Distribution`, `Finding`, `ScanResult` | `agentsec/models.py` |
| `parsers/` | Normaliza configs de LangChain/CrewAI/asistentes a `Distribution` | `agentsec/parsers/` |
| `rules/engine.py` | Carga reglas YAML y las evalua sobre `Distribution` | `agentsec/rules/engine.py` |
| `rules/builtin/` | Catalogo de reglas (AS-101..AS-110, AS-201..AS-207) | `agentsec/rules/builtin/` |
| `scoring.py` | Puntaje 0-100 y distribucion por severidad | `agentsec/scoring.py` |
| `reporter.py` | Render text/json/sarif/html | `agentsec/reporter.py` |
| `payloads/` | Suite de inyeccion indirecta + prober dinamico | `agentsec/payloads/` |
| `scanner.py` | Orquesta parsing + reglas + scoring + exit-code | `agentsec/scanner.py` |
| `cli.py` | Interfaz typer (`scan`, `probe`, `version`) | `agentsec/cli.py` |
| `app/` | API REST + panel web (FastAPI + SQLite) | `app/` |
| `.github/` | Accion reutilizable para CI | `.github/actions/agentsec` |

## 4. Modelo de datos (resumen)

- **`Distribution`**: vista normalizada de un archivo de config, con listas
  semanticamente separadas: `tools`, `agents`, `sources`, `memory`,
  `credentials`, `dependencies`. Esto permite reglas que razonan sobre el **rol**
  de cada elemento (ej: "tool de egress sin allowlist") en lugar de hacer
  busquedas textuales.
- **`Finding`**: hallazgo con `rule_id`, severidad (Critical..Info), CWE,
  referencia OWASP LLM, `Location` (archivo + linea) y evidencia.
- **`ScanResult`**: agrega hallazgos, `score` y metadatos del scan.

## 5. Motor de reglas

Reglas declarativas en YAML. Un hallazgo se emite si **alguna** comprobacion
coincide (OR); dentro de una comprobacion de coleccion se evalua cada elemento
(ANY). Operadores soportados: `exists`, `not_exists`, `eq`, `ne`, `substring`,
`regex`, `not_regex`, `in`, `gt`, `lt`.

Las reglas de exceso de agencia (AS-101..AS-103, AS-105, AS-109, AS-110) revisan
los permisos efectivos de las tools y los agentes; las de datos (AS-104, AS-106,
AS-107, AS-108) revisan secretos, sanitizacion de fuentes, memoria y suministro.
La categoria de asistentes (AS-201..AS-207) agrega permisos locales bash/edit,
MCP remotos sin validacion, credenciales en env de MCP y skills/plugins sin
version fijada.

## 6. Scoring

```
score = clamp(100 - sum(severity_weight * exposure), 0, 100)
  critical=40, high=25, medium=10, low=3, info=0.5
  exposure = 1.0 (agente accesible por red; default conservador)
```

- exit `0` PASS (score >= 80) · `1` WARN (60-79) · `2` FAIL (< 60)

## 7. Prober de inyeccion indirecta

Inyecta datos envenenados (no instrucciones de usuario) y detecta si la respuesta
contiene **marcadores** de la instruccion embebida. Es agnostico del modelo: no
llama a ninguna API de LLM; solo requiere el endpoint del agente.

## 8. Validacion (tesis)

- Corpus de **47 configs** (`tests/corpus/`) etiquetado como ground-truth:
  27 vulnerables + 20 limpias, cubriendo las **17 reglas** (AS-101..AS-110 sobre
  LangChain/CrewAI, AS-201..AS-207 sobre asistentes), incluyendo casos borde
  disenados para evitar falsos positivos triviales (sandbox, allowlists, permisos
  declarados, MCP de catalogo no habilitado).
- Metricas por regla y clasificacion binaria por archivo en
  `tests/corpus_validation.py`; **aplicadas como gate de CI** en
  `tests/test_corpus_validation.py` (falla si la exactitud binaria cae bajo 0.95
  o si alguna regla queda sin caso de ground-truth).
- Caso adversarial dedicado (`tests/corpus/*/assistant/mcp_marketplace_disabled*`):
  un MCP remoto con secreto embebido dentro de un plugin de marketplace **no
  habilitado** prueba, de punta a punta (no solo con mocks unitarios), que
  AS-203/AS-204 se suprimen correctamente por el estado del plugin mientras que
  AS-206 (secreto hardcodeado) se sigue detectando — son preocupaciones
  independientes por diseno.
- Demo end-to-end: `demo/demo_agent.py` es un agente vulnerable; `agentsec scan`
  detecta el exceso de agencia en su config y `agentsec probe` detona los 8
  payloads de inyeccion.

### Limitaciones metodologicas conocidas

- El corpus es **autoria del mismo equipo que escribio las reglas** (no es un
  corpus independiente ni ciego). La precision/recall de 1.0 obtenida demuestra
  que el motor implementa correctamente la especificacion de cada regla, no que
  las reglas generalicen a configuraciones reales no vistas.
- Trabajo futuro natural: validar contra un corpus externo (proyectos publicos
  de LangChain/CrewAI/opencode reales, etiquetados por un tercero) para medir
  generalizacion y tasa de falsos positivos "en el mundo real".