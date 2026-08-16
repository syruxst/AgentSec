# Contribuir a AgentSec

## Entorno de desarrollo

```bash
python -m venv .venv
# Windows
.venv\Scripts\python -m pip install -e ".[dev,web]"
# Linux/macOS
source .venv/bin/activate && pip install -e ".[dev,web]"
```

## Antes de abrir un PR

```bash
.venv\Scripts\python -m pytest tests
.venv\Scripts\python -m ruff check agentsec app tests
.venv\Scripts\python -m ruff format --check agentsec app tests
.venv\Scripts\python -m mypy agentsec app
```

Los cuatro comandos deben pasar sin errores. Si tu cambio toca el motor de reglas o el
scoring, corre también el corpus de validación:

```bash
.venv\Scripts\python tests/corpus_validation.py
```

## Agregar una regla nueva

1. Elige el archivo YAML correspondiente en `agentsec/rules/builtin/`:
   `agency.yaml` (exceso de agencia, agentes declarativos), `data.yaml` (datos/secretos,
   agentes declarativos) o `assistant.yaml` (asistentes de código: opencode/Claude Code).
2. Define la regla con, como mínimo:
   ```yaml
   - id: AS-1NN                 # siguiente id libre en su rango
     name: "Nombre corto"
     description: "Qué detecta y por qué es un riesgo."
     severity: critical|high|medium|low|info
     cwe: "CWE-XXX"             # si aplica
     owasp_llm: "LLMXX:2025"    # mapeo a OWASP Top 10 for LLM Apps
     remediation: "Cómo mitigarlo."
     frameworks: [langchain, crewai]   # o [assistant]
     checks:
       - scope: tools           # tools | agents | sources | memory | credentials | dependencies
         conditions:
           - field: type
             op: substring
             value: shell
   ```
   Operadores disponibles en `agentsec/rules/engine.py`: `exists`, `not_exists`, `eq`,
   `ne`, `substring`, `regex`, `not_regex`, `in`, `gt`, `lt`.
3. Agrega al menos un caso vulnerable y, si corresponde, un caso límite "limpio" que NO
   debería dispararla, en `tests/corpus/vulnerable/` o `tests/corpus/clean/`.
4. Registra ambos casos en `tests/corpus/manifest.yaml` bajo la clave correspondiente,
   listando los `rule_id` esperados por archivo.
5. Corre `pytest tests/test_rules.py tests/corpus_validation.py -q` y confirma que la
   precisión/recall de la regla nueva sea 1.0 sobre tus propios casos antes de subir el PR.
6. Documenta la regla en `docs/reglas.md`.

## Convención de commits y PRs

- Mensajes de commit en imperativo y en español o inglés consistente con el resto del
  historial (`Agrega regla AS-111 ...`, `Fix ...`, `Update ...`).
- Un PR = un cambio coherente; evita mezclar refactors con features.
- Usa la plantilla de PR (`.github/pull_request_template.md`) para describir el cambio
  y el plan de pruebas.
- Los issues de bug/feature usan las plantillas en `.github/ISSUE_TEMPLATE/`.
