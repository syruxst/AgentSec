# Catálogo de reglas

Referencia completa de las 17 reglas incluidas en `agentsec/rules/builtin/`. Para el
resumen corto orientado a uso rápido, ver `docs/uso.md`. Para cómo agregar una regla
nueva, ver `CONTRIBUTING.md`.

Cada regla tiene: severidad (peso en el score, ver `docs/arquitectura.md` §6), CWE,
mapeo a [OWASP Top 10 for LLM Applications](https://owasp.org/www-project-top-10-for-large-language-model-applications/),
frameworks a los que aplica y remediación.

## Resumen

| ID | Severidad | CWE | OWASP LLM | Frameworks | Nombre |
|---|---|---|---|---|---|
| AS-101 | critical | CWE-78 | LLM02 | langchain, crewai | Ejecución de comandos del sistema sin restricción |
| AS-102 | high | CWE-285 | LLM02 | langchain, crewai | Carga amplia de herramientas |
| AS-103 | medium | CWE-22 | LLM04 | langchain, crewai | Acceso a filesystem sin allowlist |
| AS-104 | critical | CWE-798 | LLM09 | langchain, crewai | Secreto hardcodeado en configuración |
| AS-105 | medium | CWE-779 | LLM05 | langchain, crewai | Herramienta de egress sin control de alcance |
| AS-106 | high | CWE-1336 | LLM01 | langchain, crewai | Fuente de datos sin sanitización |
| AS-107 | low | CWE-276 | LLM01 | langchain, crewai | Memoria compartida sin scoping por agente |
| AS-108 | medium | CWE-1104 | LLM07 | langchain, crewai | Dependencia o plugin no verificado |
| AS-109 | high | CWE-250 | LLM09 | langchain, crewai | Credencial sobre-scoped o sin revisión |
| AS-110 | medium | CWE-352 | LLM02 | langchain, crewai | Delegación agente-a-agente sin validación de origen |
| AS-201 | critical | CWE-78 | LLM02 | assistant | Permiso de ejecución de comandos locales (bash/shell) |
| AS-202 | high | CWE-285 | LLM02 | assistant | Capacidad amplia de escritura/edición sin allowlist |
| AS-203 | high | CWE-918 | LLM05 | assistant | MCP server remoto sin validación de origen |
| AS-204 | medium | CWE-798 | LLM09 | assistant | MCP server local con credenciales embebidas |
| AS-205 | medium | CWE-1104 | LLM07 | assistant | Plugin/skill externo sin verificación de versión |
| AS-206 | critical | CWE-798 | LLM09 | assistant | Secreto hardcodeado en config del asistente |
| AS-207 | low | CWE-352 | LLM02 | assistant | Delegación agente-a-agente sin validación de origen |

## AS-1xx — Exceso de agencia y datos (agentes declarativos)

### AS-101 · Ejecución de comandos del sistema sin restricción — `critical`
La configuración expone una herramienta capaz de ejecutar comandos del sistema (shell,
exec, subprocess) sin validación de entrada ni sandbox. Un atacante vía inyección
indirecta puede ejecutar comandos arbitrarios.
**Mitigación válida:** declarar `sandbox: true` o `allowed_commands`.
**Remediación:** eliminar las herramientas de ejecución o envolverlas con lista blanca
estricta de comandos, validación de argumentos, y no delegar al modelo la decisión sobre
el comando a ejecutar.

### AS-102 · Carga amplia de herramientas — `high`
Se cargan todas las herramientas disponibles (`load_all_tools`, `import_all_tools`) u
otra forma de agrupación masiva. Amplía la superficie de ataque y viola el principio de
mínimo privilegio.
**Remediación:** cargar únicamente las herramientas necesarias para la tarea y aplicar
allowlist explícita por agente.

### AS-103 · Acceso a filesystem sin allowlist — `medium`
Herramienta de lectura/escritura de archivos sin restricción de rutas permitidas. Puede
filtrar archivos sensibles o ser abusada para persistencia.
**Mitigación válida:** `allowed_paths` o `restrict_to_dirs`.
**Remediación:** restringir a un directorio de trabajo (allowlist) y validar rutas antes
de cualquier operación.

### AS-104 · Secreto hardcodeado en configuración — `critical`
Se detecta una API key, token, password o secreto incrustado directamente en el archivo
de configuración. Queda expuesto en el repositorio y en cualquier artefacto de CI/CD.
**Mitigación válida:** referencias (`${...}`, `env(...)`, `secret_ref`) en vez de valores
literales.
**Remediación:** mover el secreto a un gestor de secretos o variables de entorno y rotar
la credencial comprometida. Nunca versionar secretos.

### AS-105 · Herramienta de egress sin control de alcance — `medium`
Herramienta HTTP/red/correo/base de datos capaz de escribir hacia el exterior sin límite
de destinos. Permite exfiltración de datos sensibles procesados por el agente.
**Mitigación válida:** `allowed_hosts`.
**Remediación:** definir allowlist de destinos alcanzables, monitorear salidas y aplicar
controles de exfiltración (enmascarado de datos).

### AS-106 · Fuente de datos sin sanitización — `high`
El agente consume documentos, HTML/markdown, hojas de cálculo o respuestas de red sin
capa de sanitización. Un documento envenenado puede ejecutar una inyección de prompt
indirecta.
**Mitigación válida:** `sanitize` o `label_data`.
**Remediación:** sanitizar/etiquetar contenido externo, tratarlo como datos no confiables
y separarlo del contexto de instrucciones.

### AS-107 · Memoria compartida sin scoping por agente — `low`
La memoria/embeddings del agente no está aislada por entidad o tiene alcance
(`scope: global|shared|none`). Permite envenenamiento de memoria entre sesiones o
usuarios.
**Remediación:** particionar almacenes de memoria por usuario/sesión y tratar contenido
persistido como no confiable al reinyectarlo.

### AS-108 · Dependencia o plugin no verificado — `medium`
Herramienta/plugin/dependencia sin versión fijada ni verificación de origen.
**Remediación:** fijar versiones, verificar hash/origen del paquete y auditar el árbol de
skills/tools antes de permitir su uso.

### AS-109 · Credencial sobre-scoped o sin revisión — `high`
Credencial asociada a una herramienta en entorno de producción sin `scopes` ni
`permissions` documentados. El agente puede heredar permisos mayores a los necesarios.
**Remediación:** aplicar mínimo privilegio, documentar el ámbito efectivo de cada
credencial y requerir revisión de otorgamiento.

### AS-110 · Delegación agente-a-agente sin validación de origen — `medium`
El agente puede delegar o invocar otros agentes/perfiles (`allow_delegation: true`) sin
`trust_origin`, ampliando la superficie de abuso entre agentes.
**Remediación:** validar identidad y contexto de origen de cada delegación y aplicar
políticas de confianza entre agentes.

## AS-2xx — Asistentes de código agénticos (opencode, Claude Code/Desktop)

### AS-201 · Permiso de ejecución de comandos locales (bash/shell) — `critical`
El asistente tiene permiso de ejecutar comandos del sistema (`bash`, `shell`, `exec`,
`zsh`, `powershell`, `cmd`) sin restricción, con `grant: allow` o sin declarar. Un
documento o skill envenenado puede forzar ejecución arbitraria local a través del LLM.
**Mitigación válida:** permisos concretos por comando (ej. `bash:git status`) no
disparan la regla.
**Remediación:** usar reglas de permiso con lista blanca por comando, negar por defecto
y requerir confirmación interactiva para bash/exec.

### AS-202 · Capacidad amplia de escritura/edición sin allowlist — `high`
Permisos amplios de escritura, edición o aplicación de patches (`edit`, `write:*`,
`create`, `patch`) habilitados globalmente.
**Remediación:** restringir edición a directorios del proyecto, requerir confirmación
por archivo y denegar escritura fuera del workspace.

### AS-203 · MCP server remoto sin validación de origen — `high`
Se configura un servidor MCP accesible por URL (remoto), el plugin que lo declara está
**habilitado**, y no tiene `verified`. El asistente enviará contexto de conversación a
ese endpoint; uno malicioso o comprometido puede inducir exfiltración o reinyectar
instrucciones.
**Nota sobre falsos positivos:** los `.mcp.json` del catálogo de marketplace se marcan
`enabled: false` salvo que el plugin figure en `enabledPlugins` (`settings.json`) o
`installed_plugins.json`; esta regla solo opera sobre MCP habilitados.
**Remediación:** validar el origen del URL (allowlist de dominios), usar autenticación y
no conectar MCP remotos de terceros sin revisión.

### AS-204 · MCP server local con credenciales embebidas — `medium`
Un servidor MCP local (habilitado) porta claves/tokens literales en su `env`.
**Mitigación válida:** referencias `env:`/`${}`/`process.env` no disparan la regla.
**Remediación:** mover credenciales a variables de entorno del sistema o gestor de
secretos; nunca incrustarlas en la config de MCP.

### AS-205 · Plugin/skill externo sin verificación de versión — `medium`
El asistente habilita plugins o skills cuya versión no está fijada.
**Remediación:** fijar versiones exactas, verificar el origen del paquete y auditar el
código del plugin antes de habilitarlo.

### AS-206 · Secreto hardcodeado en config del asistente — `critical`
Clave (API key, token, password) literal en la configuración del asistente.
**Mitigación válida:** referencias (`${...}`, `env(...)`, `env:`, `process.env`) no
disparan la regla.
**Remediación:** usar variables de entorno o gestor de secretos; rotar la credencial
comprometida.

### AS-207 · Delegación agente-a-agente sin validación de origen — `low`
El asistente puede delegar o invocar otros agentes/perfiles sin `trust_origin`.
**Remediación:** validar identidad y contexto de origen en cada delegación.
