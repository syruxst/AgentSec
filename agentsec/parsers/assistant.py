"""Parser de configuraciones de asistentes de código agénticos.

Cubre opencode (opencode.json/.jsonc), Claude Code / Claude Desktop
(.claude/settings.json, claude.json) y configs de MCP servers (mcp.json).
Normaliza permisos de herramientas, MCP servers y skills a una Distribution.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from agentsec.models import Distribution
from agentsec.parsers.base import BaseParser, ParseError, load_mapping

ASSISTANT_FILES = {
    "opencode.json",
    "opencode.jsonc",
    "claude.json",
    "claude_desktop_config.json",
    "mcp.json",
    ".mcp.json",
}
CLAUDE_SETTINGS = "settings.json"
ASSISTANT_DIRS = ("/.claude/", "/claude/", "opencode/", ".claude/", "claude/")
MCP_KEYS = ("mcpServers", "mcp_servers", "mcp")


def _as_list(node: Any) -> list[Any]:
    if node is None:
        return []
    return node if isinstance(node, list) else [node]


def _dicts(node: Any) -> list[dict[str, Any]]:
    return [n for n in _as_list(node) if isinstance(n, dict)]


class AssistantParser(BaseParser):
    framework = "assistant"

    @classmethod
    def handles(cls, path: Path) -> bool:
        name = path.name.lower()
        rel = str(path).replace("\\", "/").lower()
        if name in ASSISTANT_FILES:
            return True
        if name == CLAUDE_SETTINGS and any(seg in rel for seg in ASSISTANT_DIRS):
            return True
        return name in {"settings.json", "config.json"} and (
            "/.claude/" in rel
            or rel.startswith(".claude/")
            or "/opencode/" in rel
            or rel.startswith("opencode/")
        )

    def parse(self, path: Path) -> Distribution | None:
        try:
            data = load_mapping(path)
        except ParseError:
            return None

        dist = Distribution(
            framework=self.framework,
            path=str(path).replace("\\", "/"),
            data=data,
            tools=self._collect_permissions(data) + self._collect_mcp(data, path),
            agents=self._collect_agents(data),
            sources=self._collect_sources(data),
            memory=[],
            credentials=self._collect_credentials(data),
            dependencies=self._collect_dependencies(data),
        )
        return dist

    # ---------------------------------- helpers ----------------------------------

    @staticmethod
    def _collect_permissions(data: dict[str, Any]) -> list[dict[str, Any]]:
        """Permisos de herramientas: allow/deny y toggles (safeMode, edit, bash)."""
        tools: list[dict[str, Any]] = []
        node = data.get("permissions") or data.get("permission") or {}
        if not isinstance(node, dict):
            return tools

        for field, mode in (("allow", "allow"), ("deny", "deny")):
            for item in _as_list(node.get(field)):
                if isinstance(item, str) and item:
                    tools.append({"name": item, "grant": mode, "kind": "permission"})
                elif isinstance(item, dict):
                    tools.append({"name": item.get("name", ""), "grant": mode, **item})

        for key in ("tools", "tool"):
            toggles = data.get(key)
            if isinstance(toggles, dict):
                for tool_name, setting in toggles.items():
                    if isinstance(setting, dict):
                        tools.append({"name": tool_name, "kind": "toggle", **setting})
        return tools

    @staticmethod
    def _collect_mcp(data: dict[str, Any], path: Path) -> list[dict[str, Any]]:
        """Servidores MCP (remotos por URL o locales por comando)."""
        servers: list[dict[str, Any]] = []
        candidates: dict[str, Any] = {}
        for key in MCP_KEYS:
            for node in (data.get(key), data.get(f"{key}Config")):
                if isinstance(node, dict):
                    candidates |= node
        if not candidates and _looks_like_mcp_map(data):
            candidates = data
        enabled = _plugin_enabled(path)
        for name, cfg in candidates.items():
            if not isinstance(cfg, dict):
                continue
            server = {"name": name, "kind": "mcp", "enabled": enabled}
            if cfg.get("url"):
                server["url"] = cfg["url"]
            elif cfg.get("command"):
                server["command"] = cfg["command"]
                server["args"] = " ".join(map(str, _as_list(cfg.get("args"))))
            if cfg.get("verified"):
                server["verified"] = True
            if cfg.get("env"):
                env = cfg["env"]
                server["env"] = _env_preview(env) if isinstance(env, dict) else list(env)
            servers.append(server)
        return servers

    @staticmethod
    def _collect_agents(data: dict[str, Any]) -> list[dict[str, Any]]:
        agents: list[dict[str, Any]] = []
        for key in ("agents", "agent"):
            node = data.get(key)
            if isinstance(node, dict):
                agents.append(node)
            elif isinstance(node, list):
                agents.extend(_dicts(node))
        return agents

    @staticmethod
    def _collect_sources(data: dict[str, Any]) -> list[dict[str, Any]]:
        """Skills/plugins/recursos externos que el asistente puede cargar."""
        sources: list[dict[str, Any]] = []
        node = data.get("skills") or data.get("plugins") or data.get("enabledPlugins") or {}
        if isinstance(node, dict):
            for name, value in node.items():
                sources.append(AssistantParser._skill(name, bool(value)))
        elif isinstance(node, list):
            for item in node:
                if isinstance(item, dict):
                    sources.append(item)
                else:
                    sources.append(AssistantParser._skill(str(item), True))
        return sources

    @staticmethod
    def _skill(name: str, enabled: bool) -> dict[str, Any]:
        """Divide 'nombre@version' y registra habilidad."""
        base, sep, version = name.partition("@")
        out: dict[str, Any] = {"name": base if sep else name, "enabled": enabled}
        if sep:
            out["version"] = version
        return out

    @staticmethod
    def _collect_credentials(data: dict[str, Any]) -> list[dict[str, Any]]:
        creds: list[dict[str, Any]] = []
        for key, value in _flatten(data).items():
            lowered = key.lower()
            if any(tok in lowered for tok in ("api_key", "apikey", "secret", "password", "token")):
                text = str(value)
                if len(text) > 12:
                    text = f"{text[:4]}...{text[-4:]}"
                creds.append({"key": key, "value_preview": text})
        return creds

    @staticmethod
    def _collect_dependencies(data: dict[str, Any]) -> list[dict[str, Any]]:
        deps: list[dict[str, Any]] = []
        for mcp in (
            data.get("mcpServers", {}).values() if isinstance(data.get("mcpServers"), dict) else []
        ):
            if isinstance(mcp, dict):
                command = mcp.get("command")
                args = " ".join(map(str, _as_list(mcp.get("args"))))
                deps.append({"name": command or mcp.get("name", "mcp"), "version": args or None})
        return deps


def _plugin_enabled(path: Path) -> bool:
    """Determina si un MCP del catalogo pertenece a un plugin habilitado.

    Los .mcp.json bajo plugins/marketplaces/ declaran MCPs de plugins
    *disponibles*; solo cuentan como activos si el plugin figura en
    settings.json (enabledPlugins) o installed_plugins.json.
    """
    catalog_plugin = _catalog_plugin(path)
    if catalog_plugin is None:
        return True
    root = _claude_root(path)
    if root is None:
        return True
    return catalog_plugin in _enabled_plugin_ids(root)


def _catalog_plugin(path: Path) -> str | None:
    """'<plugin>@<marketplace>' si el path vive en plugins/marketplaces/..."""
    parts = path.parts
    for i, part in enumerate(parts):
        if part.lower() != "marketplaces":
            continue
        if i + 3 >= len(parts):
            return None
        marketplace, layout, plugin = parts[i + 1], parts[i + 2], parts[i + 3]
        if layout.lower() not in ("plugins", "external_plugins"):
            return None
        return f"{plugin}@{marketplace}"
    return None


def _claude_root(path: Path) -> Path | None:
    """Raiz del perfil de Claude (dir con settings.json + plugins/)."""
    for parent in path.parents:
        if (parent / "settings.json").is_file() and (parent / "plugins").is_dir():
            return parent
    return None


def _enabled_plugin_ids(root: Path) -> set[str]:
    """Ids de plugins habilitados desde settings.json e installed_plugins.json."""
    ids: set[str] = set()
    settings = root / "settings.json"
    if settings.is_file():
        try:
            data = load_mapping(settings)
        except ParseError:
            data = {}
        for plugin, enabled in (data.get("enabledPlugins") or {}).items():
            if enabled:
                ids.add(plugin)
    installed = root / "plugins" / "installed_plugins.json"
    if installed.is_file():
        try:
            data = load_mapping(installed)
        except ParseError:
            data = {}
        ids.update((data.get("plugins") or {}).keys())
    return ids


def _env_preview(env: dict[str, Any]) -> list[str]:
    """Representacion 'K=V_prev' de variables de entorno para evidencia."""
    out: list[str] = []
    for key, value in env.items():
        text = str(value)
        if len(text) > 16:
            text = f"{text[:8]}...{text[-4:]}"
        out.append(f"{key}={text}")
    return out


def _looks_like_mcp_map(data: dict[str, Any]) -> bool:
    """True si el dict raiz es un mapa nombre->config de MCP (esquema 'bare')."""
    if not data:
        return False
    entries = [v for v in data.values() if isinstance(v, dict)]
    if not entries:
        return False
    configured = sum(1 for e in entries if "url" in e or "command" in e)
    return configured >= max(1, len(entries) // 2)


def _flatten(node: Any, prefix: str = "") -> dict[str, Any]:
    out: dict[str, Any] = {}
    if isinstance(node, dict):
        for key, child in node.items():
            full = f"{prefix}.{key}" if prefix else key
            if isinstance(child, (dict, list)):
                out.update(_flatten(child, full))
            else:
                out[full] = child
    elif isinstance(node, list):
        for i, child in enumerate(node):
            out.update(_flatten(child, f"{prefix}[{i}]"))
    return out
