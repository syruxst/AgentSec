"""Parser de configuraciones de LangChain (YAML/TOML/JSON)."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from agentsec.models import Distribution
from agentsec.parsers.base import BaseParser, ParseError, load_mapping

# Herramientas o tipos cuya mera presencia indica un problema serio.
DANGEROUS_TOOL_HINTS = ("shell", "exec", "subprocess", "bash")
BROAD_TOOL_HINTS = ("load_all_tools", "import_all", "get_all", "*tool*", ".tools.")
STR_TOOL_HINTS = ("create_python", "write_file", "read_file", "file", "http", "requests")


def _paths(value: Any) -> list[str]:
    """Recorre un mapping/búsqueda devolviendo las claves de cada nivel."""
    result: list[str] = []

    def walk(node: Any, prefix: str = "") -> None:
        if isinstance(node, dict):
            for key, child in node.items():
                full = f"{prefix}.{key}" if prefix else str(key)
                result.append(full)
                walk(child, full)
        elif isinstance(node, list):
            for i, child in enumerate(node):
                walk(child, f"{prefix}[{i}]")

    walk(value)
    return result


def _iter_tools(data: Any) -> list[dict[str, Any]]:
    """Extrae la lista de tools si está presente en un nodo langchain."""
    tools: list[dict[str, Any]] = []
    if isinstance(data, dict):
        for key in ("tools", "tool_list", "available_tools"):
            candidate = data.get(key)
            if isinstance(candidate, list):
                for item in candidate:
                    if isinstance(item, dict):
                        tools.append(item)
                    elif isinstance(item, str):
                        tools.append({"name": item})
    return tools


def _iter_agents(data: Any) -> list[dict[str, Any]]:
    agents: list[dict[str, Any]] = []
    if isinstance(data, dict):
        for key in ("agents", "agent", "runnable"):
            candidate = data.get(key)
            if isinstance(candidate, dict):
                agents.append(candidate)
            elif isinstance(candidate, list):
                for item in candidate:
                    if isinstance(item, dict):
                        agents.append(item)
    return agents


class LangChainParser(BaseParser):
    framework = "langchain"

    @classmethod
    def handles(cls, path: Path) -> bool:
        name = path.name.lower()
        rel = str(path).replace("\\", "/").lower()

        if any(seg in rel for seg in ("langchain", "/chains/", "/agents/")):
            return True
        return name in {"chain.yaml", "chain.yml", "chain.json", "agent.yaml", "agent.json"}

    def parse(self, path: Path) -> Distribution | None:
        try:
            data = load_mapping(path)
        except ParseError:
            return None

        if "langchain" not in self._signature(data) and not self._looks_like_langchain(path, data):
            return None

        tools = _iter_tools(data)
        agents = _iter_agents(data)

        dist = Distribution(
            framework=self.framework,
            path=self._project_path(path),
            data=data,
            tools=tools,
            agents=agents,
            sources=self._extract_sources(data),
            memory=self._extract_memory(data),
            credentials=self._extract_credentials(data),
            dependencies=self._extract_dependencies(data),
        )
        return dist

    # -------------------------------- helpers --------------------------------

    @staticmethod
    def _signature(data: dict[str, Any]) -> list[str]:
        return _paths(data)

    @staticmethod
    def _looks_like_langchain(path: Path, data: dict[str, Any]) -> bool:
        hints = ("llm", "model", "prompt", "retriever", "vectorstore", "chain", "tool")
        path_hit = any(h in path.name.lower() for h in ("chain", "agent"))
        return path_hit and any(h in str(data).lower() for h in hints)

    @staticmethod
    def _project_path(path: Path) -> str:
        return str(path).replace("\\", "/")

    @classmethod
    def _extract_sources(cls, data: Any) -> list[dict[str, Any]]:
        sources: list[dict[str, Any]] = []
        if isinstance(data, dict):
            for key in ("loader", "document_loaders", "retriever", "vectorstore"):
                node = data.get(key)
                if node is not None:
                    if isinstance(node, dict):
                        sources.append(node)
                    elif isinstance(node, list):
                        sources.extend([n for n in node if isinstance(n, dict)])
        return sources

    @classmethod
    def _extract_memory(cls, data: Any) -> list[dict[str, Any]]:
        memory: list[dict[str, Any]] = []
        if isinstance(data, dict):
            node = data.get("memory")
            if isinstance(node, dict):
                memory.append(node)
            for agent in _iter_agents(data):
                m = agent.get("memory")
                if isinstance(m, dict):
                    memory.append(m)
        return memory

    @classmethod
    def _extract_credentials(cls, data: Any) -> list[dict[str, Any]]:
        credentials: list[dict[str, Any]] = []
        for key, value in _flatten(data).items():
            lowered = key.lower()
            if any(tok in lowered for tok in ("api_key", "apikey", "secret", "password", "token")):
                credentials.append({"key": key, "value_preview": cls._preview(value)})
        return credentials

    @staticmethod
    def _preview(value: Any) -> str:
        text = str(value)
        if len(text) > 12:
            return f"{text[:4]}...{text[-4:]}"
        return text

    @classmethod
    def _extract_dependencies(cls, data: Any) -> list[dict[str, Any]]:
        deps: list[dict[str, Any]] = []
        if isinstance(data, dict):
            for key in ("dependencies", "python_deps"):
                node = data.get(key)
                if isinstance(node, list):
                    for item in node:
                        if isinstance(item, str):
                            deps.append({"name": item, "version": None})
                        elif isinstance(item, dict):
                            deps.append(item)
        return deps


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
