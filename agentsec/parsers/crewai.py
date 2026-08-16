"""Parser de configuraciones de CrewAI (crews.yaml, agents.yaml, tasks.yaml)."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from agentsec.models import Distribution
from agentsec.parsers.base import BaseParser, ParseError, load_mapping

CREW_FILES = {"crews.yaml", "crews.yml", "agents.yaml", "agents.yml", "tasks.yaml", "tasks.yml"}
CREW_SECTIONS = {"crew", "crews", "agent", "agents", "task", "tasks"}


def _list_of(node: Any) -> list[dict[str, Any]]:
    if isinstance(node, dict):
        return [node] if node else []
    if isinstance(node, list):
        return [item for item in node if isinstance(item, dict)]
    return []


class CrewAIParser(BaseParser):
    framework = "crewai"

    @classmethod
    def handles(cls, path: Path) -> bool:
        name = path.name.lower()
        rel = str(path).replace("\\", "/").lower()
        return name in CREW_FILES or "/crewai/" in rel or bool(name.startswith("crew"))

    def parse(self, path: Path) -> Distribution | None:
        try:
            data = load_mapping(path)
        except ParseError:
            return None

        dist = Distribution(
            framework=self.framework,
            path=str(path).replace("\\", "/"),
            data=data,
            tools=self._collect(data, "tools"),
            agents=self._collect(data, "agents"),
            sources=self._extra_sources(data),
            memory=[],
            credentials=self._collect_credentials(data),
            dependencies=self._collect_dependencies(data),
        )
        return dist

    # ---------------------------------- helpers ----------------------------------

    @staticmethod
    def _collect(data: dict[str, Any], key: str) -> list[dict[str, Any]]:
        items = _list_of(data.get(key))
        # CrewAI acepta a veces la seccion en plural o singular.
        for candidate in (data,):
            for section in CREW_SECTIONS:
                node = candidate.get(section)
                if isinstance(node, list):
                    for item in node:
                        if isinstance(item, dict) and key in item:
                            if key == "tools":
                                items.extend(CrewAIParser._tools_from_agent(item))
                            else:
                                items.extend(_list_of(item[key]))
        if key == "tools":
            for section in ("crew", "crews"):
                node = data.get(section)
                for item in _list_of(node):
                    items.extend(CrewAIParser._tools_from_agent(item))
                    for agent in _list_of(item.get("agents")):
                        items.extend(CrewAIParser._tools_from_agent(agent))
        return items

    @staticmethod
    def _tools_from_agent(agent: dict[str, Any]) -> list[dict[str, Any]]:
        """Extrae tools de un agente enriqueciendolas con el contexto del agente."""
        tools = _list_of(agent.get("tools"))
        context_fields = ("environment", "allow_delegation", "trust_origin")
        enriched: list[dict[str, Any]] = []
        for tool in tools:
            merged = dict(tool)
            for field in context_fields:
                if field in agent and field not in merged:
                    merged[field] = agent[field]
            enriched.append(merged)
        return enriched

    @staticmethod
    def _extra_sources(data: dict[str, Any]) -> list[dict[str, Any]]:
        sources: list[dict[str, Any]] = []
        tasks = _list_of(data.get("task")) + _list_of(data.get("tasks"))
        for node in tasks:
            merged: dict[str, Any] = {
                k: node[k]
                for k in ("input_file", "document", "url", "loader", "context")
                if k in node and node[k] is not None
            }
            for k in ("sanitize", "label_data"):
                if k in node:
                    merged[k] = node[k]
            if merged:
                sources.append(merged)
        return sources

    @staticmethod
    def _collect_credentials(data: dict[str, Any]) -> list[dict[str, Any]]:
        creds: list[dict[str, Any]] = []

        def walk(node: Any, prefix: str = "") -> None:
            if isinstance(node, dict):
                for k, v in node.items():
                    lowered = k.lower()
                    if any(t in lowered for t in ("api_key", "secret", "password", "token")):
                        text = str(v)
                        if len(text) > 12:
                            text = f"{text[:4]}...{text[-4:]}"
                        creds.append(
                            {"key": f"{prefix}.{k}" if prefix else k, "value_preview": text}
                        )
                    else:
                        walk(v, f"{prefix}.{k}" if prefix else k)
            elif isinstance(node, list):
                for i, item in enumerate(node):
                    walk(item, f"{prefix}[{i}]")

        walk(data)
        return creds

    @staticmethod
    def _collect_dependencies(data: dict[str, Any]) -> list[dict[str, Any]]:
        deps: list[dict[str, Any]] = []
        for key in ("dependencies", "requirements"):
            node = data.get(key)
            if isinstance(node, list):
                for item in node:
                    if isinstance(item, str):
                        deps.append({"name": item, "version": None})
                    elif isinstance(item, dict):
                        deps.append(item)
        return deps
