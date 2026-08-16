"""Parser base y fábrica de detección de framework."""

from __future__ import annotations

import json
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any

import yaml

from agentsec.models import Distribution, Framework

CONFIG_EXTS = {".yaml", ".yml", ".json", ".jsonc", ".toml"}
MAX_CONFIG_SIZE = 1_000_000


class ParseError(Exception):
    """Error de parsing de un archivo de configuración."""


def load_text(path: Path) -> str:
    data = path.read_text(encoding="utf-8", errors="replace")
    if len(data) > MAX_CONFIG_SIZE:
        raise ParseError(f"archivo demasiado grande: {path}")
    return data


def load_mapping(path: Path) -> dict[str, Any]:
    """Carga YAML/JSON/TOML como mapping. Lanza ParseError si no es un mapping."""
    text = load_text(path)
    try:
        if path.suffix == ".json":
            parsed = json.loads(text)
        elif path.suffix == ".jsonc":
            parsed = json.loads(_strip_jsonc_comments(text))
        elif path.suffix == ".toml":
            return _load_toml(text, path)
        else:
            parsed = yaml.safe_load(text)
    except (yaml.YAMLError, json.JSONDecodeError) as exc:
        raise ParseError(f"{path}: YAML/JSON invalido: {exc}") from exc
    if parsed is None:
        return {}
    if not isinstance(parsed, dict):
        raise ParseError(f"{path}: se esperaba un mapping, se obtuvo {type(parsed).__name__}")
    return parsed


def _load_toml(text: str, path: Path) -> dict[str, Any]:
    import tomllib

    try:
        parsed = tomllib.loads(text)
    except tomllib.TOMLDecodeError as exc:
        raise ParseError(f"{path}: TOML invalido: {exc}") from exc
    if not isinstance(parsed, dict):
        raise ParseError(f"{path}: se esperaba un mapping TOML")
    return parsed


class BaseParser(ABC):
    """Convierte archivos de config de un framework a Distribution."""

    framework: Framework

    @abstractmethod
    def parse(self, path: Path) -> Distribution | None:
        """Devuelve None si el archivo no es config de este framework."""

    @classmethod
    @abstractmethod
    def handles(cls, path: Path) -> bool:
        """Detección rápida de pertenencia al framework (por nombre/ruta)."""


def is_config_file(path: Path) -> bool:
    if path.suffix not in CONFIG_EXTS:
        return False
    return path.stat().st_size <= MAX_CONFIG_SIZE


def _strip_jsonc_comments(text: str) -> str:
    """Quita comentarios /* */ y // de JSONC conservando strings literales."""
    out: list[str] = []
    in_string = False
    i = 0
    while i < len(text):
        ch = text[i]
        if in_string:
            out.append(ch)
            if ch == "\\" and i + 1 < len(text):
                out.append(text[i + 1])
                i += 2
                continue
            if ch == '"':
                in_string = False
            i += 1
            continue
        if ch == '"':
            in_string = True
            out.append(ch)
            i += 1
            continue
        if text.startswith("//", i):
            while i < len(text) and text[i] != "\n":
                i += 1
            continue
        if text.startswith("/*", i):
            end = text.find("*/", i + 2)
            i = len(text) if end == -1 else end + 2
            continue
        out.append(ch)
        i += 1
    return "".join(out)


def walk_project(root: Path) -> list[Path]:
    """Lista archivos de config de un proyecto respetando exclusiones comunes."""
    ignored = {".venv", "venv", "node_modules", ".git", "dist", "build", "__pycache__", ".venv310"}
    candidate = root if root.is_file() else None
    try:
        entries = [root] if candidate else sorted(root.rglob("*"))
    except OSError:
        entries = []
    result: list[Path] = []
    for entry in entries:
        if not entry.is_file():
            continue
        if candidate is not None:
            if not is_config_file(entry):
                continue
            result.append(entry)
            continue
        rel = entry.relative_to(root)
        if any(part in ignored for part in rel.parts):
            continue
        if is_config_file(entry):
            result.append(entry)
    return result


def detect_framework(paths: list[Path]) -> Framework | None:
    """Devuelve el framework mayoritario entre los archivos, o None."""
    scores: dict[Framework, int] = {"langchain": 0, "crewai": 0, "assistant": 0}
    for path in paths:
        name = path.name.lower()
        rel = str(path).replace("\\", "/").lower()
        if (
            name in {"crews.yaml", "agents.yaml", "tasks.yaml"}
            or "/crewai/" in rel
        ):
            scores["crewai"] += 2
        elif (
            name in {"chain.yaml", "agent.yaml", "chains", "agents"}
            or "/langchain/" in rel
        ):
            scores["langchain"] += 2
        elif (
            name in {"opencode.json", "opencode.jsonc", "claude.json",
                     "settings.json", "mcp.json", ".mcp.json"}
            or "/opencode/" in rel or "/.claude/" in rel
        ):
            scores["assistant"] += 2
        if "crew" in name:
            scores["crewai"] += 1
    total = sum(scores.values())
    if total == 0:
        return None
    return max(scores, key=scores.get)


def parse_file(path: Path, parser: BaseParser) -> Distribution | None:
    try:
        return parser.parse(path)
    except ParseError:
        return None


class ParserRegistry:
    """Registro de parsers y orquestación de parseo de un proyecto."""

    def __init__(self) -> None:
        from agentsec.parsers.assistant import AssistantParser
        from agentsec.parsers.crewai import CrewAIParser
        from agentsec.parsers.langchain import LangChainParser

        self._parsers: list[BaseParser] = [
            LangChainParser(),
            CrewAIParser(),
            AssistantParser(),
        ]

    def distributions(self, root: Path) -> list[Distribution]:
        paths = walk_project(root)
        framework = detect_framework(paths)
        dists: list[Distribution] = []
        for path in paths:
            for parser in self._parsers:
                if framework and parser.framework != framework:
                    continue
                if not parser.handles(path):
                    continue
                dist = parse_file(path, parser)
                if dist is not None:
                    dists.append(dist)
                break
        return dists
