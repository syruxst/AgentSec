"""Tests de parsing de configs de LangChain y CrewAI."""

from pathlib import Path

from agentsec.parsers.assistant import AssistantParser
from agentsec.parsers.base import detect_framework, walk_project
from agentsec.parsers.crewai import CrewAIParser
from agentsec.parsers.langchain import LangChainParser


def test_crewai_parse_tools_and_env(tmp_path):
    config = tmp_path / "crews.yaml"
    config.write_text(
        """
crew: demo
agents:
  - name: analyst
    environment: production
    tools:
      - name: RunShellTool
""",
        encoding="utf-8",
    )
    dist = CrewAIParser().parse(config)
    assert dist is not None
    assert dist.framework == "crewai"
    assert dist.tools == [{"name": "RunShellTool", "environment": "production"}]


def test_crewai_parse_credentials_scrambled(tmp_path):
    config = tmp_path / "agents.yaml"
    config.write_text(
        """
agents:
  - name: a
    llm:
      api_key: sk-literal-deadbeef
""",
        encoding="utf-8",
    )
    dist = CrewAIParser().parse(config)
    assert dist is not None
    assert any("api_key" in c["key"] for c in dist.credentials)


def test_langchain_parse_tools_and_sources(tmp_path):
    config = tmp_path / "chain.yaml"
    config.write_text(
        """
llm:
  model: gpt-4
tools:
  - name: shell_exec
loaders:
  - UnstructuredMarkdownLoader
""",
        encoding="utf-8",
    )
    dist = LangChainParser().parse(config)
    assert dist is not None
    assert any(t["name"] == "shell_exec" for t in dist.tools)


def test_langchain_not_crew_file():
    assert LangChainParser.handles(Path("crew/something/crews.yaml")) is False
    assert CrewAIParser.handles(Path("crew/something/crews.yaml")) is True


def test_detect_framework():
    paths = [Path("x/crewai/crews.yaml"), Path("x/crewai/agents.yaml")]
    assert detect_framework(paths) == "crewai"
    paths2 = [Path("x/langchain/chain.yaml")]
    assert detect_framework(paths2) == "langchain"


def test_walk_project_single_file(tmp_path):
    f = tmp_path / "chain_vuln.yaml"
    f.write_text("llm: {}\n", encoding="utf-8")
    assert walk_project(f) == [f]


def test_walk_project_ignores_venv(tmp_path):
    (tmp_path / ".venv").mkdir()
    (tmp_path / ".venv" / "chain.yaml").write_text("llm: {}\n", encoding="utf-8")
    (tmp_path / "chain.yaml").write_text("llm: {}\n", encoding="utf-8")
    found = walk_project(tmp_path)
    assert len(found) == 1
    assert found[0].name == "chain.yaml"


def test_assistant_parse_opencode_json(tmp_path):
    config = tmp_path / "opencode.json"
    config.write_text(
        """
{
  "permission": {
    "allow": ["bash:cat", "edit"],
    "deny": ["rm"]
  },
  "mcpServers": {
    "github": {
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-github"],
      "env": {"GITHUB_TOKEN": "ghp_abcdef"}
    }
  }
}
""",
        encoding="utf-8",
    )
    dist = AssistantParser().parse(config)
    assert dist is not None
    assert dist.framework == "assistant"
    perm = [t for t in dist.tools if t.get("kind") == "permission"]
    assert {"bash:cat", "edit", "rm"} == {t["name"] for t in perm}
    mcp = [t for t in dist.tools if t.get("kind") == "mcp"]
    assert any(s["name"] == "github" and s["command"] == "npx" for s in mcp)
    assert any(c["key"].endswith("GITHUB_TOKEN") for c in dist.credentials)


def test_assistant_parse_bare_mcp_schema(tmp_path):
    """Esquema 'bare': nombre de server como clave raiz (Claude plugins)."""
    config = tmp_path / ".mcp.json"
    config.write_text(
        """
{
  "linear": {
    "type": "http",
    "url": "https://mcp.linear.app/mcp"
  }
}
""",
        encoding="utf-8",
    )
    dist = AssistantParser().parse(config)
    assert dist is not None
    mcps = [t for t in dist.tools if t.get("kind") == "mcp"]
    assert any(s["name"] == "linear" and s["url"].startswith("https://") for s in mcps)


def test_assistant_catalog_mcp_enabled_state(tmp_path):
    """Un MCP del catalogo solo se marca enabled si el plugin esta instalado."""
    root = tmp_path / ".claude"
    mkt = root / "plugins" / "marketplaces" / "claude-plugins-official" / "external_plugins"
    (mkt / "context7").mkdir(parents=True)
    (mkt / "github").mkdir()
    root.joinpath("settings.json").write_text(
        '{"enabledPlugins": {"frontend-design@claude-plugins-official": true}}',
        encoding="utf-8",
    )
    root.joinpath("plugins", "installed_plugins.json").write_text(
        '{"plugins": {"frontend-design@claude-plugins-official": [], '
        '"github@claude-plugins-official": []}}',
        encoding="utf-8",
    )
    for plugin, content in (
        ("context7", '{"mcpServers": {"context7": {"url": "https://mcp.context7.com/mcp"}}}'),
        ("github", '{"github": {"url": "https://api.githubcopilot.com/mcp/"}}'),
    ):
        (mkt / plugin / ".mcp.json").write_text(content, encoding="utf-8")

    dist_ctx = AssistantParser().parse(mkt / "context7" / ".mcp.json")
    dist_gh = AssistantParser().parse(mkt / "github" / ".mcp.json")
    assert dist_ctx is not None and dist_gh is not None
    ctx = next(t for t in dist_ctx.tools if t.get("kind") == "mcp")
    gh = next(t for t in dist_gh.tools if t.get("kind") == "mcp")
    assert ctx["enabled"] is False  # no instalado
    assert gh["enabled"] is True  # instalado


def test_assistant_mcp_outside_catalog_default_enabled(tmp_path):
    """MCP fuera del catalogo (proyecto) siempre se considera activo."""
    config = tmp_path / ".mcp.json"
    config.write_text(
        '{"mcpServers": {"db": {"url": "https://mcp.internal/db"}}}', encoding="utf-8"
    )
    dist = AssistantParser().parse(config)
    assert dist is not None
    server = next(t for t in dist.tools if t.get("kind") == "mcp")
    assert server["enabled"] is True


def test_assistant_handles_jsonc_and_settings():
    assert AssistantParser.handles(Path("proj/opencode.jsonc")) is True
    assert AssistantParser.handles(Path(".claude/settings.json")) is True
    assert AssistantParser.handles(Path("src/opencode.json")) is True
    assert AssistantParser.handles(Path("proj/package.json")) is False


def test_detect_framework_assistant():
    paths = [Path("x/opencode/opencode.json"), Path("x/.claude/settings.json")]
    assert detect_framework(paths) == "assistant"
