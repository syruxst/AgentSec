"""Tests del motor de reglas sobre distribuciones construidas a mano."""

from agentsec.models import Distribution
from agentsec.rules import RuleEngine, load_rules


def _dist(
    tools=None,
    agents=None,
    sources=None,
    memory=None,
    credentials=None,
    dependencies=None,
    framework="langchain",
):
    return Distribution(
        framework=framework,
        path="test.yaml",
        tools=tools or [],
        agents=agents or [],
        sources=sources or [],
        memory=memory or [],
        credentials=credentials or [],
        dependencies=dependencies or [],
    )


def test_rules_loaded():
    rules = load_rules()
    assert len(rules) >= 15
    ids = {r.id for r in rules}
    assert {"AS-101", "AS-102", "AS-103", "AS-104", "AS-110", "AS-201", "AS-206"} <= ids


def test_as101_shell_tool():
    engine = RuleEngine()
    dist = _dist(tools=[{"name": "RunShellTool"}])
    findings = engine.evaluate_distribution(dist)
    assert any(f.rule_id == "AS-101" for f in findings)


def test_as102_load_all():
    engine = RuleEngine()
    dist = _dist(tools=[{"name": "load_all_tools"}])
    findings = engine.evaluate_distribution(dist)
    assert any(f.rule_id == "AS-102" for f in findings)


def test_as103_file_without_allowlist():
    engine = RuleEngine()
    dist = _dist(tools=[{"name": "read_file_handler"}])
    findings = engine.evaluate_distribution(dist)
    assert any(f.rule_id == "AS-103" for f in findings)


def test_as103_clean_file_with_allowlist():
    engine = RuleEngine()
    dist = _dist(tools=[{"name": "read_file_handler", "allowed_paths": ["/srv"]}])
    findings = engine.evaluate_distribution(dist)
    assert not any(f.rule_id == "AS-103" for f in findings)


def test_as104_literal_secret():
    engine = RuleEngine()
    dist = _dist(credentials=[{"key": "api_key", "value_preview": "sk-literal"}])
    findings = engine.evaluate_distribution(dist)
    assert any(f.rule_id == "AS-104" for f in findings)


def test_as104_env_secret_clean():
    engine = RuleEngine()
    dist = _dist(credentials=[{"key": "api_key", "value_preview": "${OPENAI_API_KEY}"}])
    findings = engine.evaluate_distribution(dist)
    assert not any(f.rule_id == "AS-104" for f in findings)


def test_as101_shell_tool_sandboxed_clean():
    engine = RuleEngine()
    dist = _dist(tools=[{"name": "RunShellSafe", "sandbox": True, "allowed_commands": ["ls"]}])
    findings = engine.evaluate_distribution(dist)
    assert not any(f.rule_id == "AS-101" for f in findings)


def test_as101_shell_tool_allowed_commands_clean():
    engine = RuleEngine()
    dist = _dist(tools=[{"name": "bash_wrapper", "allowed_commands": ["cat", "grep"]}])
    findings = engine.evaluate_distribution(dist)
    assert not any(f.rule_id == "AS-101" for f in findings)


def test_as109_production_partial_scope():
    # Falta permissions aunque scopes exista: debe detectarse.
    engine = RuleEngine()
    dist = _dist(tools=[{"name": "api", "scopes": ["read"], "environment": "production"}])
    findings = engine.evaluate_distribution(dist)
    assert any(f.rule_id == "AS-109" for f in findings)


def test_as109_production_full_controls_clean():
    engine = RuleEngine()
    dist = _dist(
        tools=[
            {
                "name": "api",
                "scopes": ["read"],
                "permissions": ["read"],
                "environment": "production",
            }
        ]
    )
    findings = engine.evaluate_distribution(dist)
    assert not any(f.rule_id == "AS-109" for f in findings)


def test_as106_source_without_sanitize():
    engine = RuleEngine()
    dist = _dist(sources=[{"loader": "UnstructuredMarkdownLoader"}])
    findings = engine.evaluate_distribution(dist)
    assert any(f.rule_id == "AS-106" for f in findings)


def test_as106_sanitized_clean():
    engine = RuleEngine()
    dist = _dist(sources=[{"loader": "TextLoader", "sanitize": True}])
    findings = engine.evaluate_distribution(dist)
    assert not any(f.rule_id == "AS-106" for f in findings)


def test_as109_scoped_clean():
    engine = RuleEngine()
    dist = _dist(
        tools=[
            {"name": "api", "scopes": ["read"], "permissions": ["read"], "environment": "staging"}
        ]
    )
    findings = engine.evaluate_distribution(dist)
    assert not any(f.rule_id == "AS-109" for f in findings)


def test_as110_delegation_no_trust():
    engine = RuleEngine()
    dist = _dist(agents=[{"name": "a", "allow_delegation": True}], framework="crewai")
    findings = engine.evaluate_distribution(dist)
    assert any(f.rule_id == "AS-110" for f in findings)


def test_as110_delegation_off_clean():
    engine = RuleEngine()
    dist = _dist(agents=[{"name": "a", "allow_delegation": False, "trust_origin": True}])
    findings = engine.evaluate_distribution(dist)
    assert not any(f.rule_id == "AS-110" for f in findings)


def test_rule_frameworks_populated():
    engine = RuleEngine()
    assert all(engine.rules)


def test_framework_filter_applies():
    # Una distribucion de tipo langchain solo recibe reglas que la cubren.
    engine = RuleEngine()
    dist = _dist(tools=[{"name": "RunShellTool"}], framework="langchain")
    findings = engine.evaluate_distribution(dist)
    ids = {f.rule_id for f in findings}
    assert all(next(r for r in engine.rules if r.id == i).applies_to("langchain") for i in ids)


def test_as201_shell_permission():
    engine = RuleEngine()
    dist = _dist(
        tools=[{"name": "bash:*", "grant": "allow", "kind": "permission"}],
        framework="assistant",
    )
    findings = engine.evaluate_distribution(dist)
    assert any(f.rule_id == "AS-201" for f in findings)


def test_as201_shell_denied_clean():
    engine = RuleEngine()
    dist = _dist(
        tools=[{"name": "bash:rm", "grant": "deny", "kind": "permission"}],
        framework="assistant",
    )
    findings = engine.evaluate_distribution(dist)
    assert not any(f.rule_id == "AS-201" for f in findings)


def test_as203_remote_mcp():
    engine = RuleEngine()
    dist = _dist(
        tools=[
            {"name": "gitlab", "kind": "mcp", "url": "https://mcp.example.com", "enabled": True}
        ],
        framework="assistant",
    )
    findings = engine.evaluate_distribution(dist)
    assert any(f.rule_id == "AS-203" for f in findings)


def test_as203_verified_mcp_clean():
    engine = RuleEngine()
    dist = _dist(
        tools=[
            {
                "name": "gitlab",
                "kind": "mcp",
                "url": "https://mcp.example.com",
                "verified": True,
                "enabled": True,
            }
        ],
        framework="assistant",
    )
    findings = engine.evaluate_distribution(dist)
    assert not any(f.rule_id == "AS-203" for f in findings)


def test_as203_disabled_catalog_mcp_clean():
    """MCP declarado pero plugin NO habilitado: no debe señalarse."""
    engine = RuleEngine()
    dist = _dist(
        tools=[
            {
                "name": "context7",
                "kind": "mcp",
                "url": "https://mcp.context7.com/mcp",
                "enabled": False,
            }
        ],
        framework="assistant",
    )
    findings = engine.evaluate_distribution(dist)
    assert not any(f.rule_id == "AS-203" for f in findings)


def test_as204_mcp_env_credentials():
    engine = RuleEngine()
    dist = _dist(
        tools=[
            {
                "name": "github",
                "kind": "mcp",
                "env": ["GITHUB_TOKEN=ghp_literal123"],
                "enabled": True,
            }
        ],
        framework="assistant",
    )
    findings = engine.evaluate_distribution(dist)
    assert any(f.rule_id == "AS-204" for f in findings)


def test_as204_mcp_env_ref_clean():
    engine = RuleEngine()
    dist = _dist(
        tools=[
            {
                "name": "github",
                "kind": "mcp",
                "env": ["GITHUB_TOKEN=env:GITHUB_TOKEN"],
                "enabled": True,
            }
        ],
        framework="assistant",
    )
    findings = engine.evaluate_distribution(dist)
    assert not any(f.rule_id == "AS-204" for f in findings)


def test_as206_literal_secret():
    engine = RuleEngine()
    dist = _dist(
        credentials=[{"key": "mcpServers.github.env.GITHUB_TOKEN", "value_preview": "ghp_1234..."}],
        framework="assistant",
    )
    findings = engine.evaluate_distribution(dist)
    assert any(f.rule_id == "AS-206" for f in findings)
