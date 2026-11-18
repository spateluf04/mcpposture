import json
from pathlib import Path

import pytest

from mcpposture.discovery.parsers import MAX_SERVERS_PER_MAP, PARSERS, FileContext
from mcpposture.jsonc import loads


def parse(fmt, content, *, client="cursor", scope="user", project=None):
    text = content if isinstance(content, str) else json.dumps(content, indent=2)
    return PARSERS[fmt](loads(text), FileContext(Path("/cfg/file.json"), client, scope, project))


def test_stdio_server():
    out = parse("mcp_servers", {"mcpServers": {"fs": {"command": "npx", "args": ["-y", "pkg", 3], "env": {"A": "1", "N": 2}}}})
    (s,) = out.servers
    assert (s.name, s.transport, s.command, s.args) == ("fs", "stdio", "npx", ("-y", "pkg", "3"))
    assert dict(s.env) == {"A": "1", "N": "2"}
    assert s.location.pointer == "/mcpServers/fs"
    assert s.location.line == 3
    assert out.issues == []


@pytest.mark.parametrize(
    ("entry", "transport"),
    [
        ({"type": "http", "url": "https://x"}, "http"),
        ({"type": "streamable-http", "url": "https://x"}, "http"),
        ({"type": "SSE", "url": "https://x"}, "sse"),
        ({"type": "ws", "url": "wss://x"}, "ws"),
        ({"url": "https://x"}, "http"),
        ({}, "unknown"),
    ],
)
def test_transport_inference(entry, transport):
    (s,) = parse("mcp_servers", {"mcpServers": {"s": entry}}).servers
    assert s.transport == transport


def test_unknown_transport_type_is_an_issue():
    out = parse("mcp_servers", {"mcpServers": {"s": {"type": "carrier-pigeon"}}})
    assert out.servers[0].transport == "unknown"
    assert [i.kind for i in out.issues] == ["invalid_entry"]


def test_headers_and_env_file():
    (s,) = parse("mcp_servers", {"mcpServers": {"s": {"url": "https://x", "headers": {"Authorization": "Bearer ${T}"}, "envFile": ".env"}}}).servers
    assert dict(s.headers) == {"Authorization": "Bearer ${T}"}
    assert s.env_file == ".env"


def test_vscode_format_uses_servers_key():
    out = parse("vscode_servers", {"servers": {"a": {"command": "x"}}, "mcpServers": {"b": {"command": "y"}}}, client="vscode")
    assert [s.name for s in out.servers] == ["a"]


def test_jsonc_vscode_file():
    out = parse("vscode_servers", '{\n // comment\n "servers": {"a": {"command": "x",},},\n}', client="vscode")
    assert [s.name for s in out.servers] == ["a"]


def test_claude_json_user_and_local_scopes():
    out = parse(
        "claude_json",
        {
            "oauthAccount": {"emailAddress": "someone@example.com"},
            "mcpServers": {"u": {"command": "a"}},
            "projects": {"/work/p": {"mcpServers": {"l": {"url": "https://x"}}}, "/work/q": "garbage"},
        },
        client="claude-code",
    )
    assert [(s.name, s.scope, s.project) for s in out.servers] == [("u", "user", None), ("l", "local", "/work/p")]
    assert out.project_keys == ["/work/p", "/work/q"]
    assert out.servers[1].location.pointer == "/projects/~1work~1p/mcpServers/l"


@pytest.mark.parametrize(
    "doc",
    [
        "[1, 2]",
        '"just a string"',
        '{"mcpServers": "nope"}',
        '{"mcpServers": {"s": 5}}',
        '{"mcpServers": {"s": {"command": ["not", "a", "string"]}}}',
        '{"mcpServers": {"s": {"command": "x", "args": "not-a-list"}}}',
        '{"mcpServers": {"s": {"command": "x", "args": [{"o": 1}, null, true]}}}',
        '{"mcpServers": {"s": {"command": "x", "env": {"A": {"nested": 1}}}}}',
        '{"mcpServers": {"s": {"command": "x", "headers": []}}}',
    ],
)
def test_hostile_shapes_become_issues_not_crashes(doc):
    out = parse("mcp_servers", doc)
    assert out.issues
    for s in out.servers:
        assert all(isinstance(a, str) for a in s.args)
        assert all(isinstance(v, str) for v in s.env.values())


def test_server_count_is_capped():
    servers = {f"s{i}": {"command": "x"} for i in range(MAX_SERVERS_PER_MAP + 5)}
    out = parse("mcp_servers", {"mcpServers": servers})
    assert len(out.servers) == MAX_SERVERS_PER_MAP
    assert any("ignored" in i.detail for i in out.issues)


def test_settings_doc():
    out = parse("claude_settings", {"permissions": {"allow": ["Bash"]}}, client="claude-code")
    assert out.settings.data == {"permissions": {"allow": ["Bash"]}}
    assert out.servers == []


def test_managed_mcp_servers_only_from_managed_settings():
    doc = {"managedMcpServers": {"corp": {"type": "http", "url": "https://corp.example/mcp"}}}
    assert [s.name for s in parse("claude_settings", doc, client="claude-code", scope="managed").servers] == ["corp"]
    assert parse("claude_settings", doc, client="claude-code", scope="user").servers == []


def test_legacy_vscode_settings_mcp_key():
    out = parse("vscode_settings", {"mcp": {"servers": {"old": {"command": "x"}}}, "editor.fontSize": 14}, client="vscode")
    assert [(s.name, s.location.pointer) for s in out.servers] == [("old", "/mcp/servers/old")]
    assert parse("claude_settings", {"mcp": {"servers": {"old": {"command": "x"}}}}, client="claude-code").servers == []


def test_auto_format_sniffs_key():
    assert [s.name for s in parse("auto", {"servers": {"a": {"command": "x"}}}).servers] == ["a"]
    assert [s.name for s in parse("auto", {"mcpServers": {"b": {"command": "x"}}}).servers] == ["b"]
