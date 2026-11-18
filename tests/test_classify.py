import time

import pytest

from mcpposture.classify import RulesError, classify, default_rules, normalise_oci, parse_rules

from conftest import servers_from

RULES = default_rules()


def cls(entry, name="srv"):
    (s,) = servers_from({name: entry})
    return classify(s, RULES)


def test_shipped_rules_load():
    assert RULES.version
    assert len(RULES.servers) > 10 and len(RULES.heuristics) > 5


@pytest.mark.parametrize(
    ("entry", "rule", "flags"),
    [
        ({"command": "npx", "args": ["-y", "@modelcontextprotocol/server-filesystem@2025.8.21", "/p"]}, "mcp-filesystem", "BC"),
        ({"command": "uvx", "args": ["MCP_Server.Fetch==2025.4.7"]}, "mcp-fetch", "AC"),
        ({"command": "docker", "args": ["run", "-i", "--rm", "docker.io/mcp/fetch:latest"]}, "mcp-fetch", "AC"),
        ({"command": "docker", "args": ["run", "ghcr.io/github/github-mcp-server@sha256:" + "a" * 64]}, "github", "ABC"),
        ({"type": "http", "url": "https://api.githubcopilot.com/mcp/"}, "github", "ABC"),
        ({"type": "http", "url": "https://MCP.Context7.com/mcp"}, "context7", "A"),
        ({"command": "cmd", "args": ["/c", "npx", "-y", "@playwright/mcp@latest"]}, "playwright", "AC"),
        ({"command": "uvx", "args": ["mcp-server-time"]}, "mcp-time", ""),
        ({"command": "npx", "args": ["-y", "@modelcontextprotocol/server-brave-search"]}, "mcp-brave-search", "A"),
    ],
)
def test_exact_rules(entry, rule, flags):
    c = cls(entry)
    assert (c.source, c.rule_ids, "".join(sorted(c.flags))) == ("rule", (rule,), flags)


def test_heuristics_union_and_label():
    c = cls({"command": "node", "args": ["/opt/gmail-and-search-bridge/index.js"]}, name="mail")
    assert c.source == "heuristic"
    assert set(c.rule_ids) == {"email", "web-search"}
    assert c.flags == {"A", "B", "C"}


def test_unknown_server_is_unclassified_not_safe():
    c = cls({"command": "/opt/acme/bin/widget-mcp"}, name="widget")
    assert (c.source, c.flags) == ("unclassified", frozenset())


def test_huge_arguments_are_bounded():
    start = time.perf_counter()
    cls({"command": "x", "args": ["a" * 200_000] * 20})
    assert time.perf_counter() - start < 1.0


def test_normalise_oci():
    assert normalise_oci("docker.io/library/redis:7") == "redis"
    assert normalise_oci("registry:5000/Team/img:1.0@sha256:abc") == "registry:5000/team/img"


VALID = """
schema_version = 1
rules_version = "t"
[[server]]
id = "x"
npm = ["x"]
capabilities = ["A"]
"""


@pytest.mark.parametrize(
    ("text", "message"),
    [
        ("not = [toml", "invalid TOML"),
        (VALID.replace("schema_version = 1", "schema_version = 2"), "schema_version"),
        (VALID.replace('rules_version = "t"', ""), "rules_version"),
        ("extra = 1\n" + VALID, "unknown top-level key"),
        (VALID.replace('capabilities = ["A"]', 'capabilities = ["D"]'), "unknown capability"),
        (VALID.replace('capabilities = ["A"]', ""), "capabilities is required"),
        (VALID.replace('npm = ["x"]', 'npm = "x"'), "must be a list"),
        (VALID.replace('npm = ["x"]', ""), "needs at least one of"),
        (VALID.replace('npm = ["x"]', 'npm = ["x"]\ncolour = "red"'), "unknown key"),
        (VALID + '\n[[server]]\nid = "x"\nnpm = ["y"]\ncapabilities = []', "duplicate id"),
        (VALID + '\n[[heuristic]]\nid = "h"\npattern = "("\ncapabilities = []', "invalid pattern"),
    ],
)
def test_rules_validation(text, message):
    with pytest.raises(RulesError, match=message):
        parse_rules(text)
