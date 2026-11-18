import pytest

from mcpposture.checks import supply_chain as check
from mcpposture.model import Severity

from conftest import run_check, servers_from


def findings(entry):
    return run_check(check, servers=servers_from({"srv": entry}))


@pytest.mark.parametrize(
    "entry",
    [
        {"command": "npx", "args": ["-y", "@modelcontextprotocol/server-everything"]},
        {"command": "npx", "args": ["-y", "@playwright/mcp@latest"]},
        {"command": "cmd", "args": ["/c", "npx", "-y", "some-mcp"]},
        {"command": "uvx", "args": ["mcp-server-fetch"]},
        {"command": "pipx", "args": ["run", "some-mcp"]},
        {"command": "docker", "args": ["run", "-i", "--rm", "mcp/fetch"]},
    ],
)
def test_unpinned(entry):
    (f,) = findings(entry)
    assert (f.check_id, f.severity) == ("MP003", Severity.MEDIUM)
    assert f.cwe == ("CWE-494",) and f.owasp_llm == ("LLM03:2025",)


def test_pointer_targets_the_package_argument():
    (f,) = findings({"command": "cmd", "args": ["/c", "npx", "-y", "some-mcp"]})
    assert f.location.pointer == "/mcpServers/srv/args/3"


def test_container_tag_without_digest_is_low():
    (f,) = findings({"command": "docker", "args": ["run", "--rm", "mcp/fetch:1.2"]})
    assert f.severity == Severity.LOW


@pytest.mark.parametrize(
    "entry",
    [
        {"command": "npx", "args": ["-y", "@playwright/mcp@0.0.41"]},
        {"command": "uvx", "args": ["mcp-server-fetch==2025.4.7"]},
        {"command": "docker", "args": ["run", "mcp/fetch@sha256:" + "ab" * 32]},
        {"command": "node", "args": ["/opt/mcp/server.js"]},
        {"command": "npx", "args": ["./tools/local-server"]},
        {"type": "http", "url": "https://mcp.example.com/mcp"},
    ],
)
def test_pinned_or_not_downloaded(entry):
    assert findings(entry) == []
