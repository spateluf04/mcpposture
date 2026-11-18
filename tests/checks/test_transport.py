import pytest

from mcpposture.checks import transport as check
from mcpposture.model import Severity

from conftest import run_check, servers_from


def findings(entry):
    return run_check(check, servers=servers_from({"srv": entry}))


@pytest.mark.parametrize(
    "url",
    ["http://mcp.example.com/mcp", "HTTP://10.0.0.5:8080/mcp", "ws://mcp.example.com/socket", "http://host.docker.internal/mcp"],
)
def test_cleartext_remote(url):
    (f,) = findings({"type": "http", "url": url})
    assert (f.check_id, f.severity, f.location.pointer) == ("MP004", Severity.MEDIUM, "/mcpServers/srv/url")


def test_credentials_over_cleartext_are_high():
    (f,) = findings({"type": "http", "url": "http://mcp.example.com/mcp", "headers": {"Authorization": "Bearer ${T}"}})
    assert f.severity == Severity.HIGH


@pytest.mark.parametrize(
    "url",
    [
        "https://mcp.example.com/mcp",
        "wss://mcp.example.com/socket",
        "http://localhost:3000/mcp",
        "http://127.0.0.1:8080/mcp",
        "http://127.8.9.10/mcp",
        "http://[::1]:8080/mcp",
        "http://0.0.0.0:8080/mcp",
        "http://api.localhost/mcp",
        "${MCP_URL}",
        "http://[not-an-ip/",
    ],
)
def test_not_flagged(url):
    assert findings({"type": "http", "url": url}) == []


def test_stdio_ignored():
    assert findings({"command": "npx", "args": ["x"]}) == []
