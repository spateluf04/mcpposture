from mcpposture.checks import hardcoded_secrets as check
from mcpposture.model import Severity

from conftest import run_check, servers_from, settings_from

GH = "ghp_" + "FAKE0123456789abcdefghijklmnopqrstuv"
RANDOM = "Zx9Qw3Er7Ty1Ui5Op2As8Df4"


def findings(entry, **kw):
    return run_check(check, servers=servers_from({"srv": entry}, **kw))


def assert_redacted(found, secret):
    for f in found:
        assert secret not in f.evidence
        assert secret[:-4] not in f.evidence


def test_provider_token_in_env():
    (f,) = findings({"command": "x", "env": {"GITHUB_TOKEN": GH}})
    assert (f.check_id, f.severity, f.title) == ("MP002", Severity.HIGH, "Hardcoded github credential")
    assert f.location.pointer == "/mcpServers/srv/env/GITHUB_TOKEN"
    assert f.location.line is not None
    assert f.evidence == f"env GITHUB_TOKEN = [REDACTED github ...{GH[-4:]}]"
    assert f.cwe == ("CWE-798",)


def test_committed_project_file_raises_severity():
    (f,) = findings({"command": "x", "env": {"GITHUB_TOKEN": GH}}, scope="project")
    assert f.severity == Severity.CRITICAL


def test_entropy_and_named_secrets_are_medium():
    found = findings({"command": "x", "env": {"BLOB": RANDOM, "DB_PASSWORD": "correcthorse"}})
    assert sorted((f.location.pointer.rsplit("/", 1)[1], f.severity) for f in found) == [
        ("BLOB", Severity.MEDIUM),
        ("DB_PASSWORD", Severity.MEDIUM),
    ]
    assert_redacted(found, RANDOM)
    assert all("correcthorse" not in f.evidence for f in found)


def test_secret_in_header_args_url_and_command():
    found = findings(
        {
            "command": f"run-{GH}",
            "args": ["--api-key", "plainvalue1", f"--token={GH}", "--verbose"],
            "url": "https://user:" + "p4ssw0rdFAKE" + "@mcp.example.com/mcp",
            "headers": {"Authorization": f"Bearer {GH}"},
        }
    )
    assert sorted(f.location.pointer.split("/srv")[1] for f in found) == [
        "/args/1", "/args/2", "/command", "/headers/Authorization", "/url",
    ]
    assert_redacted(found, GH)
    assert all("plainvalue1" not in f.evidence and "p4ssw0rd" not in f.evidence for f in found)


def test_references_and_ordinary_values_are_clean():
    assert findings(
        {
            "command": "npx",
            "args": ["-y", "@modelcontextprotocol/server-github", "--token", "${GITHUB_TOKEN}"],
            "env": {"GITHUB_PERSONAL_ACCESS_TOKEN": "${env:GITHUB_TOKEN}", "PORT": "8080", "LOG_LEVEL": "debug"},
            "headers": {"Authorization": "Bearer ${input:token}"},
            "url": "https://mcp.example.com/mcp?region=us",
        }
    ) == []


def test_settings_env_block():
    doc = settings_from({"env": {"ANTHROPIC_API_KEY": "sk-ant-api03-" + "FAKEkey0123456789abcdEXAMPLE", "DEBUG": "1"}})
    (f,) = run_check(check, settings=[doc])
    assert f.location.pointer == "/env/ANTHROPIC_API_KEY"
    assert "FAKEkey" not in f.evidence
