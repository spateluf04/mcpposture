import hashlib
from pathlib import Path

import pytest

from mcpposture import policy
from mcpposture.model import Inventory, Location, Finding, Severity
from mcpposture.policy import evaluate, parse

from conftest import servers_from

EXAMPLE = Path(__file__).resolve().parents[1] / "examples" / "policy.toml"
D64 = "ab" * 32


def ok(text):
    pol, problems = parse(text)
    assert pol is not None, problems
    return pol, problems


def errors_of(text):
    pol, problems = parse(text)
    assert pol is None
    return [p.message for p in problems if p.level == "error"]


HEAD = "schema_version = 1\nrequire_approved = true\n"


def test_example_policy_is_valid():
    pol, problems = ok(EXAMPLE.read_text(encoding="utf-8"))
    assert problems == []
    assert pol.max_severity == Severity.MEDIUM and pol.require_approved
    assert len(pol.approved) == 5 and len(pol.banned) == 2


@pytest.mark.parametrize(
    ("body", "message"),
    [
        ("schema_version = 2\nmax_severity = 'high'", "must be 1"),
        (HEAD + "colour = 'red'", "unknown top-level key"),
        (HEAD + "max_severity = 'severe'", "must be one of"),
        ("schema_version = 1\nrequire_approved = 'yes'", "true or false"),
        (HEAD + "approved = 'x'", "array of tables"),
        (HEAD + "[[approved]]\nnpm = 'pkg'", "must pin a version"),
        (HEAD + "[[approved]]\nnpm = 'pkg'\nversion = '^1.2.0'", "range or tag"),
        (HEAD + "[[approved]]\nnpm = 'pkg'\nversion = 'latest'\n", "range or tag"),
        (HEAD + "[[approved]]\npypi = 'pkg'\nversion = '>=1.0'", "range or tag"),
        (HEAD + "[[approved]]\noci = 'img'\ndigest = 'sha256:abc'", "digest must look like"),
        (HEAD + "[[approved]]\noci = 'img'", "must pin a digest"),
        (HEAD + f"[[approved]]\ncommand = 'bin/server'\nsha256 = '{D64}'", "absolute path"),
        (HEAD + "[[approved]]\ncommand = '/opt/x'", "must pin a sha256"),
        (HEAD + "[[approved]]\nurl = 'http://mcp.example.com/mcp'", "https:// or wss://"),
        (HEAD + "[[approved]]\nurl = 'https://mcp.example.com/mcp'\nversion = '1.0.0'", "does not apply"),
        (HEAD + "[[approved]]\nnpm = 'a'\npypi = 'b'\nversion = '1.0.0'", "exactly one of"),
        (HEAD + "[[approved]]\nnpm = 'a'\nversion = 1", "non-empty string"),
        (HEAD + "[[banned]]\nnpm = 'a'\nversion = '1.0.0'", "a ban covers every version"),
        (HEAD + "[[approved]]\nnpm = 'a'\nversion = '1.0.0'\n[[banned]]\nnpm = 'A'", "also banned"),
        ("not toml = = =", "invalid TOML"),
    ],
)
def test_validation_errors(body, message):
    assert any(message in m for m in errors_of(body)), errors_of(body)


def test_validation_warnings():
    _, problems = ok(HEAD + "[[approved]]\nnpm = 'a'\nversion = '1.0.0'\n[[approved]]\nnpm = 'a'\nversion = '1.0.0'")
    assert [p.message for p in problems] == ["duplicates approved[0]"]
    _, problems = ok(HEAD)
    assert "every server will violate" in problems[0].message
    _, problems = ok("schema_version = 1")
    assert "enforces nothing" in problems[0].message


def test_loopback_http_url_may_be_approved():
    ok(HEAD + "[[approved]]\nurl = 'http://localhost:3000/mcp'")


def run(pol_text, entries, findings=()):
    pol, _ = ok(pol_text)
    inv = Inventory(servers=servers_from(entries))
    return evaluate(pol, inv, list(findings))


APPROVE_FS = HEAD + "[[approved]]\nnpm = '@modelcontextprotocol/server-filesystem'\nversion = '2025.8.21'\n"


def fs(spec):
    return {"command": "npx", "args": ["-y", spec, "/work"]}


def test_approved_exact_version_passes():
    assert run(APPROVE_FS, {"files": fs("@modelcontextprotocol/server-filesystem@2025.8.21")}).compliant


@pytest.mark.parametrize("spec", ["@modelcontextprotocol/server-filesystem", "@modelcontextprotocol/server-filesystem@latest", "@modelcontextprotocol/server-filesystem@2025.9.1"])
def test_unpinned_or_other_version_is_not_approved(spec):
    result = run(APPROVE_FS, {"files": fs(spec)})
    (f,) = result.findings
    assert (f.check_id, f.severity) == ("MP008", Severity.HIGH)
    assert not result.compliant and result.violations[0][1] == "not_approved"


def test_name_in_config_proves_nothing():
    (f,) = run(APPROVE_FS, {"filesystem": {"command": "npx", "args": ["-y", "@evil/server-filesystem@2025.8.21"]}}).findings
    assert "@evil/server-filesystem" in f.evidence


@pytest.mark.parametrize(
    ("entry_toml", "server"),
    [
        ("pypi = 'MCP_server_fetch'\nversion = '2025.4.7'", {"command": "uvx", "args": ["mcp-server-fetch==2025.4.7"]}),
        (f"oci = 'docker.io/mcp/fetch'\ndigest = 'sha256:{D64}'", {"command": "docker", "args": ["run", "-i", f"mcp/fetch@sha256:{D64}"]}),
        ("url = 'https://MCP.example.com/mcp/'", {"type": "http", "url": "https://mcp.example.com/mcp"}),
    ],
)
def test_other_identity_kinds(entry_toml, server):
    assert run(HEAD + "[[approved]]\n" + entry_toml, {"s": server}).compliant


def test_command_hash(tmp_path):
    binary = tmp_path / "internal-mcp"
    binary.write_bytes(b"#!/bin/sh\necho fake server\n")
    good = hashlib.sha256(binary.read_bytes()).hexdigest()
    entry = {"s": {"command": str(binary)}}
    path = str(binary).replace("\\", "\\\\")
    assert run(HEAD + f"[[approved]]\ncommand = '{binary}'\nsha256 = '{good}'", entry).compliant
    assert not run(HEAD + f"[[approved]]\ncommand = '{binary}'\nsha256 = '{D64}'", entry).compliant
    binary.write_bytes(b"tampered")
    assert not run(HEAD + f"[[approved]]\ncommand = '{binary}'\nsha256 = '{good}'", entry).compliant
    del path


def test_interpreter_script_is_what_gets_approved(tmp_path):
    script = tmp_path / "server.js"
    script.write_text("console.log(1)")
    digest = hashlib.sha256(script.read_bytes()).hexdigest()
    assert run(HEAD + f"[[approved]]\ncommand = '{script}'\nsha256 = '{digest}'", {"s": {"command": "node", "args": [str(script)]}}).compliant


def test_banned_is_critical_even_without_require_approved():
    text = "schema_version = 1\n[[banned]]\nnpm = '@example/bad'\nreason = 'stole tokens'\n[[banned]]\nurl = 'https://evil.example.com/*'"
    result = run(text, {"a": {"command": "npx", "args": ["@example/bad@1.0.0"]}, "b": {"type": "http", "url": "https://evil.example.com/v2/mcp"}, "c": {"command": "npx", "args": ["fine"]}})
    assert [(f.server, f.severity) for f in result.findings] == [("a", Severity.CRITICAL), ("b", Severity.CRITICAL)]
    assert "stole tokens" in result.findings[0].evidence
    assert {r for _, r in result.violations} == {"banned"}


def test_max_severity_turns_findings_into_violations():
    def finding(sev):
        return Finding("MP003", sev, "t", "w", "r", (), (), "cursor", Location(Path("/x")), "", f"fp{sev}")

    result = run("schema_version = 1\nmax_severity = 'medium'", {}, [finding(Severity.MEDIUM), finding(Severity.HIGH)])
    assert [(f.severity, r) for f, r in result.violations] == [(Severity.HIGH, "above_max_severity")]


def test_load_rejects_invalid_file(tmp_path):
    p = tmp_path / "p.toml"
    p.write_text("schema_version = 9")
    with pytest.raises(policy.PolicyError):
        policy.load(p)
