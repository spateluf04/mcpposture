from pathlib import Path

from mcpposture.checks import run_all
from mcpposture.discovery.hostinfo import Host, current_os
from mcpposture.discovery.inventory import scan_path
from mcpposture.model import Severity

from conftest import write

FETCH = {"command": "uvx", "args": ["mcp-server-fetch==2025.4.7"]}
FS = {"command": "npx", "args": ["-y", "@modelcontextprotocol/server-filesystem@2025.8.21", "/work/app"]}
TIME = {"command": "uvx", "args": ["mcp-server-time==2025.1.1"]}
HOST = Host(os=current_os(), is_wsl=False, home=Path("/nonexistent"))


def rule_of_two(tmp_path, files):
    for rel, content in files.items():
        write(tmp_path / rel, content)
    inv = scan_path(tmp_path, HOST)
    return [f for f in run_all(inv, [tmp_path]) if f.check_id == "MP001"], inv


def test_two_servers_completing_the_trifecta(tmp_path):
    (f,), _ = rule_of_two(tmp_path, {".mcp.json": {"mcpServers": {"web": FETCH, "files": FS, "clock": TIME}}})
    assert f.severity == Severity.HIGH
    assert f.evidence == "[A] untrusted input: web; [B] private data: files; [C] external actions: files, web"
    assert f.context_id.startswith("claude-code:project:")
    assert f.cwe == ("CWE-1427",) and "LLM01:2025" in f.owasp_llm


def test_single_server_with_all_three(tmp_path):
    (f,), _ = rule_of_two(tmp_path, {".mcp.json": {"mcpServers": {"gh": {"type": "http", "url": "https://api.githubcopilot.com/mcp/"}}}})
    assert f.server == "gh"


def test_two_of_three_is_fine(tmp_path):
    found, inv = rule_of_two(tmp_path, {".mcp.json": {"mcpServers": {"files": FS, "clock": TIME}}})
    assert found == []


def test_servers_in_different_clients_do_not_combine(tmp_path):
    found, _ = rule_of_two(
        tmp_path,
        {".mcp.json": {"mcpServers": {"web": FETCH}}, ".cursor/mcp.json": {"mcpServers": {"files": FS}}},
    )
    assert found == []


def test_unclassified_server_reported_as_incomplete(tmp_path):
    (f,), _ = rule_of_two(tmp_path, {".mcp.json": {"mcpServers": {"files": FS, "mystery": {"command": "/opt/acme/widget"}}}})
    assert f.severity == Severity.INFO
    assert f.evidence == "unclassified: mystery"


def test_heuristic_only_capability_lowers_severity(tmp_path):
    guessed = {"command": "node", "args": ["/opt/tools/scraper/index.js"]}
    (f,), _ = rule_of_two(tmp_path, {".mcp.json": {"mcpServers": {"scrape": guessed, "files": FS}}})
    assert f.severity == Severity.MEDIUM


def test_inherited_user_servers_reported_once(tmp_path):
    host_home = tmp_path / "home"
    write(host_home / ".claude.json", {
        "mcpServers": {"web": FETCH, "files": FS},
        "projects": {str(tmp_path / "p1"): {}, str(tmp_path / "p2"): {}},
    })
    write(tmp_path / "p1" / ".mcp.json", {"mcpServers": {"clock": TIME}})
    write(tmp_path / "p2" / ".mcp.json", {"mcpServers": {"clock2": TIME}})
    inv = scan_path(tmp_path, HOST)
    found = [f for f in run_all(inv, [tmp_path]) if f.check_id == "MP001"]
    assert len(found) == 1
    assert found[0].evidence.endswith("(in 3 agent contexts)")


def test_report_exposes_context_status(tmp_path, capsys):
    import json

    from mcpposture import cli

    write(tmp_path / ".mcp.json", {"mcpServers": {"web": FETCH, "files": FS}})
    cli.main(["scan", "--path", str(tmp_path), "--format", "json"])
    report = json.loads(capsys.readouterr().out)
    (ctx,) = report["contexts"]
    assert (ctx["capabilities"], ctx["rule_of_two"]) == (["A", "B", "C"], "violation")
    assert {s["name"]: s["capabilities"]["flags"] for s in report["servers"]} == {"web": ["A", "C"], "files": ["B", "C"]}
    assert report["tool"]["rules_version"]
