from datetime import datetime, timezone
from pathlib import Path

from mcpposture.discovery.hostinfo import Host
from mcpposture.model import AgentContext, Classification, Finding, Inventory, Location, ScanIssue, ServerConfig, Severity
from mcpposture.report import text
from mcpposture.report.jsonfmt import build_report


def make_report(inv, findings=()):
    return build_report(
        inv,
        list(findings),
        host=Host(os="macos", is_wsl=False, home=Path("/h"), hostname="mac"),
        mode="local",
        target=None,
        started_at=datetime(2026, 11, 18, tzinfo=timezone.utc),
        fail_on=Severity.HIGH,
    )


def finding(sev, title):
    return Finding("AP000", sev, title, "why it matters", "how to fix", ("CWE-1",), ("LLM01:2025",), "cursor", Location(Path("/f"), "/p", 3), "", "fp")


def test_clean_escapes_terminal_control_and_bidi():
    assert text.clean("a\x1b[31mb‮c\nd") == "a\\u001b[31mb\\u202ec\\u000ad"


def test_render_never_emits_raw_control_characters():
    srv = ServerConfig("id", "evil\x1b]0;pwned\x07", "cursor", "user", Location(Path("/f")), None, "stdio", command="x\x1b[2J")
    inv = Inventory(servers=[srv], issues=[ScanIssue(Path("/f"), "parse_error", "bad \x1b[1m char")])
    out = text.render(make_report(inv))
    assert "\x1b" not in out and "\x07" not in out


def test_findings_grouped_by_severity_highest_first():
    out = text.render(make_report(Inventory(), [finding(Severity.LOW, "low one"), finding(Severity.CRITICAL, "crit one")]))
    assert out.index("CRITICAL (1)") < out.index("LOW (1)")
    assert "why it matters" in out and "how to fix" in out


def test_no_findings_message():
    assert "Findings: none" in text.render(make_report(Inventory()))


def summary_of(out):
    return out[out.index("Summary"):out.index("Findings: none") if "Findings: none" in out else out.index("Details for each")]


def test_summary_lists_each_server_with_its_worst_problem():
    bad = ServerConfig("1", "bad", "vscode", "user", Location(Path("/f"), "/servers/bad"), None, "stdio", command="x")
    good = ServerConfig("2", "good", "cursor", "user", Location(Path("/g"), "/mcpServers/good"), None, "stdio", command="y")
    inv = Inventory(servers=[good, bad])
    inv.capabilities["2"] = Classification(frozenset({"A"}), "rule")
    on_bad = [
        Finding("MP003", Severity.MEDIUM, "Unpinned server package", "w", "r", (), (), "vscode", Location(Path("/f"), "/servers/bad/args/0"), "", "a", server="bad"),
        Finding("MP005", Severity.HIGH, "Too much disk", "w", "r", (), (), "vscode", Location(Path("/f"), "/servers/bad/args/1"), "", "b", server="bad"),
    ]
    summary = summary_of(text.render(make_report(inv, on_bad)))
    assert "2 MCP servers: 1 needs attention" in summary
    assert summary.index("HIGH     bad") < summary.index("ok       good")
    assert "VS Code (user)" in summary and "Too much disk (+1 more)" in summary


def test_summary_marks_unclassified_servers_unknown_not_ok():
    srv = ServerConfig("1", "mystery", "cursor", "user", Location(Path("/f"), "/mcpServers/mystery"), None, "stdio", command="x")
    summary = summary_of(text.render(make_report(Inventory(servers=[srv]))))
    assert "unknown  mystery" in summary


def test_summary_separates_settings_and_combinations():
    a = ServerConfig("1", "reader", "claude-code", "user", Location(Path("/c"), "/mcpServers/reader"), None, "stdio", command="x")
    inv = Inventory(servers=[a], contexts=[AgentContext("claude-code:user", "claude-code", None, ("1",))])
    inv.capabilities["1"] = Classification(frozenset({"A", "B", "C"}), "rule")
    combo = Finding("MP001", Severity.HIGH, "combo", "w", "r", (), (), "claude-code", Location(Path("/c"), "/mcpServers/reader"), "", "c", server="reader", context_id="claude-code:user")
    setting = finding(Severity.MEDIUM, "Every shell command is pre-approved")
    summary = summary_of(text.render(make_report(inv, [combo, setting])))
    assert "1 risky combination" in summary and "HIGH     Claude Code: reader" in summary
    assert "ok       reader" in summary
    assert "1 other setting needs attention" in summary and "Every shell command is pre-approved" in summary
