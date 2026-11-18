from datetime import datetime, timezone
from pathlib import Path

from mcpposture.discovery.hostinfo import Host
from mcpposture.model import Finding, Inventory, Location, ScanIssue, ServerConfig, Severity
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
