import json
from datetime import datetime, timezone
from pathlib import Path

from mcpposture.discovery.hostinfo import Host
from mcpposture.model import Finding, Inventory, Location, ServerConfig, Severity
from mcpposture.report.jsonfmt import SCHEMA_VERSION, build_report, render

HOST = Host(os="linux", is_wsl=True, home=Path("/h"), hostname="box")
SECRET = "sk-ant-api03-" + "FAKEkey0123456789abcdEXAMPLE"
PLAIN = "hunter2" + "plain"


def server(**kw):
    base = dict(
        id="abc",
        name="s",
        client="cursor",
        scope="user",
        location=Location(Path("/h/.cursor/mcp.json"), "/mcpServers/s", 4),
        project=None,
        transport="stdio",
        command="npx",
    )
    base.update(kw)
    return ServerConfig(**base)


def finding(sev, check="AP000"):
    return Finding(
        check_id=check,
        severity=sev,
        title="t",
        why="w",
        remediation="r",
        cwe=("CWE-798",),
        owasp_llm=("LLM02:2025",),
        client="cursor",
        location=Location(Path("/x"), "/p", 1),
        evidence="e",
        fingerprint="f",
    )


def report(inv, findings=()):
    return build_report(
        inv,
        list(findings),
        host=HOST,
        mode="local",
        target=None,
        started_at=datetime(2026, 11, 18, tzinfo=timezone.utc),
        fail_on=Severity.HIGH,
    )


def test_schema_shape():
    r = report(Inventory(servers=[server()]))
    assert r["schema_version"] == SCHEMA_VERSION
    assert set(r) == {"schema_version", "tool", "machine", "scan", "summary", "findings", "servers", "contexts", "files", "scan_issues"}
    assert r["machine"] == {"hostname": "box", "os": "linux", "wsl": True}
    assert r["servers"][0]["source"] == {"path": str(Path("/h/.cursor/mcp.json")), "pointer": "/mcpServers/s", "line": 4}
    json.loads(render(r))


def test_secrets_never_reach_the_rendered_report():
    s = server(
        args=("--api-key", PLAIN, f"--token={SECRET}"),
        env={"API_KEY": SECRET, "OTHER": PLAIN},
        url=f"https://u:{PLAIN}@h.example/mcp?key={SECRET}",
        headers={"Authorization": f"Bearer {SECRET}"},
        command=f"run-{SECRET}",
    )
    out = render(report(Inventory(servers=[s])))
    assert SECRET not in out and SECRET[:-4] not in out
    assert PLAIN not in out
    srv = json.loads(out)["servers"][0]
    assert srv["env_keys"] == ["API_KEY", "OTHER"]
    assert srv["header_keys"] == ["Authorization"]


def test_findings_sorted_and_counted():
    r = report(Inventory(), [finding(Severity.LOW, "AP002"), finding(Severity.CRITICAL, "AP001"), finding(Severity.HIGH)])
    assert [f["severity"] for f in r["findings"]] == ["critical", "high", "low"]
    assert r["summary"]["findings"] == {"critical": 1, "high": 1, "medium": 0, "low": 1, "info": 0}
    assert r["summary"]["highest_severity"] == "critical"


def test_output_is_ascii_so_control_characters_are_escaped():
    out = render(report(Inventory(servers=[server(name="evil\x1b[2J‮name")])))
    assert "\x1b" not in out and "‮" not in out
    assert out.isascii()
