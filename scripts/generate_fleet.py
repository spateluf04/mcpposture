"""Generate synthetic MCPosture reports for a fleet of developer machines.

Each machine gets a random but plausible set of agent configs, which then go
through the real pipeline (parse, contexts, checks, policy, report), so the
output matches the report schema exactly. Deterministic for a given seed.

    python scripts/generate_fleet.py --machines 500 --out fleet-reports
    mcpposture fleet fleet-reports
"""

from __future__ import annotations

import argparse
import json
import random
from datetime import datetime, timedelta, timezone
from pathlib import Path

from mcpposture import checks, jsonc, policy
from mcpposture.discovery.hostinfo import Host
from mcpposture.discovery.inventory import build_contexts
from mcpposture.discovery.parsers import PARSERS, FileContext
from mcpposture.model import FileRecord, Inventory, Severity
from mcpposture.report import jsonfmt
from mcpposture.report.write import write_report

FLEET_POLICY = """
schema_version = 1
max_severity = "high"
require_approved = true

[[approved]]
url = "https://mcp.context7.com/mcp"
[[approved]]
npm = "@playwright/mcp"
version = "0.0.41"
[[approved]]
npm = "@modelcontextprotocol/server-filesystem"
version = "2025.8.21"
[[approved]]
npm = "@modelcontextprotocol/server-memory"
version = "2025.4.25"
[[approved]]
pypi = "mcp-server-fetch"
version = "2025.4.7"
[[approved]]
url = "https://api.githubcopilot.com/mcp"

[[banned]]
npm = "@example/known-bad-mcp"
reason = "Blocked by security review (synthetic example)."
"""

# Fake credentials are assembled at runtime; generated reports only ever contain redacted forms.
FAKE_GH = "ghp_" + "FAKE" * 9
FAKE_PW = "fake-" + "password-" + "0000"


def templates(home: str) -> list[tuple[str, dict, float]]:
    return [
        ("context7", {"type": "http", "url": "https://mcp.context7.com/mcp"}, 0.50),
        ("playwright", {"command": "npx", "args": ["@playwright/mcp@latest"]}, 0.35),
        ("playwright-pinned", {"command": "npx", "args": ["@playwright/mcp@0.0.41"]}, 0.10),
        ("filesystem", {"command": "npx", "args": ["-y", "@modelcontextprotocol/server-filesystem@2025.8.21", f"{home}/projects"]}, 0.30),
        ("filesystem-home", {"command": "npx", "args": ["-y", "@modelcontextprotocol/server-filesystem", home]}, 0.08),
        ("github", {"type": "http", "url": "https://api.githubcopilot.com/mcp/", "headers": {"Authorization": "Bearer ${GITHUB_TOKEN}"}}, 0.30),
        ("github-local", {"command": "npx", "args": ["-y", "@modelcontextprotocol/server-github"], "env": {"GITHUB_PERSONAL_ACCESS_TOKEN": FAKE_GH}}, 0.05),
        ("fetch", {"command": "uvx", "args": ["mcp-server-fetch"]}, 0.25),
        ("postgres", {"command": "npx", "args": ["-y", "@modelcontextprotocol/server-postgres", "postgresql://localhost/app"], "env": {"PGPASSWORD": FAKE_PW}}, 0.10),
        ("slack", {"command": "npx", "args": ["-y", "@modelcontextprotocol/server-slack"], "env": {"SLACK_BOT_TOKEN": "${SLACK_BOT_TOKEN}"}}, 0.10),
        ("acme-internal", {"command": "/opt/acme/bin/acme-mcp", "args": ["--stdio"]}, 0.20),
        ("downloaded", {"command": f"{home}/Downloads/mcp-server"}, 0.03),
        ("intranet", {"type": "http", "url": "http://wiki.corp.example.com/mcp"}, 0.05),
        ("memory", {"command": "npx", "args": ["-y", "@modelcontextprotocol/server-memory@2025.4.25"]}, 0.10),
        ("known-bad", {"command": "npx", "args": ["-y", "@example/known-bad-mcp"]}, 0.01),
    ]


def pick(rng: random.Random, home: str, scale: float = 1.0) -> dict[str, dict]:
    return {name: entry for name, entry, p in templates(home) if rng.random() < p * scale}


def machine_files(rng: random.Random, os_name: str, home: str) -> list[tuple[str, str, str, str, str | None, dict]]:
    sep_home = home.rstrip("/")
    app_support = {
        "macos": f"{sep_home}/Library/Application Support",
        "windows": f"{sep_home}/AppData/Roaming",
        "linux": f"{sep_home}/.config",
    }[os_name]
    files: list[tuple[str, str, str, str, str | None, dict]] = []
    if rng.random() < 0.8:
        projects = {}
        for n in range(rng.choice([0, 1, 2])):
            project = f"{sep_home}/work/app{n}"
            projects[project] = {"mcpServers": pick(rng, home, 0.3)}
            if rng.random() < 0.5:
                files.append((f"{project}/.mcp.json", "claude-code", "project", "mcp_servers", project, {"mcpServers": pick(rng, home, 0.4)}))
        files.append((f"{sep_home}/.claude.json", "claude-code", "user", "claude_json", None, {"mcpServers": pick(rng, home), "projects": projects}))
        settings: dict = {"permissions": {"allow": ["Bash(npm run test *)"]}}
        if rng.random() < 0.05:
            settings["permissions"]["allow"].append("Bash(*)")
        if rng.random() < 0.03:
            settings["permissions"]["defaultMode"] = "bypassPermissions"
        if rng.random() < 0.10:
            settings["enableAllProjectMcpServers"] = True
        files.append((f"{sep_home}/.claude/settings.json", "claude-code", "user", "claude_settings", None, settings))
    if rng.random() < 0.4:
        files.append((f"{sep_home}/.cursor/mcp.json", "cursor", "user", "mcp_servers", None, {"mcpServers": pick(rng, home, 0.7)}))
    if rng.random() < 0.5:
        files.append((f"{app_support}/Code/User/mcp.json", "vscode", "user", "vscode_servers", None, {"servers": pick(rng, home, 0.6)}))
        if rng.random() < 0.04:
            files.append((f"{app_support}/Code/User/settings.json", "vscode", "user", "vscode_settings", None, {"chat.tools.global.autoApprove": True}))
    if rng.random() < 0.3:
        files.append((f"{app_support}/Claude/claude_desktop_config.json", "claude-desktop", "user", "mcp_servers", None, {"mcpServers": pick(rng, home, 0.6)}))
    return files


def machine_report(i: int, rng: random.Random, pol: policy.Policy, started: datetime) -> dict:
    os_name = rng.choices(["macos", "windows", "linux"], [55, 30, 15])[0]
    user = f"dev{i:04d}"
    home = {"macos": f"/Users/{user}", "windows": f"C:/Users/{user}", "linux": f"/home/{user}"}[os_name]
    inv = Inventory()
    for path_str, client, scope, fmt, project, data in machine_files(rng, os_name, home):
        path = Path(path_str)
        doc = jsonc.loads(json.dumps(data, indent=2))
        parsed = PARSERS[fmt](doc, FileContext(path, client, scope, project))
        inv.servers += parsed.servers
        if parsed.settings is not None:
            inv.settings.append(parsed.settings)
        inv.files.append(FileRecord(path, client, scope, fmt, "ok", len(parsed.servers)))
    inv.contexts = build_contexts(inv)
    homes = [Path(home)]
    findings = checks.run_all(inv, homes)
    evaluation = policy.evaluate(pol, inv, findings, homes)
    host = Host(os=os_name, is_wsl=False, home=Path(home), hostname=f"{user}-laptop")
    return jsonfmt.build_report(
        inv,
        findings + evaluation.findings,
        host=host,
        mode="local",
        target=None,
        started_at=started + timedelta(minutes=i),
        fail_on=Severity.HIGH,
        evaluation=evaluation,
    )


def generate(machines: int, out: Path, seed: int = 2026) -> list[Path]:
    rng = random.Random(seed)
    pol, _ = policy.parse(FLEET_POLICY, path="fleet-policy.toml")
    assert pol is not None
    out.mkdir(parents=True, exist_ok=True)
    started = datetime(2026, 11, 18, 9, 0, tzinfo=timezone.utc)
    written = []
    for i in range(1, machines + 1):
        report = machine_report(i, rng, pol, started)
        path = out / f"dev{i:04d}.json"
        write_report(jsonfmt.render(report), path)
        written.append(path)
    return written


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--machines", type=int, default=500)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--seed", type=int, default=2026)
    args = parser.parse_args()
    paths = generate(args.machines, args.out, args.seed)
    print(f"wrote {len(paths)} reports to {args.out}")


if __name__ == "__main__":
    main()
