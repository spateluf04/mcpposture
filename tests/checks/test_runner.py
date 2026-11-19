import re
from pathlib import Path

import pytest

from mcpposture import checks
from mcpposture.checks import CATALOG, CHECKS, run_all
from mcpposture.cli import CATALOG as CLI_CATALOG
from mcpposture.model import Inventory

from conftest import servers_from, settings_from


def test_catalog_ids_unique_and_metadata_complete():
    ids = [c.id for c in CATALOG]
    assert len(ids) == len(set(ids))
    for c in CATALOG:
        assert re.fullmatch(r"MP\d{3}", c.id)
        assert c.title and c.why and c.remediation
        assert c.cwe and all(re.fullmatch(r"CWE-\d+", x) for x in c.cwe)
        assert c.owasp_llm and all(re.fullmatch(r"LLM(0[1-9]|10):2025", x) for x in c.owasp_llm)
        assert all(re.fullmatch(r"ASI(0[1-9]|10):2026", x) for x in c.owasp_agentic)


# Checked against the official PDF, "OWASP Top 10 For Agentic Applications 2026" (December 2025),
# https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/
OWASP_AGENTIC = {
    "MP001": ("ASI01:2026", "ASI02:2026"),
    "MP002": ("ASI03:2026",),
    "MP003": ("ASI04:2026",),
    "MP004": (),
    "MP005": ("ASI02:2026", "ASI03:2026"),
    "MP006": ("ASI02:2026", "ASI05:2026"),
    "MP007": ("ASI04:2026",),
    "MP008": ("ASI04:2026",),
}


def test_owasp_agentic_mapping_matches_code_and_readme():
    assert {c.id: c.owasp_agentic for c in CLI_CATALOG} == OWASP_AGENTIC
    readme = (Path(__file__).resolve().parents[2] / "README.md").read_text(encoding="utf-8")
    for c in CLI_CATALOG:
        row = next(line for line in readme.splitlines() if line.startswith(f"| {c.id} |"))
        cell = row.split("|")[6].strip()
        assert cell == ", ".join(x.split(":")[0] for x in c.owasp_agentic), c.id


def test_crashing_check_becomes_scan_issue(monkeypatch):
    class Boom:
        INFO = CATALOG[0]

        @staticmethod
        def check(ctx):
            raise ZeroDivisionError

    monkeypatch.setattr(checks, "CHECKS", (Boom,) + CHECKS[1:])
    inv = Inventory(servers=servers_from({"s": {"command": "/tmp/x"}}))
    found = run_all(inv)
    assert [i.kind for i in inv.issues] == ["check_error"]
    assert [f.check_id for f in found] == ["MP007"]


def test_fingerprints_stable_across_homes():
    a = run_all(Inventory(servers=servers_from({"s": {"command": "/tmp/x"}}, path="/home/alice/.cursor/mcp.json")), [Path("/home/alice")])
    b = run_all(Inventory(servers=servers_from({"s": {"command": "/tmp/x"}}, path="/home/bob/.cursor/mcp.json")), [Path("/home/bob")])
    assert a[0].fingerprint == b[0].fingerprint


HOSTILE_ENTRIES = {
    "empty": {},
    "nulls": {"command": None, "args": None, "env": None, "url": None},
    "huge": {"command": "x" * 100_000, "args": ["y" * 50_000] * 10, "url": "http://" + "a" * 10_000},
    "unicode": {"command": "‮\u0000퟿", "args": ["\U0001f600", "--token", "\x1b[31m"], "env": {"\u0000": "\u0000"}},
    "weird_url": {"type": "http", "url": "http://[::1"},
    "only_wrappers": {"command": "cmd", "args": ["/c"]},
    "deep_shell": {"command": "sh", "args": ["-c", "sh -c 'sh -c \"sh -c x\"'"]},
    "docker_flags_only": {"command": "docker", "args": ["run", "-v"]},
    "mount_garbage": {"command": "docker", "args": ["run", "--mount", "=,=,,source", "img"]},
}


@pytest.mark.parametrize("name", sorted(HOSTILE_ENTRIES))
def test_hostile_servers_never_crash_checks(name):
    inv = Inventory(servers=servers_from({name: HOSTILE_ENTRIES[name]}))
    run_all(inv)
    assert [i for i in inv.issues if i.kind == "check_error"] == []


def test_hostile_settings_never_crash_checks():
    nested: object = "--dangerously-skip-permissions"
    for _ in range(50):
        nested = [nested]
    docs = [
        settings_from({"permissions": "nope", "env": ["x"], "hooks": nested}),
        settings_from({"permissions": {"allow": "Bash", "defaultMode": 5}}),
        settings_from({"chat.tools.terminal.autoApprove": ["/.*/"], "chat.permissions.default": None}, client="vscode"),
    ]
    inv = Inventory(settings=docs)
    run_all(inv)
    assert [i for i in inv.issues if i.kind == "check_error"] == []
