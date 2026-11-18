import re
from pathlib import Path

import pytest

from mcpposture import checks
from mcpposture.checks import CATALOG, CHECKS, run_all
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
