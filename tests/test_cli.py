import json
from pathlib import Path

import pytest

from mcpposture import cli
from mcpposture.model import Finding, Inventory, Location, Severity

from conftest import FIXTURES

BASIC = FIXTURES / "basic_repo"


def run(capsys, *argv):
    code = cli.main(list(argv))
    out = capsys.readouterr()
    return code, out.out, out.err


def test_json_scan_of_fixture_repo(capsys):
    code, out, _ = run(capsys, "scan", "--path", str(BASIC), "--format", "json")
    assert code == cli.EXIT_OK
    report = json.loads(out)
    assert {s["name"] for s in report["servers"]} == {"github", "docs", "filesystem", "search"}
    assert {c["client"] for c in report["contexts"]} == {"claude-code", "cursor", "vscode"}
    assert report["scan"]["mode"] == "path"


def test_text_scan(capsys):
    code, out, _ = run(capsys, "scan", "--path", str(BASIC))
    assert code == cli.EXIT_OK
    assert "found 4 servers" in out


def test_output_file(tmp_path, capsys):
    dest = tmp_path / "report.json"
    code, out, _ = run(capsys, "scan", "--path", str(BASIC), "--format", "json", "-o", str(dest))
    assert code == cli.EXIT_OK and out == ""
    assert json.loads(dest.read_text(encoding="utf-8"))["schema_version"]


def test_missing_path_is_exit_2(tmp_path, capsys):
    code, _, err = run(capsys, "scan", "--path", str(tmp_path / "nope"))
    assert code == cli.EXIT_ERROR
    assert "no such file" in err


def test_unwritable_output_is_exit_2(tmp_path, capsys):
    code, _, err = run(capsys, "scan", "--path", str(BASIC), "-o", str(tmp_path / "no-such-dir" / "r.json"))
    assert code == cli.EXIT_ERROR
    assert err.startswith("mcpposture: error:")


@pytest.mark.parametrize("argv", [[], ["bogus"], ["scan", "--format", "xml"], ["scan", "--max-depth", "0"]])
def test_bad_arguments_are_exit_2(capsys, argv):
    assert run(capsys, *argv)[0] == cli.EXIT_ERROR


def test_help_is_exit_0(capsys):
    assert run(capsys, "--help")[0] == cli.EXIT_OK


def _finding(sev):
    return Finding("AP999", sev, "t", "w", "r", (), (), "cursor", Location(Path("/x")), "", "fp")


@pytest.mark.parametrize(
    ("severity", "fail_on", "expected"),
    [
        (Severity.HIGH, "high", cli.EXIT_FINDINGS),
        (Severity.CRITICAL, "high", cli.EXIT_FINDINGS),
        (Severity.MEDIUM, "high", cli.EXIT_OK),
        (Severity.HIGH, "critical", cli.EXIT_OK),
        (Severity.INFO, "info", cli.EXIT_FINDINGS),
    ],
)
def test_exit_code_threshold(monkeypatch, capsys, severity, fail_on, expected):
    monkeypatch.setattr(cli, "run_checks", lambda inv: [_finding(severity)])
    assert run(capsys, "scan", "--path", str(BASIC), "--fail-on", fail_on)[0] == expected


def test_internal_error_is_exit_2_without_leaking_details(monkeypatch, capsys):
    secret = "sk-ant-api03-" + "FAKEkey0123456789abcdEXAMPLE"

    def boom(*a, **k):
        raise RuntimeError(f"exploded near {secret}")

    monkeypatch.setattr(cli, "scan_path", boom)
    code, _, err = run(capsys, "scan", "--path", str(BASIC))
    assert code == cli.EXIT_ERROR
    assert secret not in err and "RuntimeError" in err


def test_local_mode_uses_known_locations(monkeypatch, capsys):
    seen = {}

    def fake_scan_local(host, *, cwd, limits):
        seen["cwd"] = cwd
        return Inventory()

    monkeypatch.setattr(cli, "scan_local", fake_scan_local)
    code, out, _ = run(capsys, "scan", "--format", "json")
    assert code == cli.EXIT_OK
    assert json.loads(out)["scan"]["mode"] == "local"
    assert seen["cwd"] == Path.cwd()
