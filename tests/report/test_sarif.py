"""SARIF 2.1.0 structure tests. Without a third-party JSON Schema validator,
these assert the properties the SARIF spec requires and GitHub code scanning
relies on."""

import json
from pathlib import Path

import pytest

from mcpposture import cli

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures"
REPO = Path(__file__).resolve().parents[2]


@pytest.fixture
def sarif(capsys, monkeypatch):
    monkeypatch.chdir(REPO)
    code = cli.main(["scan", "--path", str(FIXTURES / "vulnerable_repo"), "--format", "sarif"])
    out = capsys.readouterr().out
    assert code == cli.EXIT_FINDINGS
    return out, json.loads(out)


def test_top_level(sarif):
    _, log = sarif
    assert log["version"] == "2.1.0"
    assert log["$schema"].endswith("sarif-2.1.0.json")
    assert len(log["runs"]) == 1


def test_driver_rules_cover_catalog(sarif):
    _, log = sarif
    driver = log["runs"][0]["tool"]["driver"]
    assert driver["name"] == "MCPosture" and driver["version"]
    ids = [r["id"] for r in driver["rules"]]
    assert ids == [c.id for c in cli.CATALOG]
    for r in driver["rules"]:
        assert r["shortDescription"]["text"] and r["fullDescription"]["text"] and r["help"]["text"]
        assert r["defaultConfiguration"]["level"] in ("error", "warning", "note")
        assert float(r["properties"]["security-severity"]) >= 0
        assert any(t.startswith("external/cwe/cwe-") for t in r["properties"]["tags"])


def test_results(sarif):
    _, log = sarif
    run = log["runs"][0]
    rules = run["tool"]["driver"]["rules"]
    assert run["results"]
    fingerprints = set()
    for res in run["results"]:
        assert rules[res["ruleIndex"]]["id"] == res["ruleId"]
        assert res["level"] in ("error", "warning", "note")
        assert res["message"]["text"]
        (loc,) = res["locations"]
        uri = loc["physicalLocation"]["artifactLocation"]["uri"]
        assert uri.startswith("tests/fixtures/vulnerable_repo/"), uri
        assert loc["physicalLocation"]["region"]["startLine"] >= 1
        fp = res["partialFingerprints"]["mcpposture/v1"]
        assert fp not in fingerprints
        fingerprints.add(fp)


def test_invocation(sarif):
    _, log = sarif
    (inv,) = log["runs"][0]["invocations"]
    assert inv["executionSuccessful"] is True


def test_no_secrets(sarif):
    out, _ = sarif
    assert "AKIAIOSFODNN7EXAMPLE" not in out and "fake-password-for-tests" not in out


def test_paths_outside_base_use_file_uris(capsys, tmp_path, monkeypatch):
    (tmp_path / ".mcp.json").write_text('{"mcpServers": {"s": {"command": "/tmp/x"}}}')
    monkeypatch.chdir(REPO)
    cli.main(["scan", "--path", str(tmp_path), "--format", "sarif"])
    results = json.loads(capsys.readouterr().out)["runs"][0]["results"]
    assert results
    for res in results:
        assert res["locations"][0]["physicalLocation"]["artifactLocation"]["uri"].startswith("file:")
