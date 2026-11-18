import json
import time

import pytest

import generate_fleet
from mcpposture import cli, fleet
from mcpposture.fleet import load_reports, render_json, render_text, summarise

from conftest import write


@pytest.fixture(scope="module")
def fleet_dir(tmp_path_factory):
    out = tmp_path_factory.mktemp("fleet")
    generate_fleet.generate(500, out)
    return out


def test_generator_is_deterministic(tmp_path):
    a, b = tmp_path / "a", tmp_path / "b"
    generate_fleet.generate(5, a, seed=1)
    generate_fleet.generate(5, b, seed=1)
    for x, y in zip(sorted(a.iterdir()), sorted(b.iterdir())):
        assert x.read_text() == y.read_text()


def test_generated_reports_contain_no_secrets(fleet_dir):
    for path in list(fleet_dir.iterdir())[:100]:
        text = path.read_text()
        assert generate_fleet.FAKE_GH not in text and generate_fleet.FAKE_PW not in text


def test_summary_of_500_machines(fleet_dir):
    start = time.perf_counter()
    loaded = load_reports([fleet_dir])
    s = summarise(loaded, top=10)
    elapsed = time.perf_counter() - start
    assert s["machines"] == 500 and s["reports_skipped"] == []
    assert sum(s["by_os"].values()) == 500
    assert sum(s["machines_by_worst_severity"].values()) == 500
    counts = [c["machines"] for c in s["top_checks"]]
    assert counts == sorted(counts, reverse=True)
    assert 0 < s["rule_of_two"]["machines"] <= 500
    assert s["policy"]["non_compliant_machines"] > 0
    assert any(u["server"].startswith("downloaded") and "~/Downloads" in u["server"] for u in s["top_unclassified_servers"])
    assert elapsed < 30


def test_fingerprints_group_the_same_issue_across_machines(fleet_dir):
    s = summarise(load_reports([fleet_dir]))
    assert s["top_issues"][0]["machines"] > 50


def test_renderers(fleet_dir):
    s = summarise(load_reports([fleet_dir]))
    assert json.loads(render_json(s))["fleet_schema_version"] == fleet.FLEET_SCHEMA_VERSION
    text = render_text(s)
    assert "500 machines" in text and "Rule of Two" in text


def _report(hostname, started, findings=()):
    return {
        "schema_version": "1.2",
        "tool": {"rules_version": "x"},
        "machine": {"hostname": hostname, "os": "linux"},
        "scan": {"started_at": started},
        "summary": {},
        "findings": list(findings),
        "servers": [],
        "policy": None,
    }


def _finding(sev="high"):
    return {"check_id": "MP003", "severity": sev, "title": "t", "fingerprint": "f", "evidence": "e"}


def test_latest_report_per_machine_wins(tmp_path):
    write(tmp_path / "old.json", _report("box", "2026-11-01T00:00:00+00:00", [_finding("critical")]))
    write(tmp_path / "new.json", _report("box", "2026-11-18T00:00:00+00:00"))
    s = summarise(load_reports([tmp_path]))
    assert s["machines"] == 1
    assert s["machines_by_worst_severity"]["none"] == 1


@pytest.mark.parametrize(
    ("content", "reason"),
    [
        ("{not json", "invalid JSON"),
        ("[1, 2]", "not a JSON object"),
        ('{"schema_version": "9.0"}', "unsupported schema_version"),
        (json.dumps({**_report("x", ""), "findings": "nope"}), "malformed 'findings'"),
        (json.dumps(_report("x", "", [{"check_id": "MP001"}])), "malformed finding"),
        (json.dumps(_report("x", "", [_finding("apocalyptic")])), "unknown severity"),
        ("[" * 10_000, "invalid JSON"),
    ],
)
def test_hostile_reports_are_skipped(tmp_path, content, reason):
    write(tmp_path / "bad.json", content)
    write(tmp_path / "good.json", _report("ok", ""))
    s = summarise(load_reports([tmp_path]))
    assert s["machines"] == 1
    (skipped,) = s["reports_skipped"]
    assert reason in skipped["reason"]


def test_oversized_report_is_skipped(tmp_path, monkeypatch):
    monkeypatch.setattr(fleet, "MAX_REPORT_BYTES", 100)
    write(tmp_path / "big.json", _report("x" * 200, ""))
    assert summarise(load_reports([tmp_path]))["reports_skipped"][0]["reason"] == "too_large"


def test_terminal_escapes_in_reports_are_neutralised(tmp_path):
    write(tmp_path / "evil.json", _report("evil\x1b[2J\x1b]0;owned\x07", "", [_finding()]))
    text = render_text(summarise(load_reports([tmp_path])))
    assert "\x1b" not in text and "\x07" not in text


def test_cli_fleet(fleet_dir, tmp_path, capsys):
    out = tmp_path / "summary.json"
    assert cli.main(["fleet", str(fleet_dir), "--format", "json", "-o", str(out)]) == cli.EXIT_OK
    assert json.loads(out.read_text())["machines"] == 500
    assert cli.main(["fleet", str(tmp_path / "missing")]) == cli.EXIT_ERROR
