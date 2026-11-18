"""Merge JSON reports collected from many machines into one fleet summary.

Reports arrive from endpoints a security team does not fully trust (any laptop
could be compromised and forge one), so they are read with the same size
limits and depth-limited parser as configuration files, and every string is
treated as data.
"""

from __future__ import annotations

import json
import re
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable, Sequence

from mcpposture import __version__, jsonc
from mcpposture.report.text import clean
from mcpposture.safefs import SafeReadError, read_config, real

FLEET_SCHEMA_VERSION = "1.0"
MAX_REPORT_BYTES = 16 * 1024 * 1024
MAX_REPORTS = 100_000
_SEVERITIES = ("critical", "high", "medium", "low", "info")
_CONTEXT_SUFFIX = re.compile(r" \(in \d+ agent contexts\)$")
# Per-user home prefixes, folded to ~ so the same tool on many machines groups together.
_HOME_PREFIX = re.compile(r"(?i)(?:/Users/|/home/|[A-Z]:[\\/]Users[\\/])[^\\/\s]+")


@dataclass
class LoadResult:
    reports: list[tuple[str, dict[str, Any]]] = field(default_factory=list)
    skipped: list[tuple[str, str]] = field(default_factory=list)


def _valid(report: object) -> str | None:
    if not isinstance(report, dict):
        return "not a JSON object"
    version = report.get("schema_version")
    if not isinstance(version, str) or version.split(".")[0] != "1":
        return f"unsupported schema_version {str(version)[:20]!r}"
    for key, kind in (("machine", dict), ("findings", list), ("servers", list), ("summary", dict)):
        if not isinstance(report.get(key), kind):
            return f"missing or malformed {key!r}"
    for f in report["findings"]:
        if not isinstance(f, dict) or not all(isinstance(f.get(k), str) for k in ("check_id", "severity", "title", "fingerprint")):
            return "malformed finding"
        if f["severity"] not in _SEVERITIES:
            return "unknown severity"
    return None


def load_reports(paths: Sequence[Path]) -> LoadResult:
    result = LoadResult()
    files: list[tuple[Path, Path]] = []
    for p in paths:
        if p.is_dir():
            files += [(f, p) for f in sorted(p.glob("*.json"))]
        else:
            files.append((p, p.parent))
    for path, root in files[:MAX_REPORTS]:
        name = str(path)
        try:
            text = read_config(path, allowed_roots=[real(root)], max_bytes=MAX_REPORT_BYTES)
            report = jsonc.loads(text).value
        except SafeReadError as e:
            result.skipped.append((name, e.kind))
            continue
        except jsonc.JsoncError as e:
            result.skipped.append((name, f"invalid JSON: {e}"))
            continue
        problem = _valid(report)
        if problem:
            result.skipped.append((name, problem))
            continue
        result.reports.append((name, report))  # type: ignore[arg-type]
    if len(files) > MAX_REPORTS:
        result.skipped.append(("-", f"stopped after {MAX_REPORTS} reports"))
    return result


def _machine_id(name: str, report: dict[str, Any]) -> str:
    host = report["machine"].get("hostname")
    return host if isinstance(host, str) and host else Path(name).stem


def _latest(loaded: LoadResult) -> dict[str, dict[str, Any]]:
    """One report per machine: the most recent scan wins."""
    latest: dict[str, dict[str, Any]] = {}
    for name, report in loaded.reports:
        mid = _machine_id(name, report)
        started = str(report.get("scan", {}).get("started_at", ""))
        if mid not in latest or started >= str(latest[mid].get("scan", {}).get("started_at", "")):
            latest[mid] = report
    return latest


def _top(counter: Counter[Any], n: int) -> list[tuple[Any, int]]:
    return sorted(counter.items(), key=lambda kv: (-kv[1], str(kv[0])))[:n]


def summarise(loaded: LoadResult, *, top: int = 10) -> dict[str, Any]:
    machines = _latest(loaded)
    by_os: Counter[str] = Counter()
    by_severity: Counter[str] = Counter()
    worst: Counter[str] = Counter()
    check_machines: dict[tuple[str, str, str], set[str]] = defaultdict(set)
    issue_machines: dict[str, set[str]] = defaultdict(set)
    issue_example: dict[str, dict[str, Any]] = {}
    r2_combos: dict[str, set[str]] = defaultdict(set)
    r2_machines: set[str] = set()
    server_machines: dict[tuple[str, str], set[str]] = defaultdict(set)
    unclassified: dict[str, set[str]] = defaultdict(set)
    non_compliant: list[dict[str, Any]] = []
    without_policy = 0
    rules_versions: Counter[str] = Counter()

    for mid, report in machines.items():
        by_os[str(report["machine"].get("os", "unknown"))] += 1
        rules_versions[str(report.get("tool", {}).get("rules_version"))] += 1
        severities = [f["severity"] for f in report["findings"]]
        by_severity.update(severities)
        worst[next((s for s in _SEVERITIES if s in severities), "none")] += 1

        for f in report["findings"]:
            check_machines[(f["check_id"], f["severity"], f["title"])].add(mid)
            issue_machines[f["fingerprint"]].add(mid)
            issue_example.setdefault(f["fingerprint"], f)
            if f["check_id"] == "MP001" and f["severity"] != "info":
                r2_machines.add(mid)
                r2_combos[_CONTEXT_SUFFIX.sub("", str(f.get("evidence", "")))].add(mid)

        for s in report["servers"]:
            if not isinstance(s, dict):
                continue
            name, client = str(s.get("name", "")), str(s.get("client", ""))
            server_machines[(client, name)].add(mid)
            caps = s.get("capabilities")
            if isinstance(caps, dict) and caps.get("source") == "unclassified":
                target = s.get("url") or " ".join([str(s.get("command") or "")] + [str(a) for a in s.get("args", [])][:3])
                unclassified[_HOME_PREFIX.sub("~", f"{name}  {target}".strip())].add(mid)

        pol = report.get("policy")
        if not isinstance(pol, dict):
            without_policy += 1
        elif pol.get("compliant") is False:
            violations = pol.get("violations") if isinstance(pol.get("violations"), list) else []
            reasons = Counter(str(v.get("reason")) for v in violations if isinstance(v, dict))
            non_compliant.append({"machine": mid, "violations": len(violations), "reasons": dict(sorted(reasons.items()))})

    def count(d: dict[Any, set[str]]) -> Counter[Any]:
        return Counter({k: len(v) for k, v in d.items()})

    total = len(machines)
    return {
        "fleet_schema_version": FLEET_SCHEMA_VERSION,
        "tool": {"name": "mcpposture", "version": __version__},
        "machines": total,
        "reports_read": len(loaded.reports),
        "reports_skipped": [{"file": f, "reason": r} for f, r in loaded.skipped],
        "by_os": dict(sorted(by_os.items())),
        "rules_versions": dict(sorted(rules_versions.items())),
        "findings_by_severity": {s: by_severity.get(s, 0) for s in _SEVERITIES},
        "machines_by_worst_severity": {s: worst.get(s, 0) for s in (*_SEVERITIES, "none")},
        "top_checks": [
            {"check_id": c, "severity": sev, "title": t, "machines": n, "percent": _pct(n, total)}
            for (c, sev, t), n in _top(count(check_machines), top)
        ],
        "top_issues": [
            {
                "fingerprint": fp,
                "machines": n,
                "check_id": issue_example[fp]["check_id"],
                "severity": issue_example[fp]["severity"],
                "title": issue_example[fp]["title"],
                "server": issue_example[fp].get("server"),
                "evidence": issue_example[fp].get("evidence"),
            }
            for fp, n in _top(count(issue_machines), top)
        ],
        "rule_of_two": {
            "machines": len(r2_machines),
            "percent": _pct(len(r2_machines), total),
            "top_combinations": [{"combination": k, "machines": n} for k, n in _top(count(r2_combos), top)],
        },
        "policy": {
            "machines_without_policy": without_policy,
            "non_compliant_machines": len(non_compliant),
            "non_compliant": sorted(non_compliant, key=lambda m: (-m["violations"], m["machine"]))[: max(top, 25)],
        },
        "top_servers": [{"client": c, "name": n, "machines": k} for (c, n), k in _top(count(server_machines), top)],
        "top_unclassified_servers": [{"server": s, "machines": n} for s, n in _top(count(unclassified), top)],
    }


def _pct(n: int, total: int) -> float:
    return round(100.0 * n / total, 1) if total else 0.0


def render_json(summary: dict[str, Any]) -> str:
    return json.dumps(summary, indent=2, ensure_ascii=True) + "\n"


def _table(rows: Iterable[str]) -> list[str]:
    return [f"  {clean(r)}" for r in rows]


def render_text(s: dict[str, Any]) -> str:
    out = [
        f"MCPosture fleet summary: {s['machines']} machines ({', '.join(f'{k} {v}' for k, v in s['by_os'].items())})",
        "Findings: " + ", ".join(f"{k} {v}" for k, v in s["findings_by_severity"].items()),
        "Machines by worst finding: " + ", ".join(f"{k} {v}" for k, v in s["machines_by_worst_severity"].items()),
    ]
    if s["reports_skipped"]:
        out.append(f"Skipped {len(s['reports_skipped'])} unreadable or invalid reports")

    pol = s["policy"]
    out += ["", f"Policy: {pol['non_compliant_machines']} machines not compliant, {pol['machines_without_policy']} not evaluated"]
    out += _table(f"{m['machine']:<28} {m['violations']:>3} violations  {m['reasons']}" for m in pol["non_compliant"][:10])

    r2 = s["rule_of_two"]
    out += ["", f"Rule of Two: {r2['machines']} machines ({r2['percent']}%) have an agent with all three capabilities"]
    out += _table(f"{c['machines']:>5}  {c['combination']}" for c in r2["top_combinations"])

    out += ["", "Most widespread checks (machines affected)"]
    out += _table(f"{c['machines']:>5}  {c['percent']:>5}%  {c['check_id']} {c['severity']:<8} {c['title']}" for c in s["top_checks"])

    out += ["", "Most widespread individual issues"]
    out += _table(f"{i['machines']:>5}  {i['check_id']} [{i['server'] or '-'}] {i['evidence']}" for i in s["top_issues"])

    out += ["", "Most common servers"]
    out += _table(f"{v['machines']:>5}  {v['client']:<16} {v['name']}" for v in s["top_servers"])

    if s["top_unclassified_servers"]:
        out += ["", "Most common unclassified servers (candidates for rules.toml)"]
        out += _table(f"{u['machines']:>5}  {u['server']}" for u in s["top_unclassified_servers"])
    return "\n".join(out) + "\n"
