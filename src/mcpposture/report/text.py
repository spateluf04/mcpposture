"""Human-readable terminal report, rendered from the redacted report dict."""

from __future__ import annotations

import re
import textwrap
from typing import Any

# C0/C1 controls (ANSI escape sequences start with \x1b), zero-width and bidi
# override characters: config text containing them could rewrite the terminal.
_UNSAFE = re.compile(r"[\x00-\x1f\x7f-\x9f​-‏‪-‮⁦-⁩﻿]")
_SEVERITY_ORDER = ("critical", "high", "medium", "low", "info")


def clean(value: object) -> str:
    return _UNSAFE.sub(lambda m: f"\\u{ord(m.group()):04x}", "" if value is None else str(value))


def _wrap(text: str, indent: str) -> list[str]:
    return textwrap.wrap(clean(text), width=88, initial_indent=indent, subsequent_indent=indent) or [indent]


def _flags(caps: dict[str, Any] | None) -> str:
    if not caps or caps.get("source") == "unclassified":
        return "???"
    flags = "".join(f if f in caps.get("flags", []) else "-" for f in "ABC")
    return flags.lower() if caps.get("source") == "heuristic" else flags


def _where(loc: dict[str, Any]) -> str:
    line = f":{loc['line']}" if loc.get("line") else ""
    pointer = f"  {loc['pointer']}" if loc.get("pointer") else ""
    return clean(f"{loc['path']}{line}{pointer}")


def render(report: dict[str, Any]) -> str:
    out: list[str] = []
    s = report["summary"]
    m = report["machine"]
    wsl = " (WSL)" if m["wsl"] else ""
    out.append(f"MCPosture {clean(report['tool']['version'])}  {clean(m['hostname'])} [{clean(m['os'])}{wsl}]")
    out.append(
        f"Scanned {s['files']} config files ({s['files_with_errors']} unreadable), "
        f"found {s['servers']} servers in {s['contexts']} agent contexts."
    )

    policy = report.get("policy")
    if policy:
        if policy["compliant"]:
            out.append(f"Policy {clean(policy['path'])}: COMPLIANT")
        else:
            reasons: dict[str, int] = {}
            for v in policy["violations"]:
                reasons[v["reason"]] = reasons.get(v["reason"], 0) + 1
            detail = ", ".join(f"{n} {r.replace('_', ' ')}" for r, n in sorted(reasons.items()))
            n = len(policy["violations"])
            out.append(f"Policy {clean(policy['path'])}: NOT COMPLIANT, {n} violation{'s' if n != 1 else ''} ({detail})")

    findings = report["findings"]
    out.append("")
    if not findings:
        out.append("Findings: none")
    for sev in _SEVERITY_ORDER:
        group = [f for f in findings if f["severity"] == sev]
        if not group:
            continue
        out.append(f"{sev.upper()} ({len(group)})")
        for f in group:
            server = f"  [{clean(f['server'])}]" if f.get("server") else ""
            out.append(f"  {clean(f['check_id'])}  {clean(f['title'])}{server}")
            out.append(f"      at   {_where(f['location'])}")
            if f.get("evidence"):
                out.append(f"      saw  {clean(f['evidence'])}")
            out.extend(_wrap("why  " + f["why"], "      "))
            out.extend(_wrap("fix  " + f["remediation"], "      "))
            refs = ", ".join(f["cwe"] + f["owasp_llm"] + f.get("owasp_agentic", []))
            if refs:
                out.append(f"      refs {clean(refs)}")
        out.append("")

    if report["servers"]:
        out.append("")
        out.append("Servers  (Rule of Two: A untrusted input, B private data, C external actions; lowercase = heuristic guess, ??? = unclassified)")
        for srv in report["servers"]:
            target = srv["url"] or " ".join([srv["command"] or ""] + srv["args"])
            out.append(
                f"  {_flags(srv.get('capabilities'))}  {clean(srv['client']):<16} {clean(srv['scope']):<8} "
                f"{clean(srv['name']):<24} {clean(srv['transport']):<6} {clean(target)[:100]}"
            )

    if report["contexts"]:
        out.append("")
        out.append("Agent contexts")
        for c in report["contexts"]:
            flags = "".join(f if f in c.get("capabilities", []) else "-" for f in "ABC")
            out.append(f"  {flags}  {clean(c.get('rule_of_two', '')):<10} {clean(c['id'])}")

    if report["scan_issues"]:
        out.append("")
        out.append("Scan issues (files skipped or partly read)")
        for issue in report["scan_issues"]:
            out.append(f"  {clean(issue['kind'])}: {clean(issue['path'])}")
            out.extend(_wrap(issue["detail"], "      "))
    return "\n".join(out).rstrip() + "\n"
