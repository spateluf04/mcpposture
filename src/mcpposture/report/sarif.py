"""SARIF 2.1.0 output for GitHub code scanning and other SARIF consumers."""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, Sequence

from mcpposture import __version__
from mcpposture.checks.base import CheckInfo

SARIF_VERSION = "2.1.0"
SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
INFORMATION_URI = "https://github.com/spateluf04/mcpposture"
FINGERPRINT_KEY = "mcpposture/v1"

_LEVEL = {"critical": "error", "high": "error", "medium": "warning", "low": "note", "info": "note"}
# GitHub maps security-severity to its labels: >=9 critical, >=7 high, >=4 medium, else low.
_SECURITY_SEVERITY = {"critical": "9.5", "high": "8.0", "medium": "5.5", "low": "3.0", "info": "0.0"}


def _rule(info: CheckInfo) -> dict[str, Any]:
    refs = list(info.cwe) + list(info.owasp_llm) + list(info.owasp_agentic)
    return {
        "id": info.id,
        "name": "".join(w.capitalize() for w in info.title.replace(",", "").split()),
        "shortDescription": {"text": info.title},
        "fullDescription": {"text": info.why},
        "help": {
            "text": f"{info.why}\n\nFix: {info.remediation}\n\nReferences: {', '.join(refs)}",
            "markdown": f"**Why it matters.** {info.why}\n\n**Fix.** {info.remediation}\n\n**References.** {', '.join(refs)}",
        },
        "helpUri": f"{INFORMATION_URI}#check-catalog",
        "defaultConfiguration": {"level": _LEVEL[info.severity.label]},
        "properties": {
            "tags": ["security", *[f"external/cwe/{c.lower()}" for c in info.cwe], *info.owasp_llm, *info.owasp_agentic],
            "security-severity": _SECURITY_SEVERITY[info.severity.label],
            "precision": "high",
        },
    }


def _artifact(path: str, bases: Sequence[Path]) -> dict[str, str]:
    p = Path(path)
    for base in bases:
        try:
            return {"uri": p.relative_to(base).as_posix()}
        except ValueError:
            continue
    try:
        return {"uri": p.as_uri()}
    except ValueError:
        return {"uri": p.as_posix()}


def _location(loc: dict[str, Any], bases: Sequence[Path]) -> dict[str, Any]:
    physical: dict[str, Any] = {"artifactLocation": _artifact(loc["path"], bases)}
    if loc.get("line"):
        physical["region"] = {"startLine": int(loc["line"])}
    return {"physicalLocation": physical}


def build(report: dict[str, Any], catalog: Sequence[CheckInfo], *, base: Path | None = None) -> dict[str, Any]:
    """SARIF log from the redacted report dict.

    Paths are made relative to ``base`` (normally the current directory, which in
    CI is the repository checkout) so code scanning can link to the file.
    """
    bases = [Path(os.path.realpath(base))] if base is not None else []
    rules = [_rule(info) for info in catalog]
    index = {r["id"]: i for i, r in enumerate(rules)}
    results = []
    for f in report["findings"]:
        message = f"{f['title']}: {f['evidence']}" if f["evidence"] else f["title"]
        result: dict[str, Any] = {
            "ruleId": f["check_id"],
            "level": _LEVEL[f["severity"]],
            "message": {"text": message},
            "locations": [_location(f["location"], bases)],
            "partialFingerprints": {FINGERPRINT_KEY: f["fingerprint"]},
            "properties": {
                "severity": f["severity"],
                "security-severity": _SECURITY_SEVERITY[f["severity"]],
                "client": f["client"],
                "server": f["server"],
                "context": f["context_id"],
                "jsonPointer": f["location"]["pointer"],
            },
        }
        if f["check_id"] in index:
            result["ruleIndex"] = index[f["check_id"]]
        results.append(result)

    notifications = [
        {
            "level": "warning",
            "message": {"text": f"{i['kind']}: {i['detail']}"},
            "locations": [_location({"path": i["path"]}, bases)],
        }
        for i in report["scan_issues"]
    ]
    return {
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "MCPosture",
                        "version": __version__,
                        "semanticVersion": __version__,
                        "informationUri": INFORMATION_URI,
                        "rules": rules,
                    }
                },
                "invocations": [{"executionSuccessful": True, "toolExecutionNotifications": notifications}],
                "results": results,
                "properties": {"rulesVersion": report["tool"].get("rules_version"), "reportSchema": report["schema_version"]},
            }
        ],
    }


def render(report: dict[str, Any], catalog: Sequence[CheckInfo], *, base: Path | None = None) -> str:
    return json.dumps(build(report, catalog, base=base), indent=2, ensure_ascii=True) + "\n"
