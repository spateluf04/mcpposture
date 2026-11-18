"""The versioned report document.

Every output format renders from the dict ``build_report`` returns, and that
dict is the only place config values are copied into output, so redaction
happens exactly once, here.
"""

from __future__ import annotations

import json
from collections import Counter
from datetime import datetime
from pathlib import Path
from typing import Sequence

from mcpposture import __version__
from mcpposture.discovery.hostinfo import Host
from mcpposture.model import AgentContext, Classification, Finding, Inventory, ServerConfig, Severity
from mcpposture.redact import redact, redact_args, redact_url

# Bump the minor version for added fields, the major version for anything
# removed, renamed, or changed in meaning.
SCHEMA_VERSION = "1.1"


def _capabilities(c: Classification | None) -> dict[str, object]:
    if c is None:
        return {"flags": [], "source": "unclassified", "rules": []}
    return {"flags": sorted(c.flags), "source": c.source, "rules": list(c.rule_ids)}


def _context(c: AgentContext, inv: Inventory) -> dict[str, object]:
    classes = [inv.capabilities.get(i) for i in c.server_ids]
    flags = sorted(frozenset().union(*(k.flags for k in classes if k is not None)))
    unclassified = [i for i, k in zip(c.server_ids, classes) if k is None or k.source == "unclassified"]
    status = "violation" if flags == ["A", "B", "C"] else ("incomplete" if unclassified else "ok")
    return {
        "id": c.id,
        "client": c.client,
        "project": c.project,
        "server_ids": list(c.server_ids),
        "capabilities": flags,
        "unclassified_server_ids": unclassified,
        "rule_of_two": status,
    }


def _server(s: ServerConfig, inv: Inventory) -> dict[str, object]:
    return {
        "id": s.id,
        "name": redact(s.name),
        "client": s.client,
        "scope": s.scope,
        "project": s.project,
        "source": {"path": str(s.location.path), "pointer": s.location.pointer, "line": s.location.line},
        "transport": s.transport,
        "command": redact(s.command) if s.command is not None else None,
        "args": list(redact_args(s.args)),
        "url": redact_url(s.url) if s.url is not None else None,
        # Values are never copied: env and headers are where credentials live.
        "env_keys": sorted(s.env),
        "header_keys": sorted(s.headers),
        "env_file": s.env_file,
        "capabilities": _capabilities(inv.capabilities.get(s.id)),
    }


def _finding(f: Finding) -> dict[str, object]:
    return {
        "check_id": f.check_id,
        "severity": f.severity.label,
        "title": f.title,
        "why": f.why,
        "remediation": f.remediation,
        "cwe": list(f.cwe),
        "owasp_llm": list(f.owasp_llm),
        "owasp_agentic": list(f.owasp_agentic),
        "client": f.client,
        "server": f.server,
        "context_id": f.context_id,
        "location": {"path": str(f.location.path), "pointer": f.location.pointer, "line": f.location.line},
        "evidence": f.evidence,
        "fingerprint": f.fingerprint,
    }


def build_report(
    inv: Inventory,
    findings: Sequence[Finding],
    *,
    host: Host,
    mode: str,
    target: Path | None,
    started_at: datetime,
    fail_on: Severity,
) -> dict[str, object]:
    ordered = sorted(findings, key=lambda f: (-f.severity, f.check_id, str(f.location.path), f.location.pointer))
    by_sev = Counter(f.severity.label for f in ordered)
    return {
        "schema_version": SCHEMA_VERSION,
        "tool": {"name": "mcpposture", "version": __version__, "rules_version": inv.rules_version},
        "machine": {"hostname": host.hostname, "os": host.os, "wsl": host.is_wsl},
        "scan": {
            "mode": mode,
            "target": str(target) if target is not None else None,
            "started_at": started_at.isoformat(timespec="seconds"),
            "fail_on": fail_on.label,
        },
        "summary": {
            "files": len(inv.files),
            "files_with_errors": sum(1 for f in inv.files if f.status == "error"),
            "servers": len(inv.servers),
            "contexts": len(inv.contexts),
            "scan_issues": len(inv.issues),
            "findings": {sev.label: by_sev.get(sev.label, 0) for sev in sorted(Severity, reverse=True)},
            "highest_severity": ordered[0].severity.label if ordered else None,
        },
        "findings": [_finding(f) for f in ordered],
        "servers": [_server(s, inv) for s in inv.servers],
        "contexts": [_context(c, inv) for c in inv.contexts],
        "files": [
            {"path": str(f.path), "client": f.client, "scope": f.scope, "format": f.fmt, "status": f.status, "servers": f.servers}
            for f in inv.files
        ],
        "scan_issues": [{"path": str(i.path), "kind": i.kind, "detail": redact(i.detail)} for i in inv.issues],
    }


def render(report: dict[str, object]) -> str:
    # ensure_ascii escapes every non-ASCII character, so terminal control and
    # bidi characters from config files cannot survive into the output.
    return json.dumps(report, indent=2, ensure_ascii=True) + "\n"
