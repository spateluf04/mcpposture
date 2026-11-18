"""Shared check metadata and Finding construction."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Iterator

from mcpposture.jsonc import escape_pointer_token
from mcpposture.model import Finding, Inventory, Location, ServerConfig, SettingsDoc, Severity


@dataclass(frozen=True)
class CheckInfo:
    id: str
    title: str
    severity: Severity
    why: str
    remediation: str
    cwe: tuple[str, ...]
    owasp_llm: tuple[str, ...]
    owasp_agentic: tuple[str, ...] = ()


@dataclass(frozen=True)
class CheckContext:
    inventory: Inventory
    homes: tuple[Path, ...] = ()


Check = Callable[[CheckContext], Iterator[Finding]]


def ptr(*tokens: str | int) -> str:
    return "".join(f"/{escape_pointer_token(str(t))}" for t in tokens)


def stable_path(path: Path, homes: tuple[Path, ...]) -> str:
    """Path with the user's home replaced by ``~``, so fingerprints match across machines."""
    for home in homes:
        try:
            return "~/" + path.relative_to(home).as_posix()
        except ValueError:
            continue
    return path.as_posix()


def fingerprint(check_id: str, client: str, path: str, pointer: str, discriminator: str = "") -> str:
    return hashlib.sha256(f"{check_id}\0{client}\0{path}\0{pointer}\0{discriminator}".encode()).hexdigest()[:32]


def _finding(
    info: CheckInfo,
    ctx: CheckContext,
    *,
    client: str,
    path: Path,
    pointer: str,
    line: int | None,
    evidence: str,
    server: str | None,
    severity: Severity | None,
    title: str | None,
    why: str | None,
    remediation: str | None,
    discriminator: str,
    cwe: tuple[str, ...] | None = None,
) -> Finding:
    return Finding(
        check_id=info.id,
        severity=severity if severity is not None else info.severity,
        title=title or info.title,
        why=why or info.why,
        remediation=remediation or info.remediation,
        cwe=cwe if cwe is not None else info.cwe,
        owasp_llm=info.owasp_llm,
        owasp_agentic=info.owasp_agentic,
        client=client,
        location=Location(path, pointer, line),
        evidence=evidence,
        fingerprint=fingerprint(info.id, client, stable_path(path, ctx.homes), pointer, discriminator),
        server=server,
    )


def server_finding(
    info: CheckInfo,
    ctx: CheckContext,
    server: ServerConfig,
    sub_pointer: str = "",
    *,
    evidence: str,
    severity: Severity | None = None,
    title: str | None = None,
    why: str | None = None,
    remediation: str | None = None,
    discriminator: str = "",
    cwe: tuple[str, ...] | None = None,
) -> Finding:
    pointer = server.location.pointer + sub_pointer
    return _finding(
        info,
        ctx,
        client=server.client,
        path=server.location.path,
        pointer=pointer,
        line=server.line_of(pointer),
        evidence=evidence,
        server=server.name,
        severity=severity,
        title=title,
        why=why,
        remediation=remediation,
        discriminator=discriminator,
        cwe=cwe,
    )


def settings_finding(
    info: CheckInfo,
    ctx: CheckContext,
    doc: SettingsDoc,
    pointer: str,
    *,
    evidence: str,
    severity: Severity | None = None,
    title: str | None = None,
    why: str | None = None,
    remediation: str | None = None,
    discriminator: str = "",
) -> Finding:
    return _finding(
        info,
        ctx,
        client=doc.client,
        path=doc.path,
        pointer=pointer,
        line=doc.lines.get(pointer),
        evidence=evidence,
        server=None,
        severity=severity,
        title=title,
        why=why,
        remediation=remediation,
        discriminator=discriminator,
    )


def bump(sev: Severity) -> Severity:
    return Severity(min(sev + 1, Severity.CRITICAL))
