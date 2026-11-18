"""Organisation policy: approved servers, banned servers, and a severity ceiling.

Servers are identified by what actually runs (package and exact version,
image digest, URL, or executable hash), never by the name in the config:
that name is a label the user chooses and proves nothing.
"""

from __future__ import annotations

import hashlib
import os
import re
import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, Iterator, Sequence
from urllib.parse import urlsplit

from mcpposture.checks.base import CheckContext, CheckInfo, server_finding
from mcpposture.checks.exec_location import executed_paths
from mcpposture.checks.launch import packages, unwrap
from mcpposture.checks.transport import is_loopback
from mcpposture.classify import normalise_oci, normalise_pypi
from mcpposture.model import Finding, Inventory, ServerConfig, Severity
from mcpposture.safefs import read_config, real, sha256_file

SCHEMA_VERSION = 1
MAX_HASH_BYTES = 512 * 1024 * 1024

INFO = CheckInfo(
    id="MP008",
    title="Server not allowed by policy",
    severity=Severity.HIGH,
    why=(
        "Your organisation's policy lists which MCP servers may run on managed machines. Anything else is software "
        "nobody has reviewed, executing with the developer's access."
    ),
    remediation="Remove the server, or ask the policy owner to review it and add the exact version or digest to the approved list.",
    cwe=("CWE-829",),
    owasp_llm=("LLM03:2025",),
    owasp_agentic=("ASI04:2026",),
)

_IDENT_KEYS = ("npm", "pypi", "oci", "url", "command")
_APPROVED_KEYS = frozenset(_IDENT_KEYS + ("version", "digest", "sha256", "note"))
_BANNED_KEYS = frozenset(_IDENT_KEYS + ("reason",))
_TOP_KEYS = frozenset({"schema_version", "max_severity", "require_approved", "approved", "banned"})
_REQUIRED_PIN = {"npm": "version", "pypi": "version", "oci": "digest", "command": "sha256"}
_EXACT_VERSION = re.compile(r"^v?[0-9]+(\.[0-9]+)*([.-]?[0-9A-Za-z]+)*(\+[0-9A-Za-z.]+)?$")
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")


class PolicyError(ValueError):
    def __init__(self, problems: list[Problem]) -> None:
        super().__init__("; ".join(f"{p.where}: {p.message}" for p in problems if p.level == "error"))
        self.problems = problems


@dataclass(frozen=True)
class Problem:
    level: str  # "error" | "warning"
    where: str
    message: str


@dataclass(frozen=True)
class Entry:
    where: str
    kind: str
    value: str
    version: str | None = None
    digest: str | None = None
    sha256: str | None = None
    reason: str | None = None


@dataclass(frozen=True)
class Policy:
    path: str
    sha256: str
    max_severity: Severity | None
    require_approved: bool
    approved: tuple[Entry, ...]
    banned: tuple[Entry, ...]


def normalise_url(url: str) -> str:
    try:
        p = urlsplit(url.strip())
    except ValueError:
        return url.strip()
    netloc = (p.hostname or "") + (f":{p.port}" if p.port else "")
    return f"{p.scheme.lower()}://{netloc.lower()}{p.path.rstrip('/')}" + (f"?{p.query}" if p.query else "")


def _normalise(kind: str, value: str) -> str:
    if kind == "npm":
        return value.lower()
    if kind == "pypi":
        return normalise_pypi(value)
    if kind == "oci":
        return normalise_oci(value)
    if kind == "url":
        return normalise_url(value)
    return os.path.normcase(value)


def _entries(raw: object, section: str, allowed: frozenset[str], problems: list[Problem]) -> list[Entry]:
    if raw is None:
        return []
    if not isinstance(raw, list):
        problems.append(Problem("error", section, "must be an array of tables ([[" + section + "]])"))
        return []
    out = []
    for i, item in enumerate(raw):
        where = f"{section}[{i}]"
        if not isinstance(item, dict):
            problems.append(Problem("error", where, "must be a table"))
            continue
        for key in sorted(set(item) - allowed):
            hint = " (not applicable to banned entries; a ban covers every version)" if key in ("version", "digest", "sha256") else ""
            problems.append(Problem("error", where, f"unknown key {key!r}{hint}"))
        kinds = [k for k in _IDENT_KEYS if k in item]
        if len(kinds) != 1:
            problems.append(Problem("error", where, f"needs exactly one of {', '.join(_IDENT_KEYS)}"))
            continue
        kind = kinds[0]
        value = item[kind]
        strings = {k: v for k, v in item.items() if k in allowed}
        if not all(isinstance(v, str) and v.strip() for v in strings.values()):
            problems.append(Problem("error", where, "every value must be a non-empty string"))
            continue
        out.append(
            Entry(
                where=where,
                kind=kind,
                value=_normalise(kind, value),
                version=item.get("version"),
                digest=item.get("digest"),
                sha256=item.get("sha256", "").lower() or None,
                reason=item.get("reason"),
            )
        )
    return out


def _check_approved(e: Entry, problems: list[Problem]) -> None:
    required = _REQUIRED_PIN.get(e.kind)
    given = {k for k in ("version", "digest", "sha256") if getattr(e, k)}
    if required and required not in given:
        problems.append(Problem("error", e.where, f"{e.kind} entries must pin a {required}"))
    for extra in sorted(given - ({required} if required else set())):
        problems.append(Problem("error", e.where, f"{extra} does not apply to {e.kind} entries"))
    if e.version and not _EXACT_VERSION.match(e.version):
        problems.append(Problem("error", e.where, f"version {e.version!r} is a range or tag; pin one exact version"))
    if e.digest and not _DIGEST.match(e.digest):
        problems.append(Problem("error", e.where, "digest must look like sha256:<64 lowercase hex>"))
    if e.sha256 and not _SHA256.match(e.sha256):
        problems.append(Problem("error", e.where, "sha256 must be 64 hex characters"))
    if e.kind == "command" and not os.path.isabs(e.value):
        problems.append(Problem("error", e.where, "command must be an absolute path"))
    if e.kind == "url":
        try:
            p = urlsplit(e.value)
        except ValueError:
            problems.append(Problem("error", e.where, "url is not a valid URL"))
            return
        if p.scheme not in ("https", "wss") and not (p.hostname and is_loopback(p.hostname)):
            problems.append(Problem("error", e.where, "approved remote servers must use https:// or wss://"))


def parse(text: str, *, path: str = "<policy>") -> tuple[Policy | None, list[Problem]]:
    problems: list[Problem] = []
    try:
        data = tomllib.loads(text)
    except tomllib.TOMLDecodeError as e:
        return None, [Problem("error", "file", f"invalid TOML: {e}")]

    for key in sorted(set(data) - _TOP_KEYS):
        problems.append(Problem("error", key, "unknown top-level key"))
    if data.get("schema_version") != SCHEMA_VERSION:
        problems.append(Problem("error", "schema_version", f"must be {SCHEMA_VERSION}"))

    max_severity = None
    if "max_severity" in data:
        try:
            max_severity = Severity.parse(str(data["max_severity"]))
        except ValueError:
            problems.append(Problem("error", "max_severity", f"must be one of {', '.join(s.label for s in Severity)}"))
    require_approved = data.get("require_approved", False)
    if not isinstance(require_approved, bool):
        problems.append(Problem("error", "require_approved", "must be true or false"))
        require_approved = False

    approved = _entries(data.get("approved"), "approved", _APPROVED_KEYS, problems)
    banned = _entries(data.get("banned"), "banned", _BANNED_KEYS, problems)
    for e in approved:
        _check_approved(e, problems)

    seen: dict[tuple[str, str, str | None, str | None, str | None], str] = {}
    for e in approved:
        key = (e.kind, e.value, e.version, e.digest, e.sha256)
        if key in seen:
            problems.append(Problem("warning", e.where, f"duplicates {seen[key]}"))
        seen.setdefault(key, e.where)
    banned_ids = {(e.kind, e.value): e.where for e in banned}
    for e in approved:
        if (e.kind, e.value) in banned_ids:
            problems.append(Problem("error", e.where, f"also banned by {banned_ids[(e.kind, e.value)]}"))

    if require_approved and not approved:
        problems.append(Problem("warning", "require_approved", "no approved servers are listed, so every server will violate"))
    if not require_approved and not banned and max_severity is None:
        problems.append(Problem("warning", "file", "policy enforces nothing: set require_approved, banned, or max_severity"))

    if any(p.level == "error" for p in problems):
        return None, problems
    digest = hashlib.sha256(text.encode()).hexdigest()
    return Policy(path, digest, max_severity, bool(require_approved), tuple(approved), tuple(banned)), problems


def load(path: Path) -> tuple[Policy, list[Problem]]:
    text = read_config(path, allowed_roots=[real(path).parent], max_bytes=1024 * 1024)
    policy, problems = parse(text, path=str(path))
    if policy is None:
        raise PolicyError(problems)
    return policy, problems


# --- evaluation --------------------------------------------------------------


@dataclass(frozen=True)
class Identity:
    kind: str
    value: str
    version: str | None = None  # exact version for npm/pypi, digest for oci, sha256 for command
    display: str = ""


def _split_version(kind: str, spec: str) -> tuple[str, str | None]:
    if kind == "npm":
        at = spec.rfind("@")
        return (spec[:at], spec[at + 1 :]) if at > 0 else (spec, None)
    name = re.split(r"[=<>!~;@\[\s]", spec, maxsplit=1)[0]
    m = re.search(r"(?:===?|@)\s*([0-9][0-9A-Za-z.+!-]*)\s*$", spec[len(name) :])
    return name, m.group(1) if m else None


def identities(server: ServerConfig) -> list[Identity]:
    """What actually runs for this server; one identity per downloaded package."""
    if server.url and server.transport != "stdio":
        return [Identity("url", normalise_url(server.url), display=server.url)]
    launch = unwrap(server)
    if launch is None:
        return []
    refs = packages(launch)
    if refs:
        out = []
        for ref in refs:
            if ref.ecosystem == "oci":
                digest = ref.spec.split("@", 1)[1] if "@sha256:" in ref.spec else None
                out.append(Identity("oci", normalise_oci(ref.spec), digest, ref.spec))
            else:
                name, version = _split_version(ref.ecosystem, ref.spec)
                out.append(Identity(ref.ecosystem, _normalise(ref.ecosystem, name), version, ref.spec))
        return out
    path = executed_paths(launch)[-1][0]
    return [Identity("command", os.path.normcase(path), None, path)]


def _approved(ident: Identity, entries: Iterable[Entry]) -> bool:
    for e in entries:
        if e.kind != ident.kind or e.value != ident.value:
            continue
        if ident.kind == "url":
            return True
        if ident.kind in ("npm", "pypi") and ident.version is not None and ident.version.lstrip("v") == (e.version or "").lstrip("v"):
            return True
        if ident.kind == "oci" and ident.version == e.digest:
            return True
        # Only paths the policy itself names are ever hashed, so a config cannot
        # make the tool read arbitrary files.
        if ident.kind == "command" and os.path.isabs(ident.value) and sha256_file(ident.display, max_bytes=MAX_HASH_BYTES) == e.sha256:
            return True
    return False


def _banned(ident: Identity, entries: Iterable[Entry]) -> Entry | None:
    for e in entries:
        if e.kind != ident.kind:
            continue
        if e.value == ident.value or (e.kind == "url" and e.value.endswith("*") and ident.value.startswith(e.value[:-1])):
            return e
    return None


@dataclass
class Evaluation:
    policy: Policy
    findings: list[Finding] = field(default_factory=list)
    violations: list[tuple[Finding, str]] = field(default_factory=list)

    @property
    def compliant(self) -> bool:
        return not self.violations


def evaluate(policy: Policy, inv: Inventory, findings: Sequence[Finding], homes: Sequence[Path] = ()) -> Evaluation:
    ctx = CheckContext(inv, tuple(homes))
    result = Evaluation(policy)
    for s in inv.servers:
        result.findings.extend(_server_findings(policy, ctx, s))
    for f in result.findings:
        result.violations.append((f, "banned" if f.severity == Severity.CRITICAL else "not_approved"))
    if policy.max_severity is not None:
        for f in findings:
            if f.severity > policy.max_severity:
                result.violations.append((f, "above_max_severity"))
    return result


def _server_findings(policy: Policy, ctx: CheckContext, s: ServerConfig) -> Iterator[Finding]:
    idents = identities(s)
    for ident in idents:
        ban = _banned(ident, policy.banned)
        if ban is not None:
            yield server_finding(
                INFO, ctx, s,
                evidence=f"{ident.kind} {ident.display} matches {ban.where}" + (f": {ban.reason}" if ban.reason else ""),
                severity=Severity.CRITICAL,
                title="Banned server is configured",
                discriminator=f"banned|{ident.kind}|{ident.value}",
            )
            return
    if not policy.require_approved:
        return
    unapproved = [i for i in idents if not _approved(i, policy.approved)] if idents else None
    if unapproved is None:
        yield server_finding(INFO, ctx, s, evidence="server has no command or URL to identify", discriminator="unidentified")
    elif unapproved:
        shown = ", ".join(f"{i.kind} {i.display}" for i in unapproved)
        yield server_finding(INFO, ctx, s, evidence=f"not approved: {shown}", discriminator="unapproved|" + shown)
