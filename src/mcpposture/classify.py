"""Classify servers into Rule of Two capability flags using the versioned rules file."""

from __future__ import annotations

import functools
import re
import tomllib
from dataclasses import dataclass
from importlib import resources
from typing import Iterable
from urllib.parse import urlsplit

from mcpposture.checks.launch import packages, program_name, unwrap
from mcpposture.model import Classification, Inventory, ServerConfig

FLAGS = ("A", "B", "C")
SCHEMA_VERSION = 1
_SERVER_KEYS = frozenset({"id", "npm", "pypi", "oci", "url_host", "command", "capabilities", "rationale", "reference"})
_MATCH_KEYS = ("npm", "pypi", "oci", "url_host", "command")
_HEURISTIC_KEYS = frozenset({"id", "pattern", "capabilities", "rationale"})
# Bounds regex work on attacker-sized argument lists.
_MAX_HEURISTIC_TEXT = 4096


class RulesError(ValueError):
    pass


@dataclass(frozen=True)
class ServerRule:
    id: str
    npm: frozenset[str]
    pypi: frozenset[str]
    oci: frozenset[str]
    url_host: frozenset[str]
    command: frozenset[str]
    capabilities: frozenset[str]
    rationale: str


@dataclass(frozen=True)
class Heuristic:
    id: str
    pattern: re.Pattern[str]
    capabilities: frozenset[str]


@dataclass(frozen=True)
class Rules:
    version: str
    servers: tuple[ServerRule, ...]
    heuristics: tuple[Heuristic, ...]


def _str_list(entry: dict[str, object], key: str, where: str) -> list[str]:
    value = entry.get(key, [])
    if not isinstance(value, list) or not all(isinstance(v, str) and v for v in value):
        raise RulesError(f"{where}: {key} must be a list of non-empty strings")
    return value


def _capabilities(entry: dict[str, object], where: str) -> frozenset[str]:
    caps = _str_list(entry, "capabilities", where)
    if "capabilities" not in entry:
        raise RulesError(f"{where}: capabilities is required (use [] for none)")
    bad = [c for c in caps if c not in FLAGS]
    if bad:
        raise RulesError(f"{where}: unknown capability {bad[0]!r}; use A, B or C")
    return frozenset(caps)


def normalise_pypi(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def normalise_oci(image: str) -> str:
    repo = image.split("@", 1)[0]
    head, _, last = repo.rpartition("/")
    last = last.split(":", 1)[0]
    repo = f"{head}/{last}" if head else last
    for prefix in ("docker.io/library/", "docker.io/", "index.docker.io/"):
        if repo.startswith(prefix):
            repo = repo[len(prefix) :]
    return repo.lower()


def parse_rules(text: str) -> Rules:
    try:
        data = tomllib.loads(text)
    except tomllib.TOMLDecodeError as e:
        raise RulesError(f"invalid TOML: {e}") from None
    unknown = set(data) - {"schema_version", "rules_version", "server", "heuristic"}
    if unknown:
        raise RulesError(f"unknown top-level key {sorted(unknown)[0]!r}")
    if data.get("schema_version") != SCHEMA_VERSION:
        raise RulesError(f"schema_version must be {SCHEMA_VERSION}")
    version = data.get("rules_version")
    if not isinstance(version, str) or not version:
        raise RulesError("rules_version is required")

    ids: set[str] = set()

    def take_id(entry: dict[str, object], where: str) -> str:
        rule_id = entry.get("id")
        if not isinstance(rule_id, str) or not rule_id:
            raise RulesError(f"{where}: id is required")
        if rule_id in ids:
            raise RulesError(f"{where}: duplicate id {rule_id!r}")
        ids.add(rule_id)
        return rule_id

    servers = []
    for i, entry in enumerate(data.get("server", [])):
        where = f"server[{i}]"
        if extra := set(entry) - _SERVER_KEYS:
            raise RulesError(f"{where}: unknown key {sorted(extra)[0]!r}")
        rule_id = take_id(entry, where)
        if not any(entry.get(k) for k in _MATCH_KEYS):
            raise RulesError(f"{where}: needs at least one of {', '.join(_MATCH_KEYS)}")
        servers.append(
            ServerRule(
                id=rule_id,
                npm=frozenset(n.lower() for n in _str_list(entry, "npm", where)),
                pypi=frozenset(normalise_pypi(n) for n in _str_list(entry, "pypi", where)),
                oci=frozenset(normalise_oci(n) for n in _str_list(entry, "oci", where)),
                url_host=frozenset(h.lower() for h in _str_list(entry, "url_host", where)),
                command=frozenset(program_name(c) for c in _str_list(entry, "command", where)),
                capabilities=_capabilities(entry, where),
                rationale=str(entry.get("rationale", "")),
            )
        )

    heuristics = []
    for i, entry in enumerate(data.get("heuristic", [])):
        where = f"heuristic[{i}]"
        if extra := set(entry) - _HEURISTIC_KEYS:
            raise RulesError(f"{where}: unknown key {sorted(extra)[0]!r}")
        rule_id = take_id(entry, where)
        pattern = entry.get("pattern")
        if not isinstance(pattern, str) or not pattern:
            raise RulesError(f"{where}: pattern is required")
        try:
            compiled = re.compile(pattern)
        except re.error as e:
            raise RulesError(f"{where}: invalid pattern: {e}") from None
        heuristics.append(Heuristic(rule_id, compiled, _capabilities(entry, where)))
    return Rules(version, tuple(servers), tuple(heuristics))


@functools.cache
def default_rules() -> Rules:
    return parse_rules(resources.files("mcpposture").joinpath("data/rules.toml").read_text(encoding="utf-8"))


@dataclass(frozen=True)
class _Identity:
    npm: frozenset[str]
    pypi: frozenset[str]
    oci: frozenset[str]
    url_host: str | None
    command: str | None


def _identity(server: ServerConfig) -> _Identity:
    npm: set[str] = set()
    pypi: set[str] = set()
    oci: set[str] = set()
    command = None
    launch = unwrap(server)
    if launch is not None:
        command = launch.program
        for ref in packages(launch):
            if ref.ecosystem == "npm":
                at = ref.spec.rfind("@")
                npm.add((ref.spec[:at] if at > 0 else ref.spec).lower())
            elif ref.ecosystem == "pypi":
                pypi.add(normalise_pypi(re.split(r"[=<>!~;@\[\s]", ref.spec, maxsplit=1)[0]))
            elif ref.ecosystem == "oci":
                oci.add(normalise_oci(ref.spec))
    host = None
    if server.url:
        try:
            host = (urlsplit(server.url.strip()).hostname or "").lower() or None
        except ValueError:
            host = None
    return _Identity(frozenset(npm), frozenset(pypi), frozenset(oci), host, command)


def classify(server: ServerConfig, rules: Rules) -> Classification:
    ident = _identity(server)
    for rule in rules.servers:
        if (
            ident.npm & rule.npm
            or ident.pypi & rule.pypi
            or ident.oci & rule.oci
            or (ident.url_host is not None and ident.url_host in rule.url_host)
            or (ident.command is not None and ident.command in rule.command)
        ):
            return Classification(rule.capabilities, "rule", (rule.id,))

    text = " ".join([server.name, server.command or "", *server.args, server.url or ""])[:_MAX_HEURISTIC_TEXT]
    matched = [h for h in rules.heuristics if h.pattern.search(text)]
    if matched:
        flags = frozenset().union(*(h.capabilities for h in matched))
        return Classification(flags, "heuristic", tuple(h.id for h in matched))
    return Classification(frozenset(), "unclassified")


def annotate(inv: Inventory, rules: Rules | None = None) -> None:
    rules = rules or default_rules()
    inv.rules_version = rules.version
    inv.capabilities = {s.id: classify(s, rules) for s in inv.servers}


def union(classes: Iterable[Classification]) -> frozenset[str]:
    return frozenset().union(*(c.flags for c in classes))
