"""Find configuration files, parse them, and group servers into agent contexts."""

from __future__ import annotations

import os
from collections import defaultdict
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Callable, Iterable, Sequence

from mcpposture import jsonc
from mcpposture.discovery import locations
from mcpposture.discovery.hostinfo import Host, LocationSet, location_sets, project_path
from mcpposture.discovery.locations import ConfigLocation
from mcpposture.discovery.parsers import PARSERS, FileContext
from mcpposture.discovery.walk import walk
from mcpposture.model import AgentContext, FileRecord, Inventory, ScanIssue, ServerConfig
from mcpposture.safefs import DEFAULT_MAX_BYTES, MISSING, SafeReadError, real, read_config

PARSE_ERROR = "parse_error"
LIMIT_REACHED = "limit_reached"

_AUTO = ConfigLocation("unknown", "file", "auto", "", doc="")


@dataclass(frozen=True)
class Limits:
    max_file_bytes: int = DEFAULT_MAX_BYTES
    max_depth: int = 8
    max_entries: int = 200_000
    max_projects: int = 2000


class ScanError(Exception):
    """A problem with the scan request itself (exit code 2), not with a config file."""


def norm(path: Path | str) -> str:
    return os.path.normcase(os.path.abspath(path))


class _Collector:
    def __init__(self, limits: Limits, project_mapper: Callable[[str], str]) -> None:
        self.limits = limits
        self.inv = Inventory()
        self.project_keys: list[str] = []
        self._map_project = project_mapper
        self._docs: dict[str, jsonc.Document | None] = {}
        self._done: set[tuple[str, str]] = set()

    def read(self, path: Path, loc: ConfigLocation, project: str | None, roots: Sequence[Path]) -> None:
        key = norm(real(path))
        if (key, loc.client) in self._done:
            return
        if key in self._docs:
            doc = self._docs[key]
            if doc is None:
                return
        else:
            doc = self._load(path, loc, roots)
            if doc is None:
                return
        self._done.add((key, loc.client))

        parsed = PARSERS[loc.fmt](doc, FileContext(path, loc.client, loc.scope, project))
        servers = [
            s if s.scope != "local" or s.project is None else _with_project(s, self._map_project(s.project))
            for s in parsed.servers
        ]
        self.inv.servers.extend(servers)
        self.inv.issues.extend(parsed.issues)
        self.project_keys.extend(parsed.project_keys)
        if parsed.settings is not None:
            self.inv.settings.append(parsed.settings)
        self.inv.files.append(FileRecord(path, loc.client, loc.scope, loc.fmt, "ok", len(servers)))

    def _load(self, path: Path, loc: ConfigLocation, roots: Sequence[Path]) -> jsonc.Document | None:
        key = norm(real(path))
        try:
            text = read_config(path, allowed_roots=roots, max_bytes=self.limits.max_file_bytes)
        except SafeReadError as e:
            if e.kind == MISSING:
                return None
            self._fail(key, path, loc, e.kind, e.detail)
            return None
        try:
            doc = jsonc.loads(text)
        except jsonc.JsoncError as e:
            self._fail(key, path, loc, PARSE_ERROR, str(e))
            return None
        self._docs[key] = doc
        return doc

    def _fail(self, key: str, path: Path, loc: ConfigLocation, kind: str, detail: str) -> None:
        self._docs[key] = None
        self.inv.issues.append(ScanIssue(path, kind, detail))
        self.inv.files.append(FileRecord(path, loc.client, loc.scope, loc.fmt, "error"))


def _with_project(server: ServerConfig, project: str) -> ServerConfig:
    return replace(server, project=project)


def _project_mapper(host: Host) -> Callable[[str], str]:
    def mapper(key: str) -> str:
        p = project_path(key, host)
        return norm(p) if p is not None else key

    return mapper


def enabled_settings(inv: Inventory) -> set[str]:
    """VS Code setting keys explicitly set to true in any discovered VS Code settings file."""
    return {
        k
        for s in inv.settings
        if s.client.startswith("vscode")
        for k, v in s.data.items()
        if v is True
    }


def _read_rows(c: _Collector, rows: Iterable[tuple[Path, ConfigLocation, str | None]], roots: Sequence[Path]) -> None:
    rows = list(rows)
    for path, loc, project in rows:
        if loc.enabled_by is None:
            c.read(path, loc, project, roots)
    enabled = enabled_settings(c.inv)
    for path, loc, project in rows:
        if loc.enabled_by is not None and loc.enabled_by in enabled:
            c.read(path, loc, project, roots)


def scan_local(
    host: Host,
    *,
    cwd: Path,
    limits: Limits = Limits(),
    sets: Sequence[LocationSet] | None = None,
) -> Inventory:
    """Scan the known per-user and managed locations, then every project those configs mention."""
    sets = list(sets) if sets is not None else location_sets(host)
    c = _Collector(limits, _project_mapper(host))
    user_roots = [base for ls in sets for base in ls.bases.values()]
    for ls in sets:
        for loc in locations.USER_LOCATIONS:
            for path in locations.expand(loc, ls.bases):
                c.read(path, loc, None, user_roots)

    candidates = [cwd] + [p for k in c.project_keys if (p := project_path(k, host)) is not None]
    seen: set[str] = set()
    scanned = 0
    for project in candidates:
        key = norm(project)
        if key in seen:
            continue
        seen.add(key)
        try:
            if not project.is_dir():
                continue
        except OSError:
            continue
        if scanned >= limits.max_projects:
            c.inv.issues.append(
                ScanIssue(project, LIMIT_REACHED, f"stopped after {limits.max_projects} project directories")
            )
            break
        scanned += 1
        rows = ((project / loc.path, loc, key) for loc in locations.PROJECT_LOCATIONS)
        _read_rows(c, rows, [project])

    c.inv.contexts = build_contexts(c.inv)
    return c.inv


def scan_path(target: Path, host: Host, *, limits: Limits = Limits()) -> Inventory:
    """Scan one file, or a directory tree, without leaving it."""
    if not os.path.lexists(target):
        raise ScanError(f"{target}: no such file or directory")
    c = _Collector(limits, _project_mapper(host))
    if os.path.isdir(target):
        root = real(target)
        result = walk(root, max_depth=limits.max_depth, max_entries=limits.max_entries)
        if result.truncated:
            c.inv.issues.append(
                ScanIssue(root, LIMIT_REACHED, f"stopped after {limits.max_entries} directory entries")
            )
        rows = [
            (path, loc, norm(locations.project_root(path, loc)) if loc.is_project else None)
            for path in result.files
            if locations.is_candidate(path)
            for loc in locations.classify(path)
        ]
        _read_rows(c, rows, [root])
    else:
        path = Path(target)
        root = real(path.parent)
        rows = [
            (path, loc, norm(locations.project_root(path, loc)) if loc.is_project else None)
            for loc in (locations.classify(path) or [_AUTO])
        ]
        _read_rows(c, rows, [root])
    c.inv.contexts = build_contexts(c.inv)
    return c.inv


def _merge(groups: Iterable[list[ServerConfig]]) -> tuple[str, ...]:
    """Later groups override earlier ones by server name, as each client resolves duplicates."""
    by_name: dict[str, ServerConfig] = {}
    for group in groups:
        for s in group:
            by_name[s.name] = s
    return tuple(s.id for s in by_name.values())


def build_contexts(inv: Inventory) -> list[AgentContext]:
    by_client: dict[str, list[ServerConfig]] = defaultdict(list)
    for s in inv.servers:
        by_client[s.client].append(s)

    out: list[AgentContext] = []

    def add(ctx_id: str, client: str, project: str | None, groups: Iterable[list[ServerConfig]]) -> None:
        ids = _merge(groups)
        if ids:
            out.append(AgentContext(ctx_id, client, project, ids))

    for client in sorted(by_client):
        servers = by_client[client]
        if client in ("claude-desktop", "unknown"):
            by_file: dict[str, list[ServerConfig]] = defaultdict(list)
            for s in servers:
                by_file[str(s.location.path)].append(s)
            for path in sorted(by_file):
                add(f"{client}:file:{path}", client, None, [by_file[path]])
            continue

        scoped: dict[str, list[ServerConfig]] = defaultdict(list)
        for s in servers:
            scoped[s.scope].append(s)

        # A readable managed-mcp.json gives Claude Code exclusive control: no
        # user, local, project or plugin server loads alongside it.
        exclusive = client == "claude-code" and any(
            f.client == client and f.scope == "managed" and f.fmt == "mcp_servers" and f.status == "ok"
            for f in inv.files
        )
        if exclusive:
            add(f"{client}:managed", client, None, [scoped["managed"]])
            continue

        base = [scoped["managed"], scoped["global"], scoped["user"]]
        add(f"{client}:user", client, None, base)

        by_profile: dict[str, list[ServerConfig]] = defaultdict(list)
        for s in scoped["profile"]:
            by_profile[str(s.location.path.parent)].append(s)
        for profile in sorted(by_profile):
            add(f"{client}:profile:{profile}", client, None, [scoped["managed"], scoped["global"], by_profile[profile]])

        by_project: dict[str, dict[str, list[ServerConfig]]] = defaultdict(lambda: defaultdict(list))
        for scope in ("project", "local"):
            for s in scoped[scope]:
                by_project[s.project or ""][scope].append(s)
        for project in sorted(by_project):
            groups = by_project[project]
            add(f"{client}:project:{project}", client, project or None, base + [groups["project"], groups["local"]])
    return out
