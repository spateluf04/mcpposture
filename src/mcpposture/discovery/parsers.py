"""Turn parsed configuration documents into ServerConfig and SettingsDoc records.

Every value here came from a file an attacker may control, so nothing is
trusted: wrong types become ScanIssues and the entry is skipped or narrowed,
never a crash.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

from mcpposture.jsonc import Document, escape_pointer_token
from mcpposture.model import Location, ScanIssue, ServerConfig, SettingsDoc, Transport

MAX_SERVERS_PER_MAP = 1000
MAX_ARGS = 500

INVALID_ENTRY = "invalid_entry"
INVALID_ROOT = "invalid_root"

_TRANSPORTS: dict[str, Transport] = {
    "stdio": "stdio",
    "http": "http",
    "streamable-http": "http",
    "streamablehttp": "http",
    "sse": "sse",
    "ws": "ws",
}


@dataclass(frozen=True)
class FileContext:
    path: Path
    client: str
    scope: str
    project: str | None


@dataclass
class Parsed:
    servers: list[ServerConfig] = field(default_factory=list)
    settings: SettingsDoc | None = None
    issues: list[ScanIssue] = field(default_factory=list)
    project_keys: list[str] = field(default_factory=list)


def server_id(client: str, path: Path, pointer: str) -> str:
    return hashlib.sha256(f"{client}\0{path}\0{pointer}".encode()).hexdigest()[:16]


class _Builder:
    def __init__(self, doc: Document, fc: FileContext) -> None:
        self.doc = doc
        self.fc = fc
        self.out = Parsed()

    def issue(self, pointer: str, detail: str, kind: str = INVALID_ENTRY) -> None:
        line = self.doc.lines.get(pointer)
        where = f"{pointer or '/'}" + (f" (line {line})" if line else "")
        self.out.issues.append(ScanIssue(self.fc.path, kind, f"{where}: {detail}"))

    def str_map(self, value: object, pointer: str) -> dict[str, str]:
        if value is None:
            return {}
        if not isinstance(value, dict):
            self.issue(pointer, "expected an object of strings")
            return {}
        out: dict[str, str] = {}
        for k, v in value.items():
            if isinstance(v, str):
                out[k] = v
            elif isinstance(v, (int, float, bool)):
                out[k] = str(v)
            else:
                self.issue(f"{pointer}/{escape_pointer_token(k)}", "expected a string value")
        return out

    def str_list(self, value: object, pointer: str) -> tuple[str, ...]:
        if value is None:
            return ()
        if not isinstance(value, list):
            self.issue(pointer, "expected an array of strings")
            return ()
        if len(value) > MAX_ARGS:
            self.issue(pointer, f"more than {MAX_ARGS} items; extra items ignored")
            value = value[:MAX_ARGS]
        out = []
        for i, item in enumerate(value):
            if isinstance(item, str):
                out.append(item)
            elif isinstance(item, (int, float)) and not isinstance(item, bool):
                out.append(str(item))
            else:
                self.issue(f"{pointer}/{i}", "expected a string")
        return tuple(out)

    def opt_str(self, entry: dict[str, object], key: str, pointer: str) -> str | None:
        value = entry.get(key)
        if value is None or isinstance(value, str):
            return value
        self.issue(f"{pointer}/{key}", "expected a string")
        return None

    def server(self, name: str, entry: object, pointer: str, scope: str, project: str | None) -> None:
        if not isinstance(entry, dict):
            self.issue(pointer, "server entry is not an object")
            return
        command = self.opt_str(entry, "command", pointer)
        url = self.opt_str(entry, "url", pointer)
        raw_type = entry.get("type")
        transport: Transport
        if isinstance(raw_type, str) and raw_type.lower() in _TRANSPORTS:
            transport = _TRANSPORTS[raw_type.lower()]
        elif raw_type is not None:
            self.issue(f"{pointer}/type", f"unrecognised transport type {str(raw_type)[:40]!r}")
            transport = "unknown"
        elif command:
            transport = "stdio"
        elif url:
            # Cursor and VS Code infer HTTP from a bare url; Claude Code rejects
            # it. Treat it as remote so transport checks still see the URL.
            transport = "http"
        else:
            transport = "unknown"
        self.out.servers.append(
            ServerConfig(
                id=server_id(self.fc.client, self.fc.path, pointer),
                name=name,
                client=self.fc.client,
                scope=scope,
                location=Location(self.fc.path, pointer, self.doc.lines.get(pointer)),
                project=project,
                transport=transport,
                command=command,
                args=self.str_list(entry.get("args"), f"{pointer}/args"),
                env=self.str_map(entry.get("env"), f"{pointer}/env"),
                url=url,
                headers=self.str_map(entry.get("headers"), f"{pointer}/headers"),
                env_file=self.opt_str(entry, "envFile", pointer),
                lines=self.doc.lines,
            )
        )

    def server_map(self, container: object, pointer: str, scope: str, project: str | None) -> None:
        if container is None:
            return
        if not isinstance(container, dict):
            self.issue(pointer, "expected an object mapping server names to entries")
            return
        items = list(container.items())
        if len(items) > MAX_SERVERS_PER_MAP:
            self.issue(pointer, f"more than {MAX_SERVERS_PER_MAP} servers; extra entries ignored")
            items = items[:MAX_SERVERS_PER_MAP]
        for name, entry in items:
            self.server(name, entry, f"{pointer}/{escape_pointer_token(name)}", scope, project)

    def root(self) -> dict[str, object] | None:
        if isinstance(self.doc.value, dict):
            return self.doc.value
        self.issue("", "top-level value is not an object", INVALID_ROOT)
        return None


def _mcp_servers(doc: Document, fc: FileContext) -> Parsed:
    b = _Builder(doc, fc)
    if (root := b.root()) is not None:
        b.server_map(root.get("mcpServers"), "/mcpServers", fc.scope, fc.project)
    return b.out


def _vscode_servers(doc: Document, fc: FileContext) -> Parsed:
    b = _Builder(doc, fc)
    if (root := b.root()) is not None:
        b.server_map(root.get("servers"), "/servers", fc.scope, fc.project)
    return b.out


def _claude_json(doc: Document, fc: FileContext) -> Parsed:
    """~/.claude.json: user-scope servers at the top, local-scope servers per project.

    The file also holds account details and history; only the MCP keys are read.
    """
    b = _Builder(doc, fc)
    root = b.root()
    if root is None:
        return b.out
    b.server_map(root.get("mcpServers"), "/mcpServers", "user", None)
    projects = root.get("projects")
    if isinstance(projects, dict):
        for key, proj in projects.items():
            b.out.project_keys.append(key)
            if isinstance(proj, dict):
                pointer = f"/projects/{escape_pointer_token(key)}/mcpServers"
                b.server_map(proj.get("mcpServers"), pointer, "local", key)
    elif projects is not None:
        b.issue("/projects", "expected an object")
    return b.out


def _settings(doc: Document, fc: FileContext) -> Parsed:
    b = _Builder(doc, fc)
    if (root := b.root()) is not None:
        b.out.settings = SettingsDoc(fc.client, fc.scope, fc.path, fc.project, root, doc.lines)
        # Claude Code honours managedMcpServers only from managed settings sources.
        if fc.client == "claude-code" and fc.scope == "managed":
            b.server_map(root.get("managedMcpServers"), "/managedMcpServers", "managed", None)
        # Before 1.102 VS Code kept servers under "mcp" in settings.json; current
        # versions migrate them to mcp.json, so anything left here is reported.
        legacy = root.get("mcp")
        if fc.client.startswith("vscode") and isinstance(legacy, dict):
            b.server_map(legacy.get("servers"), "/mcp/servers", fc.scope, fc.project)
    return b.out


def _auto(doc: Document, fc: FileContext) -> Parsed:
    """A file passed explicitly with --path whose name matches no known location."""
    if isinstance(doc.value, dict) and "servers" in doc.value and "mcpServers" not in doc.value:
        return _vscode_servers(doc, fc)
    return _mcp_servers(doc, fc)


PARSERS: dict[str, Callable[[Document, FileContext], Parsed]] = {
    "mcp_servers": _mcp_servers,
    "vscode_servers": _vscode_servers,
    "claude_json": _claude_json,
    "claude_settings": _settings,
    "vscode_settings": _settings,
    "auto": _auto,
}
