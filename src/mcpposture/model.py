"""Data model shared by discovery, checks, and reporting."""

from __future__ import annotations

import enum
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal, Mapping

Transport = Literal["stdio", "http", "sse", "ws", "unknown"]


class Severity(enum.IntEnum):
    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @property
    def label(self) -> str:
        return self.name.lower()

    @classmethod
    def parse(cls, value: str) -> Severity:
        try:
            return cls[value.strip().upper()]
        except KeyError:
            raise ValueError(f"unknown severity {value!r}") from None


@dataclass(frozen=True)
class Location:
    path: Path
    pointer: str = ""
    line: int | None = None


@dataclass(frozen=True)
class ServerConfig:
    id: str
    name: str
    client: str
    scope: str
    location: Location
    project: str | None
    transport: Transport
    command: str | None = None
    args: tuple[str, ...] = ()
    env: Mapping[str, str] = field(default_factory=dict)
    url: str | None = None
    headers: Mapping[str, str] = field(default_factory=dict)
    env_file: str | None = None
    # Line of every JSON pointer in the source file, so findings on a single
    # env var or arg can point at its exact line. Shared with the parsed doc.
    lines: Mapping[str, int] = field(default_factory=dict, compare=False, repr=False)

    def line_of(self, pointer: str) -> int | None:
        return self.lines.get(pointer, self.location.line)


@dataclass(frozen=True)
class SettingsDoc:
    """A client settings file (permissions, auto-approval); holds no servers."""

    client: str
    scope: str
    path: Path
    project: str | None
    data: Mapping[str, object]
    lines: Mapping[str, int]


@dataclass(frozen=True)
class AgentContext:
    """The set of servers one client loads together: the Rule of Two "session" unit."""

    id: str
    client: str
    project: str | None
    server_ids: tuple[str, ...]


@dataclass(frozen=True)
class FileRecord:
    path: Path
    client: str
    scope: str
    fmt: str
    status: Literal["ok", "error"]
    servers: int = 0


@dataclass(frozen=True)
class ScanIssue:
    path: Path
    kind: str
    detail: str


@dataclass(frozen=True)
class Finding:
    check_id: str
    severity: Severity
    title: str
    why: str
    remediation: str
    cwe: tuple[str, ...]
    owasp_llm: tuple[str, ...]
    client: str
    location: Location
    evidence: str
    fingerprint: str
    server: str | None = None
    context_id: str | None = None
    owasp_agentic: tuple[str, ...] = ()


@dataclass
class Inventory:
    files: list[FileRecord] = field(default_factory=list)
    servers: list[ServerConfig] = field(default_factory=list)
    settings: list[SettingsDoc] = field(default_factory=list)
    contexts: list[AgentContext] = field(default_factory=list)
    issues: list[ScanIssue] = field(default_factory=list)
