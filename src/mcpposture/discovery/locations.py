"""Every configuration file location MCPosture knows about, in one table.

User-level paths are templates over the per-OS base directories defined in
``hostinfo.bases_for``; project-level paths are relative to a project root.
Adding a client or a file is one ``ConfigLocation`` row.
"""

from __future__ import annotations

import fnmatch
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Mapping

PROJECT_SCOPES = frozenset({"project", "local"})

DOC_MCP_LOCAL = "https://modelcontextprotocol.io/docs/develop/connect-local-servers"
DOC_CC_MCP = "https://code.claude.com/docs/en/mcp"
DOC_CC_SETTINGS = "https://code.claude.com/docs/en/settings"
DOC_CC_MANAGED_MCP = "https://code.claude.com/docs/en/managed-mcp"
DOC_CC_MANAGED_SETTINGS = "https://code.claude.com/docs/en/managed-settings"
DOC_CURSOR = "https://cursor.com/docs/context/mcp"
DOC_VSCODE_MCP = "https://code.visualstudio.com/docs/agents/reference/mcp-configuration"
DOC_VSCODE_PROFILES = "https://code.visualstudio.com/docs/configure/profiles"
DOC_VSCODE_APPROVALS = "https://code.visualstudio.com/docs/agents/run/approvals"


@dataclass(frozen=True)
class ConfigLocation:
    client: str
    scope: str  # managed | global | user | profile | project | local
    fmt: str  # parser id, see parsers.PARSERS
    path: str  # "{base}/rest" for user-level rows, relative for project rows
    doc: str
    # VS Code setting that must be true for the row to apply (experimental features).
    enabled_by: str | None = None

    @property
    def is_project(self) -> bool:
        return self.scope in PROJECT_SCOPES

    @property
    def base(self) -> str | None:
        if self.path.startswith("{"):
            return self.path[1 : self.path.index("}")]
        return None

    @property
    def tail(self) -> tuple[str, ...]:
        rel = self.path[self.path.index("}") + 2 :] if self.base else self.path
        return PurePosixPath(rel).parts

    @property
    def match_tail(self) -> tuple[str, ...]:
        """Components used to recognise this file during a --path walk.

        A base that is itself a dot-directory contributes its default name, so
        ``{claude_dir}/settings.json`` matches ``.claude/settings.json`` rather
        than every ``settings.json``.
        """
        return _BASE_DIR_NAMES.get(self.base or "", ()) + self.tail


# fmt: off
LOCATIONS: tuple[ConfigLocation, ...] = (
    # client            scope      format             path
    ConfigLocation("claude-desktop", "user", "mcp_servers", "{app_support}/Claude/claude_desktop_config.json", DOC_MCP_LOCAL),
    ConfigLocation("claude-code", "managed", "mcp_servers", "{claude_managed}/managed-mcp.json", DOC_CC_MANAGED_MCP),
    ConfigLocation("claude-code", "managed", "claude_settings", "{claude_managed}/managed-settings.json", DOC_CC_MANAGED_SETTINGS),
    ConfigLocation("claude-code", "managed", "claude_settings", "{claude_managed}/managed-settings.d/*.json", DOC_CC_MANAGED_SETTINGS),
    ConfigLocation("claude-code", "user", "claude_json", "{claude_state}/.claude.json", DOC_CC_MCP),
    ConfigLocation("claude-code", "user", "claude_settings", "{claude_dir}/settings.json", DOC_CC_SETTINGS),
    ConfigLocation("claude-code", "project", "mcp_servers", ".mcp.json", DOC_CC_MCP),
    ConfigLocation("claude-code", "project", "claude_settings", ".claude/settings.json", DOC_CC_SETTINGS),
    ConfigLocation("claude-code", "local", "claude_settings", ".claude/settings.local.json", DOC_CC_SETTINGS),
    ConfigLocation("cursor", "user", "mcp_servers", "{home}/.cursor/mcp.json", DOC_CURSOR),
    ConfigLocation("cursor", "project", "mcp_servers", ".cursor/mcp.json", DOC_CURSOR),
    ConfigLocation("vscode", "global", "mcp_servers", "{copilot_home}/mcp-config.json", DOC_VSCODE_MCP),
    ConfigLocation("vscode", "user", "vscode_servers", "{app_support}/Code/User/mcp.json", DOC_VSCODE_MCP),
    ConfigLocation("vscode", "profile", "vscode_servers", "{app_support}/Code/User/profiles/*/mcp.json", DOC_VSCODE_PROFILES),
    ConfigLocation("vscode", "user", "vscode_settings", "{app_support}/Code/User/settings.json", DOC_VSCODE_APPROVALS),
    ConfigLocation("vscode", "profile", "vscode_settings", "{app_support}/Code/User/profiles/*/settings.json", DOC_VSCODE_APPROVALS),
    ConfigLocation("vscode", "project", "vscode_servers", ".vscode/mcp.json", DOC_VSCODE_MCP),
    ConfigLocation("vscode", "project", "mcp_servers", ".mcp.json", DOC_VSCODE_MCP, enabled_by="chat.mcp.workspaceRootConfig.enabled"),
    ConfigLocation("vscode-insiders", "user", "vscode_servers", "{app_support}/Code - Insiders/User/mcp.json", DOC_VSCODE_MCP),
    ConfigLocation("vscode-insiders", "profile", "vscode_servers", "{app_support}/Code - Insiders/User/profiles/*/mcp.json", DOC_VSCODE_PROFILES),
    ConfigLocation("vscode-insiders", "user", "vscode_settings", "{app_support}/Code - Insiders/User/settings.json", DOC_VSCODE_APPROVALS),
)
# fmt: on

_BASE_DIR_NAMES: dict[str, tuple[str, ...]] = {
    "claude_dir": (".claude",),
    "copilot_home": (".copilot",),
}

USER_LOCATIONS = tuple(loc for loc in LOCATIONS if not loc.is_project)
PROJECT_LOCATIONS = tuple(loc for loc in LOCATIONS if loc.is_project)

CANDIDATE_NAMES = frozenset(loc.tail[-1] for loc in LOCATIONS if "*" not in loc.tail[-1])


def expand(loc: ConfigLocation, bases: Mapping[str, Path]) -> list[Path]:
    if loc.base is None:
        raise ValueError(f"{loc.path} is project-relative")
    root = bases[loc.base]
    rest = "/".join(loc.tail)
    if "*" in rest:
        try:
            return sorted(root.glob(rest))
        except OSError:
            return []
    return [root / rest]


def tail_matches(path: Path, tail: tuple[str, ...]) -> bool:
    parts = path.parts
    if len(parts) < len(tail):
        return False
    return all(
        fnmatch.fnmatchcase(p.casefold(), t.casefold()) for p, t in zip(parts[-len(tail) :], tail)
    )


def is_candidate(path: Path) -> bool:
    return path.name in CANDIDATE_NAMES or (path.suffix == ".json" and path.parent.name == "managed-settings.d")


def classify(path: Path) -> list[ConfigLocation]:
    """Rows a file found during a --path walk matches, most specific first.

    Project rows win over user rows with the same tail (``.cursor/mcp.json``
    exists at both levels); a repository is scanned as a project.
    """
    matches = [loc for loc in LOCATIONS if tail_matches(path, loc.match_tail)]
    if not matches:
        return []
    best_len = max(len(loc.match_tail) for loc in matches)
    best = [loc for loc in matches if len(loc.match_tail) == best_len]
    project = [loc for loc in best if loc.is_project]
    return project or best


def project_root(path: Path, loc: ConfigLocation) -> Path:
    root = path
    for _ in loc.tail:
        root = root.parent
    return root
