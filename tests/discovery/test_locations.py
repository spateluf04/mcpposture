from pathlib import Path

import pytest

from mcpposture.discovery import locations
from mcpposture.discovery.hostinfo import bases_for
from mcpposture.discovery.locations import LOCATIONS, classify, expand, project_root
from mcpposture.discovery.parsers import PARSERS

from conftest import write

BASE_NAMES = set(bases_for("linux", Path("/h"), {}))


@pytest.mark.parametrize("loc", LOCATIONS, ids=lambda loc: f"{loc.client}:{loc.path}")
def test_every_row_is_well_formed(loc):
    assert loc.fmt in PARSERS
    assert loc.doc.startswith("https://")
    if loc.is_project:
        assert loc.base is None and not loc.path.startswith(("/", "{"))
    else:
        assert loc.base in BASE_NAMES


def _expanded(os_name, client, fmt="mcp_servers"):
    home = Path("/u")
    bases = bases_for(os_name, home, {})
    rows = [loc for loc in locations.USER_LOCATIONS if loc.client == client and loc.fmt == fmt and "*" not in loc.path]
    return [p.as_posix() for loc in rows for p in expand(loc, bases)]


@pytest.mark.parametrize(
    ("os_name", "expected"),
    [
        ("windows", "/u/AppData/Roaming/Claude/claude_desktop_config.json"),
        ("macos", "/u/Library/Application Support/Claude/claude_desktop_config.json"),
        ("linux", "/u/.config/Claude/claude_desktop_config.json"),
    ],
)
def test_claude_desktop_paths(os_name, expected):
    assert _expanded(os_name, "claude-desktop") == [expected]


def test_claude_code_and_cursor_user_paths():
    assert _expanded("linux", "claude-code", "claude_json") == ["/u/.claude.json"]
    assert _expanded("linux", "claude-code", "claude_settings")[-1] == "/u/.claude/settings.json"
    assert _expanded("macos", "cursor") == ["/u/.cursor/mcp.json"]
    assert _expanded("windows", "vscode", "vscode_servers") == ["/u/AppData/Roaming/Code/User/mcp.json"]


def test_glob_rows_expand_to_existing_profiles(tmp_path):
    write(tmp_path / "Code" / "User" / "profiles" / "abc123" / "mcp.json", "{}")
    row = next(loc for loc in LOCATIONS if loc.scope == "profile" and loc.fmt == "vscode_servers" and loc.client == "vscode")
    assert expand(row, {"app_support": tmp_path}) == [tmp_path / "Code" / "User" / "profiles" / "abc123" / "mcp.json"]


@pytest.mark.parametrize(
    ("rel", "expected"),
    [
        ("repo/.cursor/mcp.json", [("cursor", "project")]),
        ("repo/.vscode/mcp.json", [("vscode", "project")]),
        ("repo/.mcp.json", [("claude-code", "project"), ("vscode", "project")]),
        ("repo/.claude/settings.json", [("claude-code", "project")]),
        ("repo/.claude/settings.local.json", [("claude-code", "local")]),
        ("home/.claude.json", [("claude-code", "user")]),
        ("x/Claude/claude_desktop_config.json", [("claude-desktop", "user")]),
        ("x/Code/User/mcp.json", [("vscode", "user")]),
        ("x/Code - Insiders/User/mcp.json", [("vscode-insiders", "user")]),
        ("x/Code/User/profiles/p1/mcp.json", [("vscode", "profile")]),
        ("x/ClaudeCode/managed-mcp.json", [("claude-code", "managed")]),
        ("x/managed-settings.d/10-base.json", [("claude-code", "managed")]),
        ("home/.vscode-server/data/User/mcp.json", [("vscode-remote", "user")]),
        ("home/.vscode-server/data/Machine/settings.json", [("vscode-remote", "user")]),
        ("repo/.vscode/settings.json", []),
        ("repo/settings.json", []),
        ("repo/mcp.json", []),
    ],
)
def test_classify(rel, expected):
    assert [(loc.client, loc.scope) for loc in classify(Path(rel))] == expected


def test_project_root():
    path = Path("/r/app/.cursor/mcp.json")
    loc = classify(path)[0]
    assert project_root(path, loc) == Path("/r/app")
