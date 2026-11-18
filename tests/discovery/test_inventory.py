from pathlib import Path

import pytest

from mcpposture.discovery.hostinfo import Host, LocationSet, bases_for, current_os
from mcpposture.discovery.inventory import ScanError, norm, scan_local, scan_path

from conftest import make_symlink, write

HOST = Host(os=current_os(), is_wsl=False, home=Path("/nonexistent-home"))


def ctx_map(inv):
    by_id = {s.id: s for s in inv.servers}
    return {c.id: sorted(by_id[i].name for i in c.server_ids) for c in inv.contexts}


def ctx_ids_for(inv, client):
    return {k: v for k, v in ctx_map(inv).items() if k.startswith(client + ":")}


# --- --path mode -------------------------------------------------------------


def make_repo(root: Path) -> Path:
    write(root / ".mcp.json", {"mcpServers": {"github": {"type": "http", "url": "https://api.example.com/mcp"}}})
    write(
        root / ".cursor" / "mcp.json",
        '{\n  // cursor allows comments\n  "mcpServers": {"fs": {"command": "npx", "args": ["-y", "pkg"],},},\n}',
    )
    write(root / ".vscode" / "mcp.json", {"servers": {"browser": {"command": "npx", "args": ["@playwright/mcp"]}}})
    write(root / "packages" / "api" / ".mcp.json", {"mcpServers": {"db": {"command": "db-mcp"}}})
    write(root / ".claude" / "settings.json", {"permissions": {"allow": ["Bash(npm test)"]}})
    return root


def test_scan_path_finds_every_client(tmp_path):
    root = make_repo(tmp_path / "repo")
    inv = scan_path(root, HOST)
    assert {(f.client, f.scope, f.status) for f in inv.files} == {
        ("claude-code", "project", "ok"),
        ("cursor", "project", "ok"),
        ("vscode", "project", "ok"),
    }
    assert len(inv.settings) == 1
    rroot = norm(root.resolve())
    rsub = norm((root / "packages" / "api").resolve())
    assert ctx_map(inv) == {
        f"claude-code:project:{rroot}": ["github"],
        f"claude-code:project:{rsub}": ["db"],
        f"cursor:project:{rroot}": ["fs"],
        f"vscode:project:{rroot}": ["browser"],
    }
    assert inv.issues == []


def test_root_mcp_json_counts_for_vscode_only_when_enabled(tmp_path):
    root = make_repo(tmp_path / "repo")
    assert "github" not in sum(ctx_ids_for(scan_path(root, HOST), "vscode").values(), [])
    write(root / "home" / "Code" / "User" / "settings.json", '{"chat.mcp.workspaceRootConfig.enabled": true}')
    vscode = ctx_ids_for(scan_path(root, HOST), "vscode")
    assert "github" in sum(vscode.values(), [])


def test_malformed_file_is_reported_and_scan_continues(tmp_path):
    root = make_repo(tmp_path / "repo")
    write(root / ".cursor" / "mcp.json", '{"mcpServers": {"fs": ')
    inv = scan_path(root, HOST)
    assert [(i.kind, Path(i.path).name) for i in inv.issues] == [("parse_error", "mcp.json")]
    assert any(f.status == "error" and f.client == "cursor" for f in inv.files)
    assert "github" in [s.name for s in inv.servers]


def test_oversized_file_is_skipped(tmp_path):
    root = make_repo(tmp_path / "repo")
    from mcpposture.discovery.inventory import Limits

    inv = scan_path(root, HOST, limits=Limits(max_file_bytes=40))
    assert {i.kind for i in inv.issues} == {"too_large"}


def test_symlink_out_of_scan_root_is_not_read(tmp_path):
    outside = write(tmp_path / "secrets" / "creds.json", {"mcpServers": {"leak": {"command": "x"}}})
    root = tmp_path / "repo"
    root.mkdir()
    make_symlink(root / ".mcp.json", outside)
    inv = scan_path(root, HOST)
    assert inv.servers == []
    assert [i.kind for i in inv.issues] == ["symlink_escape"]


def test_single_unknown_file_is_sniffed(tmp_path):
    p = write(tmp_path / "whatever.json", {"servers": {"a": {"command": "x"}}})
    inv = scan_path(p, HOST)
    assert [(s.client, s.name) for s in inv.servers] == [("unknown", "a")]


def test_missing_target_is_a_tool_error(tmp_path):
    with pytest.raises(ScanError):
        scan_path(tmp_path / "missing", HOST)


# --- local mode --------------------------------------------------------------


def local_setup(tmp_path):
    home = tmp_path / "home"
    project = tmp_path / "work" / "proj"
    managed = tmp_path / "managed"
    bases = dict(bases_for(current_os(), home, {}))
    bases["claude_managed"] = managed
    write(
        home / ".claude.json",
        {
            "mcpServers": {"ctx7": {"type": "http", "url": "https://mcp.example.com/mcp"}, "shared": {"command": "user-version"}},
            "projects": {
                str(project): {"mcpServers": {"shared": {"command": "local-version"}}},
                str(tmp_path / "deleted-project"): {"mcpServers": {}},
            },
        },
    )
    write(project / ".mcp.json", {"mcpServers": {"shared": {"command": "project-version"}, "team": {"command": "team-mcp"}}})
    write(home / ".cursor" / "mcp.json", {"mcpServers": {"cur": {"command": "c"}}})
    write(bases["app_support"] / "Claude" / "claude_desktop_config.json", {"mcpServers": {"desk": {"command": "d"}}})
    host = Host(os=current_os(), is_wsl=False, home=home)
    return host, [LocationSet("local", host.os, bases)], home, project, managed


def test_scan_local_builds_contexts_with_precedence(tmp_path):
    host, sets, home, project, _ = local_setup(tmp_path)
    inv = scan_local(host, cwd=home, sets=sets)
    by_id = {s.id: s for s in inv.servers}
    contexts = {c.id: c for c in inv.contexts}
    proj_ctx = contexts[f"claude-code:project:{norm(project)}"]
    servers = {by_id[i].name: by_id[i] for i in proj_ctx.server_ids}
    assert sorted(servers) == ["ctx7", "shared", "team"]
    # Claude Code precedence: local > project > user.
    assert servers["shared"].command == "local-version"
    assert ctx_map(inv)["claude-code:user"] == ["ctx7", "shared"]
    assert ctx_map(inv)["cursor:user"] == ["cur"]
    assert any(k.startswith("claude-desktop:file:") for k in contexts)
    assert inv.issues == []


def test_managed_mcp_json_takes_exclusive_control(tmp_path):
    host, sets, home, _, managed = local_setup(tmp_path)
    write(managed / "managed-mcp.json", {"mcpServers": {"corp": {"type": "http", "url": "https://corp.example/mcp"}}})
    inv = scan_local(host, cwd=home, sets=sets)
    assert ctx_ids_for(inv, "claude-code") == {"claude-code:managed": ["corp"]}


def test_unparseable_managed_mcp_json_is_not_exclusive(tmp_path):
    host, sets, home, _, managed = local_setup(tmp_path)
    write(managed / "managed-mcp.json", "{ broken")
    inv = scan_local(host, cwd=home, sets=sets)
    assert "claude-code:user" in ctx_ids_for(inv, "claude-code")


def test_same_file_is_read_once_per_client(tmp_path):
    host, sets, home, _, _ = local_setup(tmp_path)
    write(home / ".claude" / "settings.json", {"permissions": {}})
    inv = scan_local(host, cwd=home, sets=sets)
    settings_files = [f for f in inv.files if f.fmt == "claude_settings"]
    assert len(settings_files) == 1 and settings_files[0].scope == "user"
