from pathlib import Path

from mcpposture.discovery.hostinfo import (
    Host,
    bases_for,
    is_wsl,
    location_sets,
    project_path,
    windows_homes_from_mount,
)

from conftest import write


def test_wsl_detected_from_env():
    assert is_wsl({"WSL_DISTRO_NAME": "Ubuntu"}, Path("/nonexistent"))


def test_wsl_detected_from_proc_version(tmp_path):
    proc = write(tmp_path / "version", "Linux version 5.15.153.1-microsoft-standard-WSL2")
    assert is_wsl({}, proc)
    write(proc, "Linux version 6.8.0-generic")
    assert not is_wsl({}, proc)
    assert not is_wsl({}, tmp_path / "missing")


def test_windows_homes_skip_builtin_profiles(tmp_path):
    users = tmp_path / "Users"
    for name in ("alice", "Public", "Default", "All Users"):
        (users / name / "AppData").mkdir(parents=True)
    (users / "bob").mkdir()  # no AppData: not a real profile
    write(users / "desktop.ini", "")
    assert windows_homes_from_mount(users) == (users / "alice",)
    assert windows_homes_from_mount(tmp_path / "missing") == ()


def test_bases_per_os(tmp_path):
    home = tmp_path / "home"
    win = bases_for("windows", home, {})
    assert win["app_support"] == home / "AppData" / "Roaming"
    assert win["claude_state"] == home
    assert win["claude_dir"] == home / ".claude"
    mac = bases_for("macos", home, {})
    assert mac["app_support"] == home / "Library" / "Application Support"
    assert mac["claude_managed"].as_posix() == "/Library/Application Support/ClaudeCode"
    linux = bases_for("linux", home, {})
    assert linux["app_support"] == home / ".config"
    assert linux["claude_managed"].as_posix() == "/etc/claude-code"


def test_env_overrides_and_relative_values_ignored(tmp_path):
    home = tmp_path / "home"
    cfg = tmp_path / "claude-cfg"
    xdg = tmp_path / "xdg"
    b = bases_for("linux", home, {"CLAUDE_CONFIG_DIR": str(cfg), "XDG_CONFIG_HOME": str(xdg), "COPILOT_HOME": "relative/dir"})
    assert b["claude_state"] == cfg
    assert b["claude_dir"] == cfg
    assert b["app_support"] == xdg
    assert b["copilot_home"] == home / ".copilot"


def test_location_sets_add_windows_side_under_wsl(tmp_path):
    win_home = tmp_path / "mnt" / "c" / "Users" / "alice"
    host = Host(os="linux", is_wsl=True, home=tmp_path / "linuxhome", windows_homes=(win_home,))
    sets = location_sets(host)
    assert [s.os for s in sets] == ["linux", "windows"]
    win = sets[1].bases
    assert win["app_support"] == win_home / "AppData" / "Roaming"
    assert win["claude_managed"] == tmp_path / "mnt" / "c" / "Program Files" / "ClaudeCode"


def test_project_path_translates_windows_keys_under_wsl():
    wsl = Host(os="linux", is_wsl=True, home=Path("/home/me"))
    assert project_path("C:\\Users\\a\\proj", wsl).as_posix() == "/mnt/c/Users/a/proj"
    assert project_path("D:/work/proj", wsl).as_posix() == "/mnt/d/work/proj"
    plain_linux = Host(os="linux", is_wsl=False, home=Path("/home/me"))
    assert project_path("C:/Users/a/proj", plain_linux) is None
    assert project_path("relative/dir", plain_linux) is None
