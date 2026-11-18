"""Operating system, WSL, and home-directory detection without spawning processes."""

from __future__ import annotations

import os
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Mapping, Sequence

# Built-in or service profiles under C:\Users that never hold a developer's config.
_WINDOWS_PROFILE_SKIP = frozenset(
    {"public", "default", "default user", "all users", "defaultapppool", "wdagutilityaccount"}
)
_DRIVE_PATH = re.compile(r"^([A-Za-z]):[\\/](.*)$", re.DOTALL)


@dataclass(frozen=True)
class Host:
    os: str  # "windows" | "macos" | "linux"
    is_wsl: bool
    home: Path
    env: Mapping[str, str] = field(default_factory=dict)
    windows_homes: tuple[Path, ...] = ()
    hostname: str = ""


@dataclass(frozen=True)
class LocationSet:
    """One home directory's worth of base paths, interpreted for one OS."""

    label: str
    os: str
    bases: Mapping[str, Path]


def current_os() -> str:
    if sys.platform == "win32":
        return "windows"
    if sys.platform == "darwin":
        return "macos"
    return "linux"


def _hostname(env: Mapping[str, str]) -> str:
    # platform.node() is avoided: on Windows the platform module can shell out to `ver`.
    if hasattr(os, "uname"):
        return os.uname().nodename
    return env.get("COMPUTERNAME", "")


def is_wsl(env: Mapping[str, str], proc_version: Path = Path("/proc/version")) -> bool:
    if env.get("WSL_DISTRO_NAME"):
        return True
    try:
        with open(proc_version, "rb") as f:
            return b"microsoft" in f.read(4096).lower()
    except OSError:
        return False


def windows_homes_from_mount(users_dir: Path) -> tuple[Path, ...]:
    """Real user profiles under a mounted C:\\Users, skipping links and built-in profiles."""
    homes: list[Path] = []
    try:
        entries = sorted(users_dir.iterdir())
    except OSError:
        return ()
    for entry in entries:
        try:
            if (
                entry.name.casefold() not in _WINDOWS_PROFILE_SKIP
                and not entry.is_symlink()
                and entry.is_dir()
                and (entry / "AppData").is_dir()
            ):
                homes.append(entry)
        except OSError:
            continue
    return tuple(homes)


def detect(
    environ: Mapping[str, str] | None = None,
    *,
    windows_homes: Sequence[Path] | None = None,
    proc_version: Path = Path("/proc/version"),
    mnt_users: Path = Path("/mnt/c/Users"),
) -> Host:
    env = dict(os.environ if environ is None else environ)
    os_name = current_os()
    wsl = os_name == "linux" and is_wsl(env, proc_version)
    if windows_homes:
        homes = tuple(Path(p) for p in windows_homes)
    elif wsl:
        homes = windows_homes_from_mount(mnt_users)
    else:
        homes = ()
    return Host(
        os=os_name,
        is_wsl=wsl,
        home=Path.home(),
        env=env,
        windows_homes=homes,
        hostname=_hostname(env),
    )


def _env_path(env: Mapping[str, str], key: str) -> Path | None:
    value = env.get(key)
    if value and os.path.isabs(value):
        return Path(value)
    return None


def bases_for(os_name: str, home: Path, env: Mapping[str, str]) -> dict[str, Path]:
    """Base directories that the location table's ``{name}`` placeholders expand to."""
    claude_config_dir = _env_path(env, "CLAUDE_CONFIG_DIR")
    if os_name == "windows":
        app_support = _env_path(env, "APPDATA") or home / "AppData" / "Roaming"
        claude_managed = (_env_path(env, "ProgramFiles") or Path("C:/Program Files")) / "ClaudeCode"
    elif os_name == "macos":
        app_support = home / "Library" / "Application Support"
        claude_managed = Path("/Library/Application Support/ClaudeCode")
    else:
        app_support = _env_path(env, "XDG_CONFIG_HOME") or home / ".config"
        claude_managed = Path("/etc/claude-code")
    return {
        "home": home,
        "app_support": app_support,
        # With CLAUDE_CONFIG_DIR set, Claude Code keeps both .claude.json and
        # settings.json in that directory instead of $HOME and $HOME/.claude.
        "claude_state": claude_config_dir or home,
        "claude_dir": claude_config_dir or home / ".claude",
        "claude_managed": claude_managed,
        "copilot_home": _env_path(env, "COPILOT_HOME") or home / ".copilot",
    }


def location_sets(host: Host) -> list[LocationSet]:
    sets = [LocationSet("local", host.os, bases_for(host.os, host.home, host.env))]
    for win_home in host.windows_homes:
        # win_home looks like /mnt/c/Users/<name>; the drive mount is two levels up.
        drive = win_home.parent.parent
        win_env = {"APPDATA": str(win_home / "AppData" / "Roaming"), "ProgramFiles": str(drive / "Program Files")}
        sets.append(LocationSet(f"windows:{win_home.name}", "windows", bases_for("windows", win_home, win_env)))
    return sets


def project_path(key: str, host: Host) -> Path | None:
    """Map a project path recorded by a client (possibly a Windows path seen from WSL) to a local path."""
    m = _DRIVE_PATH.match(key)
    if m and host.os != "windows":
        if not host.is_wsl and not host.windows_homes:
            return None
        rest = m.group(2).replace("\\", "/")
        return Path("/mnt") / m.group(1).lower() / rest
    if not os.path.isabs(key):
        return None
    return Path(key)
