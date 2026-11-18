"""Static interpretation of a stdio server's launch command.

Nothing here executes anything: commands are read as data to work out which
program and which downloaded package a client would start.
"""

from __future__ import annotations

import re
import shlex
from dataclasses import dataclass

from mcpposture.model import ServerConfig

_EXE_SUFFIXES = (".exe", ".cmd", ".bat", ".ps1", ".com")
_SHELLS = frozenset({"sh", "bash", "zsh", "dash"})
_EXACT_SEMVER = re.compile(r"^v?\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$")
_COMMIT = re.compile(r"^[0-9a-f]{40}$")
_PEP440_EXACT = re.compile(r"^\s*===?\s*[0-9][0-9A-Za-z.+!-]*\s*$")
_DRIVE = re.compile(r"^[A-Za-z]:[\\/]")


def program_name(command: str) -> str:
    name = re.split(r"[\\/]", command)[-1].lower()
    for suffix in _EXE_SUFFIXES:
        if name.endswith(suffix):
            return name[: -len(suffix)]
    return name


@dataclass(frozen=True)
class Launch:
    command: str
    args: tuple[str, ...]
    arg_offset: int
    # Set when the real command came from a `sh -c "..."` string: every
    # derived argument then points at that one string in the config.
    inline_arg: int | None = None

    @property
    def program(self) -> str:
        return program_name(self.command)

    def pointer(self, i: int) -> str:
        return f"/args/{self.inline_arg if self.inline_arg is not None else self.arg_offset + i}"


def unwrap(server: ServerConfig) -> Launch | None:
    """The program actually started, looking through cmd /c, env and sh -c wrappers."""
    if not server.command:
        return None
    launch = Launch(server.command, tuple(server.args), 0)
    for _ in range(4):
        name, args = launch.program, launch.args
        if name == "cmd" and len(args) >= 2 and args[0].lower() in ("/c", "/k"):
            launch = Launch(args[1], args[2:], launch.arg_offset + 2, launch.inline_arg)
        elif name == "env" and args:
            skip = 0
            while skip < len(args) and ("=" in args[skip] or args[skip].startswith("-")):
                skip += 1
            if skip >= len(args):
                break
            launch = Launch(args[skip], args[skip + 1 :], launch.arg_offset + skip + 1, launch.inline_arg)
        elif name in _SHELLS and len(args) >= 2 and args[0] in ("-c", "-lc"):
            try:
                tokens = shlex.split(args[1])
            except ValueError:
                break
            if not tokens:
                break
            inline = launch.inline_arg if launch.inline_arg is not None else launch.arg_offset + 1
            launch = Launch(tokens[0], tuple(tokens[1:]), 0, inline)
        else:
            break
    return launch


@dataclass(frozen=True)
class PackageRef:
    runner: str
    ecosystem: str  # npm | pypi | oci
    spec: str
    pinned: bool
    arg_index: int
    mutable_tag: bool = False  # OCI tag present but no digest


def _is_local(spec: str) -> bool:
    return spec.startswith((".", "/", "~", "file:", "${")) or bool(_DRIVE.match(spec))


def _npm_ref(runner: str, spec: str, index: int) -> PackageRef | None:
    if _is_local(spec):
        return None
    if spec.startswith(("git+", "git:", "github:", "gitlab:", "bitbucket:", "http:", "https:")):
        commit = spec.rsplit("#", 1)[1] if "#" in spec else ""
        return PackageRef(runner, "npm", spec, bool(_COMMIT.match(commit)), index)
    at = spec.rfind("@")
    version = spec[at + 1 :] if at > 0 else ""
    return PackageRef(runner, "npm", spec, bool(_EXACT_SEMVER.match(version)), index)


def _pypi_ref(runner: str, spec: str, index: int) -> PackageRef | None:
    if _is_local(spec):
        return None
    if spec.startswith(("git+", "http:", "https:")):
        rev = spec.rsplit("@", 1)[1] if spec.count("@") >= 1 and "://" in spec else ""
        return PackageRef(runner, "pypi", spec, bool(_COMMIT.match(rev.split("#")[0])), index)
    name_part = re.split(r"[=<>!~;@\s]", spec, maxsplit=1)[0]
    rest = spec[len(name_part) :]
    if rest.startswith("@"):
        # `uvx tool@1.2.3` shorthand
        return PackageRef(runner, "pypi", spec, bool(_EXACT_SEMVER.match(rest[1:]) or re.match(r"^\d+(\.\d+)*$", rest[1:])), index)
    return PackageRef(runner, "pypi", spec, bool(_PEP440_EXACT.match(rest)) and "*" not in rest, index)


_NPX_VALUE_FLAGS = frozenset({"-c", "--call", "--cache", "--registry", "--userconfig", "-w", "--workspace"})
_UV_VALUE_FLAGS = frozenset(
    {
        "--python", "-p", "--index", "--index-url", "--default-index", "--extra-index-url", "-i",
        "--constraint", "--constraints", "-c", "--override", "--overrides", "--cache-dir", "--directory",
        "--project", "--with-requirements", "--python-preference", "--color", "--config-file",
    }
)
_PIPX_VALUE_FLAGS = frozenset({"--python", "--index-url", "-i", "--pip-args"})
_DOCKER_VALUE_FLAGS = frozenset(
    {
        "-e", "--env", "--env-file", "-v", "--volume", "--mount", "-p", "--publish", "--name", "--network",
        "--net", "-w", "--workdir", "-u", "--user", "--entrypoint", "--platform", "-l", "--label",
        "--label-file", "--add-host", "--dns", "--cpus", "-m", "--memory", "--device", "--cap-add",
        "--cap-drop", "--security-opt", "--tmpfs", "--ulimit", "--hostname", "-h", "--ipc", "--pid",
        "--restart", "--runtime", "--shm-size", "--stop-signal", "--log-driver", "--log-opt", "--gpus",
        "--pull", "--cidfile", "--group-add", "--mac-address", "--ip", "--ip6", "--link", "--expose",
        "--userns", "--uts", "--cgroupns", "-a", "--attach", "--annotation", "--volumes-from",
    }
)


def _npx_packages(runner: str, args: tuple[str, ...], base: int) -> list[PackageRef]:
    explicit: list[PackageRef | None] = []
    positional: PackageRef | None = None
    i = 0
    while i < len(args):
        a = args[i]
        if a in ("-p", "--package") and i + 1 < len(args):
            explicit.append(_npm_ref(runner, args[i + 1], base + i + 1))
            i += 2
            continue
        if a.startswith("--package="):
            explicit.append(_npm_ref(runner, a.split("=", 1)[1], base + i))
        elif a in _NPX_VALUE_FLAGS:
            i += 1
        elif a == "--":
            if i + 1 < len(args):
                positional = _npm_ref(runner, args[i + 1], base + i + 1)
            break
        elif not a.startswith("-"):
            positional = _npm_ref(runner, a, base + i)
            break
        i += 1
    refs = [r for r in explicit if r] if explicit else [positional] if positional else []
    return refs


def _uvx_packages(runner: str, args: tuple[str, ...], base: int) -> list[PackageRef]:
    refs: list[PackageRef | None] = []
    has_from = False
    i = 0
    while i < len(args):
        a = args[i]
        flag, eq, val = a.partition("=")
        if flag in ("--from", "--with", "-w", "--with-editable") and (eq or i + 1 < len(args)):
            spec, idx = (val, i) if eq else (args[i + 1], i + 1)
            has_from = has_from or flag == "--from"
            if flag != "--with-editable":
                refs.append(_pypi_ref(runner, spec, base + idx))
            i += 1 if eq else 2
            continue
        if a in _UV_VALUE_FLAGS:
            i += 2
            continue
        if not a.startswith("-"):
            if not has_from:
                refs.append(_pypi_ref(runner, a, base + i))
            break
        i += 1
    return [r for r in refs if r]


def _pipx_packages(args: tuple[str, ...], base: int) -> list[PackageRef]:
    i = 0
    while i < len(args):
        a = args[i]
        if a == "--spec" and i + 1 < len(args):
            ref = _pypi_ref("pipx", args[i + 1], base + i + 1)
            return [ref] if ref else []
        if a.startswith("--spec="):
            ref = _pypi_ref("pipx", a.split("=", 1)[1], base + i)
            return [ref] if ref else []
        if a in _PIPX_VALUE_FLAGS:
            i += 2
            continue
        if not a.startswith("-"):
            ref = _pypi_ref("pipx", a, base + i)
            return [ref] if ref else []
        i += 1
    return []


def docker_run_args(launch: Launch) -> tuple[tuple[str, ...], int] | None:
    """Arguments after `run` for docker/podman/nerdctl, with their offset."""
    if launch.program not in ("docker", "podman", "nerdctl"):
        return None
    args = launch.args
    if args[:2] == ("container", "run"):
        return args[2:], 2
    if args[:1] == ("run",):
        return args[1:], 1
    return None


def docker_image(launch: Launch) -> PackageRef | None:
    run = docker_run_args(launch)
    if run is None:
        return None
    args, base = run
    i = 0
    while i < len(args):
        a = args[i]
        if a in _DOCKER_VALUE_FLAGS:
            i += 2
            continue
        if a.startswith("-"):
            # Unknown flags are assumed to take no value.
            i += 1
            continue
        image = a
        if "@sha256:" in image:
            return PackageRef(launch.program, "oci", image, True, base + i)
        last = image.rsplit("/", 1)[-1]
        tag = last.split(":", 1)[1] if ":" in last else ""
        return PackageRef(launch.program, "oci", image, False, base + i, mutable_tag=bool(tag) and tag != "latest")
    return None


def docker_mount_sources(launch: Launch) -> list[tuple[str, int]]:
    """Host paths bind-mounted into the container, with their argument index."""
    run = docker_run_args(launch)
    if run is None:
        return []
    args, base = run
    out: list[tuple[str, int]] = []
    for i, a in enumerate(args):
        flag, eq, inline = a.partition("=")
        if flag in ("-v", "--volume"):
            value, idx = (inline, i) if eq else ((args[i + 1], i + 1) if i + 1 < len(args) else ("", i))
            if _DRIVE.match(value):
                src = value[:2] + value[2:].split(":", 1)[0]
            else:
                src = value.split(":", 1)[0]
            if src:
                out.append((src, base + idx))
        elif flag == "--mount":
            value, idx = (inline, i) if eq else ((args[i + 1], i + 1) if i + 1 < len(args) else ("", i))
            fields = dict(part.split("=", 1) for part in value.split(",") if "=" in part)
            src = fields.get("source") or fields.get("src")
            if src:
                out.append((src, base + idx))
        elif not a.startswith("-") and (i == 0 or args[i - 1] not in _DOCKER_VALUE_FLAGS):
            break  # reached the image; later args belong to the container command
    return out


def packages(launch: Launch) -> list[PackageRef]:
    name, args = launch.program, launch.args
    if name in ("npx", "bunx"):
        return _npx_packages(name, args, 0)
    if name in ("npm", "pnpm", "yarn") and args and args[0] in ("exec", "dlx", "x"):
        return _npx_packages(f"{name} {args[0]}", args[1:], 1)
    if name == "uvx":
        return _uvx_packages("uvx", args, 0)
    if name == "uv" and args[:2] == ("tool", "run"):
        return _uvx_packages("uv tool run", args[2:], 2)
    if name == "pipx" and args[:1] == ("run",):
        return _pipx_packages(args[1:], 1)
    image = docker_image(launch)
    return [image] if image else []
