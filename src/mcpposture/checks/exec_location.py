"""MP007: servers started from temporary, download, or relative locations."""

from __future__ import annotations

import re
from typing import Iterator

from mcpposture.checks.base import CheckContext, CheckInfo, server_finding
from mcpposture.checks.launch import Launch, unwrap
from mcpposture.model import Finding, Severity

INFO = CheckInfo(
    id="MP007",
    title="Server runs from an untrusted location",
    severity=Severity.HIGH,
    why=(
        "Temporary and download folders are writable by anything running as you, including browsers and other "
        "tools, so the file executed on the next agent launch may not be the one you vetted."
    ),
    remediation="Install the server to a fixed location you control (a package manager prefix or a read-only directory) and reference it by absolute path.",
    cwe=("CWE-829",),
    owasp_llm=("LLM03:2025",),
    owasp_agentic=("ASI04:2026",),
)

_RELATIVE_WHY = (
    "A relative path is resolved against whatever directory the client starts in. In a cloned repository "
    "that is attacker-chosen content, and the search order differs between clients and operating systems."
)
_RELATIVE_FIX = "Use an absolute path, or a client variable such as ${workspaceFolder} so the location is explicit."

# Interpreters whose script argument is what actually runs.
_SCRIPT_RUNNERS = frozenset({"node", "python", "python3", "py", "bun", "ruby", "perl", "php", "bash", "sh", "zsh"})
_SCRIPT_FLAG = {"deno": "run", "pwsh": "-file", "powershell": "-file", "java": "-jar"}
_VALUE_FLAGS = frozenset({"-r", "--require", "--import", "--loader", "-X", "-W", "--env-file"})

_UNTRUSTED = (
    re.compile(r"^/(private/)?tmp/"),
    re.compile(r"^/var/tmp/"),
    re.compile(r"^/dev/shm/"),
    re.compile(r"^/(private/)?var/folders/"),
    re.compile(r"^[a-z]:/windows/temp/"),
    re.compile(r"/appdata/local/temp/"),
    re.compile(r"(^|/)downloads/"),
    re.compile(r"^(%temp%|%tmp%|\$tmpdir|\$\{tmpdir\}|\$\{env:te?mp\}|\$\{env:tmpdir\})[/\\]"),
)
_DRIVE = re.compile(r"^[a-z]:/")


def executed_paths(launch: Launch) -> list[tuple[str, str]]:
    """(path, pointer) for the program and, for interpreters, the script it runs."""
    found = [(launch.command, "/command" if launch.inline_arg is None and launch.arg_offset == 0 else launch.pointer(-1))]
    program, args = launch.program, launch.args
    script_index: int | None = None
    if program in _SCRIPT_RUNNERS:
        i = 0
        while i < len(args):
            a = args[i]
            if a in ("-m", "-c", "-e", "--eval"):
                break  # running a module or inline code, not a file
            if a in _VALUE_FLAGS:
                i += 2
                continue
            if not a.startswith("-"):
                script_index = i
                break
            i += 1
    elif program in _SCRIPT_FLAG:
        marker = _SCRIPT_FLAG[program]
        lowered = [a.lower() for a in args]
        if marker in lowered and lowered.index(marker) + 1 < len(args):
            script_index = lowered.index(marker) + 1
    if script_index is not None:
        found.append((args[script_index], launch.pointer(script_index)))
    return found


def location_kind(path: str) -> str | None:
    p = path.strip().strip('"').replace("\\", "/").lower()
    if any(pat.search(p) for pat in _UNTRUSTED):
        return "untrusted"
    if p.startswith(("$", "%", "~")) or p.startswith("/") or _DRIVE.match(p):
        return None
    if "/" in p:
        return "relative"
    return None  # bare program name, resolved through PATH


def check(ctx: CheckContext) -> Iterator[Finding]:
    for s in ctx.inventory.servers:
        launch = unwrap(s)
        if launch is None:
            continue
        for path, pointer in executed_paths(launch):
            kind = location_kind(path)
            if kind == "untrusted":
                yield server_finding(INFO, ctx, s, pointer, evidence=f"runs {path}", discriminator=path)
            elif kind == "relative":
                yield server_finding(
                    INFO, ctx, s, pointer,
                    evidence=f"runs {path}",
                    severity=Severity.MEDIUM,
                    title="Server launched from a relative path",
                    why=_RELATIVE_WHY,
                    remediation=_RELATIVE_FIX,
                    discriminator=path,
                    cwe=("CWE-427",),
                )
