"""MP005: filesystem access rooted too broadly or reaching credential stores."""

from __future__ import annotations

import re
from typing import Iterator

from mcpposture.checks.base import CheckContext, CheckInfo, server_finding
from mcpposture.checks.launch import Launch, docker_mount_sources, packages, unwrap
from mcpposture.model import Finding, ServerConfig, Severity

INFO = CheckInfo(
    id="MP005",
    title="Filesystem server can reach too much",
    severity=Severity.HIGH,
    why=(
        "The agent can read and often write everything under this path. A single prompt-injected instruction can "
        "make it read SSH keys, cloud credentials, or browser data and pass them to another tool."
    ),
    remediation="List only the project directories the agent needs. Never grant a drive root, your whole home directory, or folders such as .ssh, .aws, or a password store.",
    cwe=("CWE-250",),
    owasp_llm=("LLM06:2025",),
    owasp_agentic=("ASI02:2026", "ASI03:2026"),
)

# Servers whose positional arguments are the directories they expose.
FILESYSTEM_PACKAGES = frozenset({"@modelcontextprotocol/server-filesystem"})

_HOME_TOKENS = frozenset(
    {"~", "$home", "${home}", "${env:home}", "${userhome}", "%userprofile%", "${env:userprofile}", "${userprofile}", "$userprofile"}
)
_HOME_PATTERNS = (
    re.compile(r"^/(users|home)/[^/]+$"),
    re.compile(r"^/root$"),
    re.compile(r"^/mnt/[a-z]/users/[^/]+$"),
    re.compile(r"^[a-z]:/users/[^/]+$"),
)
_ROOT_PATTERNS = (
    re.compile(r"^/$"),
    re.compile(r"^[a-z]:/?$"),
    re.compile(r"^/mnt/[a-z]$"),
    re.compile(r"^/(users|home)$"),
    re.compile(r"^[a-z]:/users$"),
)
_SENSITIVE = (
    ".ssh", ".aws", ".gnupg", ".kube", ".docker", ".azure", ".password-store", ".git-credentials",
    ".netrc", ".npmrc", ".pypirc", ".vault-token", ".config/gcloud", "library/keychains",
    "appdata/roaming/microsoft/credentials", "appdata/local/microsoft/credentials", "appdata/roaming/microsoft/protect",
)


def _normalise(path: str) -> str:
    p = path.strip().strip('"').replace("\\", "/").lower()
    p = re.sub(r"/+", "/", p)
    return p.rstrip("/") if len(p) > 1 and not re.match(r"^[a-z]:/$", p) else p


def classify_root(path: str) -> str | None:
    """'root', 'home', 'sensitive', 'docker-socket', or None for a reasonably scoped path."""
    p = _normalise(path)
    if p.endswith("/docker.sock"):
        return "docker-socket"
    if p in _HOME_TOKENS or any(pat.match(p) for pat in _HOME_PATTERNS):
        return "home"
    if any(pat.match(p) for pat in _ROOT_PATTERNS):
        return "root"
    padded = f"/{p}/"
    if any(f"/{s}/" in padded for s in _SENSITIVE):
        return "sensitive"
    return None


_TITLES = {
    "root": "Filesystem access to an entire drive",
    "home": "Filesystem access to the whole home directory",
    "sensitive": "Filesystem access to a credential store",
    # Access to the Docker socket is equivalent to root on the host.
    "docker-socket": "Container can control the host Docker daemon",
}


def npm_package_name(spec: str) -> str:
    at = spec.rfind("@")
    return spec[:at] if at > 0 else spec


def _roots(launch: Launch) -> list[tuple[str, int]]:
    roots: list[tuple[str, int]] = []
    for ref in packages(launch):
        if ref.ecosystem == "npm" and npm_package_name(ref.spec) in FILESYSTEM_PACKAGES:
            roots += [(a, i) for i, a in enumerate(launch.args) if i > ref.arg_index and not a.startswith("-")]
    # Any container can reach the host paths bind-mounted into it, whatever server it runs.
    roots += docker_mount_sources(launch)
    return roots


def _findings(ctx: CheckContext, s: ServerConfig) -> Iterator[Finding]:
    launch = unwrap(s)
    if launch is None:
        return
    for path, index in _roots(launch):
        kind = classify_root(path)
        if kind:
            yield server_finding(
                INFO, ctx, s, launch.pointer(index),
                evidence=f"allowed path {path}",
                title=_TITLES[kind],
                discriminator=path,
            )


def check(ctx: CheckContext) -> Iterator[Finding]:
    for s in ctx.inventory.servers:
        yield from _findings(ctx, s)
