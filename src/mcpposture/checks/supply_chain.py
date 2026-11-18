"""MP003: servers downloaded at launch without a fixed version or digest."""

from __future__ import annotations

from typing import Iterator

from mcpposture.checks.base import CheckContext, CheckInfo, server_finding
from mcpposture.checks.launch import packages, unwrap
from mcpposture.model import Finding, Severity
from mcpposture.redact import redact

INFO = CheckInfo(
    id="MP003",
    title="Unpinned server package",
    severity=Severity.MEDIUM,
    why=(
        "The client downloads and runs whatever version is newest each time it starts. If the package or its "
        "publisher account is compromised, the next launch runs the attacker's code with your permissions."
    ),
    remediation=(
        "Pin an exact version (npx pkg@1.2.3, uvx pkg==1.2.3, pipx run --spec pkg==1.2.3), or install the server "
        "once and point the config at the installed binary. For containers, reference the image by digest "
        "(image@sha256:...)."
    ),
    cwe=("CWE-494",),
    owasp_llm=("LLM03:2025",),
    owasp_agentic=("ASI04:2026",),
)

_TAG_WHY = (
    "A container tag is a movable label: whoever controls the registry repository can point it at a different "
    "image without changing your config."
)


def check(ctx: CheckContext) -> Iterator[Finding]:
    for s in ctx.inventory.servers:
        launch = unwrap(s)
        if launch is None:
            continue
        for ref in packages(launch):
            if ref.pinned:
                continue
            if ref.mutable_tag:
                yield server_finding(
                    INFO, ctx, s, launch.pointer(ref.arg_index),
                    evidence=f"{ref.runner} image {redact(ref.spec)} (tag, no digest)",
                    severity=Severity.LOW,
                    title="Container image pinned by tag, not digest",
                    why=_TAG_WHY,
                )
            else:
                yield server_finding(
                    INFO, ctx, s, launch.pointer(ref.arg_index),
                    evidence=f"{ref.runner} {redact(ref.spec)}",
                )
