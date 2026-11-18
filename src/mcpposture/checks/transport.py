"""MP004: remote MCP servers reached over unencrypted HTTP or WebSocket."""

from __future__ import annotations

import ipaddress
from typing import Iterator
from urllib.parse import urlsplit

from mcpposture.checks.base import CheckContext, CheckInfo, server_finding
from mcpposture.model import Finding, Severity
from mcpposture.redact import redact_url

INFO = CheckInfo(
    id="MP004",
    title="Remote MCP server over cleartext transport",
    severity=Severity.MEDIUM,
    why=(
        "Without TLS anyone on the network path (public Wi-Fi, a compromised router) can read the tool calls and "
        "results, steal tokens sent in headers, and inject their own responses into the agent."
    ),
    remediation="Use an https:// (or wss://) URL. If the server is only reachable over HTTP, run it locally on loopback or put it behind a TLS proxy.",
    cwe=("CWE-319",),
    owasp_llm=("LLM02:2025",),
)

_CLEARTEXT = frozenset({"http", "ws"})


def is_loopback(host: str) -> bool:
    host = host.strip("[]").lower().rstrip(".")
    if host == "localhost" or host.endswith(".localhost"):
        return True
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return False
    # 0.0.0.0 as a destination reaches the local machine.
    return ip.is_loopback or ip.is_unspecified


def check(ctx: CheckContext) -> Iterator[Finding]:
    for s in ctx.inventory.servers:
        if not s.url or s.url.lstrip().startswith("${"):
            continue
        try:
            parts = urlsplit(s.url.strip())
            host = parts.hostname
        except ValueError:
            continue
        if parts.scheme.lower() not in _CLEARTEXT or not host or is_loopback(host):
            continue
        carries_credentials = bool(s.headers) or parts.password is not None or bool(parts.query)
        yield server_finding(
            INFO, ctx, s, "/url",
            evidence=f"url = {redact_url(s.url)}" + (" (sends headers)" if s.headers else ""),
            severity=Severity.HIGH if carries_credentials else Severity.MEDIUM,
        )
