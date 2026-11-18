"""MP002: credentials written directly into agent configuration."""

from __future__ import annotations

from typing import Iterator
from urllib.parse import urlsplit

from mcpposture.checks.base import CheckContext, CheckInfo, bump, ptr, server_finding, settings_finding
from mcpposture.model import Finding, Severity
from mcpposture.redact import SENSITIVE_NAME, SecretMatch, classify, find_secrets, redact_args, redact_url, redact_value

INFO = CheckInfo(
    id="MP002",
    title="Hardcoded credential",
    severity=Severity.HIGH,
    why=(
        "A secret stored in plain text in a config file can be read by any process or person with access to the file, "
        "its backups, or its git history, and agents can be tricked into reading their own config."
    ),
    remediation=(
        "Rotate the credential now, then reference it instead of storing it: use ${VAR} environment expansion, "
        "VS Code ${input:...} prompts, or the client's OAuth support."
    ),
    cwe=("CWE-798",),
    owasp_llm=("LLM02:2025",),
    owasp_agentic=("ASI03:2026",),
)

# Files meant to be committed and shared with a team; a secret there is exposed to everyone with repo access.
_SHARED_SCOPES = frozenset({"project"})


def _severity(matches: list[SecretMatch], scope: str) -> Severity:
    sev = Severity.HIGH if any(m.method == "pattern" for m in matches) else Severity.MEDIUM
    return bump(sev) if scope in _SHARED_SCOPES else sev


def _title(matches: list[SecretMatch]) -> str:
    providers = sorted({m.provider for m in matches if m.method == "pattern"})
    return f"Hardcoded {', '.join(providers)} credential" if providers else INFO.title


def check(ctx: CheckContext) -> Iterator[Finding]:
    for s in ctx.inventory.servers:
        for field, values in (("env", s.env), ("headers", s.headers)):
            for key, value in values.items():
                matches = classify(value, key)
                if matches:
                    yield server_finding(
                        INFO, ctx, s, ptr(field, key),
                        evidence=f"{field} {key} = {redact_value(value, key)}",
                        severity=_severity(matches, s.scope),
                        title=_title(matches),
                    )

        redacted_args = redact_args(s.args)
        for i, arg in enumerate(s.args):
            if redacted_args[i] != arg:
                matches = find_secrets(arg) or [SecretMatch("named-secret", 0, len(arg), "name")]
                yield server_finding(
                    INFO, ctx, s, ptr("args", i),
                    evidence=f"args[{i}] = {redacted_args[i]}",
                    severity=_severity(matches, s.scope),
                    title=_title(matches),
                )

        if s.url:
            matches = find_secrets(s.url)
            try:
                parts = urlsplit(s.url)
                if parts.password:
                    matches.append(SecretMatch("url-password", 0, 0, "name"))
                for pair in parts.query.split("&") if parts.query else []:
                    key, _, val = pair.partition("=")
                    if SENSITIVE_NAME.search(key) and classify(val, key):
                        matches.append(SecretMatch("named-secret", 0, 0, "name"))
            except ValueError:
                pass
            if matches:
                yield server_finding(
                    INFO, ctx, s, "/url",
                    evidence=f"url = {redact_url(s.url)}",
                    severity=_severity(matches, s.scope),
                    title=_title(matches),
                )

        if s.command and (matches := find_secrets(s.command)):
            yield server_finding(
                INFO, ctx, s, "/command",
                evidence=f"command = {redact_value(s.command)}",
                severity=_severity(matches, s.scope),
                title=_title(matches),
            )

    for doc in ctx.inventory.settings:
        env = doc.data.get("env")
        if not isinstance(env, dict):
            continue
        for key, value in env.items():
            if isinstance(value, str) and (matches := classify(value, key)):
                yield settings_finding(
                    INFO, ctx, doc, ptr("env", key),
                    evidence=f"env {key} = {redact_value(value, key)}",
                    severity=_severity(matches, doc.scope),
                    title=_title(matches),
                )
