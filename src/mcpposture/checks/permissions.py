"""MP006: agent settings that remove or bypass human approval."""

from __future__ import annotations

import re
from typing import Iterator

from mcpposture.checks.base import CheckContext, CheckInfo, ptr, server_finding, settings_finding
from mcpposture.model import Finding, SettingsDoc, Severity

INFO = CheckInfo(
    id="MP006",
    title="Agent permission checks bypassed or over-broad",
    severity=Severity.HIGH,
    why=(
        "Approval prompts are the last line of defence when an agent has been manipulated by something it read. "
        "With them off or widened to everything, an injected instruction runs immediately."
    ),
    remediation="Remove the setting or narrow the rule to specific, read-only commands. Reserve bypass modes for disposable containers or VMs with no credentials.",
    cwe=("CWE-250",),
    owasp_llm=("LLM06:2025",),
    owasp_agentic=("ASI02:2026", "ASI05:2026"),
)

SKIP_PERMISSION_FLAGS = ("--dangerously-skip-permissions",)
# Commands that run arbitrary code or fetch content, so a wildcard after them is as broad as no rule.
INTERPRETERS = frozenset(
    {
        "python", "python3", "py", "node", "deno", "bun", "bash", "sh", "zsh", "pwsh", "powershell", "ruby", "perl",
        "php", "npx", "uvx", "pipx", "curl", "wget", "eval", "sudo", "docker", "ssh", "env", "xargs",
    }
)
_BASH_RULE = re.compile(r"^\s*Bash\s*(?:\((.*)\))?\s*$", re.DOTALL)
_ANYTHING = frozenset({"", "*", ":*", "*:*", "**"})
_REGEX_ANYTHING = frozenset({"/.*/", "/^.*$/", "/.+/", "/^.+$/", "/.*/i", "/^.*$/i", "/(?:)/", "/^/"})
_MAX_WALK = 5000


def _first_word(spec: str) -> str:
    word = re.split(r"[\s:(]", spec.strip(), maxsplit=1)[0]
    return word.rsplit("/", 1)[-1].lower()


def _rule_command(key: str) -> str:
    """Leading command name of a VS Code terminal rule: a plain command or a /regex/flags."""
    key = key.strip()
    if key.startswith("/") and key.rfind("/") > 0:
        key = key[1 : key.rfind("/")].lstrip("^")
    m = re.match(r"[A-Za-z0-9_.+-]*", key)
    return m.group().lower() if m else ""


def _bash_rule_breadth(rule: str) -> str | None:
    m = _BASH_RULE.match(rule)
    if not m:
        return None
    spec = (m.group(1) or "").strip()
    if spec in _ANYTHING:
        return "any"
    if _first_word(spec) in INTERPRETERS and spec.rstrip().endswith("*"):
        return "interpreter"
    return None


def _strings(value: object, pointer: str, budget: list[int]) -> Iterator[tuple[str, str]]:
    if budget[0] <= 0:
        return
    budget[0] -= 1
    if isinstance(value, str):
        yield pointer, value
    elif isinstance(value, dict):
        for k, v in value.items():
            yield from _strings(v, pointer + ptr(k), budget)
    elif isinstance(value, list):
        for i, v in enumerate(value):
            yield from _strings(v, pointer + ptr(i), budget)


def _claude(ctx: CheckContext, doc: SettingsDoc) -> Iterator[Finding]:
    perms = doc.data.get("permissions")
    perms = perms if isinstance(perms, dict) else {}

    if perms.get("defaultMode") == "bypassPermissions":
        effective = doc.scope in ("user", "managed")
        yield settings_finding(
            INFO, ctx, doc, "/permissions/defaultMode",
            evidence="defaultMode = bypassPermissions",
            title="Claude Code starts in bypassPermissions mode",
            severity=Severity.HIGH if effective else Severity.MEDIUM,
            why=None if effective else (
                "This file is shared or project-local. Claude Code 2.1.257 and later ignore bypassPermissions here, "
                "but older versions honour it, and its presence shows intent to run without approval prompts."
            ),
        )

    allow = perms.get("allow")
    if isinstance(allow, list):
        for i, rule in enumerate(allow):
            if not isinstance(rule, str):
                continue
            breadth = _bash_rule_breadth(rule)
            if breadth == "any":
                yield settings_finding(
                    INFO, ctx, doc, ptr("permissions", "allow", i),
                    evidence=f"allow {rule}", title="Every shell command is pre-approved",
                )
            elif breadth == "interpreter":
                yield settings_finding(
                    INFO, ctx, doc, ptr("permissions", "allow", i),
                    evidence=f"allow {rule}", severity=Severity.MEDIUM,
                    title="Wildcard approval for a command that can run arbitrary code",
                )

    if doc.data.get("enableAllProjectMcpServers") is True:
        shared = doc.scope == "project"
        yield settings_finding(
            INFO, ctx, doc, "/enableAllProjectMcpServers",
            evidence="enableAllProjectMcpServers = true",
            title="Project MCP servers are approved without asking",
            severity=Severity.HIGH if shared else Severity.MEDIUM,
            why=(
                "Any repository you open can start the servers listed in its .mcp.json without a prompt. "
                + ("This file is committed, so the repository approves its own servers." if shared else "Cloning a malicious repository is enough to run its code.")
            ),
            remediation="Remove the setting and approve project servers individually, or list trusted ones in enabledMcpjsonServers.",
        )

    if doc.data.get("skipDangerousModePermissionPrompt") is True:
        yield settings_finding(
            INFO, ctx, doc, "/skipDangerousModePermissionPrompt",
            evidence="skipDangerousModePermissionPrompt = true", severity=Severity.LOW,
            title="Confirmation before bypass mode is disabled",
        )


def _vscode(ctx: CheckContext, doc: SettingsDoc) -> Iterator[Finding]:
    data = doc.data
    flags = {
        "chat.tools.global.autoApprove": "Every agent tool call is auto-approved",
        "github.copilot.chat.claudeAgent.allowDangerouslySkipPermissions": "Claude agent in VS Code skips all permission checks",
    }
    for key, title in flags.items():
        if data.get(key) is True:
            yield settings_finding(INFO, ctx, doc, ptr(key), evidence=f"{key} = true", title=title)

    mode = data.get("chat.permissions.default")
    if mode in ("autoApprove", "autopilot"):
        yield settings_finding(
            INFO, ctx, doc, ptr("chat.permissions.default"),
            evidence=f"chat.permissions.default = {mode}",
            title="New chat sessions run tools without confirmation",
        )

    rules = data.get("chat.tools.terminal.autoApprove")
    if isinstance(rules, dict) and data.get("chat.tools.terminal.enableAutoApprove") is not False:
        for key, value in rules.items():
            approved = value is True or (isinstance(value, dict) and value.get("approve") is True)
            if not approved:
                continue
            if key.strip() in _REGEX_ANYTHING or key.strip() == "*":
                yield settings_finding(
                    INFO, ctx, doc, ptr("chat.tools.terminal.autoApprove", key),
                    evidence=f"terminal auto-approve {key}", title="Every terminal command is auto-approved",
                )
            elif _rule_command(key) in INTERPRETERS:
                yield settings_finding(
                    INFO, ctx, doc, ptr("chat.tools.terminal.autoApprove", key),
                    evidence=f"terminal auto-approve {key}", severity=Severity.MEDIUM,
                    title="Auto-approval for a command that can run arbitrary code",
                )


def check(ctx: CheckContext) -> Iterator[Finding]:
    for doc in ctx.inventory.settings:
        if doc.client == "claude-code":
            yield from _claude(ctx, doc)
        elif doc.client.startswith("vscode"):
            yield from _vscode(ctx, doc)
        # Hooks, status lines and other commands in settings can launch a nested agent.
        for pointer, value in _strings(doc.data, "", [_MAX_WALK]):
            for flag in SKIP_PERMISSION_FLAGS:
                if flag in value:
                    yield settings_finding(
                        INFO, ctx, doc, pointer, evidence=f"command uses {flag}",
                        title="Settings launch an agent with permission checks skipped",
                    )

    for s in ctx.inventory.servers:
        for i, arg in enumerate((s.command or "",) + tuple(s.args)):
            if any(flag in arg for flag in SKIP_PERMISSION_FLAGS):
                yield server_finding(
                    INFO, ctx, s, "/command" if i == 0 else ptr("args", i - 1),
                    evidence=f"launches with {SKIP_PERMISSION_FLAGS[0]}",
                    title="MCP server launches an agent with permission checks skipped",
                )
