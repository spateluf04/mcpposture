"""MP001: an agent context whose servers together grant all three Rule of Two capabilities.

Meta AI, "Agents Rule of Two: A Practical Approach to AI Agent Security"
(31 October 2025), https://ai.meta.com/blog/practical-ai-agent-security/ :
within a session an agent should have no more than two of [A] processing
untrustworthy input, [B] access to sensitive systems or private data, and
[C] changing state or communicating externally.
"""

from __future__ import annotations

from dataclasses import replace
from typing import Iterator

from mcpposture.checks.base import CheckContext, CheckInfo, server_finding, stable_path
from mcpposture.model import AgentContext, Classification, Finding, ServerConfig, Severity

INFO = CheckInfo(
    id="MP001",
    title="Agent combines untrusted input, private data, and external actions",
    severity=Severity.HIGH,
    why=(
        "This is the setup prompt injection needs. Text the agent reads from one tool (a web page, an issue, an "
        "email) can instruct it to collect private data with a second tool and send it out or act on it with a "
        "third, and no current model reliably refuses. Meta's Agents Rule of Two says an agent session should hold "
        "at most two of these three capabilities."
    ),
    remediation=(
        "Split these servers across separate agents, profiles or projects so no single session has all three, or "
        "remove one. If a task truly needs all three, keep a human approving each state-changing action and do not "
        "pre-approve those tools."
    ),
    cwe=("CWE-1427",),
    owasp_llm=("LLM01:2025", "LLM06:2025"),
    owasp_agentic=("ASI01:2026", "ASI02:2026"),
)

INCOMPLETE = CheckInfo(
    id="MP001",
    title="Rule of Two cannot be fully evaluated: unclassified servers",
    severity=Severity.INFO,
    why=(
        "These servers match no known package or heuristic, so their capabilities are unknown. They are not "
        "assumed safe: any of them could supply the capability that completes the combination."
    ),
    remediation="Review what each unclassified server can do and add it to the rules file (see CONTRIBUTING.md) or to your policy.",
    cwe=INFO.cwe,
    owasp_llm=INFO.owasp_llm,
    owasp_agentic=INFO.owasp_agentic,
)

ALL = frozenset({"A", "B", "C"})
_LABEL = {"A": "untrusted input", "B": "private data", "C": "external actions"}


def _evidence(by_flag: dict[str, list[str]], contexts: int) -> str:
    parts = [f"[{f}] {_LABEL[f]}: {', '.join(sorted(set(by_flag[f])))}" for f in sorted(by_flag)]
    suffix = f" (in {contexts} agent contexts)" if contexts > 1 else ""
    return "; ".join(parts) + suffix


def check(ctx: CheckContext) -> Iterator[Finding]:
    inv = ctx.inventory
    by_id = {s.id: s for s in inv.servers}
    unclassified = Classification(frozenset(), "unclassified")

    # One finding per distinct combination of contributing servers, since every
    # project context inherits the user-level servers and would repeat it.
    violations: dict[tuple[str, frozenset[str]], list[AgentContext]] = {}
    incomplete: dict[tuple[str, frozenset[str]], list[AgentContext]] = {}
    for context in inv.contexts:
        servers = [by_id[i] for i in context.server_ids if i in by_id]
        classes = {s.id: inv.capabilities.get(s.id, unclassified) for s in servers}
        contributing = frozenset(s.id for s in servers if classes[s.id].flags)
        granted = frozenset().union(*(c.flags for c in classes.values()))
        if granted >= ALL:
            violations.setdefault((context.client, contributing), []).append(context)
        else:
            unknown = frozenset(s.id for s in servers if classes[s.id].source == "unclassified")
            if unknown:
                incomplete.setdefault((context.client, unknown), []).append(context)

    for (client, ids), contexts in violations.items():
        servers = [by_id[i] for i in sorted(ids, key=lambda i: contexts[0].server_ids.index(i))]
        by_flag: dict[str, list[str]] = {f: [] for f in sorted(ALL)}
        heuristic_only: set[str] = set(ALL)
        for s in servers:
            cls = inv.capabilities[s.id]
            for f in cls.flags:
                by_flag[f].append(s.name)
                if cls.source == "rule":
                    heuristic_only.discard(f)
        anchor = max(servers, key=lambda s: len(inv.capabilities[s.id].flags))
        finding = server_finding(
            INFO, ctx, anchor,
            evidence=_evidence(by_flag, len(contexts)),
            # A capability supplied only by a heuristic match is a guess; say so through severity.
            severity=Severity.MEDIUM if heuristic_only else Severity.HIGH,
            discriminator=_discriminator(ctx, client, servers),
        )
        yield replace(finding, context_id=contexts[0].id)

    for (client, ids), contexts in incomplete.items():
        servers: list[ServerConfig] = [by_id[i] for i in sorted(ids)]
        finding = server_finding(
            INCOMPLETE, ctx, servers[0],
            evidence="unclassified: " + ", ".join(sorted(s.name for s in servers)),
            discriminator="incomplete|" + _discriminator(ctx, client, servers),
        )
        yield replace(finding, context_id=contexts[0].id)


def _discriminator(ctx: CheckContext, client: str, servers: list[ServerConfig]) -> str:
    return client + "|" + "|".join(sorted(f"{stable_path(s.location.path, ctx.homes)}#{s.name}" for s in servers))
