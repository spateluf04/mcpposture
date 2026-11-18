"""Security checks. Each module exposes ``INFO`` (catalog metadata) and ``check``."""

from __future__ import annotations

from pathlib import Path
from typing import Sequence

from mcpposture.checks import exec_location, fs_scope, hardcoded_secrets, permissions, supply_chain, transport
from mcpposture.checks.base import CheckContext, CheckInfo
from mcpposture.model import Finding, Inventory, ScanIssue

CHECKS = (hardcoded_secrets, supply_chain, transport, fs_scope, permissions, exec_location)
CATALOG: tuple[CheckInfo, ...] = tuple(m.INFO for m in CHECKS)

CHECK_ERROR = "check_error"


def run_all(inv: Inventory, homes: Sequence[Path] = ()) -> list[Finding]:
    """Run every check. A check that fails on unexpected input is recorded as a
    scan issue rather than aborting the scan, so one bad file cannot hide the
    findings from every other file."""
    ctx = CheckContext(inv, tuple(homes))
    findings: list[Finding] = []
    seen: set[str] = set()
    for module in CHECKS:
        try:
            produced = list(module.check(ctx))
        except Exception as e:  # noqa: BLE001
            inv.issues.append(ScanIssue(Path("-"), CHECK_ERROR, f"{module.INFO.id} failed: {type(e).__name__}"))
            continue
        for f in produced:
            if f.fingerprint not in seen:
                seen.add(f.fingerprint)
                findings.append(f)
    return findings
