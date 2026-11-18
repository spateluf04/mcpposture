"""Command-line entry point.

Exit codes: 0 clean, 1 findings at or above --fail-on (scan), a policy
violation (enforce), or an invalid policy (policy validate), 2 the tool itself
could not complete (bad arguments, unreadable target or policy, unwritable
output, internal error).
"""

from __future__ import annotations

import argparse
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Sequence

from mcpposture import __version__, checks, policy
from mcpposture.discovery import Limits, ScanError, scan_local, scan_path
from mcpposture.discovery.hostinfo import Host, detect
from mcpposture.model import Finding, Inventory, Severity
from mcpposture.report import jsonfmt, sarif, text
from mcpposture.report.write import write_report
from mcpposture.safefs import DEFAULT_MAX_BYTES, SafeReadError

EXIT_OK = 0
EXIT_FINDINGS = 1
EXIT_ERROR = 2

CATALOG = checks.CATALOG + (policy.INFO,)


def _positive_int(value: str) -> int:
    n = int(value)
    if n <= 0:
        raise argparse.ArgumentTypeError("must be a positive integer")
    return n


def _add_scan_args(p: argparse.ArgumentParser, *, policy_required: bool) -> None:
    p.add_argument("--path", type=Path, help="scan this file or directory tree instead of the known locations")
    p.add_argument("--format", choices=("text", "json", "sarif"), default="text")
    p.add_argument("-o", "--output", type=Path, help="write the report to this file (mode 0600) instead of stdout")
    p.add_argument(
        "--policy", type=Path, required=policy_required, help="TOML policy of approved and banned servers (see docs/policy.md)"
    )
    p.add_argument(
        "--windows-home",
        type=Path,
        action="append",
        help="Windows profile directory to scan from WSL, e.g. /mnt/c/Users/me (repeatable; default: auto-detect)",
    )
    p.add_argument("--max-file-bytes", type=_positive_int, default=DEFAULT_MAX_BYTES)
    p.add_argument("--max-depth", type=_positive_int, default=Limits.max_depth, help="--path directory depth limit")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="mcpposture",
        description="Audit AI agent and MCP server configurations on this machine. Read-only; never runs anything it finds.",
    )
    parser.add_argument("--version", action="version", version=f"mcpposture {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    scan = sub.add_parser("scan", help="discover and audit agent configurations")
    _add_scan_args(scan, policy_required=False)
    scan.add_argument(
        "--fail-on",
        choices=[s.label for s in Severity],
        default="high",
        help="exit 1 if any finding is at or above this severity (default: high)",
    )

    enforce = sub.add_parser("enforce", help="scan and exit 1 if the machine violates a policy (for CI and MDM)")
    _add_scan_args(enforce, policy_required=True)

    pol = sub.add_parser("policy", help="work with policy files")
    pol_sub = pol.add_subparsers(dest="policy_command", required=True)
    validate = pol_sub.add_parser("validate", help="lint a policy file")
    validate.add_argument("policy_file", type=Path)
    return parser


def run_checks(inv: Inventory, host: Host) -> list[Finding]:
    return checks.run_all(inv, (host.home, *host.windows_homes))


def _scan(args: argparse.Namespace, *, enforcing: bool) -> int:
    started = datetime.now(timezone.utc)
    pol = None
    if args.policy is not None:
        pol, _warnings = policy.load(args.policy)

    host = detect(windows_homes=args.windows_home)
    limits = Limits(max_file_bytes=args.max_file_bytes, max_depth=args.max_depth)
    if args.path is not None:
        inv = scan_path(args.path, host, limits=limits)
        mode = "path"
    else:
        inv = scan_local(host, cwd=Path.cwd(), limits=limits)
        mode = "local"
    findings = run_checks(inv, host)

    evaluation = None
    if pol is not None:
        evaluation = policy.evaluate(pol, inv, findings, (host.home, *host.windows_homes))
        findings = findings + evaluation.findings

    fail_on = Severity.parse(getattr(args, "fail_on", "high"))
    report = jsonfmt.build_report(
        inv, findings, host=host, mode=mode, target=args.path, started_at=started, fail_on=fail_on, evaluation=evaluation
    )
    if args.format == "json":
        rendered = jsonfmt.render(report)
    elif args.format == "sarif":
        rendered = sarif.render(report, CATALOG, base=Path.cwd())
    else:
        rendered = text.render(report)
    write_report(rendered, args.output)

    if enforcing:
        assert evaluation is not None
        return EXIT_OK if evaluation.compliant else EXIT_FINDINGS
    return EXIT_FINDINGS if any(f.severity >= fail_on for f in findings) else EXIT_OK


def _validate(args: argparse.Namespace) -> int:
    path = args.policy_file
    from mcpposture.safefs import read_config, real

    try:
        source = read_config(path, allowed_roots=[real(path).parent], max_bytes=1024 * 1024)
    except SafeReadError as e:
        print(f"mcpposture: error: {text.clean(path)}: {text.clean(e.detail)}", file=sys.stderr)
        return EXIT_ERROR
    parsed, problems = policy.parse(source, path=str(path))
    errors = [p for p in problems if p.level == "error"]
    warnings = [p for p in problems if p.level == "warning"]
    status = "invalid" if parsed is None else "valid"
    print(f"{text.clean(path)}: {status} ({len(errors)} errors, {len(warnings)} warnings)")
    for p in problems:
        print(f"  {p.level}: {text.clean(p.where)}: {text.clean(p.message)}")
    return EXIT_OK if parsed is not None else EXIT_FINDINGS


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    try:
        args = parser.parse_args(argv)
    except SystemExit as e:
        return EXIT_OK if e.code in (0, None) else EXIT_ERROR
    try:
        if args.command == "scan":
            return _scan(args, enforcing=False)
        if args.command == "enforce":
            return _scan(args, enforcing=True)
        if args.command == "policy":
            return _validate(args)
    except policy.PolicyError as e:
        print(f"mcpposture: error: invalid policy: {text.clean(e)}", file=sys.stderr)
        print("run `mcpposture policy validate` for details", file=sys.stderr)
        return EXIT_ERROR
    except SafeReadError as e:
        print(f"mcpposture: error: {text.clean(e.detail)}", file=sys.stderr)
        return EXIT_ERROR
    except ScanError as e:
        print(f"mcpposture: error: {text.clean(e)}", file=sys.stderr)
        return EXIT_ERROR
    except OSError as e:
        print(f"mcpposture: error: {text.clean(e.strerror or e)}: {text.clean(e.filename or '')}", file=sys.stderr)
        return EXIT_ERROR
    except Exception as e:  # noqa: BLE001 - any crash must still map to exit code 2
        print(f"mcpposture: internal error: {type(e).__name__}", file=sys.stderr)
        return EXIT_ERROR
    return EXIT_ERROR
