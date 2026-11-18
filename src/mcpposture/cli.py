"""Command-line entry point.

Exit codes: 0 no findings at or above --fail-on, 1 findings at or above it,
2 the tool itself could not complete (bad arguments, unreadable target,
unwritable output, internal error).
"""

from __future__ import annotations

import argparse
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Sequence

from mcpposture import __version__
from mcpposture.discovery import Limits, ScanError, scan_local, scan_path
from mcpposture.discovery.hostinfo import detect
from mcpposture.model import Finding, Severity
from mcpposture.report import jsonfmt, text
from mcpposture.report.write import write_report
from mcpposture.safefs import DEFAULT_MAX_BYTES

EXIT_OK = 0
EXIT_FINDINGS = 1
EXIT_ERROR = 2


def _positive_int(value: str) -> int:
    n = int(value)
    if n <= 0:
        raise argparse.ArgumentTypeError("must be a positive integer")
    return n


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="mcpposture",
        description="Audit AI agent and MCP server configurations on this machine. Read-only; never runs anything it finds.",
    )
    parser.add_argument("--version", action="version", version=f"mcpposture {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    scan = sub.add_parser("scan", help="discover and audit agent configurations")
    scan.add_argument("--path", type=Path, help="scan this file or directory tree instead of the known locations")
    scan.add_argument("--format", choices=("text", "json"), default="text")
    scan.add_argument("-o", "--output", type=Path, help="write the report to this file (mode 0600) instead of stdout")
    scan.add_argument(
        "--fail-on",
        choices=[s.label for s in Severity],
        default="high",
        help="exit 1 if any finding is at or above this severity (default: high)",
    )
    scan.add_argument(
        "--windows-home",
        type=Path,
        action="append",
        help="Windows profile directory to scan from WSL, e.g. /mnt/c/Users/me (repeatable; default: auto-detect)",
    )
    scan.add_argument("--max-file-bytes", type=_positive_int, default=DEFAULT_MAX_BYTES)
    scan.add_argument("--max-depth", type=_positive_int, default=Limits.max_depth, help="--path directory depth limit")
    return parser


def run_checks(inventory: object) -> list[Finding]:
    return []


def _scan(args: argparse.Namespace) -> int:
    started = datetime.now(timezone.utc)
    host = detect(windows_homes=args.windows_home)
    limits = Limits(max_file_bytes=args.max_file_bytes, max_depth=args.max_depth)
    if args.path is not None:
        inv = scan_path(args.path, host, limits=limits)
        mode = "path"
    else:
        inv = scan_local(host, cwd=Path.cwd(), limits=limits)
        mode = "local"
    findings = run_checks(inv)
    fail_on = Severity.parse(args.fail_on)
    report = jsonfmt.build_report(
        inv, findings, host=host, mode=mode, target=args.path, started_at=started, fail_on=fail_on
    )
    rendered = jsonfmt.render(report) if args.format == "json" else text.render(report)
    write_report(rendered, args.output)
    return EXIT_FINDINGS if any(f.severity >= fail_on for f in findings) else EXIT_OK


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    try:
        args = parser.parse_args(argv)
    except SystemExit as e:
        return EXIT_OK if e.code in (0, None) else EXIT_ERROR
    try:
        if args.command == "scan":
            return _scan(args)
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
