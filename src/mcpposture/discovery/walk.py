"""Bounded directory walk for --path scans that never descends through links."""

from __future__ import annotations

import os
import stat
from dataclasses import dataclass, field
from pathlib import Path

SKIP_DIRS = frozenset(
    {".git", ".hg", ".svn", "node_modules", ".venv", "venv", "__pycache__", ".tox", ".mypy_cache", ".pytest_cache"}
)
_REPARSE_POINT = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)


@dataclass
class WalkResult:
    files: list[Path] = field(default_factory=list)
    truncated: bool = False
    skipped_links: int = 0


def _is_link(entry: os.DirEntry[str]) -> bool:
    if entry.is_symlink():
        return True
    # Python 3.11's is_symlink() is False for NTFS junctions, which can point
    # anywhere on the disk; treat every reparse point as a link.
    attrs = getattr(entry.stat(follow_symlinks=False), "st_file_attributes", 0)
    return bool(attrs & _REPARSE_POINT)


def walk(root: Path, *, max_depth: int, max_entries: int) -> WalkResult:
    """Files under ``root`` up to ``max_depth`` directories deep.

    Symlinked files are returned (the reader decides whether their target is
    inside the root); symlinked and junctioned directories are never entered.
    """
    result = WalkResult()
    stack: list[tuple[Path, int]] = [(root, 0)]
    seen = 0
    while stack:
        directory, depth = stack.pop()
        try:
            with os.scandir(directory) as it:
                entries = sorted(it, key=lambda e: e.name)
        except OSError:
            continue
        subdirs: list[tuple[Path, int]] = []
        for entry in entries:
            seen += 1
            if seen > max_entries:
                result.truncated = True
                return result
            try:
                if _is_link(entry):
                    if entry.is_file():
                        result.files.append(Path(entry.path))
                    else:
                        result.skipped_links += 1
                elif entry.is_dir(follow_symlinks=False):
                    if entry.name not in SKIP_DIRS and depth < max_depth:
                        subdirs.append((Path(entry.path), depth + 1))
                elif entry.is_file(follow_symlinks=False):
                    result.files.append(Path(entry.path))
            except OSError:
                continue
        stack.extend(reversed(subdirs))
    return result
