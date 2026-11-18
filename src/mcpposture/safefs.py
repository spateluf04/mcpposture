"""Defensive file reading for attacker-controlled configuration files."""

from __future__ import annotations

import os
import stat
from pathlib import Path
from typing import Sequence

DEFAULT_MAX_BYTES = 16 * 1024 * 1024  # ~/.claude.json grows to several MB on busy machines

MISSING = "missing"
UNREADABLE = "unreadable"
NOT_REGULAR = "not_regular"
SYMLINK_ESCAPE = "symlink_escape"
TOO_LARGE = "too_large"
DECODE_ERROR = "decode_error"

_OPEN_FLAGS = (
    os.O_RDONLY
    | getattr(os, "O_NOFOLLOW", 0)
    # Opening a FIFO for reading blocks until a writer appears; O_NONBLOCK lets
    # us reach the fstat check and reject it instead of hanging the scan.
    | getattr(os, "O_NONBLOCK", 0)
    | getattr(os, "O_BINARY", 0)
)


class SafeReadError(Exception):
    def __init__(self, kind: str, detail: str) -> None:
        super().__init__(detail)
        self.kind = kind
        self.detail = detail


def real(path: Path) -> Path:
    return Path(os.path.realpath(path))


def is_within(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
    except ValueError:
        return False
    return True


def read_config(
    path: Path,
    *,
    allowed_roots: Sequence[Path],
    max_bytes: int = DEFAULT_MAX_BYTES,
) -> str:
    """Return the UTF-8 text of ``path`` or raise SafeReadError.

    The fully resolved path must lie inside one of ``allowed_roots`` (themselves
    resolved here), so a symlink anywhere along the path cannot pull the scan
    outside its root. Only regular files are read.
    """
    try:
        os.lstat(path)
    except FileNotFoundError:
        raise SafeReadError(MISSING, "file does not exist") from None
    except OSError as e:
        raise SafeReadError(UNREADABLE, e.strerror or "cannot stat file") from None

    target = real(path)
    roots = [real(r) for r in allowed_roots]
    if not any(is_within(target, r) for r in roots):
        raise SafeReadError(SYMLINK_ESCAPE, f"resolves outside the scan root to {target}")

    # Checked before open() because Windows refuses to open directories at all;
    # the fstat below re-checks the opened handle in case the path was swapped.
    try:
        if not stat.S_ISREG(os.stat(target).st_mode):
            raise SafeReadError(NOT_REGULAR, "not a regular file")
    except OSError as e:
        raise SafeReadError(UNREADABLE, e.strerror or "cannot stat file") from None

    try:
        fd = os.open(target, _OPEN_FLAGS)
    except OSError as e:
        raise SafeReadError(UNREADABLE, e.strerror or "cannot open file") from None
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise SafeReadError(NOT_REGULAR, "not a regular file")
        if st.st_size > max_bytes:
            raise SafeReadError(TOO_LARGE, f"{st.st_size} bytes exceeds the {max_bytes}-byte limit")
        with os.fdopen(fd, "rb") as f:
            fd = -1
            data = f.read(max_bytes + 1)
    except OSError as e:
        raise SafeReadError(UNREADABLE, e.strerror or "read failed") from None
    finally:
        if fd != -1:
            os.close(fd)

    if len(data) > max_bytes:
        raise SafeReadError(TOO_LARGE, f"exceeds the {max_bytes}-byte limit")
    try:
        return data.decode("utf-8-sig")
    except UnicodeDecodeError as e:
        raise SafeReadError(DECODE_ERROR, f"not valid UTF-8 at byte {e.start}") from None
