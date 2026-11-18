"""Write reports to stdout or to a file only the current user can read."""

from __future__ import annotations

import os
import sys
from pathlib import Path

REPORT_MODE = 0o600
_FLAGS = os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0)


def write_report(text: str, path: Path | None) -> None:
    """Write ``text`` to ``path`` with mode 0600, or to stdout when path is None.

    O_NOFOLLOW refuses to write through a planted symlink on POSIX. On Windows
    the file inherits the directory ACL; mode bits do not apply there.
    """
    if path is None:
        sys.stdout.write(text)
        sys.stdout.flush()
        return
    fd = os.open(path, _FLAGS, REPORT_MODE)
    try:
        if hasattr(os, "fchmod"):
            # The mode argument only applies when the file is created.
            os.fchmod(fd, REPORT_MODE)
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as f:
            fd = -1
            f.write(text)
    finally:
        if fd != -1:
            os.close(fd)
