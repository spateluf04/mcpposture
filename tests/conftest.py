from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

FIXTURES = Path(__file__).parent / "fixtures"


def write(path: Path, content: str | dict | list) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    text = content if isinstance(content, str) else json.dumps(content, indent=2)
    path.write_text(text, encoding="utf-8")
    return path


def make_symlink(link: Path, target: Path, *, is_dir: bool = False) -> None:
    try:
        os.symlink(target, link, target_is_directory=is_dir)
    except (OSError, NotImplementedError) as e:
        pytest.skip(f"cannot create symlinks here: {e}")
