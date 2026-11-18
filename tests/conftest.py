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


def servers_from(entries: dict, *, client: str = "cursor", scope: str = "user", path: str = "/cfg/mcp.json"):
    """Parse ``{"name": entry}`` the way discovery would, returning ServerConfigs."""
    from mcpposture.discovery.parsers import PARSERS, FileContext
    from mcpposture.jsonc import loads

    doc = loads(json.dumps({"mcpServers": entries}, indent=2))
    return PARSERS["mcp_servers"](doc, FileContext(Path(path), client, scope, None)).servers


def settings_from(data: dict, *, client: str = "claude-code", scope: str = "user", path: str = "/cfg/settings.json"):
    from mcpposture.discovery.parsers import PARSERS, FileContext
    from mcpposture.jsonc import loads

    fmt = "vscode_settings" if client.startswith("vscode") else "claude_settings"
    doc = loads(json.dumps(data, indent=2))
    return PARSERS[fmt](doc, FileContext(Path(path), client, scope, None)).settings


def run_check(module, *, servers=(), settings=()):
    from mcpposture.checks.base import CheckContext
    from mcpposture.model import Inventory

    inv = Inventory(servers=list(servers), settings=list(settings))
    return list(module.check(CheckContext(inv, (Path("/home/me"),))))


def make_symlink(link: Path, target: Path, *, is_dir: bool = False) -> None:
    try:
        os.symlink(target, link, target_is_directory=is_dir)
    except (OSError, NotImplementedError) as e:
        pytest.skip(f"cannot create symlinks here: {e}")
