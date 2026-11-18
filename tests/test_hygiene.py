"""Static guarantees about the tool's own code: no process execution, no
network access, no dynamic code evaluation. Enforced on every test run."""

import ast
from pathlib import Path

import pytest

SRC = Path(__file__).resolve().parents[1] / "src" / "mcpposture"
FILES = sorted(SRC.rglob("*.py"))

BANNED_MODULES = {
    "subprocess", "socket", "ssl", "http", "ftplib", "smtplib", "telnetlib", "xmlrpc",
    "requests", "httpx", "aiohttp", "pickle", "marshal", "shelve", "ctypes", "multiprocessing",
    "asyncio", "platform", "webbrowser", "pty",
}
ALLOWED_SUBMODULES = {"urllib.parse"}
BANNED_BUILTINS = {"eval", "exec", "compile", "__import__", "breakpoint"}
BANNED_OS_CALLS = {"system", "popen", "startfile", "fork", "forkpty", "kill", "posix_spawn", "posix_spawnp"}


def _module_banned(name: str) -> bool:
    if name in ALLOWED_SUBMODULES:
        return False
    top = name.split(".")[0]
    return top in BANNED_MODULES or (top == "urllib" and name not in ALLOWED_SUBMODULES)


def violations(tree: ast.AST) -> list[str]:
    found = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            found += [f"import {a.name}" for a in node.names if _module_banned(a.name)]
        elif isinstance(node, ast.ImportFrom) and node.module and _module_banned(node.module):
            found.append(f"from {node.module} import ...")
        elif isinstance(node, ast.Call):
            fn = node.func
            if isinstance(fn, ast.Name) and fn.id in BANNED_BUILTINS:
                found.append(f"{fn.id}()")
            if isinstance(fn, ast.Attribute) and isinstance(fn.value, ast.Name) and fn.value.id == "os":
                if fn.attr in BANNED_OS_CALLS or fn.attr.startswith(("exec", "spawn")):
                    found.append(f"os.{fn.attr}()")
            for kw in node.keywords:
                if kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                    found.append("shell=True")
    return found


def test_source_files_found():
    assert len(FILES) > 5


@pytest.mark.parametrize("path", FILES, ids=lambda p: p.relative_to(SRC).as_posix())
def test_no_execution_network_or_eval(path):
    assert violations(ast.parse(path.read_text(encoding="utf-8"))) == []


def test_checker_catches_violations():
    bad = "import subprocess\nfrom urllib.request import urlopen\nimport os\nos.system('x')\neval('1')\nf(shell=True)\n"
    assert len(violations(ast.parse(bad))) == 5
