import sys

import pytest

from mcpposture.discovery.walk import walk

from conftest import make_symlink, write


def names(result, root):
    return sorted(p.relative_to(root).as_posix() for p in result.files)


def test_walks_nested_files(tmp_path):
    write(tmp_path / ".mcp.json", "{}")
    write(tmp_path / "a" / ".cursor" / "mcp.json", "{}")
    assert names(walk(tmp_path, max_depth=8, max_entries=1000), tmp_path) == [".mcp.json", "a/.cursor/mcp.json"]


def test_depth_limit(tmp_path):
    write(tmp_path / "1" / "2" / "3" / "deep.json", "{}")
    write(tmp_path / "1" / "shallow.json", "{}")
    assert names(walk(tmp_path, max_depth=1, max_entries=1000), tmp_path) == ["1/shallow.json"]


def test_skips_dependency_and_vcs_dirs(tmp_path):
    write(tmp_path / "node_modules" / "pkg" / ".mcp.json", "{}")
    write(tmp_path / ".git" / "mcp.json", "{}")
    write(tmp_path / ".vscode" / "mcp.json", "{}")
    assert names(walk(tmp_path, max_depth=8, max_entries=1000), tmp_path) == [".vscode/mcp.json"]


def test_entry_limit_truncates(tmp_path):
    for i in range(20):
        write(tmp_path / f"f{i}.json", "{}")
    result = walk(tmp_path, max_depth=8, max_entries=5)
    assert result.truncated
    assert len(result.files) <= 5


def test_does_not_descend_symlinked_directories(tmp_path):
    outside = tmp_path / "outside"
    write(outside / ".mcp.json", "{}")
    root = tmp_path / "root"
    root.mkdir()
    make_symlink(root / "link", outside, is_dir=True)
    result = walk(root, max_depth=8, max_entries=1000)
    assert result.files == []
    assert result.skipped_links == 1


def test_returns_symlinked_files_for_the_reader_to_vet(tmp_path):
    target = write(tmp_path / "outside.json", "{}")
    root = tmp_path / "root"
    root.mkdir()
    make_symlink(root / ".mcp.json", target)
    assert names(walk(root, max_depth=8, max_entries=1000), root) == [".mcp.json"]


@pytest.mark.skipif(sys.platform != "win32", reason="NTFS junctions are Windows-only")
def test_does_not_descend_junctions(tmp_path):
    import _winapi

    outside = tmp_path / "outside"
    write(outside / ".mcp.json", "{}")
    root = tmp_path / "root"
    root.mkdir()
    _winapi.CreateJunction(str(outside), str(root / "junction"))
    assert walk(root, max_depth=8, max_entries=1000).files == []
