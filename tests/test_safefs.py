import os
import sys

import pytest

from mcpposture import safefs
from mcpposture.safefs import SafeReadError, read_config

from conftest import make_symlink, write


def kind_of(path, roots, **kw):
    with pytest.raises(SafeReadError) as e:
        read_config(path, allowed_roots=roots, **kw)
    return e.value.kind


def test_reads_regular_file(tmp_path):
    p = write(tmp_path / "a.json", '{"a": 1}')
    assert read_config(p, allowed_roots=[tmp_path]) == '{"a": 1}'


def test_strips_utf8_bom(tmp_path):
    p = tmp_path / "a.json"
    p.write_bytes(b"\xef\xbb\xbf{}")
    assert read_config(p, allowed_roots=[tmp_path]) == "{}"


def test_missing(tmp_path):
    assert kind_of(tmp_path / "nope.json", [tmp_path]) == safefs.MISSING


def test_directory_is_not_regular(tmp_path):
    (tmp_path / "d").mkdir()
    assert kind_of(tmp_path / "d", [tmp_path]) == safefs.NOT_REGULAR


def test_size_limit(tmp_path):
    p = write(tmp_path / "big.json", "x" * 100)
    assert kind_of(p, [tmp_path], max_bytes=10) == safefs.TOO_LARGE


def test_invalid_utf8(tmp_path):
    p = tmp_path / "bad.json"
    p.write_bytes(b'{"a": "\xff\xfe"}')
    assert kind_of(p, [tmp_path]) == safefs.DECODE_ERROR


def test_path_outside_root_is_refused(tmp_path):
    p = write(tmp_path / "outside.json", "{}")
    (tmp_path / "root").mkdir()
    assert kind_of(p, [tmp_path / "root"]) == safefs.SYMLINK_ESCAPE


def test_symlink_inside_root_is_followed(tmp_path):
    target = write(tmp_path / "real.json", "{}")
    link = tmp_path / "link.json"
    make_symlink(link, target)
    assert read_config(link, allowed_roots=[tmp_path]) == "{}"


def test_symlink_escaping_root_is_refused(tmp_path):
    secret = write(tmp_path / "outside" / "id_rsa", "PRIVATE")
    root = tmp_path / "repo"
    root.mkdir()
    link = root / ".mcp.json"
    make_symlink(link, secret)
    assert kind_of(link, [root]) == safefs.SYMLINK_ESCAPE


def test_symlinked_parent_directory_escaping_root_is_refused(tmp_path):
    write(tmp_path / "outside" / "mcp.json", "{}")
    root = tmp_path / "repo"
    root.mkdir()
    make_symlink(root / ".cursor", tmp_path / "outside", is_dir=True)
    assert kind_of(root / ".cursor" / "mcp.json", [root]) == safefs.SYMLINK_ESCAPE


def test_root_reached_through_symlink_still_works(tmp_path):
    real_root = tmp_path / "real"
    p = write(real_root / "a.json", "{}")
    link_root = tmp_path / "alias"
    make_symlink(link_root, real_root, is_dir=True)
    assert read_config(link_root / "a.json", allowed_roots=[link_root]) == "{}"
    assert read_config(p, allowed_roots=[link_root]) == "{}"


@pytest.mark.skipif(sys.platform == "win32", reason="FIFOs are POSIX-only")
def test_fifo_is_rejected_without_blocking(tmp_path):
    fifo = tmp_path / "mcp.json"
    os.mkfifo(fifo)
    assert kind_of(fifo, [tmp_path]) == safefs.NOT_REGULAR
