import os
import stat
import sys

import pytest

from mcpposture.report.write import write_report

from conftest import make_symlink

posix_only = pytest.mark.skipif(sys.platform == "win32", reason="POSIX permission bits")


def test_writes_file(tmp_path):
    p = tmp_path / "r.json"
    write_report("{}\n", p)
    assert p.read_text(encoding="utf-8") == "{}\n"


@posix_only
def test_new_report_is_0600(tmp_path):
    p = tmp_path / "r.json"
    write_report("x", p)
    assert stat.S_IMODE(os.stat(p).st_mode) == 0o600


@posix_only
def test_existing_world_readable_file_is_tightened(tmp_path):
    p = tmp_path / "r.json"
    p.write_text("old")
    os.chmod(p, 0o644)
    write_report("new", p)
    assert stat.S_IMODE(os.stat(p).st_mode) == 0o600
    assert p.read_text() == "new"


@posix_only
def test_refuses_to_write_through_symlink(tmp_path):
    victim = tmp_path / "victim"
    victim.write_text("keep")
    link = tmp_path / "r.json"
    make_symlink(link, victim)
    with pytest.raises(OSError):
        write_report("overwrite", link)
    assert victim.read_text() == "keep"


def test_stdout(capsys):
    write_report("hello\n", None)
    assert capsys.readouterr().out == "hello\n"
