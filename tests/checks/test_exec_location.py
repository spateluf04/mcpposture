import pytest

from mcpposture.checks import exec_location as check
from mcpposture.checks.exec_location import location_kind
from mcpposture.model import Severity

from conftest import run_check, servers_from


def findings(command, *args):
    return run_check(check, servers=servers_from({"srv": {"command": command, "args": list(args)}}))


@pytest.mark.parametrize(
    ("path", "kind"),
    [
        ("/tmp/server", "untrusted"),
        ("/private/tmp/x", "untrusted"),
        ("/var/folders/ab/T/x", "untrusted"),
        ("/dev/shm/x", "untrusted"),
        ("C:\\Users\\sam\\Downloads\\server.exe", "untrusted"),
        ("C:\\Users\\sam\\AppData\\Local\\Temp\\x.exe", "untrusted"),
        ("C:\\Windows\\Temp\\x.exe", "untrusted"),
        ("~/Downloads/server", "untrusted"),
        ("%TEMP%\\x.bat", "untrusted"),
        ("./bin/server", "relative"),
        ("..\\tools\\server.exe", "relative"),
        ("bin/server", "relative"),
        ("npx", None),
        ("/usr/local/bin/server", None),
        ("C:\\Program Files\\Tool\\server.exe", None),
        ("${workspaceFolder}/bin/server", None),
        ("~/bin/server", None),
    ],
)
def test_location_kind(path, kind):
    assert location_kind(path) == kind


def test_binary_in_temp():
    (f,) = findings("/tmp/mcp-server")
    assert (f.check_id, f.severity, f.location.pointer) == ("MP007", Severity.HIGH, "/mcpServers/srv/command")
    assert f.cwe == ("CWE-829",)


def test_script_in_downloads_run_by_interpreter():
    (f,) = findings("node", "--require", "./hook.js", "/Users/sam/Downloads/server.js")
    assert f.location.pointer == "/mcpServers/srv/args/2"


def test_relative_script_is_medium_with_own_guidance():
    (f,) = findings("python3", "./server.py")
    assert f.severity == Severity.MEDIUM
    assert f.title == "Server launched from a relative path"
    assert f.cwe == ("CWE-427",)


def test_wrapped_command_points_at_real_program():
    (f,) = findings("cmd", "/c", "%TEMP%\\server.bat")
    assert f.location.pointer == "/mcpServers/srv/args/1"


@pytest.mark.parametrize(
    "argv",
    [
        ("npx", "-y", "pkg"),
        ("python", "-m", "my_server"),
        ("node", "/opt/mcp/server.js"),
        ("uvx", "mcp-server-fetch"),
        ("pwsh", "-File", "C:\\tools\\server.ps1"),
    ],
)
def test_clean(argv):
    assert findings(*argv) == []


def test_powershell_file_in_temp():
    (f,) = findings("powershell", "-File", "C:\\Windows\\Temp\\s.ps1")
    assert f.location.pointer == "/mcpServers/srv/args/1"
