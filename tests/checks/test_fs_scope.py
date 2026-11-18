import pytest

from mcpposture.checks import fs_scope as check
from mcpposture.checks.fs_scope import classify_root

from conftest import run_check, servers_from

FS = "@modelcontextprotocol/server-filesystem"


def fs_findings(*paths, package=FS):
    return run_check(check, servers=servers_from({"fs": {"command": "npx", "args": ["-y", package, *paths]}}))


@pytest.mark.parametrize(
    ("path", "kind"),
    [
        ("/", "root"),
        ("C:\\", "root"),
        ("c:", "root"),
        ("/mnt/c", "root"),
        ("/Users", "root"),
        ("~", "home"),
        ("${userHome}", "home"),
        ("%USERPROFILE%", "home"),
        ("/Users/sam", "home"),
        ("/home/sam/", "home"),
        ("C:\\Users\\sam", "home"),
        ("/mnt/c/Users/sam", "home"),
        ("~/.ssh", "sensitive"),
        ("/home/sam/.aws/credentials", "sensitive"),
        ("C:\\Users\\sam\\AppData\\Roaming\\Microsoft\\Credentials", "sensitive"),
        ("/Users/sam/Library/Keychains", "sensitive"),
        ("/var/run/docker.sock", "docker-socket"),
        ("/Users/sam/projects/app", None),
        ("${workspaceFolder}", None),
        ("./data", None),
        ("/Users/sam/.sshkeys-not-really", None),
    ],
)
def test_classify_root(path, kind):
    assert classify_root(path) == kind


def test_filesystem_server_roots():
    found = fs_findings("/Users/sam/projects/app", "/", "~/.ssh")
    assert [(f.title, f.location.pointer) for f in found] == [
        ("Filesystem access to an entire drive", "/mcpServers/fs/args/3"),
        ("Filesystem access to a credential store", "/mcpServers/fs/args/4"),
    ]
    assert all(f.check_id == "MP005" and f.cwe == ("CWE-250",) for f in found)


def test_pinned_filesystem_server_still_checked():
    (f,) = fs_findings("C:\\Users\\sam", package=FS + "@2025.8.21")
    assert f.title == "Filesystem access to the whole home directory"


def test_other_servers_positional_paths_ignored():
    assert fs_findings("/", package="@example/other-server") == []


def test_docker_mounts_checked_for_any_image():
    servers = servers_from(
        {"c": {"command": "docker", "args": ["run", "-i", "-v", "/:/host", "-v", "/var/run/docker.sock:/var/run/docker.sock", "-v", "/srv/app:/app", "mcp/thing"]}}
    )
    titles = [f.title for f in run_check(check, servers=servers)]
    assert titles == ["Filesystem access to an entire drive", "Container can control the host Docker daemon"]
