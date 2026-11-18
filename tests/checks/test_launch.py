import pytest

from mcpposture.checks.launch import docker_mount_sources, packages, program_name, unwrap

from conftest import servers_from

SHA = "0123456789abcdef0123456789abcdef01234567"
DIGEST = "sha256:" + "ab" * 32


def launch_of(command, *args):
    (s,) = servers_from({"s": {"command": command, "args": list(args)}})
    return unwrap(s)


@pytest.mark.parametrize(
    ("command", "expected"),
    [("npx", "npx"), ("C:\\Program Files\\nodejs\\npx.cmd", "npx"), ("/usr/bin/Python3", "python3"), ("uvx.exe", "uvx")],
)
def test_program_name(command, expected):
    assert program_name(command) == expected


def test_unwrap_cmd_c():
    launch = launch_of("cmd", "/c", "npx", "-y", "pkg")
    assert (launch.program, launch.args) == ("npx", ("-y", "pkg"))
    assert launch.pointer(1) == "/args/3"


def test_unwrap_env_assignments():
    launch = launch_of("env", "NODE_ENV=production", "node", "server.js")
    assert (launch.program, launch.args, launch.pointer(0)) == ("node", ("server.js",), "/args/2")


def test_unwrap_sh_c_points_at_script_string():
    launch = launch_of("bash", "-c", "npx -y 'pkg@latest' --flag")
    assert (launch.program, launch.args) == ("npx", ("-y", "pkg@latest", "--flag"))
    assert launch.pointer(1) == "/args/1"


def test_unwrap_bad_shell_string_does_not_crash():
    assert launch_of("sh", "-c", "unterminated 'quote").program == "sh"


def refs(command, *args):
    return [(r.spec, r.pinned) for r in packages(launch_of(command, *args))]


@pytest.mark.parametrize(
    ("argv", "expected"),
    [
        (("npx", "-y", "pkg"), [("pkg", False)]),
        (("npx", "-y", "pkg@1.2.3"), [("pkg@1.2.3", True)]),
        (("npx", "@scope/pkg@^1.2.0"), [("@scope/pkg@^1.2.0", False)]),
        (("npx", "-y", "@scope/pkg@latest"), [("@scope/pkg@latest", False)]),
        (("npx", "@scope/pkg"), [("@scope/pkg", False)]),
        (("npx", "-p", "pkg@2.0.0", "pkg-cli"), [("pkg@2.0.0", True)]),
        (("npx", "--package=pkg", "cli"), [("pkg", False)]),
        (("npx", "./local-server"), []),
        (("npx", f"github:org/repo#{SHA}"), [(f"github:org/repo#{SHA}", True)]),
        (("npx", "github:org/repo"), [("github:org/repo", False)]),
        (("npm", "exec", "pkg@1.0.0"), [("pkg@1.0.0", True)]),
        (("pnpm", "dlx", "pkg"), [("pkg", False)]),
        (("uvx", "mcp-server-fetch"), [("mcp-server-fetch", False)]),
        (("uvx", "mcp-server-fetch==2025.4.7"), [("mcp-server-fetch==2025.4.7", True)]),
        (("uvx", "mcp-server-fetch@2025.4.7"), [("mcp-server-fetch@2025.4.7", True)]),
        (("uvx", "tool@latest"), [("tool@latest", False)]),
        (("uvx", "pkg>=1.0"), [("pkg>=1.0", False)]),
        (("uvx", "--from", "pkg[extra]==1.0", "cli"), [("pkg[extra]==1.0", True)]),
        (("uvx", "--python", "3.12", "pkg"), [("pkg", False)]),
        (("uv", "tool", "run", "pkg==1.0"), [("pkg==1.0", True)]),
        (("pipx", "run", "pkg"), [("pkg", False)]),
        (("pipx", "run", "--spec", "pkg==1.0", "cli"), [("pkg==1.0", True)]),
        (("docker", "run", "-i", "--rm", "-e", "TOKEN", "mcp/server"), [("mcp/server", False)]),
        (("docker", "run", "mcp/server:latest"), [("mcp/server:latest", False)]),
        (("podman", "run", f"ghcr.io/o/s@{DIGEST}"), [(f"ghcr.io/o/s@{DIGEST}", True)]),
        (("docker", "ps"), []),
        (("node", "server.js"), []),
    ],
)
def test_packages(argv, expected):
    assert refs(*argv) == expected


def test_docker_tag_is_mutable():
    (ref,) = packages(launch_of("docker", "run", "--rm", "registry:5000/mcp/server:1.4"))
    assert ref.mutable_tag and not ref.pinned


def test_docker_mount_sources():
    launch = launch_of(
        "docker", "run", "-v", "/:/host", "--volume=C:\\Users\\me:/data", "--mount", "type=bind,source=/home/me,target=/m",
        "img", "-v", "/ignored:/after-image",
    )
    assert [src for src, _ in docker_mount_sources(launch)] == ["/", "C:\\Users\\me", "/home/me"]
