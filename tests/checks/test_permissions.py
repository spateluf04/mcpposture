import pytest

from mcpposture.checks import permissions as check
from mcpposture.model import Severity

from conftest import run_check, servers_from, settings_from


def claude(data, scope="user"):
    return run_check(check, settings=[settings_from(data, scope=scope)])


def vscode(data):
    return run_check(check, settings=[settings_from(data, client="vscode")])


def test_bypass_mode_in_user_settings_is_high():
    (f,) = claude({"permissions": {"defaultMode": "bypassPermissions"}})
    assert (f.check_id, f.severity, f.location.pointer) == ("MP006", Severity.HIGH, "/permissions/defaultMode")


def test_bypass_mode_in_project_settings_is_medium():
    (f,) = claude({"permissions": {"defaultMode": "bypassPermissions"}}, scope="project")
    assert f.severity == Severity.MEDIUM
    assert "2.1.257" in f.why


@pytest.mark.parametrize("mode", ["default", "acceptEdits", "plan", "dontAsk", "auto"])
def test_other_modes_not_flagged(mode):
    assert claude({"permissions": {"defaultMode": mode}}) == []


@pytest.mark.parametrize("rule", ["Bash", "Bash(*)", "Bash( * )", "Bash(:*)", "Bash(*:*)", "Bash()"])
def test_wildcard_shell_rules(rule):
    (f,) = claude({"permissions": {"allow": [rule]}})
    assert (f.severity, f.title) == (Severity.HIGH, "Every shell command is pre-approved")
    assert f.location.pointer == "/permissions/allow/0"


@pytest.mark.parametrize("rule", ["Bash(python *)", "Bash(curl:*)", "Bash(npx *)", "Bash(/usr/bin/node *)"])
def test_interpreter_wildcards_are_medium(rule):
    (f,) = claude({"permissions": {"allow": [rule]}})
    assert f.severity == Severity.MEDIUM


@pytest.mark.parametrize(
    "rule", ["Bash(npm run test *)", "Bash(git status)", "Read(./src/**)", "mcp__github__*", "WebFetch(domain:docs.example.com)", 42]
)
def test_narrow_rules_not_flagged(rule):
    assert claude({"permissions": {"allow": [rule]}}) == []


def test_deny_rules_are_ignored():
    assert claude({"permissions": {"deny": ["Bash"]}}) == []


def test_enable_all_project_servers():
    (shared,) = claude({"enableAllProjectMcpServers": True}, scope="project")
    (personal,) = claude({"enableAllProjectMcpServers": True}, scope="user")
    assert (shared.severity, personal.severity) == (Severity.HIGH, Severity.MEDIUM)
    assert claude({"enableAllProjectMcpServers": False}) == []


def test_skip_flag_inside_hook_command():
    (f,) = claude({"hooks": {"Stop": [{"hooks": [{"type": "command", "command": "claude -p --dangerously-skip-permissions fix"}]}]}})
    assert f.location.pointer == "/hooks/Stop/0/hooks/0/command"


def test_skip_flag_in_server_args():
    servers = servers_from({"nested": {"command": "claude", "args": ["mcp", "serve", "--dangerously-skip-permissions"]}})
    (f,) = run_check(check, servers=servers)
    assert f.location.pointer == "/mcpServers/nested/args/2"


@pytest.mark.parametrize(
    ("data", "title"),
    [
        ({"chat.tools.global.autoApprove": True}, "Every agent tool call is auto-approved"),
        ({"github.copilot.chat.claudeAgent.allowDangerouslySkipPermissions": True}, "Claude agent in VS Code skips all permission checks"),
        ({"chat.permissions.default": "autoApprove"}, "New chat sessions run tools without confirmation"),
        ({"chat.permissions.default": "autopilot"}, "New chat sessions run tools without confirmation"),
        ({"chat.tools.terminal.autoApprove": {"/.*/": True}}, "Every terminal command is auto-approved"),
        ({"chat.tools.terminal.autoApprove": {"/^.*$/": {"approve": True, "matchCommandLine": True}}}, "Every terminal command is auto-approved"),
    ],
)
def test_vscode_high(data, title):
    (f,) = vscode(data)
    assert (f.severity, f.title) == (Severity.HIGH, title)


def test_vscode_interpreter_auto_approve_is_medium():
    (f,) = vscode({"chat.tools.terminal.autoApprove": {"python": True, "/^curl\\b/": True}})[:1]
    assert f.severity == Severity.MEDIUM
    assert len(vscode({"chat.tools.terminal.autoApprove": {"python": True, "/^curl\\b/": True}})) == 2


@pytest.mark.parametrize(
    "data",
    [
        {"chat.tools.global.autoApprove": False},
        {"chat.permissions.default": "default"},
        {"chat.tools.terminal.autoApprove": {"rm": False, "/.*/": False, "git status": True}},
        {"chat.tools.terminal.autoApprove": {"/.*/": True}, "chat.tools.terminal.enableAutoApprove": False},
    ],
)
def test_vscode_safe(data):
    assert vscode(data) == []
