"""Redaction tests. Every fake secret is assembled at runtime from obviously
fake pieces so no credential-shaped literal is committed to the repository."""

import pytest

from mcpposture.redact import (
    classify,
    find_secrets,
    mask,
    named_secret,
    redact,
    redact_args,
    redact_url,
    redact_value,
)

FAKE = {
    "anthropic": "sk-ant-api03-" + "FAKEkey0123456789abcdEXAMPLE",
    "openai": "sk-proj-" + "FAKE0123456789abcdefEXAMPLE",
    "github": "ghp_" + "FAKE0123456789abcdefghijklmnopqrstuv",
    "gitlab": "glpat-" + "FAKE0123456789abcdef",
    "aws": "AKIA" + "FAKEEXAMPLE01234",
    "google": "AIza" + "FAKE_0123456789abcdefghijklmnopqrst",
    "slack": "xoxb-" + "0000-FAKE-EXAMPLE",
    "stripe": "sk_test_" + "FAKE0123456789abcdef",
    "huggingface": "hf_" + "FAKE0123456789abcdefghijklmnopqr",
    "npm": "npm_" + "FAKE0123456789abcdefghijklmnopqrstuv",
    "jwt": "eyJhbGciOiJIUzI1NiJ9" + "." + "eyJzdWIiOiJGQUtFIn0" + "." + "FAKEsignature0123",
}
PEM = "-----BEGIN " + "PRIVATE KEY-----\nFAKEFAKEFAKEbody0123\n-----END " + "PRIVATE KEY-----"
RANDOM = "Zx9Qw3Er7Ty1Ui5Op2As8Df4"


def assert_not_leaked(secret: str, output: str) -> None:
    assert secret not in output
    for i in range(len(secret) - 4):
        window = secret[i : i + 5]
        assert window not in output, f"{window!r} of the secret leaked into {output!r}"


@pytest.mark.parametrize("provider", sorted(FAKE))
def test_provider_patterns_detect_and_redact(provider):
    secret = FAKE[provider]
    text = f"before {secret} after"
    assert [m.provider for m in find_secrets(text)] == [provider]
    out = redact(text)
    assert out == f"before [REDACTED {provider} ...{secret[-4:]}] after"
    assert_not_leaked(secret, out)


def test_private_key_block_is_fully_redacted_without_tail():
    out = redact(f"key={PEM}")
    assert out == "key=[REDACTED private-key]"


def test_high_entropy_token():
    assert [m.provider for m in find_secrets(RANDOM)] == ["high-entropy"]
    assert_not_leaked(RANDOM, redact(RANDOM))


@pytest.mark.parametrize(
    "benign",
    [
        "${GITHUB_PERSONAL_ACCESS_TOKEN}",
        "${env:OPENAI_API_KEY}",
        "${input:githubToken}",
        "Bearer ${API_KEY}",
        "@modelcontextprotocol/server-filesystem",
        "/Users/someone/Projects/very-long-directory-name-2024",
        "C:\\Users\\someone\\AppData\\Roaming\\npm\\node_modules",
        "ghcr.io/org/image@sha256:" + "3f2a9c" * 10 + "abcd",
        "9fceb02d0ae598e95dc970b74767f19372d61af8",
        "123e4567-e89b-12d3-a456-426614174000",
        "https://api.example.com/v1/endpoint",
        "@playwright/mcp@0.0.41",
        "MCP_SERVER_REQUEST_TIMEOUT_MILLISECONDS",
    ],
)
def test_benign_values_are_not_secrets(benign):
    assert find_secrets(benign) == []
    assert redact(benign) == benign


def test_reference_default_is_still_scanned():
    secret = FAKE["anthropic"]
    assert [m.provider for m in find_secrets("${API_KEY:-" + secret + "}")] == ["anthropic"]


def test_mask_hides_short_secrets_entirely():
    assert mask("short123", "named-secret") == "[REDACTED named-secret]"
    assert mask("abcdefghijkl", "x") == "[REDACTED x ...ijkl]"


@pytest.mark.parametrize(
    ("name", "value", "expected"),
    [
        ("API_KEY", "hunter2pass", True),
        ("DB_PASSWORD", "correcthorse", True),
        ("Authorization", "Basic dXNlcjpwYXNz", True),
        ("API_KEY", "${API_KEY}", False),
        ("TOKEN_FILE", "/home/me/.config/token", False),
        ("GITHUB_TOKEN", "", False),
        ("PORT", "8080", False),
        ("LOG_LEVEL", "verbose-mode", False),
    ],
)
def test_named_secret(name, value, expected):
    assert named_secret(name, value) is expected


def test_classify_falls_back_to_key_name():
    assert [m.method for m in classify("hunter2pass", "API_KEY")] == ["name"]
    assert classify("hunter2pass", "USERNAME") == []


def test_redact_value_named():
    assert redact_value("hunter2pass", "API_KEY") == "[REDACTED named-secret]"


def test_redact_args_flag_forms():
    gh = FAKE["github"]
    args = ("--api-key", "plainvalue1", "--token=plainvalue2", "--verbose", "file.txt", "--header", f"Authorization: Bearer {gh}")
    out = redact_args(args)
    assert out[0] == "--api-key"
    assert out[1] == "[REDACTED named-secret]"
    assert out[2] == "--token=[REDACTED named-secret]"
    assert out[3:5] == ("--verbose", "file.txt")
    assert_not_leaked(gh, " ".join(out))


def test_redact_url_credentials_and_query():
    url = "https://user:" + "p4ssw0rdFAKE" + "@mcp.example.com/mcp?api_key=plainvalue1&mode=fast"
    out = redact_url(url)
    assert "p4ssw0rd" not in out
    assert "plainvalue1" not in out
    assert out.startswith("https://[REDACTED credentials]@mcp.example.com/mcp?")
    assert out.endswith("&mode=fast")


@pytest.mark.parametrize("secret", list(FAKE.values()) + [RANDOM])
def test_no_output_path_leaks(secret):
    outputs = [
        redact(secret),
        redact_value(secret, "ANY"),
        " ".join(redact_args(("--key", secret, f"--x={secret}", secret))),
        redact_url(f"https://h.example/{secret}?q={secret}#{secret}"),
    ]
    for out in outputs:
        assert_not_leaked(secret, out)
