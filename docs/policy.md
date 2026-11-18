# Policy file reference

A policy tells `mcpposture enforce` which MCP servers may run and how severe a finding may be. It is TOML, validated strictly: unknown keys, version ranges and malformed digests are errors, so a typo cannot silently weaken enforcement.

```sh
mcpposture policy validate policy.toml      # 0 valid, 1 invalid, 2 unreadable
mcpposture enforce --policy policy.toml     # 0 compliant, 1 violations, 2 tool error
mcpposture scan --policy policy.toml        # adds MP008 findings and a "policy" section, exit code still from --fail-on
```

## Top level

| Key | Type | Default | Meaning |
|---|---|---|---|
| `schema_version` | integer | required | Must be `1` |
| `max_severity` | string | none | `info`, `low`, `medium`, `high` or `critical`. Any check finding **more severe** than this is a violation. Omit it to ignore check findings and enforce only the server lists |
| `require_approved` | bool | `false` | When `true`, every configured server must match an `[[approved]]` entry |
| `[[approved]]` | array of tables | empty | Allowed servers |
| `[[banned]]` | array of tables | empty | Forbidden servers; a ban always wins and is reported as critical |

## Identifying a server

Each entry uses exactly one identity key. MCPosture derives the same identity from each configured server by reading its launch command or URL. It never runs the command, and it never uses the name in the config, which is a label the user chooses.

| Key | Matches | `[[approved]]` must also pin | Example |
|---|---|---|---|
| `npm` | Package run by `npx`, `bunx`, `npm exec`, `pnpm dlx`, `yarn dlx` | `version`: one exact version | `npm = "@playwright/mcp"`, `version = "0.0.41"` |
| `pypi` | Package run by `uvx`, `uv tool run`, `pipx run` (names normalised per PEP 503) | `version`: one exact version | `pypi = "mcp-server-fetch"`, `version = "2025.4.7"` |
| `oci` | Image run by `docker run`, `podman run`, `nerdctl run` (`docker.io/` and `library/` prefixes ignored) | `digest`: `sha256:` + 64 hex | `oci = "ghcr.io/github/github-mcp-server"` |
| `url` | A remote (HTTP, SSE, WebSocket) server; scheme and host case and a trailing slash are ignored | nothing, but it must be `https://` or `wss://` unless it is loopback | `url = "https://mcp.context7.com/mcp"` |
| `command` | The executable a stdio server runs, or for interpreters (`node`, `python`, ...) the script it runs, by absolute path | `sha256`: 64 hex of the file contents | `command = "/opt/acme/bin/acme-mcp"` |

So an approved npm package configured as `npx -y @playwright/mcp` or `@playwright/mcp@latest` is **not** approved: nothing pins what will download. A command whose file contents changed since approval is not approved either.

`note` (approved) and `reason` (banned) are free text shown in findings.

## Banned entries

`[[banned]]` takes an identity key and an optional `reason`. A ban covers **every version**, so `version`, `digest` and `sha256` are rejected there. A banned `url` ending in `*` matches by prefix, for example `https://untrusted.example.com/*`.

## What `validate` checks

Errors (the policy is unusable):

- invalid TOML, `schema_version` not 1, unknown top-level or entry keys
- an entry with zero or several identity keys, or a non-string value
- `npm`/`pypi` without `version`, or a version that is a range or tag (`^1.2`, `>=1`, `latest`)
- `oci` without a well-formed `digest`; `command` without a 64-hex `sha256` or not an absolute path
- an approved `url` over plain HTTP to a non-loopback host
- a pin key on an identity it does not apply to (`version` on a `url`, for example)
- the same identity both approved and banned
- `max_severity` not a known severity, `require_approved` not a boolean

Warnings (valid, but probably not what you meant):

- duplicate approved entries
- `require_approved = true` with nothing approved: every server will violate
- nothing enforced at all: no `require_approved`, no bans, no `max_severity`

## Report output

With a policy, the JSON report gains a `policy` section:

```json
"policy": {
  "path": "policy.toml",
  "sha256": "5f1c...",
  "max_severity": "medium",
  "require_approved": true,
  "compliant": false,
  "violations": [
    {"fingerprint": "...", "check_id": "MP008", "severity": "high", "server": "playwright", "reason": "not_approved"},
    {"fingerprint": "...", "check_id": "MP005", "severity": "high", "server": "filesystem", "reason": "above_max_severity"}
  ]
}
```

`reason` is `banned`, `not_approved`, or `above_max_severity`. The SHA-256 records exactly which policy text the machine was judged against.
