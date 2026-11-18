# JSON report schema

`mcpposture scan --format json` writes one JSON object. `schema_version` follows these rules:

- a **minor** bump (`1.1` to `1.2`) adds fields; existing fields keep their names, types and meaning;
- a **major** bump (`1.x` to `2.0`) removes, renames or redefines something.

Consumers should check the major version and ignore fields they do not know. `mcpposture fleet` accepts any `1.x` report.

Current version: **1.2**.

| Field | Type | Since | Description |
|---|---|---|---|
| `schema_version` | string | 1.0 | Schema version, as above |
| `tool.name`, `tool.version` | string | 1.0 | Always `mcpposture`, and the tool version |
| `tool.rules_version` | string or null | 1.1 | Version of `rules.toml` used to classify servers |
| `machine.hostname`, `machine.os`, `machine.wsl` | string, string, bool | 1.0 | `os` is `windows`, `macos` or `linux` |
| `scan.mode` | string | 1.0 | `local` (known locations) or `path` (`--path`) |
| `scan.target`, `scan.started_at`, `scan.fail_on` | string | 1.0 | `--path` value or null, ISO 8601 UTC start time, threshold used |
| `summary` | object | 1.0 | Counts: `files`, `files_with_errors`, `servers`, `contexts`, `scan_issues`, `findings` (per severity), `highest_severity` |
| `policy` | object or null | 1.2 | Present when a policy was applied; see [policy.md](policy.md) |
| `findings[]` | array | 1.0 | Sorted by severity, then check ID |
| `findings[].check_id`, `severity`, `title`, `why`, `remediation` | string | 1.0 | `severity` is `critical`, `high`, `medium`, `low` or `info` |
| `findings[].cwe`, `owasp_llm`, `owasp_agentic` | string arrays | 1.0 | e.g. `CWE-798`, `LLM02:2025`, `ASI03:2026` |
| `findings[].client`, `server`, `context_id` | string or null | 1.0 | Where the finding applies |
| `findings[].location` | object | 1.0 | `path`, RFC 6901 JSON `pointer`, 1-based `line` or null |
| `findings[].evidence` | string | 1.0 | Already redacted |
| `findings[].fingerprint` | string | 1.0 | Stable across scans and machines (home directory folded to `~`) |
| `servers[]` | array | 1.0 | `id`, `name`, `client`, `scope`, `project`, `source`, `transport`, `command`, `args` (redacted), `url` (redacted), `env_keys`, `header_keys`, `env_file`. Env and header **values are never included** |
| `servers[].capabilities` | object | 1.1 | `flags` (subset of `A`, `B`, `C`), `source` (`rule`, `heuristic`, `unclassified`), `rules` (matching rule IDs) |
| `contexts[]` | array | 1.0 | `id`, `client`, `project`, `server_ids` |
| `contexts[].capabilities`, `unclassified_server_ids`, `rule_of_two` | array, array, string | 1.1 | `rule_of_two` is `violation`, `incomplete` or `ok` |
| `files[]` | array | 1.0 | Each config file read: `path`, `client`, `scope`, `format`, `status` (`ok`/`error`), `servers` |
| `scan_issues[]` | array | 1.0 | Files skipped or partly read: `path`, `kind` (`parse_error`, `too_large`, `symlink_escape`, `not_regular`, `decode_error`, `unreadable`, `invalid_entry`, `invalid_root`, `limit_reached`, `check_error`), `detail` |

Output is ASCII-only JSON: any non-ASCII character from a config appears as a `\uXXXX` escape.
