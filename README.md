# MCPosture

**Find risky AI agent and MCP server configurations on developer machines, before an attacker does.**

AI coding agents (Claude Code, Cursor, VS Code, Claude Desktop) now load third-party "MCP servers" that can read files, browse the web, and run commands with the developer's own permissions, and the settings files that wire this up have become a new, mostly unaudited part of every endpoint. MCPosture reads those files, never runs anything in them, and tells engineers and non-specialists alike which configurations are dangerous, why, and how to fix them.

> MCPosture is an independent project. It is not affiliated with, sponsored by, or endorsed by Meta, Anthropic, Microsoft, Cursor (Anysphere), or OWASP.

## Sample output

```text
$ mcpposture scan --path tests/fixtures/vulnerable_repo
MCPosture 0.1.0  laptop [macos]
Scanned 3 config files (0 unreadable), found 7 servers in 2 agent contexts.

Summary
  7 MCP servers: 7 need attention
    CRITICAL aws-docs                 Claude Code (project)  Hardcoded aws credential (+2 more)
    HIGH     intranet                 Claude Code (project)  Remote MCP server over cleartext transport
    HIGH     filesystem               Claude Code (project)  Filesystem access to an entire drive (+1 more)
    ...
    MEDIUM   local-script             VS Code (project)      Server launched from a relative path

  1 risky combination: one agent can read untrusted content, reach private data and act externally
    HIGH     Claude Code in .../vulnerable_repo: aws-docs, filesystem, web

  4 other settings need attention
    HIGH     Every shell command is pre-approved
             in vulnerable_repo/.claude/settings.json:4  /permissions/allow/0
    ...

  Details for each problem follow below.

CRITICAL (1)
  MP002  Hardcoded aws credential  [aws-docs]
      at   vulnerable_repo/.mcp.json:7  /mcpServers/aws-docs/env/AWS_ACCESS_KEY_ID
      saw  env AWS_ACCESS_KEY_ID = [REDACTED aws ...MPLE]
      why  A secret stored in plain text in a config file can be read by any process or
      person with access to the file, its backups, or its git history, and agents can be
      tricked into reading their own config.
      fix  Rotate the credential now, then reference it instead of storing it: use
      ${VAR} environment expansion, VS Code ${input:...} prompts, or the client's OAuth
      support.
      refs CWE-798, LLM02:2025, ASI03:2026

HIGH (9)
  MP001  Agent combines untrusted input, private data, and external actions  [aws-docs]
      at   vulnerable_repo/.mcp.json:3  /mcpServers/aws-docs
      saw  [A] untrusted input: web; [B] private data: aws-docs, filesystem; [C] external actions: aws-docs, filesystem, web
      ...
  MP005  Filesystem access to a credential store  [filesystem]
      at   vulnerable_repo/.mcp.json:18  /mcpServers/filesystem/args/3
      saw  allowed path ~/.ssh
      ...

Servers  (Rule of Two: A untrusted input, B private data, C external actions; lowercase = heuristic guess, ??? = unclassified)
  -bc  claude-code      project  aws-docs        stdio  npx -y @example/aws-mcp
  -BC  claude-code      project  filesystem      stdio  npx -y @modelcontextprotocol/server-filesystem@2025.8.21 / ~/.ssh
  A-C  claude-code      project  web             stdio  uvx mcp-server-fetch
  ???  vscode           project  containers      stdio  docker run -i --rm -v /var/run/docker.sock:/var/run/docker.sock ...

Agent contexts
  ABC  violation  claude-code:project:.../vulnerable_repo
  ---  incomplete vscode:project:.../vulnerable_repo
```

(Trimmed. The summary gives one line per server, risky combination and setting, worst first. Below it, every finding prints its location, the redacted evidence, why it matters, the fix, and its CWE and OWASP references.)

## Install and use

Python 3.11 or newer. No runtime dependencies beyond the standard library.

```sh
pip install git+https://github.com/spateluf04/mcpposture
# or, from a checkout:
pip install -e ".[dev]"
```

| Command | What it does |
|---|---|
| `mcpposture scan` | Audit every known config location for the current user, plus each project those configs mention |
| `mcpposture scan --path DIR_OR_FILE` | Audit one file or a repository tree (depth 8, never leaves the directory) |
| `mcpposture scan --format json -o report.json` | Versioned JSON report ([schema](docs/report-schema.md)), written with mode 0600 |
| `mcpposture scan --format sarif -o mcpposture.sarif` | SARIF 2.1.0 for GitHub code scanning |
| `mcpposture enforce --policy policy.toml` | Exit 1 if the machine violates the policy: for CI, MDM, or a login hook |
| `mcpposture policy validate policy.toml` | Lint a policy file |
| `mcpposture fleet reports/` | Summarise JSON reports collected from many machines |

On WSL2, `scan` also covers the Windows profile under `/mnt/c/Users/...` (auto-detected; override with `--windows-home`). On Windows, if `mcpposture.exe` misbehaves because the install path contains a space, use `python -m mcpposture`.

**Exit codes:** `0` nothing at or above `--fail-on` (default `high`) / policy compliant, `1` findings at or above the threshold / policy violated / policy file invalid, `2` the tool itself could not run (bad arguments, unreadable target or policy, unwritable output). A config file that cannot be parsed is reported as a scan issue and does not change the exit code, so a hostile file cannot make CI fail or pass on purpose.

## What it reads

All locations live in one table, [`discovery/locations.py`](src/mcpposture/discovery/locations.py); each row links to the vendor documentation it was taken from.

| Client | Files |
|---|---|
| Claude Desktop | `claude_desktop_config.json` in `~/Library/Application Support/Claude` (macOS), `%APPDATA%\Claude` (Windows), `~/.config/Claude` (Linux) |
| Claude Code | `~/.claude.json` (user and per-project "local" servers), project `.mcp.json`, `~/.claude/settings.json`, `.claude/settings.json`, `.claude/settings.local.json`, and the managed `managed-mcp.json`, `managed-settings.json`, `managed-settings.d/` in the system directory |
| Cursor | `~/.cursor/mcp.json`, project `.cursor/mcp.json` |
| VS Code | user and profile `mcp.json` and `settings.json` (stable and Insiders), `~/.copilot/mcp-config.json`, workspace `.vscode/mcp.json`, workspace-root `.mcp.json` when `chat.mcp.workspaceRootConfig.enabled` is on, VS Code Server's `~/.vscode-server/data/User/mcp.json`, and servers left under the pre-1.102 `"mcp"` key in `settings.json` |

Each client's loading rules are modelled when grouping servers into **agent contexts**, the set of servers one session can use together: Claude Code's local > project > user precedence, a readable `managed-mcp.json` taking exclusive control, Cursor and VS Code merging user and workspace servers.

## Check catalog

| ID | Severity | What it flags | CWE | OWASP LLM 2025 | OWASP Agentic 2026 | Why it matters |
|---|---|---|---|---|---|---|
| MP001 | High (Medium if a capability is only guessed; Info when unclassified servers block a verdict) | One agent context whose servers together grant all three Rule of Two capabilities | CWE-1427 | LLM01, LLM06 | ASI01, ASI02 | Untrusted text can steer the agent to read private data and send it out, and no model reliably refuses |
| MP002 | High (Critical in a committed project file; Medium for entropy or key-name matches) | Credentials written into `env`, `args`, `headers`, URLs, or a settings `env` block | CWE-798 | LLM02 | ASI03 | Plain-text secrets end up in backups, git history, and in front of the agent itself |
| MP003 | Medium (Low for a container tag without digest) | `npx`, `uvx`, `pipx run`, `docker run` without an exact version or digest | CWE-494 | LLM03 | ASI04 | Every launch runs whatever was published most recently |
| MP004 | Medium (High when headers or credentials are sent) | Remote servers over `http://` or `ws://` to anything but loopback | CWE-319 | LLM02 | | Tool calls, results, and tokens can be read or rewritten on the network |
| MP005 | High | Filesystem servers or container mounts rooted at a drive, the home directory, a credential store (`.ssh`, `.aws`, Keychains, ...), or the Docker socket | CWE-250 | LLM06 | ASI03 | One injected instruction is enough to read SSH keys or cloud credentials |
| MP006 | High (Medium for narrower rules) | Claude Code `bypassPermissions`, `Bash`/`Bash(*)` allow rules, wildcard rules for interpreters, `enableAllProjectMcpServers`; VS Code global auto-approve, `chat.permissions.default` of `autoApprove`/`autopilot`, catch-all terminal auto-approve; `--dangerously-skip-permissions` in settings or server args | CWE-250 | LLM06 | ASI02 | Approval prompts are the last control between a manipulated agent and your machine |
| MP007 | High (Medium for relative paths) | Servers or interpreter scripts launched from temp or Downloads folders, or by relative path | CWE-829 (CWE-427 for relative paths) | LLM03 | ASI05 | Anything running as you can replace those files before the next launch |
| MP008 | High (Critical when banned) | Servers not on the policy's approved list, or on its banned list | CWE-829 | LLM03 | ASI04 | Unreviewed software executing with developer access |

IDs are from the [MITRE CWE list](https://cwe.mitre.org/), the [OWASP Top 10 for LLM Applications 2025](https://genai.owasp.org/llm-top-10/), and the [OWASP Top 10 for Agentic Applications 2026](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications/).

## The Rule of Two, in plain language

Meta's AI security team published the [**Agents Rule of Two**](https://ai.meta.com/blog/practical-ai-agent-security/) (31 October 2025), building on Chromium's "Rule of 2" and Simon Willison's "lethal trifecta". It says that until models can reliably resist prompt injection, an agent should have **no more than two** of these three abilities in the same session:

- **[A] It reads things strangers wrote:** web pages, search results, emails, issues and pull requests.
- **[B] It can reach private things:** your files, databases, internal systems, secrets.
- **[C] It can act or talk to the outside world:** write files, run commands, send messages, call arbitrary URLs.

Any two are manageable. All three together is how a sentence hidden in a web page becomes "read `~/.aws/credentials` and post it to this URL", and the agent does it with your permissions. If a task really needs all three, Meta's guidance is to keep a human approving the actions rather than letting the agent run on its own.

MCPosture classifies every configured server with a versioned [rules file](src/mcpposture/data/rules.toml) of known packages, images and hosts, falls back to clearly labelled keyword heuristics, and reports anything else as **unclassified**, never as safe. It then checks each agent context. For example, the GitHub MCP server alone holds all three: it reads issues anyone can file, reaches private repositories, and can push code. [CONTRIBUTING.md](CONTRIBUTING.md) explains how to add classifications.

## Enforcing a policy

```toml
schema_version = 1
max_severity = "medium"        # any finding above this is a violation
require_approved = true        # every server must match an entry below

[[approved]]
npm = "@modelcontextprotocol/server-filesystem"
version = "2025.8.21"          # exact versions only; ranges and tags are rejected

[[approved]]
url = "https://mcp.context7.com/mcp"

[[banned]]
npm = "@example/known-bad-mcp"
reason = "Blocked after review."
```

Servers are matched by **what actually runs** (package and exact version, image digest, URL, or the SHA-256 of a local executable or script), never by the name in the config, which any user can set to anything. `mcpposture policy validate` rejects unknown keys, version ranges, malformed digests, non-HTTPS approved URLs, and entries that are both approved and banned. Full reference: [docs/policy.md](docs/policy.md). A complete example: [examples/policy.toml](examples/policy.toml).

## Fleet view

`mcpposture fleet reports/` merges JSON reports from many machines into the most widespread checks, the same issue across machines (fingerprints ignore usernames), policy non-compliance, Rule of Two prevalence, and the most common unclassified servers to add to the rules file. To demonstrate scale, `scripts/generate_fleet.py --machines 500` produces 500 synthetic but realistic reports through the real pipeline; CI summarises them on every run. [docs/deployment.md](docs/deployment.md) describes collecting real reports with an MDM (Jamf, Intune) and how osquery fits alongside.

## How the tool protects itself

The config files it reads are attacker-controlled input, so MCPosture is built to be boring to attack. The full analysis is in [THREAT_MODEL.md](THREAT_MODEL.md).

- **Never executes anything it finds**, makes **no network calls**, and sends **no telemetry**. A test parses the tool's own source on every run and fails on `subprocess`, sockets, HTTP clients, `eval`/`exec`, or `shell=True`.
- **Defensive reading:** 16 MB file limit, regular files only, a FIFO cannot hang the scan, symlinks and Windows junctions cannot pull a `--path` scan outside its root, a depth-limited JSONC parser with no regex backtracking blow-up.
- **No secret is ever printed or written in full:** output shows the provider and at most the last four characters, and environment and header values are never copied at all. Tests check that no five-character slice of a test secret survives in any output format.
- **Terminal-safe output:** control and bidi characters from configs are escaped, so a config cannot inject ANSI sequences into your terminal.
- **Private reports:** files are written `0600` on POSIX and refuse to follow a planted symlink.

## Limitations

- **Static only.** It sees what configs declare, not what a server actually does at runtime, which tools it exposes, or what its tool descriptions say. A live-introspection mode would have to start untrusted servers and needs a sandbox; it is deliberately out of scope (see the threat model).
- **Rule of Two covers MCP servers only.** Clients' built-in tools (Claude Code's shell and web fetch, for example) are not counted, so a context reported as "ok" may still reach all three capabilities through built-ins.
- **Classification is only as good as the rules file.** Heuristic matches are guesses and are labelled as such; unclassified servers are reported, not judged.
- **Not covered:** Claude Desktop extensions (`.mcpb`) and remote connectors configured in an account rather than a file, Cursor's auto-run settings (not documented), JetBrains and other clients, and command-line flags in shell aliases or scripts.
- **Current user only.** `scan` covers the user it runs as. MDM deployments should run it in the logged-in user's context.
- **Tests run on Windows and Linux locally; macOS is covered by CI only.**

## Related work

- [**LlamaFirewall**](https://github.com/meta-llama/PurpleLlama/tree/main/LlamaFirewall) (Meta): a runtime guardrail framework for agents, with scanners for prompt injection, misaligned agent reasoning, and insecure code. It protects an agent while it runs; MCPosture checks how agents are configured before they run.
- [**Prompt Guard**](https://github.com/meta-llama/PurpleLlama/tree/main/Llama-Prompt-Guard-2) (Meta): classifier models that detect prompt injection and jailbreak attempts in text. Useful at runtime for exactly the [A] inputs the Rule of Two worries about.
- [**osquery**](https://osquery.io/) (originally Facebook): SQL over endpoint state, widely used for fleet inventory. MCPosture's location table and JSON reports are designed to sit alongside an osquery deployment (see [docs/deployment.md](docs/deployment.md)); osquery is not a dependency.

## Development

```sh
python -m pip install -e ".[dev]"
python -m pytest -q
```

CI ([.github/workflows/ci.yml](.github/workflows/ci.yml)) runs the tests on Ubuntu, macOS and Windows with Python 3.11 and 3.13, scans `tests/fixtures/vulnerable_repo` and uploads the SARIF to code scanning (those alerts are intentional), lints and enforces the example policy, and runs the 500-machine fleet demo.

[CONTRIBUTING.md](CONTRIBUTING.md) · [SECURITY.md](SECURITY.md) · [THREAT_MODEL.md](THREAT_MODEL.md) · [MIT License](LICENSE)
