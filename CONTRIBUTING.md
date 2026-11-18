# Contributing to MCPosture

Thanks for helping. The most valuable contribution is usually a **server classification**: every MCP server added to the rules file turns "unclassified" into a real Rule of Two verdict for everyone who uses it.

## Setup

```sh
python -m venv .venv && . .venv/bin/activate      # Windows: .venv\Scripts\activate
python -m pip install -e ".[dev]"
python -m pytest -q
```

Ground rules:

- **Standard library only at runtime.** Propose any new dependency in an issue first.
- **The tool must never execute what it scans or touch the network.** `tests/test_hygiene.py` enforces this.
- **Every check needs positive and negative tests**, and hostile inputs must not crash it.
- **Fixtures use obviously fake secrets**, assembled at runtime where possible (see `tests/test_redact.py`), so GitHub secret scanning stays quiet.
- Comments explain *why*, not *what*.

## Adding a server classification

Classifications live in [`src/mcpposture/data/rules.toml`](src/mcpposture/data/rules.toml). Each server is assigned the capability flags from Meta's [Agents Rule of Two](https://ai.meta.com/blog/practical-ai-agent-security/):

| Flag | Meaning | Typical tools |
|---|---|---|
| `A` | Processes **untrustworthy input**: content a third party could have written | web fetch, browsers, search results, email, issues, pull requests, chat messages, shared documents |
| `B` | Accesses **sensitive systems or private data** | file systems, databases, private repositories, secrets, cloud accounts, internal APIs, mail and calendars |
| `C` | **Changes state or communicates externally** | writing files, running commands, sending messages, creating issues or commits, requests to arbitrary URLs, payments |

### `[[server]]` entries (exact matches)

```toml
[[server]]
id = "mcp-fetch"                                    # unique, kebab-case
pypi = ["mcp-server-fetch"]                          # PyPI names (normalised per PEP 503)
npm = ["@modelcontextprotocol/server-fetch"]         # npm package names, without versions
oci = ["mcp/fetch"]                                  # container repositories, without tag or digest
url_host = ["fetch.example.com"]                     # hosts of remote servers
command = ["fetch-mcp"]                              # executable names, for servers installed as binaries
capabilities = ["A", "C"]                            # required; [] means "reviewed, has none"
rationale = "Returns arbitrary web content (A) and sends requests to arbitrary URLs (C)."
reference = "https://github.com/modelcontextprotocol/servers/tree/main/src/fetch"   # optional
```

- At least one of `npm`, `pypi`, `oci`, `url_host`, `command` is required. All are lists.
- The first matching `[[server]]` entry wins, so put more specific entries first.
- `capabilities = []` is a positive statement that the server has none of the three. Use it only after reading what the server's tools do.

### `[[heuristic]]` entries (fallback guesses)

```toml
[[heuristic]]
id = "web-search"
pattern = '(?i)\b(search|brave|tavily)\b'   # Python regex, matched against name + command + args + URL
capabilities = ["A"]
```

Heuristics only apply when no `[[server]]` entry matches. Every matching heuristic contributes its flags, results are shown as lower-confidence (lowercase flags in text output), and a Rule of Two violation that depends on a heuristic is reported as medium rather than high. Keep patterns simple alternations: they run on attacker-controlled text.

### What reviewers look for

1. **Evidence.** Link the server's source or tool list, and say in `rationale` which tools give each flag.
2. **Conservative flags.** When unsure, include the flag. Under-classifying hides real Rule of Two violations; over-classifying only adds a finding someone can read and dismiss.
3. **Meta's examples as the yardstick.** Search results count as `A`. Requests to arbitrary URLs count as `C` because the URL itself can carry data out.
4. **Bump `rules_version`** (`YYYY.MM.N`) in the same change.
5. **Add a test** in `tests/test_classify.py` showing the entry matches a realistic config line.

The file is validated on load. `python -c "from mcpposture.classify import default_rules; default_rules()"` reports unknown keys, missing capabilities, bad flags, duplicate IDs, and invalid regexes.

## Adding a client or config location

Add one `ConfigLocation` row to [`discovery/locations.py`](src/mcpposture/discovery/locations.py), with the vendor documentation URL in `doc`. If the file format is new, add a parser to `discovery/parsers.py`. Verify the path against official documentation, not blog posts, and mention in the row's comment if the only source is a code change or issue.

## Adding a check

Create `src/mcpposture/checks/<name>.py` exposing `INFO` (a `CheckInfo` with ID, title, severity, plain-English why, concrete remediation, and CWE and OWASP IDs checked against the official MITRE and OWASP lists) and `check(ctx)`, then register it in `checks/__init__.py`. Use `server_finding` or `settings_finding` so locations, line numbers and fingerprints are consistent. Never put a raw config value in `evidence`; pass it through `mcpposture.redact` first.

## Reporting security issues

See [SECURITY.md](SECURITY.md). Please don't open public issues for vulnerabilities in MCPosture itself.
