# MCPosture threat model

This document models threats against **MCPosture itself**: a read-only CLI that runs on developer laptops and in CI, reads AI agent configuration files, and writes reports. It uses STRIDE per trust boundary.

## Assets

| Asset | Why it matters |
|---|---|
| Secrets inside the configs being scanned (API keys, tokens, passwords) | The tool must read them to detect them; leaking them in a report would make the scanner the breach |
| The developer's machine and account | MCPosture runs with the user's privileges; anything it executes runs with them too |
| Report integrity | Security teams, CI gates and MDM compliance decisions trust the findings and exit code |
| Reports themselves | They list a machine's tools, paths and weaknesses: useful reconnaissance for an attacker |
| Policy file | Defines what is allowed; tampering changes enforcement |

## Actors

- **Malicious repository author.** Controls the content of a cloned repo's `.mcp.json`, `.cursor/mcp.json`, `.vscode/mcp.json`, `.claude/settings.json`, and anything else in the tree. This is the primary adversary.
- **Malicious local process** running as the same user (a compromised npm package, a browser exploit). Can modify user-level configs, plant symlinks or FIFOs, and race the scanner.
- **Compromised fleet machine.** Can submit a forged JSON report to the central `fleet` aggregation.
- **Network attacker.** Irrelevant by design: the tool makes no network connections.

## Trust boundaries

```
 attacker-controlled                     MCPosture process                    consumers
 ───────────────────                     ─────────────────                    ─────────
 config files ──(1) file read──▶ safefs → jsonc parser → parsers ─┐
 file system layout (links,      (size cap, regular files,         │
   FIFOs, junctions)              root containment, depth limit)   ▼
                                                    checks / classify / policy
 policy file ──(2) file read──▶ policy.parse (strict schema) ──────┤
                                                                   ▼
                                             report dict (single redaction point)
                                                     │(3)
                                  ┌──────────────────┼──────────────────┐
                                  ▼                  ▼                  ▼
                           terminal (text)    report file 0600     SARIF → GitHub
 fleet reports ──(4)──▶ fleet loader (size cap, depth-limited parser, schema check) ──▶ summary
```

1. Config contents and the file system layout are **untrusted**.
2. The policy file is trusted in intent but still **validated strictly**: it is often edited by hand and distributed by MDM.
3. Output crosses into terminals, files that may be shared, and GitHub.
4. Fleet reports come from endpoints that may be compromised and are **untrusted**.

## STRIDE

| # | Category | Threat | Mitigation | Where |
|---|---|---|---|---|
| S1 | Spoofing | A config names a malicious server `github` or `filesystem` to pass review or match an allowlist | Servers are identified by package and exact version, image digest, URL, or executable SHA-256, never by config label | `policy.identities`, `classify._identity` |
| S2 | Spoofing | A forged fleet report claims a machine is clean | Reports are treated as untrusted data; the summary reports what machines claim, and the docs recommend signed or authenticated collection (MDM channel) | `fleet.py`, `docs/deployment.md` |
| S3 | Spoofing | Duplicate JSON keys make the tool see a different value than the client | Parser resolves duplicates last-wins, the same as `JSON.parse` in the clients | `jsonc.py` |
| T1 | Tampering | Symlink or junction in a repo points at `~/.ssh/id_rsa` or `/etc` so the scan reads it | Every read resolves the full path and must stay inside the scan root; walks never descend links or NTFS reparse points | `safefs.read_config`, `discovery/walk.py` |
| T2 | Tampering | Planted symlink at the report output path redirects the write over another file | Reports open with `O_NOFOLLOW` and `O_TRUNC`, mode `0600` | `report/write.py` |
| T3 | Tampering | File swapped between check and read (TOCTOU) | Type and size re-checked with `fstat` on the opened descriptor; `O_NOFOLLOW` on the final component | `safefs.py` |
| R1 | Repudiation | Disagreement over which policy a machine was judged against | Report records the policy path and SHA-256 of its exact contents, the rules version, tool version and scan time | `report/jsonfmt.py` |
| I1 | Information disclosure | Secrets copied into reports, SARIF, terminal, or error messages | One redaction point builds the report dict that every format renders from; env and header values are never copied; at most provider and last four characters shown; internal errors print only the exception type. Tested by slicing every fake secret into 5-character windows and asserting none appear | `redact.py`, `report/jsonfmt.py`, `cli.py`, `tests/test_redact.py` |
| I2 | Information disclosure | Reports readable by other local users | Written `0600` on POSIX; inherited ACL on Windows | `report/write.py` |
| I3 | Information disclosure | Tool reads unrelated private data (account details in `~/.claude.json`) | Parsers read only MCP and permission keys; nothing else is copied into output | `discovery/parsers.py` |
| I4 | Information disclosure | Policy hashing used to read arbitrary files | Only executables named by the policy's own approved entries are hashed, not paths taken from configs alone | `policy._approved` |
| D1 | Denial of service | Huge file, deeply nested JSON, number with 10,000 digits | 16 MB cap, nesting limit 64, number errors handled; caps on servers per file and args per server | `safefs.py`, `jsonc.py`, `parsers.py` |
| D2 | Denial of service | FIFO or device named `.mcp.json` blocks the read forever | Only regular files are read; `O_NONBLOCK` lets the type check run before any blocking read | `safefs.py` |
| D3 | Denial of service | Regex catastrophic backtracking on hostile strings | Parser string regex is an unrolled loop (linear); heuristic matching input capped at 4 KB; tests time hostile inputs | `jsonc.py`, `classify.py` |
| D4 | Denial of service | Huge repo or link cycle during `--path` | Depth limit 8, 200,000-entry cap, links never followed, dependency and VCS folders skipped | `discovery/walk.py` |
| D5 | Denial of service | A crafted config crashes one check and hides all other findings | Each check runs in isolation; a failure becomes a `check_error` scan issue and the rest still report | `checks/__init__.py` |
| D6 | Denial of service | A hostile config tries to force a CI failure or pass | Unparseable files are scan issues and never change the exit code; exit code depends only on findings and policy | `cli.py` |
| E1 | Elevation of privilege | Scanner executes a discovered command (to "check its version") and runs attacker code | No process execution anywhere. Enforced by a test that parses the tool's own source and fails on `subprocess`, `os.system`, `exec`, `eval`, `shell=True`, network modules, and `platform` (which can spawn `ver` on Windows) | `tests/test_hygiene.py` |
| E2 | Elevation of privilege | Terminal escape sequences in a server name rewrite the terminal or trigger terminal features | Text output escapes C0/C1 controls and bidi or zero-width characters; JSON and SARIF are ASCII-only | `report/text.py`, `report/jsonfmt.py` |
| E3 | Elevation of privilege | A malicious rules or policy file injects code | Both are TOML parsed with `tomllib` into data only; patterns are compiled regexes, never evaluated code; unknown keys rejected | `classify.parse_rules`, `policy.parse` |

## Why there is no live-introspection mode

Some issues can only be seen by starting a server and asking for its tool list: poisoned tool descriptions, tools that differ from the package's documentation, servers that change behaviour after approval ("rug pulls"). Doing that safely requires running untrusted code, which breaks this tool's central guarantee. A future mode would need, at minimum:

- a disposable sandbox (container or VM) with no access to the user's home directory, credentials, SSH agent or cloud metadata;
- no network, or egress limited to the package registry;
- a fresh, empty environment instead of the config's `env` block, since that is where the real secrets are;
- time, memory and output limits, and a protocol client that treats every server response as hostile;
- an explicit opt-in per run, because even a sandboxed install runs package lifecycle scripts.

That is a different product with a different threat model, so it is out of scope.

## Residual risks

- **Static analysis can be evaded.** A server can be clean on disk and malicious at runtime; an innocuously named package can do anything. MCPosture reduces the attack surface; it does not prove a server safe.
- **Classification errors.** A wrong rule could under-report Rule of Two violations. Rules are versioned and reviewed (see CONTRIBUTING.md); heuristic results are labelled and lower severity; unknowns are reported.
- **Redaction misses.** A secret with no known prefix, low entropy, and an innocent-looking key name (for example `CONFIG=hunter2`) is not detected and could appear in args output. Env and header values are never printed, which covers where most secrets live.
- **Same-user attacker.** A process running as the user can alter configs right after the scan, tamper with the installed tool, or forge its reports. Endpoint integrity is outside this tool's control; MDM deployment from a root-owned location mitigates tool tampering.
- **Windows permissions.** Reports rely on directory ACLs; `0600` does not apply.
- **Remaining TOCTOU.** On Windows there is no `O_NOFOLLOW`; the window between path resolution and open is small but non-zero.
- **Fleet trust.** The fleet summary believes what reports say. Authenticate the collection channel.
