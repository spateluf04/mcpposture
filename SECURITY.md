# Security policy

## Reporting a vulnerability

Please report vulnerabilities in MCPosture privately through GitHub's **[Report a vulnerability](https://github.com/spateluf04/mcpposture/security/advisories/new)** form (Security tab, then Advisories). Do not open a public issue.

Include what you can of:

- the version (`mcpposture --version`) and operating system;
- a config file, directory layout, report, or policy that triggers the issue (use fake secrets);
- what happened and what you expected.

You should get an acknowledgement within 7 days and a fix or mitigation plan within 30 days for confirmed issues. You will be credited in the advisory unless you prefer otherwise.

## In scope

MCPosture treats every config file, file system layout, and fleet report it reads as attacker-controlled. Of particular interest:

- any way to make MCPosture **execute code**, start a process, or make a network connection;
- a **secret appearing in full**, or with more than its last four characters, in any output format, error message, or report file;
- **reading files outside the scan root** through symlinks, junctions, or races;
- crafted input that **crashes or hangs** the scanner, makes it skip files silently, or changes its exit code;
- terminal escape or other **output injection** through text, JSON, or SARIF output;
- ways to make a non-compliant machine **pass `enforce`**, or a policy that `policy validate` accepts but that does not mean what it says.

See [THREAT_MODEL.md](THREAT_MODEL.md) for the threats already considered and the known residual risks.

## Out of scope

- Weaknesses in the MCP servers or AI clients that MCPosture audits. Report those to their maintainers.
- Missing classifications or checks that are not security bugs in the tool. Please open a regular issue or pull request (see [CONTRIBUTING.md](CONTRIBUTING.md)).
- Attacks that need an attacker already able to modify the installed MCPosture code or its Python interpreter.

## Supported versions

Only the latest release receives security fixes.

## Safe harbor

Good-faith research that respects user privacy, avoids accessing other people's data, and gives reasonable time to fix before disclosure is welcome. Testing should be done on your own machines and repositories.
