# Your AI agent's config file is now part of your attack surface

*Draft. Samir Patel, November 2026.*

A year ago the riskiest file on a developer's laptop was probably `~/.ssh/config` or a `.env` someone forgot to gitignore. Today it might be a JSON file most security teams have never looked at: the one that tells an AI coding agent which tools it may use.

Claude Code, Cursor, VS Code and Claude Desktop all load **MCP servers**, small programs that give the agent new abilities: reading files, driving a browser, querying a database, opening pull requests. Each one is listed in a config file as a command line or a URL, and each one runs with the developer's own permissions. I built [MCPosture](https://github.com/spateluf04/mcpposture), a small open-source scanner, to find out what those files actually say on a real machine and to give security teams a way to audit and enforce them.

## Why these files are an endpoint problem

Endpoint security has long asked "what software is allowed to execute on this device?" Agent configs answer that question quietly, outside every allowlist:

- **They are execution instructions.** `"command": "npx", "args": ["-y", "some-mcp"]` means "download the newest version of this package and run it every time the editor starts". Nothing pins what arrives.
- **They travel with code.** A project's `.mcp.json` or `.vscode/mcp.json` is meant to be committed. Clone a repository, open it in your editor, and you may be one click from running its servers. One Claude Code setting, `enableAllProjectMcpServers`, removes even that click.
- **They hold credentials.** The easiest way to give a server an API key is to paste it into the `env` block, so keys end up in dotfile repositories and backups.
- **They decide how much the agent can do unsupervised.** Allow rules like `Bash(*)`, VS Code's global auto-approve, or a "bypass permissions" mode turn a helpful assistant into something that acts on whatever it last read.

That last point matters because of prompt injection. Meta's AI security team framed it well in the [**Agents Rule of Two**](https://ai.meta.com/blog/practical-ai-agent-security/) (October 2025), building on Simon Willison's "lethal trifecta". An agent becomes dangerous when, in one session, it can (A) read content strangers wrote, (B) reach private data, and (C) act or communicate externally. Any two are manageable. All three let a sentence hidden in a web page or a GitHub issue become "read the credentials file and send it here". The rule's practical point is that you don't need to win the unsolved problem of making models immune to injection; you need to make sure no single session holds all three capabilities without a human in the loop.

That turns a fuzzy worry into something checkable. If you know what each configured server can do, you can compute whether an agent context crosses the line.

## What it found on my own laptop

I ran MCPosture on the Windows laptop I develop on, from both Windows and WSL2. It found seven agent config files: Claude Code's user state and settings, VS Code's user MCP config and settings, and three per-project Claude Code settings files I had forgotten existed. Two MCP servers were configured. No secrets, no cleartext servers, nothing broad on the file system. Two findings stood out anyway:

1. **An unpinned browser server.** My VS Code config ran the Playwright MCP server as `@playwright/mcp@latest`. That is the setup most guides suggest, and it means my editor executes whatever version was published most recently, with access to my browser automation and network. Pinning it is one edit.
2. **A permission rule I never consciously wrote.** One project's `.claude/settings.local.json` pre-approved `Bash(python3 -c ' *)`. That came from clicking "yes, don't ask again" during a debugging session. It reads as narrow, but `python3 -c` followed by anything is arbitrary code execution. Local settings files accumulate these approvals one click at a time, and nobody reviews them.

Neither is dramatic, which is the point. Configuration drift on endpoints is rarely dramatic until it is.

To see what this looks like at fleet scale, MCPosture ships a generator that builds 500 synthetic but realistic machines and runs them through the real pipeline. In that simulation, about three quarters of machines had at least one agent context holding all three Rule of Two capabilities. The most common reason was a single server: the GitHub MCP server on its own reads issues anyone can write, reaches private repositories, and can push code. The numbers are synthetic, but the shape is plausible, and it shows why per-server review is not enough: the risk is in the combination.

## Design decisions

A tool that audits attacker-controlled files has to be very careful not to become the vulnerability.

- **Read-only, no execution, no network.** MCPosture never starts a server, not even to ask its version. A test parses the tool's own source on every run and fails if anything imports `subprocess`, opens a socket, or calls `eval`. Live introspection would catch more, such as poisoned tool descriptions, but it means running untrusted code, which needs a sandbox and a separate threat model.
- **Standard library only.** No runtime dependencies means no transitive supply chain in a security tool, even if that meant writing a small JSON-with-comments parser that records line numbers and caps nesting depth.
- **One place where secrets can leak, and it redacts.** Every output format renders from one report object. Environment and header values are never copied; anything else shows a provider label and at most the last four characters, and tests assert no five-character slice of a test secret survives.
- **Identify servers by what runs, not what they are called.** A config's server name is a label the user picks. Policy approval therefore requires an exact package version, an image digest, an HTTPS URL, or the SHA-256 of a local binary. An approved package configured as `@latest` is not approved.
- **Model each client's real loading rules.** Rule of Two is evaluated per agent context, the servers one session actually loads, following each client's precedence rules rather than lumping the whole machine together.
- **Unknown is not safe.** Servers are classified from a versioned rules file, then from labelled heuristics; anything left over is reported as unclassified.
- **Built to be enforced.** `enforce` exits 1 on a policy violation for CI and MDM, SARIF lands in GitHub code scanning, and `fleet` merges many machines into one view.

## Next steps

- **More classifications.** The rules file improves with community input, and the fleet summary lists the most common unclassified servers so they can be reviewed.
- **Counting built-in tools.** Agents' own shell and web tools can supply Rule of Two capabilities too; modelling them from each client's permission settings is the natural next check.
- **A sandboxed introspection mode,** run separately and opt-in, to compare a server's advertised tools against its classification.
- **Native fleet integration,** such as an osquery extension table, so findings appear next to the rest of an organisation's endpoint inventory.

If you run AI agents in an organisation, try it on your own laptop first.

*MCPosture is an independent project, not affiliated with Meta or any vendor mentioned here.*
