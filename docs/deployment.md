# Deploying MCPosture across a fleet

This page describes how MCPosture could run on managed laptops and feed a central view. Nothing here is required to use the tool, and none of these systems are dependencies.

## The shape of a deployment

1. **Install** the tool to a location users cannot modify (for example `/usr/local/mcpposture` owned by root, or `C:\Program Files\MCPosture`), together with a Python 3.11+ runtime. A root-owned install stops a same-user process from tampering with the scanner.
2. **Distribute** the policy file the same way, to a root-owned path.
3. **Run in the user's context.** Agent configs live in each user's home directory, and `scan` and `enforce` cover the user they run as. Running as root or SYSTEM scans the wrong home.
4. **Collect** each machine's JSON report (`--format json`, mode 0600) through an authenticated channel: the MDM's own upload, or a log shipper with device certificates.
5. **Aggregate** with `mcpposture fleet reports/` on a trusted host, on a schedule.

## Jamf Pro (macOS)

Jamf policies run scripts as root, so switch to the console user:

```sh
#!/bin/sh
user=$(stat -f %Su /dev/console)
uid=$(id -u "$user")
out="/Users/$user/Library/Application Support/MCPosture/report.json"
launchctl asuser "$uid" sudo -u "$user" mkdir -p "$(dirname "$out")"
launchctl asuser "$uid" sudo -u "$user" \
  /usr/local/mcpposture/bin/mcpposture enforce \
    --policy /Library/MCPosture/policy.toml --format json -o "$out"
echo "exit=$?"
```

An **Extension Attribute** can then report compliance by reading the `policy.compliant` field of that report, so a Smart Group lists non-compliant machines and can scope remediation messaging to them.

## Microsoft Intune (Windows and macOS)

Intune **Remediations** fit the exit codes directly: a detection script that exits `1` marks the device as having an issue. Configure the script to **run using the logged-on credentials**:

```powershell
& "C:\Program Files\MCPosture\python\python.exe" -m mcpposture enforce `
    --policy "C:\Program Files\MCPosture\policy.toml" `
    --format json -o "$env:LOCALAPPDATA\MCPosture\report.json"
exit $LASTEXITCODE   # 0 compliant, 1 violations, 2 tool error
```

Treat exit `2` as "could not evaluate", not as compliant: alert on it separately.

## osquery

osquery is good at the question "which machines have which files", and MCPosture is good at "what is wrong with them". They fit together without coupling:

- **Inventory and change detection.** The location table in `src/mcpposture/discovery/locations.py` translates directly into osquery `file` and `hash` queries, which can run on a schedule and flag new or changed agent configs across the fleet:

  ```sql
  SELECT f.path, f.mtime, h.sha256
  FROM file f JOIN hash h USING (path)
  WHERE f.path LIKE '/Users/%/.cursor/mcp.json'
     OR f.path LIKE '/Users/%/.claude.json'
     OR f.path LIKE '/Users/%/Library/Application Support/Claude/claude_desktop_config.json'
     OR f.path LIKE '/Users/%/Library/Application Support/Code/User/mcp.json';
  ```

  A changed hash is a good trigger to re-run `mcpposture enforce` through the MDM.

- **Findings in osquery.** osquery has no built-in table that parses arbitrary JSON files, so surfacing MCPosture findings as rows would take an osquery extension exposing, say, an `mcpposture_findings` table backed by the report file. That would be a separate component with its own review; it is not part of this project.

## Running in CI

To stop risky agent configs being committed to a repository:

```yaml
- run: python -m pip install mcpposture
- run: python -m mcpposture scan --path . --format sarif -o mcpposture.sarif --fail-on high
- uses: github/codeql-action/upload-sarif@v4
  if: always()
  with:
    sarif_file: mcpposture.sarif
```

Or gate on an organisation policy with `mcpposture enforce --path . --policy policy.toml`.

## Operational notes

- **Fingerprints** replace the user's home directory with `~`, so the same issue on many laptops groups in `fleet` output and in code scanning.
- **Reports are sensitive.** They list each machine's tools and weaknesses. Store them with access controls and a retention limit.
- **Forged reports.** A compromised laptop can submit a clean report. Weight MDM-collected evidence over self-reported data, and investigate machines whose reports stop arriving.
- **Rules updates.** `tool.rules_version` in each report shows which classification data a machine used. Roll rules updates out like any other config.
