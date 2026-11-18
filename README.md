# Agent Safeguard Gate

**Agent Safeguard Gate** is a Claude Code plugin that checks Claude's actions before they happen. When Claude is about to install a package, download and run a script, edit a GitHub Actions workflow, or write a file, the plugin checks it first. Anything known to be malicious is blocked. Anything risky, like a package with known vulnerabilities or a download piped straight into a shell, pauses so you decide. It never approves anything on its own.

It also adds a skill that scans a repo for vulnerable dependencies, leaked secrets and weak CI settings, then fixes only what you approve. It runs on the Python standard library, so there's nothing extra to install, and it sends only package names and versions to public vulnerability databases.

## Requirements

| Need | Why |
|---|---|
| **Claude Code v2.1.295 or later** (terminal, desktop app, or IDE), or **Cowork** | The hook fails closed (blocks) if it crashes, which needs this version |
| **Python 3.9 or later** on your `PATH` as `python3` | The hook and scanner are Python scripts. Python 3.11+ is needed to read poetry/uv lockfiles |
| **macOS or Linux** | Windows is untested. The hook calls `python3`, which often doesn't exist on Windows |
| Optional: [`osv-scanner`](https://google.github.io/osv-scanner/) | Lets the scanner also check `pnpm-lock.yaml` and `yarn.lock`. On a Mac: `brew install osv-scanner` |

**Where it works:** the always-on hook runs in Claude Code and Cowork. In claude.ai chat, only the scan skill loads, because chat doesn't run plugin hooks.

**Lite edition:** [`lite/`](lite/) holds **Agent Safeguard Lite**, an instructions-only version with no hooks or scripts. It works everywhere, including claude.ai chat, but relies on Claude following its checklists instead of blocking anything automatically. Install it with `claude plugin install agent-safeguard-lite@agent-safeguard` after adding the marketplace below.

## Install

From Claude Code, in your terminal:

```bash
claude plugin marketplace add gitgitgetitgrl/agent-safeguard-gate
claude plugin install agent-safeguard-gate@agent-safeguard
```

Or inside a Claude Code session: `/plugin install agent-safeguard-gate --marketplace gitgitgetitgrl/agent-safeguard-gate`.

Then restart Claude Code (or run `/reload-plugins`). The hook is active as soon as the plugin is enabled.

### Check that it works

In a scratch folder, ask Claude to install an old package version with a known vulnerability, for example `npm install lodash@4.17.20 --ignore-scripts`. Before anything installs, you should get a prompt whose reason starts with `agent-safeguard-gate:` and lists the vulnerabilities. Decline it.

### Optional: block Claude from reading credential files

This plugin never changes your Claude Code settings. If you also want Claude Code to refuse to read common credential files, add these rules yourself under `permissions.deny` in `~/.claude/settings.json`:

```json
{
  "permissions": {
    "deny": [
      "Read(~/.aws/credentials)",
      "Read(~/.ssh/id_*)",
      "Read(~/.config/gcloud/**)",
      "Read(~/.docker/config.json)",
      "Read(~/.npmrc)",
      "Read(~/.pypirc)",
      "Read(~/.git-credentials)",
      "Read(~/.kube/config)"
    ]
  }
}
```

If the file already has a `permissions` section, add the rules to its existing `deny` list.

## Use

- **Scan a repo:** ask Claude to "scan this repo with agent-safeguard-gate". It writes a report to `<repo>/.security-gate/`, explains the findings and lists fix IDs. Claude applies only the fixes you approve, and backs up every file it changes.
- **Install packages as usual.** The hook checks each package against OSV (known vulnerabilities and OpenSSF `MAL-` malicious-package records) and against the registry before the install command runs.
- **In CI:** `python3 scripts/scan.py <repo> --fail-on high` exits with 1 when it finds anything at or above that level.

## What the hook decides

| Action | Decision |
|---|---|
| Install a package flagged `MAL-` in OSV, or one on your IOC blocklist | deny |
| curl/wget piped into sh/bash/python/node, `bash <(curl …)` | deny |
| Read credential files + network tool in one command; `env` piped to curl/nc | deny |
| pip `--trusted-host` or an `http://` index | deny |
| Checkout or merge of a branch on your IOC blocklist | deny |
| Workflow: `pull_request_target` + PR head checkout, `${{ github.event.*.title/body }}` injection, secrets piped to network | deny |
| Writing a live-looking secret into source code | deny |
| Install with known vulns, a nonexistent package name, lifecycle scripts enabled, no lockfile, URL/git sources, `--extra-index-url`, requirements without `--require-hashes` | ask |
| `npx`/`pnpm dlx`/`uvx`/`pipx run`, download + `chmod +x`, raw-IP downloads | ask |
| Workflow actions not SHA-pinned, `write-all`, no `permissions:` block | ask |
| Writes to `.bashrc`/`.zshrc`, git hooks, LaunchAgents, cron, `authorized_keys`, Claude settings | ask |
| Network failure during verification | ask (never silently allow) |

"Ask" hands the decision to you. Nothing is ever approved automatically.

## Fixes available (approval required, backups kept)

| Fix | What it changes |
|---|---|
| `npmrc-ignore-scripts` | Sets `ignore-scripts=true` in the project `.npmrc` |
| `pin-actions` | Pins workflow actions to commit SHAs via `git ls-remote`, keeping a `# tag` comment |
| `add-permissions` | Adds top-level `permissions: contents: read` to workflows |
| `pip-pin` | Bumps a vulnerable `requirements*.txt` pin to the highest fixed version OSV lists |
| `npm-upgrade` | Runs `npm install pkg@fixed --package-lock-only --ignore-scripts` in the scanned project |
| `gitignore-env` | Adds `.env` patterns to `.gitignore` |

## What it runs, sends and stores

- **Network requests from the hook:** `https://api.osv.dev` (vulnerability lookups), `https://registry.npmjs.org` and `https://pypi.org` (to confirm a package exists and find its latest version). Only package names and versions are sent, never file contents, commands or secrets.
- **Network requests from the scanner and fixes, only when you run them:** the same OSV lookups for the scanned project's dependencies. `pin-actions` runs `git ls-remote` against `https://github.com/<owner>/<repo>` for each workflow action. If you have the GitHub CLI (`gh`) installed, the scan runs `gh pr list` on the scanned repo with your own `gh` login to look for blocklisted PR titles. If `osv-scanner` is installed, the scan runs it on the project.
- **Commands it runs locally:** `git` (read-only: refs, log, file list) in the scanned repo. The `npm-upgrade` fix runs `npm install … --package-lock-only --ignore-scripts`, only after you approve that fix.
- **Files it writes:** a decision log at `~/.security-gate/decisions.jsonl` for every deny or ask decision, including the first 400 characters of the command or edit. Scan reports and backups go to `<repo>/.security-gate/`. Approved fixes edit the project files listed above. It never edits your Claude Code settings.
- **Settings:** `SECURITY_GATE_TIMEOUT` (default 8 s per lookup) and `SECURITY_GATE_OFFLINE=1` (no network; every package check becomes `ask`).

## Your own blocklist

The bundled list in `data/iocs.json` ships empty. Add indicators from security advisories you trust to `~/.security-gate/iocs.local.json`. That file is merged with the bundled list and survives plugin updates:

```json
{
  "git_branches": [{"value": "evil-branch", "campaign": "example"}],
  "pr_titles": [{"value": "suspicious PR title", "campaign": "example"}],
  "blocked_packages": {"npm": [{"name": "bad-pkg", "version": "1.2.3"}], "PyPI": []},
  "blocked_domains": [{"value": "evil.example", "campaign": "example"}]
}
```

Leave out `version` to block every version of a package.

## Run the tests

From a clone of this repository:

```bash
python3 -m unittest discover -s tests
```

The tests are offline. Network lookups are replaced with fake results.

## Limits

- **Best-effort parsing.** It's a guardrail, not a sandbox. A determined attacker can disguise a shell command, for example by writing a downloader in inline Python. Use it alongside least-privilege tokens and normal review.
- **False positives.** It matches command text. A command that mentions both a `.env` file and a URL is denied, even when it's harmless.
- **Not covered:** `uv add` and `poetry add` aren't checked. pnpm and yarn lockfiles need `osv-scanner`.
- **Version ranges.** For ranges like `^1.2.0`, the hook checks the latest published version, which is what npm/pip will most likely install.

## Uninstall

```bash
claude plugin uninstall agent-safeguard-gate@agent-safeguard
```

## License

MIT. See [LICENSE](LICENSE).
