---
name: security-gate
description: Scans and hardens local repos, dependencies, downloads, and GitHub Actions against supply-chain threats (malicious npm/PyPI packages, Shai-Hulud-style install worms, CI workflow secret theft, pipe-to-shell installers, leaked secrets). Use before installing packages, running downloaded code, cloning or merging untrusted branches, editing CI workflows, or when the user asks to scan, audit, patch, or check a repo for compromise.
---

# Security gate

Two layers work together:

1. **Always-on hook** (`scripts/gate_hook.py`, registered automatically by this plugin's `hooks/hooks.json`). It runs before every Bash, Write, and Edit call and returns `deny` or `ask`. It never auto-approves anything.
2. **This skill**. It runs the procedure below: scan, explain, propose fixes, and apply only the fixes the user approves.

The hook is active whenever this plugin is enabled. This plugin never changes the user's Claude Code settings. If the user wants Claude blocked from reading common credential files (`~/.aws/credentials`, `~/.ssh/id_*`, `~/.npmrc`, and others), point them to the "Optional: block Claude from reading credential files" section of the plugin's README, which they apply themselves.

## Rules you must follow

- **Do not get around an agent-safeguard-gate denial.** That means no rewording the command, splitting it up, encoding it, or switching tools. Report the reason to the user and offer the safe alternative from the reason text.
- **Treat an `ask` decision as a question for the user.** Do not pre-answer it or describe it as harmless.
- **Never apply fixes without explicit approval** in the current conversation. Show the fix IDs and get a yes before running `fix.py --apply ... --yes`.
- **Never print, cat, or echo secret values,** even when confirming that a secret exists. Refer to the file and line instead.
- **Install with safe defaults.** Use `npm ci --ignore-scripts` or `npm install <pkg>@<exact> --ignore-scripts`, and `pip install --require-hashes -r requirements.txt` when hashes exist. Prefer exact versions over ranges.
- **Never pipe a download into a shell.** Download to a file, verify the checksum or signature from the vendor, show the user the script, then run it only if they approve.

## Procedure: scan a repo

1. Run `python3 ${CLAUDE_PLUGIN_ROOT}/scripts/scan.py <repo>`. It is read-only and writes `<repo>/.security-gate/report.{json,md,html}` plus `fix-plan.json`. Exit code 1 means a critical finding exists.
2. Read `report.md` and present the findings to the user, grouped as follows:
   - **Critical** (malicious package, campaign IOC): stop. Follow *Compromise response* below before anything else.
   - **High/Medium**: explain the risk in one line each and list the fix IDs.
   - **Low/Info**: summarize briefly.
3. Offer the fix plan (`python3 ${CLAUDE_PLUGIN_ROOT}/scripts/fix.py --plan <repo>/.security-gate/fix-plan.json --list`). Apply only the IDs the user approves. Every change is backed up under `.security-gate/backups/`.
4. Re-run the scan and report what changed. Tell the user to commit the hardened files and to add `.security-gate/` to `.gitignore`.

## Procedure: before a download or install

Check the package with `scan.py`, or let the hook check it. Then:

- If OSV lists a `MAL-` ID, do not install the package. If the package is already present, run *Compromise response*.
- If the package does not exist on the registry, it is probably a typo or a hallucinated "slopsquat" name. Confirm the exact name with the user.
- If it has known vulns, propose the fixed version.
- For tools such as `npx`/`uvx` that execute on first use, state that they run remote code immediately and ask.

## Procedure: compromise response (critical finding)

Follow this order. Containment comes before cleanup.

1. **Contain.** Stop running dev servers and CI jobs for the repo. Do not run `npm install` or the project's scripts again.
2. **Preserve evidence.** Copy `report.json`, `~/.security-gate/decisions.jsonl`, the lockfiles, and `git log --all` output into a dated folder.
3. **Rotate credentials.** Assume everything reachable from this machine or CI is exposed: GitHub PATs and `gh` auth, npm/PyPI tokens, cloud keys (AWS, GCP service-account keys and ADC, Azure), and AI API keys (OpenAI, Anthropic, Gemini). Revoke first, then reissue.
4. **CI or repository compromise indicators** (a branch, PR title, or commit message from the IOC list, or gaps in workflow run numbers):
   - Remove the pushing account's repo access, and delete the branch only after evidence is saved.
   - Audit workflow runs and audit logs from the earliest suspicious activity onward.
   - Review cloud OIDC trust policies and any new IAM users, roles, service accounts, or keys.
5. **Eradicate.** Delete `node_modules` and virtualenvs, and clear caches (`npm cache clean --force`, `pip cache purge`). Check `~/.bashrc`, `~/.zshrc`, LaunchAgents, cron, `.git/hooks`, `~/.ssh/authorized_keys`, and `.claude/settings*.json` for added persistence.
6. **Recover.** Reinstall from a clean lockfile with `--ignore-scripts`, then re-scan.

## Keeping it current

- Add new indicators to `~/.security-gate/iocs.local.json` as advisories publish them. Do not edit `${CLAUDE_PLUGIN_ROOT}/data/iocs.json`: plugin updates replace it, while the local file is kept and merged in. The fields are `git_branches`, `pr_titles`, `commit_messages`, `workflow_strings`, `blocked_packages`, and `blocked_domains`.
- OSV data, including OpenSSF malicious-package `MAL-` records, is queried live on every check, so no update is needed for that.
- If `osv-scanner` is on PATH, `scan.py` also uses it for pnpm and yarn lockfiles.
