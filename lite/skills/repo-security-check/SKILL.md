---
name: repo-security-check
description: Reviews a code repository for supply-chain and security problems (malicious or vulnerable dependencies, risky install scripts, unsafe GitHub Actions workflows, committed secrets, and signs of persistence), then proposes fixes and applies only the ones the user approves. Also guides the response when a repo or machine may be compromised. Use when the user asks to scan, audit, harden, or check a repo, before merging an untrusted branch or pull request, and before editing CI workflows.
---

# Repo security check

Review the repository by reading its files. Report what you find, propose fixes, and change nothing until the user approves each fix.

## Rules

- **Never print, echo or quote secret values,** even to confirm that one exists. Give the file and line number instead.
- **Change nothing without approval.** List the proposed fixes, wait for a clear yes, then apply only those. Before changing a file, copy it to a backup next to it, such as `<file>.bak`, or confirm it's committed in git.
- **Be honest about coverage.** Say what you checked and what you couldn't, such as a lockfile format you couldn't read or a lookup that failed.

## 1. Dependencies

1. **Find the dependency files:** `package-lock.json`, `npm-shrinkwrap.json`, `pnpm-lock.yaml`, `yarn.lock`, `requirements*.txt`, `poetry.lock`, `uv.lock`.
2. **List each package and its exact version** from the lockfiles. For a large project, check the direct dependencies first and say so.
3. **Look each one up in OSV.** With a shell, one request can check many packages; only names, ecosystems and versions are sent:

   ```bash
   curl -s https://api.osv.dev/v1/querybatch -d '{"queries":[{"package":{"name":"lodash","ecosystem":"npm"},"version":"4.17.20"}]}'
   ```

   If the user has Google's `osv-scanner` tool installed, `osv-scanner scan source -r .` is faster for big projects. Without a shell, check the most important packages at `https://osv.dev`.
4. **Grade the results:**
   - Any `MAL-` ID: **critical**. Stop and follow *Compromise response* below.
   - Other vulnerabilities: **high** if OSV rates them high or critical, otherwise **medium**. Note the fixed version.

## 2. Install safety

- **`package.json` without a lockfile** (medium): every install pulls the newest versions, including a freshly published malicious one.
- **Install scripts** (`preinstall`, `install`, `postinstall`, `prepare`) that download or execute code, for example using `curl`, `wget`, `node -e`, `base64` or `eval` (high).
- **Install scripts enabled for the project** (medium): suggest adding `ignore-scripts=true` to the project's `.npmrc`, and allowing builds only for the few packages that need them.
- **Requirements files without hashes** (low): suggest generating hashes, for example with `pip-compile --generate-hashes`, and installing with `--require-hashes`.

## 3. GitHub Actions workflows

Read every file in `.github/workflows/`.

- **`pull_request_target` that checks out the pull request's code** (high): for example, `ref: ${{ github.event.pull_request.head.sha }}`. Untrusted code then runs with the repo's secrets.
- **Untrusted text inside `run:` steps** (high): `${{ github.event.issue.title }}`, `…pull_request.body`, `…comment.body`, `github.head_ref` and similar can inject commands. The fix is to pass the value through `env:` and quote it.
- **Secrets sent over the network or encoded** (high): a step that converts the whole secrets context to JSON, or that passes a repository secret to a network or encoding tool such as curl, wget or base64.
- **Actions not pinned to a full commit SHA** (medium): `uses: owner/action@v4` can change under you. Pin to the 40-character commit and keep the tag as a comment.
- **`permissions: write-all`, or no top-level `permissions:` block** (medium): suggest `permissions: contents: read` at the top, with extra scopes only on the jobs that need them.
- **`id-token: write`** (low): remind the user that the cloud trust policy should pin the repo, branch or environment, and workflow, not just the organization.

## 4. Secrets

- **Look for live-looking credentials:** AWS access keys (starting `AKIA` or `ASIA`), GitHub tokens (`ghp_`, `gho_`, `github_pat_`), Anthropic keys (`sk-ant-`), OpenAI keys (`sk-`), Google API keys (`AIza`), Slack tokens (`xox`), npm tokens (`npm_`), private key blocks (`-----BEGIN … PRIVATE KEY-----`), and cloud service-account JSON files.
- **`.env` committed to git, or missing from `.gitignore`** (high or low).
- **For every secret found:** tell the user to revoke and reissue it first, because it's already in git history. Deleting the file doesn't help.

## 5. Persistence and tampering

- **Git hooks** in `.git/hooks/` (other than `*.sample`) that make network calls or decode data (high).
- **On request, the user's own machine:** recently changed `~/.bashrc`, `~/.zshrc`, LaunchAgents, cron entries, the SSH authorized-keys list, and Claude settings files that the user doesn't recognize.

## 6. Report and fix

1. Present findings grouped as **Critical**, **High**, **Medium**, **Low**, with one line each on the risk and the file it's in.
2. Number the proposed fixes and ask which ones to apply.
3. Apply only the approved fixes, then re-check those items and report what changed.

## Compromise response

Use this when a malicious package or another sign of compromise turns up. Go in this order: contain before you clean up.

1. **Contain.** Stop running dev servers and CI jobs for the repo. Don't run installs or the project's scripts again.
2. **Preserve evidence.** Copy the lockfiles, the findings, and the output of `git log --all` into a dated folder before changing anything.
3. **Rotate credentials.** Assume everything reachable from this machine or CI is exposed: GitHub access tokens and GitHub CLI sign-ins, npm and PyPI tokens, cloud keys (AWS, Google Cloud, Azure), and AI API keys. Revoke first, then reissue.
4. **Check the repository and CI.** Look for unknown branches, pull requests or commits; gaps in workflow run numbers; and new cloud users, roles or keys. Remove unknown access only after the evidence is saved.
5. **Clean up.** Delete `node_modules` and virtual environments, clear package caches, and check the persistence locations in step 5 above.
6. **Recover.** Reinstall from a clean lockfile with install scripts turned off, then run this check again.
