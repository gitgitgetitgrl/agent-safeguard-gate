---
name: safe-install
description: Checks a package, tool, or downloaded script before Claude installs or runs it, to avoid malicious packages, typo-squatted or made-up package names, known-vulnerable versions, and pipe-to-shell installers. Use before any npm, pnpm, yarn, bun, pip, uv, poetry, or similar install, before running npx, uvx, pipx run, or dlx, before running a script downloaded from the internet, and whenever the user asks whether a package is safe.
---

# Safe install

Work through these checks before installing a package or running downloaded code. Each one is quick. If a check fails, stop and tell the user what you found instead of continuing.

This skill has no always-on enforcement. It works only when you follow it, so follow every step even when the install looks routine.

## 1. Confirm the exact package

- **Confirm the name and ecosystem** with the user if there's any doubt. Spell it exactly as published, including any `@scope/`.
- **Check that it exists on the official registry.** npm: `https://www.npmjs.com/package/<name>`. PyPI: `https://pypi.org/project/<name>/`. If it doesn't exist, it may be a typo or a made-up name that an attacker could register later. Don't guess a similar name. Ask the user.
- **Watch for look-alikes.** Be suspicious of a name one letter off from a popular package, a brand-new package with very few downloads, or a package whose description or maintainer doesn't match what the user expects. Say what looks off and ask before going further.

## 2. Check for malicious or vulnerable versions

Choose an exact version: the one the user named, or the latest release. Then look it up in OSV, Google's open vulnerability database, which includes OpenSSF's malicious-package reports.

- **With a shell (Claude Code or Cowork):** send a query to the OSV API. Only the package name, ecosystem and version are sent:

  ```bash
  curl -s https://api.osv.dev/v1/query -d '{"package":{"name":"lodash","ecosystem":"npm"},"version":"4.17.20"}'
  ```

  Use `npm` or `PyPI` as the ecosystem. An empty `{}` reply means no known issues.
- **Without a shell:** ask the user to open `https://osv.dev/list?q=<name>&ecosystem=<ecosystem>`, or open it yourself if you can browse.

Then act on the result:

- **Any ID starting with `MAL-`:** the package is known to be malicious. Do not install it. If it's already installed, tell the user right away and follow the compromise response in the `repo-security-check` skill.
- **Other IDs (GHSA, PYSEC, CVE):** the version has known vulnerabilities. Show the IDs and propose the fixed version that OSV lists.
- **Can't check (no network, an error):** say so plainly. Don't treat it as safe. Let the user decide.

## 3. Install with safe defaults

- **npm and similar:** install an exact version, and turn off install-time scripts, which are how package worms usually spread. For example: `npm install <name>@<exact-version> --ignore-scripts`. In a project with a lockfile, prefer `npm ci --ignore-scripts`.
- **pip:** pin exact versions (`<name>==<version>`). When the requirements file has hashes, install with `pip install --require-hashes -r requirements.txt`.
- **Prefer the lockfile.** If a JavaScript project has no lockfile, tell the user that every install will pull whatever versions are newest at that moment.
- **Don't weaken install safety without asking.** Never turn install scripts back on, never add an extra or unencrypted package source, and never trust a host that has no valid certificate unless the user explicitly asks after hearing the risk.

## 4. Tools that run immediately

`npx`, `bunx`, `pnpm dlx`, `yarn dlx`, `uvx` and `pipx run` download a package and run it in one step. Before using one:

- Tell the user that it runs code from the internet immediately.
- Run steps 1 and 2 on the package.
- Pin an exact version, such as `npx <name>@1.2.3`.
- Ask before running it.

## 5. Downloaded scripts and installers

- **Never send a download straight into a shell or interpreter.** That means never feeding the output of a download tool such as curl or wget directly into sh, bash, zsh, python or node, whether through a pipe or through process substitution.
- Instead: download to a file, check the vendor's published checksum or signature if there is one, show the user the script or a summary of what it does, and run it only if they approve.
- Be extra careful with downloads from a raw IP address or an unfamiliar domain. Point them out to the user.

## Rules

- **Never write secrets into code.** Use environment variables or a secret manager, and never print, echo or display secret values. Refer to the file and line instead.
- **When something is risky, it's the user's call.** Describe the risk in one or two plain sentences and ask. Don't call it harmless, and don't decide for them.
- **Don't work around a concern** by renaming, splitting or disguising a command. Explain the problem and offer the safer alternative.
