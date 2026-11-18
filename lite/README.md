# Agent Safeguard Lite

**Agent Safeguard Lite** teaches Claude to check packages, downloads and code repositories before trusting them. Before Claude installs a package or runs a downloaded script, it confirms the package is real, looks it up for known malicious or vulnerable versions, and installs it with safe settings. Risky steps become a question for you, never a silent decision.

It can also review a repository for vulnerable dependencies, risky install scripts, unsafe GitHub Actions workflows and committed secrets. It proposes fixes and applies only the ones you approve.

This is the instructions-only edition of [Agent Safeguard Gate](https://github.com/gitgitgetitgrl/agent-safeguard-gate). It contains no hooks, scripts or programs, so it works everywhere Claude supports skills: claude.ai chat, Cowork and Claude Code.

## Install

- **claude.ai or Cowork:** find **Agent Safeguard Lite** in the plugin directory under **Customize > Plugins**, once it's listed.
- **Claude Code:** inside a session, run:

  ```
  /plugin install agent-safeguard-lite --marketplace gitgitgetitgrl/agent-safeguard-gate
  ```

## What's included

| Skill | When Claude uses it |
|---|---|
| `safe-install` | Before installing a package, running a tool like `npx` or `uvx`, or running a downloaded script, and when you ask whether a package is safe |
| `repo-security-check` | When you ask Claude to scan, audit or harden a repo, before merging an untrusted branch or pull request, and before editing CI workflows. It also covers what to do if something looks compromised |

## How to use it

Ask in plain words, for example:

- "Is the `left-pad` package safe to install?"
- "Install requests, but check it first."
- "Scan this repo for security problems."
- "Review this GitHub Actions workflow before I merge it."

Claude also applies the skills on its own when you ask it to install something or edit a workflow.

## Lite vs. the full plugin

| | Lite (this plugin) | [Full plugin](https://github.com/gitgitgetitgrl/agent-safeguard-gate) |
|---|---|---|
| How it protects you | Claude follows the checklists when a skill applies | An always-on hook checks every command and file edit, even if Claude forgets |
| Blocks known-bad actions automatically | No | Yes |
| Works in claude.ai chat | Yes | Scan skill only |
| Works in Claude Code and Cowork | Yes | Yes |
| Needs Python | No | Yes |

The lite edition relies on Claude following its instructions, so it's a helpful habit, not a guarantee. For automatic blocking in Claude Code, install the full plugin from its GitHub page.

## What it sends

When Claude checks a package, it may contact these public services. It sends only the package name, ecosystem and version, never your files, commands or secrets:

- `api.osv.dev` and `osv.dev`, Google's open vulnerability database (includes OpenSSF malicious-package reports)
- `registry.npmjs.org`, `www.npmjs.com` and `pypi.org`, to confirm a package exists

The plugin stores nothing and changes no settings. Any file changes during a repo review happen only after you approve each fix.

## License

MIT. See [LICENSE](LICENSE).
