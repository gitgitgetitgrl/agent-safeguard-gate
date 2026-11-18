#!/usr/bin/env python3
"""Claude Code PreToolUse hook: blocks or escalates risky downloads, installs, and edits.

Decisions: deny (known-bad / high-risk), ask (needs your approval), or no output (normal flow).
Never auto-approves anything. Reads hook JSON on stdin, writes a decision JSON on stdout.
"""
from __future__ import annotations

import json
import os
import re
import shlex
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import common  # noqa: E402

LOG = Path(os.environ.get("SECURITY_GATE_LOG", str(Path.home() / ".security-gate" / "decisions.jsonl")))
RANK = {"allow": 0, "ask": 1, "deny": 2}

NPM_INSTALL = {"install", "i", "add", "ci", "isntall", "in"}
NPX_LIKE = {"npx", "bunx", "pnpx"}
CRED_PATHS = re.compile(r"(~|\$HOME|/home/[^/\s]+|/Users/[^/\s]+)/(\.aws/credentials|\.ssh/id_[\w]+|\.config/gcloud|"
                        r"\.docker/config\.json|\.npmrc|\.pypirc|\.netrc|\.kube/config|\.git-credentials)|"
                        r"(^|[\s/])\.env(\.[\w]+)?\b|application_default_credentials\.json")
NET_TOOLS = re.compile(r"\b(curl|wget|nc|ncat|socat|scp|rsync|ftp|Invoke-WebRequest|iwr|http|https)\b")


class Verdict:
    def __init__(self) -> None:
        self.level = "allow"
        self.reasons: list[str] = []

    def add(self, level: str, reason: str) -> None:
        self.reasons.append(f"[{level.upper()}] {reason}")
        if RANK[level] > RANK[self.level]:
            self.level = level


def split_segments(cmd: str) -> list[list[str]]:
    """Split a shell command on ; && || | into token lists (best effort)."""
    try:
        lex = shlex.shlex(cmd, posix=True, punctuation_chars=";&|")
        lex.whitespace_split = True
        toks = list(lex)
    except ValueError:
        toks = cmd.split()
    segs, cur = [], []
    for t in toks:
        if t and set(t) <= set(";&|"):
            if cur:
                segs.append(cur)
            cur = []
        else:
            cur.append(t)
    if cur:
        segs.append(cur)
    return segs


def strip_prefix(seg: list[str]) -> list[str]:
    i = 0
    while i < len(seg) and (re.match(r"^\w+=", seg[i]) or seg[i] in {"sudo", "env", "time", "nohup", "command"}):
        i += 1
    return seg[i:]


def parse_npm_spec(spec: str) -> tuple[str, str | None] | None:
    if spec.startswith(("-", ".", "/", "~")) or "://" in spec or spec.startswith(("git+", "github:", "file:")):
        return None
    if spec.startswith("@"):
        at = spec.find("@", 1)
        return (spec, None) if at == -1 else (spec[:at], spec[at + 1:] or None)
    name, _, ver = spec.partition("@")
    return name, (ver or None)


def parse_pip_spec(spec: str) -> tuple[str, str | None] | None:
    if spec.startswith(("-", ".", "/")) or "://" in spec or spec.endswith((".whl", ".tar.gz", ".zip")):
        return None
    m = re.match(r"^([A-Za-z0-9][A-Za-z0-9._\-]*)(\[[^\]]*\])?\s*(==\s*([\w.\-+!]+))?", spec)
    if not m:
        return None
    return m.group(1), m.group(4)


def is_exact(ver: str | None) -> bool:
    return bool(ver) and re.fullmatch(r"v?\d+(\.\d+)*([\-+.][\w.\-]+)?", ver or "") is not None


def check_packages(eco: str, pkgs: list[tuple[str, str | None]], v: Verdict, executes: bool) -> None:
    if not pkgs:
        return
    iocs = common.load_iocs().get("blocked_packages", {}).get(eco, [])
    resolved: list[tuple[str, str, str]] = []
    for name, ver in pkgs:
        if any(b.get("name") == name and (not b.get("version") or b.get("version") == ver) for b in iocs):
            v.add("deny", f"{eco} package {name} is on the local IOC blocklist.")
            continue
        try:
            if not is_exact(ver):
                latest = common.resolve_latest(eco, name)
                if latest is None:
                    v.add("ask", f"{eco} package '{name}' does not exist on the public registry "
                                 "(possible typo, slopsquat, or private-name dependency confusion).")
                    continue
                ver = latest  # ranges/tags: verify the version npm/pip would most likely pick
            resolved.append((eco, name, ver.lstrip("v")))
        except common.NetworkError as e:
            v.add("ask", f"Could not verify {eco} package {name} ({e}); approve only if you trust it.")
    if not resolved:
        return
    try:
        results = common.osv_batch(resolved)
    except common.NetworkError as e:
        v.add("ask", f"OSV lookup failed ({e}); packages unverified: " + ", ".join(f"{n}@{x}" for _, n, x in resolved))
        return
    for (e, n, ver), ids in zip(resolved, results):
        mal = [i for i in ids if i.startswith("MAL-")]
        if mal:
            v.add("deny", f"{e} {n}@{ver} is flagged MALICIOUS by OSV/OpenSSF ({', '.join(mal)}). Do not install.")
        elif ids:
            v.add("ask", f"{e} {n}@{ver} has {len(ids)} known vulnerabilities ({', '.join(ids[:5])}"
                         f"{'...' if len(ids) > 5 else ''}). Prefer a fixed version.")
    if executes:
        v.add("ask", "This command downloads and immediately executes a package (npx/dlx/uvx/pipx run).")


def lockfile_packages(cwd: Path) -> list[tuple[str, str]]:
    lock = cwd / "package-lock.json"
    if not lock.exists():
        return []
    try:
        data = json.loads(lock.read_text())
    except (OSError, json.JSONDecodeError):
        return []
    out = []
    for path, meta in (data.get("packages") or {}).items():
        if path and "node_modules/" in path and meta.get("version") and not meta.get("link"):
            out.append((path.rsplit("node_modules/", 1)[1], meta["version"]))
    for name, meta in (data.get("dependencies") or {}).items() if not out else []:
        if meta.get("version"):
            out.append((name, meta["version"]))
    return sorted(set(out))


def check_bash(cmd: str, cwd: Path, v: Verdict) -> None:
    iocs = common.load_iocs()
    if common.PIPE_SHELL_RE.search(cmd) or re.search(r"(ba|z)?sh\s+<\(\s*(curl|wget)|(ba)?sh\s+-c\s+[\"']?\$\(\s*(curl|wget)", cmd):
        v.add("deny", "Piping a remote download directly into a shell/interpreter. Download to a file, verify checksum/signature, inspect, then run.")
    if CRED_PATHS.search(cmd) and NET_TOOLS.search(cmd):
        v.add("deny", "Command reads credential files and uses a network tool in the same invocation (exfiltration pattern).")
    elif CRED_PATHS.search(cmd) and re.search(r"\b(cat|less|more|head|tail|cp|base64|xxd|strings|type)\b", cmd):
        v.add("ask", "Command reads a credential/secret file.")
    if re.search(r"\b(env|printenv|set)\b[^|]*\|[^|]*\b(curl|wget|nc|base64)\b", cmd):
        v.add("deny", "Environment variables piped to a network/encoding tool (secret exfiltration pattern).")
    if re.search(r"(curl|wget)\b.*(-o|-O|--output)\b.*&&.*chmod\s+\+x", cmd):
        v.add("ask", "Downloads a file and makes it executable; verify its checksum/signature first.")
    if re.search(r"https?://\d{1,3}(\.\d{1,3}){3}", cmd) and re.search(r"\b(curl|wget|iwr)\b", cmd):
        v.add("ask", "Download from a raw IP address.")
    for d in iocs.get("blocked_domains", []):
        if d["value"] in cmd:
            v.add("deny", f"Blocked domain ({d.get('campaign', 'IOC')}): {d['value']}")
    for b in iocs.get("git_branches", []):
        if re.search(rf"\bgit\b.*\b(checkout|switch|merge|pull|cherry-pick|rebase)\b.*\b{re.escape(b['value'])}\b", cmd):
            v.add("deny", f"Branch '{b['value']}' is a known {b['campaign']} indicator. Investigate, do not merge or run it.")

    for seg in split_segments(cmd):
        seg = strip_prefix(seg)
        if not seg:
            continue
        tool = Path(seg[0]).name
        args = seg[1:]
        if tool in {"npm", "pnpm", "yarn", "bun", "cnpm"}:
            sub = args[0] if args else ("install" if tool == "yarn" else "")
            if tool in {"pnpm", "yarn"} and sub == "dlx":
                pk = [p for p in (parse_npm_spec(a) for a in args[1:] if not a.startswith("-")) if p][:1]
                check_packages("npm", pk, v, executes=True)
                continue
            if tool == "npm" and sub in {"exec", "x"}:
                pk = [p for p in (parse_npm_spec(a) for a in args[1:] if not a.startswith("-") and a != "--") if p][:1]
                check_packages("npm", pk, v, executes=True)
                continue
            if tool == "npm" and sub == "config" and "ignore-scripts" in " ".join(args) and "false" in args:
                v.add("ask", "Re-enabling npm lifecycle scripts globally weakens supply-chain protection.")
            if sub in NPM_INSTALL or (tool == "yarn" and not args):
                specs = [a for a in args[1:] if not a.startswith("-")]
                pkgs = [p for p in (parse_npm_spec(s) for s in specs) if p]
                for s in specs:
                    if "://" in s or s.startswith(("git+", "github:")):
                        v.add("ask", f"Installing directly from a URL/git source bypasses registry signatures: {s}")
                if pkgs:
                    check_packages("npm", pkgs, v, executes=False)
                else:
                    lp = lockfile_packages(cwd)
                    if lp:
                        try:
                            res = common.osv_batch([("npm", n, ver) for n, ver in lp])
                            mal = [(n, ver, ids) for (n, ver), ids in zip(lp, res) if any(i.startswith("MAL-") for i in ids)]
                            vuln = [(n, ver) for (n, ver), ids in zip(lp, res) if ids]
                            for n, ver, ids in mal:
                                v.add("deny", f"Lockfile contains MALICIOUS package {n}@{ver} ({', '.join(i for i in ids if i.startswith('MAL-'))}).")
                            if vuln and not mal:
                                v.add("ask", f"Lockfile has {len(vuln)} packages with known vulnerabilities "
                                             f"(e.g. {', '.join(f'{n}@{x}' for n, x in vuln[:4])}). Ask Claude to scan the repo for fixes.")
                        except common.NetworkError as e:
                            v.add("ask", f"Could not scan package-lock.json against OSV ({e}).")
                    elif sub != "ci":
                        v.add("ask", "Installing without a lockfile; resolved versions are unpinned.")
                if "--ignore-scripts" not in args and not npmrc_ignores_scripts(cwd):
                    v.add("ask", f"{tool} {sub or 'install'} will run package lifecycle scripts (the main npm worm vector). "
                                 f"Safer: add --ignore-scripts, or set ignore-scripts=true in .npmrc.")
        elif tool in NPX_LIKE:
            pk = [p for p in (parse_npm_spec(a) for a in args if not a.startswith("-")) if p][:1]
            check_packages("npm", pk, v, executes=True)
        elif tool in {"pip", "pip3"} or (tool.startswith("python") and args[:2] == ["-m", "pip"]) or \
                (tool == "uv" and args[:1] == ["pip"]):
            a = args[2:] if tool.startswith("python") else (args[1:] if tool == "uv" else args)
            if not a or a[0] != "install":
                continue
            a = a[1:]
            joined = " ".join(a)
            if "--trusted-host" in a or re.search(r"--(extra-)?index-url\s+http://", joined):
                v.add("deny", "pip told to trust an unauthenticated/HTTP index (MITM and package substitution risk).")
            if "--extra-index-url" in a:
                v.add("ask", "--extra-index-url mixes indexes; a public package can shadow your private one (dependency confusion).")
            if "-r" in a or "--requirement" in a or any(x.startswith("--requirement=") for x in a):
                if "--require-hashes" not in a:
                    v.add("ask", "Installing a requirements file without --require-hashes; tampered artifacts would not be detected.")
                continue
            specs, skip = [], False
            for x in a:
                if skip:
                    skip = False
                    continue
                if x in {"-i", "--index-url", "--extra-index-url", "-c", "--constraint", "-t", "--target", "--trusted-host"}:
                    skip = True
                    continue
                if x.startswith("-"):
                    continue
                if "://" in x or x.startswith("git+"):
                    v.add("ask", f"Installing from a URL/VCS source: {x}")
                specs.append(x)
            check_packages("PyPI", [p for p in (parse_pip_spec(s) for s in specs) if p], v, executes=False)
        elif tool in {"uvx", "pipx"}:
            rest = args[1:] if tool == "pipx" and args[:1] in (["run"], ["install"]) else args
            pk = [p for p in (parse_pip_spec(x) for x in rest if not x.startswith("-")) if p][:1]
            check_packages("PyPI", pk, v, executes=(tool == "uvx" or args[:1] == ["run"]))
        elif tool == "git" and args[:1] == ["config"] and "core.hooksPath" in args:
            v.add("ask", "Changing core.hooksPath can silently run attacker-controlled git hooks.")
        elif tool in {"chmod"} and any(re.fullmatch(r"[0-7]?777", x) for x in args):
            v.add("ask", "chmod 777 makes files world-writable.")


def npmrc_ignores_scripts(cwd: Path) -> bool:
    for p in [cwd / ".npmrc", Path.home() / ".npmrc"]:
        try:
            if re.search(r"^\s*ignore-scripts\s*=\s*true", p.read_text(), re.M):
                return True
        except OSError:
            pass
    return False


def check_write(path: str, content: str, v: Verdict, partial: bool = False) -> None:
    p = path.replace("\\", "/")
    name = Path(p).name
    if re.search(r"/\.github/workflows/[^/]+\.ya?ml$", p) or re.search(r"(^|/)action\.ya?ml$", p):
        for f in common.audit_workflow(content):
            if f["rule"] == "GHA-NO-PERMS" and partial:
                continue
            v.add(f["sev"], f"{f['rule']}: {f['msg']}")
    secrets = common.find_secrets(content)
    if secrets:
        if re.match(r"^\.env(\..+)?$", name) and not name.endswith((".example", ".sample", ".template")):
            v.add("ask", f"Writing secrets ({', '.join(secrets)}) to {name}; make sure it is gitignored.")
        else:
            v.add("deny", f"Content contains a live-looking secret ({', '.join(secrets)}). Use an env var or secret manager instead.")
    if name == "package.json" and re.search(r'"(pre|post)?install"\s*:\s*"[^"]*(curl|wget|node -e|bash|sh -c|powershell)', content):
        v.add("ask", "package.json adds an install lifecycle script that downloads or executes code.")
    if re.search(r"(/\.bashrc|/\.zshrc|/\.profile|/\.bash_profile|/\.git/hooks/|/\.claude/settings(\.local)?\.json|"
                 r"/Library/LaunchAgents/|/\.config/autostart/|/etc/cron|/\.ssh/authorized_keys)", p):
        v.add("ask", f"Writing to a persistence/startup location: {p}")
    if name in {".npmrc", "pip.conf", "pip.ini"} and re.search(r"ignore-scripts\s*=\s*false|trusted-host", content):
        v.add("ask", f"{name} change weakens install safety (ignore-scripts=false or trusted-host).")


def decide(event: dict) -> Verdict:
    v = Verdict()
    tool = event.get("tool_name", "")
    ti = event.get("tool_input", {}) or {}
    cwd = Path(event.get("cwd") or os.getcwd())
    if tool in {"Bash", "PowerShell", "Monitor"}:
        check_bash(ti.get("command", ""), cwd, v)
    elif tool == "Write":
        check_write(ti.get("file_path", ""), ti.get("content", ""), v)
    elif tool == "Edit":
        check_write(ti.get("file_path", ""), ti.get("new_string", ""), v, partial=True)
    elif tool == "MultiEdit":
        check_write(ti.get("file_path", ""), "\n".join(e.get("new_string", "") for e in ti.get("edits", [])), v, partial=True)
    elif tool == "NotebookEdit":
        check_write(ti.get("notebook_path", ""), ti.get("new_source", ""), v, partial=True)
    return v


def log(event: dict, v: Verdict) -> None:
    try:
        LOG.parent.mkdir(parents=True, exist_ok=True)
        with LOG.open("a") as fh:
            fh.write(json.dumps({"tool": event.get("tool_name"), "decision": v.level, "reasons": v.reasons,
                                 "input": str(event.get("tool_input"))[:400], "session": event.get("session_id")}) + "\n")
    except OSError:
        pass


def main() -> int:
    try:
        event = json.load(sys.stdin)
    except json.JSONDecodeError:
        print("agent-safeguard-gate: unreadable hook input", file=sys.stderr)
        return 2  # fail closed
    v = decide(event)
    if v.level != "allow":
        log(event, v)
        print(json.dumps({"hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": v.level,
            "permissionDecisionReason": "agent-safeguard-gate: " + " | ".join(v.reasons)[:1800],
        }}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
