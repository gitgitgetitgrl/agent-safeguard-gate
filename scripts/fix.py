#!/usr/bin/env python3
"""Apply approved fixes from a scan fix-plan. Nothing changes unless you name fix IDs with --apply.

  python3 fix.py --plan .security-gate/fix-plan.json --list
  python3 fix.py --plan .security-gate/fix-plan.json --apply F001 F003   # asks y/N per fix
  python3 fix.py --plan ... --apply F001 --yes                            # approval given in chat
Every modified file is backed up to <repo>/.security-gate/backups/<timestamp>/ first.
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import re
import shutil
import subprocess
import sys
from pathlib import Path

STAMP = dt.datetime.now().strftime("%Y%m%d-%H%M%S")


def backup(repo: Path, f: Path):
    if f.exists():
        dest = repo / ".security-gate" / "backups" / STAMP / f.resolve().relative_to(repo)
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(f, dest)


def resolve_sha(action: str) -> str | None:
    repo_part, _, ref = action.partition("@")
    owner_repo = "/".join(repo_part.split("/")[:2])
    try:
        out = subprocess.run(["git", "ls-remote", f"https://github.com/{owner_repo}", f"refs/tags/{ref}",
                              f"refs/tags/{ref}^{{}}", f"refs/heads/{ref}"],
                             capture_output=True, text=True, timeout=30).stdout
    except (OSError, subprocess.TimeoutExpired):
        return None
    lines = [l.split("\t") for l in out.splitlines() if "\t" in l]
    peeled = [s for s, r in lines if r.endswith("^{}")]
    return (peeled or [s for s, _ in lines] or [None])[0]


def apply(fix: dict, repo: Path) -> str:
    k, p = fix["kind"], fix["params"]
    if k == "npmrc-ignore-scripts":
        f = Path(p["file"]); backup(repo, f)
        txt = f.read_text() if f.exists() else ""
        txt = re.sub(r"^\s*ignore-scripts\s*=.*$\n?", "", txt, flags=re.M)
        f.write_text(txt + ("" if txt.endswith("\n") or not txt else "\n") + "ignore-scripts=true\n")
        return f"{f}: ignore-scripts=true (run trusted build steps explicitly, e.g. `npm rebuild <pkg>`)"
    if k == "gitignore-env":
        f = Path(p["file"]); backup(repo, f)
        txt = f.read_text() if f.exists() else ""
        f.write_text(txt + ("\n" if txt and not txt.endswith("\n") else "") + ".env\n.env.*\n!.env.example\n")
        return f"{f}: .env patterns added"
    if k == "add-permissions":
        f = Path(p["file"]); backup(repo, f)
        txt = f.read_text()
        if re.search(r"^permissions:", txt, re.M):
            return f"{f}: already has permissions"
        new, n = re.subn(r"^jobs:", "permissions:\n  contents: read\n\njobs:", txt, count=1, flags=re.M)
        if not n:
            return f"{f}: SKIPPED (no top-level jobs: key found)"
        f.write_text(new)
        return f"{f}: added permissions: contents: read (grant extra scopes per job if a job needs them)"
    if k == "pin-actions":
        f = Path(p["file"]); txt = f.read_text(); done, failed = [], []
        for act in p["actions"]:
            sha = resolve_sha(act)
            if not sha:
                failed.append(act); continue
            base, _, ref = act.partition("@")
            txt = re.sub(rf"(uses:\s*['\"]?){re.escape(act)}(['\"]?)[^\n]*",
                         lambda m: f"{m.group(1)}{base}@{sha}{m.group(2)} # {ref}", txt)
            done.append(f"{act} -> {sha[:12]}")
        if done:
            backup(repo, f); f.write_text(txt)
        return f"{f}: pinned {', '.join(done) or 'none'}" + (f"; could not resolve {', '.join(failed)}" if failed else "")
    if k == "pip-pin":
        f = Path(p["file"]); backup(repo, f)
        txt = f.read_text()
        new = re.sub(rf"(?im)^(\s*{re.escape(p['name'])}(\[[^\]]*\])?\s*==\s*)[\w.\-+!]+([^\n]*)$",
                     lambda m: m.group(1) + p["version"] + re.sub(r"\s--hash=\S+", "", m.group(3)), txt)
        f.write_text(new)
        return f"{f}: {p['name']}=={p['version']} (regenerate hashes if you use them)"
    if k == "npm-upgrade":
        cmd = ["npm", "install", f"{p['name']}@{p['version']}", "--package-lock-only", "--ignore-scripts"]
        backup(repo, Path(p["dir"]) / "package-lock.json"); backup(repo, Path(p["dir"]) / "package.json")
        r = subprocess.run(cmd, cwd=p["dir"], capture_output=True, text=True, timeout=300)
        return f"{' '.join(cmd)} -> exit {r.returncode} {r.stderr.strip()[-300:]}"
    return f"unknown fix kind {k}"


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--plan", required=True)
    ap.add_argument("--list", action="store_true")
    ap.add_argument("--apply", nargs="*", default=[])
    ap.add_argument("--yes", action="store_true", help="skip per-fix y/N prompt (only after explicit user approval)")
    a = ap.parse_args()
    plan = json.loads(Path(a.plan).read_text())
    repo = Path(plan["repo"])
    fixes = {x["id"]: x for x in plan["fixes"]}
    if a.list or not a.apply:
        for x in fixes.values():
            print(f"{x['id']}  [{x['kind']}]  {x['description']}")
        return 0
    for fid in a.apply:
        fx = fixes.get(fid)
        if not fx:
            print(f"{fid}: not in plan"); continue
        if not a.yes and input(f"Apply {fid}: {fx['description']}? [y/N] ").strip().lower() != "y":
            print(f"{fid}: skipped"); continue
        print(f"{fid}: {apply(fx, repo)}")
    print("Re-run scan.py to verify.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
