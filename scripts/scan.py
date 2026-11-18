#!/usr/bin/env python3
"""Repository scanner: dependencies (OSV, incl. MAL- malicious packages), GitHub Actions hardening,
campaign IOCs (from data/iocs.json and your local list), committed secrets, and install-safety config.

Read-only. Writes a report (JSON + Markdown + HTML) and a fix plan that fix.py can apply after approval.
Usage: python3 scan.py [repo_dir] [--out DIR] [--no-network]
"""
from __future__ import annotations

import argparse
import datetime as dt
import html
import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import common  # noqa: E402

SKIP_DIRS = {"node_modules", ".git", ".venv", "venv", "dist", "build", "__pycache__", ".security-gate", ".next"}
SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def walk(root: Path):
    for dp, dns, fns in os.walk(root):
        dns[:] = [d for d in dns if d not in SKIP_DIRS]
        for fn in fns:
            yield Path(dp) / fn


def git(root: Path, *args: str) -> str:
    try:
        return subprocess.run(["git", "-C", str(root), *args], capture_output=True, text=True, timeout=30).stdout
    except (OSError, subprocess.TimeoutExpired):
        return ""


class Report:
    def __init__(self, root: Path):
        self.root = root
        self.findings: list[dict] = []
        self.fixes: list[dict] = []
        self.stats = {"npm_packages": 0, "pypi_packages": 0, "workflows": 0, "files_scanned": 0}

    def add(self, sev, category, title, detail, path=None, fix_id=None):
        self.findings.append({"severity": sev, "category": category, "title": title, "detail": detail,
                              "path": str(path.relative_to(self.root)) if isinstance(path, Path) else path,
                              "fix": fix_id})

    def fix(self, kind, desc, **params):
        fid = f"F{len(self.fixes) + 1:03d}"
        self.fixes.append({"id": fid, "kind": kind, "description": desc, "params": params, "requires_approval": True})
        return fid


# ---------------- dependencies ----------------

def npm_lock(path: Path) -> list[tuple[str, str]]:
    try:
        data = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError):
        return []
    out = set()
    for k, meta in (data.get("packages") or {}).items():
        if k and "node_modules/" in k and meta.get("version") and not meta.get("link"):
            out.add((k.rsplit("node_modules/", 1)[1], meta["version"]))

    def rec(deps):
        for n, m in (deps or {}).items():
            if m.get("version"):
                out.add((n, m["version"]))
            rec(m.get("dependencies"))
    if not out:
        rec(data.get("dependencies"))
    return sorted(out)


def py_reqs(path: Path) -> list[tuple[str, str, int]]:
    out = []
    for i, line in enumerate(path.read_text(errors="ignore").splitlines(), 1):
        m = re.match(r"^\s*([A-Za-z0-9][A-Za-z0-9._\-]*)(\[[^\]]*\])?\s*==\s*([\w.\-+!]+)", line)
        if m:
            out.append((m.group(1), m.group(3), i))
    return out


def toml_lock(path: Path) -> list[tuple[str, str]]:
    try:
        import tomllib
        data = tomllib.loads(path.read_text())
    except Exception:
        return []
    return [(p["name"], p["version"]) for p in data.get("package", []) if p.get("name") and p.get("version")]


def scan_dependencies(r: Report, network: bool):
    queries: list[tuple[str, str, str, Path, dict]] = []
    for f in walk(r.root):
        n = f.name
        if n == "package-lock.json" or n == "npm-shrinkwrap.json":
            for name, ver in npm_lock(f):
                queries.append(("npm", name, ver, f, {}))
        elif re.match(r"requirements.*\.txt$", n) or n == "constraints.txt":
            reqs = py_reqs(f)
            for name, ver, line in reqs:
                queries.append(("PyPI", name, ver, f, {"line": line}))
            text = f.read_text(errors="ignore")
            if reqs and "--hash=" not in text:
                r.add("low", "install-safety", "Requirements not hash-pinned",
                      "pip cannot detect tampered artifacts without --hash entries. Generate with "
                      "`pip-compile --generate-hashes` or `uv pip compile --generate-hashes`, then install with --require-hashes.", f)
        elif n in {"poetry.lock", "uv.lock"}:
            for name, ver in toml_lock(f):
                queries.append(("PyPI", name, ver, f, {}))
        elif n == "package.json" and "node_modules" not in f.parts:
            if not any((f.parent / l).exists() for l in ("package-lock.json", "pnpm-lock.yaml", "yarn.lock", "bun.lockb", "bun.lock", "npm-shrinkwrap.json")):
                r.add("medium", "install-safety", "package.json without a lockfile",
                      "Every install resolves fresh versions, so a newly published malicious release is pulled automatically. "
                      "Commit a lockfile and use `npm ci --ignore-scripts`.", f)
            try:
                pj = json.loads(f.read_text())
            except (OSError, json.JSONDecodeError):
                pj = {}
            for hook in ("preinstall", "install", "postinstall", "prepare"):
                cmd = (pj.get("scripts") or {}).get(hook, "")
                if cmd and re.search(r"curl|wget|node -e|base64|eval|powershell|https?://", cmd):
                    r.add("high", "supply-chain", f"Suspicious {hook} script", f"`{cmd[:200]}`", f)
        elif n in {"pnpm-lock.yaml", "yarn.lock"}:
            r.add("info", "coverage", f"{n} not parsed natively",
                  "Install osv-scanner (`osv-scanner scan source -r .`) for full coverage of this lockfile; "
                  "the scanner will use it automatically when on PATH.", f)
    r.stats["npm_packages"] = len({(n, v) for e, n, v, _, _ in queries if e == "npm"})
    r.stats["pypi_packages"] = len({(n, v) for e, n, v, _, _ in queries if e == "PyPI"})
    if not queries or not network:
        if queries and not network:
            r.add("info", "coverage", "Dependency lookup skipped", "Run without --no-network to check OSV.", None)
        return
    uniq = sorted({(e, n, v) for e, n, v, _, _ in queries})
    try:
        res = dict(zip(uniq, common.osv_batch(uniq)))
    except common.NetworkError as e:
        r.add("medium", "coverage", "OSV lookup failed", str(e), None)
        return
    detail_cache: dict[str, dict] = {}
    seen = set()
    for e, n, v, f, meta in queries:
        ids = res.get((e, n, v), [])
        if not ids or (e, n, v, f) in seen:
            continue
        seen.add((e, n, v, f))
        mal = [i for i in ids if i.startswith("MAL-")]
        if mal:
            r.add("critical", "malicious-package", f"MALICIOUS {e} package {n}@{v}",
                  f"{', '.join(mal)}. Remove it, delete node_modules/venv, rotate every credential available on this machine "
                  "and in CI, and check for persistence.", f)
            continue
        fixes, sevs = [], []
        for vid in ids[:12]:
            d = detail_cache.setdefault(vid, common.osv_details(vid))
            fixes += common.fixed_versions(d, e, n)
            sevs.append(common.severity_label(d))
        sev = "high" if any(s in {"CRITICAL", "HIGH"} for s in sevs) else "medium"
        target = max(fixes, key=_vkey) if fixes else None
        fid = None
        if target:
            if e == "PyPI" and "line" in meta:
                fid = r.fix("pip-pin", f"Pin {n}=={target} in {f.relative_to(r.root)}", file=str(f), name=n, version=target)
            elif e == "npm":
                fid = r.fix("npm-upgrade", f"Upgrade {n} to {target} (lockfile only, scripts disabled)",
                            dir=str(f.parent), name=n, version=target)
        r.add(sev, "vulnerable-dependency", f"{e} {n}@{v}: {len(ids)} known vulns",
              f"{', '.join(ids[:6])}{'...' if len(ids) > 6 else ''}" + (f". Fixed in {target}." if target else ". No fixed version listed."),
              f, fid)


def _vkey(v: str):
    return [int(x) if x.isdigit() else -1 for x in re.split(r"[.\-+]", v)]


def run_osv_scanner(r: Report):
    exe = shutil.which("osv-scanner")
    if not exe:
        return
    try:
        out = subprocess.run([exe, "scan", "source", "-r", "--format", "json", str(r.root)],
                             capture_output=True, text=True, timeout=240).stdout
        data = json.loads(out or "{}")
    except Exception as e:
        r.add("info", "coverage", "osv-scanner failed", str(e), None)
        return
    for res in data.get("results", []):
        for pkg in res.get("packages", []):
            p = pkg.get("package", {})
            ids = [v.get("id") for v in pkg.get("vulnerabilities", [])]
            if ids and res.get("source", {}).get("path", "").endswith(("pnpm-lock.yaml", "yarn.lock")):
                sev = "critical" if any(i.startswith("MAL-") for i in ids) else "medium"
                r.add(sev, "vulnerable-dependency", f"{p.get('ecosystem')} {p.get('name')}@{p.get('version')}",
                      ", ".join(ids[:6]), res["source"]["path"])


# ---------------- GitHub Actions ----------------

def scan_workflows(r: Report):
    wf_dir = r.root / ".github" / "workflows"
    files = list(wf_dir.glob("*.y*ml")) if wf_dir.exists() else []
    r.stats["workflows"] = len(files)
    sev_map = {"deny": "high", "ask": "medium"}
    for f in files:
        text = f.read_text(errors="ignore")
        for fd in common.audit_workflow(text):
            fid = None
            if fd["rule"] == "GHA-UNPINNED":
                fid = r.fix("pin-actions", f"Pin {len(fd['actions'])} action(s) to commit SHAs in {f.name}",
                            file=str(f), actions=fd["actions"])
            elif fd["rule"] == "GHA-NO-PERMS":
                fid = r.fix("add-permissions", f"Add top-level `permissions: contents: read` to {f.name}", file=str(f))
            sev = "critical" if fd["rule"] == "IOC" else sev_map[fd["sev"]]
            r.add(sev, "github-actions", fd["rule"], fd["msg"], f, fid)
        if re.search(r"id-token:\s*write", text):
            r.add("low", "github-actions", "OIDC id-token: write",
                  "Make sure the cloud trust policy pins repo, branch/environment and workflow (sub claim), "
                  "not just the org. Loose OIDC trust lets a stolen workflow mint cloud identities.", f)


# ---------------- IOCs ----------------

def scan_iocs(r: Report):
    if not (r.root / ".git").exists():
        return
    iocs = common.load_iocs()
    refs = git(r.root, "for-each-ref", "--format=%(refname)", "refs/heads", "refs/remotes")
    for b in iocs.get("git_branches", []):
        hits = [x for x in refs.splitlines() if x.rsplit("/", 1)[-1] == b["value"]]
        if hits:
            r.add("critical", "ioc", f"{b['campaign']} branch present",
                  f"Refs: {', '.join(hits)}. Treat as compromise: revoke the pushing account's tokens, review workflow runs "
                  "(look for gaps in run numbers), rotate all repo/org secrets and cloud OIDC trusts.", None)
    log = git(r.root, "log", "--all", "--since=60.days", "--format=%H%x09%an%x09%s")
    for c in iocs.get("commit_messages", []):
        for line in log.splitlines():
            parts = line.split("\t")
            if len(parts) == 3 and c["value"].lower() in parts[2].lower():
                r.add("critical", "ioc", f"{c['campaign']} commit message", f"{parts[0][:12]} by {parts[1]}: {parts[2]}", None)
    if shutil.which("gh"):
        for t in iocs.get("pr_titles", []):
            try:
                out = subprocess.run(["gh", "pr", "list", "--state", "all", "--search", f'"{t["value"]}" in:title',
                                      "--json", "number,author,title,createdAt"], cwd=r.root,
                                     capture_output=True, text=True, timeout=30).stdout
                for pr in json.loads(out or "[]"):
                    r.add("critical", "ioc", f"{t['campaign']} pull request #{pr['number']}",
                          f"'{pr['title']}' by {pr['author'].get('login')} at {pr['createdAt']}", None)
            except Exception:
                pass
    hooks = r.root / ".git" / "hooks"
    if hooks.exists():
        for h in hooks.iterdir():
            if h.is_file() and not h.name.endswith(".sample"):
                body = h.read_text(errors="ignore")
                if re.search(r"curl|wget|base64|nc |/dev/tcp", body):
                    r.add("high", "persistence", f"Suspicious git hook {h.name}", "Git hook makes network calls or decodes payloads.", h)


# ---------------- secrets & config ----------------

def scan_secrets(r: Report):
    tracked = git(r.root, "ls-files").splitlines()
    files = [r.root / t for t in tracked] if tracked else list(walk(r.root))
    for f in files:
        if not f.is_file() or f.stat().st_size > 2_000_000 or f.suffix in {".png", ".jpg", ".pdf", ".zip", ".woff2", ".ico"}:
            continue
        r.stats["files_scanned"] += 1
        try:
            text = f.read_text(errors="ignore")
        except OSError:
            continue
        hits = common.find_secrets(text)
        if hits:
            r.add("high", "secret", f"Secret committed: {', '.join(hits)}",
                  "Rotate the credential first (it is in git history), then remove it and use a secret manager. "
                  "Deleting the file alone does not help.", f)
    if tracked and any(Path(t).name == ".env" for t in tracked):
        r.add("high", "secret", ".env tracked by git", "Remove with `git rm --cached .env`, rotate its values.", None)
    gi = r.root / ".gitignore"
    if (r.root / ".git").exists() and (not gi.exists() or not re.search(r"^\.env", gi.read_text(errors="ignore"), re.M)):
        r.add("low", "secret", ".env not gitignored", "Add .env and .env.* to .gitignore.", gi,
              r.fix("gitignore-env", "Append .env patterns to .gitignore", file=str(gi)))
    if any(r.root.glob("**/package.json")):
        npmrc = r.root / ".npmrc"
        txt = npmrc.read_text(errors="ignore") if npmrc.exists() else ""
        if not re.search(r"^\s*ignore-scripts\s*=\s*true", txt, re.M):
            r.add("medium", "install-safety", "npm lifecycle scripts enabled",
                  "Install-time scripts are how Shai-Hulud-style worms spread. Set ignore-scripts=true and allowlist the few packages that need builds.",
                  npmrc, r.fix("npmrc-ignore-scripts", "Add ignore-scripts=true to project .npmrc", file=str(npmrc)))
        if re.search(r"_authToken\s*=\s*[^$\s{]", txt):
            r.add("high", "secret", "Literal npm token in .npmrc", "Use ${NPM_TOKEN} instead and rotate the token.", npmrc)


# ---------------- output ----------------

def render(r: Report, out: Path):
    out.mkdir(parents=True, exist_ok=True)
    r.findings.sort(key=lambda x: SEV_ORDER[x["severity"]])
    counts = {s: sum(1 for f in r.findings if f["severity"] == s) for s in SEV_ORDER}
    meta = {"repo": str(r.root), "scanned_at": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"),
            "counts": counts, "stats": r.stats, "ioc_version": common.load_iocs().get("updated")}
    (out / "report.json").write_text(json.dumps({"meta": meta, "findings": r.findings}, indent=2))
    (out / "fix-plan.json").write_text(json.dumps({"repo": str(r.root), "fixes": r.fixes}, indent=2))
    md = [f"# Security scan: {r.root.name}", "", f"Scanned {meta['scanned_at']}. "
          + ", ".join(f"{k}: {v}" for k, v in counts.items()), ""]
    for f in r.findings:
        md.append(f"- **{f['severity'].upper()}** [{f['category']}] {f['title']}"
                  + (f" (`{f['path']}`)" if f['path'] else "") + f" — {f['detail']}" + (f" → fix `{f['fix']}`" if f['fix'] else ""))
    md += ["", "## Proposed fixes (need approval)", ""] + [f"- `{x['id']}` {x['description']}" for x in r.fixes]
    (out / "report.md").write_text("\n".join(md) + "\n")
    (out / "report.html").write_text(html_report(meta, r.findings, r.fixes))
    return meta


def html_report(meta, findings, fixes) -> str:
    colors = {"critical": "#b42318", "high": "#c4320a", "medium": "#b54708", "low": "#475467", "info": "#667085"}
    rows = "".join(
        f"<tr data-sev='{f['severity']}'><td><span class='pill' style='background:{colors[f['severity']]}'>{f['severity']}</span></td>"
        f"<td>{html.escape(f['category'])}</td><td><strong>{html.escape(f['title'])}</strong><div class='d'>{html.escape(f['detail'])}</div></td>"
        f"<td><code>{html.escape(f['path'] or '')}</code></td><td>{html.escape(f['fix'] or '')}</td></tr>" for f in findings)
    fx = "".join(f"<li><code>{x['id']}</code> {html.escape(x['description'])}</li>" for x in fixes) or "<li>None</li>"
    cards = "".join(f"<div class='card'><div class='n' style='color:{colors[k]}'>{v}</div><div>{k}</div></div>"
                    for k, v in meta["counts"].items())
    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Security scan · {html.escape(Path(meta['repo']).name)}</title><style>
:root{{--bg:#f7f7f5;--fg:#1d2939;--mut:#667085;--line:#e4e7ec;--card:#fff}}
@media (prefers-color-scheme:dark){{:root{{--bg:#111315;--fg:#e6e6e3;--mut:#98a2b3;--line:#2a2e33;--card:#1a1d20}}}}
body{{margin:0;font:15px/1.5 system-ui,-apple-system,Segoe UI,sans-serif;background:var(--bg);color:var(--fg)}}
main{{max-width:1180px;margin:0 auto;padding:32px 20px}}h1{{font-size:22px;margin:0 0 4px}}.m{{color:var(--mut);font-size:13px}}
.cards{{display:grid;grid-template-columns:repeat(5,1fr);gap:12px;margin:20px 0}}.card{{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:14px}}
.n{{font-size:26px;font-weight:700;font-variant-numeric:tabular-nums}}table{{width:100%;border-collapse:collapse;background:var(--card);border:1px solid var(--line);border-radius:10px;overflow:hidden}}
td,th{{text-align:left;padding:10px 12px;border-bottom:1px solid var(--line);vertical-align:top}}th{{font-size:12px;color:var(--mut);text-transform:uppercase;letter-spacing:.04em}}
.pill{{color:#fff;border-radius:999px;padding:2px 8px;font-size:12px}}.d{{color:var(--mut);font-size:13px;margin-top:2px}}code{{font-size:12px}}
.f{{margin:14px 0;display:flex;gap:8px;flex-wrap:wrap}}button{{border:1px solid var(--line);background:var(--card);color:var(--fg);border-radius:8px;padding:6px 12px;cursor:pointer}}
button[aria-pressed=true]{{outline:2px solid #2e90fa}}@media(max-width:700px){{.cards{{grid-template-columns:repeat(2,1fr)}}td:nth-child(4){{display:none}}}}
</style></head><body><main><h1>Security scan · {html.escape(Path(meta['repo']).name)}</h1>
<div class="m">{html.escape(meta['repo'])} · {meta['scanned_at']} · {meta['stats']['npm_packages']} npm / {meta['stats']['pypi_packages']} PyPI packages · {meta['stats']['workflows']} workflows · IOC set {meta['ioc_version']}</div>
<div class="cards">{cards}</div><div class="f" role="group" aria-label="Filter">{''.join(f"<button data-s='{s}' aria-pressed='false'>{s}</button>" for s in ['all'] + list(colors))}</div>
<table><thead><tr><th>Severity</th><th>Category</th><th>Finding</th><th>Path</th><th>Fix</th></tr></thead><tbody>{rows or '<tr><td colspan=5>No findings</td></tr>'}</tbody></table>
<h2 style="font-size:17px;margin-top:28px">Proposed fixes (apply only after approval)</h2><ul>{fx}</ul>
<p class="m">Apply: <code>python3 scripts/fix.py --plan fix-plan.json --apply F001 F002</code></p></main>
<script>document.querySelectorAll('[data-s]').forEach(b=>b.onclick=()=>{{document.querySelectorAll('[data-s]').forEach(x=>x.setAttribute('aria-pressed',x===b));
document.querySelectorAll('tbody tr').forEach(r=>r.style.display=(b.dataset.s==='all'||r.dataset.sev===b.dataset.s)?'':'none')}})</script></body></html>"""


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("repo", nargs="?", default=".")
    ap.add_argument("--out", default=None, help="output dir (default <repo>/.security-gate)")
    ap.add_argument("--no-network", action="store_true")
    ap.add_argument("--fail-on", default="critical", choices=list(SEV_ORDER), help="exit 1 at/above this severity")
    a = ap.parse_args()
    root = Path(a.repo).resolve()
    out = Path(a.out).resolve() if a.out else root / ".security-gate"
    r = Report(root)
    scan_dependencies(r, network=not a.no_network)
    if not a.no_network:
        run_osv_scanner(r)
    scan_workflows(r)
    scan_iocs(r)
    scan_secrets(r)
    meta = render(r, out)
    print(json.dumps({"out": str(out), **meta["counts"], "fixes": len(r.fixes)}))
    worst = min((SEV_ORDER[f["severity"]] for f in r.findings), default=9)
    return 1 if worst <= SEV_ORDER[a.fail_on] else 0


if __name__ == "__main__":
    sys.exit(main())
