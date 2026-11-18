"""Shared helpers for agent-safeguard-gate: OSV lookups, registry resolution, IOC loading, content rules."""
from __future__ import annotations

import json
import os
import re
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DATA = ROOT / "data"
OSV_BATCH = "https://api.osv.dev/v1/querybatch"
OSV_VULN = "https://api.osv.dev/v1/vulns/"
TIMEOUT = float(os.environ.get("SECURITY_GATE_TIMEOUT", "8"))
OFFLINE = os.environ.get("SECURITY_GATE_OFFLINE") == "1"


class NetworkError(Exception):
    pass


def _http_json(url: str, payload: dict | None = None) -> dict:
    if OFFLINE:
        raise NetworkError("offline mode")
    data = json.dumps(payload).encode() if payload is not None else None
    req = urllib.request.Request(url, data=data, headers={
        "Content-Type": "application/json", "User-Agent": "agent-safeguard-gate/1.0"})
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as r:
            return json.loads(r.read().decode())
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return {"__not_found__": True}
        raise NetworkError(f"HTTP {e.code} for {url}") from e
    except (urllib.error.URLError, TimeoutError, OSError, json.JSONDecodeError) as e:
        raise NetworkError(f"{type(e).__name__}: {e}") from e


LOCAL_IOCS = Path(os.environ.get("SECURITY_GATE_LOCAL_IOCS", str(Path.home() / ".security-gate" / "iocs.local.json")))


def load_iocs() -> dict:
    """Bundled indicators merged with the user's own ~/.security-gate/iocs.local.json (kept across plugin updates)."""
    p = DATA / "iocs.json"
    base = json.loads(p.read_text()) if p.exists() else {}
    try:
        local = json.loads(LOCAL_IOCS.read_text()) if LOCAL_IOCS.exists() else {}
    except (OSError, json.JSONDecodeError):
        local = {}
    for k, v in local.items():
        if isinstance(v, list):
            base[k] = list(base.get(k, [])) + v
        elif isinstance(v, dict) and k == "blocked_packages":
            merged = dict(base.get(k, {}))
            for eco, pkgs in v.items():
                merged[eco] = list(merged.get(eco, [])) + list(pkgs)
            base[k] = merged
    return base


def resolve_latest(ecosystem: str, name: str) -> str | None:
    """Return latest published version, or None if the package does not exist."""
    if ecosystem == "npm":
        enc = urllib.parse.quote(name, safe="@")
        enc = enc.replace("/", "%2F") if name.startswith("@") else enc
        doc = _http_json(f"https://registry.npmjs.org/{enc}/latest")
        return None if doc.get("__not_found__") else doc.get("version")
    if ecosystem == "PyPI":
        doc = _http_json(f"https://pypi.org/pypi/{urllib.parse.quote(name)}/json")
        return None if doc.get("__not_found__") else doc.get("info", {}).get("version")
    return None


def osv_batch(queries: list[tuple[str, str, str]]) -> list[list[str]]:
    """queries: (ecosystem, name, version). Returns list of vuln-id lists, same order."""
    out: list[list[str]] = []
    for i in range(0, len(queries), 900):
        chunk = queries[i:i + 900]
        body = {"queries": [{"version": v, "package": {"name": n, "ecosystem": e}} for e, n, v in chunk]}
        res = _http_json(OSV_BATCH, body).get("results", [])
        for r in res:
            out.append([v["id"] for v in r.get("vulns", []) or []])
        out.extend([[]] * (len(chunk) - len(res)))
    return out


def osv_details(vuln_id: str) -> dict:
    try:
        return _http_json(OSV_VULN + urllib.parse.quote(vuln_id))
    except NetworkError:
        return {}


def fixed_versions(vuln: dict, ecosystem: str, name: str) -> list[str]:
    fixes = []
    for aff in vuln.get("affected", []):
        pkg = aff.get("package", {})
        if pkg.get("ecosystem") != ecosystem or pkg.get("name", "").lower() != name.lower():
            continue
        for rng in aff.get("ranges", []):
            for ev in rng.get("events", []):
                if "fixed" in ev:
                    fixes.append(ev["fixed"])
    return fixes


def severity_label(vuln: dict) -> str:
    sev = (vuln.get("database_specific") or {}).get("severity")
    return str(sev).upper() if sev else "UNKNOWN"


# ---------- content rules shared by hook and scanner ----------

SECRET_PATTERNS = [
    ("AWS access key", re.compile(r"\b(AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("GitHub token", re.compile(r"\b(ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,}\b|\bgithub_pat_[A-Za-z0-9_]{60,}\b")),
    ("Anthropic API key", re.compile(r"\bsk-ant-[A-Za-z0-9_\-]{20,}")),
    ("OpenAI API key", re.compile(r"\bsk-(proj-)?[A-Za-z0-9_\-]{32,}")),
    ("Google API key", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b")),
    ("Slack token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}")),
    ("npm token", re.compile(r"\bnpm_[A-Za-z0-9]{36}\b")),
    ("Private key", re.compile(r"-----BEGIN (RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----")),
    ("GCP service account key", re.compile(r'"type"\s*:\s*"service_account"[\s\S]{0,400}"private_key"')),
]

UNTRUSTED_CTX = re.compile(
    r"\$\{\{\s*(github\.event\.(issue|pull_request|comment|review|review_comment|discussion|pages|head_commit|commits|workflow_run)"
    r"[\w.\[\]*]*\.(title|body|message|name|email|label|ref|head_ref|default_branch|page_name)"
    r"|github\.head_ref)\s*\}\}")
USES_RE = re.compile(r"^\s*-?\s*uses:\s*['\"]?([^'\"\s#]+)['\"]?", re.M)
SHA_RE = re.compile(r"@[0-9a-f]{40}$")
PIPE_SHELL_RE = re.compile(r"(curl|wget|iwr|invoke-webrequest)\b[^|\n]*\|\s*(sudo\s+)?(ba|z|k|da)?sh\b|"
                           r"(curl|wget)\b[^|\n]*\|\s*(sudo\s+)?(python3?|node|perl|ruby|iex)\b", re.I)


def find_secrets(text: str) -> list[str]:
    return [label for label, rx in SECRET_PATTERNS if rx.search(text)]


def audit_workflow(text: str) -> list[dict]:
    """Return findings for a GitHub Actions workflow body. severity: deny|ask."""
    f: list[dict] = []
    iocs = load_iocs()
    if re.search(r"^\s*pull_request_target\s*:|on:\s*\[?[^\n]*pull_request_target", text, re.M):
        if re.search(r"github\.event\.pull_request\.head\.(sha|ref)|github\.head_ref|refs/pull/", text):
            f.append({"sev": "deny", "rule": "GHA-PRT-CHECKOUT",
                      "msg": "pull_request_target workflow checks out untrusted PR code (privileged context + attacker code = repo takeover)."})
        else:
            f.append({"sev": "ask", "rule": "GHA-PRT",
                      "msg": "pull_request_target runs with secrets/write token; confirm it never runs PR-supplied code."})
    for m in UNTRUSTED_CTX.finditer(text):
        f.append({"sev": "deny", "rule": "GHA-INJECTION",
                  "msg": f"Untrusted context {m.group(0)} interpolated into workflow; pass it via env: and quote it instead."})
        break
    unpinned = sorted({u for u in USES_RE.findall(text)
                       if not u.startswith("./") and not u.startswith("docker://") and not SHA_RE.search(u)})
    if unpinned:
        f.append({"sev": "ask", "rule": "GHA-UNPINNED",
                  "msg": "Actions not pinned to a full commit SHA: " + ", ".join(unpinned[:8]), "actions": unpinned})
    if re.search(r"permissions:\s*write-all", text):
        f.append({"sev": "ask", "rule": "GHA-WRITE-ALL", "msg": "permissions: write-all grants every scope to GITHUB_TOKEN."})
    if not re.search(r"^permissions:", text, re.M):
        f.append({"sev": "ask", "rule": "GHA-NO-PERMS",
                  "msg": "No top-level permissions block; GITHUB_TOKEN may default to broad write access."})
    if PIPE_SHELL_RE.search(text):
        f.append({"sev": "deny", "rule": "GHA-PIPE-SHELL", "msg": "Workflow pipes a remote download straight into a shell/interpreter."})
    if re.search(r"(toJSON\(\s*secrets\s*\)|\$\{\{\s*secrets\.[A-Z0-9_]+\s*\}\}[^\n]*(curl|wget|nc |base64))", text):
        f.append({"sev": "deny", "rule": "GHA-SECRET-EXFIL", "msg": "Workflow serialises or ships secrets to a network/encoding command."})
    for s in iocs.get("workflow_strings", []):
        if s["value"] in text:
            f.append({"sev": "deny", "rule": "IOC", "msg": f"Known campaign indicator ({s['campaign']}): {s['value']}"})
    return f
