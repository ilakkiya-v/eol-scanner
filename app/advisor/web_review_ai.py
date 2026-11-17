"""AI web review: Claude works through what the crawl saw, like a pentester reviewing a proxy history.

Input is the scan's snapshot folder (crawled pages, same-origin scripts, robots/API documents, saved with cookie and
authorization values redacted) plus three files written here:
  context.md   target, technologies and their lifecycle / CVE status, scan settings
  endpoints.json  every endpoint the crawl found (method, URL, parameter names, where it was seen, status)
  leads.json   the scanner's own findings, numbered W1..Wn, for the AI to confirm or reject

Engines (same as the code review):
  * Claude API family: tool loop with read-only file tools over that folder, plus `http_get` for a limited number of
    live, in-scope GET requests (only for scans run in Safe or Active mode; every request is scope-checked and logged).
  * Claude Code: runs in the folder with only Read / Grep / Glob, no network.

Output: findings with URL, method, parameter, evidence, a manual check (benign probe; see MANUAL_CHECK_RULES), and
containment; verdicts on the leads; and a summary that includes where each end-of-life component is exposed.
"""
from __future__ import annotations

import json
import re
import time
from pathlib import Path
from typing import Callable, Optional
from urllib.parse import urlsplit

import httpx

from .. import db, scope
from ..config import USER_AGENT
from ..importers import _cwes, _kb_for
from .code_review_ai import MANUAL_CHECK_RULES, SourceTree, _parse_json_block, manual_check, tool_loop
from .llm import LLMUnavailable, PLATFORMS, model_for

SYSTEM = (
    "You are a senior web application penetration tester on an authorized assessment of an internal lab/QA "
    "application for the company's security team. The application runs end-of-life components and its code will not "
    "be changed, so the team needs: which weaknesses are real and reachable, how a tester confirms each by hand, and how "
    "to contain it at the infrastructure level (WAF / reverse-proxy rules, network restrictions, configuration, "
    "monitoring). Base every statement on evidence in the files (quote the file and the relevant line or header). "
    "Separate what the evidence shows from what still needs a manual test. " + MANUAL_CHECK_RULES
)

TASK = """Review the crawl results of {target} in the working folder.

Files:
- context.md: technologies found, their end-of-life status and known CVE counts, scan settings.
- endpoints.json: every endpoint the crawl found (method, url, params, sources, status, title, login/upload flags).
- leads.json: the scanner's own findings (ids W1..Wn) to confirm or reject.
- pages/*.txt, scripts/*.txt, api-docs/*.txt, robots/*.txt: saved responses (first line URL, then status and headers,
  then the body). Cookie and authorization values are redacted.

How to work:
1. Map the application: login and session handling, roles, sensitive functions (admin, upload, export, user
   management, payments, settings), and parameters that look like ids, file names, URLs, redirects, templates, sort or
   filter expressions, or serialized data.
2. Check each lead in leads.json and give a verdict.
3. Look for weaknesses the evidence supports: input reflected into pages or scripts, verbose errors and stack traces,
   candidate IDOR / missing access control (ids in URLs or APIs), open redirects, file and path parameters, URL
   parameters that the server may fetch (SSRF), state-changing POST forms without anti-CSRF tokens, tokens or session
   ids in URLs, secrets or internal hostnames in pages and scripts, debug or admin functions reachable without login,
   insecure API documentation, and outdated client libraries whose vulnerable functions are actually used on these
   pages.
4. For each end-of-life or vulnerable component in context.md: where it is exposed (URLs), and which of its known
   weaknesses are plausibly reachable here and how to check.
{live}
For every weakness report: title; severity (critical/high/medium/low/info); CWE id; URL; HTTP method; the parameter(s);
evidence (file name and the quoted line/header); why it matters; confidence (high = the evidence shows it, medium /
low = candidate that needs the manual check); a manual check (HTTP request template with a benign probe value in place,
what in the response confirms it, short Burp Repeater steps); and containment steps that need no code change.
Finish with an overall summary in markdown: the most important risks first, then a short prioritized manual test plan."""

LIVE_ON = """5. You may send up to {n} live GET requests with http_get to confirm reflection or response differences, using benign
   probe values only. Requests outside the allowlisted scope are refused.
"""

CC_OUTPUT = """
When you are done, reply with ONLY a JSON object in a ```json fenced block, with this shape:
{"findings": [{"title": "", "severity": "medium", "cwe": "CWE-79", "url": "https://host/path", "method": "GET",
  "params": ["q"], "evidence": "pages/0003.txt: <quoted line>", "description": "", "confidence": "medium",
  "manual_check": {"request": "GET /path?q=<probe> HTTP/1.1\\nHost: host", "probe": "benign value and why",
                   "expected": "what in the response confirms it", "steps": ["Burp Repeater step"]},
  "containment": ["step"]}],
 "verdicts": [{"lead_id": "W1", "verdict": "confirmed|likely false positive|needs manual check", "reason": ""}],
 "summary": "markdown summary"}"""

_FINDING_PROPS = {
    "title": {"type": "string"}, "severity": {"type": "string", "enum": ["critical", "high", "medium", "low", "info"]},
    "cwe": {"type": "string"}, "url": {"type": "string"}, "method": {"type": "string"},
    "params": {"type": "array", "items": {"type": "string"}},
    "evidence": {"type": "string", "description": "file name and quoted line/header that shows it"},
    "description": {"type": "string"}, "confidence": {"type": "string", "enum": ["high", "medium", "low"]},
    "manual_check": {"type": "object", "description": "Hand-run proof of concept for the lab, benign probes only.",
                     "properties": {"request": {"type": "string"}, "probe": {"type": "string"},
                                    "expected": {"type": "string"}, "steps": {"type": "array", "items": {"type": "string"}}}},
    "containment": {"type": "array", "items": {"type": "string"}},
}

TOOLS = [
    {"name": "list_files", "description": "List files in the crawl folder matching a glob (e.g. 'pages/*', '*.json').",
     "input_schema": {"type": "object", "properties": {"glob": {"type": "string"}}, "required": ["glob"]}},
    {"name": "read_file", "description": "Read part of a file with line numbers (max 400 lines per call).",
     "input_schema": {"type": "object", "properties": {"path": {"type": "string"}, "start_line": {"type": "integer"},
                                                     "end_line": {"type": "integer"}}, "required": ["path"]}},
    {"name": "search", "description": "Regex search (case-insensitive) across the saved responses. Optional glob filter.",
     "input_schema": {"type": "object", "properties": {"pattern": {"type": "string"}, "glob": {"type": "string"}},
                      "required": ["pattern"]}},
    {"name": "report_finding", "description": "Record one weakness. Call once per weakness.",
     "input_schema": {"type": "object", "properties": _FINDING_PROPS,
                      "required": ["title", "severity", "url", "description", "evidence", "manual_check", "containment"]}},
    {"name": "lead_verdict", "description": "Record your verdict on one lead from leads.json.",
     "input_schema": {"type": "object", "properties": {
         "lead_id": {"type": "string"},
         "verdict": {"type": "string", "enum": ["confirmed", "likely false positive", "needs manual check"]},
         "reason": {"type": "string"}}, "required": ["lead_id", "verdict", "reason"]}},
]
HTTP_GET = {"name": "http_get", "description": "Send one live GET request to an in-scope URL of the target (benign probe "
            "values only). Returns status, headers (secrets redacted) and up to 20 KB of the body.",
            "input_schema": {"type": "object", "properties": {"url": {"type": "string"}}, "required": ["url"]}}

_REDACT = re.compile(r"^(set-cookie|cookie|authorization|proxy-authorization|x-api-key|x-auth-token)$", re.I)


# ---------------------------------------------------------------- context files
def prepare(scan: dict, findings: list[dict]) -> tuple[Path, dict]:
    """Write context.md / endpoints.json / leads.json into the snapshot folder. Returns (folder, {lead_id: finding_id})."""
    s = scan.get("summary") or {}
    folder = Path(s.get("snapshot_dir") or "")
    if not s.get("snapshot_dir") or not folder.is_dir():
        raise LLMUnavailable("this scan has no saved crawl data (scans made before this feature, or deleted). Re-scan the target.")
    inv = s.get("inventory") or []
    nv = lambda i: i.get("vulns") if isinstance(i.get("vulns"), int) else len(i.get("vulns") or [])  # noqa: E731
    comp = [f"- {i.get('product')} {i.get('version') or '?'}: lifecycle {i.get('status')}"
            + (f", end of life {i.get('eol_date')}" if i.get("eol_date") else "") + (f", {nv(i)} known CVEs" if nv(i) else "")
            + (f" (seen at {', '.join((i.get('locations') or [])[:2])})" if i.get("locations") else "")
            for i in inv if i.get("status") in ("eol", "eol_soon") or nv(i)][:80]
    cves = []
    for f in findings:
        if f.get("vulns"):
            top = ", ".join(f"{(v.get('aliases') or [v['id']])[0]} ({v.get('severity')}): {v.get('summary', '')[:90]}"
                            for v in f["vulns"][:6])
            cves.append(f"- {f.get('product')} {f.get('version')}: {top}")
    opts = scan.get("options") or {}
    (folder / "context.md").write_text(
        f"# Target\n{scan['target']}\n\nScan mode: {scan.get('mode')}; pages crawled: {len(s.get('pages') or [])}; "
        f"endpoints: {len(s.get('endpoints') or [])}; authenticated crawl: "
        f"{'yes' if opts.get('cookies_set') or opts.get('auth_headers') else 'no'}\n\n"
        f"# End-of-life / vulnerable components\n" + ("\n".join(comp) or "none found") + "\n\n"
        f"# Known CVEs per component (top)\n" + ("\n".join(cves[:40]) or "none") + "\n\n"
        f"# All technologies seen\n" + ", ".join(sorted({f"{i.get('product')} {i.get('version') or ''}".strip() for i in inv}))[:4000]
        + "\n", encoding="utf-8")
    (folder / "endpoints.json").write_text(json.dumps(s.get("endpoints") or [], indent=1)[:3_000_000], encoding="utf-8")
    leads, out = {}, []
    order = ["critical", "high", "medium", "low", "info"]
    web = [f for f in findings if f.get("category") not in ("eol", "eol-soon", "vulnerable-component", "outdated", "version-unknown")]
    for n, f in enumerate(sorted(web, key=lambda f: order.index(f["severity"]))[:80], 1):
        lid = f"W{n}"
        leads[lid] = f["id"]
        ev = f.get("evidence")
        ev = ev if isinstance(ev, str) else json.dumps(ev)[:800]
        out.append({"id": lid, "severity": f["severity"], "title": f["title"], "location": f.get("location"),
                    "source": f.get("source_tool") or "EOL Scanner", "evidence": (ev or "")[:800]})
    (folder / "leads.json").write_text(json.dumps(out, indent=1), encoding="utf-8")
    return folder, leads


# ---------------------------------------------------------------- normalize
def to_finding(d: dict, label: str) -> Optional[dict]:
    if not isinstance(d, dict) or not d.get("title"):
        return None
    cw = _cwes(d.get("cwe"))
    sev = str(d.get("severity", "medium")).lower()
    sev = sev if sev in ("critical", "high", "medium", "low", "info") else "medium"
    url = str(d.get("url") or "")
    params = [str(x) for x in (d.get("params") or []) if x][:10]
    method = str(d.get("method") or "GET").upper()
    path = urlsplit(url).path or url
    f = {"category": "web-app", "severity": sev, "title": str(d["title"])[:200],
         "kb": _kb_for(str(d["title"]), cw, "imported"), "location": url, "source_tool": label,
         "evidence": str(d.get("evidence") or "")[:2000], "detail": str(d.get("description") or "")[:3000],
         "cwe": [f"CWE-{c}" for c in cw][:3], "confidence": d.get("confidence"),
         "entry_point": {"method": method, "path": path, "params": params, "how": "AI web review"},
         "ai_containment": [str(x) for x in (d.get("containment") or [])][:12]}
    mc = manual_check(d.get("manual_check"))
    if mc:
        f["manual_check"] = mc
    return f


# ---------------------------------------------------------------- live GET (API engine only)
class LiveGet:
    def __init__(self, scan: dict, rules: dict, log, limit: int):
        self.left, self.log, self.rules = limit, log, rules
        opts = scan.get("options") or {}
        self.verify = bool(opts.get("verify_tls"))
        self.target = scan["target"]

    def __call__(self, url: str) -> str:
        if self.left <= 0:
            return "live request budget used up; continue from the saved files"
        scope.check(url, self.rules)
        if urlsplit(url).netloc.lower() != urlsplit(self.target).netloc.lower():
            raise ValueError("only the scanned target's host may be requested")
        self.left -= 1
        self.log(f"live GET {url}")
        time.sleep(0.3)
        with httpx.Client(verify=self.verify, timeout=15, follow_redirects=False, headers={"User-Agent": USER_AGENT},
                          trust_env=False) as c:
            r = c.get(url)
        heads = "\n".join(f"{k}: {'<redacted>' if _REDACT.match(k) else v}" for k, v in r.headers.multi_items())
        return f"STATUS {r.status_code}\n{heads}\n\n{r.text[:20000]}"


# ---------------------------------------------------------------- engines
def _review_api(folder: Path, scan: dict, cfg: dict, log, cancelled) -> dict:
    review_cfg = db.get_setting("code_review")
    model = model_for(cfg)
    tree = SourceTree(folder)
    live_n = int(review_cfg.get("web_live_requests", 40)) if scan.get("mode") in ("safe", "active") else 0
    live = LiveGet(scan, db.get_setting("scope"), log, live_n) if live_n else None
    findings, verdicts = [], {}
    label = f"Claude AI web review ({model})"

    def handle(name: str, inp: dict) -> str:
        if name == "list_files":
            return tree.list_files(str(inp.get("glob") or "**/*"))
        if name == "read_file":
            return tree.read_file(str(inp.get("path", "")), inp.get("start_line") or 1, inp.get("end_line"))
        if name == "search":
            return tree.search(str(inp.get("pattern", "")), inp.get("glob"))
        if name == "http_get" and live:
            return live(str(inp.get("url", "")))
        if name == "report_finding":
            f = to_finding(inp, label)
            if not f:
                raise ValueError("title is required")
            findings.append(f)
            log(f"finding: [{f['severity']}] {f['title']} ({f['location']})")
            return "recorded"
        if name == "lead_verdict":
            verdicts[str(inp.get("lead_id"))] = {"verdict": inp.get("verdict"), "reason": inp.get("reason", "")}
            return "recorded"
        raise ValueError(f"unknown tool {name}")

    first = (TASK.format(target=scan["target"], live=LIVE_ON.format(n=live_n) if live else "")
             + "\n\nUse report_finding for each weakness and lead_verdict for each lead. Your final message (no tool calls) "
               "is the overall summary.")
    r = tool_loop(cfg, SYSTEM, first, TOOLS + ([HTTP_GET] if live else []), handle, log, cancelled,
                  int(review_cfg.get("max_turns", 60)), int(review_cfg.get("max_input_tokens", 4_000_000)))
    return {"findings": findings, "verdicts": verdicts, **r, "engine": PLATFORMS.get(cfg.get("platform"), {}).get("label")}


def _review_claude_code(folder: Path, scan: dict, cfg: dict, log, cancelled) -> dict:
    from .claude_code import ClaudeCodeError, run

    review_cfg = db.get_setting("code_review")
    prompt = SYSTEM + "\n\n" + TASK.format(target=scan["target"], live="") + CC_OUTPUT
    try:
        r = run(prompt, cfg, cwd=str(folder), tools=True, max_turns=int(review_cfg.get("max_turns", 60)),
                timeout=int(review_cfg.get("timeout_min", 45)) * 60, log=log, cancelled=cancelled)
    except ClaudeCodeError as e:
        raise LLMUnavailable(str(e)) from e
    data = _parse_json_block(r["text"])
    label = f"Claude Code web review ({r.get('model') or 'your default model'})"
    findings = [f for f in (to_finding(d, label) for d in data.get("findings") or []) if f]
    verdicts = {str(v.get("lead_id")): {"verdict": v.get("verdict"), "reason": v.get("reason", "")}
                for v in data.get("verdicts") or [] if isinstance(v, dict)}
    return {"findings": findings, "verdicts": verdicts, "summary": data.get("summary") or "", "model": r.get("model"),
            "turns": r.get("turns"), "cost_usd": r.get("cost_usd"), "engine": "Claude Code"}


def review(scan: dict, findings: list[dict], log: Callable[[str], None], cancelled: Callable[[], bool]) -> dict:
    cfg = db.get_setting("llm")
    if cfg.get("provider") != "anthropic":
        raise LLMUnavailable("AI web review needs a Claude connection (Settings -> AI assist). Ollama is not supported for this.")
    folder, leads = prepare(scan, findings)
    log(f"starting AI web review with {PLATFORMS.get(cfg.get('platform'), {}).get('label')}; {len(leads)} leads, "
        f"{len((scan.get('summary') or {}).get('endpoints') or [])} endpoints")
    engine = _review_claude_code if cfg.get("platform") == "claude_code" else _review_api
    res = engine(folder, scan, cfg, log, cancelled)
    res["verdicts"] = {leads[k]: v for k, v in res.get("verdicts", {}).items() if k in leads}
    return res
