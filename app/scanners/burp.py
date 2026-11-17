"""Burp Suite Professional connection (optional).

Two independent ways to use a Burp licence with this scanner:

1. Proxy: the scanner's own crawl (and the headless browser) is sent through Burp's proxy listener, so every page,
   script and API call lands in Burp's HTTP history and site map, ready for Repeater / Intruder / manual testing.
2. Burp scan via the REST API: after the crawl, the scanner asks Burp to run its own crawl + audit of the same target,
   limited to that target's origin, then imports Burp's issues as findings next to the EOL and code results.
   Enable it in Burp: Settings -> Suite -> REST API -> "Service running" (default http://127.0.0.1:1337).
   If you create an API key there, put it in the BURP_API_KEY environment variable before starting the scanner
   (it is never stored by this app).

Only Burp Suite Professional has this REST API (Burp Suite Enterprise / DAST uses a different API).
Scope: the target is checked against this app's allowlist before Burp is asked to scan it, and Burp's scope is set to
that origin only. Logout-like URLs seen by the crawl are excluded from Burp's scope.
"""
from __future__ import annotations

import base64
import os
import re
import time
from typing import Callable, Optional
from urllib.parse import urlsplit

import httpx

from .. import scope
from ..importers import _cwes, _finding, _text

# Burp's built-in scan configuration names (Burp Pro "Use a preset scan mode" / configuration library).
DEFAULT_CONFIGS = {
    "passive": ["Crawl strategy - faster", "Audit checks - passive"],
    "safe": ["Crawl strategy - faster", "Audit checks - light active"],
    "active": ["Crawl strategy - more complete", "Audit checks - all except time-based detection methods"],
}
SEV = {"high": "high", "medium": "medium", "low": "low", "info": "info", "information": "info"}
_SECRET_HEADER = re.compile(r"^((?:cookie|set-cookie|authorization|proxy-authorization|x-api-key|x-auth-token)\s*:).*$", re.I | re.M)


class BurpError(RuntimeError):
    pass


def _base(cfg: dict) -> str:
    url = (cfg.get("api_url") or "http://127.0.0.1:1337").rstrip("/")
    key = os.environ.get("BURP_API_KEY", "").strip()
    return f"{url}/{key}/v0.1" if key else f"{url}/v0.1"


def _client(timeout: float = 20) -> httpx.Client:
    # trust_env=False: Burp's API is local; a corporate proxy must not be used to reach it.
    return httpx.Client(timeout=timeout, trust_env=False)


def _err(e: Exception, cfg: dict) -> BurpError:
    return BurpError(f"cannot reach the Burp REST API at {cfg.get('api_url') or 'http://127.0.0.1:1337'} ({type(e).__name__}). "
                     "In Burp Suite Professional: Settings -> Suite -> REST API -> tick 'Service running'.")


def test(cfg: dict) -> dict:
    """Check that the Burp REST API answers (lists Burp's issue definitions; starts nothing)."""
    t = time.time()
    try:
        with _client(10) as c:
            r = c.get(_base(cfg) + "/knowledge_base/issue_definitions")
    except httpx.HTTPError as e:
        return {"ok": False, "error": str(_err(e, cfg))}
    if r.status_code == 401:
        return {"ok": False, "error": "Burp asks for an API key: set BURP_API_KEY in the scanner's environment and restart it."}
    if r.status_code != 200:
        return {"ok": False, "error": f"Burp answered HTTP {r.status_code}: {r.text[:200]}"}
    try:
        n = len(r.json())
    except ValueError:
        n = 0
    return {"ok": True, "issue_definitions": n, "seconds": round(time.time() - t, 1), "key_set": bool(os.environ.get("BURP_API_KEY"))}


def scan_request(target: str, mode: str, cfg: dict, exclude: Optional[list[str]] = None) -> dict:
    p = urlsplit(target)
    origin = f"{p.scheme}://{p.netloc}/"
    names = (cfg.get("scan_configs") or {}).get(mode) or DEFAULT_CONFIGS.get(mode) or DEFAULT_CONFIGS["safe"]
    body = {"urls": [target],
            "scope": {"type": "SimpleScope", "include": [{"rule": origin, "type": "SimpleScopeDef"}],
                      "exclude": [{"rule": u, "type": "SimpleScopeDef"} for u in (exclude or [])[:50]]},
            "scan_configurations": [{"type": "NamedConfiguration", "name": n} for n in names]}
    if cfg.get("resource_pool"):
        body["resource_pool"] = cfg["resource_pool"]
    return body


def start(target: str, mode: str, cfg: dict, rules: Optional[dict] = None, exclude: Optional[list[str]] = None) -> str:
    scope.check(target, rules)  # never ask Burp to scan anything outside this app's allowlist
    try:
        with _client() as c:
            r = c.post(_base(cfg) + "/scan", json=scan_request(target, mode, cfg, exclude))
    except httpx.HTTPError as e:
        raise _err(e, cfg) from e
    if r.status_code != 201 or not r.headers.get("location"):
        hint = " Check the scan configuration names in Settings -> Burp Suite (they must exist in Burp's configuration library)." \
            if r.status_code == 400 else ""
        raise BurpError(f"Burp did not start the scan (HTTP {r.status_code}): {r.text[:300]}{hint}")
    return r.headers["location"].rstrip("/").split("/")[-1]


def get(task_id: str, cfg: dict) -> dict:
    try:
        with _client() as c:
            r = c.get(f"{_base(cfg)}/scan/{task_id}")
    except httpx.HTTPError as e:
        raise _err(e, cfg) from e
    if r.status_code != 200:
        raise BurpError(f"Burp task {task_id}: HTTP {r.status_code} {r.text[:200]}")
    return r.json()


def _segments(segs) -> str:
    """Burp returns request/response as segments; data is base64 in most versions."""
    out = []
    for s in segs or []:
        data = s.get("data", "") if isinstance(s, dict) else str(s)
        try:
            out.append(base64.b64decode(data, validate=True).decode("utf-8", "ignore"))
        except (ValueError, TypeError):
            out.append(str(data))
    return "".join(out)


def _evidence(issue: dict) -> str:
    parts = []
    for ev in (issue.get("evidence") or [])[:2]:
        rr = ev.get("request_response") or {}
        req = _segments(rr.get("request"))
        if req:
            head = req.split("\r\n\r\n", 1)[0].split("\n\n", 1)[0]
            parts.append(_SECRET_HEADER.sub(r"\1 <redacted>", head)[:900])
        if ev.get("detail"):
            parts.append(_text(ev.get("detail"), 300))
    return "\n---\n".join(parts)


def issues_to_findings(data: dict, origin_hint: str = "") -> list[dict]:
    groups: dict[str, dict] = {}
    for ev in data.get("issue_events") or []:
        issue = ev.get("issue") or {}
        name = issue.get("name") or "Burp issue"
        url = (issue.get("origin") or origin_hint).rstrip("/") + (issue.get("path") or "")
        loc = {"path": url, "line": issue.get("confidence", ""), "code": _text(issue.get("caption"), 160)}
        f = groups.get(name)
        if f:
            if all(l["path"] != url for l in f["locations"]):
                f["locations"].append(loc)
            continue
        refs = re.findall(r'href="(https?://[^"]+)"', (issue.get("references") or "") + (issue.get("vulnerability_classifications") or ""))
        cw = _cwes(*re.findall(r"CWE-\d+", issue.get("vulnerability_classifications") or ""))
        groups[name] = _finding("Burp Suite (live scan)", name, SEV.get(str(issue.get("severity")).lower(), "info"), cw, url,
                                category="web-app", locations=[loc], evidence=_evidence(issue),
                                detail=_text(issue.get("description") or issue.get("issue_background")),
                                solution=_text(issue.get("remediation") or issue.get("remediation_background")),
                                references=refs, confidence=(issue.get("confidence") or "").lower() or None,
                                rule=f"burp-{issue.get('type_index', '')}")
    for f in groups.values():
        n = len(f["locations"])
        if n > 1:
            f["location"] += f" (+{n - 1} more)"
    return list(groups.values())


def run(target: str, mode: str, cfg: dict, rules: dict, log: Callable[[str], None],
        progress: Callable[[float, str], None], cancelled: Callable[[], bool], exclude: Optional[list[str]] = None) -> dict:
    """Start a Burp scan, wait for it, and return {task_id, status, findings, metrics}."""
    task = start(target, mode, cfg, rules, exclude)
    names = (cfg.get("scan_configs") or {}).get(mode) or DEFAULT_CONFIGS.get(mode)
    log(f"Burp scan started (task {task}; configurations: {', '.join(names or [])})")
    deadline = time.time() + float(cfg.get("max_minutes", 120)) * 60
    data: dict = {}
    last_note = ""
    while True:
        if cancelled():
            log(f"stopped waiting for Burp; task {task} keeps running in Burp (stop it in Burp's Dashboard if needed)")
            break
        try:
            data = get(task, cfg)
        except BurpError as e:
            log(f"Burp: {e}")
            time.sleep(10)
            if time.time() > deadline:
                break
            continue
        st = data.get("scan_status", "?")
        m = data.get("scan_metrics") or {}
        pct = float(m.get("crawl_and_audit_progress") or 0)
        note = (f"Burp {st}: {pct:.0f}% · {m.get('crawl_requests_made', 0)} crawl / {m.get('audit_requests_made', 0)} audit "
                f"requests · {len(data.get('issue_events') or [])} issues")
        progress(pct / 100, note)
        if note != last_note and int(time.time()) % 60 < 6:
            log(note)
        last_note = note
        if st in ("succeeded", "failed"):
            log(f"Burp scan {st}")
            break
        if time.time() > deadline:
            log(f"Burp scan still {st} after {cfg.get('max_minutes', 120)} min; importing what it found so far "
                f"(the task keeps running in Burp)")
            break
        time.sleep(5)
    findings = issues_to_findings(data, f"{urlsplit(target).scheme}://{urlsplit(target).netloc}")
    return {"task_id": task, "status": data.get("scan_status"), "findings": findings, "metrics": data.get("scan_metrics") or {}}
