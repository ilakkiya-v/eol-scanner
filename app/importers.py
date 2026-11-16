"""Import results from other scanners so everything lands in one report with containment advice.

Supported (auto-detected from the file content):
  * OWASP ZAP  - JSON ("Traditional JSON") or XML report
  * Burp Suite - "Report selected issues" / issues XML export
  * Semgrep    - `semgrep --json`
  * SARIF 2.1  - CodeQL, Semgrep --sarif, Snyk Code, Checkmarx, SonarQube, ESLint, Bandit, ... (anything that writes SARIF)
  * Nuclei     - `nuclei -jsonl` (one JSON object per line) or `-json-export` (JSON array)

Import files are parsed as data only. XML with entity declarations is rejected (no XXE / entity-expansion).
"""
from __future__ import annotations

import json
import re
import uuid
import xml.etree.ElementTree as ET
from typing import Any, Optional

from bs4 import BeautifulSoup


class ImportError_(ValueError):
    pass


# CWE id -> containment KB key (see advisor/mitigations.py)
CWE_KB = {
    89: "sql-injection", 564: "sql-injection", 943: "sql-injection", 90: "sql-injection",
    77: "command-injection", 78: "command-injection", 88: "command-injection",
    79: "xss", 80: "xss", 83: "xss", 87: "xss",
    22: "path-traversal", 23: "path-traversal", 36: "path-traversal", 73: "path-traversal", 98: "path-traversal",
    918: "ssrf", 611: "xxe", 776: "xxe", 601: "open-redirect",
    94: "code-injection", 95: "code-injection", 917: "code-injection", 1336: "code-injection",
    502: "deserialization",
    798: "secrets", 259: "secrets", 321: "secrets", 312: "secrets", 532: "secrets",
    326: "weak-crypto", 327: "weak-crypto", 328: "weak-crypto", 330: "weak-crypto", 338: "weak-crypto", 295: "weak-crypto", 916: "weak-crypto",
    693: "security-headers", 1021: "security-headers", 16: "security-headers", 525: "security-headers",
    614: "cookie-flags", 1004: "cookie-flags", 1275: "cookie-flags",
    942: "cors", 346: "cors",
    319: "cleartext-login", 523: "cleartext-login",
    200: "header-disclosure", 209: "debug-endpoint", 497: "header-disclosure", 215: "debug-endpoint", 489: "debug-endpoint",
    548: "directory-listing", 538: "exposed-files", 530: "exposed-files", 527: "exposed-vcs",
    1104: "eol", 937: "eol", 1035: "eol", 1395: "eol",
}

# Keyword fallback when a tool gives no CWE
KEYWORD_KB = [
    (r"sql\s*injection|sqli\b", "sql-injection"), (r"command injection|os command|rce\b|remote code", "command-injection"),
    (r"cross[- ]site scripting|\bxss\b", "xss"), (r"path traversal|directory traversal|file inclusion|\blfi\b|\brfi\b", "path-traversal"),
    (r"server[- ]side request forgery|\bssrf\b", "ssrf"), (r"\bxxe\b|xml external entit", "xxe"), (r"open redirect", "open-redirect"),
    (r"deserializ", "deserialization"), (r"content[- ]security[- ]policy|x-frame-options|clickjack|strict-transport|hsts|x-content-type", "security-headers"),
    (r"cookie.*(?:httponly|secure|samesite)|(?:httponly|secure|samesite).*cookie", "cookie-flags"), (r"\bcors\b|cross-origin resource", "cors"),
    (r"directory (?:listing|browsing)", "directory-listing"), (r"vulnerable (?:js|javascript) librar|outdated|end[- ]of[- ]life|unsupported version", "eol"),
    (r"hard-?coded|secret|password in|api key", "secrets"), (r"weak (?:cipher|hash|crypto)|tls 1\.[01]|sslv", "weak-crypto"),
    (r"template injection|ssti|expression language|ognl", "code-injection"), (r"information disclosure|version disclosure|server leaks", "header-disclosure"),
]

SEV_WORDS = {"critical": "critical", "high": "high", "medium": "medium", "moderate": "medium", "low": "low",
             "info": "info", "information": "info", "informational": "info", "note": "low", "warning": "medium",
             "error": "high", "unknown": "info", "none": "info"}


def _text(html: Optional[str], limit: int = 1500) -> str:
    if not html:
        return ""
    t = BeautifulSoup(str(html), "html.parser").get_text(" ", strip=True) if "<" in str(html) else str(html)
    t = re.sub(r"\s+", " ", t).strip()
    return t[:limit] + ("…" if len(t) > limit else "")


def _cwes(*vals: Any) -> list[int]:
    out: list[int] = []
    for v in vals:
        if v is None:
            continue
        for m in re.finditer(r"(?i)cwe[-_/ ]?0*(\d{1,4})|^0*(\d{1,4})$", str(v) if not isinstance(v, (list, tuple)) else " ".join(map(str, v))):
            n = int(m.group(1) or m.group(2))
            if n > 0 and n not in out:
                out.append(n)
    return out


def _kb_for(title: str, cwes: list[int], default: str = "imported") -> str:
    for c in cwes:
        if c in CWE_KB:
            return CWE_KB[c]
    t = title.lower()
    for rx, kb in KEYWORD_KB:
        if re.search(rx, t):
            return kb
    return default


def _finding(tool: str, title: str, severity: str, cwes: list[int], location: str, *, category: str,
             locations: Optional[list[dict]] = None, evidence: str = "", detail: str = "", solution: str = "",
             references: Optional[list[str]] = None, confidence: Optional[str] = None, rule: Optional[str] = None) -> dict:
    kb = _kb_for(title + " " + detail[:200], cwes)
    if kb == "eol":  # tool-reported outdated component: generic containment
        kb = "imported"
    f = {"id": uuid.uuid4().hex[:12], "category": category, "severity": SEV_WORDS.get(str(severity).lower(), "info"),
         "title": f"{title}", "kb": kb, "location": location, "evidence": evidence[:1500], "detail": detail,
         "source_tool": tool, "cwe": [f"CWE-{c}" for c in cwes][:5]}
    if locations:
        f["locations"] = locations[:50]
    if solution:
        f["tool_solution"] = solution
    if references:
        f["references"] = [r for r in references if r][:8]
    if confidence:
        f["confidence"] = confidence
    if rule:
        f["rule"] = rule
    return f


# ---------------------------------------------------------------- ZAP
_ZAP_RISK = {"3": "high", "2": "medium", "1": "low", "0": "info"}
_ZAP_CONF = {"3": "high", "4": "high", "2": "medium", "1": "low", "0": "low"}


def _zap_alert(site: str, a: dict, instances: list[dict]) -> dict:
    locs = [{"path": i.get("uri", ""), "line": i.get("method", ""), "code": " ".join(x for x in (
        f"param={i['param']}" if i.get("param") else "", f"evidence={i['evidence'][:120]}" if i.get("evidence") else "") if x)}
        for i in instances]
    title = a.get("alert") or a.get("name") or "ZAP alert"
    refs = [r for r in re.split(r"\s+|<p>|</p>", a.get("reference") or "") if r.startswith("http")]
    return _finding("OWASP ZAP", title, _ZAP_RISK.get(str(a.get("riskcode")), "info"), _cwes(a.get("cweid")),
                    (instances[0].get("uri") if instances else site) + (f" (+{len(instances) - 1} more)" if len(instances) > 1 else ""),
                    category="web-app", locations=locs, evidence=(instances[0].get("evidence") or "") if instances else "",
                    detail=_text(a.get("desc")) + (f" {_text(a.get('otherinfo'), 400)}" if a.get("otherinfo") else ""),
                    solution=_text(a.get("solution")), references=refs, confidence=_ZAP_CONF.get(str(a.get("confidence"))),
                    rule=f"zap-{a.get('pluginid', '')}")


def parse_zap_json(d: dict) -> list[dict]:
    out = []
    for site in d.get("site") or []:
        for a in site.get("alerts") or []:
            out.append(_zap_alert(site.get("@name", ""), a, a.get("instances") or []))
    return out


def parse_zap_xml(root: ET.Element) -> list[dict]:
    out = []
    for site in root.iter("site"):
        for item in site.iter("alertitem"):
            a = {c.tag: (c.text or "") for c in item if c.tag != "instances"}
            inst = [{c.tag: (c.text or "") for c in i} for i in item.iter("instance")]
            out.append(_zap_alert(site.get("name", ""), a, inst))
    return out


# ---------------------------------------------------------------- Burp
def parse_burp_xml(root: ET.Element) -> list[dict]:
    groups: dict[str, dict] = {}
    for issue in root.iter("issue"):
        g = lambda t: (issue.findtext(t) or "").strip()  # noqa: E731
        name = g("name") or "Burp issue"
        host = g("host")
        url = host.rstrip("/") + (g("path") or "")
        key = name
        cls = g("vulnerabilityClassifications")
        f = groups.get(key)
        loc = {"path": url, "line": g("confidence"), "code": _text(g("location"), 200)}
        if f:
            f["locations"].append(loc)
            continue
        refs = re.findall(r'href="(https?://[^"]+)"', g("references") + cls)
        groups[key] = _finding("Burp Suite", name, g("severity"), _cwes(*re.findall(r"CWE-\d+", cls)), url, category="web-app",
                               locations=[loc], evidence=_text(g("issueDetail"), 800),
                               detail=_text(g("issueBackground")), solution=_text(g("remediationDetail") or g("remediationBackground")),
                               references=refs, confidence=g("confidence").lower() or None, rule=f"burp-{g('type')}")
    for f in groups.values():
        n = len(f["locations"])
        if n > 1:
            f["location"] += f" (+{n - 1} more)"
    return list(groups.values())


# ---------------------------------------------------------------- Semgrep
def parse_semgrep(d: dict) -> list[dict]:
    groups: dict[str, dict] = {}
    for r in d.get("results") or []:
        ex = r.get("extra") or {}
        md = ex.get("metadata") or {}
        rid = r.get("check_id", "semgrep")
        loc = {"path": r.get("path", ""), "line": (r.get("start") or {}).get("line", ""), "code": (ex.get("lines") or "").strip()[:240]}
        if rid in groups:
            groups[rid]["locations"].append(loc)
            continue
        title = (ex.get("message") or rid).split("\n")[0][:160]
        refs = md.get("references") or []
        groups[rid] = _finding("Semgrep", title, ex.get("severity", "info"), _cwes(md.get("cwe")), f"{loc['path']}:{loc['line']}",
                               category="code", locations=[loc], evidence=loc["code"], detail=_text(ex.get("message"), 800),
                               references=refs if isinstance(refs, list) else [refs],
                               confidence=str(md.get("confidence", "")).lower() or None, rule=rid)
    return _plus_more(groups)


# ---------------------------------------------------------------- SARIF
def _sec_sev(props: dict, level: str) -> str:
    try:
        v = float(props.get("security-severity"))
        return "critical" if v >= 9 else "high" if v >= 7 else "medium" if v >= 4 else "low" if v > 0 else "info"
    except (TypeError, ValueError):
        return SEV_WORDS.get((level or "warning").lower(), "medium")


def parse_sarif(d: dict) -> list[dict]:
    groups: dict[str, dict] = {}
    for run in d.get("runs") or []:
        driver = ((run.get("tool") or {}).get("driver") or {})
        tool = driver.get("name") or "SARIF"
        rules = {r.get("id"): r for r in driver.get("rules") or []}
        for ext in (run.get("tool") or {}).get("extensions") or []:
            rules.update({r.get("id"): r for r in ext.get("rules") or []})
        rule_list = driver.get("rules") or []
        for res in run.get("results") or []:
            rid = res.get("ruleId") or (rule_list[res["ruleIndex"]]["id"] if isinstance(res.get("ruleIndex"), int) and res["ruleIndex"] < len(rule_list) else "rule")
            rule = rules.get(rid, {})
            props = {**(rule.get("properties") or {}), **(res.get("properties") or {})}
            pl = ((res.get("locations") or [{}])[0].get("physicalLocation") or {})
            path = (pl.get("artifactLocation") or {}).get("uri", "")
            region = pl.get("region") or {}
            loc = {"path": path, "line": region.get("startLine", ""), "code": ((region.get("snippet") or {}).get("text") or "").strip()[:240]}
            key = f"{tool}:{rid}"
            if key in groups:
                groups[key]["locations"].append(loc)
                continue
            title = ((rule.get("shortDescription") or {}).get("text") or (res.get("message") or {}).get("text") or rid).split("\n")[0][:160]
            level = res.get("level") or (rule.get("defaultConfiguration") or {}).get("level") or "warning"
            groups[key] = _finding(tool, title, _sec_sev(props, level), _cwes(props.get("tags"), props.get("cwe")),
                                   f"{path}:{loc['line']}", category="code", locations=[loc], evidence=loc["code"],
                                   detail=_text((res.get("message") or {}).get("text") or (rule.get("fullDescription") or {}).get("text"), 800),
                                   solution=_text((rule.get("help") or {}).get("text"), 800),
                                   references=[rule["helpUri"]] if rule.get("helpUri") else None,
                                   confidence=str(props.get("precision", "")).lower() or None, rule=rid)
    return _plus_more(groups)


# ---------------------------------------------------------------- Nuclei
def parse_nuclei(items: list[dict]) -> list[dict]:
    groups: dict[str, dict] = {}
    for it in items:
        info = it.get("info") or {}
        tid = it.get("template-id") or it.get("templateID") or "nuclei"
        loc = {"path": it.get("matched-at") or it.get("matched") or it.get("host", ""), "line": it.get("matcher-name", ""),
               "code": ", ".join(map(str, it.get("extracted-results") or []))[:240]}
        if tid in groups:
            groups[tid]["locations"].append(loc)
            continue
        cls = info.get("classification") or {}
        cves = cls.get("cve-id") or []
        cves = cves if isinstance(cves, list) else [cves]
        name = info.get("name") or tid
        title = name + (f" ({', '.join(c.upper() for c in cves[:3] if c)})" if cves and cves[0] else "")
        refs = info.get("reference") or []
        groups[tid] = _finding("Nuclei", title, info.get("severity", "info"), _cwes(cls.get("cwe-id")), loc["path"],
                               category="web-app", locations=[loc], evidence=loc["code"], detail=_text(info.get("description"), 800),
                               solution=_text(info.get("remediation"), 600), references=refs if isinstance(refs, list) else [refs],
                               rule=f"nuclei-{tid}")
    return _plus_more(groups)


def _plus_more(groups: dict[str, dict]) -> list[dict]:
    for f in groups.values():
        n = len(f.get("locations") or [])
        if n > 1:
            f["location"] += f" (+{n - 1} more)"
    return list(groups.values())


# ---------------------------------------------------------------- detection
def parse(data: bytes, filename: str = "") -> tuple[str, list[dict]]:
    """Detect the format and return (tool, findings)."""
    text = data.decode("utf-8-sig", "replace").strip()
    if not text:
        raise ImportError_("the file is empty")
    if text.startswith("<"):
        head = text[:4000]
        if re.search(r"<!ENTITY", text, re.I):
            raise ImportError_("XML with entity declarations is not accepted")
        try:
            root = ET.fromstring(text)
        except ET.ParseError as e:
            raise ImportError_(f"not valid XML: {e}") from e
        if root.tag == "OWASPZAPReport" or "OWASPZAPReport" in head:
            return "OWASP ZAP", parse_zap_xml(root)
        if root.tag == "issues" or root.find(".//issue/serialNumber") is not None:
            return "Burp Suite", parse_burp_xml(root)
        raise ImportError_("unrecognised XML report (supported: ZAP XML, Burp issues XML)")
    try:
        d = json.loads(text)
    except json.JSONDecodeError:
        lines = [ln for ln in text.splitlines() if ln.strip()]
        try:
            items = [json.loads(ln) for ln in lines]
        except json.JSONDecodeError as e:
            raise ImportError_(f"not valid JSON / JSON lines: {e}") from e
        if items and isinstance(items[0], dict) and ("template-id" in items[0] or "templateID" in items[0]):
            return "Nuclei", parse_nuclei(items)
        raise ImportError_("unrecognised JSON-lines file (supported: Nuclei -jsonl)")
    if isinstance(d, list):
        if d and isinstance(d[0], dict) and ("template-id" in d[0] or "templateID" in d[0]):
            return "Nuclei", parse_nuclei(d)
        if not d:
            return "Nuclei", []
        raise ImportError_("unrecognised JSON array")
    if isinstance(d, dict):
        if "runs" in d and ("$schema" in d and "sarif" in str(d["$schema"]).lower() or str(d.get("version", "")).startswith("2.")):
            names = sorted({((r.get("tool") or {}).get("driver") or {}).get("name") or "SARIF" for r in d.get("runs") or []})
            return f"{', '.join(names) or 'SARIF'} (SARIF)", parse_sarif(d)
        if "site" in d and ("@programName" in d or "@version" in d or isinstance(d.get("site"), list)):
            return "OWASP ZAP", parse_zap_json(d)
        if "results" in d and ("errors" in d or "paths" in d or "version" in d):
            return "Semgrep", parse_semgrep(d)
    raise ImportError_("unrecognised report format (supported: ZAP JSON/XML, Burp XML, Semgrep JSON, SARIF, Nuclei JSON/JSONL)")
