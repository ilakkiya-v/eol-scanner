"""Export formats: JSON, CSV, Markdown, standalone HTML."""
from __future__ import annotations

import csv
import datetime as dt
import html
import io
import json

from .analysis import SEV_ORDER


def _sorted(findings):
    return sorted(findings, key=lambda f: (SEV_ORDER.index(f["severity"]), f.get("vuln_count", 0)), reverse=True)


def _ts(t):
    return dt.datetime.fromtimestamp(t).strftime("%Y-%m-%d %H:%M") if t else "-"


def to_json(scan: dict, findings: list[dict]) -> str:
    s = dict(scan)
    s.pop("log", None)
    return json.dumps({"scan": s, "findings": _sorted(findings)}, indent=2, default=str)


def to_csv(scan: dict, findings: list[dict]) -> str:
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["severity", "category", "title", "product", "version", "eol_date", "status", "cves", "location", "confidence",
                "source_tool", "cwe", "top_containment"])
    for f in _sorted(findings):
        lc = f.get("lifecycle") or {}
        cves = ";".join(((v.get("aliases") or [v["id"]])[0]) for v in f.get("vulns", [])[:20])
        w.writerow([f["severity"], f["category"], f["title"], f.get("product", ""), f.get("version", ""), lc.get("eol_date", ""),
                    lc.get("status", ""), cves, f.get("location", ""), f.get("confidence", ""),
                    f.get("source_tool", "EOL Scanner"), ";".join(f.get("cwe") or []), (f.get("containment") or [{}])[0].get("title", "")])
    return buf.getvalue()


def to_markdown(scan: dict, findings: list[dict]) -> str:
    s = scan.get("summary", {})
    c = s.get("severity_counts", {})
    lines = [f"# EOL assessment: {scan['target']}", "",
             f"- Scan: `{scan['id']}` ({scan['kind']}, mode `{scan.get('mode')}`)",
             f"- Operator: {scan.get('operator') or '-'}  Ticket/authorization: {scan.get('ticket') or '-'}",
             f"- Started: {_ts(scan.get('created'))}  Finished: {_ts(scan.get('finished'))}",
             f"- Findings: {s.get('findings', 0)} (critical {c.get('critical',0)}, high {c.get('high',0)}, medium {c.get('medium',0)}, low {c.get('low',0)}, info {c.get('info',0)})",
             f"- Components: {s.get('components', 0)}, EOL: {s.get('eol_components', 0)}, EOL soon: {s.get('eol_soon_components', 0)}"]
    if s.get("imports"):
        lines.append("- Imported: " + ", ".join(f"{i['tool']} ({i['count']} from {i['file']})" for i in s["imports"]))
    lines.append("")
    comp_cats = {"eol", "eol-soon", "vulnerable-component", "outdated", "version-unknown"}
    vulns = [f for f in findings if f.get("category") not in comp_cats]
    comps = [f for f in findings if f.get("category") in comp_cats]
    vuln_title = {"code": "Code vulnerabilities", "import": "Findings"}.get(scan.get("kind"), "Web findings")
    if s.get("ai_review"):
        lines += ["## AI review summary", "", s["ai_review"], ""]
    for title, group in ((vuln_title, vulns), ("End-of-life and vulnerable components", comps)):
        if not group:
            continue
        lines += [f"## {title} ({len(group)})", ""]
        for f in _sorted(group):
            lines += _md_finding(f)
    eps = s.get("endpoints") or []
    if eps:
        lines += [f"## Attack surface ({len(eps)} endpoints)", "", "| Method | URL | Parameters | Found via |", "|---|---|---|---|"]
        lines += [f"| {e['method']} | `{e['url']}` | {', '.join(e.get('params') or [])} | {', '.join(e.get('sources') or [])} |" for e in eps[:500]]
        lines.append("")
    return "\n".join(lines)


def _md_finding(f: dict) -> list[str]:
    lines = [f"### [{f['severity'].upper()}] {f['title']}", ""]
    if f.get("location"):
        lines.append(f"**Location:** `{f['location']}`  ")
    if f.get("source_tool") or f.get("cwe"):
        lines.append(f"**Source:** {f.get('source_tool', 'EOL Scanner')}" + (f"  **CWE:** {', '.join(f['cwe'])}" if f.get("cwe") else "") + "  ")
    if f.get("ai_verdict"):
        lines.append(f"**AI review verdict:** {f['ai_verdict'].get('verdict')} — {f['ai_verdict'].get('reason', '')}  ")
    if f.get("detail"):
        lines.append(f"**Details:** {f['detail']}  ")
    ep = f.get("entry_point") or {}
    if ep.get("path"):
        lines.append(f"**Reached via:** `{ep.get('method', 'GET')} {ep['path']}`" + (f" parameters: {', '.join(ep.get('params') or [])}" if ep.get("params") else "") + "  ")
    lc = f.get("lifecycle") or {}
    if lc.get("status"):
        lines.append(f"**Lifecycle:** {lc.get('status')} — cycle {lc.get('cycle') or '?'}, EOL {lc.get('eol_date') or lc.get('status')}, latest {lc.get('latest_version') or '-'}  ")
    if f.get("vulns"):
        lines.append(f"**Known vulnerabilities ({f.get('vuln_count')}):** " + ", ".join(
            f"{(v.get('aliases') or [v['id']])[0]} ({v['severity']})" for v in f["vulns"][:15]))
    mc = f.get("manual_check")
    if mc:
        lines += ["", "**Manual check (PoC, benign probe, authorized lab only):**"]
        if mc.get("request"):
            lines += ["```http", mc["request"], "```"]
        if mc.get("probe"):
            lines.append(f"- Probe: {mc['probe']}")
        if mc.get("expected"):
            lines.append(f"- Confirms it: {mc['expected']}")
        lines += [f"{i}. {t}" for i, t in enumerate(mc.get("steps") or [], 1)]
    elif f.get("verification_steps"):
        lines += ["", "**How to verify (AI review):**"] + [f"{i}. {t}" for i, t in enumerate(f["verification_steps"], 1)]
    if f.get("evidence"):
        ev = f["evidence"]
        if isinstance(ev, list):
            lines += ["", "**Evidence:**"] + [f"- `{e['location']}` — {e['text']}" for e in ev[:5]]
        else:
            lines += ["", "**Evidence:**", "```", str(ev)[:800], "```"]
    if f.get("ai_containment"):
        lines += ["", "**Containment (AI review):**"] + [f"- {t}" for t in f["ai_containment"]]
    if f.get("containment"):
        lines += ["", "**Containment:**"]
        for m in f["containment"]:
            lines.append(f"- **{m['title']}** — {m['detail']}")
            if m.get("snippet"):
                lines += ["  ```", *["  " + l for l in m["snippet"].splitlines()], "  ```"]
    if len(f.get("locations") or []) > 1:
        lines += ["", "**All locations:**"] + [f"- `{l.get('path')}:{l.get('line')}` {l.get('code', '')}" for l in f["locations"][:25]]
    if f.get("tool_solution"):
        lines += ["", f"**Fix suggested by {f.get('source_tool', 'the tool')} (needs a code change):** {f['tool_solution']}"]
    if f.get("review_steps"):
        lines += ["", "**Confirm in the code:**"] + [f"{i}. {t}" for i, t in enumerate(f["review_steps"], 1)]
    if f.get("manual_tests"):
        lines += ["", "**More checks (authorized lab only):**"] + [f"- {t}" for t in f["manual_tests"]]
    if f.get("extended_support"):
        lines += ["", f"**Extended support options:** {f['extended_support']}"]
    if f.get("ai_advice"):
        lines += ["", "**AI containment plan:**", "", f["ai_advice"]]
    lines.append("")
    return lines


def to_html(scan: dict, findings: list[dict]) -> str:
    md = to_markdown(scan, findings)
    e = html.escape
    sev_color = {"critical": "#b42318", "high": "#c4320a", "medium": "#b54708", "low": "#175cd3", "info": "#475467"}
    rows = []
    for f in _sorted(findings):
        lc = f.get("lifecycle") or {}
        rows.append(f"<tr><td><span class=s style='background:{sev_color[f['severity']]}'>{e(f['severity'])}</span></td>"
                    f"<td>{e(f['title'])}</td><td>{e(lc.get('eol_date') or '')}</td><td>{f.get('vuln_count', '')}</td>"
                    f"<td><code>{e(str(f.get('location', ''))[:90])}</code></td></tr>")
    return f"""<!doctype html><html><head><meta charset=utf-8><meta name=viewport content="width=device-width,initial-scale=1">
<title>EOL Report {e(scan['target'])}</title>
<style>body{{font:14px/1.5 system-ui,sans-serif;max-width:1100px;margin:24px auto;padding:0 16px;color:#101828}}
table{{border-collapse:collapse;width:100%}}td,th{{border-bottom:1px solid #eaecf0;padding:6px 8px;text-align:left;vertical-align:top}}
.s{{color:#fff;border-radius:4px;padding:1px 6px;font-size:12px;text-transform:uppercase}}pre{{background:#f2f4f7;padding:12px;white-space:pre-wrap;border-radius:6px}}
code{{font-size:12px}}</style></head><body>
<h1>EOL assessment report</h1><p><b>Target:</b> {e(scan['target'])} &nbsp; <b>Scan:</b> {e(scan['id'])} &nbsp; <b>Generated:</b> {e(_ts(dt.datetime.now().timestamp()))}</p>
<table><tr><th>Severity</th><th>Finding</th><th>EOL date</th><th>Vulns</th><th>Location</th></tr>{''.join(rows)}</table>
<h2>Details</h2><pre>{e(md)}</pre></body></html>"""


# ---------------------------------------------------------------- combined (batch) reports
def combined(scans: list[dict], findings: dict, fmt: str) -> str:
    """One report across several scans (e.g. every allowlisted host). findings: {scan_id: [finding, ...]}."""
    if fmt == "json":
        return json.dumps([{"scan": {k: v for k, v in s.items() if k != "log"}, "findings": _sorted(findings.get(s["id"], []))}
                           for s in scans], indent=2, default=str)
    if fmt == "csv":
        buf = io.StringIO()
        w = csv.writer(buf)
        w.writerow(["target", "severity", "category", "title", "product", "version", "eol_date", "status", "cves", "location", "top_containment"])
        for s in scans:
            for f in _sorted(findings.get(s["id"], [])):
                lc = f.get("lifecycle") or {}
                cves = ";".join(((v.get("aliases") or [v["id"]])[0]) for v in f.get("vulns", [])[:20])
                w.writerow([s["target"], f["severity"], f["category"], f["title"], f.get("product", ""), f.get("version", ""),
                            lc.get("eol_date", ""), lc.get("status", ""), cves, f.get("location", ""),
                            (f.get("containment") or [{}])[0].get("title", "")])
        return buf.getvalue()
    # markdown / html: overview table, EOL components across hosts, then each scan's full section
    lines = ["# Combined EOL assessment", "", f"Targets: {len(scans)}  Generated: {_ts(dt.datetime.now().timestamp())}", "",
             "| Target | Status | Critical | High | Medium | EOL components |", "|---|---|---|---|---|---|"]
    eol_hosts: dict[str, set] = {}
    for s in scans:
        c = (s.get("summary") or {}).get("severity_counts", {})
        lines.append(f"| {s['target']} | {s['status']} | {c.get('critical', 0)} | {c.get('high', 0)} | {c.get('medium', 0)} | "
                     f"{(s.get('summary') or {}).get('eol_components', 0)} |")
        for f in findings.get(s["id"], []):
            if (f.get("lifecycle") or {}).get("status") == "eol":
                eol_hosts.setdefault(f"{f.get('product')} {f.get('version') or ''}".strip(), set()).add(s["target"])
    if eol_hosts:
        lines += ["", "## End-of-life components across targets", "", "| Component | Targets |", "|---|---|"]
        for comp, hosts in sorted(eol_hosts.items(), key=lambda x: -len(x[1])):
            lines.append(f"| {comp} | {', '.join(sorted(hosts))} |")
    for s in scans:
        section = to_markdown(s, findings.get(s["id"], []))
        lines += ["", "---", "", "#" + section if section.startswith("# ") else section]
    md = "\n".join(lines)
    if fmt == "md":
        return md
    e = html.escape
    return (f"<!doctype html><html><head><meta charset=utf-8><meta name=viewport content='width=device-width,initial-scale=1'>"
            f"<title>Combined EOL report</title><style>body{{font:14px/1.5 system-ui,sans-serif;max-width:1100px;margin:24px auto;"
            f"padding:0 16px}}pre{{background:#f2f4f7;padding:12px;white-space:pre-wrap;border-radius:6px}}</style></head>"
            f"<body><h1>Combined EOL assessment</h1><pre>{e(md)}</pre></body></html>")
