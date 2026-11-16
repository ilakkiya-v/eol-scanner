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
    w.writerow(["severity", "category", "title", "product", "version", "eol_date", "status", "cves", "location", "confidence", "top_containment"])
    for f in _sorted(findings):
        lc = f.get("lifecycle") or {}
        cves = ";".join(((v.get("aliases") or [v["id"]])[0]) for v in f.get("vulns", [])[:20])
        w.writerow([f["severity"], f["category"], f["title"], f.get("product", ""), f.get("version", ""), lc.get("eol_date", ""),
                    lc.get("status", ""), cves, f.get("location", ""), f.get("confidence", ""),
                    (f.get("containment") or [{}])[0].get("title", "")])
    return buf.getvalue()


def to_markdown(scan: dict, findings: list[dict]) -> str:
    s = scan.get("summary", {})
    c = s.get("severity_counts", {})
    lines = [f"# EOL assessment: {scan['target']}", "",
             f"- Scan: `{scan['id']}` ({scan['kind']}, mode `{scan.get('mode')}`)",
             f"- Operator: {scan.get('operator') or '-'}  Ticket/authorization: {scan.get('ticket') or '-'}",
             f"- Started: {_ts(scan.get('created'))}  Finished: {_ts(scan.get('finished'))}",
             f"- Findings: {s.get('findings', 0)} (critical {c.get('critical',0)}, high {c.get('high',0)}, medium {c.get('medium',0)}, low {c.get('low',0)}, info {c.get('info',0)})",
             f"- Components: {s.get('components', 0)}, EOL: {s.get('eol_components', 0)}, EOL soon: {s.get('eol_soon_components', 0)}", ""]
    for f in _sorted(findings):
        lines += [f"## [{f['severity'].upper()}] {f['title']}", ""]
        if f.get("location"):
            lines.append(f"**Location:** `{f['location']}`  ")
        lc = f.get("lifecycle") or {}
        if lc.get("status"):
            lines.append(f"**Lifecycle:** {lc.get('status')} — cycle {lc.get('cycle') or '?'}, EOL {lc.get('eol_date') or lc.get('status')}, latest {lc.get('latest_version') or '-'}  ")
        if f.get("vulns"):
            lines.append(f"**Known vulnerabilities ({f.get('vuln_count')}):** " + ", ".join(
                f"{(v.get('aliases') or [v['id']])[0]} ({v['severity']})" for v in f["vulns"][:15]))
        if f.get("evidence"):
            ev = f["evidence"]
            if isinstance(ev, list):
                lines += ["", "**Evidence:**"] + [f"- `{e['location']}` — {e['text']}" for e in ev[:5]]
            else:
                lines += ["", "**Evidence:**", "```", str(ev)[:800], "```"]
        if f.get("containment"):
            lines += ["", "**Containment:**"]
            for m in f["containment"]:
                lines.append(f"- **{m['title']}** — {m['detail']}")
                if m.get("snippet"):
                    lines += ["  ```", *["  " + l for l in m["snippet"].splitlines()], "  ```"]
        if f.get("manual_tests"):
            lines += ["", "**Manual verification (authorized lab only):**"] + [f"- {t}" for t in f["manual_tests"]]
        if f.get("extended_support"):
            lines += ["", f"**Extended support options:** {f['extended_support']}"]
        if f.get("ai_advice"):
            lines += ["", "**AI-assisted analysis:**", "", f["ai_advice"]]
        lines.append("")
    if s.get("ai_review"):
        lines += ["## AI-assisted code review", "", s["ai_review"], ""]
    return "\n".join(lines)


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
