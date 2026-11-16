"""AI deep code review: Claude reads the extracted source like a reviewer would.

Two engines, chosen by Settings -> AI assist -> Connection:
  * Claude API family (direct / gateway / Bedrock / Vertex / Foundry / ...): a manual tool-use loop with four read-only
    tools over the kept source folder (list_files, read_file, search, report_finding).
  * Claude Code (your Claude / Enterprise login): runs the local `claude` CLI in the source folder with only Read, Grep
    and Glob allowed, and parses the JSON it returns.

Both return the same shape: {findings, verdicts, summary, model, turns, cost_usd, engine}.
Source code is sent to the configured Claude connection; the UI warns about this before a review starts.
"""
from __future__ import annotations

import fnmatch
import json
import os
import re
from pathlib import Path
from typing import Callable, Optional

from .. import db
from ..importers import _kb_for, _cwes
from .llm import LLMUnavailable, PLATFORMS, _client, model_for

SYSTEM = (
    "You are a senior application security engineer doing an authorized source code review for an internal security "
    "team. The application is a legacy QA/lab system whose code will not be changed, so the team needs an accurate list "
    "of real, reachable vulnerabilities and how to contain them at the infrastructure level (WAF/proxy rules, network "
    "isolation, configuration, monitoring). Be precise and evidence-based: cite file and line, trace data from its source "
    "to the dangerous sink, and say what protection is missing. Prefer fewer, confirmed findings over speculative ones. "
    "For verification, describe how a tester can safely confirm the issue in the authorized lab (which request and "
    "parameter to examine and what observable behavior confirms it). Keep verification non-destructive; do not write "
    "exploit payloads or weaponized code."
)

TASK = """Review the application source in the working folder.

Context from the automated scan (use it as leads, not conclusions):
{context}

How to work:
1. Get oriented: list the files, find the entry points (controllers, routes, servlets, JSP/PHP/ASPX pages, API handlers,
   message consumers) and how authentication and sessions work.
2. Check each rule-based lead above: open the code, trace the data, and decide whether it is a real, reachable issue.
3. Look beyond the leads for what pattern matching misses: injection reached through helper functions, missing
   authorization / access control (IDOR), authentication and session flaws, unsafe deserialization, file upload and file
   path handling, SSRF, XXE, template injection, hardcoded credentials and keys, weak crypto, sensitive data exposure,
   and dangerous use of the end-of-life components listed above.
4. Stop when you have covered the entry points; do not read every file of a large codebase.

For every confirmed vulnerability report: title; severity (critical/high/medium/low); CWE id; file and line; the entry
point (HTTP method, path, parameter) if you can determine it; the data flow from source to sink; why existing protections
do not stop it; confidence (high/medium/low); verification steps a tester can follow safely in the lab (what to send to
which endpoint/parameter in general terms and what observable behavior confirms it; non-destructive, no exploit
payloads); and containment steps that need no code change.
For every rule-based lead you checked, give a verdict: confirmed, likely false positive, or needs runtime check, with a
one-line reason. Finish with a short overall summary (most important risks first)."""

CC_OUTPUT = """
When you are done, reply with ONLY a JSON object in a ```json fenced block, with this shape:
{"findings": [{"title": "", "severity": "high", "cwe": "CWE-89", "file": "path/from/root", "line": 1,
  "entry_point": {"method": "GET", "path": "/x", "params": ["id"]}, "data_flow": "", "description": "",
  "missing_protection": "", "confidence": "high", "verification": ["step"], "containment": ["step"]}],
 "verdicts": [{"lead_id": "<id from the leads list>", "verdict": "confirmed|likely false positive|needs runtime check",
  "reason": ""}],
 "summary": "markdown summary"}"""

TOOLS = [
    {"name": "list_files", "description": "List files in the source tree matching a glob (e.g. '**/*.java', 'src/**'). "
     "Returns up to 400 relative paths with sizes.",
     "input_schema": {"type": "object", "properties": {"glob": {"type": "string"}}, "required": ["glob"]}},
    {"name": "read_file", "description": "Read part of a file with line numbers (max 400 lines per call).",
     "input_schema": {"type": "object", "properties": {"path": {"type": "string"}, "start_line": {"type": "integer"},
                                                     "end_line": {"type": "integer"}}, "required": ["path"]}},
    {"name": "search", "description": "Regex search across the source tree (Python regex, case-insensitive). Optional glob "
     "filter. Returns up to 80 'path:line: text' matches.",
     "input_schema": {"type": "object", "properties": {"pattern": {"type": "string"}, "glob": {"type": "string"}},
                      "required": ["pattern"]}},
    {"name": "report_finding", "description": "Record one confirmed vulnerability. Call once per vulnerability.",
     "input_schema": {"type": "object", "properties": {
         "title": {"type": "string"}, "severity": {"type": "string", "enum": ["critical", "high", "medium", "low"]},
         "cwe": {"type": "string"}, "file": {"type": "string"}, "line": {"type": "integer"},
         "entry_point": {"type": "object", "properties": {"method": {"type": "string"}, "path": {"type": "string"},
                                                         "params": {"type": "array", "items": {"type": "string"}}}},
         "data_flow": {"type": "string"}, "description": {"type": "string"}, "missing_protection": {"type": "string"},
         "confidence": {"type": "string", "enum": ["high", "medium", "low"]},
         "verification": {"type": "array", "items": {"type": "string"}},
         "containment": {"type": "array", "items": {"type": "string"}}},
         "required": ["title", "severity", "file", "description", "verification", "containment"]}},
    {"name": "lead_verdict", "description": "Record your verdict on one rule-based lead from the context.",
     "input_schema": {"type": "object", "properties": {
         "lead_id": {"type": "string"},
         "verdict": {"type": "string", "enum": ["confirmed", "likely false positive", "needs runtime check"]},
         "reason": {"type": "string"}}, "required": ["lead_id", "verdict", "reason"]}},
]

SKIP_DIRS = {".git", "node_modules", "bower_components", "vendor", "target", "build", "dist", "bin", "obj", ".venv", "venv",
             "__pycache__", ".idea", ".vscode"}
BINARY = re.compile(r"\.(?:png|jpe?g|gif|ico|svg|woff2?|ttf|eot|pdf|zip|gz|jar|war|ear|class|dll|exe|so|dylib|mp[34]|min\.js|map|lock)$", re.I)


# ---------------------------------------------------------------- context
def build_context(scan: dict, findings: list[dict]) -> tuple[str, dict]:
    """Compact text context + {lead_id: finding_id} for rule-based code findings."""
    summary = scan.get("summary") or {}
    inv = summary.get("inventory") or []
    eol = [f"{i.get('product')} {i.get('version') or ''} ({i.get('status')})" for i in inv if i.get("status") in ("eol", "eol_soon")][:40]
    nv = lambda i: i.get("vulns") if isinstance(i.get("vulns"), int) else len(i.get("vulns") or [])  # noqa: E731 - count or list
    vuln = [f"{i.get('product')} {i.get('version') or ''}: {nv(i)} known CVEs" for i in inv if nv(i)][:40]
    leads, lines = {}, []
    code = [f for f in findings if f.get("category") == "code" and not f.get("source_tool")]
    for n, f in enumerate(sorted(code, key=lambda f: ["critical", "high", "medium", "low", "info"].index(f["severity"]))[:60], 1):
        lid = f"L{n}"
        leads[lid] = f["id"]
        locs = ", ".join(f"{l['path']}:{l['line']}" for l in (f.get("locations") or [])[:6])
        ep = f.get("entry_point") or {}
        lines.append(f"- {lid} [{f['severity']}] {f['title']} at {locs}"
                     + (f" (reached via {ep.get('method')} {ep.get('path')} params {ep.get('params')})" if ep.get("path") else ""))
    ctx = (f"Languages: {summary.get('languages')}\n"
           f"End-of-life components: {'; '.join(eol) or 'none found'}\n"
           f"Components with known CVEs: {'; '.join(vuln) or 'none found'}\n"
           f"Rule-based leads:\n" + ("\n".join(lines) or "- none"))
    return ctx, leads


# ---------------------------------------------------------------- read-only file tools (API engine)
class SourceTree:
    def __init__(self, root: Path):
        self.root = root.resolve()

    def _safe(self, rel: str) -> Path:
        p = (self.root / rel.lstrip("/\\")).resolve()
        if p != self.root and self.root not in p.parents:
            raise ValueError("path is outside the source tree")
        return p

    def _files(self):
        for dp, dns, fns in os.walk(self.root):
            dns[:] = [d for d in dns if d not in SKIP_DIRS]
            for fn in fns:
                rel = os.path.relpath(os.path.join(dp, fn), self.root).replace(os.sep, "/")
                if not BINARY.search(fn):
                    yield rel

    def list_files(self, glob: str = "**/*") -> str:
        out = []
        for rel in self._files():
            if fnmatch.fnmatch(rel, glob) or fnmatch.fnmatch(rel, glob.replace("**/", "")):
                try:
                    out.append(f"{rel} ({(self.root / rel).stat().st_size} B)")
                except OSError:
                    continue
                if len(out) >= 400:
                    out.append("... (truncated; use a narrower glob)")
                    break
        return "\n".join(out) or "no files match"

    def read_file(self, path: str, start_line: int = 1, end_line: Optional[int] = None) -> str:
        p = self._safe(path)
        if not p.is_file():
            return f"not a file: {path}"
        lines = p.read_text("utf-8", "ignore").splitlines()
        start = max(1, int(start_line or 1))
        end = min(len(lines), int(end_line or start + 399), start + 399)
        body = "\n".join(f"{i}: {lines[i - 1][:400]}" for i in range(start, end + 1))
        more = f"\n... ({len(lines) - end} more lines)" if end < len(lines) else ""
        return f"{path} lines {start}-{end} of {len(lines)}\n{body}{more}"

    def search(self, pattern: str, glob: Optional[str] = None) -> str:
        try:
            rx = re.compile(pattern, re.I)
        except re.error as e:
            return f"invalid regex: {e}"
        out = []
        for rel in self._files():
            if glob and not (fnmatch.fnmatch(rel, glob) or fnmatch.fnmatch(rel, glob.replace("**/", ""))):
                continue
            try:
                if (self.root / rel).stat().st_size > 2_000_000:
                    continue
                for i, line in enumerate((self.root / rel).read_text("utf-8", "ignore").splitlines(), 1):
                    if rx.search(line):
                        out.append(f"{rel}:{i}: {line.strip()[:200]}")
                        if len(out) >= 80:
                            return "\n".join(out) + "\n... (truncated; refine the pattern or glob)"
            except OSError:
                continue
        return "\n".join(out) or "no matches"


# ---------------------------------------------------------------- normalize
def _to_finding(d: dict, engine_label: str) -> Optional[dict]:
    if not isinstance(d, dict) or not d.get("title") or not d.get("file"):
        return None
    cwes = _cwes(d.get("cwe"))
    sev = str(d.get("severity", "medium")).lower()
    sev = sev if sev in ("critical", "high", "medium", "low") else "medium"
    ep = d.get("entry_point") if isinstance(d.get("entry_point"), dict) else None
    loc = f"{d['file']}:{d.get('line') or ''}".rstrip(":")
    detail = " ".join(x for x in (d.get("description"), f"Data flow: {d['data_flow']}" if d.get("data_flow") else "",
                                  f"Missing protection: {d['missing_protection']}" if d.get("missing_protection") else "") if x)
    return {
        "category": "code", "severity": sev, "title": str(d["title"])[:200], "kb": _kb_for(d["title"], cwes, "imported"),
        "location": loc, "locations": [{"path": d["file"], "line": d.get("line") or "", "code": "", **({"entry": ep} if ep else {})}],
        "evidence": d.get("data_flow", "")[:1500], "detail": detail[:3000], "source_tool": engine_label,
        "cwe": [f"CWE-{c}" for c in cwes][:3], "confidence": d.get("confidence"),
        **({"entry_point": ep} if ep else {}),
        "verification_steps": [str(x) for x in (d.get("verification") or [])][:12],
        "ai_containment": [str(x) for x in (d.get("containment") or [])][:12],
    }


def _parse_json_block(text: str) -> dict:
    m = re.search(r"```(?:json)?\s*(\{.*\})\s*```", text, re.S)
    raw = m.group(1) if m else text[text.find("{"): text.rfind("}") + 1]
    try:
        return json.loads(raw)
    except ValueError:
        return {"findings": [], "verdicts": [], "summary": text}


# ---------------------------------------------------------------- engines
def _review_api(root: Path, ctx: str, cfg: dict, log, cancelled) -> dict:
    import anthropic

    client = _client(cfg)
    model = model_for(cfg)
    tree = SourceTree(root)
    review_cfg = db.get_setting("code_review")
    max_turns = int(review_cfg.get("max_turns", 60))
    budget = int(review_cfg.get("max_input_tokens", 4_000_000))
    messages: list = [{"role": "user", "content": TASK.format(context=ctx)
                       + "\n\nUse report_finding for each confirmed vulnerability and lead_verdict for each lead. "
                         "Your final message (no tool calls) is the overall summary."}]
    findings, verdicts, summary = [], {}, ""
    used, turns = 0, 0
    # Prompt caching keeps the growing conversation cheap; effort "high" for a thorough review. Some platforms or
    # gateways reject these, so they are dropped after the first 400 that mentions them.
    extras: dict = {"cache_control": {"type": "ephemeral"}, "output_config": {"effort": cfg.get("effort") or "high"}}

    def call(msgs):
        nonlocal extras
        for _ in range(2):
            try:
                return client.messages.create(model=model, max_tokens=16000, system=SYSTEM, tools=TOOLS, messages=msgs, **extras)
            except TypeError:
                if not extras:
                    raise
                extras = {}
            except anthropic.BadRequestError as e:
                if extras and re.search(r"cache_control|output_config|effort|extra", str(e), re.I):
                    log("this connection does not accept caching/effort options; continuing without them")
                    extras = {}
                    continue
                raise LLMUnavailable(f"API error 400: {e.message}") from e
            except anthropic.APIStatusError as e:
                raise LLMUnavailable(f"API error {e.status_code}: {e.message}") from e
            except anthropic.APIConnectionError as e:
                raise LLMUnavailable(f"cannot reach the {cfg.get('platform')} endpoint: {e}") from e
        raise LLMUnavailable("request failed")

    while turns < max_turns and not cancelled():
        turns += 1
        resp = call(messages)
        u = resp.usage
        used += (u.input_tokens or 0) + (getattr(u, "cache_read_input_tokens", 0) or 0) + (getattr(u, "cache_creation_input_tokens", 0) or 0)
        messages.append({"role": "assistant", "content": resp.content})  # append-only: keeps thinking blocks valid
        if resp.stop_reason == "refusal":
            log("the model declined to continue this review; keeping what was found so far")
            break
        if resp.stop_reason == "pause_turn":
            continue
        tool_uses = [b for b in resp.content if b.type == "tool_use"]
        text = "".join(b.text for b in resp.content if b.type == "text").strip()
        if not tool_uses:
            summary = text
            break
        results = []
        for tu in tool_uses:
            inp = tu.input if isinstance(tu.input, dict) else {}
            try:
                if tu.name == "list_files":
                    out = tree.list_files(str(inp.get("glob") or "**/*"))
                elif tu.name == "read_file":
                    log(f"reading {inp.get('path')}")
                    out = tree.read_file(str(inp.get("path", "")), inp.get("start_line") or 1, inp.get("end_line"))
                elif tu.name == "search":
                    out = tree.search(str(inp.get("pattern", "")), inp.get("glob"))
                elif tu.name == "report_finding":
                    f = _to_finding(inp, f"Claude AI review ({model})")
                    if not f:
                        raise ValueError("title and file are required")
                    findings.append(f)
                    log(f"finding: [{f['severity']}] {f['title']} ({f['location']})")
                    out = "recorded"
                elif tu.name == "lead_verdict":
                    verdicts[str(inp.get("lead_id"))] = {"verdict": inp.get("verdict"), "reason": inp.get("reason", "")}
                    out = "recorded"
                else:
                    raise ValueError(f"unknown tool {tu.name}")
                results.append({"type": "tool_result", "tool_use_id": tu.id, "content": out})
            except Exception as e:  # noqa: BLE001 - report tool errors back to the model
                results.append({"type": "tool_result", "tool_use_id": tu.id, "content": f"Error: {e}", "is_error": True})
        if used > budget:
            log(f"input token budget reached ({used:,}); asking for the summary")
            messages.append({"role": "user", "content": results + [
                {"type": "text", "text": "Budget reached: do not call more tools; reply with the overall summary now."}]})
            final = call(messages)
            summary = "".join(b.text for b in final.content if b.type == "text").strip()
            break
        messages.append({"role": "user", "content": results})
    return {"findings": findings, "verdicts": verdicts, "summary": summary, "model": model, "turns": turns,
            "input_tokens": used, "engine": PLATFORMS.get(cfg.get("platform"), {}).get("label")}


def _review_claude_code(root: Path, ctx: str, cfg: dict, log, cancelled) -> dict:
    from .claude_code import ClaudeCodeError, run

    review_cfg = db.get_setting("code_review")
    prompt = SYSTEM + "\n\n" + TASK.format(context=ctx) + CC_OUTPUT
    try:
        r = run(prompt, cfg, cwd=str(root), tools=True, max_turns=int(review_cfg.get("max_turns", 60)),
                timeout=int(review_cfg.get("timeout_min", 45)) * 60, log=log, cancelled=cancelled)
    except ClaudeCodeError as e:
        raise LLMUnavailable(str(e)) from e
    data = _parse_json_block(r["text"])
    chosen = cfg.get("model") if cfg.get("model") and cfg.get("model") != "claude-opus-5-5" else None
    label = f"Claude Code review ({r.get('model') or chosen or 'your default model'})"
    findings = [f for f in (_to_finding(d, label) for d in data.get("findings") or []) if f]
    verdicts = {str(v.get("lead_id")): {"verdict": v.get("verdict"), "reason": v.get("reason", "")}
                for v in data.get("verdicts") or [] if isinstance(v, dict)}
    return {"findings": findings, "verdicts": verdicts, "summary": data.get("summary") or "", "model": r.get("model"),
            "turns": r.get("turns"), "cost_usd": r.get("cost_usd"), "engine": "Claude Code"}


def review(scan: dict, findings: list[dict], log: Callable[[str], None], cancelled: Callable[[], bool]) -> dict:
    cfg = db.get_setting("llm")
    if cfg.get("provider") != "anthropic":
        raise LLMUnavailable("AI deep review needs a Claude connection (Settings -> AI assist). Ollama is not supported for this.")
    src = (scan.get("summary") or {}).get("source_dir")
    if not src or not Path(src).is_dir():
        raise LLMUnavailable("the source for this scan was not kept (or was deleted); upload the archive again")
    ctx, leads = build_context(scan, findings)
    log(f"starting AI deep review with {PLATFORMS.get(cfg.get('platform'), {}).get('label')}; {len(leads)} rule-based leads")
    engine = _review_claude_code if cfg.get("platform") == "claude_code" else _review_api
    res = engine(Path(src), ctx, cfg, log, cancelled)
    res["verdicts"] = {leads[k]: v for k, v in res.get("verdicts", {}).items() if k in leads}
    return res
