"""Background scan execution (thread per scan, bounded)."""
from __future__ import annotations

import asyncio
import shutil
import threading
import time
import traceback
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Optional

from . import analysis, db, scope
from .config import UPLOAD_DIR
from .scanners import code as code_scanner
from .scanners.web import WebScanner

_pool = ThreadPoolExecutor(max_workers=3, thread_name_prefix="scan")
_cancel: dict[str, threading.Event] = {}


def cancel(sid: str) -> bool:
    ev = _cancel.get(sid)
    if ev:
        ev.set()
        return True
    return False


def _hooks(sid: str):
    ev = _cancel.setdefault(sid, threading.Event())
    last = {"t": 0.0}

    def log(msg: str) -> None:
        db.append_log(sid, msg)

    def progress(p: float, msg: str = "") -> None:
        now = time.time()
        if now - last["t"] > 0.5 or p >= 1:
            last["t"] = now
            db.update_scan(sid, progress=round(min(1.0, p), 3), message=msg)

    return log, progress, ev.is_set


def _finish(sid: str, findings: list[dict], inventory: list[dict], extra: dict) -> None:
    for f in findings:
        db.add_finding(sid, f)
    summary = analysis.summarize(findings, inventory)
    summary.update(extra)
    summary["inventory"] = inventory
    db.update_scan(sid, summary=summary)


def _run_web(sid: str, target: str, mode: str, options: dict) -> None:
    log, progress, cancelled = _hooks(sid)
    db.update_scan(sid, status="running", message="starting")
    try:
        rules = db.get_setting("scope")
        feeds_cfg = db.get_setting("feeds")
        log(f"web scan {target} mode={mode} operator={db.get_scan(sid)['operator']}")
        scanner = WebScanner(target, mode, options, rules, log, progress, cancelled)
        res = asyncio.run(scanner.run())
        log(f"{res.requests} HTTP requests sent")
        progress(0.92, "lifecycle + vulnerability lookups")
        comp_findings, inventory = analysis.enrich(res.components, feeds_cfg.get("online", True), feeds_cfg.get("osv", True), log, progress)
        raw = analysis.enrich_raw(res.findings)
        _finish(sid, comp_findings + raw, inventory, {"pages": res.pages[:200], "scripts": res.scripts[:300],
                                                       "requests": res.requests, "tls": res.tls,
                                                       "api_endpoints": res.api_endpoints})
        db.update_scan(sid, status="cancelled" if cancelled() else "done", progress=1.0, message="complete", finished=time.time())
    except Exception as e:
        log("ERROR: " + "".join(traceback.format_exception_only(type(e), e)).strip())
        db.update_scan(sid, status="error", message=str(e)[:300], finished=time.time())
    finally:
        _cancel.pop(sid, None)


def _run_code(sid: str, archive: Path, options: dict) -> None:
    log, progress, cancelled = _hooks(sid)
    db.update_scan(sid, status="running", message="extracting archive")
    work = archive.parent / "src"
    try:
        n = code_scanner.safe_extract(archive, work)
        log(f"extracted {n} files (archive is parsed only, never executed)")
        res = code_scanner.scan_tree(work, log, progress, cancelled, include_node_modules=bool(options.get("include_node_modules")))
        log(f"reviewed {res.files_scanned} files; manifests: {', '.join(res.manifests[:30]) or 'none'}")
        feeds_cfg = db.get_setting("feeds")
        progress(0.7, "lifecycle + vulnerability lookups")
        comp_findings, inventory = analysis.enrich(res.components, feeds_cfg.get("online", True), feeds_cfg.get("osv", True), log, progress)
        raw = analysis.enrich_raw(res.findings)
        _finish(sid, comp_findings + raw, inventory, {"files_scanned": res.files_scanned, "manifests": res.manifests[:300],
                                                       "languages": res.languages})
        # Keep only the small snippet set for optional LLM review; delete extracted source.
        db.cache_set(f"snippets:{sid}", res.snippets)
        db.update_scan(sid, status="cancelled" if cancelled() else "done", progress=1.0, message="complete", finished=time.time())
    except code_scanner.ArchiveError as e:
        log(f"ERROR: {e}")
        db.update_scan(sid, status="error", message=str(e), finished=time.time())
    except Exception as e:
        log("ERROR: " + "".join(traceback.format_exception_only(type(e), e)).strip())
        db.update_scan(sid, status="error", message=str(e)[:300], finished=time.time())
    finally:
        _cancel.pop(sid, None)
        if not options.get("keep_source"):
            shutil.rmtree(archive.parent, ignore_errors=True)


def start_web(target: str, mode: str, operator: str, ticket: str, options: dict) -> str:
    raw_target = target.strip()
    url = raw_target if "://" in raw_target else f"https://{raw_target}"
    scope.check(url)  # fail fast before queuing
    opts = {**db.get_setting("scan_defaults"), **{k: v for k, v in options.items() if v not in (None, "")}}
    opts["raw_target"] = raw_target
    stored = {k: v for k, v in opts.items() if k not in ("headers", "cookies")}
    stored["auth_headers"] = sorted((opts.get("headers") or {}).keys())
    stored["cookies_set"] = bool(opts.get("cookies"))
    sid = db.create_scan("web", url, mode, operator, ticket, stored)
    _pool.submit(_run_web, sid, url, mode, opts)
    return sid


def start_code(filename: str, archive: Path, operator: str, ticket: str, options: dict) -> str:
    sid = db.create_scan("code", filename, "code-review", operator, ticket, options)
    _pool.submit(_run_code, sid, archive, options)
    return sid


def upload_path(filename: str) -> Path:
    d = code_scanner.new_workdir(UPLOAD_DIR)
    safe = "".join(ch for ch in Path(filename).name if ch.isalnum() or ch in "._-") or "upload.zip"
    return d / safe


def import_results(tool: str, filename: str, findings: list[dict], operator: str, ticket: str,
                   into_scan: Optional[str] = None) -> str:
    """Store imported findings, either as a new scan or merged into an existing one (one combined report)."""
    findings = analysis.enrich_raw(findings)
    record = {"tool": tool, "file": filename, "count": len(findings), "at": time.time(), "operator": operator}
    if into_scan:
        s = db.get_scan(into_scan)
        if not s:
            raise KeyError(into_scan)
        for f in findings:
            db.add_finding(into_scan, f)
        summary = s.get("summary") or {}
        inventory = summary.get("inventory") or []
        fresh = analysis.summarize(db.get_findings(into_scan), inventory)
        summary.update(fresh)
        summary["imports"] = (summary.get("imports") or []) + [record]
        db.update_scan(into_scan, summary=summary)
        db.append_log(into_scan, f"imported {len(findings)} findings from {tool} ({filename}) by {operator}")
        return into_scan
    sid = db.create_scan("import", filename, tool, operator, ticket, {"tool": tool})
    for f in findings:
        db.add_finding(sid, f)
    summary = analysis.summarize(findings, [])
    summary.update({"inventory": [], "imports": [record]})
    db.update_scan(sid, status="done", progress=1.0, message="imported", finished=time.time(), summary=summary)
    db.append_log(sid, f"imported {len(findings)} findings from {tool} ({filename}) by {operator}")
    return sid
