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
        burp_cfg = db.get_setting("burp")
        log(f"web scan {target} mode={mode} operator={db.get_scan(sid)['operator']}")
        snap = code_scanner.new_workdir(UPLOAD_DIR) / "web"
        snap.mkdir(parents=True, exist_ok=True)
        options = {**options, "snapshot_dir": str(snap)}
        if options.get("burp_proxy"):
            options["proxy_url"] = burp_cfg.get("proxy_url") or "http://127.0.0.1:8080"
        use_burp = bool(options.get("burp_scan"))
        share = 0.55 if use_burp else 1.0  # with a Burp scan, our crawl is the first half of the progress bar
        scanner = WebScanner(target, mode, options, rules, log, lambda p, m="": progress(p * share, m), cancelled)
        res = asyncio.run(scanner.run())
        log(f"{res.requests} HTTP requests sent")
        burp_findings, burp_info = [], None
        if use_burp and not cancelled():
            from .scanners import burp
            progress(0.55, "Burp Suite scan starting")
            try:
                exclude = [e["url"] for e in res.endpoints if e.get("not_followed")]
                br = burp.run(scanner.target, mode, burp_cfg, rules, log, lambda p, m="": progress(0.55 + 0.35 * p, m),
                              cancelled, exclude)
                burp_findings = br["findings"]
                burp_info = {"task_id": br["task_id"], "status": br["status"], "issues": len(burp_findings),
                             "metrics": br["metrics"]}
                log(f"Burp reported {len(burp_findings)} issue types")
            except (burp.BurpError, scope.OutOfScope) as e:
                log(f"Burp scan skipped: {e}")
                burp_info = {"error": str(e)[:400]}
        progress(0.92, "lifecycle + vulnerability lookups")
        comp_findings, inventory = analysis.enrich(res.components, feeds_cfg.get("online", True), feeds_cfg.get("osv", True), log, progress)
        raw = analysis.enrich_raw(res.findings + burp_findings)
        (snap / "index.json").write_text(__import__("json").dumps(scanner.snap.index, indent=1), encoding="utf-8")
        _finish(sid, comp_findings + raw, inventory, {"pages": res.pages[:500], "scripts": res.scripts[:300],
                                                       "requests": res.requests, "tls": res.tls,
                                                       "api_endpoints": res.api_endpoints,
                                                       "endpoints": res.endpoints[:3000], "page_info": res.page_info[:1000],
                                                       "snapshot_dir": str(snap), "burp": burp_info,
                                                       "crawl_stats": res.crawl_stats})
        db.update_scan(sid, status="cancelled" if cancelled() else "done", progress=1.0, message="complete", finished=time.time())
    except Exception as e:
        log("ERROR: " + "".join(traceback.format_exception_only(type(e), e)).strip())
        db.update_scan(sid, status="error", message=str(e)[:300], finished=time.time())
    finally:
        _cancel.pop(sid, None)
    s = db.get_scan(sid)
    if options.get("ai_review") and s and s["status"] == "done":
        start_ai_review(sid)


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
        extra = {"files_scanned": res.files_scanned, "manifests": res.manifests[:300], "languages": res.languages}
        if options.get("keep_source", True):
            extra["source_dir"] = str(work)  # kept for the AI deep review; removed when the scan is deleted
        if options.get("semgrep"):
            from .scanners import semgrep_runner
            progress(0.8, "running Semgrep")
            sg = semgrep_runner.run(work, db.get_setting("code_review").get("semgrep_config") or "p/default", log, cancelled)
            raw += analysis.enrich_raw(sg)
            extra["semgrep"] = len(sg)
        _finish(sid, comp_findings + raw, inventory, extra)
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
        try:
            archive.unlink()  # the uploaded archive itself is no longer needed
        except OSError:
            pass
        if not options.get("keep_source", True) or db.get_scan(sid) is None or db.get_scan(sid)["status"] == "error":
            shutil.rmtree(archive.parent, ignore_errors=True)
    if options.get("ai_review") and db.get_scan(sid) and db.get_scan(sid)["status"] == "done":
        start_ai_review(sid)


def start_web(target: str, mode: str, operator: str, ticket: str, options: dict) -> str:
    raw_target = target.strip()
    url = raw_target if "://" in raw_target else f"https://{raw_target}"
    scope.check(url)  # fail fast before queuing
    opts = {**db.get_setting("scan_defaults"), **{k: v for k, v in options.items() if v not in (None, "")}}
    opts["raw_target"] = raw_target
    stored = {k: v for k, v in opts.items() if k not in ("headers", "cookies", "login_password", "login_fields")}  # never stored
    stored["auth_headers"] = sorted((opts.get("headers") or {}).keys())
    stored["cookies_set"] = bool(opts.get("cookies"))
    if opts.get("burp_scan") or opts.get("burp_proxy"):
        stored["burp"] = {"scan": bool(opts.get("burp_scan")), "proxy": bool(opts.get("burp_proxy"))}
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


def remove_source(sid: str) -> bool:
    """Delete the kept source of a code scan / saved crawl data of a web scan (on scan delete or from the UI)."""
    s = db.get_scan(sid)
    if not s:
        return False
    summary = s.get("summary") or {}
    removed = False
    for key in ("source_dir", "snapshot_dir"):
        src = summary.get(key)
        if src and Path(src).resolve().is_relative_to(UPLOAD_DIR.resolve()):  # never delete outside the uploads folder
            shutil.rmtree(Path(src).parent, ignore_errors=True)
            summary.pop(key, None)
            removed = True
    if removed:
        db.update_scan(sid, summary=summary)
    return removed


def start_ai_review(sid: str) -> None:
    s = db.get_scan(sid)
    summary = s.get("summary") or {}
    summary["ai_review_status"] = {"state": "queued", "queued": time.time()}
    db.update_scan(sid, summary=summary)
    _pool.submit(_run_ai_review, sid)


def _run_ai_review(sid: str) -> None:
    from .advisor import code_review_ai, web_review_ai

    def set_status(**kw):
        s = db.get_scan(sid)
        if not s:
            return
        summary = s.get("summary") or {}
        summary["ai_review_status"] = {**(summary.get("ai_review_status") or {}), **kw}
        db.update_scan(sid, summary=summary)

    ev = _cancel.setdefault(sid, threading.Event())
    ev.clear()
    log = lambda m: db.append_log(sid, "[AI] " + m)  # noqa: E731
    set_status(state="running", started=time.time())
    try:
        s = db.get_scan(sid)
        engine = web_review_ai if s["kind"] == "web" else code_review_ai
        res = engine.review(s, db.get_findings(sid), log, ev.is_set)
        new = analysis.enrich_raw(res["findings"])
        for f in new:
            db.add_finding(sid, f)
        for fid, verdict in res.get("verdicts", {}).items():
            f = db.get_finding(fid)
            if f:
                f["ai_verdict"] = verdict
                db.update_finding(fid, f)
        s = db.get_scan(sid)
        summary = s["summary"]
        summary.update(analysis.summarize(db.get_findings(sid), summary.get("inventory") or []))
        summary["ai_review"] = res.get("summary", "")
        db.update_scan(sid, summary=summary)
        set_status(state="cancelled" if ev.is_set() else "done", finished=time.time(), found=len(new),
                   model=res.get("model"), turns=res.get("turns"), cost_usd=res.get("cost_usd"), engine=res.get("engine"))
        log(f"AI review finished: {len(new)} findings, {len(res.get('verdicts', {}))} rule findings re-assessed")
    except Exception as e:  # noqa: BLE001 - surface any provider error in the UI
        log("ERROR: " + "".join(traceback.format_exception_only(type(e), e)).strip())
        set_status(state="error", finished=time.time(), error=str(e)[:500])
    finally:
        _cancel.pop(sid, None)


def start_batch(targets: list[str], mode: str, operator: str, ticket: str, options: dict) -> dict:
    """Start one web scan per target (each scope-checked). Scans share a batch id for the combined report."""
    import uuid
    bid = "b" + uuid.uuid4().hex[:10]
    started, skipped = [], []
    seen = set()
    for raw in targets:
        t = raw.strip()
        if not t or t in seen:
            continue
        seen.add(t)
        try:
            sid = start_web(t, mode, operator, ticket, {**options, "batch": bid})
            started.append({"target": t, "id": sid})
        except scope.OutOfScope as e:
            skipped.append({"target": t, "reason": str(e)})
    return {"batch": bid, "started": started, "skipped": skipped}


def batch_scans(bid: str) -> list[dict]:
    return [s for s in db.list_scans(1000) if (s.get("options") or {}).get("batch") == bid]


def import_traffic(kind: str, filename: str, data: bytes, operator: str, ticket: str) -> str:
    """Passive analysis of a Burp items export or HAR file (runs in the background)."""
    label = {"burp-items": "Burp proxy history", "har": "HAR file"}[kind]
    sid = db.create_scan("passive", filename, label, operator, ticket, {"source": kind})
    _pool.submit(_run_traffic, sid, kind, data)
    return sid


def _run_traffic(sid: str, kind: str, data: bytes) -> None:
    import json as _json
    from .scanners import passive
    log, progress, cancelled = _hooks(sid)
    db.update_scan(sid, status="running", message="reading recorded traffic")
    try:
        entries = passive.read_burp_items(data) if kind == "burp-items" else passive.read_har(_json.loads(data.decode("utf-8-sig")))
        res, hosts = passive.analyze(entries, log)
        progress(0.6, "lifecycle + vulnerability lookups")
        feeds_cfg = db.get_setting("feeds")
        comp_findings, inventory = analysis.enrich(res.components, feeds_cfg.get("online", True), feeds_cfg.get("osv", True), log, progress)
        raw = analysis.enrich_raw(res.findings)
        _finish(sid, comp_findings + raw, inventory, {"pages": res.pages[:500], "scripts": res.scripts[:500],
                                                       "requests": res.requests, "hosts": hosts})
        db.update_scan(sid, status="done", progress=1.0, message="complete", finished=time.time())
    except Exception as e:  # noqa: BLE001
        log("ERROR: " + "".join(traceback.format_exception_only(type(e), e)).strip())
        db.update_scan(sid, status="error", message=str(e)[:300], finished=time.time())
    finally:
        _cancel.pop(sid, None)
