"""FastAPI entrypoint: REST API + static single-page UI."""
from __future__ import annotations

import os
import secrets
import shutil
from typing import Any, Optional

from fastapi import Depends, FastAPI, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import FileResponse, JSONResponse, PlainTextResponse, Response
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from starlette.concurrency import run_in_threadpool
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from . import db, importers, jobs, report, scope
from .advisor import llm
from .config import APP_DIR, MAX_UPLOAD_BYTES
from .eol import feeds
from .scanners import browser
from .eol.database import EOL_DB

app = FastAPI(title="EOL Scanner", version="1.0.0", docs_url="/api/docs", redoc_url=None)

# Optional basic auth for when the UI is shared on a team VM: set EOLSCAN_USER / EOLSCAN_PASSWORD.
_security = HTTPBasic(auto_error=False)
_USER, _PASS = os.environ.get("EOLSCAN_USER"), os.environ.get("EOLSCAN_PASSWORD")


def auth(creds: Optional[HTTPBasicCredentials] = Depends(_security)) -> None:
    if not _USER:
        return
    if not creds or not (secrets.compare_digest(creds.username, _USER) and secrets.compare_digest(creds.password, _PASS or "")):
        raise HTTPException(401, "authentication required", headers={"WWW-Authenticate": "Basic"})


@app.middleware("http")
async def security_headers(request: Request, call_next):
    resp = await call_next(request)
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Referrer-Policy"] = "no-referrer"
    # Revalidate the UI on every load so an upgraded image never runs a stale app.js against a newer API.
    resp.headers.setdefault("Cache-Control", "no-cache")
    if not request.url.path.startswith("/api/docs"):
        resp.headers["Content-Security-Policy"] = "default-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; object-src 'none'; base-uri 'none'; frame-ancestors 'none'"
    return resp


# ------------------------------------------------------------------ models
class WebScanIn(BaseModel):
    target: str
    mode: str = Field("safe", pattern="^(passive|safe|active)$")
    operator: str = ""
    ticket: str = ""
    attest: bool = False
    headers: dict[str, str] = {}
    cookies: str = ""
    rate_per_sec: Optional[float] = None
    concurrency: Optional[int] = None
    max_pages: Optional[int] = None
    timeout: Optional[float] = None
    verify_tls: Optional[bool] = None
    use_proxy: Optional[bool] = None
    render_js: Optional[bool] = None
    burp_proxy: Optional[bool] = None   # send the crawl through Burp's proxy listener
    burp_scan: Optional[bool] = None    # ask Burp Suite Pro (REST API) to crawl + audit the target too
    ai_review: Optional[bool] = None    # start the AI web review when the scan finishes


class ScopeIn(BaseModel):
    allow: list[str] = []
    deny: list[str] = []


class SettingsIn(BaseModel):
    llm: Optional[dict[str, Any]] = None
    feeds: Optional[dict[str, Any]] = None
    scan_defaults: Optional[dict[str, Any]] = None
    code_review: Optional[dict[str, Any]] = None
    burp: Optional[dict[str, Any]] = None


class AdviceIn(BaseModel):
    context: str = ""


# ------------------------------------------------------------------ scans
@app.post("/api/scans/web", dependencies=[Depends(auth)])
def start_web(body: WebScanIn):
    if not body.attest:
        raise HTTPException(400, "You must confirm you are authorized to test this target.")
    if not body.operator.strip():
        raise HTTPException(400, "Operator name is required for the audit trail.")
    try:
        sid = jobs.start_web(body.target, body.mode, body.operator.strip(), body.ticket.strip(),
                             body.model_dump(exclude={"target", "mode", "operator", "ticket", "attest"}))
    except scope.OutOfScope as e:
        raise HTTPException(403, str(e))
    return {"id": sid}


@app.post("/api/scans/code", dependencies=[Depends(auth)])
async def start_code(file: UploadFile = File(...), operator: str = Form(...), ticket: str = Form(""),
                     attest: bool = Form(False), include_node_modules: bool = Form(False), ai_review: bool = Form(False),
                     semgrep: bool = Form(False), keep_source: bool = Form(True)):
    if not attest:
        raise HTTPException(400, "You must confirm you are authorized to review this code.")
    if not operator.strip():
        raise HTTPException(400, "Operator name is required for the audit trail.")
    dest = jobs.upload_path(file.filename or "upload.zip")
    size = 0
    with open(dest, "wb") as out:
        while chunk := await file.read(1 << 20):
            size += len(chunk)
            if size > MAX_UPLOAD_BYTES:
                out.close()
                shutil.rmtree(dest.parent, ignore_errors=True)
                raise HTTPException(413, f"upload exceeds {MAX_UPLOAD_BYTES // (1024*1024)} MB")
            out.write(chunk)
    sid = jobs.start_code(file.filename or "upload.zip", dest, operator.strip(), ticket.strip(),
                          {"include_node_modules": include_node_modules, "size": size, "ai_review": ai_review,
                           "semgrep": semgrep, "keep_source": keep_source or ai_review})
    return {"id": sid}


IMPORT_LIMIT = 200 * 1024 * 1024


@app.post("/api/scans/import", dependencies=[Depends(auth)])
async def import_results(file: UploadFile = File(...), operator: str = Form(...), ticket: str = Form(""),
                         attest: bool = Form(False), into_scan: str = Form("")):
    """Import ZAP / Burp / Semgrep / SARIF / Nuclei results as a new scan or into an existing one."""
    if not attest:
        raise HTTPException(400, "You must confirm these results come from authorized testing.")
    if not operator.strip():
        raise HTTPException(400, "Operator name is required for the audit trail.")
    data = await file.read(IMPORT_LIMIT + 1)
    if len(data) > IMPORT_LIMIT:
        raise HTTPException(413, "import file exceeds 200 MB")
    traffic = importers.recorded_traffic_kind(data)
    if traffic:  # Burp proxy history / HAR: passive fingerprinting of recorded responses, no traffic sent
        sid = jobs.import_traffic(traffic, file.filename or "traffic", data, operator.strip(), ticket.strip())
        return {"id": sid, "tool": {"burp-items": "Burp proxy history", "har": "HAR"}[traffic], "imported": None, "passive": True}
    try:
        tool, found = await run_in_threadpool(importers.parse, data, file.filename or "")
    except importers.ImportError_ as e:
        raise HTTPException(400, str(e))
    if into_scan and not db.get_scan(into_scan):
        raise HTTPException(404, "scan to merge into was not found")
    sid = await run_in_threadpool(jobs.import_results, tool, file.filename or "import", found, operator.strip(),
                                  ticket.strip(), into_scan or None)
    return {"id": sid, "tool": tool, "imported": len(found)}


@app.get("/api/capabilities", dependencies=[Depends(auth)])
def capabilities():
    from .advisor import claude_code
    from .scanners import semgrep_runner
    return {"browser": browser.available(), "semgrep": semgrep_runner.available(),
            "claude_code": claude_code.find_cli(db.get_setting("llm")) is not None, "ai": llm.status(),
            "burp_key_set": bool(os.environ.get("BURP_API_KEY"))}


@app.post("/api/burp/test", dependencies=[Depends(auth)])
def burp_test(body: Optional[dict[str, Any]] = None):
    """Check that Burp Suite Pro's REST API answers, with the given (unsaved) or saved settings. Starts nothing."""
    from .scanners import burp
    return burp.test({**db.get_setting("burp"), **{k: v for k, v in (body or {}).items() if k in ("api_url",)}})


class BatchIn(WebScanIn):
    target: str = ""
    targets: list[str] = []


@app.post("/api/batches/web", dependencies=[Depends(auth)])
def start_batch(body: BatchIn):
    """Scan several targets with the same settings (e.g. every allowlisted host). Out-of-scope targets are skipped."""
    if not body.attest:
        raise HTTPException(400, "You must confirm you are authorized to test these targets.")
    if not body.operator.strip():
        raise HTTPException(400, "Operator name is required for the audit trail.")
    targets = [t for t in body.targets if t.strip()][:200]
    if not targets:
        raise HTTPException(400, "Add at least one target.")
    return jobs.start_batch(targets, body.mode, body.operator.strip(), body.ticket.strip(),
                            body.model_dump(exclude={"target", "targets", "mode", "operator", "ticket", "attest"}))


@app.get("/api/batches/{bid}/report.{fmt}", dependencies=[Depends(auth)])
def batch_report(bid: str, fmt: str):
    scans = jobs.batch_scans(bid)
    if not scans:
        raise HTTPException(404, "batch not found")
    if fmt not in ("json", "csv", "md", "html"):
        raise HTTPException(400, "format must be json, csv, md or html")
    body = report.combined(scans, {s["id"]: db.get_findings(s["id"]) for s in scans}, fmt)
    media = {"json": "application/json", "csv": "text/csv", "md": "text/markdown", "html": "text/html"}[fmt]
    return Response(body, media_type=media, headers={"Content-Disposition": f"attachment; filename=eol-combined-{bid}.{fmt}"})


@app.get("/api/scope/hosts", dependencies=[Depends(auth)])
def scope_hosts():
    """Allowlist entries that are concrete hosts (wildcards and IP ranges can't be crawled directly)."""
    allow = db.get_setting("scope").get("allow") or []
    return [a for a in allow if "*" not in a and "/" not in a]


@app.get("/api/scans", dependencies=[Depends(auth)])
def list_scans():
    out = []
    for s in db.list_scans():
        s["summary"] = {k: v for k, v in (s.get("summary") or {}).items() if k not in ("inventory", "pages", "scripts", "manifests", "ai_review")}
        out.append(s)
    return out


@app.get("/api/scans/{sid}", dependencies=[Depends(auth)])
def get_scan(sid: str):
    s = db.get_scan(sid)
    if not s:
        raise HTTPException(404)
    return s


@app.get("/api/scans/{sid}/findings", dependencies=[Depends(auth)])
def get_findings(sid: str):
    return db.get_findings(sid)


@app.post("/api/scans/{sid}/cancel", dependencies=[Depends(auth)])
def cancel_scan(sid: str):
    return {"cancelled": jobs.cancel(sid)}


@app.delete("/api/scans/{sid}", dependencies=[Depends(auth)])
def delete_scan(sid: str):
    jobs.cancel(sid)
    jobs.remove_source(sid)
    db.delete_scan(sid)
    return {"deleted": sid}


@app.get("/api/scans/{sid}/report.{fmt}", dependencies=[Depends(auth)])
def export(sid: str, fmt: str):
    s = db.get_scan(sid)
    if not s:
        raise HTTPException(404)
    f = db.get_findings(sid)
    name = f"eol-report-{sid}"
    if fmt == "json":
        return Response(report.to_json(s, f), media_type="application/json", headers={"Content-Disposition": f"attachment; filename={name}.json"})
    if fmt == "csv":
        return Response(report.to_csv(s, f), media_type="text/csv", headers={"Content-Disposition": f"attachment; filename={name}.csv"})
    if fmt == "md":
        return Response(report.to_markdown(s, f), media_type="text/markdown", headers={"Content-Disposition": f"attachment; filename={name}.md"})
    if fmt == "html":
        return Response(report.to_html(s, f), media_type="text/html", headers={"Content-Disposition": f"attachment; filename={name}.html"})
    raise HTTPException(400, "format must be json|csv|md|html")


# ------------------------------------------------------------------ AI assist
@app.post("/api/findings/{fid}/advise", dependencies=[Depends(auth)])
def ai_advise(fid: str, body: AdviceIn):
    f = db.get_finding(fid)
    if not f:
        raise HTTPException(404)
    try:
        f["ai_advice"] = llm.advise_finding(f, body.context or None)
    except llm.LLMUnavailable as e:
        raise HTTPException(503, str(e))
    db.update_finding(fid, f)
    return {"advice": f["ai_advice"]}


@app.post("/api/findings/{fid}/manual-check", dependencies=[Depends(auth)])
def ai_manual_check(fid: str):
    """Ask Claude for a hand-run manual check (benign-probe PoC) for one finding. Code is only sent if allowed."""
    f = db.get_finding(fid)
    if not f:
        raise HTTPException(404)
    try:
        f["manual_check"] = llm.manual_check_for(f)
    except llm.LLMUnavailable as e:
        raise HTTPException(503, str(e))
    db.update_finding(fid, f)
    return {"manual_check": f["manual_check"]}


@app.post("/api/scans/{sid}/ai-review", dependencies=[Depends(auth)])
def ai_review(sid: str):
    """Start the AI review of a code or web scan (runs in the background; poll the scan for ai_review_status)."""
    s = db.get_scan(sid)
    if not s or s["kind"] not in ("code", "web"):
        raise HTTPException(404, "code or web scan not found")
    if s["status"] in ("queued", "running"):
        raise HTTPException(409, "wait for the scan to finish first")
    st = (s.get("summary") or {}).get("ai_review_status") or {}
    if st.get("state") in ("queued", "running"):
        raise HTTPException(409, "an AI review is already running for this scan")
    if s["kind"] == "code" and not (s.get("summary") or {}).get("source_dir"):
        raise HTTPException(400, "the source for this scan was not kept or was deleted; upload the archive again")
    if s["kind"] == "web" and not (s.get("summary") or {}).get("snapshot_dir"):
        raise HTTPException(400, "this scan has no saved crawl data (made before this feature, or deleted); re-scan the target")
    if not llm.status()["enabled"] or db.get_setting("llm").get("provider") != "anthropic":
        raise HTTPException(400, "connect Claude first: Settings -> AI assist")
    if not db.get_setting("llm").get("send_code"):
        raise HTTPException(400, "allow sending source code and crawled pages to your Claude connection first: Settings -> AI assist")
    jobs.start_ai_review(sid)
    return {"started": True}


@app.delete("/api/scans/{sid}/source", dependencies=[Depends(auth)])
def delete_source(sid: str):
    return {"deleted": jobs.remove_source(sid)}


# ------------------------------------------------------------------ settings / feeds
@app.get("/api/settings", dependencies=[Depends(auth)])
def get_settings():
    return {**db.all_settings(), "llm_status": llm.status(), "auth_enabled": bool(_USER)}


@app.put("/api/settings", dependencies=[Depends(auth)])
def put_settings(body: SettingsIn):
    for k, v in body.model_dump(exclude_none=True).items():
        if k == "llm":
            v = llm.scrub(v)  # never persist keys/tokens
        db.set_setting(k, {**db.get_setting(k), **v})
    return db.all_settings()


@app.get("/api/llm/options", dependencies=[Depends(auth)])
def llm_options():
    return llm.options()


@app.post("/api/llm/test", dependencies=[Depends(auth)])
def llm_test(body: Optional[dict[str, Any]] = None):
    """Try the given (unsaved) AI settings with a one-line prompt. Runs in a worker thread (sync def)."""
    return llm.test_connection(body or {})


@app.put("/api/scope", dependencies=[Depends(auth)])
def put_scope(body: ScopeIn):
    clean = lambda xs: [x.strip() for x in xs if x.strip()]  # noqa: E731
    db.set_setting("scope", {"allow": clean(body.allow), "deny": clean(body.deny)})
    return db.get_setting("scope")


@app.get("/api/scope/check", dependencies=[Depends(auth)])
def check_scope(url: str):
    u = url if "://" in url else f"https://{url}"
    try:
        scope.check(u)
        return {"in_scope": True}
    except scope.OutOfScope as e:
        return {"in_scope": False, "reason": str(e)}


@app.get("/api/feeds", dependencies=[Depends(auth)])
def feed_status(check: bool = False):
    out = {"snapshot": feeds.snapshot_info(), "active": EOL_DB.meta}
    if check:
        out["connectivity"] = feeds.connectivity()
    return out


@app.post("/api/feeds/sync", dependencies=[Depends(auth)])
def feed_sync():
    try:
        path, n = feeds.build_snapshot()
    except Exception as e:
        raise HTTPException(502, f"sync failed (offline?): {e}")
    EOL_DB.reload()
    return {"products": n, "path": str(path), "active": EOL_DB.meta}


@app.get("/api/eol/lookup", dependencies=[Depends(auth)])
def eol_lookup(product: str, version: str = ""):
    return EOL_DB.lookup(product, version or None)


@app.get("/api/eol/products", dependencies=[Depends(auth)])
def eol_products():
    return EOL_DB.product_list()


@app.get("/api/health")
def health():
    return {"ok": True, "eol_products": EOL_DB.meta.get("products")}


# ------------------------------------------------------------------ UI
STATIC = APP_DIR / "static"
app.mount("/static", StaticFiles(directory=STATIC), name="static")


@app.get("/", include_in_schema=False, dependencies=[Depends(auth)])
def index():
    return FileResponse(STATIC / "index.html")


@app.exception_handler(scope.OutOfScope)
def _oos(_req, exc):
    return JSONResponse({"detail": str(exc)}, status_code=403)
