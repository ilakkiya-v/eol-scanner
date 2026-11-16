"""Core safety/logic tests. Run: python -m pytest tests  (or: python tests/test_core.py)"""
import json
import os
import pathlib
import sys
import tempfile
import zipfile

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
os.environ.setdefault("EOLSCAN_DATA", tempfile.mkdtemp())

from app import scope  # noqa: E402
from app.eol.database import EOL_DB  # noqa: E402
from app.scanners import manifests  # noqa: E402
from app.scanners.code import ArchiveError, safe_extract  # noqa: E402
from app.scanners.fingerprints import match_headers, match_js  # noqa: E402


def test_zip_traversal_blocked():
    d = pathlib.Path(tempfile.mkdtemp())
    z = d / "evil.zip"
    with zipfile.ZipFile(z, "w") as zf:
        zf.writestr("../../escape.txt", "x")
    try:
        safe_extract(z, d / "out")
        assert False, "traversal allowed"
    except ArchiveError:
        pass


def test_zip_symlink_skipped():
    d = pathlib.Path(tempfile.mkdtemp())
    z = d / "link.zip"
    with zipfile.ZipFile(z, "w") as zf:
        info = zipfile.ZipInfo("link")
        info.external_attr = 0o120777 << 16
        zf.writestr(info, "/etc/passwd")
        zf.writestr("a.txt", "a")
    assert safe_extract(z, d / "out") == 1
    assert os.listdir(d / "out") == ["a.txt"]


def test_scope_rules():
    rules = {"allow": ["*.qa.corp", "10.20.0.0/16", "app.lab.corp:8443"], "deny": ["db.qa.corp"]}
    assert scope.in_scope("https://x.qa.corp", rules)
    assert not scope.in_scope("https://qa.corp", rules)
    assert not scope.in_scope("https://db.qa.corp", rules)          # deny wins
    assert scope.in_scope("http://10.20.3.4:8080", rules)
    assert scope.in_scope("https://app.lab.corp:8443/x", rules)
    assert not scope.in_scope("https://app.lab.corp/", rules)       # wrong port
    assert not scope.in_scope("https://anything", {"allow": [], "deny": []})  # empty = block all


def test_eol_lookup():
    assert EOL_DB.lookup("angularjs", "1.5.8")["status"] == "eol"
    assert EOL_DB.lookup("php", "5.6.40")["status"] == "eol"
    assert EOL_DB.lookup("java", "1.8.0_292")["cycle"] == "8"
    assert EOL_DB.lookup("iis", "7.5")["status"] == "eol"  # curated
    assert not EOL_DB.lookup("not-a-product", "1")["known_product"]


def test_fingerprints():
    comps = match_headers([("Server", "Apache/2.2.15 (CentOS)"), ("X-Powered-By", "PHP/5.6.40")], "u")
    assert {(c.product, c.version) for c in comps} >= {("apache-http-server", "2.2.15"), ("php", "5.6.40")}
    js = match_js("/*! jQuery v1.12.4 | (c) jQuery Foundation */", "jquery.min.js")
    assert js[0].product == "jquery" and js[0].version == "1.12.4"


def test_manifests():
    pom = """<project><properties><v>2.14.1</v></properties><dependencies><dependency>
      <groupId>org.apache.logging.log4j</groupId><artifactId>log4j-core</artifactId><version>${v}</version></dependency></dependencies></project>"""
    c = manifests.parse_pom("pom.xml", pom)[0]
    assert (c.product, c.version, c.package) == ("log4j", "2.14.1", "org.apache.logging.log4j:log4j-core")
    d = manifests.parse_dockerfile("Dockerfile", "FROM python:2.7-slim-stretch\n")
    assert ("python", "2.7") in {(x.product, x.version) for x in d} and ("debian", "9") in {(x.product, x.version) for x in d}
    t = manifests.parse_csproj("a.csproj", "<TargetFramework>netcoreapp2.1</TargetFramework>")
    assert (t[0].product, t[0].version) == ("dotnet", "2.1")


def test_llm_settings_and_models():
    from app.advisor import llm
    assert llm.scrub({"platform": "gateway", "api_key": "x", "auth_token": "y", "aws_secret": "z"}) == {"platform": "gateway"}
    assert llm.model_for({"platform": "bedrock", "model": "claude-mythos-5-2"}) == "anthropic.claude-mythos-5-2"
    assert llm.model_for({"platform": "bedrock", "model": "us.anthropic.claude-opus-5-5"}) == "us.anthropic.claude-opus-5-5"
    assert llm.model_for({"platform": "bedrock", "model": "arn:aws:bedrock:x"}).startswith("arn:")
    assert llm.model_for({"platform": "anthropic", "model": "claude-mythos-5-2"}) == "claude-mythos-5-2"


def test_llm_gateway_retry_without_fallback():
    """A strict gateway that rejects the fallback beta still works (plain-request retry), with a Bearer token."""
    try:
        import anthropic  # noqa: F401
    except ImportError:
        print("skip: anthropic SDK not installed")
        return
    import threading
    from http.server import ThreadingHTTPServer
    sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
    import fake_gateway
    from app.advisor import llm
    srv = ThreadingHTTPServer(("127.0.0.1", 0), fake_gateway.H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    old = {k: os.environ.pop(k, None) for k in ("ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN")}
    os.environ["ANTHROPIC_AUTH_TOKEN"] = "test-token"
    try:
        cfg = {"provider": "anthropic", "platform": "gateway", "model": "claude-mythos-5-2",
               "base_url": f"http://127.0.0.1:{srv.server_port}"}
        r = llm.test_connection(cfg)
        assert r["ok"] and r["reply"] == "OK", r
        assert fake_gateway.SEEN[-1]["beta"] is None and fake_gateway.SEEN[-1]["model"] == "claude-mythos-5-2"
        r = llm.test_connection({**cfg, "base_url": ""})
        assert not r["ok"] and "gateway URL" in r["error"]
    finally:
        srv.shutdown()
        for k, v in old.items():
            os.environ.pop(k, None)
            if v is not None:
                os.environ[k] = v


def test_llm_missing_cloud_config_is_friendly():
    try:
        import anthropic  # noqa: F401
    except ImportError:
        return
    from app.advisor import llm
    saved = {k: os.environ.pop(k, None) for k in ("AWS_REGION", "AWS_DEFAULT_REGION", "ANTHROPIC_AWS_WORKSPACE_ID",
                                                   "ANTHROPIC_FOUNDRY_RESOURCE", "ANTHROPIC_FOUNDRY_BASE_URL")}
    try:
        for plat in ("aws", "foundry"):
            r = llm.test_connection({"provider": "anthropic", "platform": plat})
            assert not r["ok"] and r["error"], (plat, r)
    finally:
        for k, v in saved.items():
            if v is not None:
                os.environ[k] = v


def test_code_injection_rules():
    from app.scanners import code
    fx = pathlib.Path(__file__).resolve().parent / "fixtures" / "legacyapp"
    r = code.scan_tree(fx, lambda m: None, lambda p, m="": None, lambda: False)
    rules = {f["rule"] for f in r.findings}
    for want in ("sqli-java-concat", "sqli-php-var", "sqli-python-format", "sqli-node-template", "sqli-dotnet-concat",
                 "cmdi-java", "cmdi-php", "cmdi-node", "cmdi-python", "xss-php-echo", "xss-asp-write", "xss-dom-sink",
                 "path-traversal-php-include", "path-traversal-file", "ssrf", "open-redirect", "xxe-java-default"):
        assert want in rules, want
    flagged = [l["path"] for f in r.findings for l in f["locations"]]
    assert not [x for x in flagged if x.endswith("safe.js")], "safe patterns were flagged"
    assert not [x for x in flagged if "vendor/" in x and x.endswith(".min.js") and "xss" in x], "vendored lib flagged"
    for f in r.findings:  # no duplicate locations
        locs = [(l["path"], l["line"]) for l in f["locations"]]
        assert len(locs) == len(set(locs)), f["rule"]


def test_importers():
    from app import importers
    d = pathlib.Path(__file__).resolve().parent / "fixtures" / "imports"
    expect = {"zap.json": ("OWASP ZAP", {"sql-injection", "security-headers"}), "zap.xml": ("OWASP ZAP", {"xss"}),
              "burp.xml": ("Burp Suite", {"xss", "cookie-flags"}), "semgrep.json": ("Semgrep", {"sql-injection", "command-injection"}),
              "codeql.sarif": ("CodeQL (SARIF)", {"path-traversal", "ssrf"}), "nuclei.jsonl": ("Nuclei", {"path-traversal", "imported"})}
    for name, (tool, kbs) in expect.items():
        t, fs = importers.parse((d / name).read_bytes(), name)
        assert t == tool and {f["kb"] for f in fs} == kbs, (name, t, {f["kb"] for f in fs})
    try:
        importers.parse(b'<?xml version="1.0"?><!DOCTYPE x [<!ENTITY a "b">]><issues/>')
        assert False, "entity XML accepted"
    except importers.ImportError_:
        pass


def _serve_fake_target():
    import threading
    from http.server import ThreadingHTTPServer
    sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
    import fake_target
    srv = ThreadingHTTPServer(("127.0.0.1", 0), fake_target.H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


def test_web_hygiene_checks():
    import asyncio
    from app.scanners.web import WebScanner
    srv = _serve_fake_target()
    try:
        sc = WebScanner(f"http://127.0.0.1:{srv.server_port}", "safe", {"rate_per_sec": 100, "max_pages": 10},
                        {"allow": ["127.0.0.1"], "deny": []}, lambda m: None, lambda p, m="": None, lambda: False)
        r = asyncio.run(sc.run())
        kbs = {f["kb"]: f for f in r.findings}
        assert {"security-headers", "cookie-flags", "cors", "cleartext-login"} <= set(kbs), set(kbs)
        assert kbs["cors"]["severity"] == "high"
    finally:
        srv.shutdown()


def test_browser_crawl_scoped():
    from app.scanners import browser
    if not browser.available():
        print("skip: playwright not installed")
        return
    import asyncio
    from app.scanners.web import WebScanner
    srv = _serve_fake_target()
    logs = []
    try:
        sc = WebScanner(f"http://127.0.0.1:{srv.server_port}", "passive", {"rate_per_sec": 100, "max_pages": 6, "render_js": True},
                        {"allow": ["127.0.0.1"], "deny": []}, logs.append, lambda p, m="": None, lambda: False)
        r = asyncio.run(sc.run())
        if any("Chromium is not installed" in l for l in logs):
            print("skip: chromium not installed")
            return
        found = {(c.product, c.version) for c in r.components if c.source == "browser"}
        assert ("vue", "2.5.17") in found, found
        assert any("blocked out-of-scope request" in l for l in logs), "CDN requests were not blocked"
    finally:
        srv.shutdown()


def test_zip_windows_unsafe_names_skipped():
    d = pathlib.Path(tempfile.mkdtemp())
    z = d / "win.zip"
    with zipfile.ZipFile(z, "w") as zf:
        for bad in ("NUL", "dir/con.txt", "a.txt:hidden", "trail.", "sp /x.txt"):
            zf.writestr(bad, "x")
        zf.writestr("ok/fine.txt", "ok")
    safe_extract(z, d / "out")
    got = sorted(str(p.relative_to(d / "out")).replace(os.sep, "/") for p in (d / "out").rglob("*") if p.is_file())
    assert got == ["ok/fine.txt"], got


def test_llm_missing_key_message_is_friendly():
    try:
        import anthropic  # noqa: F401
    except ImportError:
        return
    from app.advisor import llm
    saved = {k: os.environ.pop(k, None) for k in ("ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN")}
    try:
        r = llm.test_connection({"provider": "anthropic", "platform": "anthropic"})
        assert not r["ok"] and "ANTHROPIC_API_KEY" in r["error"] and "TypeError" not in r["error"], r
    finally:
        for k, v in saved.items():
            if v is not None:
                os.environ[k] = v


def test_code_findings_have_review_steps():
    from app import analysis
    f = analysis.enrich_raw([{"category": "code", "kb": "sql-injection", "severity": "high", "title": "t"}])[0]
    assert len(f["review_steps"]) >= 5 and f["manual_tests"]
    w = analysis.enrich_raw([{"category": "config", "kb": "cors", "severity": "high", "title": "t"}])[0]
    assert "review_steps" not in w


def test_routes_map_findings_to_entry_points():
    from app.scanners import routes
    java = 'import x;\n@RequestMapping("/api/r")\npublic class C {\n  @GetMapping("/find")\n  Object f(@RequestParam("owner") String o) {\n    q("SELECT " + o);\n  }\n}'
    ep = routes.entry_point("C.java", java, 6)
    assert ep["path"] == "/api/r/find" and ep["params"] == ["owner"], ep
    assert routes.entry_point("src/main/webapp/a/b.jsp", 'x\n<%= request.getParameter("q") %>', 2)["path"] == "/a/b.jsp"


def _fake_source():
    d = pathlib.Path(tempfile.mkdtemp()) / "src"
    (d / "app").mkdir(parents=True)
    (d / "app" / "views.py").write_text("def search(request, cur):\n    cur.execute(\"SELECT * FROM t WHERE n='%s'\" % request.GET['n'])\n")
    return d


def test_ai_review_api_tool_loop():
    try:
        import anthropic  # noqa: F401
    except ImportError:
        return
    from types import SimpleNamespace as NS
    from app import db
    from app.advisor import code_review_ai
    src = _fake_source()
    script = [
        [NS(type="tool_use", id="t1", name="list_files", input={"glob": "**/*.py"})],
        [NS(type="tool_use", id="t2", name="read_file", input={"path": "app/views.py"}),
         NS(type="tool_use", id="t3", name="read_file", input={"path": "../../etc/passwd"})],
        [NS(type="tool_use", id="t4", name="report_finding", input={
            "title": "SQL injection in search", "severity": "high", "cwe": "CWE-89", "file": "app/views.py", "line": 2,
            "entry_point": {"method": "GET", "path": "/search", "params": ["n"]}, "data_flow": "request.GET['n'] -> cur.execute",
            "description": "string formatting into SQL", "confidence": "high",
            "verification": ["Send a request with a single quote in n and look for a database error"],
            "containment": ["Allowlist n at the proxy"]}),
         NS(type="tool_use", id="t5", name="lead_verdict", input={"lead_id": "L1", "verdict": "confirmed", "reason": "reachable"})],
        [NS(type="text", text="Summary: one confirmed SQL injection.")],
    ]
    seen = []

    class FakeMessages:
        def create(self, **kw):
            seen.append({**kw, "messages": list(kw["messages"])})
            content = script[len(seen) - 1]
            stop = "tool_use" if any(b.type == "tool_use" for b in content) else "end_turn"
            return NS(content=content, stop_reason=stop, usage=NS(input_tokens=100, cache_read_input_tokens=0, cache_creation_input_tokens=0))

    orig = code_review_ai._client
    code_review_ai._client = lambda cfg: NS(messages=FakeMessages())
    db.set_setting("llm", {**db.get_setting("llm"), "provider": "anthropic", "platform": "anthropic", "send_code": True})
    try:
        scan = {"summary": {"source_dir": str(src), "inventory": [{"product": "django", "version": "1.11", "status": "eol", "vulns": 7}], "languages": {"Python": 1}}}
        leads = [{"id": "f1", "category": "code", "severity": "high", "title": "SQL query built with string formatting",
                  "locations": [{"path": "app/views.py", "line": 2}]}]
        res = code_review_ai.review(scan, leads, lambda m: None, lambda: False)
    finally:
        code_review_ai._client = orig
    assert len(res["findings"]) == 1 and res["findings"][0]["kb"] == "sql-injection"
    assert res["findings"][0]["entry_point"]["path"] == "/search" and res["findings"][0]["verification_steps"]
    assert res["verdicts"] == {"f1": {"verdict": "confirmed", "reason": "reachable"}}
    assert "one confirmed" in res["summary"]
    # tool results went back with matching ids; path traversal was refused as a tool error
    results = seen[2]["messages"][-1]["content"]
    assert [r["tool_use_id"] for r in results] == ["t2", "t3"]
    assert "cur.execute" in results[0]["content"] and results[1].get("is_error")
    assert seen[0].get("cache_control") == {"type": "ephemeral"}


def test_ai_review_claude_code_engine():
    import stat
    from app import db
    from app.advisor import code_review_ai
    src = _fake_source()
    tmp = pathlib.Path(tempfile.mkdtemp())
    record = tmp / "record.json"
    cli = tmp / "claude"
    cli.write_text(f"""#!{sys.executable}
import json, sys
prompt = sys.stdin.read()
json.dump({{"argv": sys.argv[1:], "prompt_len": len(prompt), "cwd": __import__("os").getcwd(),
           "has_key": "ANTHROPIC_API_KEY" in __import__("os").environ}}, open({str(record)!r}, "w"))
out = {{"findings": [{{"title": "Command injection in backup", "severity": "critical", "cwe": "CWE-78", "file": "app/views.py",
        "line": 2, "verification": ["check"], "containment": ["isolate"]}}],
       "verdicts": [{{"lead_id": "L1", "verdict": "likely false positive", "reason": "constant"}}], "summary": "done"}}
print(json.dumps({{"type": "system", "subtype": "init", "model": "claude-mythos-5-2"}}))
print(json.dumps({{"type": "assistant", "message": {{"content": [{{"type": "tool_use", "name": "Read", "input": {{"file_path": "app/views.py"}}}}]}}}}))
print(json.dumps({{"type": "result", "result": "```json\\n" + json.dumps(out) + "\\n```", "num_turns": 3, "total_cost_usd": 0.42}}))
""")
    cli.chmod(cli.stat().st_mode | stat.S_IEXEC)
    if os.name == "nt":
        return  # shebang scripts don't run on Windows; the engine itself is covered on macOS/Linux
    db.set_setting("llm", {**db.get_setting("llm"), "provider": "anthropic", "platform": "claude_code", "send_code": True,
                           "claude_cli": str(cli), "model": "claude-mythos-5-2"})
    os.environ["ANTHROPIC_API_KEY"] = "should-not-leak"
    try:
        scan = {"summary": {"source_dir": str(src), "inventory": []}}
        leads = [{"id": "f9", "category": "code", "severity": "medium", "title": "x", "locations": [{"path": "app/views.py", "line": 2}]}]
        logs = []
        res = code_review_ai.review(scan, leads, logs.append, lambda: False)
    finally:
        os.environ.pop("ANTHROPIC_API_KEY", None)
    rec = json.loads(record.read_text())
    argv = rec["argv"]
    assert argv[argv.index("--allowedTools") + 1: argv.index("--allowedTools") + 4] == ["Read", "Grep", "Glob"]
    assert "Bash" in argv and "Edit" in argv and "WebFetch" in argv  # in --disallowedTools
    assert argv[argv.index("--model") + 1] == "claude-mythos-5-2"
    assert rec["prompt_len"] > 500 and not rec["has_key"] and pathlib.Path(rec["cwd"]).resolve() == src.resolve()
    assert res["findings"][0]["kb"] == "command-injection" and res["model"] == "claude-mythos-5-2" and res["cost_usd"] == 0.42
    assert res["verdicts"] == {"f9": {"verdict": "likely false positive", "reason": "constant"}}
    assert any("Read app/views.py" in l for l in logs)


def test_passive_traffic_analysis():
    from app import importers
    from app.scanners import passive
    d = pathlib.Path(__file__).resolve().parent / "fixtures" / "imports"
    for name in ("burp-items.xml", "traffic.har"):
        data = (d / name).read_bytes()
        kind = importers.recorded_traffic_kind(data)
        assert kind in ("burp-items", "har"), name
        entries = passive.read_burp_items(data) if kind == "burp-items" else passive.read_har(json.loads(data))
        res, hosts = passive.analyze(entries, lambda m: None)
        comps = {(c.product, c.version) for c in res.components}
        assert {("apache-http-server", "2.2.15"), ("jquery", "1.12.4"), ("php", "5.6.40")} <= comps, (name, comps)
        kbs = {f["kb"] for f in res.findings}
        assert {"security-headers", "cookie-flags", "cors", "cleartext-login", "exposed-manifest"} <= kbs, (name, kbs)
    assert importers.recorded_traffic_kind((d / "burp.xml").read_bytes()) is None


def test_batch_scope_and_combined_report():
    from app import db, jobs, report
    db.set_setting("scope", {"allow": ["127.0.0.1"], "deny": []})
    r = jobs.start_batch(["https://not-allowed.example", "https://also-not.example"], "passive", "t", "", {})
    assert not r["started"] and len(r["skipped"]) == 2
    scans = [{"id": "a", "target": "https://a.lab", "status": "done", "kind": "web", "mode": "safe",
              "summary": {"severity_counts": {"high": 1}, "eol_components": 1}},
             {"id": "b", "target": "https://b.lab", "status": "done", "kind": "web", "mode": "safe",
              "summary": {"severity_counts": {}, "eol_components": 1}}]
    f = {"severity": "high", "category": "eol", "title": "php 5.6 is end-of-life", "product": "php", "version": "5.6",
         "lifecycle": {"status": "eol"}}
    md = report.combined(scans, {"a": [f], "b": [dict(f)]}, "md")
    assert "| php 5.6 | https://a.lab, https://b.lab |" in md and "## EOL assessment: https://a.lab" in md
    assert report.combined(scans, {"a": [f], "b": []}, "csv").count("\n") == 2


if __name__ == "__main__":
    for name, fn in list(globals().items()):
        if name.startswith("test_"):
            fn()
            print("ok", name)
