"""Core safety/logic tests. Run: python -m pytest tests  (or: python tests/test_core.py)"""
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


if __name__ == "__main__":
    for name, fn in list(globals().items()):
        if name.startswith("test_"):
            fn()
            print("ok", name)
