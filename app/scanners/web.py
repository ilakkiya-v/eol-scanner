"""Live web application scanner: fingerprint -> version -> lifecycle.

Every outbound request goes through `_request`, which enforces the scope
allowlist (including on each redirect hop), a global rate limit, and a
request budget.
"""
from __future__ import annotations

import asyncio
import hashlib
import os
import re
import socket
import ssl
import tempfile
import time
import uuid
from dataclasses import dataclass, field
from typing import Callable, Optional
from urllib.parse import urljoin, urlsplit, urlunsplit

import httpx
from bs4 import BeautifulSoup

from .. import scope
from ..config import USER_AGENT
from . import browser, manifests, probes
from .fingerprints import Component, match_headers, match_html, match_js, match_js_url


@dataclass
class WebScanResult:
    components: list[Component] = field(default_factory=list)
    findings: list[dict] = field(default_factory=list)
    pages: list[str] = field(default_factory=list)
    scripts: list[str] = field(default_factory=list)
    requests: int = 0
    tls: dict = field(default_factory=dict)
    api_endpoints: list[str] = field(default_factory=list)


def _origin(url: str) -> str:
    p = urlsplit(url)
    return f"{p.scheme}://{p.netloc}".lower()


def _strip_fragment(url: str) -> str:
    p = urlsplit(url)
    return urlunsplit((p.scheme, p.netloc, p.path or "/", p.query, ""))


class WebScanner:
    def __init__(self, target: str, mode: str, options: dict, rules: dict,
                 log: Callable[[str], None], progress: Callable[[float, str], None],
                 cancelled: Callable[[], bool]):
        self.target = target if "://" in target else f"https://{target}"
        self.mode = mode  # passive | safe | active
        self.opt = options
        self.rules = rules
        self.log, self.progress, self.cancelled = log, progress, cancelled
        self.res = WebScanResult()
        self._last = 0.0
        self.interval = 1.0 / max(0.2, float(options.get("rate_per_sec", 5)))
        self.max_requests = int(options.get("max_requests", 1500))
        self.baseline: Optional[dict] = None
        self._pages_seen: list[tuple[str, httpx.Headers]] = []  # (url, headers) of crawled HTML pages
        self._cookies: dict[str, tuple[str, str]] = {}          # cookie name -> (Set-Cookie value, url)
        self._cleartext_forms: list[str] = []

    # ------------------------------------------------------------ transport
    async def _request(self, method: str, url: str, max_bytes: int = 3_000_000,
                       headers: Optional[dict] = None) -> Optional[httpx.Response]:
        hops = 0
        while True:
            if self.cancelled():
                return None
            try:
                scope.check(url, self.rules)
            except scope.OutOfScope as e:
                self.log(f"skip (out of scope): {url} - {e}")
                return None
            if self.res.requests >= self.max_requests:
                return None
            async with self._rate_lock:
                wait = self._last + self.interval - time.monotonic()
                if wait > 0:
                    await asyncio.sleep(wait)
                self._last = time.monotonic()
            self.res.requests += 1
            try:
                async with self.sem:
                    req = self.client.build_request(method, url, headers=headers)
                    r = await self.client.send(req, stream=True)
                    body = b""
                    if method != "HEAD":
                        async for chunk in r.aiter_bytes():
                            body += chunk
                            if len(body) > max_bytes:
                                break
                    await r.aclose()
                    r._content = body  # noqa: SLF001 - store truncated body
            except (httpx.HTTPError, ssl.SSLError, OSError) as e:
                self.log(f"{method} {url} failed: {type(e).__name__}: {e}")
                return None
            if r.is_redirect and hops < 5 and method in ("GET", "HEAD"):
                loc = r.headers.get("location")
                if not loc:
                    return r
                url = urljoin(url, loc)
                hops += 1
                continue
            return r

    # ------------------------------------------------------------ helpers
    def _add(self, comps: list[Component]) -> None:
        self.res.components.extend(comps)

    def _finding(self, **kw) -> None:
        kw.setdefault("id", uuid.uuid4().hex[:12])
        self.res.findings.append(kw)

    async def _baseline(self) -> None:
        url = urljoin(self.target, f"/eolscan-{uuid.uuid4().hex[:10]}.html")
        r = await self._request("GET", url)
        if r is None:
            return
        body = r.content or b""
        self.baseline = {"status": r.status_code, "len": len(body), "hash": hashlib.sha1(body).hexdigest()}
        text = body.decode("utf-8", "ignore")
        self._add(match_headers(r.headers.multi_items(), url))
        comps = match_html(text, url)
        for c in comps:
            c.source = "error-page"
        self._add(comps)
        if self.mode != "passive":
            # Error pages often reveal exact versions (Tomcat/Jetty/IIS defaults)
            self.log(f"baseline 404: status={r.status_code} len={len(body)}")

    def _looks_like_baseline(self, r: httpx.Response) -> bool:
        if not self.baseline:
            return False
        body = r.content or b""
        if hashlib.sha1(body).hexdigest() == self.baseline["hash"]:
            return True
        if r.status_code == self.baseline["status"] and self.baseline["len"] and \
                abs(len(body) - self.baseline["len"]) / max(1, self.baseline["len"]) < 0.03:
            return True
        return False

    # ------------------------------------------------------------ crawl
    async def _crawl(self) -> None:
        start = _strip_fragment(self.target)
        origin = _origin(start)
        queue, seen, scripts_seen = [start], {start}, set()
        max_pages = int(self.opt.get("max_pages", 30))
        script_jobs = []
        while queue and len(self.res.pages) < max_pages and not self.cancelled():
            url = queue.pop(0)
            r = await self._request("GET", url)
            if r is None:
                continue
            self.res.pages.append(str(r.url))
            self._add(match_headers(r.headers.multi_items(), str(r.url)))
            self._observe_cookies(r)
            ctype = r.headers.get("content-type", "")
            if "html" not in ctype and not (r.content or b"").lstrip()[:15].lower().startswith((b"<!doctype", b"<html")):
                continue
            html = (r.content or b"").decode("utf-8", "ignore")
            self._add(match_html(html, str(r.url)))
            self._pages_seen.append((str(r.url), r.headers))
            soup = BeautifulSoup(html, "html.parser")
            self._check_forms(soup, str(r.url))
            for s in soup.find_all("script"):
                src = s.get("src")
                if src:
                    full = _strip_fragment(urljoin(str(r.url), src))
                    if full in scripts_seen:
                        continue
                    scripts_seen.add(full)
                    self.res.scripts.append(full)
                    self._add(match_js_url(full))
                    if _origin(full) == origin or scope.in_scope(full, self.rules):
                        script_jobs.append(full)
                elif s.string:
                    self._add(match_js(s.string, "", f"{r.url} (inline script)"))
            for l in soup.find_all("link", href=True):
                full = _strip_fragment(urljoin(str(r.url), l["href"]))
                if full.endswith(".css") or "stylesheet" in (l.get("rel") or []):
                    self._add(match_js_url(full))  # bootstrap/font-awesome versions in CSS URLs
            for a in soup.find_all("a", href=True):
                full = _strip_fragment(urljoin(str(r.url), a["href"]))
                if _origin(full) == origin and full not in seen and not re.search(
                        r"\.(?:png|jpe?g|gif|svg|ico|pdf|zip|gz|mp4|woff2?|ttf|css|js)(?:\?|$)|logout|signout|delete|remove", full, re.I):
                    seen.add(full)
                    queue.append(full)
            self.progress(0.05 + 0.35 * len(self.res.pages) / max_pages, f"crawled {len(self.res.pages)} pages")

        max_scripts = int(self.opt.get("max_scripts", 80))

        async def fetch_script(u: str) -> None:
            r = await self._request("GET", u)
            if r is not None and r.status_code == 200:
                self._add(match_js((r.content or b"").decode("utf-8", "ignore"), urlsplit(u).path, u))

        await asyncio.gather(*(fetch_script(u) for u in script_jobs[:max_scripts]))
        self.log(f"crawl done: {len(self.res.pages)} pages, {len(self.res.scripts)} scripts")

    # ------------------------------------------------------------ probes
    async def _run_probe(self, p: dict) -> None:
        url = urljoin(self.target, p["path"])
        r = await self._request(p["method"], url)
        if r is None or r.status_code >= 500 or r.status_code in (404, 410):
            return
        if p["method"] == "HEAD":
            ct = r.headers.get("content-type", "")
            if r.status_code != 200 or "html" in ct or "json" in ct:
                return
            body = ""
        else:
            if self._looks_like_baseline(r):
                return
            body = (r.content or b"").decode("utf-8", "ignore")
            if not re.search(p["match"], body, re.I | re.M):
                return
        evidence = "(redacted - sensitive content)" if p["redact"] else body[:400]
        comps: list[Component] = []
        if p["parse_as"]:
            parser = manifests.parser_for(p["parse_as"])
            try:
                comps = parser(url, body) if parser else []
            except Exception as e:  # malformed file
                self.log(f"parse {url}: {e}")
            for c in comps:
                c.source = "exposed-file"
        if p["product"]:
            ver = None
            if p["version_rx"]:
                m = re.search(p["version_rx"], body, re.I | re.M)
                ver = m.group(1) if m else None
            comps.append(Component(p["product"], ver, evidence=f"{p['title']}: {(ver or 'version not shown')}",
                                   location=url, confidence="high" if ver else "low", source="probe"))
        comps += match_headers(r.headers.multi_items(), url)
        self._add(comps)
        if p["severity"] != "info":
            self._finding(category=p["category"], severity=p["severity"], title=p["title"], kb=p["kb"],
                          location=url, status=r.status_code, evidence=evidence,
                          detail=f"{len(comps)} component(s) identified from this response" if comps else "")
        else:
            self.log(f"info: {p['title']} at {url}")

    async def _probes(self) -> None:
        plist = list(probes.SAFE)
        if self.mode == "active":
            plist += probes.ACTIVE
        done = 0

        async def run(p):
            nonlocal done
            await self._run_probe(p)
            done += 1
            self.progress(0.45 + 0.4 * done / len(plist), f"probes {done}/{len(plist)}")

        await asyncio.gather(*(run(p) for p in plist))

    # ------------------------------------------------------------ active extras
    async def _http_methods(self) -> None:
        r = await self._request("OPTIONS", self.target)
        if r is not None and r.headers.get("allow"):
            allow = r.headers["allow"].upper()
            risky = [m for m in ("PUT", "DELETE", "TRACE", "PROPFIND", "MKCOL", "COPY", "MOVE") if m in allow]
            if risky:
                self._finding(category="config", severity="medium", title=f"Risky HTTP methods advertised: {', '.join(risky)}",
                              kb="http-methods", location=self.target, evidence=f"Allow: {r.headers['allow']}")
        r = await self._request("TRACE", self.target)
        if r is not None and r.status_code == 200 and b"TRACE /" in (r.content or b"")[:200]:
            self._finding(category="config", severity="medium", title="HTTP TRACE enabled (Cross-Site Tracing)",
                          kb="http-methods", location=self.target, evidence=(r.content or b"")[:200].decode("utf-8", "ignore"))

    async def _dir_listing(self) -> None:
        dirs = set()
        for s in self.res.scripts:
            if _origin(s) == _origin(self.target):
                path = urlsplit(s).path.rsplit("/", 1)[0] + "/"
                if path != "/":
                    dirs.add(urljoin(self.target, path))
        for d in list(dirs)[:10]:
            r = await self._request("GET", d)
            if r is not None and r.status_code == 200 and re.search(rb"<title>Index of /|Directory Listing For|\[To Parent Directory\]", r.content or b"", re.I):
                self._finding(category="exposure", severity="medium", title="Directory listing enabled", kb="directory-listing",
                              location=d, evidence=(r.content or b"")[:300].decode("utf-8", "ignore"))
                self._add(match_html((r.content or b"").decode("utf-8", "ignore"), d))

    def _tls_info(self) -> dict:
        p = urlsplit(self.target)
        if p.scheme != "https":
            return {}
        host, port = p.hostname, p.port or 443
        info: dict = {"host": host, "port": port}
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        try:
            with socket.create_connection((host, port), timeout=8) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as ss:
                    info["protocol"] = ss.version()
                    info["cipher"] = ss.cipher()[0] if ss.cipher() else None
                    der = ss.getpeercert(binary_form=True)
            if der:
                # Windows can't reopen a NamedTemporaryFile by name while it is open, so close it first.
                f = tempfile.NamedTemporaryFile("w", suffix=".pem", delete=False, encoding="ascii")
                try:
                    with f:
                        f.write(ssl.DER_cert_to_PEM_cert(der))
                    cert = ssl._ssl._test_decode_cert(f.name)  # noqa: SLF001 - stdlib, no extra deps
                finally:
                    os.unlink(f.name)
                info["not_after"] = cert.get("notAfter")
                info["issuer"] = dict(x[0] for x in cert.get("issuer", ()))
                info["subject"] = dict(x[0] for x in cert.get("subject", ()))
        except Exception as e:
            info["error"] = f"{type(e).__name__}: {e}"
            return info
        # Strict verification (does the corp CA chain validate?)
        try:
            vctx = ssl.create_default_context()
            with socket.create_connection((host, port), timeout=8) as sock:
                with vctx.wrap_socket(sock, server_hostname=host):
                    info["verified"] = True
        except ssl.SSLCertVerificationError as e:
            info["verified"] = False
            info["verify_error"] = e.verify_message
        except Exception:
            pass
        if self.mode == "active":
            info["legacy"] = {}
            for name, ver in (("TLSv1.0", ssl.TLSVersion.TLSv1), ("TLSv1.1", ssl.TLSVersion.TLSv1_1)):
                try:
                    lctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                    lctx.check_hostname = False
                    lctx.verify_mode = ssl.CERT_NONE
                    lctx.minimum_version = ver
                    lctx.maximum_version = ver
                    try:
                        lctx.set_ciphers("ALL:@SECLEVEL=0")
                    except ssl.SSLError:
                        pass
                    with socket.create_connection((host, port), timeout=8) as sock:
                        with lctx.wrap_socket(sock, server_hostname=host) as ss:
                            info["legacy"][name] = ss.version() == name
                except ssl.SSLError as e:
                    msg = str(e).lower()
                    info["legacy"][name] = None if ("no protocols available" in msg or "unsupported protocol" in msg and "alert" not in msg) else False
                except (OSError, ValueError):
                    info["legacy"][name] = None
        return info

    def _tls_findings(self, info: dict) -> None:
        if not info or info.get("error"):
            return
        legacy = [k for k, v in (info.get("legacy") or {}).items() if v]
        if legacy:
            self._finding(category="config", severity="medium", title=f"Legacy TLS accepted: {', '.join(legacy)}",
                          kb="legacy-tls", location=self.target, evidence=str(info.get("legacy")))
        untested = [k for k, v in (info.get("legacy") or {}).items() if v is None]
        if untested:
            self.log(f"TLS {', '.join(untested)} could not be tested from this host (local OpenSSL refuses); verify with testssl.sh/nmap.")
        if info.get("protocol") in ("TLSv1", "TLSv1.1", "SSLv3"):
            self._finding(category="config", severity="high", title=f"Server negotiates {info['protocol']} by default",
                          kb="legacy-tls", location=self.target, evidence=str(info))
        na = info.get("not_after")
        if na:
            try:
                exp = time.mktime(time.strptime(na, "%b %d %H:%M:%S %Y %Z"))
                days = int((exp - time.time()) / 86400)
                info["days_to_expiry"] = days
                if days < 0:
                    self._finding(category="config", severity="medium", title=f"TLS certificate expired {-days} days ago",
                                  kb="certificate", location=self.target, evidence=f"notAfter={na}")
                elif days < 30:
                    self._finding(category="config", severity="low", title=f"TLS certificate expires in {days} days",
                                  kb="certificate", location=self.target, evidence=f"notAfter={na}")
            except ValueError:
                pass
        if info.get("verified") is False:
            self._finding(category="config", severity="low", title="TLS certificate does not validate against the scanner's trust store",
                          kb="certificate", location=self.target,
                          evidence=f"{info.get('verify_error')} (expected for internal lab CAs unless the corp CA is mounted)")

    def _header_disclosure(self) -> None:
        leaks = {}
        for c in self.res.components:
            if c.source == "header" and c.version:
                leaks.setdefault(c.evidence.split(":")[0], c.evidence)
        if leaks:
            self._finding(category="config", severity="low", title="Software versions disclosed in HTTP response headers",
                          kb="header-disclosure", location=self.target, evidence="\n".join(sorted(set(leaks.values())))[:600])

    async def _browser_crawl(self) -> None:
        self.progress(0.4, "rendering pages in headless browser")
        await browser.crawl(self)

    # ------------------------------------------------------------ web hygiene checks (headers, cookies, CORS, forms)
    def _observe_cookies(self, r: httpx.Response) -> None:
        for v in r.headers.get_list("set-cookie"):
            name = v.split("=", 1)[0].strip()
            if name and name not in self._cookies:
                self._cookies[name] = (v, str(r.url))

    def _check_forms(self, soup: BeautifulSoup, page_url: str) -> None:
        for form in soup.find_all("form"):
            if not form.find("input", attrs={"type": re.compile("^password$", re.I)}):
                continue
            action = urljoin(page_url, form.get("action") or page_url)
            if page_url.startswith("http://") or action.startswith("http://"):
                self._cleartext_forms.append(f"{page_url} -> {action}")

    def _security_headers(self) -> None:
        if not self._pages_seen:
            return
        url, h = self._pages_seen[0]
        lower = {k.lower(): v for k, v in h.items()}
        csp = lower.get("content-security-policy", "")
        missing = []
        if not csp:
            missing.append("Content-Security-Policy (limits the impact of XSS in code that can't be fixed)")
        if "x-frame-options" not in lower and "frame-ancestors" not in csp:
            missing.append("X-Frame-Options / CSP frame-ancestors (clickjacking)")
        if url.startswith("https://") and "strict-transport-security" not in lower:
            missing.append("Strict-Transport-Security (HTTPS downgrade)")
        if lower.get("x-content-type-options", "").lower() != "nosniff":
            missing.append("X-Content-Type-Options: nosniff (MIME sniffing)")
        if "referrer-policy" not in lower:
            missing.append("Referrer-Policy (URL/token leakage to third parties)")
        weak = []
        if csp and re.search(r"'unsafe-inline'|'unsafe-eval'|(?:^|\s)\*(?:\s|;|$)", csp):
            weak.append("CSP allows 'unsafe-inline' / 'unsafe-eval' / '*', so it gives little XSS protection")
        if missing or weak:
            sev = "medium" if (not csp and "x-frame-options" not in lower and "frame-ancestors" not in csp) else "low"
            self._finding(category="config", severity=sev, title=f"Missing or weak browser security headers ({len(missing) + len(weak)})",
                          kb="security-headers", location=url,
                          evidence="\n".join([f"missing: {m}" for m in missing] + [f"weak: {w}" for w in weak]))

    def _cookie_flags(self) -> None:
        https = self.target.startswith("https://")
        problems = []
        sev = "low"
        for name, (raw, url) in self._cookies.items():
            attrs = {a.strip().split("=", 1)[0].lower() for a in raw.split(";")[1:]}
            sess = bool(re.search(r"sess|sid|auth|token|jwt|login|asp\.net|jsession|phpsess|connect\.sid|remember", name, re.I))
            miss = []
            if https and "secure" not in attrs:
                miss.append("Secure")
            if "httponly" not in attrs and sess:
                miss.append("HttpOnly")
            if "samesite" not in attrs:
                miss.append("SameSite")
            if miss:
                problems.append(f"{name}: missing {', '.join(miss)}" + (" (session cookie)" if sess else ""))
                if sess and ("HttpOnly" in miss or "Secure" in miss):
                    sev = "medium"
        if problems:
            self._finding(category="config", severity=sev, title=f"Cookies without security flags ({len(problems)})", kb="cookie-flags",
                          location=self.target, evidence="\n".join(problems[:20]))

    async def _cors_check(self) -> None:
        """Send two ordinary GETs with a foreign Origin header and see whether the app trusts it. No state is changed."""
        tests = (("https://eolscan-cors-check.invalid", "arbitrary origin"), ("null", "'null' origin"))
        hits = []
        sev = "low"
        for origin, label in tests:
            r = await self._request("GET", self.target, headers={"Origin": origin})
            if r is None:
                continue
            acao = r.headers.get("access-control-allow-origin", "")
            creds = r.headers.get("access-control-allow-credentials", "").lower() == "true"
            if acao == origin:
                hits.append(f"{label} reflected in Access-Control-Allow-Origin" + (" WITH credentials" if creds else ""))
                sev = "high" if creds else max(sev, "medium", key=["low", "medium", "high"].index)
            elif acao == "*" and origin != "null":
                hits.append("Access-Control-Allow-Origin: * (any site can read unauthenticated responses)")
        if hits:
            self._finding(category="config", severity=sev, title="Permissive CORS policy", kb="cors", location=self.target,
                          evidence="\n".join(hits))

    def _cleartext_login(self) -> None:
        if self._cleartext_forms:
            self._finding(category="config", severity="medium", title="Password form served or submitted over plain HTTP",
                          kb="cleartext-login", location=self._cleartext_forms[0].split(" -> ")[0],
                          evidence="\n".join(sorted(set(self._cleartext_forms))[:10]))

    # ------------------------------------------------------------ main
    async def run(self) -> WebScanResult:
        # asyncio primitives must be created inside the running loop (py3.9)
        self._rate_lock = asyncio.Lock()
        self.sem = asyncio.Semaphore(int(self.opt.get("concurrency", 4)))
        headers = {"User-Agent": USER_AGENT}
        headers.update(self.opt.get("headers") or {})
        if self.opt.get("cookies"):
            headers["Cookie"] = self.opt["cookies"]
        async with httpx.AsyncClient(verify=bool(self.opt.get("verify_tls", False)), timeout=float(self.opt.get("timeout", 10)),
                                     headers=headers, follow_redirects=False, trust_env=bool(self.opt.get("use_proxy", False))) as c:
            self.client = c
            self.progress(0.02, "checking reachability")
            r = await self._request("GET", self.target)
            if r is None and self.target.startswith("https://") and "://" not in self.opt.get("raw_target", "://"):
                self.target = "http://" + self.target[len("https://"):]
                r = await self._request("GET", self.target)
            if r is None:
                raise RuntimeError(f"target not reachable or out of scope: {self.target}")
            await self._baseline()
            await self._crawl()
            if self.opt.get("render_js") and not self.cancelled():
                await self._browser_crawl()
            if self.mode in ("safe", "active") and not self.cancelled():
                await self._cors_check()
                await self._probes()
            if self.mode == "active" and not self.cancelled():
                self.progress(0.88, "HTTP method / directory listing checks")
                await self._http_methods()
                await self._dir_listing()
        self.progress(0.9, "TLS checks")
        try:
            scope.check(self.target, self.rules)
            self.res.tls = await asyncio.get_running_loop().run_in_executor(None, self._tls_info)
            self._tls_findings(self.res.tls)
        except scope.OutOfScope:
            pass
        self._header_disclosure()
        self._security_headers()
        self._cookie_flags()
        self._cleartext_login()
        return self.res
