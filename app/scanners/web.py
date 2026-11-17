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
from urllib.parse import urljoin, urlsplit

import httpx
from bs4 import BeautifulSoup

from .. import scope
from ..config import USER_AGENT
from . import browser, discovery as d, manifests, probes
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
    endpoints: list[dict] = field(default_factory=list)   # method, url, params, sources, status, ... (attack surface)
    page_info: list[dict] = field(default_factory=list)   # url, status, type, title, size


_REDACT = re.compile(r"^(set-cookie|cookie|authorization|proxy-authorization|x-api-key|x-auth-token)$", re.I)


class Snapshot:
    """Saves crawled responses (headers + body, secrets redacted) for the AI web review. Disabled without a folder."""

    def __init__(self, folder: Optional[str], max_bytes: int = 60_000_000, max_files: int = 600):
        self.dir = folder
        self.left, self.files_left = max_bytes, max_files
        self.index: list[dict] = []
        self._seen: set[str] = set()

    def save(self, kind: str, url: str, r: httpx.Response) -> None:
        if not self.dir or url in self._seen or self.files_left <= 0 or self.left <= 0:
            return
        self._seen.add(url)
        body = (r.content or b"")[:400_000]
        heads = []
        for k, v in r.headers.multi_items():
            if _REDACT.match(k):
                v = v.split("=", 1)[0] + "=<redacted>" if k.lower() == "set-cookie" else "<redacted>"
            heads.append(f"{k}: {v}")
        name = f"{kind}s/{len(self.index) + 1:04d}.txt"
        text = f"URL: {url}\nSTATUS: {r.status_code}\n" + "\n".join(heads) + "\n\n" + body.decode("utf-8", "ignore")
        path = os.path.join(self.dir, name)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(text)
        self.left -= len(text)
        self.files_left -= 1
        self.index.append({"file": name, "url": url, "status": r.status_code, "type": r.headers.get("content-type", "")})


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
        self._comments: list[str] = []
        self.endpoints = d.EndpointMap()
        self.snap = Snapshot(options.get("snapshot_dir"))

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
    def _enqueue(self, url: str, source: str, depth: int) -> None:
        """Record a same-origin URL as an endpoint and queue it for crawling unless it is static, unsafe, or a repeat."""
        url = d.strip_fragment(url)
        if not url.startswith(("http://", "https://")) or d.origin(url) != self._org or d.STATIC.search(url):
            return
        if d.SCRIPT.search(url):
            self._queue_script(url)
            return
        unsafe = bool(d.UNSAFE_LINK.search(url))
        self.endpoints.add("GET", url, source=source, **({"not_followed": "state-changing name"} if unsafe else {}))
        if unsafe or url in self._seen or "{x}" in url or depth > self._max_depth:
            return
        k = d.pattern_key(url)
        if self._patterns.get(k, 0) >= self._per_pattern:
            return
        self._patterns[k] = self._patterns.get(k, 0) + 1
        self._seen.add(url)
        self._queue.append((url, depth))

    def _queue_script(self, full: str) -> None:
        if full in self._scripts_seen:
            return
        self._scripts_seen.add(full)
        self.res.scripts.append(full)
        self._add(match_js_url(full))
        if d.origin(full) == self._org or scope.in_scope(full, self.rules):
            self._script_jobs.append(full)

    async def _seed(self) -> None:
        """robots.txt and sitemaps (all modes: they are published for crawlers), OpenAPI documents (safe/active)."""
        r = await self._request("GET", urljoin(self.target, "/robots.txt"))
        sitemaps = [urljoin(self.target, "/sitemap.xml")]
        if r is not None and r.status_code == 200 and "html" not in r.headers.get("content-type", ""):
            paths, sm = d.parse_robots((r.content or b"").decode("utf-8", "ignore"))
            self.snap.save("robots", str(r.url), r)
            for p in paths[:300]:
                self._enqueue(urljoin(self.target, p), "robots.txt", 1)
            sitemaps = sm[:5] + sitemaps
            if paths:
                self.log(f"robots.txt lists {len(paths)} paths")
        done, tried = 0, set()
        while sitemaps and done < 6 and not self.cancelled():
            u = sitemaps.pop(0)
            if d.origin(u) != self._org or u in tried:
                continue
            tried.add(u)
            done += 1
            r = await self._request("GET", u)
            if r is None or r.status_code != 200 or b"<loc>" not in (r.content or b"")[:200_000].lower():
                continue
            pages, children = d.parse_sitemap((r.content or b"").decode("utf-8", "ignore"))
            sitemaps += children
            for p in pages[:1000]:
                self._enqueue(p, "sitemap", 1)
            self.log(f"sitemap {u}: {len(pages)} URLs")
        if self.mode == "passive":
            return
        for path in d.OPENAPI_PATHS:
            if self.cancelled():
                return
            r = await self._request("GET", urljoin(self.target, path))
            if r is None or r.status_code != 200:
                continue
            eps = d.parse_openapi((r.content or b"").decode("utf-8", "ignore"), self.target)
            if eps:
                self.snap.save("api-doc", str(r.url), r)
                for e in eps:
                    self.endpoints.add(e["method"], e["url"], e["params"], "openapi", auth=e["auth"])
                    if e["method"] == "GET" and "{" not in e["url"]:
                        self._enqueue(e["url"], "openapi", 1)
                self._finding(category="exposure", severity="low", title=f"API description published ({len(eps)} operations)",
                              kb="api-docs", location=str(r.url), evidence=f"{len(eps)} operations listed in {path}")
                self.log(f"OpenAPI document {path}: {len(eps)} operations")
                break

    async def _visit(self, url: str, depth: int) -> None:
        r = await self._request("GET", url)
        if r is None:
            return
        final = str(r.url)
        ctype = r.headers.get("content-type", "").split(";")[0].strip().lower()
        body = r.content or b""
        self.res.pages.append(final)
        self._add(match_headers(r.headers.multi_items(), final))
        self._observe_cookies(r)
        is_html = "html" in ctype or body.lstrip()[:15].lower().startswith((b"<!doctype", b"<html"))
        title = ""
        if is_html:
            html = body.decode("utf-8", "ignore")
            soup = BeautifulSoup(html, "html.parser")
            title = (soup.title.string or "").strip()[:120] if soup.title and soup.title.string else ""
        self.endpoints.add("GET", url, source="crawl", status=r.status_code, type=ctype or "?", title=title, size=len(body))
        self.res.page_info.append({"url": final, "status": r.status_code, "type": ctype, "title": title, "size": len(body)})
        self.snap.save("page", final, r)
        if not is_html:
            if "javascript" in ctype:
                self._add(match_js(body.decode("utf-8", "ignore"), urlsplit(final).path, final))
            return
        self._add(match_html(html, final))
        self._pages_seen.append((final, r.headers))
        self._check_forms(soup, final)
        for f in d.html_forms(soup, final):
            if d.origin(f["action"]) != self._org:
                continue
            self.endpoints.add(f["method"], f["action"], f["params"], "form", login=f["has_password"], upload=f["has_file"],
                               csrf_token=f["csrf_token"] if f["method"] == "POST" else None)
            if f["method"] == "GET" and not f["has_password"]:
                self._enqueue(f["action"].split("?")[0], "form", depth + 1)  # a search-style page; the form is never submitted
        for s in soup.find_all("script"):
            src = s.get("src")
            if src:
                self._queue_script(d.strip_fragment(urljoin(final, src)))
            elif s.string:
                self._add(match_js(s.string, "", f"{final} (inline script)"))
                for p in d.js_endpoints(s.string):
                    self._enqueue(urljoin(final, p), "inline-js", depth + 1)
        for l in soup.find_all("link", href=True):
            full = d.strip_fragment(urljoin(final, l["href"]))
            if full.endswith(".css") or "stylesheet" in (l.get("rel") or []):
                self._add(match_js_url(full))  # bootstrap/font-awesome versions in CSS URLs
        for link in d.html_links(soup, final):
            self._enqueue(link, "link", depth + 1)
        for c in d.html_comments(html):
            if len(self._comments) < 40 and c not in self._comments:
                self._comments.append(f"{final}: {c[:300]}")

    async def _drain(self, max_pages: int) -> None:
        conc = max(1, int(self.opt.get("concurrency", 4)))
        while self._queue and len(self.res.pages) < max_pages and not self.cancelled():
            batch = []
            while self._queue and len(batch) < min(conc, max_pages - len(self.res.pages)):
                batch.append(self._queue.pop(0))
            await asyncio.gather(*(self._visit(u, dep) for u, dep in batch))
            self.progress(0.05 + 0.35 * min(1.0, len(self.res.pages) / max_pages),
                          f"crawled {len(self.res.pages)} pages, {len(self.endpoints)} endpoints")

    async def _crawl(self) -> None:
        start = d.strip_fragment(self.target)
        self._org = d.origin(start)
        self._queue, self._seen, self._patterns = [], set(), {}
        self._scripts_seen, self._script_jobs = set(), []
        self._per_pattern = int(self.opt.get("per_pattern", 3))
        self._max_depth = int(self.opt.get("max_depth", 8))
        max_pages = int(self.opt.get("max_pages", 150))
        self._seen.add(start)
        self._queue.append((start, 0))
        self._patterns[d.pattern_key(start)] = 1
        await self._seed()
        await self._drain(max_pages)

        # Scripts: library versions, and the endpoints they call (single-page apps keep their routes and API there).
        max_scripts = int(self.opt.get("max_scripts", 80))
        fetched = 0
        while self._script_jobs and fetched < max_scripts and not self.cancelled():
            jobs_now = self._script_jobs[: max_scripts - fetched]
            self._script_jobs = self._script_jobs[len(jobs_now):]
            fetched += len(jobs_now)

            async def fetch_script(u: str) -> None:
                r = await self._request("GET", u)
                if r is None or r.status_code != 200:
                    return
                text = (r.content or b"").decode("utf-8", "ignore")
                self._add(match_js(text, urlsplit(u).path, u))
                if d.origin(u) == self._org:
                    self.snap.save("script", u, r)
                for p in d.js_endpoints(text):
                    self._enqueue(urljoin(u, p), "script", 2)

            await asyncio.gather(*(fetch_script(u) for u in jobs_now))
        # Second pass: pages and endpoints only referenced from JavaScript.
        await self._drain(max_pages)
        if self._comments:
            self._finding(category="info", severity="info", title=f"Developer comments in HTML ({len(self._comments)})",
                          kb="html-comments", location=self.target, evidence="\n".join(self._comments[:25]))
        self.res.endpoints = self.endpoints.to_list()
        self.log(f"crawl done: {len(self.res.pages)} pages, {len(self.res.scripts)} scripts, {len(self.endpoints)} endpoints"
                 f" ({sum(1 for e in self.res.endpoints if e['method'] != 'GET')} non-GET, "
                 f"{sum(1 for e in self.res.endpoints if e['params'])} with parameters)")

    # ------------------------------------------------------------ probes
    async def _run_probe(self, p: dict) -> None:
        url = urljoin(self.target, p["path"])
        r = await self._request(p["method"], url)
        self._apply_probe(p, url, r)

    def _apply_probe(self, p: dict, url: str, r: Optional[httpx.Response]) -> None:
        """Evaluate a probe against a response (live, or recorded in a Burp/HAR file)."""
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
            if d.origin(s) == d.origin(self.target):
                path = urlsplit(s).path.rsplit("/", 1)[0] + "/"
                if path != "/":
                    dirs.add(urljoin(self.target, path))
        for dir_url in list(dirs)[:10]:
            r = await self._request("GET", dir_url)
            if r is not None and r.status_code == 200 and re.search(rb"<title>Index of /|Directory Listing For|\[To Parent Directory\]", r.content or b"", re.I):
                self._finding(category="exposure", severity="medium", title="Directory listing enabled", kb="directory-listing",
                              location=dir_url, evidence=(r.content or b"")[:300].decode("utf-8", "ignore"))
                self._add(match_html((r.content or b"").decode("utf-8", "ignore"), dir_url))

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
        proxy = self.opt.get("proxy_url") or None
        if proxy:
            self.log(f"sending traffic through {proxy} (it appears in that proxy's history / site map)")
        async with httpx.AsyncClient(verify=bool(self.opt.get("verify_tls", False)) and not proxy, timeout=float(self.opt.get("timeout", 10)),
                                     headers=headers, follow_redirects=False, proxy=proxy,
                                     trust_env=bool(self.opt.get("use_proxy", False)) and not proxy) as c:
            self.client = c
            self.progress(0.02, "checking reachability")
            r = await self._request("GET", self.target)
            if r is None and self.target.startswith("https://") and "://" not in self.opt.get("raw_target", "://"):
                self.target = "http://" + self.target[len("https://"):]
                r = await self._request("GET", self.target)
            if r is None:
                hint = " (is Burp running with its proxy listener on that address?)" if proxy else ""
                raise RuntimeError(f"target not reachable or out of scope: {self.target}{hint}")
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
