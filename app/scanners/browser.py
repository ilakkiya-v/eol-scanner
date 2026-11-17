"""Optional headless-browser crawl for JavaScript-heavy / single-page apps.

Single-page apps build the page in the browser, so the plain HTTP crawl only sees an empty shell. This renders pages in
headless Chromium (Playwright), then:
  * reads library versions from the live page (window.angular.version, jQuery.fn.jquery, React.version, ...),
  * fingerprints every script the browser actually loaded,
  * follows links that only exist in the rendered DOM, and records API (XHR/fetch) endpoints for the surface view.

Guardrails are the same as the HTTP crawl: every browser request is checked against the scope allowlist (out-of-scope
requests are aborted, not sent), counted against the request budget, and rate limited. Service workers are blocked
and downloads are refused. Install with `pip install -r requirements-browser.txt && playwright install chromium`.
"""
from __future__ import annotations

import asyncio
import os
import re
import time
from typing import TYPE_CHECKING
from urllib.parse import urljoin, urlsplit

from .. import scope
from .discovery import SCRIPT, STATIC, UNSAFE_LINK
from .fingerprints import JS_LIBS, Component, match_html, match_js, match_js_url

# product -> (OSV ecosystem, package) so live-page versions get CVE lookups too
_PKG = {prod: (eco, pkg) for prod, eco, pkg, _c, _f in JS_LIBS if eco}
_PKG.update({"angular": ("npm", "@angular/core"), "react": ("npm", "react"), "vue": ("npm", "vue")})

if TYPE_CHECKING:  # pragma: no cover
    from .web import WebScanner

# Global version properties exposed by common libraries. Evaluated in the page; returns {product: version}.
_VERSION_PROBE = r"""() => {
  const out = {};
  const g = (fn) => { try { const v = fn(); return (typeof v === "string" && /^\d/.test(v)) ? v : null; } catch (e) { return null; } };
  const add = (k, fn) => { const v = g(fn); if (v) out[k] = v; };
  add("angularjs", () => window.angular.version.full);
  add("angular", () => document.querySelector("[ng-version]").getAttribute("ng-version"));
  add("jquery", () => window.jQuery.fn.jquery);
  add("jquery-ui", () => window.jQuery.ui.version);
  add("react", () => window.React.version);
  add("vue", () => (window.Vue && window.Vue.version) || document.querySelector("#app").__vue_app__.version);
  add("lodash", () => window._.VERSION);
  add("moment", () => window.moment.version);
  add("bootstrap", () => (window.bootstrap && window.bootstrap.Tooltip.VERSION) || window.jQuery.fn.tooltip.Constructor.VERSION);
  add("backbone", () => window.Backbone.VERSION);
  add("ember", () => window.Ember.VERSION);
  add("knockout", () => window.ko.version);
  add("handlebars", () => window.Handlebars.VERSION);
  add("dojo", () => window.dojo.version.toString());
  add("prototype", () => window.Prototype.Version);
  add("d3", () => window.d3.version);
  add("extjs", () => window.Ext.getVersion().version);
  add("yui", () => window.YUI.version);
  add("tinymce", () => window.tinymce.majorVersion + "." + window.tinymce.minorVersion);
  add("ckeditor", () => window.CKEDITOR.version);
  return out;
}"""

_SKIP_LINK = re.compile(f"{STATIC.pattern}|{SCRIPT.pattern}|{UNSAFE_LINK.pattern}", re.I)


def available() -> bool:
    try:
        import playwright.async_api  # noqa: F401
        return True
    except ImportError:
        return False


async def crawl(sc: "WebScanner") -> None:
    try:
        from playwright.async_api import Error as PWError
        from playwright.async_api import async_playwright
    except ImportError:
        sc.log("browser crawl skipped: Playwright is not installed (pip install -r requirements-browser.txt && playwright install chromium)")
        return

    rules, origin = sc.rules, f"{urlsplit(sc.target).scheme}://{urlsplit(sc.target).netloc}".lower()
    max_pages = max(1, int(sc.opt.get("browser_pages", min(15, int(sc.opt.get("max_pages", 30))))))
    blocked: set[str] = set()
    api_calls: set[str] = set()
    script_urls: set[str] = set()

    async def gate(route, request):
        url = request.url
        if not url.startswith(("http://", "https://")):
            return await route.continue_()
        if sc.cancelled() or sc.res.requests >= sc.max_requests:
            return await route.abort()
        try:
            scope.check(url, rules)
        except scope.OutOfScope:
            host = urlsplit(url).netloc
            if host not in blocked:
                blocked.add(host)
                sc.log(f"browser: blocked out-of-scope request to {host}")
            return await route.abort()
        async with sc._rate_lock:  # noqa: SLF001 - share the scanner's rate limit
            wait = sc._last + sc.interval - time.monotonic()  # noqa: SLF001
            if wait > 0:
                await asyncio.sleep(wait)
            sc._last = time.monotonic()  # noqa: SLF001
        sc.res.requests += 1
        if request.resource_type in ("xhr", "fetch"):
            api_calls.add(f"{request.method} {url.split('?')[0]}")
            if url.lower().startswith(origin):
                sc.endpoints.add(request.method, url, source="browser")
        await route.continue_()

    launch: dict = {"headless": True}
    if sc.opt.get("proxy_url"):
        launch["proxy"] = {"server": sc.opt["proxy_url"]}
    elif sc.opt.get("use_proxy") and (os.environ.get("HTTPS_PROXY") or os.environ.get("https_proxy")):
        launch["proxy"] = {"server": os.environ.get("HTTPS_PROXY") or os.environ.get("https_proxy"),
                           "bypass": os.environ.get("NO_PROXY") or os.environ.get("no_proxy") or ""}
    extra = dict(sc.opt.get("headers") or {})
    if sc.opt.get("cookies"):
        extra["Cookie"] = sc.opt["cookies"]

    pages_done = 0
    try:
        async with async_playwright() as pw:
            browser = await pw.chromium.launch(**launch)
            ctx = await browser.new_context(ignore_https_errors=not sc.opt.get("verify_tls") or bool(sc.opt.get("proxy_url")), service_workers="block",
                                            accept_downloads=False, extra_http_headers=extra,
                                            user_agent=sc.client.headers.get("user-agent"))
            await ctx.route("**/*", gate)
            page = await ctx.new_page()
            page.set_default_timeout(float(sc.opt.get("timeout", 10)) * 1000 * 2)

            async def on_response(resp):
                try:
                    if resp.request.resource_type == "script" and resp.ok and resp.url not in script_urls:
                        script_urls.add(resp.url)
                        sc._add(match_js_url(resp.url))  # noqa: SLF001
                        body = await resp.body()
                        if len(body) < 3_000_000:
                            comps = match_js(body.decode("utf-8", "ignore"), urlsplit(resp.url).path, resp.url)
                            for c in comps:
                                c.source = "browser"
                            sc._add(comps)  # noqa: SLF001
                except PWError:
                    pass

            page.on("response", lambda r: asyncio.ensure_future(on_response(r)))
            queue, seen = [sc.target], {sc.target}
            while queue and pages_done < max_pages and not sc.cancelled():
                url = queue.pop(0)
                try:
                    await page.goto(url, wait_until="networkidle")
                except PWError as e:
                    sc.log(f"browser: {url} failed: {str(e).splitlines()[0]}")
                    continue
                pages_done += 1
                html = await page.content()
                sc._add(match_html(html, page.url))  # noqa: SLF001
                versions = await page.evaluate(_VERSION_PROBE)
                for product, ver in (versions or {}).items():
                    eco, pkg = _PKG.get(product, ("npm", product))
                    sc._add([Component(product, ver, eco, pkg, evidence=f"live page global ({product} {ver})",  # noqa: SLF001
                                       location=page.url, confidence="high", source="browser")])
                links = await page.eval_on_selector_all("a[href]", "els => els.map(e => e.href)")
                for href in links:
                    full = urljoin(page.url, href).split("#")[0]
                    if full.lower().startswith(origin):
                        sc.endpoints.add("GET", full, source="browser")
                    if full.lower().startswith(origin) and full not in seen and not _SKIP_LINK.search(full):
                        seen.add(full)
                        queue.append(full)
                sc.progress(0.4 + 0.05 * pages_done / max_pages, f"browser rendered {pages_done} pages")
            await asyncio.sleep(0.2)  # let pending response handlers finish
            await browser.close()
    except PWError as e:
        msg = str(e).splitlines()[0]
        if "Executable doesn't exist" in str(e) or "playwright install" in str(e):
            msg = "Chromium is not installed for Playwright (run: playwright install chromium)"
        sc.log(f"browser crawl failed: {msg}")
        return
    for s in sorted(script_urls):
        if s not in sc.res.scripts:
            sc.res.scripts.append(s)
    sc.res.api_endpoints = sorted(api_calls)[:300]
    sc.res.endpoints = sc.endpoints.to_list()
    sc.log(f"browser crawl: {pages_done} pages rendered, {len(script_urls)} scripts, {len(api_calls)} API endpoints"
           + (f", blocked {len(blocked)} out-of-scope hosts" if blocked else ""))
