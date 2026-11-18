"""Crawl discovery helpers: where to find more of the application than <a href> links show.

Pure functions (no network) so they are easy to test:
  * links from every HTML place that can hold one (a/area/frame/iframe/form/meta refresh/data-* /onclick),
  * endpoint paths referenced from JavaScript (fetch/axios/$.ajax/url: "..." and plain "/api/..." strings),
  * robots.txt paths and sitemaps, sitemap.xml <loc> entries,
  * OpenAPI / Swagger documents -> endpoints with their parameters,
  * an endpoint map (method + path + parameter names + where it was seen) used for the attack-surface view,
    the AI web review and Burp.
"""
from __future__ import annotations

import json
import re
from typing import Iterable, Optional
from urllib.parse import parse_qsl, urljoin, urlsplit, urlunsplit

# Links that change state or log the crawler out are never followed automatically.
UNSAFE_LINK = re.compile(
    r"log_?out|sign_?out|logoff|delete|remove|destroy|drop|purge|reset|unsubscribe|shutdown|restart|reboot|"
    r"disable|deactivate|revoke|kill|terminate|approve|reject|cancel|void|truncate|wipe|uninstall", re.I)
STATIC = re.compile(r"\.(?:png|jpe?g|gif|svg|ico|bmp|webp|pdf|docx?|xlsx?|pptx?|zip|gz|tgz|rar|7z|jar|war|exe|msi|dmg|iso|"
                    r"mp[34]|avi|mov|woff2?|ttf|eot|otf|css|map)(?:[?#]|$)", re.I)
SCRIPT = re.compile(r"\.m?js(?:[?#]|$)", re.I)

# JavaScript: strings passed to HTTP helpers, and quoted absolute paths that look like app endpoints.
_JS_CALL = re.compile(
    r"""(?:fetch|axios(?:\.(?:get|post|put|patch|delete|head|request))?|\$\.(?:ajax|get|post|getJSON|load)|"""
    r"""\.open|http\.(?:get|post|put|patch|delete)|request)\s*\(\s*(?:["'][A-Z]+["']\s*,\s*)?[`"']([^`"'\s<>]{1,300})[`"']""")
_JS_URLKEY = re.compile(r"""\b(?:url|uri|endpoint|href|action|path|baseURL|apiUrl|api_url)\s*[:=]\s*[`"']([^`"'\s<>]{1,300})[`"']""", re.I)
_JS_PATH = re.compile(
    r"""[`"'](/(?:api|rest|services?|ws|graphql|v\d+|rpc|ajax|admin|internal|data|json|odata|actuator|manage|auth|oauth|"""
    r"""account|user|users|login|upload|download|export|import|search|report|reports)\b[^`"'\s<>]{0,200})[`"']""", re.I)
_JS_FILEPATH = re.compile(r"""[`"'](/[A-Za-z0-9_\-./]{1,200}\.(?:jsp|jspx|do|action|php|aspx?|ashx|asmx|svc|cfm|pl|cgi|html?))(?:\?[^`"'\s]*)?[`"']""")


def strip_fragment(url: str) -> str:
    p = urlsplit(url)
    return urlunsplit((p.scheme, p.netloc, p.path or "/", p.query, ""))


def origin(url: str) -> str:
    p = urlsplit(url)
    return f"{p.scheme}://{p.netloc}".lower()


def _id_like(v: str) -> bool:
    """Values that identify a record (collapsed) rather than pick a page/route (kept)."""
    return bool(re.fullmatch(r"-?\d+(?:\.\d+)?|[0-9a-f]{8}-?[0-9a-f]{4}-?[0-9a-f]{4}-?[0-9a-f]{4}-?[0-9a-f]{12}|[0-9a-f]{16,}|.{41,}",
                             v, re.I)) or not re.fullmatch(r"[\w.\-/]{1,40}", v)


def pattern_key(url: str) -> str:
    """Collapse URLs that are the same page with different ids so the crawl spends its budget on new pages.

    /item/123?id=5&x=a -> /item/{n}?id&x=a ; /u/3f2a...(uuid/hex) -> /u/{id}
    Route-like query values (index.php?page=about, ?action=list, ?module=users) are kept, because legacy PHP/JSP/ASP
    apps use them to pick the page: collapsing them would hide most of the app.
    """
    p = urlsplit(url)
    segs = []
    for s in p.path.split("/"):
        if re.fullmatch(r"\d+", s):
            s = "{n}"
        elif re.fullmatch(r"[0-9a-f]{8}-?[0-9a-f]{4}-?[0-9a-f]{4}-?[0-9a-f]{4}-?[0-9a-f]{12}", s, re.I) or \
                re.fullmatch(r"[0-9a-f]{16,}", s, re.I):
            s = "{id}"
        segs.append(s)
    parts = sorted({k if _id_like(v) else f"{k}={v.lower()}" for k, v in parse_qsl(p.query, keep_blank_values=True)})
    return p.netloc.lower() + "/".join(segs) + ("?" + "&".join(parts) if parts else "")


def query_params(url: str) -> list[str]:
    return sorted({k for k, _ in parse_qsl(urlsplit(url).query, keep_blank_values=True)})


# ---------------------------------------------------------------- HTML
def html_links(soup, base: str) -> list[str]:
    """Every URL an HTML page points at (pages, frames, meta refresh, data-href, onclick)."""
    out: list[str] = []
    b = soup.find("base", href=True)
    if b:
        base = urljoin(base, b["href"])

    def add(v: Optional[str]) -> None:
        if v and not v.strip().lower().startswith(("javascript:", "mailto:", "tel:", "data:", "#")):
            out.append(urljoin(base, v.strip()))

    # Form actions are not links: they are recorded by html_forms() and never requested by the crawl (POST targets
    # can change state even when fetched with GET on badly written apps).
    for tag, attr in (("a", "href"), ("area", "href"), ("frame", "src"), ("iframe", "src"), ("link", "href")):
        for el in soup.find_all(tag):
            if tag == "link" and not set(el.get("rel") or []) & {"alternate", "next", "prev", "canonical", "help", "search"}:
                continue
            add(el.get(attr))
    for el in soup.find_all(attrs={"data-href": True}):
        add(el["data-href"])
    for el in soup.find_all(attrs={"data-url": True}):
        add(el["data-url"])
    for m in soup.find_all("meta", attrs={"http-equiv": re.compile("refresh", re.I)}):
        mm = re.search(r"url\s*=\s*['\"]?([^'\";]+)", m.get("content", ""), re.I)
        if mm:
            add(mm.group(1))
    for el in soup.find_all(attrs={"onclick": True}):
        for mm in re.finditer(r"""(?:location(?:\.href)?|window\.open)\s*(?:=|\()\s*['"]([^'"]+)['"]""", el["onclick"]):
            add(mm.group(1))
    return out


def html_forms(soup, base: str) -> list[dict]:
    forms = []
    for f in soup.find_all("form"):
        action = urljoin(base, f.get("action") or base)
        fields, kinds = [], set()
        for i in f.find_all(["input", "select", "textarea", "button"]):
            name = i.get("name")
            t = (i.get("type") or i.name).lower()
            if t in ("password", "file", "hidden"):
                kinds.add(t)
            if name and name not in fields:
                fields.append(name)
        forms.append({"method": (f.get("method") or "GET").upper(), "action": strip_fragment(action), "params": fields,
                      "has_password": "password" in kinds, "has_file": "file" in kinds,
                      "csrf_token": any(re.search(r"csrf|xsrf|token|authenticity|__requestverification", n, re.I) for n in fields)})
    return forms


_INTERESTING_COMMENT = re.compile(r"todo|fixme|hack|password|passwd|pwd|secret|api[_-]?key|token|debug|internal|"
                                  r"version|build|test user|admin|deprecated|remove (?:this|before)", re.I)


def html_comments(html: str) -> list[str]:
    out = []
    for m in re.finditer(r"<!--(.*?)-->", html, re.S):
        c = " ".join(m.group(1).split())
        if 6 < len(c) < 400 and _INTERESTING_COMMENT.search(c) and not c.startswith(("[if", "<![endif")):
            out.append(c)
    return out


# ---------------------------------------------------------------- JavaScript
def js_endpoints(text: str) -> list[str]:
    """Paths/URLs a script calls or references. Template parts (${x}, :id, {id}) are kept as placeholders."""
    found = []
    for rx in (_JS_CALL, _JS_URLKEY, _JS_PATH, _JS_FILEPATH):
        for m in rx.finditer(text[:3_000_000]):
            v = m.group(1)
            v = re.sub(r"\$\{[^}]*\}", "{x}", v)
            if v.startswith(("http://", "https://", "/")) and not v.startswith("//") and not STATIC.search(v) \
                    and not SCRIPT.search(v) and len(v) > 1 and not re.search(r"[\\*]|\s", v):
                found.append(v)
    seen, out = set(), []
    for v in found:
        if v not in seen:
            seen.add(v)
            out.append(v)
    return out[:500]


# ---------------------------------------------------------------- robots / sitemap / OpenAPI
def parse_robots(text: str) -> tuple[list[str], list[str]]:
    paths, sitemaps = [], []
    for line in text.splitlines()[:2000]:
        line = line.split("#", 1)[0].strip()
        k, _, v = line.partition(":")
        k, v = k.strip().lower(), v.strip()
        if k in ("allow", "disallow") and v.startswith("/") and v != "/":
            v = v.split("*", 1)[0].rstrip("$")  # wildcard rules: keep the literal prefix
            if len(v) > 1:
                paths.append(v)
        elif k == "sitemap" and v.startswith(("http://", "https://")):
            sitemaps.append(v)
    return paths, sitemaps


def parse_sitemap(text: str) -> tuple[list[str], list[str]]:
    """(page urls, child sitemap urls). Regex on <loc>, so no XML parser (and no entity expansion) is involved."""
    locs = [re.sub(r"&amp;", "&", m.strip()) for m in re.findall(r"<loc>\s*([^<\s]+)\s*</loc>", text[:5_000_000], re.I)]
    if re.search(r"<sitemapindex", text[:2000], re.I):
        return [], locs[:50]
    return locs[:5000], []


OPENAPI_PATHS = ["/openapi.json", "/swagger.json", "/v3/api-docs", "/v2/api-docs", "/api-docs", "/swagger/v1/swagger.json",
                 "/api/swagger.json", "/api/openapi.json", "/swagger/docs/v1", "/api/v1/swagger.json"]


def parse_openapi(text: str, base: str) -> list[dict]:
    """Endpoints from an OpenAPI 3 / Swagger 2 JSON document: [{method, url, params, source}]."""
    try:
        doc = json.loads(text)
    except ValueError:
        return []
    if not isinstance(doc, dict) or not isinstance(doc.get("paths"), dict) or not (doc.get("openapi") or doc.get("swagger")):
        return []
    prefix = ""
    if doc.get("swagger"):
        prefix = (doc.get("basePath") or "").rstrip("/")
    else:
        srv = (doc.get("servers") or [{}])[0].get("url", "") if doc.get("servers") else ""
        prefix = urlsplit(srv).path.rstrip("/") if srv else ""
    out = []
    for path, ops in list(doc["paths"].items())[:2000]:
        if not isinstance(ops, dict):
            continue
        shared = [p.get("name") for p in ops.get("parameters", []) if isinstance(p, dict) and p.get("name")]
        for method, op in ops.items():
            if method.lower() not in ("get", "post", "put", "patch", "delete", "head", "options") or not isinstance(op, dict):
                continue
            params = list(shared) + [p.get("name") for p in op.get("parameters", []) if isinstance(p, dict) and p.get("name")]
            body = ((op.get("requestBody") or {}).get("content") or {})
            for media in body.values():
                props = ((media or {}).get("schema") or {}).get("properties") or {}
                params += [k for k in props][:40]
            out.append({"method": method.upper(), "url": urljoin(base, prefix + path), "params": sorted(set(params)),
                        "source": "openapi", "auth": bool(op.get("security") or doc.get("security"))})
    return out


# ---------------------------------------------------------------- endpoint map
class EndpointMap:
    """method + path -> parameter names, where it was seen, last status. Path ids are collapsed ({n}/{id})."""

    def __init__(self, limit: int = 3000):
        self._d: dict[tuple[str, str], dict] = {}
        self.limit = limit

    def add(self, method: str, url: str, params: Iterable[str] = (), source: str = "", **meta) -> None:
        url = strip_fragment(url)
        p = urlsplit(url)
        key_path = pattern_key(urlunsplit((p.scheme, p.netloc, p.path, "", ""))).split("?")[0]
        key = (method.upper(), key_path)
        e = self._d.get(key)
        if e is None:
            if len(self._d) >= self.limit:
                return
            e = self._d[key] = {"method": method.upper(), "url": urlunsplit((p.scheme, p.netloc, p.path or "/", "", "")),
                                "example": url, "params": [], "sources": []}
        for n in list(params) + query_params(url):
            if n and n not in e["params"] and len(e["params"]) < 60:
                e["params"].append(n)
        if source and source not in e["sources"]:
            e["sources"].append(source)
        for k, v in meta.items():
            if v not in (None, "", False) or k not in e:
                e[k] = v

    def to_list(self) -> list[dict]:
        return sorted(self._d.values(), key=lambda e: (e["url"], e["method"]))

    def __len__(self) -> int:
        return len(self._d)
