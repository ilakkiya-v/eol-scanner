"""Passive analysis of recorded traffic: Burp Suite "Save items" XML (proxy history / site map) and HAR files.

Nothing is sent to any target: every request/response pair in the file is run through the same fingerprinting and
hygiene checks as a live scan (server/framework/JS versions -> lifecycle + CVEs, exposed files, security headers,
cookie flags, CORS reflection, login forms over HTTP, version disclosure). Useful when you already browsed the lab app
through Burp, or can only capture traffic (e.g. authenticated single-page apps).
"""
from __future__ import annotations

import base64
import gzip
import re
import zlib
from typing import Callable, Iterable, Optional
from urllib.parse import urlsplit, urljoin
import xml.etree.ElementTree as ET

import httpx
from bs4 import BeautifulSoup

from . import probes
from .fingerprints import Component, match_headers, match_html, match_js, match_js_url
from .web import WebScanner, WebScanResult


class PassiveError(ValueError):
    pass


# ---------------------------------------------------------------- raw HTTP helpers
def _split_raw(raw: bytes) -> tuple[str, list[tuple[str, str]], bytes]:
    head, sep, body = raw.partition(b"\r\n\r\n")
    if not sep:
        head, sep, body = raw.partition(b"\n\n")
    lines = head.decode("iso-8859-1", "replace").splitlines()
    first = lines[0] if lines else ""
    headers = []
    for ln in lines[1:]:
        if ":" in ln:
            k, v = ln.split(":", 1)
            headers.append((k.strip(), v.strip()))
    return first, headers, body


def _dechunk(body: bytes) -> bytes:
    out, i = b"", 0
    while i < len(body):
        j = body.find(b"\r\n", i)
        if j == -1:
            break
        try:
            size = int(body[i:j].split(b";")[0], 16)
        except ValueError:
            return body
        if size == 0:
            break
        out += body[j + 2:j + 2 + size]
        i = j + 2 + size + 2
    return out or body


def _decode_body(headers: list[tuple[str, str]], body: bytes) -> bytes:
    h = {k.lower(): v.lower() for k, v in headers}
    if "chunked" in h.get("transfer-encoding", ""):
        body = _dechunk(body)
    enc = h.get("content-encoding", "")
    try:
        if "gzip" in enc:
            body = gzip.decompress(body)
        elif "deflate" in enc:
            body = zlib.decompress(body, -zlib.MAX_WBITS) if body[:1] != b"\x78" else zlib.decompress(body)
    except (OSError, zlib.error):
        pass
    return body


def _b(el: Optional[ET.Element]) -> bytes:
    if el is None or el.text is None:
        return b""
    if el.get("base64") == "true":
        try:
            return base64.b64decode(el.text)
        except ValueError:
            return b""
    return el.text.encode("utf-8", "replace")


# ---------------------------------------------------------------- readers -> uniform entries
def read_burp_items(data: bytes) -> Iterable[dict]:
    """Stream <items><item>... from Burp's 'Save items' export without loading the whole tree."""
    prolog = data[:20000].decode("utf-8", "ignore")
    if re.search(r"<!ENTITY", prolog, re.I):
        raise PassiveError("XML with entity declarations is not accepted")
    import io
    for _, el in ET.iterparse(io.BytesIO(data), events=("end",)):
        if el.tag != "item":
            continue
        url = (el.findtext("url") or "").strip()
        req_first, req_h, _ = _split_raw(_b(el.find("request")))
        resp_raw = _b(el.find("response"))
        el.clear()
        if not url or not resp_raw:
            continue
        status_line, resp_h, body = _split_raw(resp_raw)
        m = re.match(r"HTTP/\S+\s+(\d{3})", status_line)
        yield {"url": url, "method": (req_first.split(" ", 1)[0] or "GET").upper(), "req_headers": req_h,
               "status": int(m.group(1)) if m else 0, "headers": resp_h, "body": _decode_body(resp_h, body)}


def read_har(d: dict) -> Iterable[dict]:
    for e in (d.get("log") or {}).get("entries") or []:
        req, resp = e.get("request") or {}, e.get("response") or {}
        content = resp.get("content") or {}
        text = content.get("text") or ""
        body = base64.b64decode(text) if content.get("encoding") == "base64" else text.encode("utf-8", "replace")
        yield {"url": req.get("url", ""), "method": (req.get("method") or "GET").upper(),
               "req_headers": [(h.get("name", ""), h.get("value", "")) for h in req.get("headers") or []],
               "status": int(resp.get("status") or 0), "headers": [(h.get("name", ""), h.get("value", "")) for h in resp.get("headers") or []],
               "body": body}


# ---------------------------------------------------------------- analysis
_PROBES_BY_PATH = {}
for _p in probes.SAFE + probes.ACTIVE:
    _PROBES_BY_PATH.setdefault(_p["path"].split("?")[0], []).append(_p)


def analyze(entries: Iterable[dict], log: Callable[[str], None]) -> tuple[WebScanResult, list[str]]:
    """Group recorded traffic by origin and run the live-scan checks on each origin's responses."""
    per_origin: dict[str, WebScanner] = {}
    total = 0
    noop = lambda *a, **k: None  # noqa: E731
    for e in entries:
        url = e.get("url") or ""
        if not url.startswith(("http://", "https://")):
            continue
        total += 1
        parts = urlsplit(url)
        origin = f"{parts.scheme}://{parts.netloc}"
        sc = per_origin.get(origin)
        if sc is None:
            sc = WebScanner(origin + "/", "passive", {}, {"allow": [], "deny": []}, log, noop, lambda: False)
            per_origin[origin] = sc
        try:
            r = httpx.Response(e.get("status") or 0, headers=e.get("headers") or [], content=e.get("body") or b"",
                               request=httpx.Request(e.get("method") or "GET", url))
        except Exception:  # noqa: BLE001 - malformed recorded response
            continue
        sc.res.requests += 1
        sc._add(match_headers(r.headers.multi_items(), url))  # noqa: SLF001
        sc._observe_cookies(r)  # noqa: SLF001
        ctype = r.headers.get("content-type", "").lower()
        body = e.get("body") or b""
        text = body[:3_000_000].decode("utf-8", "ignore")
        if r.status_code and r.status_code < 400 and ("html" in ctype or text.lstrip()[:15].lower().startswith(("<!doctype", "<html"))):
            if url not in sc.res.pages:
                sc.res.pages.append(url)
            sc._add(match_html(text, url))  # noqa: SLF001
            sc._pages_seen.append((url, r.headers))  # noqa: SLF001
            soup = BeautifulSoup(text, "html.parser")
            sc._check_forms(soup, url)  # noqa: SLF001
            for s in soup.find_all("script", src=True):
                full = urljoin(url, s["src"])
                if full not in sc.res.scripts:
                    sc.res.scripts.append(full)
                    sc._add(match_js_url(full))  # noqa: SLF001
        if "javascript" in ctype or parts.path.endswith((".js", ".mjs")):
            comps = match_js(text, parts.path, url)
            for c in comps:
                c.source = "recorded-js"
            sc._add(comps)  # noqa: SLF001
            if url not in sc.res.scripts:
                sc.res.scripts.append(url)
        for p in _PROBES_BY_PATH.get(parts.path, []):
            if p["method"] in (e.get("method"), "GET") and r.status_code == 200:
                sc._apply_probe(p, url, r)  # noqa: SLF001
        origin_hdr = next((v for k, v in e.get("req_headers") or [] if k.lower() == "origin"), None)
        acao = r.headers.get("access-control-allow-origin")
        if origin_hdr and acao and acao == origin_hdr and urlsplit(origin_hdr).netloc != parts.netloc \
                and r.headers.get("access-control-allow-credentials", "").lower() == "true":
            sc._finding(category="config", severity="medium", title="Cross-origin request trusted with credentials (seen in traffic)",  # noqa: SLF001
                        kb="cors", location=url, evidence=f"Origin: {origin_hdr} -> Access-Control-Allow-Origin: {acao}, credentials allowed")
    merged = WebScanResult()
    for origin, sc in per_origin.items():
        sc._header_disclosure()  # noqa: SLF001
        sc._security_headers()  # noqa: SLF001
        sc._cookie_flags()  # noqa: SLF001
        sc._cleartext_login()  # noqa: SLF001
        merged.components += sc.res.components
        merged.findings += sc.res.findings
        merged.pages += sc.res.pages
        merged.scripts += sc.res.scripts
        merged.requests += sc.res.requests
    log(f"analyzed {total} recorded requests across {len(per_origin)} host(s); no traffic was sent")
    return merged, sorted(per_origin)
