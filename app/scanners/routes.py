"""Map source files to the URLs that reach them, so a code finding can say which request to send in a lab PoC.

Best effort and pattern-based: annotation/decorator routes (Spring, JAX-RS, servlets, Express, Flask/FastAPI, ASP.NET,
Rails) and file-path routes (PHP, JSP, ASP, ASPX, CFM). Also extracts request parameter names read on a given line.
"""
from __future__ import annotations

import re
from pathlib import PurePosixPath
from typing import Optional

# (regex, method group or fixed method, path group). Applied per line.
_LINE_ROUTES = [
    (re.compile(r"@(Get|Post|Put|Delete|Patch)Mapping\s*\(\s*(?:value\s*=\s*|path\s*=\s*)?\{?\s*\"([^\"]*)\""), 1, 2),
    (re.compile(r"@RequestMapping\s*\((?:[^)]*?(?:value|path)\s*=\s*)?\{?\s*\"([^\"]*)\"(?:[^)]*method\s*=\s*\{?\s*RequestMethod\.(\w+))?"), 2, 1),
    (re.compile(r"@Path\s*\(\s*\"([^\"]*)\""), None, 1),
    (re.compile(r"@WebServlet\s*\((?:[^)]*?(?:urlPatterns|value)\s*=\s*)?\{?\s*\"([^\"]*)\""), None, 1),
    (re.compile(r"\b(?:app|router|api|server)\.(get|post|put|delete|patch|all)\s*\(\s*['\"`]([^'\"`]+)['\"`]"), 1, 2),
    (re.compile(r"@\w+\.(?:route|get|post|put|delete|patch)\s*\(\s*['\"]([^'\"]+)['\"](?:[^)]*methods\s*=\s*\[\s*['\"](\w+))?"), 2, 1),
    (re.compile(r"\[(?:Http(Get|Post|Put|Delete|Patch)|Route)\s*\(\s*\"([^\"]*)\""), 1, 2),
    (re.compile(r"^\s*(get|post|put|delete|patch|match)\s+['\"]([^'\"]+)['\"]"), 1, 2),
]
_CLASS_PREFIX = re.compile(r"@(?:RequestMapping|Path)\s*\(\s*(?:value\s*=\s*|path\s*=\s*)?\{?\s*\"([^\"]*)\"[^)]*\)\s*(?:\n\s*@[\w.()\"= ,]+)*\s*\n\s*(?:public\s+)?(?:abstract\s+)?(?:final\s+)?class\b")
_WEBROOTS = ("src/main/webapp/", "webapp/", "WebContent/", "web/", "public/", "public_html/", "htdocs/", "www/", "wwwroot/", "html/")
_FILE_ROUTE_EXT = (".php", ".jsp", ".jspx", ".asp", ".aspx", ".ashx", ".asmx", ".cfm", ".cgi", ".pl")

_PARAM_RX = [
    re.compile(r"getParameter(?:Values)?\s*\(\s*\"([\w.\-\[\]]+)\""),
    re.compile(r"\$_(GET|POST|REQUEST|COOKIE)\s*\[\s*['\"]([\w.\-]+)['\"]"),
    re.compile(r"request\.(?:GET|POST|args|form|values|query_params|cookies)(?:\.get)?\s*[\[(]\s*['\"]([\w.\-]+)['\"]"),
    re.compile(r"req\.(?:query|body|params|cookies)\.([A-Za-z_]\w*)"),
    re.compile(r"req\.(?:query|body|params|cookies)\s*\[\s*['\"]([\w.\-]+)['\"]"),
    re.compile(r"Request(?:\.QueryString|\.Form|\.Params|\.Cookies)?\s*\[\s*\"([\w.\-]+)\""),
    re.compile(r"@(?:RequestParam|PathVariable|QueryParam|FormParam)\s*\(\s*(?:value\s*=\s*|name\s*=\s*)?\"([\w.\-]+)\""),
    re.compile(r"params\s*\[\s*:(\w+)\s*\]"),
]


def _join(prefix: str, path: str) -> str:
    p = "/" + "/".join(x for x in (prefix.strip("/"), path.strip("/")) if x)
    return p if p != "" else "/"


def file_route(rel: str) -> Optional[str]:
    """Route for page-per-file stacks (PHP, JSP, ASP...)."""
    if not rel.lower().endswith(_FILE_ROUTE_EXT):
        return None
    for root in _WEBROOTS:
        i = rel.find(root)
        if i != -1:
            return "/" + rel[i + len(root):]
    return "/" + rel


def routes_in(text: str) -> list[dict]:
    """[{line, method, path}] for annotation/decorator routes in one file."""
    out = []
    m = _CLASS_PREFIX.search(text)
    prefix = m.group(1) if m else ""
    class_line = text.count("\n", 0, m.start()) + 1 if m else 0
    for i, line in enumerate(text.splitlines(), 1):
        for rx, mg, pg in _LINE_ROUTES:
            mm = rx.search(line)
            if not mm:
                continue
            if m and i == class_line:
                continue  # the class-level prefix itself
            method = (mm.group(mg) if isinstance(mg, int) and mm.group(mg) else "GET").upper()
            if method in ("ALL", "MATCH", "ROUTE"):
                method = "GET"
            path = mm.group(pg) or ""
            full = _join(prefix, path) if prefix and not path.startswith(prefix) else (path if path.startswith("/") else "/" + path)
            out.append({"line": i, "method": method, "path": full})
            break
    return out


def params_on(line: str) -> list[str]:
    found = []
    for rx in _PARAM_RX:
        for m in rx.finditer(line):
            name = m.groups()[-1]
            if name and name not in found:
                found.append(name)
    return found


def entry_point(rel: str, text: str, line_no: int, file_routes: Optional[list[dict]] = None) -> Optional[dict]:
    """Best guess of the request that reaches `line_no` in `rel`: nearest route declared above it, or the file's own URL."""
    lines = text.splitlines()
    params = params_on(lines[line_no - 1]) if 0 < line_no <= len(lines) else []
    if not params:  # look a few lines up for where the variable was read
        for back in range(max(0, line_no - 8), max(0, line_no - 1)):
            params += [p for p in params_on(lines[back]) if p not in params]
    routes = file_routes if file_routes is not None else routes_in(text)
    above = [r for r in routes if r["line"] <= line_no]
    if above:
        r = above[-1]
        return {"method": r["method"], "path": r["path"], "params": params[:5], "how": "route annotation"}
    fr = file_route(rel)
    if fr:
        return {"method": "POST" if re.search(r"\$_POST|Request\.Form", "\n".join(lines[max(0, line_no - 8):line_no])) else "GET",
                "path": fr, "params": params[:5], "how": "file path"}
    if params:
        return {"method": "GET", "path": None, "params": params[:5], "how": "parameter only"}
    return None
