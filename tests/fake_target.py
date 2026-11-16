"""A deliberately 'legacy' fake web app for testing the scanner locally.

    python tests/fake_target.py 8899

It serves fake banners/files only; nothing here is actually vulnerable.
"""
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

JQ = "/*! jQuery v1.12.4 | (c) jQuery Foundation | jquery.org/license */\n!function(a,b){}(this);"
NG = "/**\n * @license AngularJS v1.5.8\n * (c) 2010-2016 Google, Inc. http://angularjs.org\n */\n(function(window){})(window);"
INDEX = """<!doctype html><html><head><title>Legacy QA App</title>
<meta name="generator" content="WordPress 4.9.8">
<link rel="stylesheet" href="https://maxcdn.bootstrapcdn.com/bootstrap/3.3.7/css/bootstrap.min.css">
<script src="/static/js/jquery.min.js"></script>
<script src="/static/vendor/angular.js"></script>
<script src="https://cdnjs.cloudflare.com/ajax/libs/moment.js/2.18.1/moment.min.js"></script>
</head><body ng-app><a href="/about">About</a><a href="/login">Login</a><a href="/app">Dashboard (SPA)</a><a href="/logout">Logout</a></body></html>"""
LOGIN = """<html><body><form method="post" action="/login"><input name="user"><input type="password" name="pass"><button>Sign in</button></form></body></html>"""
# A single-page app shell: the library is only loaded by JavaScript, so a plain HTTP crawl can't see it.
SPA = """<!doctype html><html><head><title>Dashboard</title></head><body><div id="root">Loading…</div>
<script>var s=document.createElement('script');s.src='/static/app/'+'bundle-'+'7f3a.js';document.head.appendChild(s);
fetch('/api/v1/widgets').then(function(){});</script></body></html>"""
# Fake library build with no banner comment; only its runtime global reveals the version.
BUNDLE = "window.Vue={version:'2.5.17'};window.Handlebars={VERSION:'4.0.11'};document.getElementById('root').textContent='ready';"

FILES = {
    "/": ("text/html", INDEX),
    "/about": ("text/html", "<html><body>About <a href='/'>home</a></body></html>"),
    "/login": ("text/html", LOGIN),
    "/app": ("text/html", SPA),
    "/static/app/bundle-7f3a.js": ("application/javascript", BUNDLE),
    "/api/v1/widgets": ("application/json", "[]"),
    "/static/js/jquery.min.js": ("application/javascript", JQ),
    "/static/vendor/angular.js": ("application/javascript", NG),
    "/package.json": ("application/json", '{"name":"legacy","dependencies":{"lodash":"4.17.4","express":"4.15.2"}}'),
    "/.git/HEAD": ("text/plain", "ref: refs/heads/master\n"),
    "/server-status": ("text/html", "<html><title>Apache Status</title><h1>Apache Server Status for qa</h1><dl><dt>Server Version: Apache/2.2.15 (CentOS)</dt></dl></html>"),
    "/api/health": ("application/json", '{"commit":"abc","database":"ok","version":"7.5.2"}'),
    "/actuator": ("application/json", '{"_links":{"self":{"href":"/actuator"}}}'),
    "/static/js/": ("text/html", "<html><title>Index of /static/js</title><h1>Index of /static/js</h1></html>"),
}


class H(BaseHTTPRequestHandler):
    server_version = "Apache/2.2.15 (CentOS)"
    sys_version = ""

    def _send(self, body_only=False):
        path = self.path.split("?")[0]
        if path in FILES:
            ctype, body = FILES[path]
            code = 200
        else:
            ctype, body, code = "text/html", "<html><body><h1>Not Found</h1><address>Apache/2.2.15 (CentOS) Server at qa Port 80</address></body></html>", 404
        data = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("X-Powered-By", "PHP/5.6.40")
        self.send_header("Set-Cookie", "PHPSESSID=abc; path=/")
        origin = self.headers.get("Origin")
        if origin:  # misconfigured CORS: trusts any origin, with credentials
            self.send_header("Access-Control-Allow-Origin", origin)
            self.send_header("Access-Control-Allow-Credentials", "true")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        if not body_only:
            self.wfile.write(data)

    def do_GET(self):
        self._send()

    def do_HEAD(self):
        self._send(body_only=True)

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header("Allow", "GET, HEAD, POST, OPTIONS, TRACE, PUT")
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_TRACE(self):
        body = f"TRACE {self.path} HTTP/1.1\r\n".encode()
        self.send_response(200)
        self.send_header("Content-Type", "message/http")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8899
    host = sys.argv[2] if len(sys.argv) > 2 else "127.0.0.1"  # pass 0.0.0.0 so a Linux Docker container can reach it
    ThreadingHTTPServer((host, port), H).serve_forever()
