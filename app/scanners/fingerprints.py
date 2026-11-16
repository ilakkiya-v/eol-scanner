"""Version fingerprint signatures shared by the web scanner and code review.

Each detection yields a Component(product, version, ecosystem, package, evidence).
`product` is an endoflife.date id (or curated id); `ecosystem`/`package` are
used for OSV lookups.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Iterable, Optional

V = r"(\d+(?:\.\d+){0,3}(?:[-.]?(?:rc|beta|alpha|b|a)\d*)?)"


@dataclass
class Component:
    product: str
    version: Optional[str]
    ecosystem: Optional[str] = None   # OSV ecosystem: npm, PyPI, Maven, Packagist, RubyGems, Go, NuGet
    package: Optional[str] = None     # OSV package name
    evidence: str = ""
    location: str = ""
    confidence: str = "medium"         # high | medium | low
    source: str = ""                   # header | html | js | file | manifest | ...
    extra: dict = field(default_factory=dict)

    @property
    def key(self) -> tuple:
        return (self.product, self.version or "", self.location if not self.version else "")


# ------------------------------------------------------------------ HTTP headers
# (header, regex, product, ecosystem, package)
HEADER_SIGS: list[tuple[str, str, str, Optional[str], Optional[str]]] = [
    ("server", r"nginx/" + V, "nginx", None, None),
    ("server", r"Apache/" + V, "apache-http-server", None, None),
    ("server", r"Microsoft-IIS/" + V, "iis", None, None),
    ("server", r"Apache-Coyote/" + V, "tomcat", None, None),
    ("server", r"Jetty\(" + V, "eclipse-jetty", None, None),
    ("server", r"openresty/" + V, "openresty", None, None),
    ("server", r"lighttpd/" + V, "lighttpd", None, None),
    ("server", r"Caddy", "caddy", None, None),
    ("server", r"Werkzeug/" + V, "werkzeug", "PyPI", "werkzeug"),
    ("server", r"Python/" + V, "python", None, None),
    ("server", r"gunicorn/" + V, "gunicorn", "PyPI", "gunicorn"),
    ("server", r"WEBrick/" + V, "webrick", "RubyGems", "webrick"),
    ("server", r"Kestrel", "dotnet", None, None),
    ("server", r"WildFly/" + V, "wildfly", None, None),
    ("server", r"WebLogic(?: Server)? " + V, "oracle-weblogic", None, None),
    ("server", r"IBM_HTTP_Server/" + V, "ibm-http-server", None, None),
    ("server", r"OpenSSL/" + V, "openssl", None, None),
    ("server", r"PHP/" + V, "php", None, None),
    ("server", r"mod_ssl/" + V, "mod_ssl", None, None),
    ("server", r"Phusion_Passenger/" + V, "passenger", None, None),
    ("server", r"Varnish", "varnish", None, None),
    ("server", r"squid/" + V, "squid", None, None),
    ("server", r"HAProxy", "haproxy", None, None),
    ("server", r"Kong/" + V, "kong-gateway", None, None),
    ("server", r"envoy", "envoy", None, None),
    ("x-powered-by", r"PHP/" + V, "php", None, None),
    ("x-powered-by", r"ASP\.NET", "dotnetfx", None, None),
    ("x-powered-by", r"Express", "express", "npm", "express"),
    ("x-powered-by", r"Next\.js ?" + V + "?", "nextjs", "npm", "next"),
    ("x-powered-by", r"Servlet/" + V, "java-servlet", None, None),
    ("x-powered-by", r"JSP/" + V, "jsp", None, None),
    ("x-powered-by", r"JBoss[- ]?(?:EAP[- ]?)?" + V, "redhat-jboss-eap", None, None),
    ("x-powered-by", r"Undertow/" + V, "undertow", None, None),
    ("x-powered-by", r"Phusion Passenger(?: \(mod_rails/mod_rack\))? " + V, "passenger", None, None),
    ("x-powered-by", r"PleskLin", "plesk", None, None),
    ("x-aspnet-version", V, "dotnetfx", None, None),
    ("x-aspnetmvc-version", V, "aspnet-mvc", "NuGet", "Microsoft.AspNet.Mvc"),
    ("x-generator", r"Drupal " + V, "drupal", None, None),
    ("x-generator", r"WordPress " + V, "wordpress", None, None),
    ("x-drupal-cache", r".*", "drupal", None, None),
    ("x-jenkins", V, "jenkins", None, None),
    ("x-confluence-request-time", r".*", "confluence", None, None),
    ("x-gitlab-meta", r".*", "gitlab", None, None),
    ("x-grafana-version", V, "grafana", None, None),
    ("x-kibana-version", V, "kibana", None, None),
    ("x-elastic-product", r"Elasticsearch", "elasticsearch", None, None),
    ("x-runtime", r".*", "rails", None, None),
    ("x-magento-cache-debug", r".*", "magento", None, None),
    ("x-litespeed-cache", r".*", "litespeed", None, None),
    ("x-owa-version", V, "msexchange", None, None),
    ("x-sharepointhealthscore", r".*", "sharepoint", None, None),
    ("microsoftsharepointteamservices", V, "sharepoint", None, None),
    ("x-amz-cf-id", r".*", "cloudfront", None, None),
    ("x-varnish", r".*", "varnish", None, None),
]

# Cookie name -> technology hint (no version)
COOKIE_HINTS = {
    "phpsessid": "php", "jsessionid": "java-servlet", "asp.net_sessionid": "dotnetfx",
    "aspsessionid": "classic-asp", "laravel_session": "laravel", "ci_session": "codeigniter",
    "csrftoken": "django", "_rails_session": "rails", "cfid": "coldfusion", "cftoken": "coldfusion",
    "connect.sid": "express", "wordpress_logged_in": "wordpress", "symfony": "symfony",
    "zend_session": "zend-framework", "struts_token": "apache-struts", "jenkins": "jenkins",
    "grafana_session": "grafana", "_gitlab_session": "gitlab", "jsessionidsso": "redhat-jboss-eap",
}

# ------------------------------------------------------------------ HTML
HTML_SIGS: list[tuple[str, str, Optional[str], Optional[str]]] = [
    (r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']WordPress ' + V, "wordpress", None, None),
    (r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']Drupal ' + V, "drupal", None, None),
    (r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']Joomla!? ' + V, "joomla", None, None),
    (r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']TYPO3 (?:CMS )?' + V, "typo3", None, None),
    (r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']MediaWiki ' + V, "mediawiki", None, None),
    (r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']Umbraco ' + V, "umbraco", None, None),
    (r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']Plone', "plone", None, None),
    (r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']Hugo ' + V, "hugo", None, None),
    (r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']Discourse ' + V, "discourse", None, None),
    (r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']Moodle', "moodle", None, None),
    (r'ng-version=["\']' + V, "angular", "npm", "@angular/core"),
    (r'\bng-app\b', "angularjs", "npm", "angular"),
    (r'data-reactroot|__REACT_DEVTOOLS', "react", "npm", "react"),
    (r'__NEXT_DATA__', "nextjs", "npm", "next"),
    (r'window\.__NUXT__', "nuxt", "npm", "nuxt"),
    (r'Powered by <a[^>]+>Jenkins ver\. ' + V, "jenkins", None, None),
    (r'Apache Tomcat/' + V, "tomcat", None, None),
    (r'<address>Apache/' + V, "apache-http-server", None, None),
    (r'<hr><center>nginx/' + V, "nginx", None, None),
    (r'Microsoft-IIS/' + V, "iis", None, None),
    (r'Werkzeug Debugger|The debugger caught an exception', "werkzeug", "PyPI", "werkzeug"),
    (r"You're seeing this error because you have <code>DEBUG = True</code>", "django", "PyPI", "django"),
    (r'Confluence ' + V + r'</a>|ajs-version-number" content="' + V, "confluence", None, None),
    (r'data-version="' + V + r'"[^>]*id="jira', "jira-software", None, None),
    (r'phpMyAdmin ' + V, "phpmyadmin", None, None),
    (r'GitLab Community Edition|gon\.gitlab_url', "gitlab", None, None),
    (r'X-AspNet-Version|__VIEWSTATE', "dotnetfx", None, None),
    (r'Powered by .{0,40}Struts', "apache-struts", None, None),
    (r'JBoss(?:AS| EAP| Web)[^<]{0,20}' + V, "redhat-jboss-eap", None, None),
    (r'WebLogic Server(?: Version:)? ' + V, "oracle-weblogic", None, None),
    (r'Grafana v' + V, "grafana", None, None),
    (r'Kibana', "kibana", None, None),
    (r'SonarQube', "sonarqube-server", None, None),
    (r'Spring Boot|Whitelabel Error Page', "spring-boot", "Maven", "org.springframework.boot:spring-boot"),
    (r'ColdFusion', "coldfusion", None, None),
    (r'Laravel', "laravel", "Packagist", "laravel/framework"),
    (r'Magento', "magento", None, None),
]

# ------------------------------------------------------------------ JS library banners / filenames
# (product, ecosystem, npm package, [content regexes], [filename regexes])
JS_LIBS: list[tuple[str, Optional[str], Optional[str], list[str], list[str]]] = [
    ("jquery", "npm", "jquery",
     [r"/\*!? jQuery v" + V, r"jQuery JavaScript Library v" + V, r"jquery:\s*[\"']" + V + r"[\"']", r"\.fn\.jquery\s*=\s*[\"']" + V],
     [r"jquery[.-]" + V + r"(?:\.min|\.slim)*\.js"]),
    ("jquery-ui", "npm", "jquery-ui",
     [r"jQuery UI - v" + V, r"jQuery UI (?:Core )?" + V],
     [r"jquery-ui[.-]" + V + r"(?:\.custom)?(?:\.min)?\.js"]),
    ("jquery-mobile", "npm", "jquery-mobile",
     [r"jQuery Mobile (?:v)?" + V], [r"jquery\.mobile-" + V + r"(?:\.min)?\.js"]),
    ("angularjs", "npm", "angular",
     [r"@license AngularJS v" + V, r"AngularJS v" + V, r"angular\.version\s*=\s*\{full:\s*[\"']" + V],
     [r"angular[.-]" + V + r"(?:\.min)?\.js", r"/angular\.js/" + V + "/"]),
    ("angular", "npm", "@angular/core",
     [r"@angular/core@" + V, r"new [a-zA-Z_$]{1,3}\(\"" + V + r"\"\)[,;][^\n]{0,80}VERSION"], []),
    ("bootstrap", "npm", "bootstrap",
     [r"Bootstrap v" + V + r" \(https?://getbootstrap", r"Bootstrap v" + V],
     [r"bootstrap[.-]" + V + r"(?:\.bundle)?(?:\.min)?\.(?:js|css)", r"/bootstrap/" + V + "/"]),
    ("vue", "npm", "vue",
     [r"Vue\.js v" + V, r"\bversion\s*=\s*[\"']" + V + r"[\"'][^;]{0,40}Vue", r"Vue\.version\s*=\s*[\"']" + V],
     [r"vue[.@-]" + V + r"(?:/dist/vue)?(?:\.min)?\.js", r"/vue/" + V + "/"]),
    ("react", "npm", "react",
     [r"@license React v" + V, r"React v" + V, r"react(?:-dom)?\.production\.min\.js[^\n]{0,40}" + V],
     [r"react(?:-dom)?[.@-]" + V + r"(?:/umd/react)?", r"/react/" + V + "/"]),
    ("lodash", "npm", "lodash",
     [r"@license\s+Lodash\s*(?:\(Custom Build\)\s*)?(?:lodash\.com/license)?[^\n]*\n[^\n]*?" + V, r"var VERSION\s*=\s*[\"']" + V + r"[\"'];[^\n]{0,200}lodash", r"lodash\s+" + V],
     [r"lodash[.-]" + V + r"(?:\.min)?\.js", r"/lodash\.js/" + V + "/"]),
    ("underscore", "npm", "underscore",
     [r"Underscore\.js " + V], [r"underscore[.-]" + V + r"(?:\.min)?\.js"]),
    ("moment", "npm", "moment",
     [r"//! version : " + V, r"moment\.version\s*=\s*[\"']" + V],
     [r"moment[.-]" + V + r"(?:\.min)?\.js", r"/moment\.js/" + V + "/"]),
    ("handlebars", "npm", "handlebars",
     [r"Handlebars v" + V, r"handlebars v" + V], [r"handlebars[.-]v?" + V + r"(?:\.min)?\.js"]),
    ("backbone", "npm", "backbone",
     [r"Backbone\.js " + V], [r"backbone[.-]" + V + r"(?:\.min)?\.js"]),
    ("knockout", "npm", "knockout",
     [r"Knockout JavaScript library v" + V], [r"knockout-" + V + r"(?:\.min)?\.js"]),
    ("emberjs", "npm", "ember-source",
     [r"@version\s+" + V + r"[^\n]*\n[^\n]*Ember", r"Ember\.VERSION\s*=\s*[\"']" + V], [r"ember[.-]" + V + r"(?:\.min)?\.js"]),
    ("dompurify", "npm", "dompurify",
     [r"DOMPurify " + V], [r"purify[.-]" + V + r"(?:\.min)?\.js"]),
    ("tinymce", "npm", "tinymce",
     [r"TinyMCE version " + V, r"tinymce\.majorVersion"], [r"/tinymce/" + V + "/"]),
    ("ckeditor", "npm", "ckeditor4",
     [r"CKEDITOR\.version\s*=\s*[\"']" + V, r"CKEditor " + V], [r"/ckeditor/" + V + "/"]),
    ("chartjs", "npm", "chart.js",
     [r"Chart\.js v" + V], [r"chart(?:\.js)?[@/-]" + V]),
    ("prototypejs", "npm", "prototype",
     [r"Prototype JavaScript framework, version " + V], [r"prototype[.-]" + V + r"\.js"]),
    ("yui", None, None, [r"YUI " + V + r" \(build"], [r"/yui/" + V + "/"]),
    ("swfobject", None, None, [r"SWFObject v" + V], []),
    ("axios", "npm", "axios", [r"axios v" + V], [r"axios[@/-]" + V]),
    ("socket.io", "npm", "socket.io-client", [r"Socket\.IO v" + V], [r"socket\.io[@/-]" + V]),
    ("highcharts", "npm", "highcharts", [r"Highcharts JS v" + V], [r"highcharts[@/-]" + V]),
    ("select2", "npm", "select2", [r"Select2 " + V], [r"select2[@/-]" + V]),
    ("datatables", "npm", "datatables.net", [r"DataTables " + V], [r"datatables[@/-]" + V]),
    ("video.js", "npm", "video.js", [r"Video\.js " + V], [r"video(?:\.js)?[@/-]" + V]),
    ("pdfjs", "npm", "pdfjs-dist", [r"pdfjsVersion\s*=\s*[\"']" + V], [r"pdf\.js/" + V]),
]

_JS_CONTENT = [(p, eco, pkg, [re.compile(r, re.I) for r in c], [re.compile(r, re.I) for r in f]) for p, eco, pkg, c, f in JS_LIBS]


def match_js(content: str, filename: str = "", location: str = "") -> list[Component]:
    out: list[Component] = []
    head = content[:20000]  # banners live at the top of the file
    for product, eco, pkg, crx, frx in _JS_CONTENT:
        found = None
        for rx in crx:
            m = rx.search(head) or (rx.search(content) if len(content) < 2_000_000 and "VERSION" in rx.pattern else None)
            if m:
                ver = next((g for g in m.groups() if g), None) if m.groups() else None
                found = Component(product, ver, eco, pkg, evidence=m.group(0)[:160], location=location,
                                  confidence="high" if ver else "low", source="js-banner")
                break
        if not found and filename:
            for rx in frx:
                m = rx.search(filename)
                if m:
                    found = Component(product, m.group(1), eco, pkg, evidence=f"filename: {filename[-120:]}",
                                      location=location, confidence="medium", source="js-filename")
                    break
        if found:
            out.append(found)
    return out


def match_js_url(url: str) -> list[Component]:
    """Versions from URLs only (e.g. CDN links) without fetching."""
    out = []
    for product, eco, pkg, _crx, frx in _JS_CONTENT:
        for rx in frx:
            m = rx.search(url)
            if m:
                out.append(Component(product, m.group(1), eco, pkg, evidence=f"URL: {url[:200]}", location=url,
                                     confidence="medium", source="js-url"))
                break
    # WordPress-style ?ver= on known libs
    m = re.search(r"/(jquery(?:-migrate)?)(?:\.min)?\.js\?ver=" + V, url, re.I)
    if m and not out and m.group(1).lower() == "jquery":
        out.append(Component("jquery", m.group(2), "npm", "jquery", evidence=f"URL: {url[:200]}", location=url,
                             confidence="low", source="js-url"))
    return out


def match_headers(headers: Iterable[tuple[str, str]], location: str) -> list[Component]:
    out: list[Component] = []
    for name, value in headers:
        lname = name.lower()
        for hname, rx, product, eco, pkg in HEADER_SIGS:
            if hname != lname:
                continue
            m = re.search(rx, value, re.I)
            if m:
                ver = m.group(1) if m.groups() and m.group(1) else None
                out.append(Component(product, ver, eco, pkg, evidence=f"{name}: {value}"[:200], location=location,
                                     confidence="high" if ver else "medium", source="header"))
        if lname == "set-cookie":
            cname = value.split("=", 1)[0].strip().lower()
            for k, product in COOKIE_HINTS.items():
                if cname.startswith(k):
                    out.append(Component(product, None, evidence=f"cookie {value.split('=',1)[0]}", location=location,
                                         confidence="low", source="cookie"))
    return out


_HTML = [(re.compile(rx, re.I), p, e, k) for rx, p, e, k in HTML_SIGS]


def match_html(html: str, location: str) -> list[Component]:
    out = []
    for rx, product, eco, pkg in _HTML:
        m = rx.search(html)
        if m:
            ver = next((g for g in m.groups() if g), None) if m.groups() else None
            out.append(Component(product, ver, eco, pkg, evidence=m.group(0)[:200], location=location,
                                 confidence="high" if ver else "low", source="html"))
    return out
