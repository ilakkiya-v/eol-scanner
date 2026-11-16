"""Containment knowledge base.

EOL software that will never receive code changes can't be "fixed" in place,
so advice focuses on *containment*: reduce exposure, add compensating
controls in front of it, detect exploitation, and plan retirement. Manual
test suggestions are for authorized lab verification only.
"""
from __future__ import annotations

from typing import Optional


def S(title: str, detail: str, snippet: Optional[str] = None, effort: str = "medium", kind: str = "contain") -> dict:
    d = {"title": title, "detail": detail, "effort": effort, "kind": kind}
    if snippet:
        d["snippet"] = snippet
    return d


# ---------------------------------------------------------------- generic EOL containment
GENERIC_EOL = [
    S("Restrict network reachability",
      "Put the app behind the lab VPN only and allowlist the specific tester/QA source ranges at the firewall or reverse proxy. "
      "EOL components should never be reachable from general corp or internet networks.",
      "# nginx (in front of the EOL app)\nallow 10.0.0.0/8;     # QA / VPN ranges\ndeny  all;", effort="low", kind="isolate"),
    S("Egress filtering",
      "Block outbound connections from the EOL host except to required dependencies. Most RCE chains (JNDI/LDAP, SSRF, reverse shells, "
      "payload download) need egress; default-deny outbound breaks them even when the vuln is unpatched.",
      "# iptables example: allow only DNS to corp resolver + DB\niptables -P OUTPUT DROP\niptables -A OUTPUT -o lo -j ACCEPT\n"
      "iptables -A OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT\niptables -A OUTPUT -p udp -d <corp-dns> --dport 53 -j ACCEPT\n"
      "iptables -A OUTPUT -p tcp -d <db-host> --dport 5432 -j ACCEPT", effort="medium", kind="isolate"),
    S("Virtual patching with a WAF",
      "Place a WAF/reverse proxy (e.g. ModSecurity + OWASP CRS, cloud WAF, F5 ASM) in front and enable rules for the CVEs listed on this finding. "
      "Run in detection mode in QA first, then blocking.", effort="medium", kind="virtual-patch"),
    S("Compensating authentication",
      "Require SSO in front of the app (oauth2-proxy / IdP-aware proxy) so unauthenticated attack surface of the legacy stack is not reachable.",
      effort="medium", kind="isolate"),
    S("Harden the runtime",
      "Run as a non-root, least-privilege service account; read-only filesystem where possible; drop container capabilities; no shared credentials with production.",
      effort="medium", kind="harden"),
    S("Detection & monitoring",
      "Forward web/app logs to SIEM and alert on exploit signatures for the listed CVEs, new child processes of the app server, and unexpected outbound connections.",
      effort="medium", kind="detect"),
    S("Hide version banners",
      "Strip Server / X-Powered-By / X-AspNet-Version headers and default error pages at the proxy. This does not fix anything but slows automated targeting.",
      "# nginx\nserver_tokens off;\nproxy_hide_header X-Powered-By;\nproxy_hide_header X-AspNet-Version;\nproxy_hide_header Server;",
      effort="low", kind="harden"),
    S("Risk acceptance with an expiry",
      "Record a time-boxed risk acceptance (owner, compensating controls above, review date) and a retirement/upgrade plan. "
      "If the app must live on, evaluate commercial extended-support offerings for the component.", effort="low", kind="govern"),
]

# ---------------------------------------------------------------- per-product knowledge
PRODUCTS: dict[str, dict] = {
    "log4j": {
        "contain": [
            S("Remove the JndiLookup class", "For log4j-core 2.x that cannot be upgraded: delete JndiLookup from the jar. For 1.x: remove JMSAppender/SocketServer/JDBCAppender classes and their config.",
              "zip -q -d log4j-core-*.jar org/apache/logging/log4j/core/lookup/JndiLookup.class\n# log4j 1.x\nzip -q -d log4j-1.2.*.jar org/apache/log4j/net/JMSAppender.class org/apache/log4j/net/SocketServer.class",
              effort="low", kind="virtual-patch"),
            S("Disable lookups", "2.10+: set -Dlog4j2.formatMsgNoLookups=true (insufficient alone for CVE-2021-45046, combine with class removal).", effort="low", kind="virtual-patch"),
        ],
        "manual": [
            "Lab only: send a benign DNS-only canary in a header that is logged (User-Agent, X-Api-Version, X-Forwarded-For): ${jndi:dns://<your-oob-domain>/eolscan}. A DNS hit on your interactsh/Collaborator server confirms the lookup path without code execution.",
            "Search the deployed artifact for vulnerable jars: find / -name 'log4j-core-*.jar' and nested in WAR/EAR (unzip -l app.war | grep log4j).",
            "For 1.x: grep the log4j.properties/xml for JMSAppender, SocketServer, JDBCAppender, Chainsaw to determine reachable CVEs.",
        ],
        "extended": "Vendors that bundle log4j (e.g. app servers) may ship mitigated builds; check vendor advisories.",
    },
    "apache-struts": {
        "contain": [
            S("WAF rules for OGNL injection", "Block OGNL markers (%{, ${, #_memberAccess, @java.lang.Runtime) in Content-Type, URL params and multipart filenames.",
              "SecRule REQUEST_HEADERS:Content-Type|ARGS|ARGS_NAMES|FILES_NAMES \"@rx (?:%\\{|\\$\\{|#_memberAccess|@java\\.lang\\.)\" \\\n  \"id:100100,phase:2,deny,status:403,msg:'Struts OGNL injection'\"",
              effort="low", kind="virtual-patch"),
            S("Disable devMode and dynamic method invocation", "struts.devMode=false, struts.enable.DynamicMethodInvocation=false, restrict struts.action.extension.", effort="low", kind="harden"),
        ],
        "manual": [
            "Fingerprint exact version from WEB-INF/lib/struts2-core-*.jar or /struts/ static paths.",
            "Lab only: run nuclei templates for the listed CVEs (e.g. `nuclei -u <target> -id CVE-2017-5638,CVE-2018-11776,CVE-2023-50164`) — they use benign arithmetic/echo payloads.",
            "Review file upload actions for CVE-2023-50164 / CVE-2024-53677 style path traversal in a lab clone.",
        ],
        "extended": "HeroDevs NES and some app-server vendors offer patched Struts builds.",
    },
    "spring-framework": {
        "contain": [
            S("Block class-loader parameter binding (Spring4Shell class)", "Reject requests with parameters matching class.*, Class.*, *.class.*, *.Class.* at the WAF.",
              "SecRule ARGS_NAMES \"@rx (?i)(?:^|\\.)class\\.\" \"id:100200,phase:2,deny,status:403,msg:'Spring class binding'\"",
              effort="low", kind="virtual-patch"),
            S("Global @InitBinder denylist", "Add a ControllerAdvice that sets disallowedFields {\"class.*\",\"Class.*\",\"*.class.*\",\"*.Class.*\"} — a config-only change if code changes are allowed at all.", effort="low", kind="virtual-patch"),
        ],
        "manual": [
            "Confirm JDK version (>=9) and WAR-on-Tomcat packaging; both are prerequisites for CVE-2022-22965.",
            "Lab only: benign check — POST class.module.classLoader.DefaultAssertionStatus=nonsense; a 400 response indicates binding reaches the class loader (vulnerable path), 200 suggests not.",
        ],
        "extended": "Spring commercial support (Tanzu) and HeroDevs NES provide patches for EOL Spring lines.",
    },
    "spring-boot": {
        "contain": [
            S("Lock down Actuator", "Expose only health/info; move management to a separate internal port; require auth.",
              "management.endpoints.web.exposure.include=health,info\nmanagement.server.port=9001\nmanagement.server.address=127.0.0.1", effort="low", kind="harden"),
            S("Block actuator paths at the proxy", "Deny /actuator/* (and /env, /heapdump, /jolokia, /trace for Boot 1.x) from untrusted networks.",
              "location ~ ^/(actuator|env|heapdump|jolokia|trace|dump|mappings)(/|$) { deny all; return 404; }", effort="low", kind="isolate"),
        ],
        "manual": [
            "Check /actuator/heapdump, /env, /jolokia exposure; a heap dump typically contains credentials and session tokens (do not exfiltrate — confirm presence via HEAD / size only).",
            "Determine underlying Spring Framework version from /actuator/info or the fat jar BOOT-INF/lib.",
        ],
    },
    "tomcat": {
        "contain": [
            S("Remove default webapps", "Delete docs, examples, host-manager and manager (or bind manager to localhost with a RemoteAddrValve).",
              "<!-- conf/Catalina/localhost/manager.xml -->\n<Context><Valve className=\"org.apache.catalina.valves.RemoteAddrValve\" allow=\"127\\.0\\.0\\.1\"/></Context>",
              effort="low", kind="harden"),
            S("Disable AJP or bind it locally with a secret", "Ghostcat (CVE-2020-1938) needs AJP reachable. Comment out the AJP connector or set address=127.0.0.1 secretRequired=true.", effort="low", kind="isolate"),
            S("Hide version in error pages", "Set server.info / ErrorReportValve showServerInfo=false showReport=false.",
              "<Valve className=\"org.apache.catalina.valves.ErrorReportValve\" showReport=\"false\" showServerInfo=\"false\"/>", effort="low", kind="harden"),
        ],
        "manual": [
            "Scan for AJP (8009/tcp) reachability from the tester network: nmap -sV -p8009 <host>.",
            "If manager is reachable, test for default credentials only with written authorization (tomcat/tomcat, admin/admin) and lockout awareness.",
            "Check for PUT enabled (readonly=false in web.xml) — CVE-2017-12617 class; confirm with an OPTIONS request rather than uploading.",
        ],
    },
    "jquery": {
        "contain": [
            S("Content-Security-Policy", "A strict CSP (no unsafe-inline/unsafe-eval, nonce-based scripts) blunts most jQuery XSS gadgets (CVE-2020-11022/11023, CVE-2019-11358 prototype pollution chains).",
              "Content-Security-Policy: default-src 'self'; script-src 'self' 'nonce-{RANDOM}'; object-src 'none'; base-uri 'none'", effort="medium", kind="virtual-patch"),
            S("jQuery Migrate / drop-in patched build", "If code can't change but static assets can, swapping the file for the last patch release of the same major (1.12.4 → patched forks, 3.x → 3.7.1) is usually low-risk; test in QA.", effort="low", kind="upgrade"),
            S("Subresource Integrity", "Pin CDN-loaded libraries with integrity= hashes so a compromised CDN can't swap code.", effort="low", kind="harden"),
        ],
        "manual": [
            "Find sinks: grep the app JS for .html(, .append(, $( with URL/user data (location.hash, location.search).",
            "Lab only: test DOM-XSS with a harmless payload such as <img src=x onerror=console.log(1)> on any parameter reflected into those sinks.",
            "For CVE-2019-11358: look for $.extend(true, {}, userControlledJSON) and test with {\"__proto__\":{\"eolscan\":1}} then check ({}).eolscan in the console.",
        ],
        "extended": "HeroDevs NES offers patched jQuery 1.x/2.x/3.x builds.",
    },
    "jquery-ui": {
        "contain": [S("CSP + restrict option sources", "Known XSS (CVE-2021-41182/41183/41184, CVE-2022-31160) is via widget options; ensure options are never user-controlled and enforce CSP.", effort="medium", kind="virtual-patch")],
        "manual": ["Review calls to .datepicker/.dialog/.tooltip/.position for options built from URL or user input."],
    },
    "angularjs": {
        "contain": [
            S("Strict CSP and ng-csp", "AngularJS 1.x is EOL since 2021-12-31. Client-side template injection ({{constructor.constructor('...')()}}) bypasses sanitizers; use ng-csp + strict CSP, never render user input inside ng-app scope.", effort="medium", kind="virtual-patch"),
            S("Server-side encoding of {{ }}", "Encode {{ and }} in any server-rendered user data inside ng-app elements, or add ng-non-bindable around user content.", effort="medium", kind="virtual-patch"),
        ],
        "manual": [
            "Lab only: test client-side template injection by submitting {{7*7}} into fields rendered inside ng-app; a rendered 49 confirms CSTI.",
            "Check angular.version.full in the browser console to confirm the exact version.",
        ],
        "extended": "HeroDevs NES for AngularJS and Google's XLTS successor offerings provide patched 1.x builds.",
    },
    "bootstrap": {
        "contain": [S("Don't feed user data to data-* attributes", "Bootstrap 3/4 XSS (CVE-2018-14040/14041/14042, CVE-2019-8331) is via data-target/data-template/tooltip attributes; enforce CSP and audit templates.", effort="low", kind="virtual-patch")],
        "manual": ["Grep templates for data-target, data-template, data-content populated from user data."],
        "extended": "HeroDevs NES offers patched Bootstrap 3/4.",
    },
    "moment": {
        "contain": [S("Bound input length", "Moment ReDoS (CVE-2022-31129, CVE-2017-18214) is triggered by long date strings; cap length of user-supplied dates server-side/at WAF.", effort="low", kind="virtual-patch")],
        "manual": ["Locate moment(userInput) / moment(userInput, format) usage with untrusted input."],
    },
    "php": {
        "contain": [
            S("Disable dangerous functions", "php.ini: disable_functions=exec,passthru,shell_exec,system,proc_open,popen; expose_php=Off; allow_url_include=Off; open_basedir set.", effort="low", kind="harden"),
            S("PHP-FPM not reachable", "Ensure FastCGI (9000/tcp) is bound to localhost/unix socket only.", effort="low", kind="isolate"),
        ],
        "manual": ["Check for CVE-2019-11043 (nginx + php-fpm path_info) prerequisites in nginx config: fastcgi_split_path_info with regex ending in ^(.+?\\.php)(/.*)$ and no try_files.",
                   "Check phpinfo exposure and allow_url_include/allow_url_fopen settings."],
        "extended": "Zend PHP LTS, TuxCare ELS for PHP, and distro vendors (RHEL/Ubuntu Pro) backport fixes for EOL PHP.",
    },
    "python": {"contain": [], "manual": ["Identify interpreter-level CVEs reachable from the app (e.g. tarfile/zipfile extraction, urllib parsing) and where untrusted input reaches them."],
               "extended": "Ubuntu Pro ESM / RHEL / TuxCare ELS provide patched Python 2.7/3.x for supported distros."},
    "nodejs": {"contain": [S("Run behind a reverse proxy", "Terminate HTTP at nginx/HAProxy to mitigate Node HTTP parser smuggling/DoS CVEs in old Node versions.", effort="low", kind="isolate")],
               "manual": ["Test request smuggling against the proxy+node pair with a lab tool (e.g. smuggler.py) only with authorization."],
               "extended": "HeroDevs NES for Node.js provides patched EOL Node versions."},
    "dotnetfx": {
        "contain": [S("Protect machineKey and ViewState", "Ensure ViewState MAC is enabled and machineKey is unique/secret; leaked keys = RCE via ViewState deserialization.", effort="low", kind="harden"),
                    S("Remove version headers", "<httpRuntime enableVersionHeader=\"false\"/> and remove X-Powered-By in IIS.",
                      "<system.web><httpRuntime enableVersionHeader=\"false\" /></system.web>\n<system.webServer><httpProtocol><customHeaders><remove name=\"X-Powered-By\"/></customHeaders></httpProtocol></system.webServer>", effort="low", kind="harden")],
        "manual": ["Check trace.axd / elmah.axd exposure and customErrors mode.", "Look for __VIEWSTATE without __VIEWSTATEGENERATOR MAC; test with ViewState decoders in lab."],
    },
    "dotnet": {"contain": [], "manual": ["Confirm runtime version via `dotnet --list-runtimes` on host or from deps.json in the published app."],
               "extended": "Microsoft does not patch EOL .NET Core lines; HeroDevs NES offers support for some."},
    "iis": {"contain": [S("Request filtering", "Use IIS Request Filtering to deny unused verbs (PUT, DELETE, TRACE, WebDAV) and hidden segments (web.config, bin, App_Data).", effort="low", kind="harden")],
            "manual": ["Check WebDAV (PROPFIND) and short-name (~1) disclosure with IIS ShortName scanner in lab.", "Map IIS version to Windows Server version; the OS is likely EOL too."],
            "extended": "Microsoft Extended Security Updates (ESU) via Azure Arc for Windows Server 2012/2012 R2."},
    "apache-http-server": {"contain": [S("Disable unused modules", "Remove mod_status/mod_info/mod_cgi/mod_userdir/mod_dav if unused; ServerTokens Prod; ServerSignature Off.",
                                         "ServerTokens Prod\nServerSignature Off\nTraceEnable Off", effort="low", kind="harden")],
                           "manual": ["Check path traversal CVE-2021-41773/42013 only if version is 2.4.49/2.4.50 (nuclei templates, lab only)."]},
    "nginx": {"contain": [S("Hide version", "server_tokens off;", "server_tokens off;", effort="low", kind="harden")],
              "manual": ["Review alias/location misconfigurations (off-by-slash path traversal) in nginx config."]},
    "wordpress": {"contain": [S("Lock down admin & XML-RPC", "Restrict /wp-admin and /wp-login.php to VPN ranges; disable xmlrpc.php; disable plugin/theme editors (DISALLOW_FILE_EDIT).",
                                "location ~ ^/(wp-admin|wp-login\\.php|xmlrpc\\.php) { allow 10.0.0.0/8; deny all; }", effort="low", kind="isolate")],
                  "manual": ["Enumerate plugins/themes and versions (wpscan --enumerate vp,vt in lab) — plugins are the usual entry point."]},
    "drupal": {"contain": [S("WAF rules for Drupalgeddon class", "Block '#' prefixed render-array keys in parameters (e.g. #post_render, #markup) — Drupalgeddon2 (CVE-2018-7600).", effort="low", kind="virtual-patch")],
               "manual": ["Check CHANGELOG.txt and core version; run droopescan in lab."],
               "extended": "Drupal 7 ended 2025-01-05; Tag1 / HeroDevs offer D7 extended support."},
    "jenkins": {"contain": [S("Require auth and restrict network", "Disable anonymous read, CLI over remoting, and restrict /script, /scriptText to admins on VPN.", effort="low", kind="isolate")],
                "manual": ["Check anonymous access to /script, /asynchPeople, /computer; check CLI port (X-Jenkins-CLI-Port header).", "Review CVE-2024-23897 (arbitrary file read via CLI args) applicability if < 2.442 / LTS 2.426.3."]},
    "confluence": {"contain": [S("Restrict to VPN + WAF", "Atlassian OGNL CVEs (CVE-2022-26134, CVE-2023-22515/22518/22527) are pre-auth; block from all untrusted networks.", effort="low", kind="isolate")],
                   "manual": ["Lab only: nuclei -id CVE-2022-26134,CVE-2023-22527 (detection templates)."]},
    "elasticsearch": {"contain": [S("Enable security", "xpack.security.enabled: true; bind to internal interface; never expose 9200 without auth.", effort="low", kind="harden")],
                      "manual": ["Check unauthenticated _cat/indices access (read-only GET)."]},
    "grafana": {"contain": [], "manual": ["Check CVE-2021-43798 path traversal (/public/plugins/<id>/../../) in lab if 8.0.0-8.3.0."]},
    "redhat-jboss-eap": {"contain": [S("Remove/secure consoles", "Remove jmx-console, web-console, invoker servlets (JMXInvokerServlet, EJBInvokerServlet) — common deserialization RCE vectors.", effort="low", kind="harden")],
                         "manual": ["Check /invoker/JMXInvokerServlet and /invoker/EJBInvokerServlet reachability (GET returns serialized Java)."]},
    "oracle-weblogic": {"contain": [S("Block T3/IIOP from untrusted networks", "Use connection filters to restrict T3/T3S/IIOP to admin hosts; most WebLogic RCEs use these protocols.", effort="low", kind="isolate")],
                        "manual": ["Check T3 exposure: nmap -sV --script weblogic-t3-info -p7001 <host>.", "Check /wls-wsat/ and /_async/ endpoints (CVE-2017-10271, CVE-2019-2725)."]},
    "coldfusion": {"contain": [S("Lock down CFIDE", "Block /CFIDE/administrator, /CFIDE/adminapi, /cf_scripts from non-admin networks.", effort="low", kind="isolate")], "manual": []},
    "centos": {"contain": [], "manual": ["Inventory exposed services on the host (nmap -sV); each is likely an EOL package too."],
               "extended": "TuxCare ELS for CentOS 6/7/8, or migrate to RHEL (RHEL 7 ELS) / AlmaLinux / Rocky via in-place tools (ELevate, convert2rhel)."},
    "windows-server": {"contain": [], "manual": [], "extended": "Microsoft Extended Security Updates (ESU) via Azure Arc."},
    "django": {"contain": [S("Disable DEBUG", "DEBUG=False and restrict ALLOWED_HOSTS.", effort="low", kind="harden")], "manual": ["Trigger a 404 and check for the Django debug page."]},
    "rails": {"contain": [], "manual": ["Check for /rails/info and verbose error pages; check secret_key_base exposure in repo."]},
    "laravel": {"contain": [S("Disable debug / Ignition", "APP_DEBUG=false; remove facade/ignition from production deps (CVE-2021-3129).", effort="low", kind="harden")],
                "manual": ["Check /_ignition/execute-solution reachability (CVE-2021-3129) in lab."]},
    "eclipse-temurin": {"contain": [], "manual": ["Check deserialization endpoints (RMI, JMX, T3) exposed by the JVM: nmap -sV for 1099/9999/7001."],
                        "extended": "Azul, Red Hat and other vendors provide paid updates for older Java LTS lines."},
    "openssl": {"contain": [], "manual": ["Run testssl.sh against the endpoint to see which protocol/cipher-level issues are reachable."]},
    "phpmyadmin": {"contain": [S("Remove or restrict", "phpMyAdmin should not be reachable from tester networks; bind to localhost/SSH tunnel.", effort="low", kind="isolate")], "manual": []},
    "solr": {"contain": [S("Enable auth and restrict admin API", "Enable BasicAuth plugin; block /solr/admin and config APIs from untrusted networks.", effort="low", kind="isolate")],
             "manual": ["Check VelocityResponseWriter / params.resource.loader (CVE-2019-17558) and DataImportHandler exposure (read-only GETs)."]},
    "magento": {"contain": [], "manual": ["Run magescan in lab; check admin path exposure."], "extended": "Magento 1 is EOL since 2020-06-30; Mage-OS/OpenMage are community forks."},
}

# ---------------------------------------------------------------- non-component findings (exposures, config, code)
KB: dict[str, dict] = {
    "exposed-manifest": {"contain": [S("Block dependency files at the proxy", "Deny dotfiles and dependency manifests/lockfiles from being served.",
                                        "location ~* /(?:\\.|package(?:-lock)?\\.json|yarn\\.lock|composer\\.(?:json|lock)|Gemfile(?:\\.lock)?|requirements\\.txt|go\\.mod|pom\\.xml|vendor/composer/) { deny all; return 404; }",
                                        effort="low", kind="harden")],
                         "manual": ["Use the disclosed dependency list to prioritize which library CVEs to verify."]},
    "exposed-vcs": {"contain": [S("Block VCS metadata", "Deny /.git, /.svn, /.hg at the web server and remove them from the deploy artifact.",
                                  "location ~ /\\.(git|svn|hg)(/|$) { deny all; return 404; }\n# Apache\nRedirectMatch 404 /\\.(git|svn|hg)", effort="low", kind="harden")],
                    "manual": ["Lab only: confirm repo reconstruction is possible with git-dumper into an isolated folder; review history for secrets; rotate any found."]},
    "exposed-secrets": {"contain": [S("Remove and rotate", "Remove the file from the webroot immediately and rotate every credential it contained.", effort="low", kind="harden")],
                        "manual": ["Do not reuse discovered credentials beyond what the engagement authorizes; report and rotate."]},
    "exposed-config": {"contain": [S("Block config files", "Deny web.config / WEB-INF / *.config / *.properties from being served; check handler mappings.", effort="low", kind="harden")],
                       "manual": ["Review the config for machineKey, connection strings, debug flags."]},
    "exposed-files": {"contain": [S("Clean deploy artifacts", "Exclude .DS_Store and editor/backup files from deployment.", effort="low", kind="harden")], "manual": []},
    "status-page": {"contain": [S("Restrict status pages", "Limit server-status/info/stub_status to localhost.",
                                  "<Location /server-status>\n  Require local\n</Location>", effort="low", kind="harden")],
                    "manual": ["Review server-status for internal URLs, client IPs, and session tokens in query strings."]},
    "debug-endpoint": {"contain": [S("Disable debug features", "Turn off debug/trace/profiler endpoints in the deployed config and block their paths at the proxy.", effort="low", kind="harden")],
                       "manual": ["Debug consoles (Werkzeug, Ignition, profiler) frequently give code execution; verify reachability only, don't execute commands without explicit authorization."]},
    "admin-console": {"contain": [S("Restrict admin consoles", "Bind admin consoles to localhost / admin VLAN, require MFA/SSO, and block paths at the proxy.", effort="low", kind="isolate")],
                      "manual": ["Check for default credentials only if explicitly in the rules of engagement (watch account lockout)."]},
    "actuator": PRODUCTS["spring-boot"],
    "default-content": {"contain": [S("Remove default/sample apps", "Delete sample apps and docs shipped with the server.", effort="low", kind="harden")], "manual": []},
    "directory-listing": {"contain": [S("Disable autoindex", "nginx: autoindex off; Apache: Options -Indexes; IIS: directoryBrowse enabled=false.", "autoindex off;\n# Apache\nOptions -Indexes", effort="low", kind="harden")],
                          "manual": ["Browse the listing for backups (.bak, .old, .zip) and config files."]},
    "unauth-datastore": PRODUCTS["elasticsearch"],
    "api-docs": {"contain": [S("Restrict API docs", "Serve Swagger/GraphQL introspection only on internal/dev profiles.", effort="low", kind="harden")],
                 "manual": ["Use the API spec to enumerate unauthenticated endpoints and test authz (IDOR) in lab."]},
    "http-methods": {"contain": [S("Disable unused verbs", "Allow only GET/POST/HEAD (and those the app needs).",
                                   "if ($request_method !~ ^(GET|POST|HEAD)$) { return 405; }\n# Apache\nTraceEnable Off", effort="low", kind="harden")],
                     "manual": ["Verify PUT/DELETE/WebDAV are not actually writable — use OPTIONS and a non-destructive PROPFIND rather than uploading."]},
    "legacy-tls": {"contain": [S("Terminate TLS on a modern proxy", "If the legacy server can't be reconfigured, front it with a TLS-terminating proxy that only offers TLS 1.2+.",
                                 "ssl_protocols TLSv1.2 TLSv1.3;\nssl_prefer_server_ciphers on;", effort="low", kind="isolate")],
                   "manual": ["Run testssl.sh <host:port> for a full protocol/cipher/vuln matrix."]},
    "certificate": {"contain": [S("Renew / use corp CA", "Issue the certificate from the corporate internal CA and mount that CA into this scanner (SSL_CERT_FILE) to remove noise.", effort="low", kind="harden")], "manual": []},
    "header-disclosure": {"contain": [GENERIC_EOL[6]], "manual": []},
    "legacy-flash": {"contain": [S("Remove cross-domain policy files", "Flash/Silverlight are EOL; remove crossdomain.xml / clientaccesspolicy.xml or restrict domains.", effort="low", kind="harden")], "manual": []},
    "deserialization": {"contain": [S("Isolate deserialization endpoints", "Block endpoints that accept serialized objects at the proxy, add JEP 290 serialization filters (jdk.serialFilter) for Java, and egress-filter the host.",
                                      "-Djdk.serialFilter=!org.apache.commons.collections.functors.*;!org.codehaus.groovy.runtime.*;!com.sun.rowset.*", effort="medium", kind="virtual-patch")],
                        "manual": ["Trace whether the deserialized data can come from the network; lab-test with ysoserial URLDNS payload (DNS-only, no execution) to confirm reachability."]},
    "struts": PRODUCTS["apache-struts"],
    "log4j": PRODUCTS["log4j"],
    "python2": {"contain": [], "manual": [], "extended": "Python 2.7 is EOL since 2020-01-01; distro ESM (RHEL 7/8, Ubuntu Pro) still patches system python2."},
    "php-legacy": PRODUCTS["php"],
    "code-injection": {"contain": [S("Block at WAF", "Add a WAF rule for the affected parameter(s); this is directly exploitable.", effort="low", kind="virtual-patch")],
                       "manual": ["Confirm with a benign expression (arithmetic) in lab only."]},
    "viewstate": PRODUCTS["dotnetfx"],
    "angularjs": PRODUCTS["angularjs"],
    "dom-xss": PRODUCTS["jquery"],
    "secrets": {"contain": [S("Rotate & purge", "Rotate the credential and purge it from history (git filter-repo) and from build artifacts.", effort="low", kind="harden")], "manual": []},
    "weak-crypto": {"contain": [], "manual": ["Assess where the weak setting is used and whether an attacker can sit on that network path (MITM in lab)."]},
    # ---------------- application-level weaknesses (code can't change -> filter in front, limit blast radius behind)
    "sql-injection": {"contain": [
        S("Virtual-patch with the OWASP Core Rule Set",
          "Put ModSecurity/Coraza (or your WAF) in front of the app with CRS SQLi rules (942xxx) at paranoia level 2+ in blocking mode for the affected paths. "
          "Start in detection-only for a day of QA traffic, tune false positives, then block.",
          "# Apache / nginx-modsecurity\nSecRuleEngine On\nInclude /etc/modsecurity/crs/crs-setup.conf\nInclude /etc/modsecurity/crs/rules/*.conf\n"
          "SecAction \"id:900000,phase:1,pass,nolog,setvar:tx.blocking_paranoia_level=2\"", effort="medium", kind="virtual-patch"),
        S("Allowlist parameter formats at the proxy",
          "If a parameter should only ever be numeric or a short code, reject anything else at the reverse proxy. This is the most reliable fix when code can't change.",
          "# nginx: only digits allowed for ?id= on /report\nlocation /report {\n  if ($arg_id !~ \"^[0-9]{1,10}$\") { return 400; }\n  proxy_pass http://legacy_app;\n}", effort="low", kind="virtual-patch"),
        S("Least-privilege database account",
          "Point the app at a DB login that can only read/write the tables it needs: no DDL, no xp_cmdshell / COPY PROGRAM / LOAD_FILE / INTO OUTFILE, no access to other schemas. "
          "This turns a full compromise into a limited data exposure.", effort="medium", kind="harden"),
        S("Detect", "Alert on DB errors in app logs (syntax errors, 'unclosed quotation mark'), WAF 942xxx hits, and unusual query volume from the app account.", effort="low", kind="detect"),
    ], "manual": [
        "Lab only: send a single quote (') and a benign boolean pair (id=1 AND 1=1 vs id=1 AND 1=2) to the flagged parameter and compare responses.",
        "For deeper confirmation run sqlmap against an isolated clone only, with --level 1 --risk 1 (read-only checks), never on shared QA.",
        "Confirm the WAF rule blocks the same requests after it is deployed."]},
    "command-injection": {"contain": [
        S("Block shell metacharacters for the affected parameters",
          "Reject ; | & ` $( ) < > and newlines in the flagged parameters at the WAF/proxy (CRS 932xxx rules cover this).",
          "# nginx\nif ($args ~* \"(%3B|;|%7C|\\||%60|`|%24%28|\\$\\(|%26|&&)\") { return 400; }", effort="low", kind="virtual-patch"),
        S("Run the app as an unprivileged user with egress blocked",
          "Command injection gives the attacker whatever the app user can do. Use a dedicated low-privilege account, a read-only filesystem where possible, and default-deny outbound traffic so no reverse shell or download works.", effort="medium", kind="isolate"),
        S("Detect", "Alert on unexpected child processes of the app server (sh, cmd.exe, powershell, curl, wget, nc) with EDR or auditd.",
          "# auditd: log every execve by the app user\n-a always,exit -F arch=b64 -S execve -F uid=<app-uid> -k legacy_app_exec", effort="low", kind="detect"),
    ], "manual": ["Lab only: inject a harmless time delay (e.g. `;sleep 5`) or a DNS lookup to a canary you control into the flagged parameter and observe."]},
    "xss": {"contain": [
        S("Add a Content-Security-Policy at the proxy",
          "A CSP added by the reverse proxy blocks injected inline scripts without touching the app. Start with Report-Only, review violations, then enforce.",
          "# nginx\nadd_header Content-Security-Policy-Report-Only \"default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'self'\" always;\n"
          "# Apache\nHeader always set Content-Security-Policy \"default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'self'\"", effort="medium", kind="virtual-patch"),
        S("WAF XSS rules for the affected parameters", "Enable CRS 941xxx rules (or the WAF's XSS signatures) in blocking mode for the flagged pages.", effort="low", kind="virtual-patch"),
        S("Protect session cookies", "Make session cookies HttpOnly and SameSite at the proxy so stolen-cookie attacks don't work even if a script runs (see cookie-flags).",
          "# nginx >= 1.19.3\nproxy_cookie_flags ~ httponly secure samesite=lax;", effort="low", kind="harden"),
    ], "manual": ["Lab only: submit a harmless marker such as <i>eolscan</i> or \"><svg> in the flagged parameter and check whether it renders unencoded.",
                 "After adding CSP, confirm a test payload no longer executes and the app still works (check the browser console for CSP violations)."]},
    "path-traversal": {"contain": [
        S("Block traversal sequences at the proxy", "Reject ../, ..\\, %2e%2e, null bytes and absolute paths in the flagged parameters (CRS 930xxx).",
          "# nginx\nif ($args ~* \"(\\.\\./|\\.\\.%2f|%2e%2e|%00|\\.\\.\\\\)\") { return 400; }", effort="low", kind="virtual-patch"),
        S("Restrict what the app can read", "Run the app with filesystem permissions limited to its own directories; keep secrets (keys, configs of other apps) unreadable by the app user. For PHP set open_basedir and allow_url_include=Off.",
          "; php.ini\nopen_basedir = /var/www/app:/tmp\nallow_url_include = Off", effort="medium", kind="harden"),
    ], "manual": ["Lab only: request a known harmless file through the parameter (e.g. ../../../../etc/hostname or ..\\..\\windows\\win.ini) and check the response."]},
    "ssrf": {"contain": [
        S("Egress-filter the app host", "Default-deny outbound from the app; allow only the specific hosts it must call. Block cloud metadata (169.254.169.254) and internal admin ranges explicitly.",
          "iptables -A OUTPUT -d 169.254.169.254 -j DROP\n# then allow only the required upstreams", effort="medium", kind="isolate"),
        S("Allowlist URL values at the proxy", "If the parameter should only point to a few known hosts, reject any other value at the WAF/proxy.", effort="low", kind="virtual-patch"),
        S("Use IMDSv2 / metadata protection", "On AWS require IMDSv2 (hop limit 1); on GCP/Azure require the metadata header, so SSRF can't read cloud credentials.", effort="low", kind="harden"),
    ], "manual": ["Lab only: point the parameter at a canary URL you control (or a DNS canary) and confirm whether the server calls it."]},
    "xxe": {"contain": [
        S("Reject DOCTYPE in XML requests at the WAF", "Block request bodies containing <!DOCTYPE or <!ENTITY on the endpoints that accept XML.",
          "SecRule REQUEST_BODY \"@rx <!(?:DOCTYPE|ENTITY)\" \"id:100010,phase:2,deny,status:400,msg:'XML DTD not allowed'\"", effort="low", kind="virtual-patch"),
        S("Disable DTDs via JVM/system settings where possible", "For Java you can set system properties without code changes: -Djavax.xml.accessExternalDTD=\"\" -Djavax.xml.accessExternalSchema=\"\" (JAXP 1.5+). Egress filtering also stops out-of-band XXE.",
          "-Djavax.xml.accessExternalDTD=\"\" -Djavax.xml.accessExternalSchema=\"\" -Djdk.xml.entityExpansionLimit=1000", effort="low", kind="harden"),
    ], "manual": ["Lab only: send an XML body with an external entity pointing at a DNS canary you control; a lookup confirms XXE without reading files."]},
    "open-redirect": {"contain": [
        S("Allowlist redirect targets at the proxy", "Reject redirect parameters that are absolute URLs to other domains (or that start with //).",
          "# nginx: only allow relative paths in ?next=\nif ($arg_next ~* \"^(https?:|//|%2f%2f)\") { return 400; }", effort="low", kind="virtual-patch"),
    ], "manual": ["Lab only: set the parameter to https://example.com and check whether the response redirects there."]},
    "security-headers": {"contain": [
        S("Add the headers at the reverse proxy", "All of these can be added in front of the app without touching its code.",
          "# nginx\nadd_header X-Frame-Options \"SAMEORIGIN\" always;\nadd_header X-Content-Type-Options \"nosniff\" always;\n"
          "add_header Referrer-Policy \"strict-origin-when-cross-origin\" always;\nadd_header Strict-Transport-Security \"max-age=31536000\" always;\n"
          "add_header Content-Security-Policy-Report-Only \"default-src 'self'; object-src 'none'; frame-ancestors 'self'\" always;\n\n"
          "# Apache (mod_headers)\nHeader always set X-Frame-Options \"SAMEORIGIN\"\nHeader always set X-Content-Type-Options \"nosniff\"\n\n"
          "# IIS web.config\n<httpProtocol><customHeaders>\n  <add name=\"X-Frame-Options\" value=\"SAMEORIGIN\" />\n  <add name=\"X-Content-Type-Options\" value=\"nosniff\" />\n</customHeaders></httpProtocol>",
          effort="low", kind="harden"),
    ], "manual": ["Roll CSP out as Report-Only first; legacy apps often rely on inline scripts, so check the browser console before enforcing."]},
    "cookie-flags": {"contain": [
        S("Set cookie flags at the proxy", "Add Secure, HttpOnly and SameSite to cookies as they pass through the proxy, without changing the app.",
          "# nginx >= 1.19.3\nproxy_cookie_flags ~ secure httponly samesite=lax;\n\n# Apache 2.4\nHeader always edit Set-Cookie \"(?i)^((?:(?!;\\s?HttpOnly).)+)$\" \"$1; HttpOnly\"\n"
          "Header always edit Set-Cookie \"(?i)^((?:(?!;\\s?Secure).)+)$\" \"$1; Secure\"\n\n# IIS / ASP.NET web.config\n<httpCookies httpOnlyCookies=\"true\" requireSSL=\"true\" sameSite=\"Lax\" />",
          effort="low", kind="harden"),
    ], "manual": ["After the change, log in and confirm the app still works (some legacy JS reads its own cookies; leave those without HttpOnly)."]},
    "cors": {"contain": [
        S("Override CORS at the proxy", "Strip the app's Access-Control-* headers and set a fixed allowlist of trusted origins, or none at all if no cross-site access is needed.",
          "# nginx\nproxy_hide_header Access-Control-Allow-Origin;\nproxy_hide_header Access-Control-Allow-Credentials;\n"
          "map $http_origin $cors_ok { default \"\"; \"https://portal.qa.corp\" $http_origin; }\nadd_header Access-Control-Allow-Origin $cors_ok always;", effort="low", kind="virtual-patch"),
    ], "manual": ["Lab only: from a page on another origin, try fetch(target, {credentials: 'include'}) and see whether the response is readable."]},
    "cleartext-login": {"contain": [
        S("Force HTTPS at the proxy", "Terminate TLS on a modern proxy and redirect all HTTP to HTTPS; add HSTS once HTTPS works everywhere.",
          "# nginx\nserver { listen 80; return 301 https://$host$request_uri; }", effort="low", kind="harden"),
    ], "manual": ["Capture a lab login with a proxy (Burp/ZAP) or tcpdump and confirm the password is sent in clear text before and not after the fix."]},
    "imported": {"contain": [
        S("Virtual-patch at the WAF/proxy", "Map the finding to the WAF rule group that covers it (OWASP CRS: 941 XSS, 942 SQLi, 930 traversal, 932 command injection, 934 SSRF/Node) and enable it in blocking mode for the affected paths.", effort="medium", kind="virtual-patch"),
        S("Limit reachability", "Restrict the affected endpoint to the QA/VPN ranges that need it.", effort="low", kind="isolate"),
    ], "manual": ["Re-run the original tool's check after the containment is in place to confirm it is no longer exploitable."]},
    "info": {"contain": [], "manual": []},
    "config": {"contain": [], "manual": []},
}


def _dedupe(items: list[dict]) -> list[dict]:
    seen, out = set(), []
    for i in items:
        if i["title"] not in seen:
            seen.add(i["title"])
            out.append(i)
    return out


def advise_component(product: str, lifecycle: dict, vulns: list[dict]) -> dict:
    kb = PRODUCTS.get(product, {})
    status = lifecycle.get("status")
    contain = list(kb.get("contain", []))
    manual = list(kb.get("manual", []))
    upgrade = []
    if lifecycle.get("latest_cycle"):
        upgrade.append(S("Plan upgrade / replacement",
                         f"Move to a supported {product} release (latest cycle {lifecycle.get('latest_cycle')}, latest {lifecycle.get('latest_version') or 'n/a'}). "
                         + ("This cycle is already end-of-life and will not receive security fixes." if status == "eol" else
                            f"This cycle reaches EOL on {lifecycle.get('eol_date')}." if status == "eol_soon" else
                            f"Patch within the cycle to {lifecycle.get('cycle_latest')}." if lifecycle.get("outdated_patch") else ""),
                         effort="high", kind="upgrade"))
    if status in ("eol", "eol_soon") or any(v["severity"] in ("critical", "high") for v in vulns):
        contain += GENERIC_EOL
    serious = [v for v in vulns if v["severity"] in ("critical", "high")]
    if serious:
        ids = ", ".join((v["aliases"][0] if v.get("aliases") else v["id"]) for v in serious[:8])
        manual.append(f"Prioritize verifying: {ids}. Check whether each vulnerable code path is reachable in this deployment (feature enabled, endpoint exposed, auth required?).")
        cves = [v["aliases"][0] for v in serious if v.get("aliases")]
        if cves:
            manual.append(f"Lab only: check for public detection templates — `nuclei -u <target> -id {','.join(cves[:10])}` (detection templates are non-destructive; review each before running).")
        manual.append("Reproduce any exploit only in an isolated clone of the QA app, never against shared environments.")
    return {"containment": _dedupe(contain) + upgrade, "manual_tests": manual, "extended_support": kb.get("extended")}


def advise_kb(kb_key: str) -> dict:
    kb = KB.get(kb_key) or {}
    return {"containment": _dedupe(list(kb.get("contain", []))), "manual_tests": list(kb.get("manual", [])),
            "extended_support": kb.get("extended")}
