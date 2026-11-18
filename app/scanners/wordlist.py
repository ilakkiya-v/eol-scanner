"""Content discovery: common paths of legacy web apps that are often not linked from any page.

Used by the optional "Guess common paths" step of the web crawl (GET only, same rate limit, scope check and request
budget as everything else; soft-404 pages are filtered with the baseline 404 fingerprint). Nothing here changes state:
paths that perform actions (logout, shutdown, delete, reset...) are deliberately not in the list, and the crawl's
UNSAFE_LINK filter is applied on top.
"""

PATHS = [
    # entry points and auth
    "/login", "/login.jsp", "/login.do", "/login.php", "/login.aspx", "/login.html", "/signin", "/sign-in", "/auth",
    "/auth/login", "/account", "/account/login", "/accounts/login/", "/user/login", "/users/sign_in", "/sso", "/cas/login",
    "/register", "/signup", "/forgot", "/forgot-password", "/password/reset/request", "/profile", "/home", "/index",
    "/index.php", "/index.jsp", "/index.html", "/default.aspx", "/default.asp", "/main", "/main.do", "/portal", "/dashboard",
    "/welcome", "/start", "/app", "/apps", "/web", "/site", "/en", "/en-us",
    # admin and management
    "/admin", "/admin/", "/admin/login", "/admin/index.php", "/administrator", "/admin.php", "/admin.jsp", "/admin.aspx",
    "/manage", "/management", "/manager", "/console", "/controlpanel", "/cpanel", "/backend", "/backoffice", "/staff",
    "/sysadmin", "/system", "/settings", "/config", "/configuration", "/setup", "/install", "/installer", "/maintenance",
    "/ops", "/support", "/helpdesk", "/moderator", "/webadmin", "/siteadmin", "/admincp", "/panel",
    # APIs and docs
    "/api", "/api/", "/api/v1", "/api/v1/", "/api/v2", "/api/v3", "/rest", "/rest/", "/rest/api", "/services", "/service",
    "/ws", "/webservice", "/webservices", "/soap", "/rpc", "/jsonrpc", "/xmlrpc.php", "/graphql", "/graphiql", "/odata",
    "/api/docs", "/api-docs", "/docs", "/doc", "/documentation", "/swagger", "/swagger/", "/swagger-ui", "/swagger-ui/",
    "/swagger-ui.html", "/swagger/index.html", "/redoc", "/api/swagger", "/wsdl", "/services/listServices",
    "/api/health", "/api/status", "/api/version", "/api/info", "/api/users", "/api/user", "/api/me", "/api/config",
    "/api/admin", "/api/search", "/api/reports",
    # health / info / build
    "/health", "/healthz", "/healthcheck", "/status", "/info", "/version", "/build", "/about", "/ping", "/metrics",
    "/monitor", "/monitoring", "/stats", "/statistics", "/diagnostics", "/debug", "/trace", "/test", "/tests", "/testing",
    "/demo", "/sample", "/samples", "/examples", "/example", "/dev", "/development", "/staging", "/beta", "/old", "/legacy",
    "/backup", "/backups", "/bak", "/temp", "/tmp", "/archive", "/archives",
    # content, files and uploads
    "/upload", "/uploads", "/upload.php", "/fileupload", "/files", "/file", "/download", "/downloads", "/attachments",
    "/media", "/images", "/img", "/assets", "/static", "/public", "/resources", "/content", "/data", "/export", "/exports",
    "/import", "/reports", "/report", "/reporting", "/logs", "/log", "/documents", "/docs/files", "/userfiles",
    # common app features
    "/search", "/search.php", "/search.jsp", "/search.aspx", "/users", "/user", "/members", "/customers", "/accounts",
    "/orders", "/order", "/products", "/product", "/catalog", "/cart", "/checkout", "/invoice", "/invoices", "/billing",
    "/payments", "/messages", "/inbox", "/mail", "/notifications", "/feedback", "/contact", "/help", "/faq", "/news",
    "/blog", "/forum", "/forums", "/wiki", "/calendar", "/tasks", "/projects", "/tickets", "/issues", "/jobs", "/queue",
    "/scheduler", "/workflow", "/audit", "/history", "/preferences",
    # Java / Spring / app servers
    "/WEB-INF/web.xml", "/jmx-console/", "/web-console/", "/invoker/JMXInvokerServlet", "/status.jsp", "/info.jsp",
    "/servlet", "/servlets", "/struts", "/action", "/actions", "/faces", "/jsf", "/portal/web", "/c/portal/login",
    "/axis2", "/axis2/services", "/axis", "/cxf", "/services/", "/jolokia", "/hawtio", "/h2-console", "/env",
    # .NET
    "/elmah.axd", "/trace.axd", "/WebResource.axd", "/ScriptResource.axd", "/umbraco", "/sitecore", "/Account/Login",
    "/Home/Index", "/api/values", "/_layouts", "/_vti_bin",
    # PHP and CMS
    "/phpinfo.php", "/info.php", "/test.php", "/phpmyadmin/", "/pma/", "/adminer.php", "/wp-login.php", "/wp-admin/",
    "/wp-json/", "/wp-json/wp/v2/users", "/xmlrpc.php", "/user/register", "/node", "/typo3/", "/joomla", "/administrator/",
    "/magento", "/downloader/", "/vendor/", "/composer.json",
    # Node / front-end builds
    "/app.js", "/main.js", "/bundle.js", "/config.js", "/env.js", "/settings.js", "/manifest.json", "/asset-manifest.json",
    # (no websocket / event-stream endpoints: they never finish loading)
    
    # misc legacy
    "/cgi-bin/", "/cgi-bin/test-cgi", "/scripts/", "/include/", "/includes/", "/inc/", "/lib/", "/library/", "/common/",
    "/shared/", "/modules/", "/plugins/", "/components/", "/themes/", "/templates/", "/cache/", "/sql/", "/db/",
    "/database/", "/dump/", "/private/", "/secret/", "/hidden/", "/internal/", "/intranet/", "/extranet/", "/partner/",
    "/partners/", "/vendor-portal/", "/mobile/", "/m/", "/wap/", "/lite/", "/classic/", "/v1/", "/v2/",
    # well-known
    "/.well-known/security.txt", "/.well-known/openid-configuration", "/crossdomain.xml", "/clientaccesspolicy.xml",
    "/humans.txt", "/sitemap_index.xml", "/sitemap.xml.gz",
]
PATHS = list(dict.fromkeys(PATHS))  # keep order, drop duplicates
