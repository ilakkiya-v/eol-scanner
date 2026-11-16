"""Probe catalogue. Every probe is a single non-destructive GET/HEAD/OPTIONS
request; none sends exploit payloads. A probe counts as a hit only if the body
matches `match` (soft-404 protection), and isn't the same as the baseline 404.

mode:  safe   - well-known disclosure files and error-page fingerprinting
       active - product-specific version endpoints, debug/admin consoles,
                HTTP method checks (louder: many app-specific paths)
"""
from __future__ import annotations

P = []


def probe(path, match, title, category="exposure", severity="medium", mode="safe", product=None, version_rx=None,
          parse_as=None, kb=None, redact=False, method="GET"):
    P.append(dict(path=path, match=match, title=title, category=category, severity=severity, mode=mode,
                  product=product, version_rx=version_rx, parse_as=parse_as, kb=kb or category, redact=redact,
                  method=method))


# ---------------- source / dependency disclosure (safe)
probe("/package.json", r'"(?:dependencies|devDependencies|name)"\s*:', "Exposed package.json", parse_as="package.json", kb="exposed-manifest")
probe("/package-lock.json", r'"lockfileVersion"', "Exposed package-lock.json", parse_as="package-lock.json", kb="exposed-manifest")
probe("/yarn.lock", r"# yarn lockfile|__metadata:", "Exposed yarn.lock", parse_as="yarn.lock", kb="exposed-manifest")
probe("/composer.json", r'"require"\s*:', "Exposed composer.json", parse_as="composer.json", kb="exposed-manifest")
probe("/composer.lock", r'"packages"\s*:\s*\[', "Exposed composer.lock", parse_as="composer.lock", kb="exposed-manifest")
probe("/vendor/composer/installed.json", r'"packages"|"name"\s*:\s*"[\w-]+/', "Exposed composer installed.json", parse_as="composer.lock", kb="exposed-manifest")
probe("/Gemfile.lock", r"GEM\s+remote:", "Exposed Gemfile.lock", parse_as="Gemfile.lock", kb="exposed-manifest")
probe("/requirements.txt", r"^[A-Za-z0-9_.\-]+\s*==\s*\d", "Exposed requirements.txt", parse_as="requirements.txt", kb="exposed-manifest")
probe("/go.mod", r"^module\s+\S+", "Exposed go.mod", parse_as="go.mod", kb="exposed-manifest")
probe("/pom.xml", r"<project[\s>]", "Exposed pom.xml", parse_as="pom.xml", kb="exposed-manifest")
probe("/web.config", r"<configuration", "Exposed web.config", severity="high", parse_as="web.config", kb="exposed-config")
probe("/.git/HEAD", r"^ref:\s*refs/", "Exposed .git repository", severity="high", kb="exposed-vcs")
probe("/.git/config", r"\[core\]", "Exposed .git/config", severity="high", kb="exposed-vcs", redact=True)
probe("/.svn/entries", r"^\d+\s*$|svn:", "Exposed .svn metadata", severity="high", kb="exposed-vcs")
probe("/.hg/requires", r"revlogv1|store", "Exposed Mercurial repo", severity="high", kb="exposed-vcs")
probe("/.env", r"^(?:APP_|DB_|[A-Z_]+=)", "Exposed .env file (secrets)", severity="critical", kb="exposed-secrets", redact=True)
probe("/.DS_Store", r"Bud1", "Exposed .DS_Store (directory listing)", severity="low", kb="exposed-files")
probe("/WEB-INF/web.xml", r"<web-app", "Exposed WEB-INF/web.xml", severity="high", kb="exposed-config")
probe("/robots.txt", r"(?i)user-agent|disallow", "robots.txt present (review disallowed paths)", category="info", severity="info", kb="info")
probe("/crossdomain.xml", r'allow-access-from\s+domain="\*"', "Permissive crossdomain.xml", severity="low", kb="legacy-flash")
probe("/clientaccesspolicy.xml", r'<domain uri="\*"', "Permissive clientaccesspolicy.xml (Silverlight)", severity="low", kb="legacy-flash")

# ---------------- CMS / framework version files (safe)
probe("/readme.html", r"WordPress", "WordPress readme.html", category="version-disclosure", severity="low", product="wordpress", version_rx=r"Version\s+(\d+(?:\.\d+)+)")
probe("/wp-includes/js/jquery/jquery.js", r"jQuery", "WordPress bundled jQuery", category="version-disclosure", severity="info", product="wordpress")
probe("/CHANGELOG.txt", r"Drupal (\d+\.\d+)", "Drupal 7 CHANGELOG.txt", category="version-disclosure", severity="low", product="drupal", version_rx=r"Drupal (\d+\.\d+(?:\.\d+)?)")
probe("/core/CHANGELOG.txt", r"Drupal (\d+\.\d+)", "Drupal 8+ CHANGELOG.txt", category="version-disclosure", severity="low", product="drupal", version_rx=r"Drupal (\d+\.\d+(?:\.\d+)?)")
probe("/administrator/manifests/files/joomla.xml", r"<version>", "Joomla manifest", category="version-disclosure", severity="low", product="joomla", version_rx=r"<version>([\d.]+)</version>")
probe("/typo3conf/ext/", r"Index of", "TYPO3 extension listing", severity="medium", product="typo3", kb="directory-listing")
probe("/magento_version", r"Magento/\d", "Magento version endpoint", category="version-disclosure", severity="low", product="magento", version_rx=r"Magento/([\d.]+)")
probe("/phpmyadmin/ChangeLog", r"phpMyAdmin - ChangeLog", "phpMyAdmin ChangeLog", category="version-disclosure", severity="medium", product="phpmyadmin", version_rx=r"^(\d+\.\d+\.\d+)", kb="admin-console")
probe("/phpMyAdmin/README", r"phpMyAdmin", "phpMyAdmin README", category="version-disclosure", severity="medium", product="phpmyadmin", version_rx=r"Version (\d+\.\d+\.\d+)", kb="admin-console")

# ---------------- server status / info (safe)
probe("/server-status", r"Apache Server Status", "Apache mod_status exposed", severity="medium", product="apache-http-server", version_rx=r"Server Version: Apache/([\d.]+)", kb="status-page")
probe("/server-info", r"Apache Server Information", "Apache mod_info exposed", severity="medium", product="apache-http-server", version_rx=r"Server Version:.*?Apache/([\d.]+)", kb="status-page")
probe("/nginx_status", r"Active connections:", "nginx stub_status exposed", severity="low", kb="status-page")
probe("/phpinfo.php", r"<title>phpinfo\(\)|PHP Version", "phpinfo() page exposed", severity="high", product="php", version_rx=r"PHP Version (\d+\.\d+\.\d+)", kb="debug-endpoint")
probe("/info.php", r"<title>phpinfo\(\)|PHP Version", "phpinfo() page exposed", severity="high", product="php", version_rx=r"PHP Version (\d+\.\d+\.\d+)", kb="debug-endpoint")
probe("/elmah.axd", r"Error Log for", "ELMAH error log exposed", severity="high", kb="debug-endpoint")
probe("/trace.axd", r"Application Trace", "ASP.NET trace.axd exposed", severity="high", kb="debug-endpoint")

# ---------------- product version endpoints (active)
probe("/api/health", r'"version"\s*:\s*"[\d.]+"', "Grafana /api/health version", category="version-disclosure", severity="low", mode="active", product="grafana", version_rx=r'"version"\s*:\s*"([\d.]+)"')
probe("/api/status", r'"version"\s*:\s*\{\s*"number"', "Kibana /api/status version", category="version-disclosure", severity="low", mode="active", product="kibana", version_rx=r'"number"\s*:\s*"([\d.]+)"')
probe("/", r'"cluster_name"\s*:.*"number"\s*:\s*"[\d.]+"', "Elasticsearch root banner (unauthenticated)", category="exposure", severity="high", mode="active", product="elasticsearch", version_rx=r'"number"\s*:\s*"([\d.]+)"', kb="unauth-datastore")
probe("/rest/api/2/serverInfo", r'"version"\s*:\s*"[\d.]+"', "Jira serverInfo", category="version-disclosure", severity="low", mode="active", product="jira-software", version_rx=r'"version"\s*:\s*"([\d.]+)"')
probe("/rest/applinks/1.0/manifest", r"<version>", "Atlassian applinks manifest", category="version-disclosure", severity="low", mode="active", product="confluence", version_rx=r"<version>([\d.]+)</version>")
probe("/api/server/version", r"^\d+\.\d+", "SonarQube version", category="version-disclosure", severity="low", mode="active", product="sonarqube-server", version_rx=r"^(\d+\.\d+(?:\.\d+)?)")
probe("/artifactory/api/system/version", r'"version"', "Artifactory version", category="version-disclosure", severity="low", mode="active", product="artifactory", version_rx=r'"version"\s*:\s*"([\d.]+)"')
probe("/service/rest/v1/status", r".*", "Nexus status endpoint", category="info", severity="info", mode="active", product="nexus")
probe("/api/v4/version", r'"version"', "GitLab version API", category="version-disclosure", severity="low", mode="active", product="gitlab", version_rx=r'"version"\s*:\s*"([\d.]+)')
probe("/help", r"GitLab (?:Community|Enterprise) Edition\s*<?[^\d]{0,40}(\d+\.\d+)", "GitLab help page version", category="version-disclosure", severity="low", mode="active", product="gitlab", version_rx=r"GitLab (?:Community|Enterprise) Edition[^\d]{0,40}(\d+\.\d+(?:\.\d+)?)")
probe("/login", r"Jenkins", "Jenkins login", category="info", severity="info", mode="active", product="jenkins", version_rx=r"Jenkins ver\. ([\d.]+)")
probe("/docs/", r"Apache Tomcat", "Tomcat docs (default webapp)", category="exposure", severity="low", mode="active", product="tomcat", version_rx=r"Apache Tomcat ?(?:Version )?(\d+\.\d+\.\d+)", kb="default-content")
probe("/examples/servlets/", r"Servlet Examples", "Tomcat examples webapp", category="exposure", severity="medium", mode="active", product="tomcat", kb="default-content")
probe("/manager/html", r"Tomcat Web Application Manager|tomcat-users\.xml", "Tomcat Manager reachable", category="exposure", severity="high", mode="active", product="tomcat", kb="admin-console")
probe("/host-manager/html", r"Tomcat Virtual Host Manager", "Tomcat Host Manager reachable", category="exposure", severity="high", mode="active", product="tomcat", kb="admin-console")
probe("/jmx-console/", r"JMX Agent View|JBoss", "JBoss JMX console reachable", category="exposure", severity="critical", mode="active", product="redhat-jboss-eap", kb="admin-console")
probe("/web-console/", r"JBoss|Web Console", "JBoss web-console reachable", category="exposure", severity="high", mode="active", product="redhat-jboss-eap", kb="admin-console")
probe("/console/login/LoginForm.jsp", r"WebLogic", "WebLogic admin console reachable", category="exposure", severity="high", mode="active", product="oracle-weblogic", version_rx=r"WebLogic Server Version: ([\d.]+)", kb="admin-console")
probe("/CFIDE/administrator/", r"ColdFusion", "ColdFusion administrator reachable", category="exposure", severity="high", mode="active", product="coldfusion", kb="admin-console")
probe("/solr/admin/info/system?wt=json", r'"solr-spec-version"', "Solr admin API (unauthenticated)", category="exposure", severity="high", mode="active", product="solr", version_rx=r'"solr-spec-version"\s*:\s*"([\d.]+)"', kb="admin-console")
probe("/zabbix/", r"Zabbix", "Zabbix frontend", category="info", severity="info", mode="active", product="zabbix", version_rx=r"Zabbix ([\d.]+)")
probe("/nagios/", r"Nagios", "Nagios frontend", category="info", severity="info", mode="active", product="nagios")
probe("/owa/", r"Outlook", "Exchange OWA", category="info", severity="info", mode="active", product="msexchange")

# ---------------- framework debug / actuator (active)
probe("/actuator", r'"_links"\s*:', "Spring Boot Actuator index exposed", severity="medium", mode="active", product="spring-boot", kb="actuator")
probe("/actuator/env", r'"propertySources"|"activeProfiles"', "Spring Boot /actuator/env exposed", severity="critical", mode="active", product="spring-boot", kb="actuator", redact=True)
probe("/actuator/heapdump", r".*", "Spring Boot heapdump endpoint", severity="critical", mode="active", product="spring-boot", kb="actuator", method="HEAD")
probe("/actuator/info", r'"build"|"git"|"app"', "Spring Boot /actuator/info", category="version-disclosure", severity="low", mode="active", product="spring-boot", kb="actuator")
probe("/env", r'"propertySources"|"profiles"', "Spring Boot 1.x /env exposed", severity="critical", mode="active", product="spring-boot", kb="actuator", redact=True)
probe("/console", r"Werkzeug|Interactive Console", "Werkzeug debug console", severity="critical", mode="active", product="werkzeug", kb="debug-endpoint")
probe("/_ignition/health-check", r'"can_execute_commands"', "Laravel Ignition exposed", severity="high", mode="active", product="laravel", kb="debug-endpoint")
probe("/_profiler/", r"Symfony Profiler", "Symfony profiler exposed", severity="high", mode="active", product="symfony", kb="debug-endpoint")
probe("/rails/info/properties", r"Rails version", "Rails info page exposed", severity="medium", mode="active", product="rails", version_rx=r"Rails version</td>\s*<td[^>]*>([\d.]+)", kb="debug-endpoint")
probe("/__debug__/", r"djdt|Django Debug Toolbar", "Django Debug Toolbar", severity="medium", mode="active", product="django", kb="debug-endpoint")
probe("/swagger-ui.html", r"swagger", "Swagger UI exposed", category="info", severity="low", mode="active", kb="api-docs")
probe("/v2/api-docs", r'"swagger"\s*:', "Swagger API docs exposed", category="info", severity="low", mode="active", kb="api-docs")
probe("/graphql?query=%7B__typename%7D", r'"__typename"', "GraphQL endpoint", category="info", severity="info", mode="active", kb="api-docs")
probe("/struts/webconsole.html", r"OGNL Console", "Struts OGNL web console", severity="critical", mode="active", product="apache-struts", kb="debug-endpoint")

SAFE = [p for p in P if p["mode"] == "safe"]
ACTIVE = [p for p in P if p["mode"] == "active"]
