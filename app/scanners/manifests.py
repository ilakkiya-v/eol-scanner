"""Dependency manifest / lockfile / runtime-pin parsers.

Each parser takes (path, text) and returns Components. Used both by code
review (zip upload) and by the web scanner when a lockfile is exposed.
Nothing here executes project code.
"""
from __future__ import annotations

import io
import json
import re
import zipfile
from pathlib import PurePosixPath
from typing import Callable, Optional
from xml.etree import ElementTree as ET

from .fingerprints import Component

# ecosystem package -> endoflife product
PKG_PRODUCT = {
    "npm": {
        "jquery": "jquery", "jquery-ui": "jquery-ui", "jquery-ui-dist": "jquery-ui", "angular": "angularjs",
        "@angular/core": "angular", "react": "react", "vue": "vue", "bootstrap": "bootstrap", "next": "nextjs",
        "nuxt": "nuxt", "ember-source": "emberjs", "express": "express", "moment": "moment", "request": "request",
        "node-sass": "node-sass", "@nestjs/core": "nestjs", "electron": "electron", "svelte": "svelte",
        "tailwindcss": "tailwind-css", "@ionic/angular": "ionic", "react-native": "react-native", "eslint": "eslint",
        "font-awesome": "font-awesome", "@fortawesome/fontawesome-free": "font-awesome", "vuetify": "vuetify",
        "quasar": "quasar", "jquery-mobile": "jquery-mobile", "protractor": "protractor", "yarn": "yarn",
        "pnpm": "pnpm", "@adonisjs/core": "adonisjs", "grunt": "grunt", "@strapi/strapi": "strapi",
    },
    "PyPI": {
        "django": "django", "numpy": "numpy", "ansible": "ansible", "ansible-core": "ansible-core",
        "apache-airflow": "apache-airflow", "wagtail": "wagtail", "dbt-core": "dbt-core", "plone": "plone",
    },
    "Packagist": {
        "laravel/framework": "laravel", "symfony/symfony": "symfony", "symfony/http-kernel": "symfony",
        "drupal/core": "drupal", "drupal/core-recommended": "drupal", "cakephp/cakephp": "cakephp",
        "magento/product-community-edition": "magento", "typo3/cms-core": "typo3", "twig/twig": "twig",
        "guzzlehttp/guzzle": "guzzle", "livewire/livewire": "livewire", "silverstripe/framework": "silverstripe",
        "craftcms/cms": "craft-cms", "shopware/core": "shopware", "api-platform/core": "api-platform",
        "sylius/sylius": "sylius", "laravel/horizon": "horizon", "statamic/cms": "statamic", "contao/core-bundle": "contao",
    },
    "RubyGems": {"rails": "rails", "railties": "rails", "jekyll": "jekyll"},
    "Maven": {
        "org.springframework:spring-core": "spring-framework", "org.springframework:spring-webmvc": "spring-framework",
        "org.springframework:spring-web": "spring-framework", "org.springframework:spring-context": "spring-framework",
        "org.springframework.boot:spring-boot": "spring-boot", "org.springframework.boot:spring-boot-starter-parent": "spring-boot",
        "org.springframework.boot:spring-boot-starter-web": "spring-boot", "org.springframework.boot:spring-boot-autoconfigure": "spring-boot",
        "org.springframework.security:spring-security-core": "spring-security",
        "org.apache.logging.log4j:log4j-core": "log4j", "log4j:log4j": "log4j",
        "org.apache.struts:struts2-core": "apache-struts", "struts:struts": "apache-struts",
        "org.hibernate:hibernate-core": "hibernate-orm", "org.hibernate.orm:hibernate-core": "hibernate-orm",
        "org.apache.tomcat.embed:tomcat-embed-core": "tomcat", "org.apache.tomcat:tomcat-catalina": "tomcat",
        "org.eclipse.jetty:jetty-server": "eclipse-jetty", "io.quarkus:quarkus-core": "quarkus-framework",
        "io.micronaut:micronaut-core": "micronaut", "org.codehaus.groovy:groovy": "apache-groovy",
        "org.apache.groovy:groovy": "apache-groovy", "org.apache.camel:camel-core": "apache-camel",
        "org.apache.kafka:kafka-clients": "apache-kafka", "org.apache.solr:solr-core": "solr",
        "org.apache.lucene:lucene-core": "apache-lucene", "io.dropwizard:dropwizard-core": "dropwizard",
        "org.liquibase:liquibase-core": "liquibase", "org.grails:grails-core": "grails",
        "org.apache.activemq:activemq-broker": "apache-activemq", "org.apache.zookeeper:zookeeper": "zookeeper",
        "org.springframework.cloud:spring-cloud-commons": "spring-cloud",
    },
    "NuGet": {},
    "Go": {},
}

# well-known jar artifact -> Maven coordinates (for jars without pom.properties)
JAR_COORDS = {
    "log4j-core": "org.apache.logging.log4j:log4j-core", "log4j-api": "org.apache.logging.log4j:log4j-api",
    "log4j": "log4j:log4j", "spring-core": "org.springframework:spring-core", "spring-webmvc": "org.springframework:spring-webmvc",
    "spring-web": "org.springframework:spring-web", "spring-beans": "org.springframework:spring-beans",
    "spring-boot": "org.springframework.boot:spring-boot", "struts2-core": "org.apache.struts:struts2-core",
    "struts": "struts:struts", "commons-collections": "commons-collections:commons-collections",
    "commons-collections4": "org.apache.commons:commons-collections4", "commons-text": "org.apache.commons:commons-text",
    "commons-fileupload": "commons-fileupload:commons-fileupload", "jackson-databind": "com.fasterxml.jackson.core:jackson-databind",
    "xstream": "com.thoughtworks.xstream:xstream", "fastjson": "com.alibaba:fastjson", "hibernate-core": "org.hibernate:hibernate-core",
    "tomcat-embed-core": "org.apache.tomcat.embed:tomcat-embed-core", "jetty-server": "org.eclipse.jetty:jetty-server",
    "snakeyaml": "org.yaml:snakeyaml", "h2": "com.h2database:h2", "groovy": "org.codehaus.groovy:groovy",
    "bcprov-jdk15on": "org.bouncycastle:bcprov-jdk15on", "c3p0": "com.mchange:c3p0", "shiro-core": "org.apache.shiro:shiro-core",
}

DOCKER_IMAGES = {
    "node": "nodejs", "python": "python", "php": "php", "ruby": "ruby", "golang": "go", "openjdk": "eclipse-temurin",
    "eclipse-temurin": "eclipse-temurin", "adoptopenjdk": "eclipse-temurin", "amazoncorretto": "amazon-corretto",
    "tomcat": "tomcat", "nginx": "nginx", "httpd": "apache-http-server", "centos": "centos", "ubuntu": "ubuntu",
    "debian": "debian", "alpine": "alpine-linux", "mysql": "mysql", "mariadb": "mariadb", "postgres": "postgresql",
    "redis": "redis", "mongo": "mongodb", "elasticsearch": "elasticsearch", "kibana": "kibana", "jenkins": "jenkins",
    "wordpress": "wordpress", "drupal": "drupal", "joomla": "joomla", "rabbitmq": "rabbitmq", "memcached": "memcached",
    "haproxy": "haproxy", "traefik": "traefik", "fedora": "fedora", "rockylinux": "rocky-linux", "almalinux": "almalinux",
    "amazonlinux": "amazon-linux", "oraclelinux": "oracle-linux", "ubi8": "rhel", "ubi7": "rhel", "ubi9": "rhel",
    "dotnet/aspnet": "dotnet", "dotnet/runtime": "dotnet", "dotnet/sdk": "dotnet", "dotnet/core/aspnet": "dotnet",
    "dotnet/core/runtime": "dotnet", "dotnet/core/sdk": "dotnet", "dotnet/framework/aspnet": "dotnetfx",
    "dotnet/framework/runtime": "dotnetfx", "dotnet/framework/sdk": "dotnetfx", "jboss/wildfly": "wildfly",
    "sonarqube": "sonarqube-server", "grafana/grafana": "grafana", "gitlab/gitlab-ce": "gitlab", "solr": "solr",
    "zookeeper": "zookeeper", "cassandra": "apache-cassandra", "couchdb": "apache-couchdb", "neo4j": "neo4j",
    "keycloak/keycloak": "keycloak", "jboss/keycloak": "keycloak", "bitnami/keycloak": "keycloak",
}
DEBIAN_CODENAMES = {"trixie": "13", "bookworm": "12", "bullseye": "11", "buster": "10", "stretch": "9", "jessie": "8", "wheezy": "7"}
UBUNTU_CODENAMES = {"noble": "24.04", "jammy": "22.04", "focal": "20.04", "bionic": "18.04", "xenial": "16.04", "trusty": "14.04"}


def _c(product, version, path, evidence, eco=None, pkg=None, conf="high", source="manifest", **extra) -> Component:
    return Component(product=product, version=version, ecosystem=eco, package=pkg, evidence=evidence[:200],
                     location=path, confidence=conf, source=source, extra=extra)


def _pkg(eco: str, name: str, version: Optional[str], path: str, evidence: str, conf="high", direct=True) -> Component:
    product = PKG_PRODUCT.get(eco, {}).get(name if eco != "PyPI" else name.lower(), f"{eco.lower()}:{name}")
    return _c(product, version, path, evidence, eco, name, conf, "manifest", direct=direct)


def _clean_range(spec: str) -> tuple[Optional[str], str]:
    """'^1.12.4' -> ('1.12.4','low'); '1.12.4' -> ('1.12.4','high')."""
    spec = (spec or "").strip()
    if re.search(r"\.(?:x|\*)$", spec, re.I):
        m = re.match(r"v?(\d+(?:\.\d+)*)", spec)
        return (m.group(1), "low") if m else (None, "low")
    if re.fullmatch(r"\d+(\.\d+)*([-.+][\w.]+)?", spec):
        return spec, "high"
    m = re.search(r"\d+(\.\d+)*", spec)
    return (m.group(0), "low") if m else (None, "low")


# ------------------------------------------------------------------ JS
def parse_package_json(path: str, text: str) -> list[Component]:
    d = json.loads(text)
    out = []
    for sect in ("dependencies", "devDependencies", "peerDependencies"):
        for name, spec in (d.get(sect) or {}).items():
            if not isinstance(spec, str):
                continue
            ver, conf = _clean_range(spec)
            out.append(_pkg("npm", name, ver, path, f'{sect}: "{name}": "{spec}"', conf))
    node = (d.get("engines") or {}).get("node")
    if node:
        ver, _ = _clean_range(node)
        out.append(_c("nodejs", ver, path, f'engines.node: "{node}"', conf="low", source="runtime-pin"))
    return out


def parse_package_lock(path: str, text: str) -> list[Component]:
    d = json.loads(text)
    out = []
    if "packages" in d:
        for key, meta in d["packages"].items():
            if not key or not isinstance(meta, dict) or "version" not in meta:
                continue
            name = meta.get("name") or key.split("node_modules/")[-1]
            out.append(_pkg("npm", name, meta["version"], path, f"{key}@{meta['version']}", direct=key.count("node_modules/") == 1))
    else:
        def walk(deps, depth=0):
            for name, meta in (deps or {}).items():
                if isinstance(meta, dict) and meta.get("version"):
                    out.append(_pkg("npm", name, meta["version"], path, f"{name}@{meta['version']}", direct=depth == 0))
                    walk(meta.get("dependencies"), depth + 1)
        walk(d.get("dependencies"))
    return out


def parse_yarn_lock(path: str, text: str) -> list[Component]:
    out = []
    for m in re.finditer(r'^"?(@?[^@\s"]+)@[^\n]*:\n(?:\s+[^\n]*\n)*?\s+version:?\s+"?([^"\n]+)"?', text, re.M):
        out.append(_pkg("npm", m.group(1), m.group(2), path, f"{m.group(1)}@{m.group(2)}"))
    return out


# ------------------------------------------------------------------ Python
def parse_requirements(path: str, text: str) -> list[Component]:
    out = []
    for line in text.splitlines():
        line = line.split("#")[0].strip()
        m = re.match(r"^([A-Za-z0-9_.\-\[\]]+)\s*(==|>=|~=|<=)\s*([\w.\-*]+)", line)
        if m:
            name = re.sub(r"\[.*\]", "", m.group(1))
            out.append(_pkg("PyPI", name, m.group(3), path, line, "high" if m.group(2) == "==" else "low"))
    return out


def parse_pipfile_lock(path: str, text: str) -> list[Component]:
    d = json.loads(text)
    out = []
    for sect in ("default", "develop"):
        for name, meta in (d.get(sect) or {}).items():
            v = (meta.get("version") or "").lstrip("=")
            if v:
                out.append(_pkg("PyPI", name, v, path, f"{name}=={v}"))
    py = ((d.get("_meta") or {}).get("requires") or {}).get("python_version")
    if py:
        out.append(_c("python", py, path, f"requires.python_version: {py}", source="runtime-pin"))
    return out


def parse_poetry_lock(path: str, text: str) -> list[Component]:
    return [_pkg("PyPI", m.group(1), m.group(2), path, f"{m.group(1)}=={m.group(2)}")
            for m in re.finditer(r'\[\[package\]\]\s*\nname\s*=\s*"([^"]+)"\s*\nversion\s*=\s*"([^"]+)"', text)]


def parse_pyproject(path: str, text: str) -> list[Component]:
    m = re.search(r'(?:requires-python|^python)\s*=\s*"([^"]+)"', text, re.M)
    if m:
        ver, _ = _clean_range(m.group(1))
        return [_c("python", ver, path, m.group(0), conf="low", source="runtime-pin")]
    return []


def parse_runtime_txt(path: str, text: str) -> list[Component]:
    m = re.search(r"python-?(\d+(?:\.\d+)*)", text)
    return [_c("python", m.group(1), path, m.group(0), source="runtime-pin")] if m else []


def parse_setup_py(path: str, text: str) -> list[Component]:
    m = re.search(r"python_requires\s*=\s*['\"]([^'\"]+)", text)
    if m:
        ver, _ = _clean_range(m.group(1))
        return [_c("python", ver, path, m.group(0), conf="low", source="runtime-pin")]
    return []


# ------------------------------------------------------------------ PHP / Ruby / Go
def parse_composer_json(path: str, text: str) -> list[Component]:
    d = json.loads(text)
    out = []
    for sect in ("require", "require-dev"):
        for name, spec in (d.get(sect) or {}).items():
            ver, conf = _clean_range(str(spec))
            if name == "php":
                out.append(_c("php", ver, path, f'require.php: "{spec}"', conf="low", source="runtime-pin"))
            elif "/" in name:
                out.append(_pkg("Packagist", name, ver, path, f'"{name}": "{spec}"', conf))
    return out


def parse_composer_lock(path: str, text: str) -> list[Component]:
    d = json.loads(text)
    out = []
    for sect in ("packages", "packages-dev"):
        for p in d.get(sect) or []:
            v = str(p.get("version", "")).lstrip("v")
            out.append(_pkg("Packagist", p.get("name"), v, path, f"{p.get('name')} {v}"))
    plat = (d.get("platform") or {}).get("php")
    if plat:
        ver, _ = _clean_range(plat)
        out.append(_c("php", ver, path, f"platform.php: {plat}", conf="low", source="runtime-pin"))
    return out


def parse_gemfile_lock(path: str, text: str) -> list[Component]:
    out = [_pkg("RubyGems", m.group(1), m.group(2), path, m.group(0).strip())
           for m in re.finditer(r"^    ([A-Za-z0-9_\-.]+) \(([\d.]+[\w.]*)\)$", text, re.M)]
    m = re.search(r"RUBY VERSION\s+ruby (\d+(?:\.\d+)*)", text)
    if m:
        out.append(_c("ruby", m.group(1), path, m.group(0).replace("\n", " "), source="runtime-pin"))
    return out


def parse_go_mod(path: str, text: str) -> list[Component]:
    out = []
    m = re.search(r"^go (\d+\.\d+(?:\.\d+)?)", text, re.M)
    if m:
        out.append(_c("go", m.group(1), path, m.group(0), source="runtime-pin"))
    for m in re.finditer(r"^\s*(?:require\s+)?([\w.\-]+\.[\w.\-/]+)\s+v([\w.\-+]+)", text, re.M):
        out.append(_pkg("Go", m.group(1), m.group(2), path, m.group(0).strip()))
    return out


# ------------------------------------------------------------------ Java
def _strip_ns(root: ET.Element) -> None:
    for el in root.iter():
        if isinstance(el.tag, str) and "}" in el.tag:
            el.tag = el.tag.split("}", 1)[1]


def parse_pom(path: str, text: str) -> list[Component]:
    out = []
    try:
        root = ET.fromstring(text.encode("utf-8", "ignore"))
    except ET.ParseError:
        return out
    _strip_ns(root)
    props = {el.tag: (el.text or "").strip() for el in root.findall("./properties/*")}
    parent = root.find("parent")
    if parent is not None:
        g, a, v = (parent.findtext(x, "") for x in ("groupId", "artifactId", "version"))
        props.setdefault("project.parent.version", v)
        if a:
            out.append(_pkg("Maven", f"{g}:{a}", v, path, f"<parent>{g}:{a}:{v}"))
    props.setdefault("project.version", root.findtext("version", ""))

    def res(s: str) -> str:
        for _ in range(5):
            s2 = re.sub(r"\$\{([^}]+)\}", lambda m: props.get(m.group(1), m.group(0)), s)
            if s2 == s:
                break
            s = s2
        return s

    for dep in root.iter("dependency"):
        g, a, v = (res(dep.findtext(x, "") or "") for x in ("groupId", "artifactId", "version"))
        if a:
            ver = v if v and "${" not in v else None
            out.append(_pkg("Maven", f"{g}:{a}", ver, path, f"{g}:{a}:{v or '(managed)'}", "high" if ver else "low"))
    for key in ("java.version", "maven.compiler.release", "maven.compiler.source", "maven.compiler.target"):
        if props.get(key):
            out.append(_c("eclipse-temurin", res(props[key]), path, f"<{key}>{props[key]}", source="runtime-pin",
                          conf="medium"))
            break
    return out


def parse_gradle(path: str, text: str) -> list[Component]:
    out = []
    for m in re.finditer(r"['\"]([\w.\-]+):([\w.\-]+):([\w.\-]+)['\"]", text):
        out.append(_pkg("Maven", f"{m.group(1)}:{m.group(2)}", m.group(3), path, m.group(0)))
    m = re.search(r"id\s*\(?['\"]org\.springframework\.boot['\"]\)?\s+version\s+['\"]([\w.\-]+)", text)
    if m:
        out.append(_pkg("Maven", "org.springframework.boot:spring-boot", m.group(1), path, m.group(0)))
    m = re.search(r"(?:sourceCompatibility|targetCompatibility|languageVersion)\s*=?\s*(?:JavaVersion\.VERSION_|JavaLanguageVersion\.of\()?['\"]?([\d._]+)", text)
    if m:
        out.append(_c("eclipse-temurin", m.group(1).replace("_", "."), path, m.group(0), source="runtime-pin", conf="medium"))
    return out


def parse_jar(path: str, data: bytes) -> list[Component]:
    """Identify a jar via META-INF/maven/**/pom.properties, else its filename."""
    out = []
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            for n in zf.namelist():
                if n.startswith("META-INF/maven/") and n.endswith("pom.properties"):
                    props = dict(re.findall(r"^(\w+)=(.*)$", zf.read(n).decode("utf-8", "ignore"), re.M))
                    if props.get("artifactId") and props.get("version"):
                        coord = f"{props.get('groupId','').strip()}:{props['artifactId'].strip()}"
                        out.append(_pkg("Maven", coord, props["version"].strip(), path, f"{n}: {coord}:{props['version'].strip()}"))
    except (zipfile.BadZipFile, OSError, RuntimeError):
        pass
    if not out:
        out.extend(parse_jar_name(path))
    return out


def parse_jar_name(path: str) -> list[Component]:
    m = re.match(r"(.+?)-(\d+(?:\.\d+)+(?:[.-][\w]+)?)\.jar$", PurePosixPath(path).name)
    if not m:
        return []
    art, ver = m.group(1), m.group(2)
    coord = JAR_COORDS.get(art)
    if coord:
        return [_pkg("Maven", coord, ver, path, f"jar filename {PurePosixPath(path).name}", "medium")]
    return [_c(f"jar:{art}", ver, path, f"jar filename {PurePosixPath(path).name}", conf="low", source="jar")]


# ------------------------------------------------------------------ .NET
TFM_RX = re.compile(r"^(?:net(\d)(\d)(\d)?|netcoreapp(\d+\.\d+)|net(\d+\.\d+)(?:-[\w.]+)?|netstandard(\d\.\d))$")


def _tfm(tfm: str, path: str, evidence: str) -> Optional[Component]:
    m = TFM_RX.match(tfm.strip().lower())
    if not m:
        return None
    if m.group(1):
        ver = f"{m.group(1)}.{m.group(2)}" + (f".{m.group(3)}" if m.group(3) else "")
        return _c("dotnetfx", ver, path, evidence, source="runtime-pin")
    if m.group(4) or m.group(5):
        return _c("dotnet", m.group(4) or m.group(5), path, evidence, source="runtime-pin")
    return None


def parse_csproj(path: str, text: str) -> list[Component]:
    out = []
    for m in re.finditer(r"<TargetFrameworks?>([^<]+)</TargetFrameworks?>", text):
        for t in m.group(1).split(";"):
            c = _tfm(t, path, m.group(0))
            if c:
                out.append(c)
    m = re.search(r"<TargetFrameworkVersion>v([\d.]+)</TargetFrameworkVersion>", text)
    if m:
        out.append(_c("dotnetfx", m.group(1), path, m.group(0), source="runtime-pin"))
    for m in re.finditer(r'<PackageReference\s+Include="([^"]+)"\s+Version="([^"]+)"', text):
        out.append(_pkg("NuGet", m.group(1), m.group(2), path, m.group(0)))
    return out


def parse_packages_config(path: str, text: str) -> list[Component]:
    return [_pkg("NuGet", m.group(1), m.group(2), path, m.group(0))
            for m in re.finditer(r'<package\s+id="([^"]+)"\s+version="([^"]+)"', text)]


def parse_web_config(path: str, text: str) -> list[Component]:
    m = re.search(r'targetFramework="([\d.]+)"', text)
    return [_c("dotnetfx", m.group(1), path, m.group(0), source="runtime-pin")] if m else []


def parse_global_json(path: str, text: str) -> list[Component]:
    v = ((json.loads(text).get("sdk") or {}).get("version"))
    return [_c("dotnet", ".".join(v.split(".")[:2]), path, f"sdk.version {v}", source="runtime-pin")] if v else []


# ------------------------------------------------------------------ containers / version pins
def parse_dockerfile(path: str, text: str) -> list[Component]:
    out = []
    for m in re.finditer(r"^\s*FROM\s+(?:--platform=\S+\s+)?([^\s:@]+)(?::([^\s@]+))?", text, re.M | re.I):
        image, tag = m.group(1).lower(), (m.group(2) or "latest")
        name = re.sub(r"^(?:docker\.io/|mcr\.microsoft\.com/|registry\.access\.redhat\.com/|library/|quay\.io/)", "", image)
        product = DOCKER_IMAGES.get(name) or DOCKER_IMAGES.get(name.split("/")[-1])
        if not product:
            continue
        vm = re.match(r"v?(\d+(?:\.\d+)*)", tag)
        ver = vm.group(1) if vm else None
        if product == "debian" and not ver:
            ver = DEBIAN_CODENAMES.get(tag.split("-")[0])
        if product == "ubuntu" and not ver:
            ver = UBUNTU_CODENAMES.get(tag.split("-")[0])
        if product == "rhel" and not ver:
            ver = re.sub(r"\D", "", name.split("/")[-1]) or None
        conf = "high" if ver else "low"
        out.append(_c(product, ver, path, m.group(0).strip(), conf=conf, source="container-image", image=f"{image}:{tag}"))
        for code, dv in DEBIAN_CODENAMES.items():
            if code in tag and product != "debian":
                out.append(_c("debian", dv, path, f"{m.group(0).strip()} (base {code})", source="container-image"))
        if "alpine" in tag and product != "alpine-linux":
            am = re.search(r"alpine(\d+\.\d+)", tag)
            out.append(_c("alpine-linux", am.group(1) if am else None, path, m.group(0).strip(), source="container-image",
                          conf="high" if am else "low"))
    return out


def parse_version_file(product: str) -> Callable[[str, str], list[Component]]:
    def _p(path: str, text: str) -> list[Component]:
        m = re.search(r"v?(\d+(?:\.\d+)*)", text.strip())
        return [_c(product, m.group(1), path, text.strip()[:60], source="runtime-pin")] if m else []
    return _p


def parse_tool_versions(path: str, text: str) -> list[Component]:
    mp = {"nodejs": "nodejs", "node": "nodejs", "python": "python", "ruby": "ruby", "golang": "go", "java": "eclipse-temurin",
          "php": "php", "erlang": "erlang", "elixir": "elixir"}
    out = []
    for line in text.splitlines():
        parts = line.split()
        if len(parts) >= 2 and parts[0] in mp:
            m = re.search(r"(\d+(?:\.\d+)*)", parts[1])
            if m:
                out.append(_c(mp[parts[0]], m.group(1), path, line.strip(), source="runtime-pin"))
    return out


# filename (lowercase basename or glob-ish) -> parser
PARSERS: list[tuple[Callable[[str], bool], Callable[[str, str], list[Component]]]] = [
    (lambda n: n == "package.json", parse_package_json),
    (lambda n: n in ("package-lock.json", "npm-shrinkwrap.json"), parse_package_lock),
    (lambda n: n == "yarn.lock", parse_yarn_lock),
    (lambda n: re.fullmatch(r"requirements[\w\-.]*\.txt", n) is not None, parse_requirements),
    (lambda n: n == "pipfile.lock", parse_pipfile_lock),
    (lambda n: n == "poetry.lock", parse_poetry_lock),
    (lambda n: n == "pyproject.toml", parse_pyproject),
    (lambda n: n == "setup.py", parse_setup_py),
    (lambda n: n == "runtime.txt", parse_runtime_txt),
    (lambda n: n == ".python-version", parse_version_file("python")),
    (lambda n: n in (".nvmrc", ".node-version"), parse_version_file("nodejs")),
    (lambda n: n == ".ruby-version", parse_version_file("ruby")),
    (lambda n: n == ".java-version", parse_version_file("eclipse-temurin")),
    (lambda n: n == ".tool-versions", parse_tool_versions),
    (lambda n: n == "composer.json", parse_composer_json),
    (lambda n: n == "composer.lock", parse_composer_lock),
    (lambda n: n == "gemfile.lock", parse_gemfile_lock),
    (lambda n: n == "go.mod", parse_go_mod),
    (lambda n: n == "pom.xml", parse_pom),
    (lambda n: n in ("build.gradle", "build.gradle.kts"), parse_gradle),
    (lambda n: n.endswith((".csproj", ".vbproj", ".fsproj")), parse_csproj),
    (lambda n: n == "packages.config", parse_packages_config),
    (lambda n: n == "web.config", parse_web_config),
    (lambda n: n == "global.json", parse_global_json),
    (lambda n: n == "dockerfile" or n.startswith("dockerfile.") or n.endswith(".dockerfile") or n == "containerfile", parse_dockerfile),
]


def parser_for(filename: str) -> Optional[Callable[[str, str], list[Component]]]:
    n = PurePosixPath(filename).name.lower()
    for pred, fn in PARSERS:
        if pred(n):
            return fn
    return None
