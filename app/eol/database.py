"""Lifecycle lookup: (product, version) -> support status."""
from __future__ import annotations

import datetime as dt
import json
import re
import threading
from typing import Any, Optional

from packaging.version import InvalidVersion, Version

from ..config import BUNDLED_SNAPSHOT, CURATED_FILE, EOL_SOON_DAYS, LIVE_SNAPSHOT

# Friendly / ecosystem names -> endoflife.date product ids.
ALIASES = {
    "apache": "apache-http-server", "httpd": "apache-http-server", "apache-httpd": "apache-http-server",
    "node": "nodejs", "node.js": "nodejs", "php-fpm": "php", "golang": "go",
    "java": "eclipse-temurin", "openjdk": "eclipse-temurin", "jdk": "eclipse-temurin", "jre": "eclipse-temurin",
    "struts": "apache-struts", "struts2": "apache-struts", "spring": "spring-framework",
    "jetty": "eclipse-jetty", "jboss-eap": "redhat-jboss-eap", "postgres": "postgresql",
    "mssql": "mssqlserver", "sqlserver": "mssqlserver", "alpine": "alpine-linux",
    "rhel": "rhel", "redhat": "rhel", "asp.net": "dotnetfx", "dotnet-framework": "dotnetfx",
    ".net": "dotnet", ".net-core": "dotnet", "dotnet-core": "dotnet", "aspnetcore": "dotnet",
    "angular.js": "angularjs", "vue.js": "vue", "vuejs": "vue", "next": "nextjs", "next.js": "nextjs",
    "jira": "jira-software", "sonarqube": "sonarqube-server", "jquery.ui": "jquery-ui",
    "rubyonrails": "rails", "ruby-on-rails": "rails", "elastic": "elasticsearch",
    "mongo": "mongodb", "mysql-server": "mysql", "microsoft-iis": "iis",
}


def _today() -> dt.date:
    return dt.date.today()


def _parse_date(v: Any) -> Optional[dt.date]:
    if isinstance(v, str):
        try:
            return dt.date.fromisoformat(v[:10])
        except ValueError:
            return None
    return None


def vparse(v: str) -> Optional[Version]:
    v = (v or "").strip().lstrip("vV=^~")
    v = re.split(r"[\s+]", v)[0]
    try:
        return Version(v)
    except InvalidVersion:
        m = re.match(r"\d+(\.\d+)*", v)
        if m:
            try:
                return Version(m.group(0))
            except InvalidVersion:
                return None
    return None


def normalize_version(product: str, version: str) -> str:
    v = (version or "").strip().lstrip("vV")
    if product in ("eclipse-temurin", "oracle-jdk") and v.startswith("1."):
        v = v[2:]  # 1.8.0_292 -> 8.0_292
    if product == "eclipse-temurin":
        v = v.split("_")[0].split("u")[0] if re.match(r"^\d+u\d+", v) else v.split("_")[0]
    if product == "python" and v.startswith("2") and "." not in v:
        v = "2.7"
    return v


class EOLDatabase:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self.products: dict[str, list[dict]] = {}
        self.meta: dict[str, Any] = {}
        self.reload()

    def reload(self) -> None:
        with self._lock:
            src = LIVE_SNAPSHOT if LIVE_SNAPSHOT.exists() else BUNDLED_SNAPSHOT
            products: dict[str, list[dict]] = {}
            meta: dict[str, Any] = {"source": None}
            if src.exists():
                snap = json.loads(src.read_text(encoding="utf-8"))
                products = snap.get("products", {})
                meta = {"source": str(src), "generated": snap.get("generated"), "products": len(products)}
            if CURATED_FILE.exists():
                for k, v in json.loads(CURATED_FILE.read_text(encoding="utf-8")).get("products", {}).items():
                    products.setdefault(k, [dict(c, curated=True) for c in v])
            self.products, self.meta = products, meta

    def resolve(self, product: str) -> Optional[str]:
        p = (product or "").strip().lower()
        p = ALIASES.get(p, p)
        return p if p in self.products else None

    def _cycle_for(self, product: str, version: str) -> Optional[dict]:
        cycles = self.products.get(product, [])
        v = normalize_version(product, version)
        best, best_len = None, -1
        for c in cycles:
            name = str(c.get("cycle", "")).lower().removesuffix(".x")
            if not name:
                continue
            if v == name or v.startswith(name + ".") or v.startswith(name + "-") or v.startswith(name + "_"):
                if len(name) > best_len:
                    best, best_len = c, len(name)
        if best is None:
            # Fall back to numeric comparison of major(.minor)
            pv = vparse(v)
            if pv is not None:
                for c in cycles:
                    cv = vparse(str(c.get("cycle")))
                    if cv is not None and cv.release == pv.release[: len(cv.release)]:
                        return c
        return best

    def lookup(self, product: str, version: Optional[str]) -> dict:
        """Return lifecycle status. status in: eol, eol_soon, supported, unknown."""
        pid = self.resolve(product)
        res: dict[str, Any] = {"product": pid or product, "version": version, "known_product": bool(pid),
                               "status": "unknown"}
        if not pid:
            return res
        cycles = self.products[pid]
        res["latest_cycle"] = cycles[0].get("cycle") if cycles else None
        res["latest_version"] = cycles[0].get("latest") if cycles else None
        if not version:
            res["status"] = "unknown"
            res["note"] = "Product detected but version hidden; verify manually."
            return res
        c = self._cycle_for(pid, version)
        if not c:
            return res
        res.update(cycle=c.get("cycle"), cycle_latest=c.get("latest"), lts=c.get("lts"),
                   eol_date=c.get("eol") if isinstance(c.get("eol"), str) else None,
                   support_end=c.get("support") if isinstance(c.get("support"), str) else None,
                   extended_support=c.get("extendedSupport"), note=c.get("note"), curated=c.get("curated", False))
        eol = c.get("eol")
        eol_d = _parse_date(eol)
        today = _today()
        if eol is True or (eol_d and eol_d <= today):
            res["status"] = "eol"
            res["days_past_eol"] = (today - eol_d).days if eol_d else None
        elif eol_d and (eol_d - today).days <= EOL_SOON_DAYS:
            res["status"] = "eol_soon"
            res["days_to_eol"] = (eol_d - today).days
        else:
            res["status"] = "supported"
        # Patch currency inside the cycle.
        lv, cv = vparse(str(c.get("latest") or "")), vparse(normalize_version(pid, version))
        if lv and cv and cv < lv:
            res["outdated_patch"] = True
        return res

    def product_list(self) -> list[str]:
        return sorted(self.products)


EOL_DB = EOLDatabase()
