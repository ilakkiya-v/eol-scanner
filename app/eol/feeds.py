"""External data feeds: endoflife.date (EOL lifecycle) and OSV.dev (vulns).

Everything degrades gracefully when the scanner runs inside a VPN/air-gapped
lab: EOL data falls back to the bundled/last-synced snapshot, OSV results
fall back to whatever is cached in SQLite.
"""
from __future__ import annotations

import json
import math
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any, Optional

import httpx

from .. import db
from ..config import BUNDLED_SNAPSHOT, LIVE_SNAPSHOT, USER_AGENT

EOL_API = "https://endoflife.date/api"
OSV_API = "https://api.osv.dev/v1"
OSV_CACHE_TTL = 7 * 24 * 3600


def _client(timeout: float = 20) -> httpx.Client:
    # trust_env=True honours HTTPS_PROXY / SSL_CERT_FILE in corp networks.
    return httpx.Client(timeout=timeout, headers={"User-Agent": USER_AGENT}, trust_env=True, follow_redirects=True)


# ------------------------------------------------------------------ endoflife.date
def build_snapshot(out: Optional[Path] = None, products: Optional[list[str]] = None) -> tuple[Path, int]:
    out = out or LIVE_SNAPSHOT
    with _client() as c:
        names = products or c.get(f"{EOL_API}/all.json").raise_for_status().json()

        def fetch(name: str) -> tuple[str, Any]:
            for attempt in range(3):
                try:
                    r = c.get(f"{EOL_API}/{name}.json")
                    if r.status_code == 200:
                        return name, r.json()
                    return name, None
                except httpx.HTTPError:
                    time.sleep(1 + attempt)
            return name, None

        with ThreadPoolExecutor(max_workers=12) as pool:
            results = dict(pool.map(fetch, names))
    data = {k: v for k, v in results.items() if isinstance(v, list)}
    snapshot = {"source": "endoflife.date", "generated": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "products": data}
    out.parent.mkdir(parents=True, exist_ok=True)
    tmp = out.with_suffix(".tmp")
    tmp.write_text(json.dumps(snapshot, separators=(",", ":")))
    tmp.replace(out)
    return out, len(data)


def snapshot_info() -> dict:
    info = {}
    for label, p in (("live", LIVE_SNAPSHOT), ("bundled", BUNDLED_SNAPSHOT)):
        if p.exists():
            try:
                meta = json.loads(p.read_text())
                info[label] = {"path": str(p), "generated": meta.get("generated"), "products": len(meta.get("products", {}))}
            except Exception as e:  # pragma: no cover
                info[label] = {"path": str(p), "error": str(e)}
    return info


# ------------------------------------------------------------------ OSV
def _cvss3_score(vector: str) -> Optional[float]:
    """CVSS v3.x base score from a vector string."""
    try:
        parts = dict(p.split(":") for p in vector.split("/")[1:])
        W = {"AV": {"N": .85, "A": .62, "L": .55, "P": .2}, "AC": {"L": .77, "H": .44},
             "UI": {"N": .85, "R": .62}, "C": {"H": .56, "L": .22, "N": 0}}
        scope_changed = parts["S"] == "C"
        pr = {"N": .85, "L": .68 if scope_changed else .62, "H": .5 if scope_changed else .27}[parts["PR"]]
        iss = 1 - (1 - W["C"][parts["C"]]) * (1 - W["C"][parts["I"]]) * (1 - W["C"][parts["A"]])
        impact = 7.52 * (iss - .029) - 3.25 * (iss - .02) ** 15 if scope_changed else 6.42 * iss
        expl = 8.22 * W["AV"][parts["AV"]] * W["AC"][parts["AC"]] * pr * W["UI"][parts["UI"]]
        if impact <= 0:
            return 0.0
        raw = min((impact + expl) * (1.08 if scope_changed else 1), 10)
        return math.ceil(raw * 10 - 1e-9) / 10
    except Exception:
        return None


def _severity_from_vuln(v: dict) -> tuple[str, Optional[float]]:
    score = None
    for s in v.get("severity", []) or []:
        if s.get("type", "").startswith("CVSS_V3"):
            score = _cvss3_score(s.get("score", ""))
    label = (v.get("database_specific") or {}).get("severity")
    if score is not None:
        label = "critical" if score >= 9 else "high" if score >= 7 else "medium" if score >= 4 else "low"
    label = (label or "medium").lower()
    if label == "moderate":
        label = "medium"
    return label, score


def _fixed_versions(v: dict, pkg: str) -> list[str]:
    fixed = set()
    for a in v.get("affected", []) or []:
        if (a.get("package") or {}).get("name", "").lower() != pkg.lower():
            continue
        for r in a.get("ranges", []) or []:
            for e in r.get("events", []) or []:
                if "fixed" in e:
                    fixed.add(e["fixed"])
    return sorted(fixed)


def osv_query(ecosystem: str, name: str, version: str, online: bool = True) -> dict:
    """Return {'vulns': [...], 'source': 'live'|'cache'|'unavailable'}."""
    key = f"osv:{ecosystem}:{name}:{version}"
    cached = db.cache_get(key, OSV_CACHE_TTL)
    if cached is not None:
        return {"vulns": cached, "source": "cache"}
    if online:
        try:
            with _client(15) as c:
                r = c.post(f"{OSV_API}/query", json={"package": {"name": name, "ecosystem": ecosystem}, "version": version})
                r.raise_for_status()
                vulns = []
                for v in r.json().get("vulns", []) or []:
                    sev, score = _severity_from_vuln(v)
                    vulns.append({
                        "id": v.get("id"),
                        "aliases": [a for a in v.get("aliases", []) if a.startswith("CVE-")],
                        "summary": (v.get("summary") or (v.get("details") or "")[:200]).strip(),
                        "severity": sev, "cvss": score,
                        "fixed": _fixed_versions(v, name),
                        "references": [x.get("url") for x in (v.get("references") or [])[:5]],
                        "published": v.get("published"),
                    })
                db.cache_set(key, vulns)
                return {"vulns": vulns, "source": "live"}
        except httpx.HTTPError:
            pass
    stale = db.cache_get_any_age(key)
    if stale is not None:
        return {"vulns": stale, "source": "cache"}
    return {"vulns": [], "source": "unavailable"}


def connectivity() -> dict:
    out = {}
    for name, url in (("endoflife.date", f"{EOL_API}/nginx.json"), ("osv.dev", "https://osv.dev")):
        try:
            with _client(6) as c:
                out[name] = c.get(url).status_code < 500
        except httpx.HTTPError:
            out[name] = False
    return out
