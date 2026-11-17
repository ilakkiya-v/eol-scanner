"""Turn raw component detections into prioritized, enriched findings."""
from __future__ import annotations

import uuid
from concurrent.futures import ThreadPoolExecutor
from typing import Callable

from .advisor.mitigations import code_review_steps, advise_component, advise_kb
from .eol import feeds
from .eol.database import EOL_DB, vparse
from .scanners.fingerprints import Component

SEV_ORDER = ["info", "low", "medium", "high", "critical"]
CONF_ORDER = ["low", "medium", "high"]


def sev_max(*sevs: str) -> str:
    return max((s for s in sevs if s), key=SEV_ORDER.index, default="info")


def _merge(components: list[Component]) -> list[dict]:
    groups: dict[tuple, dict] = {}
    for c in components:
        pid = EOL_DB.resolve(c.product) or c.product
        ver = (c.version or "").strip() or None
        if ver and not vparse(ver):
            ver = ver[:40]
        key = (pid, ver)
        g = groups.setdefault(key, {"product": pid, "version": ver, "ecosystem": c.ecosystem, "package": c.package,
                                    "confidence": c.confidence, "evidence": [], "sources": set(), "direct": False})
        g["ecosystem"] = g["ecosystem"] or c.ecosystem
        g["package"] = g["package"] or c.package
        if CONF_ORDER.index(c.confidence) > CONF_ORDER.index(g["confidence"]):
            g["confidence"] = c.confidence
        g["sources"].add(c.source)
        g["direct"] = g["direct"] or c.extra.get("direct", True)
        if len(g["evidence"]) < 12 and not any(e["location"] == c.location and e["text"] == c.evidence for e in g["evidence"]):
            g["evidence"].append({"location": c.location, "text": c.evidence, "source": c.source})
    versioned = {p for (p, v) in groups if v}
    out = []
    for (p, v), g in groups.items():
        if v is None and p in versioned:
            # merge hint evidence into the versioned entry
            for (p2, v2), g2 in groups.items():
                if p2 == p and v2:
                    g2["evidence"].extend(g["evidence"][: max(0, 12 - len(g2["evidence"]))])
                    g2["sources"] |= g["sources"]
                    break
            continue
        out.append(g)
    for g in out:
        g["sources"] = sorted(g["sources"])
    return out


def enrich(components: list[Component], online: bool, osv_enabled: bool, log: Callable[[str], None],
           progress: Callable[[float, str], None] = lambda *_: None) -> tuple[list[dict], list[dict]]:
    """Returns (findings, inventory)."""
    merged = _merge(components)
    log(f"{len(components)} detections merged into {len(merged)} unique components")
    to_query = [g for g in merged if osv_enabled and g["ecosystem"] and g["package"] and g["version"]][:3000]
    done = 0

    def q(g):
        nonlocal done
        r = feeds.osv_query(g["ecosystem"], g["package"], g["version"], online=online)
        done += 1
        if done % 25 == 0:
            progress(0.7 + 0.25 * done / max(1, len(to_query)), f"vulnerability lookups {done}/{len(to_query)}")
        return g, r

    osv_results = {}
    if to_query:
        with ThreadPoolExecutor(max_workers=8) as pool:
            for g, r in pool.map(q, to_query):
                osv_results[id(g)] = r
        srcs = {r["source"] for r in osv_results.values()}
        log(f"OSV lookups: {len(to_query)} packages (sources: {', '.join(sorted(srcs))})")

    findings, inventory = [], []
    for g in merged:
        lc = EOL_DB.lookup(g["product"], g["version"])
        osv = osv_results.get(id(g), {"vulns": [], "source": "skipped"})
        vulns = sorted(osv["vulns"], key=lambda v: (SEV_ORDER.index(v["severity"]), v.get("cvss") or 0), reverse=True)
        vmax = vulns[0]["severity"] if vulns else None
        status = lc.get("status")
        inv = {"product": g["product"], "version": g["version"], "status": status, "eol_date": lc.get("eol_date"),
               "cycle": lc.get("cycle"), "latest": lc.get("latest_version"), "vulns": len(vulns), "confidence": g["confidence"],
               "ecosystem": g["ecosystem"], "package": g["package"], "direct": g["direct"], "sources": g["sources"],
               "locations": list(dict.fromkeys(e.get("location") for e in g["evidence"] if e.get("location")))[:3]}
        inventory.append(inv)

        if status == "eol":
            sev = "critical" if vmax == "critical" else "high"
            cat = "eol"
            past = lc.get("days_past_eol")
            title = f"{g['product']} {g['version']} is end-of-life" + (f" (since {lc.get('eol_date')}, {past} days)" if lc.get("eol_date") else "")
        elif status == "eol_soon":
            sev, cat = sev_max("medium", vmax), "eol-soon"
            title = f"{g['product']} {g['version']} reaches end-of-life on {lc.get('eol_date')} ({lc.get('days_to_eol')} days)"
        elif vulns:
            sev, cat = vmax, "vulnerable-component"
            title = f"{g['package'] or g['product']} {g['version']} has {len(vulns)} known vulnerabilit{'y' if len(vulns)==1 else 'ies'}"
        elif lc.get("known_product") and not g["version"]:
            sev, cat = "info", "version-unknown"
            title = f"{g['product']} detected but version not disclosed — verify lifecycle manually"
        elif lc.get("outdated_patch") and g["confidence"] != "low":
            sev, cat = "low", "outdated"
            title = f"{g['product']} {g['version']} is behind the latest patch {lc.get('cycle_latest')} in its supported cycle"
        else:
            continue
        if not g["direct"] and sev in ("high", "critical") and cat == "vulnerable-component":
            sev = SEV_ORDER[SEV_ORDER.index(sev) - 1]  # transitive dependency: one notch lower
        if g["confidence"] == "low" and cat in ("eol", "eol-soon"):
            title += " (version inferred from a range — confirm)"
        adv = advise_component(g["product"], lc, vulns)
        findings.append({
            "id": uuid.uuid4().hex[:12], "category": cat, "severity": sev, "title": title,
            "product": g["product"], "version": g["version"], "package": g["package"], "ecosystem": g["ecosystem"],
            "confidence": g["confidence"], "direct": g["direct"], "lifecycle": lc, "vulns": vulns[:50], "vuln_count": len(vulns),
            "osv_source": osv["source"], "evidence": g["evidence"], "sources": g["sources"],
            "location": g["evidence"][0]["location"] if g["evidence"] else "", **adv,
        })
    return findings, inventory


def enrich_raw(findings: list[dict]) -> list[dict]:
    """Attach containment / manual tests to exposure, config and code findings."""
    for f in findings:
        f.setdefault("id", uuid.uuid4().hex[:12])
        kb = f.get("kb", f.get("category", "info"))
        adv = advise_kb(kb)
        if f.get("category") == "code":  # source-code findings: confirm in the code first, then in the lab
            f.setdefault("review_steps", code_review_steps(kb))
        for k, v in adv.items():
            f.setdefault(k, v)
    return findings


def summarize(findings: list[dict], inventory: list[dict]) -> dict:
    counts = {s: 0 for s in SEV_ORDER}
    for f in findings:
        counts[f["severity"]] += 1
    return {
        "severity_counts": counts,
        "eol_components": sum(1 for i in inventory if i["status"] == "eol"),
        "eol_soon_components": sum(1 for i in inventory if i["status"] == "eol_soon"),
        "components": len(inventory),
        "vulnerable_components": sum(1 for i in inventory if i["vulns"]),
        "findings": len(findings),
        "risk_score": counts["critical"] * 10 + counts["high"] * 5 + counts["medium"] * 2 + counts["low"],
    }
