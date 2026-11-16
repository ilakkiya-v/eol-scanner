"""Optional LLM assist. Off by default; the tool is fully functional without it.

Providers:
  anthropic - Claude via the official SDK (needs ANTHROPIC_API_KEY or `ant auth login`; data leaves the box)
  ollama    - a local model through Ollama's native /api/chat (data stays on your network)
"""
from __future__ import annotations

import json
from typing import Optional

import httpx

from .. import db

SYSTEM = (
    "You are a senior application security engineer supporting an AUTHORIZED internal security assessment of "
    "QA/lab web applications. Many components are end-of-life and the application code will NOT be changed, so "
    "prioritise containment: network isolation, reverse-proxy/WAF virtual patches, configuration hardening, "
    "detection, and retirement planning. When you suggest verification steps, keep them non-destructive and lab-only "
    "(detection templates, benign canaries, version checks). Be concrete: give config snippets where useful. "
    "Answer in GitHub-flavoured Markdown with short sections."
)


class LLMUnavailable(Exception):
    pass


def _anthropic(prompt: str, model: str) -> str:
    try:
        import anthropic
    except ImportError as e:
        raise LLMUnavailable("anthropic SDK not installed (pip install -r requirements-llm.txt)") from e
    client = anthropic.Anthropic()
    kwargs = dict(model=model or "claude-opus-5-5", max_tokens=16000, system=SYSTEM,
                  messages=[{"role": "user", "content": prompt}])
    try:
        # Server-side refusal fallback: security content can trip classifiers; let the API retry on a fallback model.
        resp = client.beta.messages.create(betas=["server-side-fallback-2026-07-01"], fallbacks="default", **kwargs)
    except TypeError:
        resp = client.messages.create(**kwargs)  # older SDK without the fallbacks parameter
    except anthropic.AuthenticationError as e:
        raise LLMUnavailable("Anthropic credentials missing/invalid (set ANTHROPIC_API_KEY)") from e
    except anthropic.APIConnectionError as e:
        raise LLMUnavailable(f"cannot reach the Anthropic API from this network: {e}") from e
    except anthropic.APIStatusError as e:
        raise LLMUnavailable(f"Anthropic API error {e.status_code}: {e.message}") from e
    if resp.stop_reason == "refusal":
        raise LLMUnavailable("the model declined this request; rely on the rule-based guidance")
    return "".join(b.text for b in resp.content if getattr(b, "type", "") == "text").strip()


def _ollama(prompt: str, url: str, model: str) -> str:
    try:
        r = httpx.post(url.rstrip("/") + "/api/chat", timeout=300, json={
            "model": model, "stream": False,
            "messages": [{"role": "system", "content": SYSTEM}, {"role": "user", "content": prompt}]})
        r.raise_for_status()
        return r.json()["message"]["content"].strip()
    except (httpx.HTTPError, KeyError, ValueError) as e:
        raise LLMUnavailable(f"Ollama error: {e}") from e


def complete(prompt: str) -> str:
    cfg = db.get_setting("llm")
    p = cfg.get("provider", "none")
    if p == "anthropic":
        return _anthropic(prompt, cfg.get("model"))
    if p == "ollama":
        return _ollama(prompt, cfg.get("ollama_url"), cfg.get("ollama_model"))
    raise LLMUnavailable("LLM assist is disabled (Settings -> AI assist)")


def status() -> dict:
    cfg = db.get_setting("llm")
    return {"provider": cfg.get("provider"), "enabled": cfg.get("provider") not in (None, "none"),
            "send_code": cfg.get("send_code", False)}


def _finding_brief(f: dict) -> dict:
    keep = ("title", "severity", "category", "product", "version", "location", "kb", "rule")
    d = {k: f.get(k) for k in keep if f.get(k)}
    lc = f.get("lifecycle") or {}
    if lc:
        d["lifecycle"] = {k: lc.get(k) for k in ("status", "eol_date", "cycle", "latest_version", "extended_support") if lc.get(k)}
    if f.get("vulns"):
        d["top_vulns"] = [{"id": (v.get("aliases") or [v["id"]])[0], "severity": v["severity"], "summary": v["summary"][:160]}
                          for v in f["vulns"][:10]]
    return d


def advise_finding(f: dict, context: Optional[str] = None) -> str:
    prompt = (
        "Produce a containment plan for this finding from an authorized scan of an internal QA application whose code "
        "will not be changed. Include: 1) realistic attack paths given the details, 2) prioritized containment steps "
        "with config snippets (nginx/Apache/IIS/WAF as relevant), 3) non-destructive lab verification steps, 4) what "
        "to monitor, 5) retirement/upgrade notes.\n\n"
        f"Finding:\n```json\n{json.dumps(_finding_brief(f), indent=2)}\n```\n"
        + (f"\nEnvironment notes from the operator: {context}\n" if context else "")
    )
    return complete(prompt)


def review_code(findings: list[dict], snippets: list[dict], inventory: list[dict]) -> str:
    cfg = db.get_setting("llm")
    send_code = bool(cfg.get("send_code")) or cfg.get("provider") == "ollama"
    eol = [i for i in inventory if i["status"] in ("eol", "eol_soon")][:60]
    vuln = [i for i in inventory if i["vulns"]][:60]
    parts = [
        "Review this legacy codebase from an authorized code review. The code will not be modified, so focus on "
        "which end-of-life components and risky patterns are actually reachable, how an attacker would chain them, "
        "and how to contain them at the infrastructure layer. Also call out anything the rule-based scan likely missed "
        "in the snippets. Finish with a prioritized containment checklist.",
        f"\nEOL / near-EOL components:\n```json\n{json.dumps(eol, indent=1)}\n```",
        f"\nComponents with known vulnerabilities:\n```json\n{json.dumps(vuln, indent=1)}\n```",
        f"\nRule-based findings:\n```json\n{json.dumps([_finding_brief(f) for f in findings[:80]], indent=1)}\n```",
    ]
    if send_code:
        budget = 120_000
        for s in snippets:
            block = f"\n--- {s['path']}" + (f":{s.get('line')}" if s.get("line") else "") + f" ({s['kind']})\n{s['text']}\n"
            if budget - len(block) < 0:
                break
            budget -= len(block)
            parts.append(block)
    else:
        parts.append("\n(Source snippets withheld by policy: 'send code to LLM' is off. Base the review on the metadata above.)")
    return complete("\n".join(parts))
