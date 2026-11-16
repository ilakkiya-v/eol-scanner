"""Optional LLM assist. Off by default; the tool is fully functional without it.

Providers:
  anthropic - Claude through the official SDK, on any of the connections in PLATFORMS (data leaves the box)
  ollama    - a local model through Ollama's native /api/chat (data stays on your network)

Secrets (API keys, tokens, cloud credentials) are never stored in settings: each connection reads them from
the environment or the cloud SDK's normal credential chain (AWS profile/role, gcloud ADC, ...). Settings only
hold non-secret routing values such as region, project, workspace ID and base URL.
"""
from __future__ import annotations

import json
import time
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

# How each connection authenticates. Shown in the UI so users know which env var / login to set up.
PLATFORMS = {
    "anthropic": {"label": "Anthropic API (direct)", "extra": None,
                  "auth": "ANTHROPIC_API_KEY env var (an org/workspace key works), or `ant auth login`"},
    "gateway": {"label": "Company LLM gateway / proxy (Anthropic-compatible)", "extra": None,
                "auth": "Gateway URL below, plus ANTHROPIC_API_KEY (sent as x-api-key) or ANTHROPIC_AUTH_TOKEN (sent as Bearer)"},
    "bedrock": {"label": "Amazon Bedrock", "extra": "bedrock",
                "auth": "AWS credentials (profile, SSO, role, AWS_* env vars) or AWS_BEARER_TOKEN_BEDROCK; region required"},
    "bedrock_invoke": {"label": "Amazon Bedrock (legacy InvokeModel)", "extra": "bedrock",
                       "auth": "AWS credentials (profile, SSO, role, AWS_* env vars); region required"},
    "aws": {"label": "Claude Platform on AWS", "extra": "aws",
            "auth": "AWS credentials (profile, SSO, role, AWS_* env vars); region + workspace ID required"},
    "vertex": {"label": "Google Vertex AI", "extra": "vertex",
               "auth": "gcloud Application Default Credentials (`gcloud auth application-default login` or GOOGLE_APPLICATION_CREDENTIALS)"},
    "google_cloud": {"label": "Claude on Google Cloud (Anthropic managed)", "extra": "google_cloud",
                     "auth": "gcloud Application Default Credentials; project + workspace ID (wrkspc_...) required"},
    "foundry": {"label": "Microsoft Foundry (Azure)", "extra": None,
                "auth": "ANTHROPIC_FOUNDRY_API_KEY env var; Foundry resource name required"},
}

# Model presets. Mythos is only served to organizations Anthropic has verified (e.g. Cyber Verification Program).
MODEL_PRESETS = [
    {"id": "claude-opus-5-5", "label": "Claude Opus 5.5 (default)"},
    {"id": "claude-fable-5-2", "label": "Claude Fable 5.2 (most capable, open to all)"},
    {"id": "claude-mythos-5-2", "label": "Claude Mythos 5.2 (verified orgs only)"},
    {"id": "claude-sonnet-5-5", "label": "Claude Sonnet 5.5 (faster, cheaper)"},
    {"id": "claude-haiku-5-5", "label": "Claude Haiku 5.5 (fastest)"},
]

# Platforms where the server-side refusal fallback is supported. Elsewhere we send a plain request.
_FALLBACK_OK = {"anthropic", "gateway", "aws", "google_cloud"}

SECRET_HINTS = ("key", "token", "secret", "password", "credential")


class LLMUnavailable(Exception):
    pass


def scrub(cfg: dict) -> dict:
    """Drop anything that looks like a secret before llm settings are saved."""
    return {k: v for k, v in cfg.items() if not any(h in k.lower() for h in SECRET_HINTS)}


def _opt(cfg: dict, key: str) -> Optional[str]:
    v = (cfg.get(key) or "").strip() if isinstance(cfg.get(key), str) else cfg.get(key)
    return v or None


def _client(cfg: dict):
    try:
        import anthropic
    except ImportError as e:
        raise LLMUnavailable("anthropic SDK not installed (pip install -r requirements-llm.txt)") from e
    plat = cfg.get("platform") or "anthropic"
    kw = {"timeout": 300.0, "max_retries": 2}
    try:
        if plat == "anthropic":
            return anthropic.Anthropic(**kw)
        if plat == "gateway":
            url = _opt(cfg, "base_url")
            if not url:
                raise LLMUnavailable("set the gateway URL in Settings -> AI assist")
            return anthropic.Anthropic(base_url=url, **kw)
        if plat in ("bedrock", "bedrock_invoke", "aws"):
            aws = {"aws_region": _opt(cfg, "aws_region"), "aws_profile": _opt(cfg, "aws_profile")}
            aws = {k: v for k, v in aws.items() if v}
            if plat == "bedrock":
                return anthropic.AnthropicBedrockMantle(**aws, **kw)
            if plat == "bedrock_invoke":
                return anthropic.AnthropicBedrock(**aws, **kw)
            return anthropic.AnthropicAWS(workspace_id=_opt(cfg, "workspace_id"), **aws, **kw)
        if plat == "vertex":
            return anthropic.AnthropicVertex(region=_opt(cfg, "gcp_region") or "global",
                                             project_id=_opt(cfg, "gcp_project"), **kw)
        if plat == "google_cloud":
            gc = {"project": _opt(cfg, "gcp_project"), "workspace_id": _opt(cfg, "workspace_id")}
            return anthropic.AnthropicGoogleCloud(**{k: v for k, v in gc.items() if v}, **kw)
        if plat == "foundry":
            return anthropic.AnthropicFoundry(resource=_opt(cfg, "foundry_resource"), **kw)
    except AttributeError as e:
        raise LLMUnavailable(f"this anthropic SDK has no client for '{plat}'; upgrade it (pip install -U anthropic)") from e
    except ImportError as e:
        extra = PLATFORMS.get(plat, {}).get("extra")
        raise LLMUnavailable(f"missing cloud dependencies; pip install 'anthropic[{extra}]'" if extra else str(e)) from e
    except (ValueError, TypeError) as e:  # e.g. missing region / workspace / resource
        raise LLMUnavailable(f"{PLATFORMS.get(plat, {}).get('label', plat)} is not fully configured: {e}") from e
    except anthropic.AnthropicError as e:
        raise LLMUnavailable(f"could not set up the {plat} client: {e}") from e
    raise LLMUnavailable(f"unknown connection type '{plat}'")


def model_for(cfg: dict) -> str:
    model = _opt(cfg, "model") or "claude-opus-5-5"
    # Claude in Amazon Bedrock uses an "anthropic." provider prefix (ARNs / inference profiles are passed through).
    if cfg.get("platform") in ("bedrock", "bedrock_invoke") and not model.startswith(("anthropic.", "arn:")) \
            and "." not in model.split("-")[0]:
        model = "anthropic." + model
    return model


def _anthropic(prompt: str, cfg: dict, max_tokens: int = 16000) -> str:
    import anthropic

    client = _client(cfg)
    plat = cfg.get("platform") or "anthropic"
    kwargs = dict(model=model_for(cfg), max_tokens=max_tokens, system=SYSTEM,
                  messages=[{"role": "user", "content": prompt}])
    try:
        resp = None
        if plat in _FALLBACK_OK and cfg.get("fallback", True):
            # Server-side refusal fallback: security content can trip classifiers; let the API retry on a fallback
            # model. Gateways or older SDKs that don't understand it get a plain request instead.
            try:
                resp = client.beta.messages.create(betas=["server-side-fallback-2026-07-01"], fallbacks="default", **kwargs)
            except TypeError:
                resp = None
            except anthropic.BadRequestError as e:
                if not any(w in str(e).lower() for w in ("fallback", "beta", "unknown", "extra")):
                    raise
                resp = None
        if resp is None:
            resp = client.messages.create(**kwargs)
    except anthropic.AuthenticationError as e:
        raise LLMUnavailable(f"credentials missing/invalid for {PLATFORMS.get(plat, {}).get('label', plat)}: "
                             f"{PLATFORMS.get(plat, {}).get('auth', '')}") from e
    except anthropic.PermissionDeniedError as e:
        raise LLMUnavailable(f"access denied (403): your org/account may not have access to model "
                             f"'{kwargs['model']}' on this connection. {e.message}") from e
    except anthropic.NotFoundError as e:
        raise LLMUnavailable(f"model '{kwargs['model']}' not found on this connection (check the ID / region). {e.message}") from e
    except anthropic.APIConnectionError as e:
        raise LLMUnavailable(f"cannot reach the {plat} endpoint from this network (proxy / VPN / CA?): {e}") from e
    except anthropic.APIStatusError as e:
        raise LLMUnavailable(f"API error {e.status_code}: {e.message}") from e
    except anthropic.AnthropicError as e:
        raise LLMUnavailable(f"{plat}: {e}") from e
    except LLMUnavailable:
        raise
    except Exception as e:  # noqa: BLE001 - cloud credential chains (botocore, google-auth, azure) raise their own types
        raise LLMUnavailable(f"{PLATFORMS.get(plat, {}).get('label', plat)} is not ready: {type(e).__name__}: {e}") from e
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


def complete(prompt: str, cfg: Optional[dict] = None, max_tokens: int = 16000) -> str:
    cfg = cfg or db.get_setting("llm")
    p = cfg.get("provider", "none")
    if p == "anthropic":
        return _anthropic(prompt, cfg, max_tokens)
    if p == "ollama":
        return _ollama(prompt, cfg.get("ollama_url"), cfg.get("ollama_model"))
    raise LLMUnavailable("LLM assist is disabled (Settings -> AI assist)")


def test_connection(cfg: Optional[dict] = None) -> dict:
    """Send a tiny prompt with the given (unsaved) or saved settings. No scan data is sent."""
    cfg = {**db.get_setting("llm"), **scrub(cfg or {})}
    t = time.time()
    try:
        text = complete("Connection test from EOL Scanner. Reply with exactly: OK", cfg, max_tokens=2048)
        return {"ok": True, "reply": text[:200], "model": model_for(cfg) if cfg.get("provider") == "anthropic"
                else cfg.get("ollama_model"), "seconds": round(time.time() - t, 1)}
    except LLMUnavailable as e:
        return {"ok": False, "error": str(e), "seconds": round(time.time() - t, 1)}


def status() -> dict:
    cfg = db.get_setting("llm")
    return {"provider": cfg.get("provider"), "enabled": cfg.get("provider") not in (None, "none"),
            "platform": cfg.get("platform", "anthropic"), "send_code": cfg.get("send_code", False)}


def options() -> dict:
    return {"platforms": {k: {"label": v["label"], "auth": v["auth"]} for k, v in PLATFORMS.items()},
            "models": MODEL_PRESETS}


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
