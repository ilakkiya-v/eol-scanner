"""Optional LLM assist. Off by default; the tool is fully functional without it.

Providers:
  anthropic - Claude through the official SDK, on any of the connections in PLATFORMS (data leaves the box)
  ollama    - a local model through Ollama's native /api/chat (data stays on your network)

Credentials are never stored by this app: each connection reads them from environment variables or the cloud SDK's
normal credential chain (AWS profile/SSO, gcloud ADC, ...). The "claude_code" connection uses the local Claude Code
CLI and whatever account it is logged in to (e.g. a Claude Enterprise login), so no API key is needed at all.
"""
from __future__ import annotations

import json
import os
import re
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
    "claude_code": {"label": "Claude Code (your Claude / Enterprise login, no API key)", "extra": None,
                    "auth": "Install Claude Code on this machine and sign in once with your work account (run `claude`, then /login). "
                            "The scanner runs it read-only; Mythos is used if your org has enabled it and you pick it as the model."},
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

# Environment variables each connection reads its key/token from (used in error messages).
KEY_PLATFORMS = {
    "anthropic": {"label": "Anthropic API key", "env": ["ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN"], "placeholder": "sk-ant-..."},
    "gateway": {"label": "Gateway API key / token", "env": ["ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN"], "placeholder": "token from your gateway"},
    "foundry": {"label": "Foundry API key", "env": ["ANTHROPIC_FOUNDRY_API_KEY"], "placeholder": "Azure Foundry key"},
    "bedrock": {"label": "Bedrock API key (optional)", "env": ["AWS_BEARER_TOKEN_BEDROCK"], "placeholder": "leave empty to use your AWS login"},
    "bedrock_invoke": {"label": "Bedrock API key (optional)", "env": ["AWS_BEARER_TOKEN_BEDROCK"], "placeholder": "leave empty to use your AWS login"},
    "aws": {"label": "Claude Platform on AWS API key (optional)", "env": [], "placeholder": "leave empty to use your AWS login"},
}
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
            return anthropic.Anthropic(base_url=url, **kw)  # ANTHROPIC_API_KEY -> x-api-key, ANTHROPIC_AUTH_TOKEN -> Bearer
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


def _missing_credentials(plat: str) -> str:
    info = KEY_PLATFORMS.get(plat)
    label = PLATFORMS.get(plat, {}).get("label", plat)
    if info and info["env"]:
        return (f"No API key found for {label}. Set {' or '.join(info['env'])} in the environment of the machine running "
                "the scanner, then restart it. Or use the 'Claude Code (your Claude login)' connection, which needs no key.")
    return f"No credentials found for {label}. {PLATFORMS.get(plat, {}).get('auth', '')}"


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
        raise LLMUnavailable(f"The key or login was rejected by {PLATFORMS.get(plat, {}).get('label', plat)} (401). "
                             "Check it was copied completely, hasn't been revoked, and belongs to this connection.") from e
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
    except TypeError as e:
        if "authentication method" in str(e) or "api_key" in str(e):
            raise LLMUnavailable(_missing_credentials(plat)) from e
        raise LLMUnavailable(f"{PLATFORMS.get(plat, {}).get('label', plat)} is not ready: {e}") from e
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
    if p == "anthropic" and cfg.get("platform") == "claude_code":
        from . import claude_code
        return claude_code.complete(SYSTEM + "\n\n" + prompt, cfg)
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
            "models": MODEL_PRESETS, "env": {k: _env_status(k) for k in PLATFORMS}}


def _env_status(platform: str) -> dict:
    """Which credential env var (name only, never the value) this connection would use, if any is set."""
    info = KEY_PLATFORMS.get(platform)
    if platform == "claude_code":
        from . import claude_code
        return {"names": [], "set": claude_code.find_cli(db.get_setting("llm")) is not None, "kind": "cli"}
    if not info:
        return {"names": [], "set": None, "kind": "cloud"}
    return {"names": info["env"], "set": next((e for e in info["env"] if os.environ.get(e)), None), "kind": "env"}


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
        "to monitor, 5) retirement/upgrade notes.\n" + UNTRUSTED_RULES + "\n\n"
        f"<untrusted_finding_data>\n{json.dumps(_finding_brief(f), indent=2)}\n</untrusted_finding_data>\n"
        + (f"\nEnvironment notes from the operator (trusted): {context}\n" if context else "")
    )
    return clean(complete(prompt), db.get_setting("scope"))


def _code_excerpt(f: dict, scan: Optional[dict]) -> str:
    """A few lines around each location of a code finding, read from the kept source (only if sending code is allowed)."""
    from pathlib import Path
    src = ((scan or {}).get("summary") or {}).get("source_dir")
    if not src or not db.get_setting("llm").get("send_code"):
        return ""
    root = Path(src).resolve()
    out = []
    for loc in (f.get("locations") or [])[:3]:
        try:
            p = (root / str(loc.get("path", "")).lstrip("/\\")).resolve()
            if root not in p.parents or not p.is_file():
                continue
            lines = p.read_text("utf-8", "ignore").splitlines()
            n = int(loc.get("line") or 1)
            lo, hi = max(1, n - 25), min(len(lines), n + 25)
            out.append(f"--- {loc.get('path')} lines {lo}-{hi}\n" + "\n".join(f"{i}: {lines[i - 1][:300]}" for i in range(lo, hi + 1)))
        except (OSError, ValueError):
            continue
    return "\n".join(out)


def manual_check_for(f: dict) -> dict:
    """Hand-run manual check (benign-probe PoC) for one finding, as {request, probe, expected, steps}."""
    from .code_review_ai import MANUAL_CHECK_RULES, manual_check
    scan = db.get_scan(db.finding_scan_id(f["id"]) or "")
    brief = _finding_brief(f)
    for k in ("detail", "entry_point", "cwe", "source_tool"):
        if f.get(k):
            brief[k] = f[k]
    ev = f.get("evidence")
    brief["evidence"] = (ev if isinstance(ev, str) else json.dumps(ev, default=str))[:1500] if ev else ""
    target = (scan or {}).get("target", "")
    code = _code_excerpt(f, scan) if f.get("category") == "code" else ""
    prompt = (
        "Write a manual check (a proof of concept the tester runs by hand) for this finding from an authorized "
        "assessment of an internal lab application. " + MANUAL_CHECK_RULES + "\n"
        "If the finding is about an end-of-life component, the check confirms the exact version and whether the "
        "vulnerable feature is exposed (which URL, which response shows it), not an exploit.\n"
        "Reply with ONLY a JSON object: {\"request\": \"raw HTTP request template with the probe in place\", "
        "\"probe\": \"the benign value and why it is safe\", \"expected\": \"what in the response confirms or rules out "
        "the issue\", \"steps\": [\"short Burp Repeater / browser steps\"]}\n" + UNTRUSTED_RULES + "\n\n"
        f"Scan target (trusted): {target or 'source code review'}\n"
        f"<untrusted_finding_data>\n{json.dumps(brief, indent=1, default=str)}\n</untrusted_finding_data>\n"
        + (f"\n<untrusted_source_code>\n{code}\n</untrusted_source_code>\n" if code else "")
    )
    text = complete(prompt, max_tokens=4000)
    m = re.search(r"\{.*\}", text, re.S)
    try:
        mc = manual_check(json.loads(m.group(0))) if m else None
    except ValueError:
        mc = None
    rules = db.get_setting("scope")
    mc = clean(mc or {"request": "", "probe": "", "expected": text.strip()[:3000], "steps": []}, rules)
    mc["warnings"] = lint_manual_check(mc, target, rules)  # deterministic review of what the AI wrote
    return mc


from .guard import UNTRUSTED_RULES, clean, lint_manual_check  # noqa: E402 - guard imports scanners, keep it last
