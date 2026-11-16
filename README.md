# EOL Scanner

Finds **end-of-life and vulnerable components** in authorized web apps (live scan) and source code (zip upload), and tells you how to **contain** them when the code will never be changed.

- **Web scan**: crawls the target, fingerprints server, framework, CMS and JS-library versions from headers, HTML, JS banners, error pages and exposed lockfiles, then maps each one to its lifecycle (endoflife.date) and known CVEs (OSV.dev).
- **Code review**: upload `.zip`/`.tar.gz`. The tool parses npm, PyPI, Maven/Gradle, Composer, RubyGems, Go, NuGet, Dockerfile `FROM`, runtime pins, vendored JS and bundled JARs (via `pom.properties`), and flags risky legacy patterns. It **never executes** the code.
- **Containment advice** for every finding: network isolation, WAF/virtual-patch rules, proxy config snippets (nginx/Apache/IIS), hardening, detection, extended-support options, and **manual lab verification steps** for the serious ones.
- **Optional AI assist**: Claude (Anthropic API) or a local Ollama model gives tailored containment plans and a deeper code review. It's off by default, and by default no source code is sent.
- **Exports**: HTML, Markdown, CSV, JSON.

## Run it

```bash
docker compose up -d --build        # → http://127.0.0.1:8080
```

Without Docker (Python 3.9+):

```bash
python3 -m venv .venv && .venv/bin/pip install -r requirements.txt   # + requirements-llm.txt for Claude (incl. Bedrock/Vertex/AWS/GCP clients)
EOLSCAN_DATA=./data .venv/bin/uvicorn app.main:app --port 8080
```

First steps: **Settings → Scope**: add the authorized lab hosts. An empty allowlist blocks every scan.

## Corp VPN / air-gapped labs

| Need | How |
|---|---|
| No internet in the lab | The EOL database (489 products) is bundled. Refresh it before you go in with **Settings → Sync** or `python scripts/build_snapshot.py`. OSV results are cached in SQLite, so scan once while online to warm the cache. |
| Corp proxy | Set `HTTPS_PROXY` for feeds. Tick "route through proxy" per scan only if the target also needs it. |
| Internal CA | Mount it and set `SSL_CERT_FILE` (see `docker-compose.yml`). TLS verification of targets is off by default. |
| Shared team VM | Bind to `0.0.0.0` and set `EOLSCAN_USER` / `EOLSCAN_PASSWORD` (HTTP basic auth). |
| Authenticated apps | Add `Authorization` headers or a `Cookie` per scan. Their values are never stored. |

## AI assist on your org's Claude

**Settings → AI assist → Provider: Claude**, then pick the **Connection** your org gives you and press **Test connection**. Keys and tokens are never saved in the app: they come from environment variables or your cloud login on the machine/container running the scanner.

| Connection | Fill in | Credentials (env / login) |
|---|---|---|
| Anthropic API (direct) | — | `ANTHROPIC_API_KEY` (an org/workspace key) |
| Company LLM gateway / proxy | Gateway URL | `ANTHROPIC_API_KEY` (x-api-key) or `ANTHROPIC_AUTH_TOKEN` (Bearer) |
| Amazon Bedrock (or legacy InvokeModel) | AWS region, optional profile | AWS profile/SSO/role, `AWS_*` keys, or `AWS_BEARER_TOKEN_BEDROCK` |
| Claude Platform on AWS | AWS region, workspace ID | AWS profile/SSO/role or `AWS_*` keys |
| Google Vertex AI | GCP project, region | `gcloud auth application-default login` / `GOOGLE_APPLICATION_CREDENTIALS` |
| Claude on Google Cloud (Anthropic managed) | GCP project, workspace ID | gcloud ADC |
| Microsoft Foundry | Foundry resource | `ANTHROPIC_FOUNDRY_API_KEY` |

**Models**: pick a preset or type any ID. `claude-mythos-5-2` works only if Anthropic has verified your organization (for example through the Cyber Verification Program); otherwise use `claude-fable-5-2`, the same model open to everyone, or the default `claude-opus-5-5`. On Bedrock the `anthropic.` prefix is added for you, and inference-profile IDs and ARNs are passed through unchanged. Which models are available depends on your org's account and region; a 403 or 404 on Test usually means that model isn't enabled for you.

The gateway connection only works with gateways that speak the Anthropic Messages API. Gateways that only accept the OpenAI format aren't supported. If a gateway rejects the refusal-fallback option, the scanner retries with a plain request.

## Scan modes

| Mode | What it sends |
|---|---|
| Passive | Normal page loads and same-origin JS only. |
| Safe (default) | Passive, plus about 40 GETs for well-known disclosure files (lockfiles, `.git/HEAD`, `server-status`, phpinfo…) and a random 404 for error-page fingerprinting. |
| Active | Safe, plus product version endpoints (Grafana, Jira, GitLab, Solr…), admin/debug consoles (Tomcat manager, actuator, Werkzeug, Ignition…), OPTIONS/TRACE, directory listing and a legacy TLS 1.0/1.1 handshake test. **No exploit payloads.** |

Guardrails: every request (and every redirect hop) is checked against the scope allowlist. Scans also have a rate limit, a concurrency cap and a request budget. The operator name, ticket and authorization attestation are recorded per scan. Sensitive responses (`.env`, actuator `/env`) are redacted in evidence.

## Layout

```
app/
  main.py            FastAPI API + static UI
  jobs.py            background scan runner
  scope.py           allowlist enforcement
  analysis.py        detections → lifecycle + CVEs → prioritized findings
  eol/               endoflife.date snapshot, curated additions, OSV client
  scanners/          web.py, code.py, fingerprints.py, manifests.py, probes.py
  advisor/           mitigations.py (containment KB), llm.py (optional Claude/Ollama)
  static/            dependency-free UI (works offline)
tests/               test_core.py, fake_target.py (local legacy-looking app), fixtures/
```

Extending: add fingerprints in `scanners/fingerprints.py`, probes in `scanners/probes.py`, lifecycle data for untracked products in `eol/data/curated.json`, and containment guidance in `advisor/mitigations.py`.

## Try it locally

```bash
.venv/bin/python tests/fake_target.py 8899 &      # fake legacy app (Apache 2.2 / PHP 5.6 / AngularJS 1.5…)
# Settings → Scope → allow 127.0.0.1, then scan http://127.0.0.1:8899 in Active mode
# Code review → upload tests/fixtures/legacyapp.zip
.venv/bin/python tests/fake_gateway.py 8898 &     # fake company LLM gateway (strict, rejects beta options)
# Start the scanner with ANTHROPIC_AUTH_TOKEN=test, then Settings → AI assist → Company gateway → http://127.0.0.1:8898 → Test
.venv/bin/python tests/test_core.py
```

Use only against systems you are authorized to test.
