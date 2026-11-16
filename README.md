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
python3 -m venv .venv && .venv/bin/pip install -r requirements.txt   # + requirements-llm.txt for Claude
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
.venv/bin/python tests/test_core.py
```

Use only against systems you are authorized to test.
