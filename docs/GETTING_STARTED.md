# Getting started on a work laptop

This guide takes you from a fresh laptop to a working scan in this order:

1. Get the code.
2. Run it.
3. Point it at your lab.
4. Connect it to your company's Claude (optional).
5. Check that everything works.

Commands are given for **macOS / Linux** and for **Windows (PowerShell)**.

> Use EOL Scanner only on systems you are authorized to test. Get written approval (a ticket or change request) before scanning lab apps, and check that your company allows running a scanner from your laptop.

---

## 1. What you need

| Need | Notes |
|---|---|
| Access to the GitHub repo | Ask the owner to add you if it's private. |
| `git` | macOS: `xcode-select --install`. Windows: Git for Windows, or ask IT. |
| **Either** Docker **or** Python | Docker Desktop, Rancher Desktop or Podman all work. Without Docker, Python 3.9 or newer (3.12 recommended). |
| Corporate VPN | Only needed while scanning lab apps. |
| A browser | The whole tool is a web page at `http://127.0.0.1:8080`. |

Corporate laptops often need IT approval for Docker. If that's a problem, use the Python option. It does the same thing.

---

## 2. Get the code

Replace `<owner>` with the GitHub account or organization that holds the repo.

```bash
git clone https://github.com/<owner>/eol-scanner.git
cd eol-scanner
```

To update later, run `git pull` in the same folder, then restart the tool (see "Updating" at the end).

---

## 3. Run it

### Option A: Docker (recommended)

```bash
docker compose up -d --build
```

Open **http://127.0.0.1:8080**.

- Stop it: `docker compose down`
- Logs: `docker compose logs -f`

Scan history and settings live in a Docker volume, so they survive restarts and rebuilds.

### Option B: Python

macOS / Linux:

```bash
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt -r requirements-llm.txt
EOLSCAN_DATA=./data .venv/bin/uvicorn app.main:app --host 127.0.0.1 --port 8080
```

Windows (PowerShell):

```powershell
py -3 -m venv .venv
.venv\Scripts\pip install -r requirements.txt -r requirements-llm.txt
$env:EOLSCAN_DATA = ".\data"
.venv\Scripts\uvicorn app.main:app --host 127.0.0.1 --port 8080
```

Open **http://127.0.0.1:8080**. Leave the terminal open while you use it, and press Ctrl+C to stop.

If `pip install` fails behind the corporate proxy, set it first:

```bash
export HTTPS_PROXY=http://proxy.corp:8080
```

On Windows: `$env:HTTPS_PROXY="http://proxy.corp:8080"`. If you also need your company's certificate authority, set `PIP_CERT=/path/corp-ca.pem`.

---

## 4. First-time setup in the UI

1. **Settings → Scope allowlist**: add the lab hosts you are authorized to scan, one per line. For example `qa-app.lab.corp`, `*.qa.corp`, `10.20.0.0/16` or `app.lab.corp:8443`. Use the deny list for anything off-limits, such as databases. **An empty allowlist blocks every scan.**
2. **Settings → Data feeds**: while you are on a network with internet access, click **Sync EOL data**. If the lab network has no internet, do this before you connect to it. The tool still works offline using the lifecycle data that ships with it.
3. If your lab sites use your company's own TLS certificates, leave **Verify TLS** off, which is the default. Or provide your company's CA (see Troubleshooting).

---

## 5. Connect it to your company's Claude (optional)

The scanner works without AI. Claude adds a tailored containment plan for each finding and a deeper review of uploaded code.

### Important: Claude Enterprise is not the same as API access

A **Claude Enterprise** seat is for claude.ai (the chat app). Tools like this one call Claude through the **API**, which is set up and billed separately. An Enterprise login does not work here, and the plan does not include API credits.

Ask your Claude admin, platform team or IT which of these your company provides. The answer decides which **Connection** you pick:

| What IT gives you | Connection to pick | What to set |
|---|---|---|
| An Anthropic API key from the company's Claude Console organization | **Anthropic API (direct)** | `ANTHROPIC_API_KEY` |
| An internal "LLM gateway" or AI proxy URL plus a token | **Company LLM gateway / proxy** | Gateway URL in the UI, plus `ANTHROPIC_AUTH_TOKEN` (or `ANTHROPIC_API_KEY` if the gateway expects an x-api-key header) |
| Claude through AWS Bedrock | **Amazon Bedrock** | AWS region in the UI, plus your normal AWS login (SSO profile, role or keys) |
| Claude Platform on AWS | **Claude Platform on AWS** | Region and workspace ID in the UI, plus your AWS login |
| Claude through Google Vertex AI | **Google Vertex AI** | GCP project and region in the UI, plus `gcloud auth application-default login` |
| Claude on Google Cloud (Anthropic managed) | **Claude on Google Cloud** | GCP project and workspace ID in the UI, plus your gcloud login |
| Claude through Azure / Microsoft Foundry | **Microsoft Foundry** | Foundry resource name in the UI, plus `ANTHROPIC_FOUNDRY_API_KEY` |

Questions worth asking IT at the same time:

- Is the gateway "Anthropic-compatible"? It must accept Anthropic's Messages API format. Gateways that only accept the OpenAI format won't work.
- Which models are enabled for us?
- Are we allowed to send source code to the model? If not, keep that setting off (it's off by default).

### Where to put the key

Keys are **never** typed into or saved by the app. They are read from the environment of whatever runs the scanner.

**Docker:**

1. Create a file named `.env` next to `docker-compose.yml`. It is git-ignored.

   ```
   ANTHROPIC_API_KEY=sk-ant-...
   # or, for a gateway:
   ANTHROPIC_AUTH_TOKEN=...
   ```

2. In `docker-compose.yml`, under `environment:`, uncomment the matching line, for example `ANTHROPIC_API_KEY: ${ANTHROPIC_API_KEY}`.
3. For Bedrock or Vertex, also uncomment the `~/.aws` or `~/.config/gcloud` volume line.
4. Restart with `docker compose up -d`.

**Python, macOS / Linux**, in the same terminal before starting uvicorn:

```bash
export ANTHROPIC_API_KEY=sk-ant-...
# or: export ANTHROPIC_AUTH_TOKEN=...
# or: export AWS_PROFILE=my-sso-profile
```

**Python, Windows**, in the same PowerShell window before starting uvicorn:

```powershell
$env:ANTHROPIC_API_KEY = "sk-ant-..."
```

### Turn it on

1. Go to **Settings → AI assist**.
2. Set **Provider** to **Claude** and pick your **Connection**.
3. Fill in the fields that appear: gateway URL, region, project, workspace or resource.
4. **Model**: leave `claude-opus-5-5` or pick from the list.
   - `claude-mythos-5-2` only works if Anthropic has verified your company's organization (for example through the Cyber Verification Program). If you get a 403, use `claude-fable-5-2`, which is the same model and open to everyone.
   - On Bedrock, the scanner adds the `anthropic.` prefix for you.
5. Click **Test connection**. You should see `Connected · <model> · <n>s`. If you see an error, the message says what's missing, and the Troubleshooting section below covers the common ones.
6. Click **Save**.

To use it: open a finding and click **Ask AI for a tailored containment plan**. You can add environment notes first, such as "behind F5". For a code scan, open the **AI review** tab. By default only metadata (component names, versions, findings) is sent. Source code is sent only if you tick **Allow sending source-code snippets**.

---

## 6. Check that it works

These checks use only your laptop. No VPN or lab access is needed.

### a) Unit tests (about 5 seconds)

macOS / Linux:

```bash
.venv/bin/python tests/test_core.py
```

Windows: `.venv\Scripts\python tests\test_core.py`

The Docker image doesn't include the tests, so run them with Python. You only need `pip install -r requirements.txt -r requirements-llm.txt` in a venv.

You should see 9 lines starting with `ok`.

### b) Live scan of a fake legacy app

1. Start the fake app in a second terminal:

   ```bash
   .venv/bin/python tests/fake_target.py 8899
   ```

   Windows: `.venv\Scripts\python tests\fake_target.py 8899`

2. In the UI, go to **Settings → Scope** and add `127.0.0.1`.
3. Open **Web scan**:
   - target `http://127.0.0.1:8899`
   - mode **Active**
   - tick the authorization box
   - click **Start scan**.
4. Expect about 20 findings: Apache 2.2, PHP 5.6, AngularJS 1.5, jQuery 1.12, an exposed `.git` folder, an exposed Spring actuator, TRACE enabled, and more.
5. Try a target that isn't in scope, such as `http://example.com`. It should be refused.

If the scanner runs in Docker, `127.0.0.1` means the container itself. In that case use `http://host.docker.internal:8899` as the target and add `host.docker.internal` to the scope. On Linux, also start the fake app with `tests/fake_target.py 8899 0.0.0.0`.

### c) Code review of a sample legacy project

1. In **Code review**, upload `tests/fixtures/legacyapp.zip`.
2. Expect about 25 findings: log4j 2.14.1 (Log4Shell), Struts 2.3, Django 1.11, Python 2.7 and Debian 9 base images, ViewState MAC disabled, a hardcoded password, and more.

### d) AI connection without a real account (optional)

This checks the gateway path against a fake gateway on your laptop.

1. Start the fake gateway:

   ```bash
   .venv/bin/python tests/fake_gateway.py 8898
   ```

2. Start the scanner with `ANTHROPIC_AUTH_TOKEN=test` set.
3. In **Settings → AI assist**, pick **Company LLM gateway**, enter `http://127.0.0.1:8898`, then click **Test connection**.
4. You should see `Connected`.

The fake gateway only replies "OK". Real advice needs a real connection (step 5).

---

## 7. Running a real lab scan

1. Connect to the VPN and make sure the lab host is in **Scope**.
2. Go to **Web scan** and fill in:
   - **Operator**: your name.
   - **Ticket**: your approval or change number.
   - Any auth headers or cookies the app needs. These are used for the scan only and never stored.
3. Pick a mode:
   - **Passive**: page loads only.
   - **Safe** (default): adds about 40 GETs for well-known files.
   - **Active**: adds version endpoints, admin consoles, TRACE and a legacy TLS check. It never sends exploit payloads.

   Start with Safe on fragile apps.
4. Review the findings. Each one has containment steps (WAF/proxy snippets, isolation), extended-support options and, for serious ones, manual lab verification steps.
5. Export the results as HTML, Markdown, CSV or JSON from the scan page for your ticket or report.

---

## Updating

```bash
git pull
docker compose up -d --build        # Docker
# Python: re-run pip install, then restart uvicorn
```

Your settings and scan history are kept.

---

## Troubleshooting

| Symptom | Fix |
|---|---|
| Scan says "out of scope" | Add the exact host, a wildcard like `*.qa.corp`, a CIDR range, or `host:port` in Settings → Scope. |
| Lab site unreachable in Docker | Docker may not see the VPN routes. Try the Python option, or Docker's host networking on Linux. |
| TLS or certificate errors to feeds or Claude | Put the corporate CA in a file and set `SSL_CERT_FILE=/path/corp-ca.pem`. For Docker, uncomment the CA volume and `SSL_CERT_FILE` in `docker-compose.yml`. |
| Corporate proxy blocks feeds or Claude | Set `HTTPS_PROXY` (and `NO_PROXY=127.0.0.1,localhost,.lab.corp`). |
| Test connection: "credentials missing/invalid" | The key or token isn't in the scanner's environment. Docker: check `.env` and the uncommented line. Python: set it in the same terminal, then restart. |
| Test connection: 403 | Your org doesn't have that model, or Mythos isn't enabled. Try `claude-fable-5-2` or `claude-opus-5-5`. |
| Test connection: 404 / model not found | Wrong model ID or region for Bedrock/Vertex. Ask IT which IDs are enabled. |
| Test connection: cannot reach endpoint | Proxy, VPN or firewall. Gateways are often reachable only on the VPN. |
| UI looks out of date after an update | Hard refresh (Ctrl/Cmd+Shift+R). |
| Port 8080 already in use | Python: use `--port 8090`. Docker: change `127.0.0.1:8080:8080` to `127.0.0.1:8090:8080`. |
| Sharing with your team on a VM | Bind to `0.0.0.0` and set `EOLSCAN_USER` / `EOLSCAN_PASSWORD`. See the README. |
