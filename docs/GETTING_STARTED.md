# EOL Scanner on your work laptop

This guide takes you from nothing to a working setup:

1. [Install it](#1-install)
2. [First-time setup](#2-first-time-setup)
3. [Connect your company's Claude (Enterprise / Mythos)](#3-connect-your-companys-claude-for-the-ai-features)
4. [Use the three features](#4-use-the-three-features)
5. [Check that everything works](#5-check-that-everything-works)

At the end there's [Updating](#updating) and [Troubleshooting](#troubleshooting).

> Use EOL Scanner only on systems you are authorized to test. Get written approval (a ticket or change request), and check that your company allows running a scanner from your laptop and sending source code to Claude.

---

## 1. Install

You need **Python 3.10 or newer** and **Git**, or the repo downloaded as a ZIP. No admin rights are needed. Docker works too but isn't required.

### Windows

1. Install Python, either from your software center or https://www.python.org/downloads/windows/. Tick **Add python.exe to PATH**.
2. Get the code:

   ```powershell
   cd $HOME\Documents
   git clone https://github.com/<owner>/eol-scanner.git
   ```

3. Open the `eol-scanner` folder and double-click **`install-windows.cmd`**. It ends with `ok` lines and **Done**.
4. Double-click **`start-windows.cmd`**. Your browser opens **http://127.0.0.1:8080**.

More options and Windows troubleshooting: [INSTALL_WINDOWS.md](INSTALL_WINDOWS.md).

### macOS / Linux

```bash
git clone https://github.com/<owner>/eol-scanner.git
cd eol-scanner
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt -r requirements-llm.txt
EOLSCAN_DATA=./data .venv/bin/uvicorn app.main:app --host 127.0.0.1 --port 8080
```

Then open **http://127.0.0.1:8080**. Leave the terminal open while you use it.

### Optional extras

| Extra | What it adds | Install |
|---|---|---|
| Browser crawl | Finds JavaScript libraries in single-page apps (React, Angular, Vue) | Windows: `install-windows.ps1 -WithBrowser`. Mac/Linux: `.venv/bin/pip install -r requirements-browser.txt` then `.venv/bin/playwright install chromium` |
| Semgrep | Extra data-flow rules during code review | `.venv/bin/pip install semgrep` (Windows: `.venv\Scripts\pip install semgrep`) |

### Behind a corporate proxy

Set the proxy before installing:

- Mac/Linux: `export HTTPS_PROXY=http://proxy.corp:8080`
- Windows: `$env:HTTPS_PROXY="http://proxy.corp:8080"`

If pip reports certificate errors, also set `PIP_CERT` to your company's CA file.

---

## 2. First-time setup

1. **Settings → Scope allowlist**: add the lab hosts you're authorized to scan, one per line. For example `qa-app.lab.corp`, `*.qa.corp` or `10.20.0.0/16`. Everything else is blocked, and an empty list blocks all scans.
2. **Settings → Data feeds → Sync EOL data**: do this while you have internet. The tool also works offline with its built-in data.

---

## 3. Connect your company's Claude (for the AI features)

The scanner works fully without AI. Claude adds the **AI deep code review** and tailored containment plans.

### Which option you have

**A Claude Enterprise seat on its own is a claude.ai chat login.** Tools can't use a chat login directly. Most companies give you one of these three routes; ask your Claude admin or IT which:

| You have | Use the connection | Key needed? |
|---|---|---|
| **Claude Code** on your company Claude account | **Claude Code (your Claude / Enterprise login)** | **No.** It uses your login. |
| An **API key** from your company's Claude Console organization | **Anthropic API (direct)** | Yes, as an environment variable |
| An internal **AI gateway** URL and token, or Claude through **AWS Bedrock / Google Vertex / Azure Foundry** | The matching connection | An environment variable or your cloud login |

**Mythos:**
- If your organization has access to `claude-mythos-5-2`, select it as the **Model**.
- If you don't have it, Claude Code or the API tells you so. Leave the model at the default, or use `claude-fable-5-2` (same model, open to everyone).
- With the Claude Code connection, Mythos is used only if your org enabled it for Claude Code. Run `claude`, then `/model`, to see what's available to you.

### Option 1: Claude Code with your work login (recommended, no API key)

1. **Install Claude Code** on the same laptop as the scanner. You can also use your company's software center if it's listed there.
   - Windows (PowerShell): `irm https://claude.ai/install.ps1 | iex`
   - macOS / Linux: `curl -fsSL https://claude.ai/install.sh | bash`
   - Or, with Node.js installed: `npm install -g @anthropic-ai/claude-code`
2. **Sign in once.** Open a new terminal, run `claude`, and log in with your **work** Claude account (your company's SSO). Type `/model` to see which models you can use, including Mythos if enabled. Then exit with `/exit`.
3. In the scanner, go to **Settings → AI assist**:
   - **Provider:** Claude
   - **Connection:** Claude Code (your Claude / Enterprise login)
   - **Model:** leave the default, or pick `claude-mythos-5-2` if you have it
   - Tick **"I'm allowed to send source code to this Claude connection"** (needed for the code review)
   - Click **Save**, then **Test connection**. You should see `Connected`.
   - If it says Claude Code wasn't found, paste its full path into **Claude Code path**. Find it with `where claude` (Windows) or `which claude` (Mac/Linux).

This connection needs the scanner running directly on your laptop (the Python install), not in Docker.

How the scanner runs Claude Code:
- **Read-only:** only Read, Grep and Glob are allowed. Bash, file editing, web access and sub-agents are blocked.
- **Only the uploaded code:** it runs inside that scan's extracted source folder.
- **Your login, not an API key:** any `ANTHROPIC_API_KEY` in the environment is ignored, so your work login is used.

### Option 2: API key, gateway or cloud

The scanner never asks for or stores keys. Set the key as an environment variable **before starting the scanner**, in the same window.

- **API key.** Windows (PowerShell):

  ```powershell
  $env:ANTHROPIC_API_KEY = "sk-ant-..."
  powershell -ExecutionPolicy Bypass -File scripts\start-windows.ps1
  ```

  Mac/Linux:

  ```bash
  export ANTHROPIC_API_KEY=sk-ant-...
  EOLSCAN_DATA=./data .venv/bin/uvicorn app.main:app --host 127.0.0.1 --port 8080
  ```

- **Company gateway.** Set `ANTHROPIC_AUTH_TOKEN`, or `ANTHROPIC_API_KEY` if your gateway expects an `x-api-key` header. Then enter the gateway URL in Settings.
- **Bedrock:** sign in with `aws sso login --profile <name>`, then fill in the region and profile in Settings.
- **Vertex:** run `gcloud auth application-default login`, then fill in the project and region in Settings.
- **Foundry:** set `ANTHROPIC_FOUNDRY_API_KEY` and fill in the resource name in Settings.

Then go to **Settings → AI assist**, pick the connection, **Save**, and **Test connection**. The page shows whether the needed variable is set (never its value).

---

## 4. Use the three features

### Feature 1: Code review of an uploaded ZIP

1. Open **Code review** and upload a `.zip` or `.tar.gz` of the application. The code is extracted and read, never run.
2. Tick the options you want, then **Upload & review**:
   - **Run the AI deep review after the scan** (needs Claude, section 3).
   - **Also run Semgrep** (if installed).
3. The automatic scan finishes in seconds to minutes. It finds:
   - **Outdated components:** every dependency and runtime (npm, Maven/Gradle, PyPI, NuGet, Composer, RubyGems, Go, Dockerfile base images, bundled JARs), with end-of-life dates and known CVEs.
   - **Risky code:** about 54 rules (SQL and command injection, XSS, file inclusion and path traversal, SSRF, XXE, open redirects, unsafe deserialization, hardcoded secrets, weak crypto, debug settings). Each is mapped to the **URL and parameter** that reaches it where possible.
4. The **AI deep review** (tab "AI deep review ✦", or the button at the top of the scan) runs in the background. Large codebases can take 10–40 minutes; watch progress in the **Log** tab. Claude:
   - finds the entry points and traces user input through the code;
   - gives each pattern match a verdict: *confirmed*, *likely false positive* or *needs runtime check*;
   - looks for what patterns miss: access control, authentication, logic flaws, deserialization, file handling.

   Each confirmed vulnerability appears in **Findings** with the Claude badge.
5. Every code finding shows:
   - **Reached via**: the HTTP method, path and parameter.
   - **Confirm in the code**: a checklist to tell real issues from false alarms.
   - **How to verify safely**: non-destructive checks for the authorized lab.
   - **Containment (no code change needed)**: WAF/proxy rules with copyable nginx/Apache/IIS snippets, isolation, least privilege, monitoring.
6. Export with **HTML / Markdown / CSV / JSON** at the top of the scan.

The extracted source is kept so the AI review can read it. **Delete kept source** (on the AI tab) or deleting the scan removes it.

### Feature 2: Web crawl of your allowlisted hosts

1. Open **Web scan** and enter one target, or several (one per line). **Use all allowlisted hosts** fills in every exact host from your scope.
2. Pick a depth:
   - **Passive:** page loads only.
   - **Safe:** adds about 40 checks for well-known files.
   - **Active:** adds version endpoints, admin consoles, HTTP methods and legacy TLS.

   None of them sends exploit payloads.
3. Optional, under **Advanced**: auth headers or cookies (never stored), and **Render pages in a headless browser** for single-page apps.
4. Each target gets its own scan. For several targets, the Dashboard shows **Multi-target scans** with a **Combined HTML / CSV / Markdown** report. It includes a table of which end-of-life components run on which hosts.
5. Every finding comes with containment for code that won't change: isolation, WAF virtual patches, proxy snippets, header and cookie fixes at the proxy, monitoring, extended-support options, and manual lab checks for the serious ones.

### Feature 3: Versions in use, plus Burp and other tools

- **Inventory tab** (on any scan): every component and version found, its lifecycle status (end-of-life, ending soon, supported) and known CVE count.
- **Import → Burp proxy history:** in Burp go to **Proxy → HTTP history**, select the items, then right-click → **Save items** (keep "Base64-encode" on). Upload the XML.
  - It's analysed **passively**: versions, end-of-life components, exposed files, security headers, cookie flags, CORS and login forms over HTTP.
  - **No traffic is sent.** This also works for apps that need login, because you already browsed them.
- **Import → HAR file:** in browser DevTools → Network, choose **Save all as HAR**. Analysed the same way.
- **Import → scanner reports:** Burp issues XML, OWASP ZAP (JSON or XML), Semgrep JSON, SARIF (CodeQL, Snyk, Checkmarx, SonarQube…), Nuclei JSONL. Each finding gets containment advice, and you can merge it into an existing scan for one report.

---

## 5. Check that everything works

These checks use only your laptop: no VPN, no lab, no Claude needed.

1. **Self-tests:**
   - Windows: `.venv\Scripts\python tests\test_core.py`
   - Mac/Linux: `.venv/bin/python tests/test_core.py`

   You should see 21 lines starting with `ok`. A `skip` line is fine for an optional extra you didn't install.
2. **Fake legacy web app.** In a second terminal, run `.venv/bin/python tests/fake_target.py 8899` (Windows: `.venv\Scripts\python tests\fake_target.py 8899`). Then:
   - add `127.0.0.1` to the scope;
   - start a **Web scan** of `http://127.0.0.1:8899` in **Active** mode.

   Expect about 24 findings: Apache 2.2, PHP 5.6, AngularJS 1.5, jQuery 1.12, an exposed `.git` folder, CORS trusting any site, missing headers, a login form over HTTP, and more.
3. **Code review:** upload `tests/fixtures/legacyapp.zip`. Expect about 42 findings, including log4j 2.14.1, Struts 2.3 and Django 1.11, plus SQL injection, command injection and XSS in the sample PHP, Java, Node, Python and C# files, each with its URL and parameter.
4. **Burp / HAR:** in **Import**, upload `tests/fixtures/imports/burp-items.xml` or `traffic.har`. Expect Apache 2.2, PHP 5.6, jQuery 1.12 and six header/cookie/CORS findings.
5. **Claude:** in **Settings → AI assist**, click **Test connection**. Then open the code scan from step 3 and run **AI deep review**.

---

## Updating

```bash
git pull
```

Then:
- **Windows:** re-run `install-windows.cmd`.
- **Mac/Linux:** re-run the `pip install` line.

Restart the scanner. Your settings and scans are kept in `data/`.

## Troubleshooting

| Problem | Fix |
|---|---|
| Scan says "out of scope" | Add the host to **Settings → Scope allowlist**. Use exact host, `*.domain`, CIDR or `host:port`. |
| Test connection: "Claude Code not found" | Install Claude Code (section 3), open a **new** terminal, run `claude` once, or paste its path in Settings. |
| Claude Code connection doesn't work in Docker | Expected: the container can't see your `claude` install or login. Run the scanner with Python (section 1) to use Claude Code. |
| Test connection: Claude Code not signed in | Run `claude` in a terminal and log in with your work account. |
| Test connection: "No API key found" | The key wasn't set in the same window that started the scanner. Set it, then restart the scanner. |
| 403 / model not available | Your org doesn't have that model, for example Mythos. Choose the default or `claude-fable-5-2`. |
| AI review says "the model declined" | Rare with security code. Re-run, or use the rule-based results and the "Confirm in the code" checklist. |
| AI review is slow | Large codebases take time. Lower **max steps** or **effort** in Settings, or review one module at a time (zip a sub-folder). |
| Lab site unreachable | Connect to the VPN. If lab sites need the corporate proxy, tick **Route through HTTP(S)_PROXY** in the scan's Advanced section. |
| TLS errors | Leave **Verify TLS** off for internal certificates, or set `SSL_CERT_FILE` to your company's CA. |
| Import says "unrecognised format" | Use one of the listed exports. For Burp history, use **Save items** (XML), not "Report issues". |
| Port 8080 in use | Start with `--port 8090` (Windows: `start-windows.ps1 -Port 8090`). |
