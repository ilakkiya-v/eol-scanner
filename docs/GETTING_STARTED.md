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
4. Double-click **`start-windows.cmd`**. Your browser opens **http://127.0.0.1:8765**.

More options and Windows troubleshooting: [INSTALL_WINDOWS.md](INSTALL_WINDOWS.md).

### macOS / Linux

```bash
git clone https://github.com/<owner>/eol-scanner.git
cd eol-scanner
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt -r requirements-llm.txt
EOLSCAN_DATA=./data .venv/bin/uvicorn app.main:app --host 127.0.0.1 --port 8765
```

Then open **http://127.0.0.1:8765**. Leave the terminal open while you use it.

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
  EOLSCAN_DATA=./data .venv/bin/uvicorn app.main:app --host 127.0.0.1 --port 8765
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
4. The **AI review** (tab "AI review ✦", or the button at the top of the scan) runs in the background. Large codebases can take 10–40 minutes; watch progress in the **Log** tab. Claude:
   - finds the entry points and traces user input through the code;
   - gives each pattern match a verdict: *confirmed*, *likely false positive* or *needs runtime check*;
   - looks for what patterns miss: access control, authentication, logic flaws, deserialization, file handling.

   Each confirmed vulnerability appears in **Code vulnerabilities** with the Claude badge.
5. Results are split into tabs, with a summary card for each at the top:
   - **Code vulnerabilities**: injection and other code flaws.
   - **EOL & components**: a table of every end-of-life or vulnerable dependency (version, end-of-life date, CVE count, where it was found), then details and containment for each.
   - **All components**: the full inventory.
6. Every code vulnerability shows:
   - **Reached via**: the HTTP method, path and parameter.
   - **Manual check (PoC)**: the HTTP request to send (copy it into Burp Repeater), a harmless probe value, and what in the response confirms the issue. The AI review writes one for each issue it reports. For any other finding, press **Write a manual check (PoC) with AI**. Probes are deliberately benign (a marker string, a quote character, two equivalent numbers, another test record's id): they show the flaw exists without extracting data or changing anything.
   - **Confirm in the code**: a checklist to tell real issues from false alarms.
   - **Containment (no code change needed)**: WAF/proxy rules with copyable nginx/Apache/IIS snippets, isolation, least privilege, monitoring.
7. **Export** (top right) gives HTML, Markdown, CSV or JSON. The reports follow the same split: vulnerabilities, then end-of-life components, then the attack surface.

The extracted source is kept so the AI review can read it. **Delete kept source** (on the AI tab) or deleting the scan removes it.

### Feature 2: Web crawl of your allowlisted hosts

1. Open **Web scan**. The form has four steps.
2. **Target:** one URL, or several (one per line). **Use all allowlisted hosts** fills in every exact host from your scope.
3. **How deep:**
   - **Passive:** page loads, `robots.txt` and sitemaps only.
   - **Safe:** adds API documents (OpenAPI/Swagger), about 40 checks for well-known files, and a CORS check.
   - **Active:** adds version endpoints, admin consoles, HTTP methods and legacy TLS.

   None of them sends exploit payloads. **Max pages** defaults to 150. Tick **Also render pages in a headless browser** for single-page apps.
4. **Extra engines** (optional): Burp Suite (see below) and **AI web review when the scan finishes**.
5. **Authorization:** your name and ticket. Under **Advanced** you can add a session cookie or auth header for a logged-in crawl. Log in with a test account, then copy the cookie from Burp or the browser. It is never stored.

**If the crawl finds little**, it is almost always one of these. The **Attack surface** tab's *How the crawl went* panel tells you which:
- **The app needs a login.** Under *Logged-in crawl*, give the login page and a **dedicated test account**. The scanner fills in the app's own form once, keeps the session and never follows logout links. The password is not stored.
  - It recognises the usual legacy patterns: hidden `username`/`passwd` fields filled by JavaScript, `<button>` submits such as `jxn=login`, and inputs without a type.
  - The log and *How the crawl went* show exactly what was sent, for example `POST /lab/login.do with username=<username>, passwd=<password>, jxn=login`.
  - **If the login still fails,** open the app's real login request in Burp and copy its field names into **Login form fields**, e.g. `username={user}&passwd={password}&jxn=login`. If the request goes to a different URL than the login page, put it in **Send them to**. Hidden anti-CSRF fields are still added automatically.
  - If the login goes through single sign-on on another host, paste a session cookie under **Advanced** instead.
  - With **Run a Burp Suite Pro scan too**, Burp's crawler is given the same test account. Without one, Burp fills login forms with random values such as `username=QpbASCGm`; those requests come from Burp, not from this scanner.
  - To see this scanner's own login request in Burp, tick **Send the crawl through Burp** and look in **Proxy → HTTP history** for the request whose User-Agent is `EOL-Scanner`.
- **Pages aren't linked from anywhere.** Keep **Guess common unlinked paths** ticked. It tries about 340 well-known admin, API, docs and backup paths with GET and filters out "soft 404" pages. Also add the pages you know about under *Extra start paths*.
- **The app spans several hosts.** The panel lists other hosts the app links to. Add them to the scope and tick **Also crawl other allowlisted hosts**.
- **It's a single-page JavaScript app.** Tick **Also render pages in a headless browser**.
- **It hit the page limit.** Raise **Max pages**.

**What the crawl finds.** It follows every link, frame and meta refresh, and reads `robots.txt`, sitemaps and OpenAPI/Swagger documents. It pulls endpoint paths out of JavaScript (fetch/axios/jQuery calls and `/api/...` strings) and records every form with its fields. It does not follow logout, delete, reset or similar links, and it never submits forms or requests POST targets. Pages that differ only by an id (`/item/1`, `/item/2`, …) are visited a few times, not hundreds.

**Results** are split like the code review:
- **Web findings:** exposures, misconfigurations, Burp issues and AI review findings.
- **EOL & components:** end-of-life and vulnerable components, with containment.
- **Attack surface:** every endpoint with its method, parameters and where it was found. It flags login forms, file uploads and POST forms without an anti-CSRF token. **Copy URLs** gives a list to paste into Burp.

For several targets, the Dashboard shows **Multi-target scans** with a **Combined HTML / CSV / Markdown** report, including a table of which end-of-life components run on which hosts.

**AI web review** (button **AI review ✦** on the scan, or tick it before scanning). Claude goes through every crawled page, script and endpoint, like a pentester reading proxy history. It:
- maps login, roles and sensitive functions;
- gives each finding a verdict;
- looks for what automated checks miss: reflected input, verbose errors, IDOR candidates, open redirects, SSRF-style URL parameters, forms without anti-CSRF tokens, secrets in scripts, exposed admin functions;
- says where each end-of-life component is exposed.

Every issue it reports comes with a **manual check (PoC)** and containment.

The scanner checks the AI's work in code, not by trusting the AI:
- Each finding's quoted evidence is looked up in the crawled pages. If it can't be found, the finding shows **unverified** and is capped in severity.
- Each manual check is scanned for harmful requests, which get a red warning.
- Pages that contain text aimed at AI tools are reported as a separate finding.

See [THREAT_MODEL.md](THREAT_MODEL.md). With an API connection (not Claude Code), it may also send a limited number of live in-scope GET requests (default 40; Settings → Code review) to confirm what it sees, in Safe and Active scans only. The crawled pages are saved, with cookie and authorization values redacted, so the review can read them. Deleting the scan, or **Delete saved crawl data** on the AI tab, removes them.

#### Using your Burp Suite Professional licence

Two independent options in step 3 of the web scan form:

- **Send the crawl through Burp:** the scanner sends all its traffic through Burp's proxy listener (Settings → Burp Suite → *Proxy listener*, default `http://127.0.0.1:8080`). Every page, script and API call then appears in Burp's **HTTP history** and **site map**, ready for Repeater and Intruder. Burp just needs to be running with its normal proxy listener.
- **Run a Burp Suite Pro scan too:** after the crawl, the scanner asks Burp (through its REST API) to crawl and audit the same target, then imports Burp's issues into **Web findings**. Burp's scope is set to that host only, and logout-style URLs are excluded. Setup, once:
  1. In Burp: **Settings → Suite → REST API → tick "Service running"** (default `http://127.0.0.1:1337`).
  2. If you create an API key there, set it before starting the scanner (it is never stored):
     - Windows: `$env:BURP_API_KEY = "..."`
     - Mac: `export BURP_API_KEY=...`
  3. In the scanner: **Settings → Burp Suite Professional → Test connection**.

  The Burp scan configuration follows the scan depth:
  - Passive: *Audit checks - passive*
  - Safe: *Audit checks - light active*
  - Active: *Audit checks - all except time-based detection methods*

  You can change these per depth in Settings. Burp scans can take a long time; the scanner waits up to 120 minutes (configurable), then imports what Burp found so far. The task keeps running in Burp's Dashboard. Only Burp Suite **Professional** has this REST API.

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

   You should see 32 lines starting with `ok`. A `skip` line is fine for an optional extra you didn't install.
2. **Fake legacy web app.** In a second terminal, run `.venv/bin/python tests/fake_target.py 8899` (Windows: `.venv\Scripts\python tests\fake_target.py 8899`). Then:
   - add `127.0.0.1` to the scope;
   - start a **Web scan** of `http://127.0.0.1:8899` in **Active** mode.

   Expect about 25 findings: Apache 2.2, PHP 5.6, AngularJS 1.5, jQuery 1.12, an exposed `.git` folder, CORS trusting any site, missing headers, a login form over HTTP, an API description, and more. The **Attack surface** tab should list about 15 endpoints, found from links, `robots.txt`, the sitemap, the OpenAPI document and forms.
3. **Code review:** upload `tests/fixtures/legacyapp.zip`. Expect about 42 findings, including log4j 2.14.1, Struts 2.3 and Django 1.11, plus SQL injection, command injection and XSS in the sample PHP, Java, Node, Python and C# files, each with its URL and parameter.
4. **Burp / HAR:** in **Import**, upload `tests/fixtures/imports/burp-items.xml` or `traffic.har`. Expect Apache 2.2, PHP 5.6, jQuery 1.12 and six header/cookie/CORS findings.
5. **Claude:** in **Settings → AI assist**, click **Test connection**. Then open the code scan from step 3 and press **AI review ✦**. The web scan from step 2 has the same button.
6. **Burp (optional):** with Burp Suite Pro running and its REST API on, **Settings → Burp Suite Professional → Test connection** should say *Connected*.

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
| Browser says "can't reach this page" for 127.0.0.1 | 1) Use **http://127.0.0.1:8765**: the scanner moved from 8080 to 8765. 2) Keep the start window open: if it shows an error or closes, re-run `install-windows.cmd`. 3) Double-click **`diagnose-windows.cmd`**: it checks the install, the port, a proxy-free connection and your proxy bypass list, and says what to fix. 4) If it says the browser sends 127.0.0.1 to the corporate proxy, add `127.0.0.1;localhost` to the proxy exceptions or try `http://localhost:8765`. |
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
| Port 8765 in use | Start with `--port 8766` (Windows: `start-windows.ps1 -Port 8766`). The scanner avoids 8080 on purpose so it doesn't clash with Burp Suite or ZAP. |
