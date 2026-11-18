# Installing on Windows

There are two ways to run EOL Scanner on a Windows laptop:

| | Option A: Python (recommended) | Option B: Docker Desktop |
|---|---|---|
| Admin rights | Not needed | Needed (WSL 2 and Docker Desktop) |
| Licence | Free | Docker Desktop needs a paid licence at larger companies |
| Reaches VPN-only lab sites | Yes, directly | Sometimes not: some VPN clients don't route traffic from WSL 2 |
| Setup time | About 5 minutes | About 30 minutes, plus IT approval |

On a corporate laptop, start with **Option A**.

> Use the scanner only on systems you are authorized to test.

---

## Option A: Python

### 1. Install the prerequisites (once)

- **Python 3.10 or newer**, 3.12 recommended. 3.9 also works.
  - Use your company's software center if Python is listed there.
  - Otherwise use https://www.python.org/downloads/windows/. On the first screen, tick **Add python.exe to PATH**. You can choose **Install for current user only**, which doesn't need admin rights.
- **Git for Windows**, to clone the repo. If you can't install Git, download the repo as a ZIP from GitHub (**Code → Download ZIP**) and unzip it.

Check both in a **new** PowerShell window:

```powershell
py -3 --version
git --version
```

If `py` isn't found, try `python --version`. If typing `python` opens the Microsoft Store, see Troubleshooting.

### 2. Get the code

```powershell
cd $HOME\Documents
git clone https://github.com/<owner>/eol-scanner.git
cd eol-scanner
```

Replace `<owner>` with the GitHub account that holds the repo.

### 3. Install

> **Downloaded the ZIP instead of using git?** Windows marks every file in it as "from the internet" and asks *"Do not run / Run once"* before each script. The default answer, **Do not run**, silently stops the scanner. Unblock your copy once: open PowerShell in the `eol-scanner` folder and run:
>
> ```powershell
> Get-ChildItem -Recurse | Unblock-File
> ```
>
> Also prefer a folder outside OneDrive, such as `C:\tools\eol-scanner`. If you keep it in OneDrive, the start script stores scan data in `%LOCALAPPDATA%\EOLScanner` automatically, because OneDrive sync can lock the database.


**Easiest:** double-click **`install-windows.cmd`** in the `eol-scanner` folder.

**Or from PowerShell:**

```powershell
powershell -ExecutionPolicy Bypass -File scripts\install-windows.ps1
```

The script:

1. finds Python;
2. creates a private environment in `.venv` (nothing is installed system-wide);
3. installs the packages;
4. runs the self-tests.

It ends with 30 `ok` lines and **Done**. If the browser crawl isn't installed, one of those lines says `skip` instead, which is fine.

Optional extras:

| Add this | To get |
|---|---|
| `-WithBrowser` | The headless-browser crawl for single-page apps (React, Angular, Vue). It downloads Chromium, about 150 MB. |
| `-NoAI` | Skips the Claude library if you'll never use AI assist. |

Example: `powershell -ExecutionPolicy Bypass -File scripts\install-windows.ps1 -WithBrowser`

**Behind a corporate proxy?** Set the proxy in the same PowerShell window first, then run the install:

```powershell
$env:HTTPS_PROXY = "http://proxy.corp:8080"
$env:PIP_CERT = "C:\certs\corp-ca.pem"     # only if your company inspects TLS
```

### 4. Start it

**Easiest:** double-click **`start-windows.cmd`**. Your browser opens **http://127.0.0.1:8765** once the server is ready.

**Or from PowerShell:**

```powershell
powershell -ExecutionPolicy Bypass -File scripts\start-windows.ps1
```

- Keep the window open while you use it. Press **Ctrl+C** or close the window to stop.
- Other port: add `-Port 8766`.
- Settings and scan history are saved in the `data` folder inside `eol-scanner`.
- Page won't load? Double-click **`diagnose-windows.cmd`**. It changes nothing and tells you what's wrong.

### 5. If scripts are blocked: do it by hand

Some companies block PowerShell scripts with Group Policy. These commands do the same thing:

```powershell
cd $HOME\Documents\eol-scanner
py -3 -m venv .venv
.venv\Scripts\python -m pip install -r requirements.txt -r requirements-llm.txt
.venv\Scripts\python tests\test_core.py
```

Then start it each time with:

```powershell
cd $HOME\Documents\eol-scanner
$env:EOLSCAN_DATA = "$PWD\data"
.venv\Scripts\python -m uvicorn app.main:app --host 127.0.0.1 --port 8765
```

For the browser crawl, also run:

```powershell
.venv\Scripts\python -m pip install -r requirements-browser.txt
.venv\Scripts\python -m playwright install chromium
```

---

## Option B: Docker Desktop

1. Install **Docker Desktop for Windows** with the **WSL 2** backend. This needs admin rights, and usually IT approval and a licence.
2. In the `eol-scanner` folder:

   ```powershell
   docker compose up -d --build
   ```

3. Open **http://127.0.0.1:8765**.

Notes:

- For the browser crawl, set `WITH_BROWSER: "1"` in `docker-compose.yml` before building.
- To scan a lab site, the container must reach the VPN. Some VPN clients (for example Cisco AnyConnect or GlobalProtect in certain modes) don't route traffic from WSL 2. If lab sites time out from Docker but open in your browser, use Option A.
- To test against the fake app on your laptop, start it as described below, then scan `http://host.docker.internal:8899` and add `host.docker.internal` to the scope.

---

## Connect your company's Claude (optional)

The full explanation is in [GETTING_STARTED.md, section 3](GETTING_STARTED.md#3-connect-your-companys-claude-for-the-ai-features). The short version for Windows:

**With your work Claude login (recommended, no API key):**

1. In PowerShell, install Claude Code:

   ```powershell
   irm https://claude.ai/install.ps1 | iex
   ```

   Or use your software center, or `npm install -g @anthropic-ai/claude-code`.
2. Open a **new** PowerShell window and run `claude`. Sign in with your work account, type `/model` to see your models (Mythos if enabled), then `/exit`.
3. In the scanner, go to **Settings → AI assist**:
   - **Provider:** Claude
   - **Connection:** Claude Code
   - Tick **I'm allowed to send source code**
   - Click **Save**, then **Test connection**.

   If it says Claude Code wasn't found, run `where claude` and paste that path into **Claude Code path**.

**With an API key or gateway token:** set it in the PowerShell window **before** starting the scanner. It lasts only for that window, and the app never stores it:

```powershell
$env:ANTHROPIC_API_KEY = "sk-ant-..."          # or $env:ANTHROPIC_AUTH_TOKEN for a gateway
powershell -ExecutionPolicy Bypass -File scripts\start-windows.ps1
```

`start-windows.cmd` opens a new window that doesn't see keys set this way. Start from PowerShell as above when using a key.

**AWS (Bedrock):** run `aws sso login --profile <name>`, then `$env:AWS_PROFILE = "<name>"`.

**Google Cloud (Vertex):** run `gcloud auth application-default login`.

---

## Check it works

1. **Self-tests:**

   ```powershell
   .venv\Scripts\python tests\test_core.py
   ```

   The install script already ran these.

2. **Scan the fake legacy app.** In a second PowerShell window, start it:

   ```powershell
   .venv\Scripts\python tests\fake_target.py 8899
   ```

   Then in the scanner:
   - go to **Settings → Scope allowlist** and add `127.0.0.1`;
   - start a **Web scan** of `http://127.0.0.1:8899` in **Active** mode.

   Expect about 24 findings.
3. **Code review:** upload `tests\fixtures\legacyapp.zip`. Expect about 42 findings.
4. **Import:** upload any file from `tests\fixtures\imports\`.

More detail is in [GETTING_STARTED.md, section 6](GETTING_STARTED.md#6-check-that-it-works).

---

## Updating

```powershell
cd $HOME\Documents\eol-scanner
git pull
powershell -ExecutionPolicy Bypass -File scripts\install-windows.ps1
```

Re-running the install reuses `.venv`, updates the packages and keeps your `data` folder. If you downloaded a ZIP instead, download the new one and copy your old `data` folder into it.

## Uninstalling

1. Delete the `eol-scanner` folder.
2. If you installed the browser crawl, also delete `%LOCALAPPDATA%\ms-playwright`.

Nothing else is installed.

---

## Troubleshooting (Windows)

| Problem | Fix |
|---|---|
| "Security warning … Do not run / Run once" when starting | The files came from a downloaded ZIP. Run `Get-ChildItem -Recurse \| Unblock-File` once in the `eol-scanner` folder (or answer **R**, Run once, each time; the default **D** stops the script). |
| Browser says "can't reach this page" for 127.0.0.1 | 1) Use **http://127.0.0.1:8765**: the scanner moved from 8080 to 8765. 2) Keep the start window open: if it shows an error or closes, re-run `install-windows.cmd`. 3) Double-click **`diagnose-windows.cmd`**: it checks the install, the port, a proxy-free connection and your proxy bypass list, and says what to fix. 4) If it says the browser sends 127.0.0.1 to the corporate proxy, add `127.0.0.1;localhost` to the proxy exceptions or try `http://localhost:8765`. |
| Typing `python` opens the Microsoft Store | That's a placeholder, not Python. Install Python as in step 1, or turn off the placeholder: **Settings → Apps → Advanced app settings → App execution aliases**, then switch off `python.exe` and `python3.exe`. Open a new window afterwards. |
| `py` / `python` is not recognized | Python isn't on PATH. Re-run the Python installer, choose **Modify**, tick **Add Python to environment variables**, then open a new PowerShell window. |
| "running scripts is disabled on this system" | Use the `.cmd` launchers, or the `-ExecutionPolicy Bypass` commands above. If Group Policy blocks even that, use the manual commands in step 5. |
| `pip install` fails with SSL or certificate errors | Your company inspects TLS. Set `$env:PIP_CERT` to the company CA file (ask IT for it in `.pem` format). |
| `pip install` times out | Set `$env:HTTPS_PROXY` (see step 3). |
| Lab site unreachable but opens in the browser | The scanner ignores the system proxy by default. If lab sites must go through a proxy, tick **Route through HTTP(S)_PROXY** in the scan's Advanced section. Check the host is in **Scope**. |
| TLS errors against lab sites | Leave **Verify TLS** off (default) for internal certificates, or set `$env:SSL_CERT_FILE` to the company CA file. |
| Windows Firewall asks about Python | Only happens with `-Share`. Allow it on **Private / Domain** networks only. |
| Antivirus quarantines files under `tests\fixtures` | Those are sample "vulnerable" files used by the self-tests. Restore them or ask IT to exclude the folder. The scanner itself still works; only the self-tests need them. |
| Port 8765 in use | `scripts\start-windows.ps1 -Port 8766` |
| Browser option is greyed out | Install with `-WithBrowser`, or run the two browser commands from step 5. |
| "Chromium is not installed" in the scan log | Run `.venv\Scripts\python -m playwright install chromium`. If downloads are blocked, ask IT for a mirror and set `$env:PLAYWRIGHT_DOWNLOAD_HOST`. |
| Long path errors when unzipping | Clone or unzip to a short path such as `C:\tools\eol-scanner`. |

Share with your team: run `start-windows.ps1 -Share` after setting `$env:EOLSCAN_USER` and `$env:EOLSCAN_PASSWORD`. Teammates then open `http://<your-pc-name>:8765`.
