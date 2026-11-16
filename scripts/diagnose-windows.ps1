<#
.SYNOPSIS
  Checks why EOL Scanner can't be reached on this Windows machine and says what to do.

.EXAMPLE
  powershell -ExecutionPolicy Bypass -File scripts\diagnose-windows.ps1
  powershell -ExecutionPolicy Bypass -File scripts\diagnose-windows.ps1 -Port 8766

  Read-only: it starts nothing and changes nothing. Copy the output if you need help.
#>
param([int]$Port = 8765)

$ErrorActionPreference = "Continue"
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root
$problems = @()

function Ok($m)   { Write-Host "  [ok]   $m" -ForegroundColor Green }
function Bad($m)  { Write-Host "  [FAIL] $m" -ForegroundColor Red }
function Info($m) { Write-Host "  [info] $m" }

Write-Host "EOL Scanner diagnostics  (folder: $root)" -ForegroundColor Cyan
Write-Host "Windows PowerShell $($PSVersionTable.PSVersion)"

# 1. install ---------------------------------------------------------------
Write-Host "`n1. Installation"
$venvPy = Join-Path $root ".venv\Scripts\python.exe"
if (Test-Path $venvPy) {
    $ver = & $venvPy -c "import sys; print('%d.%d.%d' % sys.version_info[:3])" 2>$null
    Ok "virtual environment found (Python $ver)"
    $load = & $venvPy -c "import app.main; print('loaded')" 2>&1 | ForEach-Object { "$_" }
    if (($load -join "`n") -match "loaded") { Ok "the scanner code loads" }
    else {
        Bad "the scanner code does not load:"
        $load | Select-Object -Last 6 | ForEach-Object { Write-Host "         $_" }
        $problems += "Re-run the installer: powershell -ExecutionPolicy Bypass -File scripts\install-windows.ps1"
    }
} else {
    Bad "not installed (.venv is missing)"
    $problems += "Run the installer first: double-click install-windows.cmd"
}

# 1b. downloaded-file block and OneDrive ----------------------------------------
$blocked = @(Get-ChildItem -Path (Join-Path $root "scripts"), $root -Filter "*.*" -File -ErrorAction SilentlyContinue |
    Where-Object { Get-Item -LiteralPath $_.FullName -Stream Zone.Identifier -ErrorAction SilentlyContinue })
if ($blocked.Count) {
    Bad "$($blocked.Count) script(s) are marked as downloaded from the internet, so Windows asks 'Do not run / Run once' (default: Do not run)"
    $problems += "Unblock the folder once (your own download): open PowerShell in this folder and run:  Get-ChildItem -Recurse | Unblock-File   - then start again"
} else { Ok "scripts are not blocked" }
if ($root -match "OneDrive") {
    Info "the folder is inside OneDrive; scan data is kept in $env:LOCALAPPDATA\EOLScanner instead (OneDrive sync can lock the database)"
}

# 2. is something listening ---------------------------------------------------
Write-Host "`n2. Ports"
foreach ($p in @($Port, 8080)) {
    $l = Get-NetTCPConnection -LocalPort $p -State Listen -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($l) {
        $proc = Get-Process -Id $l.OwningProcess -ErrorAction SilentlyContinue
        $name = if ($proc) { $proc.ProcessName } else { "pid $($l.OwningProcess)" }
        $addr = $l.LocalAddress
        if ($p -eq $Port) { Ok "port $p is in use by '$name' on $addr" } else { Info "port $p is in use by '$name' (probably Burp Suite / ZAP; the scanner no longer uses 8080)" }
        if ($p -eq $Port -and $name -notmatch "python") {
            $problems += "Port $Port is taken by '$name'. Start the scanner on another port: scripts\start-windows.ps1 -Port 8766, then open http://127.0.0.1:8766"
        }
    } elseif ($p -eq $Port) {
        Bad "nothing is listening on port ${Port} - the scanner is not running"
        $problems += "Start it with start-windows.cmd and keep that window open. If the window shows an error and closes, copy the error."
    }
}

# 3. does it answer (bypassing any proxy) -------------------------------------
Write-Host "`n3. Connection test (no proxy)"
try {
    $req = [System.Net.HttpWebRequest]::Create("http://127.0.0.1:$Port/api/health")
    $req.Proxy = $null
    $req.Timeout = 4000
    $resp = $req.GetResponse()
    $code = [int]$resp.StatusCode
    $resp.Close()
    Ok "http://127.0.0.1:$Port answered (HTTP $code)"
    $answered = $true
} catch {
    $msg = $_.Exception.Message
    if ($msg -match "401") { Ok "the scanner answered (it asks for a login: EOLSCAN_USER / EOLSCAN_PASSWORD are set)"; $answered = $true }
    else { Bad "no answer from http://127.0.0.1:$Port ($msg)"; $answered = $false }
}

# 4. proxy settings that can break 127.0.0.1 in browsers -----------------------
Write-Host "`n4. Proxy settings"
$ie = Get-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings" -ErrorAction SilentlyContinue
if ($ie -and $ie.ProxyEnable -eq 1) {
    Info "system proxy: $($ie.ProxyServer)   bypass list: $($ie.ProxyOverride)"
    if ($ie.ProxyOverride -notmatch "<local>|127\.0\.0\.1|localhost") {
        Bad "127.0.0.1 is not in the proxy bypass list"
        if ($answered) { $problems += "The scanner runs, but your browser sends 127.0.0.1 to the corporate proxy. Add 127.0.0.1 and localhost to the proxy bypass list (Settings > Network > Proxy > 'Use the proxy server except for...'), or ask IT." }
    } else { Ok "local addresses bypass the proxy" }
} elseif ($ie -and $ie.AutoConfigURL) {
    Info "proxy auto-config (PAC): $($ie.AutoConfigURL)  - normally bypasses 127.0.0.1"
} else { Ok "no system proxy" }
if ($env:HTTP_PROXY -or $env:HTTPS_PROXY) { Info "HTTP(S)_PROXY is set in this window: $env:HTTPS_PROXY $env:HTTP_PROXY" }

# summary --------------------------------------------------------------------
Write-Host "`nResult" -ForegroundColor Cyan
if ($answered -and -not $problems) {
    Write-Host "  The scanner is running. Open http://127.0.0.1:$Port in your browser (not :8080)." -ForegroundColor Green
    Write-Host "  If the browser still can't reach it, try http://localhost:$Port, another browser, or an InPrivate window."
} elseif ($problems) {
    $i = 1
    foreach ($p in ($problems | Select-Object -Unique)) { Write-Host "  $i. $p" -ForegroundColor Yellow; $i++ }
} else {
    Write-Host "  Start the scanner (start-windows.cmd), wait for 'Uvicorn running on http://127.0.0.1:$Port', then run this check again." -ForegroundColor Yellow
}
