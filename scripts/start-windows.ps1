<#
.SYNOPSIS
  Starts EOL Scanner on Windows and opens it in your browser.

.EXAMPLE
  powershell -ExecutionPolicy Bypass -File scripts\start-windows.ps1
  powershell -ExecutionPolicy Bypass -File scripts\start-windows.ps1 -Port 8766

.PARAMETER Port
  Port to listen on (default 8765; 8080 is avoided because Burp Suite and ZAP proxies use it).

.PARAMETER Share
  Listen on all network interfaces so teammates can reach it. Requires EOLSCAN_USER and EOLSCAN_PASSWORD
  to be set (HTTP basic auth). By default it only listens on 127.0.0.1 (this machine).

.PARAMETER NoBrowser
  Don't open the browser automatically.

  Stop the scanner with Ctrl+C. Data (settings, scan history) is kept in the .\data folder unless
  EOLSCAN_DATA points somewhere else. Put API keys in environment variables before starting, for example
    $env:ANTHROPIC_API_KEY = "sk-ant-..."
#>
param(
    [int]$Port = 8765,
    [switch]$Share,
    [switch]$NoBrowser
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root

$venvPy = Join-Path $root ".venv\Scripts\python.exe"
if (-not (Test-Path $venvPy)) {
    Write-Host "Not installed yet. Run first:  powershell -ExecutionPolicy Bypass -File scripts\install-windows.ps1" -ForegroundColor Red
    exit 1
}

if (-not $env:EOLSCAN_DATA) { $env:EOLSCAN_DATA = Join-Path $root "data" }

$bind = "127.0.0.1"
if ($Share) {
    if (-not $env:EOLSCAN_USER -or -not $env:EOLSCAN_PASSWORD) {
        Write-Host "-Share needs a login. Set it first, e.g.:" -ForegroundColor Red
        Write-Host '  $env:EOLSCAN_USER = "team"; $env:EOLSCAN_PASSWORD = "<a long random password>"'
        exit 1
    }
    $bind = "0.0.0.0"
    Write-Host "Sharing on all interfaces with basic auth. Windows Firewall may ask to allow Python." -ForegroundColor Yellow
}

$busy = Get-NetTCPConnection -LocalPort $Port -State Listen -ErrorAction SilentlyContinue
if ($busy) {
    Write-Host "Port $Port is already in use (another app, or EOL Scanner is already running). Use another one:  scripts\start-windows.ps1 -Port 8766" -ForegroundColor Red
    exit 1
}

$url = "http://127.0.0.1:$Port"
Write-Host "EOL Scanner starting on $url  (data: $env:EOLSCAN_DATA)  - press Ctrl+C to stop" -ForegroundColor Green
if (-not $NoBrowser) {
    # Open the browser once the server answers (up to ~20 s).
    Start-Job -ArgumentList $url -ScriptBlock {
        param($u)
        for ($i = 0; $i -lt 40; $i++) {
            try { Invoke-WebRequest -UseBasicParsing -TimeoutSec 1 "$u/api/health" | Out-Null; Start-Process $u; break }
            catch { Start-Sleep -Milliseconds 500 }
        }
    } | Out-Null
}

& $venvPy -m uvicorn app.main:app --host $bind --port $Port
