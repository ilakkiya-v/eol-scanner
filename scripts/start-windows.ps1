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

if (-not $env:EOLSCAN_DATA) {
    if ($root -match "OneDrive") {
        # OneDrive syncs/locks open files, which breaks the SQLite database: keep data on the local disk instead.
        $env:EOLSCAN_DATA = Join-Path $env:LOCALAPPDATA "EOLScanner\data"
        Write-Host "This folder is inside OneDrive, so scan data is stored in $env:EOLSCAN_DATA" -ForegroundColor Yellow
    } else {
        $env:EOLSCAN_DATA = Join-Path $root "data"
    }
}

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

# Catch a broken install (e.g. after `git pull` added a package) before starting, with a clear message.
$ErrorActionPreference = "Continue"   # PowerShell 5.1 would otherwise stop at the first stderr line
& $venvPy -c "import app.main" 2>&1 | ForEach-Object { "$_" } | Out-Host
$loadExit = $LASTEXITCODE
$ErrorActionPreference = "Stop"
if ($loadExit -ne 0) {
    Write-Host ""
    Write-Host "The scanner could not load (see the error above). Re-run the installer, then start again:" -ForegroundColor Red
    Write-Host "  powershell -ExecutionPolicy Bypass -File scripts\install-windows.ps1"
    exit 1
}

$url = "http://127.0.0.1:$Port"
Write-Host ""
Write-Host "EOL Scanner is starting. Open:  $url" -ForegroundColor Green
Write-Host "(data: $env:EOLSCAN_DATA)  Keep this window open; press Ctrl+C to stop." -ForegroundColor Green
Write-Host ""
if (-not $NoBrowser) {
    # Open the browser once the port accepts connections (up to ~60 s). A raw TCP check is used on purpose:
    # Invoke-WebRequest follows the corporate proxy settings and can fail for 127.0.0.1.
    Start-Job -ArgumentList $url, $Port -ScriptBlock {
        param($u, $p)
        for ($i = 0; $i -lt 120; $i++) {
            $c = New-Object System.Net.Sockets.TcpClient
            try { $c.Connect("127.0.0.1", $p); $c.Close(); Start-Process $u; return } catch { Start-Sleep -Milliseconds 500 } finally { $c.Dispose() }
        }
    } | Out-Null
}

& $venvPy -m uvicorn app.main:app --host $bind --port $Port
Write-Host ""
Write-Host "The scanner has stopped. If it stopped right after starting, the reason is in the lines above." -ForegroundColor Yellow
Write-Host "For a full check run:  powershell -ExecutionPolicy Bypass -File scripts\diagnose-windows.ps1" -ForegroundColor Yellow
