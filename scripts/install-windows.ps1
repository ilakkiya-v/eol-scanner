<#
.SYNOPSIS
  Installs EOL Scanner on Windows (no Docker needed).

.DESCRIPTION
  Creates a Python virtual environment in .venv, installs the requirements, and runs the self-tests.
  Nothing is installed system-wide and no admin rights are needed.

.EXAMPLE
  powershell -ExecutionPolicy Bypass -File scripts\install-windows.ps1
  powershell -ExecutionPolicy Bypass -File scripts\install-windows.ps1 -WithBrowser

.PARAMETER WithBrowser
  Also install Playwright + Chromium for the headless-browser crawl of single-page apps (~150 MB download).

.PARAMETER NoAI
  Skip the Claude SDK (AI assist). The scanner works fully without it.

.PARAMETER SkipTests
  Don't run the self-tests at the end.
#>
param(
    [switch]$WithBrowser,
    [switch]$NoAI,
    [switch]$SkipTests
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root

function Step($msg) { Write-Host ""; Write-Host "==> $msg" -ForegroundColor Cyan }
function Fail($msg) { Write-Host ""; Write-Host "ERROR: $msg" -ForegroundColor Red; exit 1 }

# ---------------------------------------------------------------- find Python 3.9+
Step "Looking for Python 3.9 or newer"
$pyExe = $null
$pyArgs = @()
foreach ($candidate in @("py -3", "python", "python3")) {
    $parts = $candidate -split " "
    $cmd = Get-Command $parts[0] -ErrorAction SilentlyContinue
    if (-not $cmd) { continue }
    if ($cmd.Source -like "*\WindowsApps\*") { continue }   # Microsoft Store placeholder that opens the Store
    $extra = @($parts | Select-Object -Skip 1)
    try {
        $ok = & $parts[0] @extra -c "import sys; print(sys.version_info[:2] >= (3, 9))" 2>$null
    } catch { continue }
    if ("$ok".Trim() -eq "True") { $pyExe = $parts[0]; $pyArgs = $extra; break }
}
if (-not $pyExe) {
    Fail ("Python 3.9+ was not found. Install it from your company software center or https://www.python.org/downloads/ " +
          "(tick 'Add python.exe to PATH'), then open a NEW PowerShell window and run this script again.")
}
$ver = & $pyExe @pyArgs -c "import sys; print('%d.%d.%d' % sys.version_info[:3])"
Write-Host "Using $pyExe $($pyArgs -join ' ') (Python $ver)"

# ---------------------------------------------------------------- virtual environment
Step "Creating virtual environment in .venv"
$venvPy = Join-Path $root ".venv\Scripts\python.exe"
if (-not (Test-Path $venvPy)) {
    & $pyExe @pyArgs -m venv .venv
    if ($LASTEXITCODE -ne 0) { Fail "could not create the virtual environment" }
} else {
    Write-Host ".venv already exists, reusing it"
}

# ---------------------------------------------------------------- packages
if ($env:HTTPS_PROXY) { Write-Host "Using proxy from HTTPS_PROXY: $env:HTTPS_PROXY" }
Step "Installing packages (this takes a minute)"
& $venvPy -m pip install --upgrade pip --disable-pip-version-check -q
$reqs = @("-r", "requirements.txt")
if (-not $NoAI) { $reqs += @("-r", "requirements-llm.txt") }
if ($WithBrowser) { $reqs += @("-r", "requirements-browser.txt") }
& $venvPy -m pip install --disable-pip-version-check -q @reqs
if ($LASTEXITCODE -ne 0) {
    Fail ("pip install failed. Behind a corporate proxy, set it first:  `$env:HTTPS_PROXY = 'http://proxy.corp:8080'  " +
          "and, if your company inspects TLS, point pip at the company CA:  `$env:PIP_CERT = 'C:\path\corp-ca.pem'")
}

if ($WithBrowser) {
    Step "Downloading Chromium for the headless-browser crawl"
    & $venvPy -m playwright install chromium
    if ($LASTEXITCODE -ne 0) {
        Write-Host "Chromium download failed. The scanner still works; the browser option stays unavailable." -ForegroundColor Yellow
        Write-Host "If downloads are blocked, ask IT for a mirror and set PLAYWRIGHT_DOWNLOAD_HOST, then run: .venv\Scripts\python -m playwright install chromium" -ForegroundColor Yellow
    }
}

# ---------------------------------------------------------------- self-test
if (-not $SkipTests) {
    Step "Running self-tests"
    $env:EOLSCAN_DATA = Join-Path $env:TEMP ("eolscan-test-" + [guid]::NewGuid().ToString("N").Substring(0, 8))
    & $venvPy tests\test_core.py
    $testExit = $LASTEXITCODE
    Remove-Item Env:\EOLSCAN_DATA
    if ($testExit -ne 0) { Fail "self-tests failed (see output above)" }
}

Step "Done"
Write-Host "Start the scanner with:" -ForegroundColor Green
Write-Host "  powershell -ExecutionPolicy Bypass -File scripts\start-windows.ps1"
Write-Host "Then open http://127.0.0.1:8080 and add your lab hosts in Settings -> Scope allowlist."
