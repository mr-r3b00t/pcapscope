<#
.SYNOPSIS
    Launch the pcapscope web dashboard (token-authenticated).

.DESCRIPTION
    Finds Python, runs `pcapscope.py serve` from this folder, prints the
    token-protected URL, and opens it in your browser. Runs in the foreground -
    press Ctrl-C to stop.

.EXAMPLE
    .\start-dashboard.ps1
    .\start-dashboard.ps1 -Port 9000 -Dir C:\captures
    .\start-dashboard.ps1 -Token mysecret -NoBrowser

    If PowerShell blocks the script ("running scripts is disabled"), run:
        powershell -ExecutionPolicy Bypass -File .\start-dashboard.ps1
#>
[CmdletBinding()]
param(
    [int]$Port = 8090,
    [string]$Dir,
    [string]$Token,
    [string]$Hashcat,
    [string]$WordlistDir,
    [string]$BindHost = "127.0.0.1",
    [string]$Open,                     # capture file to open on start
    [switch]$NoBrowser
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
if (-not $Dir) { $Dir = $root }

# locate a Python interpreter
$py = $null
foreach ($c in @("python", "py", "python3")) {
    $cmd = Get-Command $c -ErrorAction SilentlyContinue
    if ($cmd) { $py = $cmd.Source; break }
}
if (-not $py) {
    Write-Host "[x] Python was not found on PATH. Install Python 3 and try again." -ForegroundColor Red
    exit 1
}

$entry = Join-Path $root "pcapscope.py"
if (-not (Test-Path $entry)) {
    Write-Host "[x] pcapscope.py not found next to this script ($root)." -ForegroundColor Red
    exit 1
}

# build the argument list (-u = unbuffered, so the token URL prints immediately)
$argv = @("-u", $entry, "serve", "--host", $BindHost, "--port", $Port, "--dir", $Dir)
if ($Token)       { $argv += @("--token", $Token) }
if ($Hashcat)     { $argv += @("--hashcat", $Hashcat) }
if ($WordlistDir) { $argv += @("--wordlist-dir", $WordlistDir) }
if ($Open)        { $argv += @($Open) }
if ($NoBrowser)   { $argv += @("--no-browser") }

Write-Host ""
Write-Host "  pcapscope dashboard" -ForegroundColor Cyan
Write-Host "  captures : $Dir" -ForegroundColor DarkGray
Write-Host "  python   : $py" -ForegroundColor DarkGray
Write-Host "  the access URL with the token prints below; Ctrl-C to stop." -ForegroundColor DarkGray
Write-Host ""

& $py @argv
exit $LASTEXITCODE
