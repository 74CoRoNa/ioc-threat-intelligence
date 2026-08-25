<#
    Launch the IOC Threat Intelligence Analyzer.

    The script is self-bootstrapping: it locates a suitable Python interpreter,
    creates or repairs the virtual environment, installs dependencies, and then
    serves the application. It is intended to work on a computer that has never
    run this project before.
#>
param(
    [int]$Port = 8000,
    [switch]$NoBrowser,
    [switch]$Reload,
    [switch]$Recreate
)

$ErrorActionPreference = "Stop"
$projectRoot = $PSScriptRoot
$backend = Join-Path $projectRoot "backend"
$venv = Join-Path $projectRoot ".venv"
$venvPython = Join-Path $venv "Scripts\python.exe"
$requirements = Join-Path $backend "requirements.txt"
$url = "http://127.0.0.1:$Port"
$MinimumPython = [Version]"3.10"

function Write-Step($text) { Write-Host "  $text" -ForegroundColor DarkGray }

function Stop-Script($message) {
    Write-Host ""
    Write-Host $message -ForegroundColor Red
    Write-Host ""
    Read-Host "Press Enter to close"
    exit 1
}

function Get-PythonVersion($exe) {
    try {
        $raw = & $exe -c "import sys; print('%d.%d' % sys.version_info[:2])" 2>$null
        if ($LASTEXITCODE -ne 0 -or -not $raw) { return $null }
        return [Version]($raw.Trim())
    } catch { return $null }
}

function Find-BasePython {
    $candidates = New-Object System.Collections.Generic.List[string]

    # The py launcher is the most reliable locator on Windows.
    $launcher = Get-Command py -ErrorAction SilentlyContinue
    if ($launcher) {
        foreach ($tag in @("-3.13", "-3.12", "-3.11", "-3.10", "-3")) {
            try {
                $found = & $launcher.Source $tag -c "import sys; print(sys.executable)" 2>$null
                if ($LASTEXITCODE -eq 0 -and $found) { $candidates.Add($found.Trim()) }
            } catch { }
        }
    }

    foreach ($name in @("python", "python3")) {
        foreach ($command in @(Get-Command $name -All -ErrorAction SilentlyContinue)) {
            # Skip the Microsoft Store alias stub, which is not a real interpreter.
            if ($command.Source -and $command.Source -notlike "*WindowsApps*") {
                $candidates.Add($command.Source)
            }
        }
    }

    $searchRoots = @(
        "$env:LOCALAPPDATA\Programs\Python",
        "$env:ProgramFiles",
        "${env:ProgramFiles(x86)}",
        "C:\"
    )
    foreach ($root in $searchRoots) {
        if (-not $root -or -not (Test-Path -LiteralPath $root)) { continue }
        foreach ($dir in @(Get-ChildItem -LiteralPath $root -Directory -Filter "Python3*" -ErrorAction SilentlyContinue)) {
            $exe = Join-Path $dir.FullName "python.exe"
            if (Test-Path -LiteralPath $exe) { $candidates.Add($exe) }
        }
    }

    foreach ($candidate in ($candidates | Select-Object -Unique)) {
        $version = Get-PythonVersion $candidate
        if ($version -and $version -ge $MinimumPython) {
            return [pscustomobject]@{ Path = $candidate; Version = $version }
        }
    }
    return $null
}

function Test-VenvHealthy {
    # A virtual environment stores an absolute path to the interpreter that
    # built it. If that interpreter is moved, upgraded, or uninstalled - or the
    # project folder was copied from another computer - the environment still
    # exists on disk but cannot run.
    if (-not (Test-Path -LiteralPath $venvPython)) { return $false }
    try {
        & $venvPython -c "import sys" 2>$null | Out-Null
        return $LASTEXITCODE -eq 0
    } catch { return $false }
}

function Test-DependenciesInstalled {
    try {
        & $venvPython -c "import fastapi, uvicorn, httpx, sqlalchemy, dns, pydantic_settings" 2>$null | Out-Null
        return $LASTEXITCODE -eq 0
    } catch { return $false }
}

function Initialize-Environment {
    if ($Recreate -and (Test-Path -LiteralPath $venv)) {
        Write-Step "Removing the existing environment as requested."
        Remove-Item -LiteralPath $venv -Recurse -Force
    }

    if (-not (Test-VenvHealthy)) {
        if (Test-Path -LiteralPath $venv) {
            Write-Step "The existing environment cannot run on this computer; rebuilding it."
            Remove-Item -LiteralPath $venv -Recurse -Force
        }
        $python = Find-BasePython
        if (-not $python) {
            Stop-Script "No suitable Python interpreter was found on this computer.`n`nInstall Python $MinimumPython or newer from https://www.python.org/downloads/`nand tick `"Add python.exe to PATH`" during setup, then run this script again."
        }
        Write-Step "Using Python $($python.Version) at $($python.Path)"
        Write-Step "Creating the virtual environment (first run only)..."
        & $python.Path -m venv $venv
        if ($LASTEXITCODE -ne 0 -or -not (Test-VenvHealthy)) {
            Stop-Script "The virtual environment could not be created using $($python.Path)."
        }
    }

    if (-not (Test-DependenciesInstalled)) {
        Write-Step "Installing dependencies (first run only; this may take a minute)..."
        & $venvPython -m pip install --upgrade pip --quiet --disable-pip-version-check
        & $venvPython -m pip install -r $requirements --quiet --disable-pip-version-check
        if ($LASTEXITCODE -ne 0 -or -not (Test-DependenciesInstalled)) {
            Stop-Script "Dependencies could not be installed.`n`nCheck that this computer has internet access, then run the script again.`nTo install them by hand:`n    .venv\Scripts\python.exe -m pip install -r backend\requirements.txt"
        }
    }
}

function Test-Ready {
    try { return (Invoke-RestMethod -Uri "$url/api/health" -TimeoutSec 1).status -eq "ok" }
    catch { return $false }
}

# --- Preparation ---------------------------------------------------------

Write-Host ""
Write-Host "IOC Threat Intelligence" -ForegroundColor Cyan

if (-not (Test-Path -LiteralPath $requirements)) {
    Stop-Script "This script must stay inside the project folder; backend\requirements.txt was not found."
}
if (-not (Test-Path -LiteralPath (Join-Path $projectRoot ".env"))) {
    Copy-Item -LiteralPath (Join-Path $projectRoot ".env.example") -Destination (Join-Path $projectRoot ".env")
    Write-Step "Created .env from .env.example. Add provider API keys there."
}

Initialize-Environment

# --- Port ----------------------------------------------------------------

if (Test-Ready) {
    Write-Host "  Already running at $url" -ForegroundColor Green
    if (-not $NoBrowser) { Start-Process $url }
    Read-Host "Press Enter to close"
    exit 0
}

$blocking = Get-NetTCPConnection -LocalPort $Port -State Listen -ErrorAction SilentlyContinue
if ($blocking) {
    $owner = Get-Process -Id $blocking[0].OwningProcess -ErrorAction SilentlyContinue
    Write-Host "  Port $Port is held by $($owner.ProcessName) (PID $($owner.Id)) and is not responding." -ForegroundColor Yellow
    if ((Read-Host "  Stop that process and continue? [y/N]") -match '^(y|yes)$') {
        Stop-Process -Id $blocking[0].OwningProcess -Force
        Start-Sleep -Milliseconds 500
    } else {
        Stop-Script "Startup cancelled. Try another port, for example: .\run.ps1 -Port 8080"
    }
}

# --- Serve ---------------------------------------------------------------

$arguments = @("-m", "uvicorn", "app.main:app", "--host", "127.0.0.1", "--port", $Port.ToString())
if ($Reload) { $arguments += "--reload" }

Write-Step "Starting the server on $url ..."
$logPath = Join-Path $projectRoot "server.log"
$server = Start-Process -FilePath $venvPython -ArgumentList $arguments -WorkingDirectory $backend `
    -WindowStyle Hidden -PassThru -RedirectStandardError $logPath

try {
    $ready = $false
    for ($attempt = 0; $attempt -lt 100; $attempt++) {
        if ($server.HasExited) {
            $reason = "no output captured"
            if (Test-Path -LiteralPath $logPath) { $reason = (Get-Content -LiteralPath $logPath -Tail 15) -join "`n" }
            Stop-Script "The backend stopped during startup.`n`n$reason"
        }
        if (Test-Ready) { $ready = $true; break }
        Start-Sleep -Milliseconds 200
    }
    if (-not $ready) { Stop-Script "The application did not become ready in time. See $logPath" }

    Write-Host ""
    Write-Host "  Running at $url" -ForegroundColor Green
    Write-Host ""
    if (-not $NoBrowser) { Start-Process $url }
    Write-Host "  Press Ctrl+C to stop." -ForegroundColor DarkGray
    Wait-Process -Id $server.Id
}
finally {
    if ($server -and -not $server.HasExited) { Stop-Process -Id $server.Id -Force }
}
