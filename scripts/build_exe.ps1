<#
.SYNOPSIS
    NEXUS Standalone Desktop Executable Build Script
.DESCRIPTION
    Compiles the NEXUS Autonomous Data Pipeline & Analytics Engine into a standalone
    Windows desktop executable using PyInstaller with bloat exclusion, Tcl/Tk asset
    bundling, and post-build verification.
.PARAMETER Mode
    Compilation mode: 'onedir' (default, fast-startup) or 'onefile' (single portable .exe).
.PARAMETER Clean
    Purges existing 'build' and 'dist' artifacts prior to compilation.
.PARAMETER SmokeTest
    Immediately executes the compiled binary with '--smoke-test' to verify runtime integrity.
.EXAMPLE
    .\scripts\build_exe.ps1 -Mode onedir -SmokeTest
.EXAMPLE
    .\scripts\build_exe.ps1 -Mode onefile -Clean -SmokeTest
#>

[CmdletBinding()]
param (
    [ValidateSet("onedir", "onefile")]
    [string]$Mode = "onedir",

    [switch]$Clean,

    [switch]$SmokeTest = $true
)

$ErrorActionPreference = "Stop"
$sw = [System.Diagnostics.Stopwatch]::StartNew()

Write-Host "=====================================================================" -ForegroundColor Cyan
Write-Host " NEXUS STANDALONE EXECUTABLE BUILD PIPELINE" -ForegroundColor Cyan
Write-Host " Target Mode: $Mode | Clean: $Clean | SmokeTest: $SmokeTest" -ForegroundColor Cyan
Write-Host "=====================================================================" -ForegroundColor Cyan

# 1. Verify Prerequisites
$pythonCmd = "python"
try {
    $pythonVer = & $pythonCmd --version 2>&1
    Write-Host "[OK] Python Environment: $pythonVer" -ForegroundColor Green
} catch {
    Write-Error "Python is not detected on PATH. Aborting build."
    exit 1
}

$pyinstallerCheck = & $pythonCmd -m PyInstaller --version 2>$null
if ($LASTEXITCODE -ne 0) {
    Write-Host "[!] PyInstaller not found. Installing pyinstaller..." -ForegroundColor Yellow
    & $pythonCmd -m pip install pyinstaller
    $pyinstallerCheck = & $pythonCmd -m PyInstaller --version
}
Write-Host "[OK] PyInstaller Version: $pyinstallerCheck" -ForegroundColor Green

# 2. Clean Workspace if requested
if ($Clean) {
    Write-Host "[*] Purging legacy build artifacts..." -ForegroundColor Yellow
    if (Test-Path "build") { Remove-Item -Path "build" -Recurse -Force }
    if (Test-Path "dist") { Remove-Item -Path "dist" -Recurse -Force }
    Write-Host "[OK] Workspace clean complete." -ForegroundColor Green
}

# 3. Configure Build Mode Environment Variable
$env:NEXUS_BUILD_MODE = $Mode

# 4. Execute PyInstaller Compilation
Write-Host "[*] Launching PyInstaller build with nexus.spec (Mode: $Mode)..." -ForegroundColor Cyan
$buildStart = [System.Diagnostics.Stopwatch]::StartNew()

& $pythonCmd -m PyInstaller nexus.spec --noconfirm

if ($LASTEXITCODE -ne 0) {
    Write-Error "PyInstaller compilation failed with exit code $LASTEXITCODE"
    exit $LASTEXITCODE
}

$buildStart.Stop()
Write-Host "[OK] PyInstaller compilation completed in $($buildStart.Elapsed.TotalSeconds.ToString('F2')) seconds." -ForegroundColor Green

# 5. Resolve Output Binary Location
$exePath = if ($Mode -eq "onefile") {
    Join-Path $PSScriptRoot "..\dist\NEXUS.exe"
} else {
    Join-Path $PSScriptRoot "..\dist\NEXUS\NEXUS.exe"
}
$exePath = [System.IO.Path]::GetFullPath($exePath)

if (-not (Test-Path $exePath)) {
    Write-Error "Expected binary not found at: $exePath"
    exit 1
}

# 6. Measure Artifact Size
if ($Mode -eq "onefile") {
    $fileSizeMB = (Get-Item $exePath).Length / 1MB
    Write-Host "[OK] Standalone Executable: $exePath" -ForegroundColor Green
    Write-Host "[OK] Executable Size: $($fileSizeMB.ToString('F2')) MB" -ForegroundColor Green
} else {
    $dirPath = Split-Path -Parent $exePath
    $dirSizeMB = (Get-ChildItem -Path $dirPath -Recurse | Measure-Object -Property Length -Sum).Sum / 1MB
    $exeSizeMB = (Get-Item $exePath).Length / 1MB
    Write-Host "[OK] Executable Root: $dirPath" -ForegroundColor Green
    Write-Host "[OK] NEXUS.exe Size: $($exeSizeMB.ToString('F2')) MB" -ForegroundColor Green
    Write-Host "[OK] Total Bundle Size: $($dirSizeMB.ToString('F2')) MB" -ForegroundColor Green
}

# 7. Post-Build Smoke Test Verification
if ($SmokeTest) {
    Write-Host "`n[*] Running automated binary startup smoke test..." -ForegroundColor Cyan
    $smokeStart = [System.Diagnostics.Stopwatch]::StartNew()
    
    $smokeOutput = & $exePath --smoke-test 2>&1 | Out-String
    $smokeExitCode = $LASTEXITCODE
    $smokeStart.Stop()

    Write-Host "Smoke Test Execution Output:" -ForegroundColor Gray
    $smokeOutput | ForEach-Object { Write-Host "  $_" -ForegroundColor Gray }

    if ($smokeExitCode -eq 0 -and ($smokeOutput -match "NEXUS_SMOKE_TEST_OK")) {
        Write-Host "[PASS] Binary smoke test validated in $($smokeStart.Elapsed.TotalSeconds.ToString('F2'))s (Code: 0, Token: NEXUS_SMOKE_TEST_OK)" -ForegroundColor Green
    } else {
        Write-Error "Binary smoke test FAILED (Exit Code: $smokeExitCode). Expected token 'NEXUS_SMOKE_TEST_OK'."
        exit 1
    }
}

$sw.Stop()
Write-Host "`n=====================================================================" -ForegroundColor Green
Write-Host " NEXUS BUILD SUCCESSFUL - Total Time: $($sw.Elapsed.TotalSeconds.ToString('F2'))s" -ForegroundColor Green
Write-Host " Binary Ready at: $exePath" -ForegroundColor Green
Write-Host "=====================================================================" -ForegroundColor Green
exit 0
