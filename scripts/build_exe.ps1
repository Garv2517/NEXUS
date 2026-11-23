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
.PARAMETER BuildInstaller
    Compiles an Inno Setup 6 Windows desktop installer (e.g. NEXUS-Setup-v1.1.0.exe).
.EXAMPLE
    .\scripts\build_exe.ps1 -Mode onedir -SmokeTest
.EXAMPLE
    .\scripts\build_exe.ps1 -Mode onefile -Clean -SmokeTest
.EXAMPLE
    .\scripts\build_exe.ps1 -BuildInstaller
#>

[CmdletBinding()]
param (
    [ValidateSet("onedir", "onefile")]
    [string]$Mode = "onedir",

    [switch]$Clean,

    [switch]$SmokeTest = $true,

    [switch]$BuildInstaller
)

$ErrorActionPreference = "Stop"
$sw = [System.Diagnostics.Stopwatch]::StartNew()

Write-Host "=====================================================================" -ForegroundColor Cyan
Write-Host " NEXUS STANDALONE EXECUTABLE BUILD PIPELINE" -ForegroundColor Cyan
Write-Host " Target Mode: $Mode | Clean: $Clean | SmokeTest: $SmokeTest | BuildInstaller: $BuildInstaller" -ForegroundColor Cyan
Write-Host "=====================================================================" -ForegroundColor Cyan

# Helper: Locate Inno Setup Compiler
function Get-InnoSetupCompiler {
    # 1. Check PATH
    $cmd = Get-Command "ISCC.exe" -ErrorAction SilentlyContinue
    if ($cmd) { return $cmd.Source }

    # 2. Check standard Program Files (x86)
    if (${env:ProgramFiles(x86)}) {
        $candidate = Join-Path ${env:ProgramFiles(x86)} "Inno Setup 6\ISCC.exe"
        if (Test-Path $candidate) { return $candidate }
    }

    # 3. Check Local AppData (per-user / winget standard)
    if (${env:LOCALAPPDATA}) {
        $candidate = Join-Path ${env:LOCALAPPDATA} "Programs\Inno Setup 6\ISCC.exe"
        if (Test-Path $candidate) { return $candidate }
    }

    # 4. Check standard Program Files (64-bit)
    if ($env:ProgramFiles) {
        $candidate = Join-Path $env:ProgramFiles "Inno Setup 6\ISCC.exe"
        if (Test-Path $candidate) { return $candidate }
    }

    return $null
}

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

$isccPath = $null
if ($BuildInstaller) {
    $isccPath = Get-InnoSetupCompiler
    if (-not $isccPath) {
        Write-Host "`n=====================================================================" -ForegroundColor Yellow
        Write-Host " [!] INNO SETUP 6 COMPILER (ISCC.EXE) NOT DETECTED" -ForegroundColor Yellow
        Write-Host "=====================================================================" -ForegroundColor Yellow
        Write-Host "The -BuildInstaller switch requires Inno Setup 6 to compile the Windows installer." -ForegroundColor Yellow
        Write-Host "`nPlease install Inno Setup 6 by running:" -ForegroundColor White
        Write-Host "  winget install JRSoftware.InnoSetup" -ForegroundColor Cyan
        Write-Host "`nExiting build cleanly." -ForegroundColor Yellow
        Write-Host "=====================================================================" -ForegroundColor Yellow
        exit 0
    }
    Write-Host "[OK] Inno Setup Compiler: $isccPath" -ForegroundColor Green
}

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

# 8. Inno Setup Windows Installer Compilation
$installerPath = $null
$installerSizeMB = 0
if ($BuildInstaller) {
    Write-Host "`n=====================================================================" -ForegroundColor Cyan
    Write-Host " INNO SETUP 6 WINDOWS INSTALLER COMPILATION" -ForegroundColor Cyan
    Write-Host "=====================================================================" -ForegroundColor Cyan

    if (-not $isccPath) {
        $isccPath = Get-InnoSetupCompiler
    }

    if (-not $isccPath) {
        Write-Host "[!] Inno Setup compiler (ISCC.exe) was not found." -ForegroundColor Yellow
        Write-Host "    Install Inno Setup 6 via: winget install JRSoftware.InnoSetup" -ForegroundColor Cyan
        Write-Host "    Exiting installer compilation cleanly." -ForegroundColor Yellow
        exit 0
    }

    $issPath = Join-Path $PSScriptRoot "..\installer\nexus_setup.iss"
    $issPath = [System.IO.Path]::GetFullPath($issPath)

    if (-not (Test-Path $issPath)) {
        Write-Error "Inno Setup script not found at: $issPath"
        exit 1
    }

    Write-Host "[*] Compiling installer: $issPath" -ForegroundColor Cyan
    Write-Host "[*] Compiler: $isccPath" -ForegroundColor Gray
    $installerStart = [System.Diagnostics.Stopwatch]::StartNew()

    & $isccPath $issPath

    if ($LASTEXITCODE -ne 0) {
        Write-Error "Inno Setup compilation failed with exit code $LASTEXITCODE"
        exit $LASTEXITCODE
    }

    $installerStart.Stop()

    $versionPath = Join-Path $PSScriptRoot "..\VERSION"
    $appVersion = if (Test-Path $versionPath) { (Get-Content $versionPath).Trim() } else { "1.1.0" }
    $installerPath = Join-Path $PSScriptRoot "..\dist\installer\NEXUS-Setup-v$appVersion.exe"
    $installerPath = [System.IO.Path]::GetFullPath($installerPath)

    if (-not (Test-Path $installerPath)) {
        Write-Error "Expected installer binary not found at: $installerPath"
        exit 1
    }

    $installerSizeMB = (Get-Item $installerPath).Length / 1MB
    Write-Host "[OK] Inno Setup Installer: $installerPath" -ForegroundColor Green
    Write-Host "[OK] NEXUS-Setup-v$appVersion.exe Size: $($installerSizeMB.ToString('F2')) MB" -ForegroundColor Green
    Write-Host "[OK] Installer compiled in $($installerStart.Elapsed.TotalSeconds.ToString('F2')) seconds." -ForegroundColor Green
}

$sw.Stop()
Write-Host "`n=====================================================================" -ForegroundColor Green
Write-Host " NEXUS BUILD SUCCESSFUL - Total Time: $($sw.Elapsed.TotalSeconds.ToString('F2'))s" -ForegroundColor Green
Write-Host " Binary Ready at: $exePath" -ForegroundColor Green
if ($BuildInstaller -and $installerPath -and (Test-Path $installerPath)) {
    Write-Host " Installer Ready at: $installerPath ($($installerSizeMB.ToString('F2')) MB)" -ForegroundColor Green
}
Write-Host "=====================================================================" -ForegroundColor Green
exit 0
