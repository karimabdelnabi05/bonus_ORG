<#
.SYNOPSIS
    Build script for the Runtime Memory Patcher project (PowerShell alternative to Makefile)
.DESCRIPTION
    Usage:
        .\build.ps1 all          # Build everything
        .\build.ps1 check        # Build check.exe only
        .\build.ps1 patcher      # Build patcher.exe only
        .\build.ps1 tests        # Build test executables
        .\build.ps1 test-check   # Build and run check.exe tests
        .\build.ps1 test-patcher # Build and run patcher tests (check.exe must be running)
        .\build.ps1 clean        # Remove build artifacts
#>

param(
    [Parameter(Position=0)]
    [ValidateSet("all", "check", "patcher", "tests", "test-check", "test-patcher", "clean")]
    [string]$Target = "all"
)

$BuildDir = "build"
$CC = "gcc"
$CFLAGS = "-Wall -Wextra -std=c99"

# Ensure build directory exists
if (-not (Test-Path $BuildDir)) {
    New-Item -ItemType Directory -Path $BuildDir | Out-Null
}

function Build-Check {
    Write-Host "Building check.exe..." -ForegroundColor Cyan
    & $CC $CFLAGS.Split(" ") -o "$BuildDir/check.exe" src/check.c
    if ($LASTEXITCODE -eq 0) { Write-Host "  OK: $BuildDir/check.exe" -ForegroundColor Green }
    else { Write-Host "  FAILED" -ForegroundColor Red; exit 1 }
}

function Build-Patcher {
    Write-Host "Building patcher.exe..." -ForegroundColor Cyan
    & $CC $CFLAGS.Split(" ") -o "$BuildDir/patcher.exe" src/patcher.c src/patcher_lib.c
    if ($LASTEXITCODE -eq 0) { Write-Host "  OK: $BuildDir/patcher.exe" -ForegroundColor Green }
    else { Write-Host "  FAILED" -ForegroundColor Red; exit 1 }
}

function Build-Tests {
    Write-Host "Building test_check.exe..." -ForegroundColor Cyan
    & $CC $CFLAGS.Split(" ") -o "$BuildDir/test_check.exe" tests/test_check.c
    if ($LASTEXITCODE -eq 0) { Write-Host "  OK: $BuildDir/test_check.exe" -ForegroundColor Green }
    else { Write-Host "  FAILED" -ForegroundColor Red; exit 1 }

    Write-Host "Building test_patcher.exe..." -ForegroundColor Cyan
    & $CC $CFLAGS.Split(" ") -I. -o "$BuildDir/test_patcher.exe" tests/test_patcher.c src/patcher_lib.c
    if ($LASTEXITCODE -eq 0) { Write-Host "  OK: $BuildDir/test_patcher.exe" -ForegroundColor Green }
    else { Write-Host "  FAILED" -ForegroundColor Red; exit 1 }
}

switch ($Target) {
    "all" {
        Build-Check
        Build-Patcher
        Build-Tests
    }
    "check" { Build-Check }
    "patcher" { Build-Patcher }
    "tests" { Build-Tests }
    "test-check" {
        Build-Check
        Build-Tests
        Write-Host "`nRunning check.exe integration tests..." -ForegroundColor Yellow
        Push-Location $BuildDir
        & ./test_check.exe
        Pop-Location
    }
    "test-patcher" {
        Build-Patcher
        Build-Tests
        Write-Host "`nRunning patcher tests..." -ForegroundColor Yellow
        Write-Host "NOTE: check.exe must be running in another terminal!" -ForegroundColor Yellow
        Push-Location $BuildDir
        & ./test_patcher.exe
        Pop-Location
    }
    "clean" {
        if (Test-Path $BuildDir) {
            Remove-Item -Recurse -Force $BuildDir
            Write-Host "Cleaned build directory" -ForegroundColor Green
        }
    }
}
