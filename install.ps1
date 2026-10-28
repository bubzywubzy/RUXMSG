[CmdletBinding()]
param(
    [string]$InstallDir
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$AppName = 'RUXMSG'
$BinaryName = 'ruxmsg.exe'
$ScriptDir = $PSScriptRoot
$ManifestPath = Join-Path $ScriptDir 'Cargo.toml'
$LockPath = Join-Path $ScriptDir 'Cargo.lock'
$TargetDir = Join-Path $ScriptDir 'target'

if ([string]::IsNullOrWhiteSpace($InstallDir)) {
    if (-not [string]::IsNullOrWhiteSpace($env:RUXMSG_INSTALL_DIR)) {
        $InstallDir = $env:RUXMSG_INSTALL_DIR
    }
    else {
        $InstallDir = Join-Path $env:LOCALAPPDATA 'Programs\RUXMSG'
    }
}

$InstallDir = [System.IO.Path]::GetFullPath($InstallDir)
$Destination = Join-Path $InstallDir $BinaryName

$StagedBinary = $null
$BackupBinary = $null

# ---------- Presentation ----------

function Write-Info {
    param([string]$Message)
    Write-Host "==> $Message" -ForegroundColor Cyan
}

function Write-Success {
    param([string]$Message)
    Write-Host "[OK] $Message" -ForegroundColor Green
}

function Write-Warn {
    param([string]$Message)
    Write-Warning $Message
}

function Stop-Install {
    param([string]$Message)
    throw $Message
}

function Write-Banner {
    Write-Host ''
    Write-Host '██████╗  ██╗   ██╗ ██╗  ██╗ ███╗   ███╗ ███████╗  ██████╗' -ForegroundColor Cyan
    Write-Host '██╔══██╗ ██║   ██║ ╚██╗██╔╝ ████╗ ████║ ██╔════╝ ██╔════╝' -ForegroundColor Cyan
    Write-Host '██████╔╝ ██║   ██║  ╚███╔╝  ██╔████╔██║ ███████╗ ██║  ███╗' -ForegroundColor Cyan
    Write-Host '██╔══██╗ ██║   ██║  ██╔██╗  ██║╚██╔╝██║ ╚════██║ ██║   ██║' -ForegroundColor Cyan
    Write-Host '██║  ██║ ╚██████╔╝ ██╔╝ ██╗ ██║ ╚═╝ ██║ ███████║ ╚██████╔╝' -ForegroundColor Cyan
    Write-Host '╚═╝  ╚═╝  ╚═════╝  ╚═╝  ╚═╝ ╚═╝     ╚═╝ ╚══════╝  ╚═════╝' -ForegroundColor Cyan
    Write-Host ''
    Write-Host '  Encrypted peer-to-peer messaging' -ForegroundColor DarkGray
    Write-Host '  Windows release build and installation' -ForegroundColor DarkGray
    Write-Host ''
}

# ---------- Cleanup ----------

function Remove-StagingFiles {
    foreach ($Path in @($StagedBinary, $BackupBinary)) {
        if (-not [string]::IsNullOrWhiteSpace($Path) -and
            (Test-Path -LiteralPath $Path)) {
            try {
                Remove-Item -LiteralPath $Path -Force
            }
            catch {
                Write-Warn "Could not clean up temporary file: $Path"
            }
        }
    }
}

# ---------- Validation ----------

Write-Banner

if (-not (Test-Path -LiteralPath $ManifestPath -PathType Leaf)) {
    Stop-Install 'Cargo.toml was not found. Save this script in the RUXMSG repository root.'
}

if (-not (Test-Path -LiteralPath $LockPath -PathType Leaf)) {
    Stop-Install 'Cargo.lock is missing. Commit the lockfile before installing.'
}

foreach ($Command in @('cargo', 'rustc')) {
    if (-not (Get-Command $Command -ErrorAction SilentlyContinue)) {
        Stop-Install "$Command is not installed or is not available on PATH."
    }
}

$InstallRoot = [System.IO.Path]::GetPathRoot($InstallDir)

if ([string]::Equals(
    $InstallDir.TrimEnd('\', '/'),
    $InstallRoot.TrimEnd('\', '/'),
    [System.StringComparison]::OrdinalIgnoreCase
)) {
    Stop-Install "Refusing to use a filesystem root as the installation directory."
}

# Determine the host target. This avoids accidental cross-compilation.
$RustInfo = & rustc -vV
if ($LASTEXITCODE -ne 0) {
    Stop-Install 'Could not query rustc.'
}

$HostLine = $RustInfo |
    Select-String -Pattern '^host:\s*(.+)$' |
    Select-Object -First 1

if ($null -eq $HostLine) {
    Stop-Install 'Could not determine the Rust host target.'
}

$HostTarget = $HostLine.Matches[0].Groups[1].Value.Trim()
$BinaryPath = Join-Path $TargetDir "$HostTarget\release\$BinaryName"

Write-Info "Preparing $AppName release"
Write-Host "  Repository : $ScriptDir"
Write-Host "  Target     : $HostTarget"
Write-Host "  Compiler   : $(& rustc --version)"
Write-Host "  Cargo      : $(& cargo --version)"
Write-Host "  Destination: $Destination"
Write-Host ''

# ---------- Build ----------

Write-Info 'Building optimized release executable'

$BuildArgs = @(
    'build'
    '--release'
    '--locked'
    '--bin'
    'ruxmsg'
    '--target'
    $HostTarget
    '--target-dir'
    $TargetDir
    '--manifest-path'
    $ManifestPath
)

& cargo @BuildArgs

if ($LASTEXITCODE -ne 0) {
    Stop-Install "Cargo build failed with exit code $LASTEXITCODE."
}

if (-not (Test-Path -LiteralPath $BinaryPath -PathType Leaf)) {
    Stop-Install "Expected executable was not produced: $BinaryPath"
}

Write-Success 'Release build completed'

# ---------- Installation ----------

Write-Info 'Preparing installation directory'

if (-not (Test-Path -LiteralPath $InstallDir -PathType Container)) {
    New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
}

if (-not (Test-Path -LiteralPath $InstallDir -PathType Container)) {
    Stop-Install "Installation destination is not a directory: $InstallDir"
}

try {
    # Stage beside the destination so replacement occurs on the same volume.
    $StagedBinary = Join-Path $InstallDir (
        '.ruxmsg.' + [Guid]::NewGuid().ToString('N') + '.tmp'
    )

    [System.IO.File]::Copy($BinaryPath, $StagedBinary, $false)

    if (Test-Path -LiteralPath $Destination) {
        # File.Replace preserves the previous executable if replacement fails.
        # A running executable or restrictive permissions can prevent replacement.
        $BackupBinary = Join-Path $InstallDir (
            '.ruxmsg.backup.' + [Guid]::NewGuid().ToString('N') + '.tmp'
        )

        Write-Info 'Replacing existing executable'
        [System.IO.File]::Replace(
            $StagedBinary,
            $Destination,
            $BackupBinary,
            $true
        )

        $StagedBinary = $null

        # Do not fail the installation just because backup cleanup fails.
        try {
            if (Test-Path -LiteralPath $BackupBinary) {
                Remove-Item -LiteralPath $BackupBinary -Force
            }
            $BackupBinary = $null
        }
        catch {
            Write-Warn "The new executable was installed, but the backup remains at: $BackupBinary"
            $BackupBinary = $null
        }
    }
    else {
        Move-Item -LiteralPath $StagedBinary -Destination $Destination
        $StagedBinary = $null
    }
}
finally {
    Remove-StagingFiles
}

# ---------- Verification ----------

if (-not (Test-Path -LiteralPath $Destination -PathType Leaf)) {
    Stop-Install "Installation verification failed: $Destination"
}

Write-Host ''
Write-Success "$AppName installed successfully"
Write-Host ''
Write-Host "  Executable : $Destination"
Write-Host "  Target     : $HostTarget"
Write-Host "  Configuration: managed separately by RUXMSG"
Write-Host "  Credentials  : Windows credential store"
Write-Host ''
Write-Host "  Run    : & '$Destination'"
Write-Host "  Verify : & '$Destination' --help"
Write-Host ''
Write-Host 'The installer does not remove or modify user configuration or credentials.'