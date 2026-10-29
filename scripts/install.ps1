
[CmdletBinding()]
param(
    [string]$InstallDir,

    [switch]$Check,

    [switch]$DryRun,

    [switch]$Help
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$AppName = 'RUXMSG'
$BinaryName = 'ruxmsg.exe'
$ScriptDir = $PSScriptRoot
$RepoRoot = Split-Path -Parent $ScriptDir
$ManifestPath = Join-Path $RepoRoot 'Cargo.toml'
$LockPath = Join-Path $RepoRoot 'Cargo.lock'
$TargetDir = Join-Path $RepoRoot 'target'

if ([string]::IsNullOrWhiteSpace($InstallDir)) {
    if ($Help) {
        $InstallDir = [System.IO.Path]::GetTempPath()
    }
    elseif (-not [string]::IsNullOrWhiteSpace($env:RUXMSG_INSTALL_DIR)) {
        $InstallDir = $env:RUXMSG_INSTALL_DIR
    }
    else {
        if ([string]::IsNullOrWhiteSpace($env:LOCALAPPDATA)) {
            throw 'LOCALAPPDATA is not set. Specify -InstallDir explicitly.'
        }

        $InstallDir = Join-Path $env:LOCALAPPDATA 'Programs\RUXMSG'
    }
}

$InstallDir = [System.IO.Path]::GetFullPath($InstallDir)
$Destination = Join-Path $InstallDir $BinaryName
$StagedBinary = $null
$BackupBinary = $null

function Show-Help {
        @'
Usage:
    .\scripts\install.ps1 [-InstallDir <path>] [-Check | -DryRun | -Help]

Build and install RUXMSG from this checkout using Cargo --locked.

Options:
    -InstallDir <path>  Installation directory.
    -Check              Validate prerequisites and paths without building/changing files.
    -DryRun             Show build/install actions without changing files.
    -Help               Show this help.

Environment:
    RUXMSG_INSTALL_DIR  Installation-directory override (used if -InstallDir is absent).

The installation directory is not added to PATH automatically.
'@ | Write-Host
}

function Write-Info {
    param([Parameter(Mandatory)][string]$Message)
    Write-Host "==> $Message" -ForegroundColor Cyan
}

function Write-Success {
    param([Parameter(Mandatory)][string]$Message)
    Write-Host "[OK] $Message" -ForegroundColor Green
}

function Write-Warn {
    param([Parameter(Mandatory)][string]$Message)
    Write-Warning $Message
}

function Stop-Install {
    param([Parameter(Mandatory)][string]$Message)
    throw $Message
}

function Test-NoReparsePath {
    param([Parameter(Mandatory)][string]$Path)

    $FullPath = [System.IO.Path]::GetFullPath($Path)
    $Root = [System.IO.Path]::GetPathRoot($FullPath)
    $Current = $Root
    $Relative = $FullPath.Substring($Root.Length)

    foreach ($Component in ($Relative -split '[\\/]')) {
        if ([string]::IsNullOrWhiteSpace($Component)) {
            continue
        }

        $Current = Join-Path $Current $Component
        if (Test-Path -LiteralPath $Current) {
            $Item = Get-Item -LiteralPath $Current -Force
            if (($Item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
                Stop-Install "Refusing an installation path containing a reparse point: $Current"
            }
        }
    }
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

function Remove-StagingFiles {
    if (-not [string]::IsNullOrWhiteSpace($StagedBinary) -and
        (Test-Path -LiteralPath $StagedBinary -PathType Leaf)) {
        try {
            Remove-Item -LiteralPath $StagedBinary -Force
        }
        catch {
            Write-Warn "Could not clean up temporary file: $StagedBinary"
        }
    }

    if (-not [string]::IsNullOrWhiteSpace($BackupBinary) -and
        (Test-Path -LiteralPath $BackupBinary -PathType Leaf)) {
        Write-Warn "A recovery backup was retained at: $BackupBinary"
    }
}

try {
    if ($Help) {
        Show-Help
        exit 0
    }

    if ($Check -and $DryRun) {
        Stop-Install 'Choose either -Check or -DryRun, not both.'
    }

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

    $TrimChars = [char[]]@('\', '/')
    $InstallRoot = [System.IO.Path]::GetPathRoot($InstallDir)

    if ([string]::Equals(
        $InstallDir.TrimEnd($TrimChars),
        $InstallRoot.TrimEnd($TrimChars),
        [System.StringComparison]::OrdinalIgnoreCase
    )) {
        Stop-Install 'Refusing to use a filesystem root as the installation directory.'
    }

    if (Test-Path -LiteralPath $InstallDir -PathType Leaf) {
        Stop-Install "Installation path is a file, not a directory: $InstallDir"
    }

    Test-NoReparsePath -Path $InstallDir

    # Determine the host target to avoid accidental cross-compilation.
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
    $BinaryPath = Join-Path $TargetDir (
        Join-Path $HostTarget (Join-Path 'release' $BinaryName)
    )

    if (Test-Path -LiteralPath $Destination) {
        $Existing = Get-Item -LiteralPath $Destination -Force

        if ($Existing -isnot [System.IO.FileInfo] -or
            (($Existing.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0)) {
            Stop-Install "Refusing to replace a non-regular file or reparse point: $Destination"
        }
    }

    if ($Check) {
        Write-Success 'Prerequisites and paths are valid'
        Write-Host "  Repository : $RepoRoot"
        Write-Host "  Target     : $HostTarget"
        Write-Host "  Destination: $Destination"
        Write-Host "  Cargo.lock : $LockPath"
        exit 0
    }

    if ($DryRun) {
        Write-Info 'Dry run: no files will be changed'
        Write-Host "  Build      : cargo build --release --locked --bin ruxmsg --target $HostTarget"
        Write-Host "  Target dir : $TargetDir"
        Write-Host "  Destination: $Destination"
        exit 0
    }

    Write-Info "Preparing $AppName release"
    Write-Host "  Repository : $RepoRoot"
    Write-Host "  Target     : $HostTarget"
    Write-Host "  Compiler   : $(& rustc --version)"
    Write-Host "  Cargo      : $(& cargo --version)"
    Write-Host "  Destination: $Destination"
    Write-Host ''

    # Build the release executable using the committed lockfile.
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

    # Prepare the installation directory.
    Write-Info 'Preparing installation directory'

    if (-not (Test-Path -LiteralPath $InstallDir -PathType Container)) {
        New-Item -ItemType Directory -Path $InstallDir -Force |
            Out-Null
    }

    if (-not (Test-Path -LiteralPath $InstallDir -PathType Container)) {
        Stop-Install "Installation destination is not a directory: $InstallDir"
    }

    # Stage beside the destination so replacement stays on the same volume.
    $StagedBinary = Join-Path $InstallDir (
        '.ruxmsg.' + [Guid]::NewGuid().ToString('N') + '.tmp'
    )

    [System.IO.File]::Copy($BinaryPath, $StagedBinary, $false)

    if (Test-Path -LiteralPath $Destination) {
        $Existing = Get-Item -LiteralPath $Destination -Force

        if ($Existing -isnot [System.IO.FileInfo] -or
            (($Existing.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0)) {
            Stop-Install "Refusing to replace a non-regular file or reparse point: $Destination"
        }

        $BackupBinary = Join-Path $InstallDir (
            '.ruxmsg.backup.' + [Guid]::NewGuid().ToString('N') + '.tmp'
        )

        Write-Info 'Replacing existing executable'

        # Replace the destination and retain a backup until replacement succeeds.
        [System.IO.File]::Replace(
            $StagedBinary,
            $Destination,
            $BackupBinary,
            $true
        )

        $StagedBinary = $null

        try {
            if (Test-Path -LiteralPath $BackupBinary -PathType Leaf) {
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

    # Verify the installed executable.
    if (-not (Test-Path -LiteralPath $Destination -PathType Leaf)) {
        Stop-Install "Installation verification failed: $Destination"
    }

    Write-Host ''
    Write-Success "$AppName installed successfully"
    Write-Host ''
    Write-Host "  Executable   : $Destination"
    Write-Host "  Target       : $HostTarget"
    Write-Host '  Configuration: managed separately by RUXMSG'
    Write-Host '  Credentials  : Windows Credential Manager'
    Write-Host ''
    Write-Host "  Run    : & '$Destination'"
    Write-Host "  Verify : & '$Destination' --help"
    Write-Host ''
    Write-Host 'The installer does not remove or modify user configuration or credentials.'
}
catch {
    Write-Error $_
    exit 1
}
finally {
    Remove-StagingFiles
}
