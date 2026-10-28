[CmdletBinding()]
param(
    [ValidateSet('binary', 'all', 'help')]
    [string]$Mode = 'binary',

    [string]$InstallDir
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$AppName = 'RUXMSG'
$BinaryName = 'ruxmsg.exe'

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

# Match the application's config.rs path resolution:
# absolute XDG_CONFIG_HOME, otherwise HOME/.config.
if (-not [string]::IsNullOrWhiteSpace($env:XDG_CONFIG_HOME) -and
    [System.IO.Path]::IsPathRooted($env:XDG_CONFIG_HOME)) {
    $ConfigDir = Join-Path $env:XDG_CONFIG_HOME 'ruxmsg'
}
else {
    $ConfigDir = Join-Path $HOME '.config\ruxmsg'
}

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

function Stop-Uninstall {
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
    Write-Host '  Windows removal utility' -ForegroundColor DarkGray
    Write-Host ''
}

# ---------- Validation ----------

function Test-SafeTarget {
    param([Parameter(Mandatory)][string]$Path)

    $FullPath = [System.IO.Path]::GetFullPath($Path)
    $Root = [System.IO.Path]::GetPathRoot($FullPath)

    if ([string]::Equals(
        $FullPath.TrimEnd('\', '/'),
        $Root.TrimEnd('\', '/'),
        [System.StringComparison]::OrdinalIgnoreCase
    )) {
        Stop-Uninstall "Refusing to remove a filesystem root: $FullPath"
    }

    if (Test-Path -LiteralPath $FullPath) {
        $Item = Get-Item -LiteralPath $FullPath -Force

        if (($Item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
            Stop-Uninstall "Refusing to remove a symbolic link or reparse point: $FullPath"
        }

        if (-not ($Item -is [System.IO.FileInfo]) -and
            -not ($Item -is [System.IO.DirectoryInfo])) {
            Stop-Uninstall "Refusing unexpected filesystem object: $FullPath"
        }
    }
}

function Remove-Target {
    param([Parameter(Mandatory)][string]$Path)

    Test-SafeTarget -Path $Path

    if (-not (Test-Path -LiteralPath $Path)) {
        Write-Warn "Not present; skipping: $Path"
        return
    }

    Remove-Item -LiteralPath $Path -Recurse -Force

    if (Test-Path -LiteralPath $Path) {
        Stop-Uninstall "Removal verification failed: $Path"
    }

    Write-Success "Removed: $Path"
}

function Confirm-Removal {
    param([Parameter(Mandatory)][string]$Prompt)

    $Answer = Read-Host $Prompt

    return $Answer -match '^(?i:y|yes)$'
}

function Show-Help {
    @'
Usage:
  .\uninstall.ps1
  .\uninstall.ps1 -Mode binary
  .\uninstall.ps1 -Mode all
  .\uninstall.ps1 -Mode help

Parameters:
  -Mode binary     Remove only ruxmsg.exe (default).
  -Mode all        Remove ruxmsg.exe and the default config directory.
  -InstallDir      Override the installation directory.

Environment:
  RUXMSG_INSTALL_DIR  Alternative installation-directory override.
  XDG_CONFIG_HOME     Configuration base directory when absolute.

Notes:
  - Identity credentials in Windows Credential Manager are not deleted.
  - Custom paths passed through --config are not discovered.
  - The repository and build artifacts are retained.
'@ | Write-Host
}

# ---------- Main ----------

try {
    if ($Mode -eq 'help') {
        Show-Help
        exit 0
    }

    Write-Banner

    Write-Info "Removal mode: $Mode"
    Write-Host "  Executable: $Destination"

    Test-SafeTarget -Path $Destination

    $Targets = @($Destination)

    if ($Mode -eq 'all') {
        # Never permit a broad parent directory as the config target.
        $ConfigFull = [System.IO.Path]::GetFullPath($ConfigDir)
        $HomeFull = [System.IO.Path]::GetFullPath($HOME)
        $ConfigRoot = [System.IO.Path]::GetPathRoot($ConfigFull)

        if ([string]::Equals(
            $ConfigFull.TrimEnd('\', '/'),
            $ConfigRoot.TrimEnd('\', '/'),
            [System.StringComparison]::OrdinalIgnoreCase
        )) {
            Stop-Uninstall "Refusing unsafe configuration directory: $ConfigFull"
        }

        if ([string]::Equals(
            $ConfigFull.TrimEnd('\', '/'),
            $HomeFull.TrimEnd('\', '/'),
            [System.StringComparison]::OrdinalIgnoreCase
        )) {
            Stop-Uninstall "Refusing to remove the home directory: $ConfigFull"
        }

        $Forbidden = @(
            (Join-Path $HOME '.config'),
            (Join-Path $HOME '.local'),
            (Join-Path $HOME '.ssh'),
            (Join-Path $HOME 'Documents'),
            (Join-Path $HOME 'Downloads'),
            (Join-Path $HOME 'Desktop'),
            $env:WINDIR,
            $env:ProgramFiles,
            ${env:ProgramFiles(x86)}
        ) | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }

        foreach ($Path in $Forbidden) {
            $ForbiddenFull = [System.IO.Path]::GetFullPath($Path)

            if ([string]::Equals(
                $ConfigFull.TrimEnd('\', '/'),
                $ForbiddenFull.TrimEnd('\', '/'),
                [System.StringComparison]::OrdinalIgnoreCase
            )) {
                Stop-Uninstall "Refusing broad or sensitive configuration target: $ConfigFull"
            }
        }

        Test-SafeTarget -Path $ConfigFull
        $Targets += $ConfigFull

        Write-Host ''
        Write-Host 'FULL REMOVAL TARGETS' -ForegroundColor Yellow
        foreach ($Target in $Targets) {
            Write-Host "  - $Target"
        }

        Write-Host ''
        Write-Warn 'The configuration directory may contain user settings.'
        Write-Warn 'Identity credentials in Windows Credential Manager are NOT removed.'
        Write-Warn 'Custom --config paths, repository files, and build artifacts are retained.'

        if (-not (Confirm-Removal 'Permanently remove the listed targets? [y/N]')) {
            Write-Info 'Removal cancelled.'
            exit 0
        }
    }
    else {
        Write-Host ''
        Write-Host 'This removes only the installed executable.'
        Write-Host 'Configuration, credentials, and repository files will be retained.'
        Write-Host ''

        if (-not (Confirm-Removal "Uninstall $AppName? [y/N]")) {
            Write-Info 'Removal cancelled.'
            exit 0
        }
    }

    Write-Info 'Removing installed executable'
    Remove-Target -Path $Destination

    if ($Mode -eq 'all') {
        Write-Info 'Removing default configuration directory'
        Remove-Target -Path $ConfigDir
    }

    Write-Host ''
    Write-Success "$AppName filesystem removal completed."

    if ($Mode -eq 'binary') {
        Write-Host '  Retained: configuration, credentials, repository, build artifacts'
    }
    else {
        Write-Host '  Retained: identity credentials, custom config paths, repository, build artifacts'
    }

    Write-Host ''
    Write-Warn 'Identity credentials in Windows Credential Manager were not erased.'
}
catch {
    Write-Error $_
    exit 1
}