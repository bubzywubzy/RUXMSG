
[CmdletBinding()]
param(
    [ValidateSet('binary', 'all', 'help')]
    [string]$Mode = 'binary',

    [string]$InstallDir,

    [switch]$DryRun
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$AppName = 'RUXMSG'
$BinaryName = 'ruxmsg.exe'
$TrimChars = [char[]]@('\', '/')

if ([string]::IsNullOrWhiteSpace($InstallDir)) {
    if ($Mode -eq 'help') {
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

# Match config.rs path resolution: only an absolute XDG_CONFIG_HOME is honored;
# otherwise the application uses the process HOME environment variable.
$ConfigBase = $null
if (-not [string]::IsNullOrWhiteSpace($env:XDG_CONFIG_HOME) -and
    [System.IO.Path]::IsPathRooted($env:XDG_CONFIG_HOME)) {
    $ConfigBase = [System.IO.Path]::GetFullPath($env:XDG_CONFIG_HOME)
}
elseif (-not [string]::IsNullOrWhiteSpace($env:HOME) -and
    [System.IO.Path]::IsPathRooted($env:HOME)) {
    $ConfigBase = [System.IO.Path]::GetFullPath((Join-Path $env:HOME '.config'))
}

$ConfigDir = $null
if ($null -ne $ConfigBase) {
    $ConfigDir = [System.IO.Path]::GetFullPath((Join-Path $ConfigBase 'ruxmsg'))
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

function Stop-Uninstall {
    param([Parameter(Mandatory)][string]$Message)
    throw $Message
}

function Write-Banner {
    Write-Host ''
    Write-Host '██████╗  ██╗   ██╗ ██╗  ██╗ ███╗   ███╗ ███████╗  ██████╗' -ForegroundColor Cyan
    Write-Host '██╔══██╗ ██║   ██║ ╚██╗██╔╝ ████╗ ████║ ██╔════╝ ██╔════╝' -ForegroundColor Cyan
    Write-Host '██████╔╝ ██║   ██║  ╚███╔╝  ██╔████╔██║ ███████╗ ██║  ███╗' -ForegroundColor Cyan
    Write-Host '██╔══██╗ ██║   ██║  ██╔██╗  ██║╚██╔╝██║ ╚════██║ ██║   ██║' -ForegroundColor Cyan
    Write-Host '██║  ██║ ╚██████╔╝ ██╔╝ ██╗ ██║ ╚═╝ ██║ ███████║ ╚██████╔╝' -ForegroundColor Cyan
    Write-Host '╚═╝  ╚═╝  ╚═════╝  ╚═╝  ╚═╝ ╚═╝     ╚═╝ ╚══════╝  ══════╝' -ForegroundColor Cyan
    Write-Host ''
    Write-Host '  Encrypted peer-to-peer messaging' -ForegroundColor DarkGray
    Write-Host '  Windows removal utility' -ForegroundColor DarkGray
    Write-Host ''
}

function Test-SafeTarget {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][ValidateSet('File', 'Directory')][string]$Kind
    )

    $FullPath = [System.IO.Path]::GetFullPath($Path)
    $Root = [System.IO.Path]::GetPathRoot($FullPath)

    if ([string]::Equals(
        $FullPath.TrimEnd($TrimChars),
        $Root.TrimEnd($TrimChars),
        [System.StringComparison]::OrdinalIgnoreCase
    )) {
        Stop-Uninstall "Refusing to remove a filesystem root: $FullPath"
    }

    # Refuse junctions/symlinks in any existing path component, not only the
    # final target. This keeps validation and displayed paths aligned.
    $Current = $Root
    $Relative = $FullPath.Substring($Root.Length)
    $Components = $Relative -split '[\\/]'
    foreach ($Component in $Components) {
        if ([string]::IsNullOrWhiteSpace($Component)) {
            continue
        }

        $Current = Join-Path $Current $Component
        if (Test-Path -LiteralPath $Current) {
            $Ancestor = Get-Item -LiteralPath $Current -Force
            if (($Ancestor.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
                Stop-Uninstall "Refusing a path containing a symbolic link or reparse point: $Current"
            }
        }
    }

    if (Test-Path -LiteralPath $FullPath) {
        $Item = Get-Item -LiteralPath $FullPath -Force

        if (($Item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
            Stop-Uninstall "Refusing to remove a symbolic link or reparse point: $FullPath"
        }

        if ($Item -isnot [System.IO.FileInfo] -and
            $Item -isnot [System.IO.DirectoryInfo]) {
            Stop-Uninstall "Refusing unexpected filesystem object: $FullPath"
        }

        if ($Kind -eq 'File' -and $Item -isnot [System.IO.FileInfo]) {
            Stop-Uninstall "Refusing to remove a non-file executable target: $FullPath"
        }

        if ($Kind -eq 'Directory' -and $Item -isnot [System.IO.DirectoryInfo]) {
            Stop-Uninstall "Refusing to remove a non-directory configuration target: $FullPath"
        }
    }
}

function Remove-Target {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][ValidateSet('File', 'Directory')][string]$Kind
    )

    Test-SafeTarget -Path $Path -Kind $Kind

    if (-not (Test-Path -LiteralPath $Path)) {
        Write-Warn "Not present; skipping: $Path"
        return
    }

    if ($Kind -eq 'File') {
        Remove-Item -LiteralPath $Path -Force
    }
    else {
        Remove-Item -LiteralPath $Path -Recurse -Force
    }

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
    .\uninstall.ps1 -Mode all -DryRun
  .\uninstall.ps1 -Mode help

Parameters:
  -Mode binary     Remove only ruxmsg.exe (default).
  -Mode all        Remove ruxmsg.exe and the default config directory.
    -DryRun          Show validated targets without changing files or prompting.
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

try {
    if ($Mode -eq 'help') {
        Show-Help
        exit 0
    }

    Write-Banner

    Write-Info "Removal mode: $Mode"
    Write-Host "  Executable: $Destination"

    # Validate the executable path before requesting confirmation.
    Test-SafeTarget -Path $Destination -Kind File

    $Targets = @($Destination)

    if ($Mode -eq 'all') {
        if ([string]::IsNullOrWhiteSpace($ConfigDir)) {
            Stop-Uninstall 'The application has no resolved default config path in this environment; refusing all-mode removal.'
        }

        $ConfigFull = [System.IO.Path]::GetFullPath($ConfigDir)
        $HomeFull = [System.IO.Path]::GetFullPath($HOME)
        $ConfigRoot = [System.IO.Path]::GetPathRoot($ConfigFull)

        if ([string]::Equals(
            $ConfigFull.TrimEnd($TrimChars),
            $ConfigRoot.TrimEnd($TrimChars),
            [System.StringComparison]::OrdinalIgnoreCase
        )) {
            Stop-Uninstall "Refusing unsafe configuration directory: $ConfigFull"
        }

        if ([string]::Equals(
            $ConfigFull.TrimEnd($TrimChars),
            $HomeFull.TrimEnd($TrimChars),
            [System.StringComparison]::OrdinalIgnoreCase
        )) {
            Stop-Uninstall "Refusing to remove the home directory: $ConfigFull"
        }

        # Refuse known broad or sensitive directories.
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
        ) | Where-Object {
            -not [string]::IsNullOrWhiteSpace($_)
        }

        foreach ($ForbiddenPath in $Forbidden) {
            $ForbiddenFull = [System.IO.Path]::GetFullPath(
                $ForbiddenPath
            )

            if ([string]::Equals(
                $ConfigFull.TrimEnd($TrimChars),
                $ForbiddenFull.TrimEnd($TrimChars),
                [System.StringComparison]::OrdinalIgnoreCase
            )) {
                Stop-Uninstall "Refusing broad or sensitive configuration target: $ConfigFull"
            }
        }

        # Reconstruct and verify the exact expected config path.
        $ExpectedConfigTarget = [System.IO.Path]::GetFullPath(
            (Join-Path $ConfigBase 'ruxmsg')
        )

        if (-not [string]::Equals(
            $ConfigFull.TrimEnd($TrimChars),
            $ExpectedConfigTarget.TrimEnd($TrimChars),
            [System.StringComparison]::OrdinalIgnoreCase
        )) {
            Stop-Uninstall "Configuration path did not pass validation: $ConfigFull"
        }

        Test-SafeTarget -Path $ConfigFull -Kind Directory
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

        if ($DryRun) {
            Write-Info 'Dry run: no files were changed.'
            exit 0
        }

        if (-not (Confirm-Removal 'Permanently remove the listed targets? [y/N]')) {
            Write-Info 'Removal cancelled.'
            exit 0
        }
    }
    else {
        Write-Host ''

        if ($DryRun) {
            Write-Info 'Dry run: no files were changed.'
            exit 0
        }
        Write-Host 'This removes only the installed executable.'
        Write-Host 'Configuration, credentials, and repository files will be retained.'
        Write-Host ''

        if (-not (Confirm-Removal "Uninstall $AppName? [y/N]")) {
            Write-Info 'Removal cancelled.'
            exit 0
        }
    }

    Write-Info 'Removing installed executable'
    Remove-Target -Path $Destination -Kind File

    if ($Mode -eq 'all') {
        Write-Info 'Removing default configuration directory'
        Remove-Target -Path $ConfigDir -Kind Directory
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
