# Phase 1 of the build: install the AD-DS Windows role, promote the
# server to the first DC of a new forest, then reboot. Phase 2 is
# Install-AddsContent.ps1.
#
# This script bootstraps the AD-DS + management-tools features BEFORE
# importing the AdDehydrationKit module, because the module's manifest
# declares RequiredModules = ActiveDirectory, GroupPolicy. Those modules
# only exist once the AD-DS role's management tools are installed -
# which is exactly the bootstrap problem this script solves. Without
# the bootstrap, a fresh server would fail Import-Module on the first
# run and you'd have to install the feature manually and re-run.
#
#Requires -RunAsAdministrator

[CmdletBinding(SupportsShouldProcess)]
param(
    [string] $DomainDnsName,
    [string] $DomainNetBiosName,
    [string] $DbPath      = 'C:\ADDS\Db',
    [string] $LogPath     = 'C:\ADDS\DbLog',
    [string] $SysvolPath  = 'C:\ADDS\SYSVOL',
    [string] $DsrmPwd
)

$ErrorActionPreference = 'Stop'

# -- OS patch-level pre-flight -----------------------------------------
# Windows LAPS (built-in) minimum builds:
#   Server 2025 (26100+)      - available OOB, no minimum revision
#   Server 2022 (20348.1668+) - April 2023 cumulative update
#   Server 2019 (17763.4252+) - April 2023 cumulative update
# If the current build is below the minimum the Schema step will skip LAPS.
# Low patch level also implies other security updates are missing.
$_reg       = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
$_osBuild   = [int]$_reg.CurrentBuildNumber
$_osUBR     = [int]$_reg.UBR
$_osName    = $_reg.ProductName

$_lapsReady = ($_osBuild -ge 26100) -or
              ($_osBuild -eq 20348 -and $_osUBR -ge 1668) -or
              ($_osBuild -eq 17763 -and $_osUBR -ge 4252)

if (-not $_lapsReady) {
    Write-Host ''
    Write-Host '  OS patch level check' -ForegroundColor Cyan
    Write-Host "  OS      : $_osName" -ForegroundColor Yellow
    Write-Host "  Build   : $_osBuild.$_osUBR" -ForegroundColor Yellow
    if ($_osBuild -ge 26100) {
        # Should not happen - 2025 is always ready
    } elseif ($_osBuild -eq 20348) {
        Write-Host '  Minimum : 20348.1668  (April 2023 cumulative update)' -ForegroundColor Yellow
    } elseif ($_osBuild -eq 17763) {
        Write-Host '  Minimum : 17763.4252  (April 2023 cumulative update)' -ForegroundColor Yellow
    } else {
        Write-Host '  WARNING : OS version not supported (requires Server 2019, 2022, or 2025)' -ForegroundColor Red
    }
    Write-Host ''
    Write-Host '  Windows LAPS will not be installed until the OS is patched.' -ForegroundColor Yellow
    Write-Host '  Other security updates are likely missing as well.' -ForegroundColor Yellow
    Write-Host ''
    $answer = Read-Host '  Continue anyway? [y/N]'
    if ($answer -notmatch '^[Yy]') { exit 1 }
    Write-Host ''
}
Remove-Variable _reg, _osBuild, _osUBR, _osName, _lapsReady -ErrorAction SilentlyContinue

# ---------- Bootstrap: AD-DS + GPMC management tools ----------
# Idempotent - Install-WindowsFeature returns immediately if the
# feature is already installed.

function Ensure-WindowsFeature {
    [CmdletBinding(SupportsShouldProcess)]
    param([string] $Name)
    $f = Get-WindowsFeature $Name -ErrorAction SilentlyContinue
    if (-not $f) {
        throw "Windows feature [$Name] is not available on this OS. This script must run on Windows Server."
    }
    if ($f.Installed) {
        Write-Host "  feature [$Name] already installed" -ForegroundColor DarkGray
        return
    }
    if (-not $PSCmdlet.ShouldProcess($Name, 'Install Windows feature')) { return }
    Write-Host "  installing feature [$Name].." -ForegroundColor Yellow
    Install-WindowsFeature $Name -IncludeManagementTools | Out-Null
}

Write-Host 'Bootstrapping AD-DS + management tools..' -ForegroundColor Cyan

# ServerManager isn't loaded by default on legacy OSes
$serverMan = Get-Module ServerManager -ListAvailable
if ($null -eq $serverMan) {
    Add-PSSnapin Microsoft.Windows.ServerManager.PSSnapin -ErrorAction SilentlyContinue
} else {
    Import-Module ServerManager -ErrorAction SilentlyContinue
}

# Explicit -WhatIf propagation: PS 5.1 does not reliably pass
# $WhatIfPreference across module/function boundaries.
Ensure-WindowsFeature -Name 'AD-Domain-Services' -WhatIf:$WhatIfPreference
Ensure-WindowsFeature -Name 'GPMC' -WhatIf:$WhatIfPreference

# ---------- Now safe to import the module ----------
# Under -WhatIf the features may not actually be installed yet, so
# the module import can fail (RequiredModules = ActiveDirectory, GroupPolicy).
# Show what would happen and exit gracefully.
$scriptDir = Split-Path -Parent $PSCommandPath
$modulePath = Join-Path $scriptDir 'AdDehydrationKit\AdDehydrationKit.psd1'
if (-not (Test-Path $modulePath)) {
    throw "AdDehydrationKit module not found at $modulePath"
}
try {
    Import-Module $modulePath -Force -WarningAction SilentlyContinue
} catch {
    if ($WhatIfPreference) {
        Write-Host "  [WhatIf] Module import skipped (AD-DS features not yet installed)" -ForegroundColor DarkGray
        Write-Host "  [WhatIf] Would promote server to first DC of a new forest" -ForegroundColor DarkGray
        return
    }
    throw
}

# ---------- Promote to DC ----------
$installArgs = @{}
if ($DomainDnsName)     { $installArgs.DomainDnsName     = $DomainDnsName }
if ($DomainNetBiosName) { $installArgs.DomainNetBiosName = $DomainNetBiosName }
if ($DbPath)            { $installArgs.DbPath            = $DbPath }
if ($LogPath)           { $installArgs.LogPath           = $LogPath }
if ($SysvolPath)        { $installArgs.SysvolPath        = $SysvolPath }
if ($DsrmPwd)           { $installArgs.DsrmPassword      = (ConvertTo-SecureString $DsrmPwd -AsPlainText -Force) }

Install-AdkForest @installArgs -WhatIf:$WhatIfPreference
