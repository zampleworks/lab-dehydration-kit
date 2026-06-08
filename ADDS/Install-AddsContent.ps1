# Entry-point script for the AD content build. Run this after the
# forest is installed and the machine has rebooted.
#
# This script handles host-level concerns (OS pre-flight, ADWS wait,
# transcript, interactive prompts) then delegates all AD work to the
# Install-AdkContent cmdlet inside the AdDehydrationKit module.
#
# Usage (from the ADDS folder):
#   .\Install-AddsContent.ps1                           # all steps
#   .\Install-AddsContent.ps1 -Step Groups              # single step
#   .\Install-AddsContent.ps1 -Step WmiFilters,SecurityBaselines
#   .\Install-AddsContent.ps1 -SkipStep ServerHardening # skip a step
#   .\Install-AddsContent.ps1 -Force                    # reimport GPOs
#
#Requires -RunAsAdministrator

[CmdletBinding(SupportsShouldProcess)]
param(
    [string] $DataPath,
    [string] $GpoPath,

    [ValidateSet(
        'OuTree','Groups','Apps','Users','Memberships','Fgpp',
        'ForestFeatures','Delegations','SodGpos','DefaultPolicies',
        'WmiFilters','AdmxTemplates','SecurityBaselines','DnsReplication',
        'AuthPolicies','DomainHardening','ServerHardening'
    )]
    [string[]] $Step,

    [ValidateSet(
        'OuTree','Groups','Apps','Users','Memberships','Fgpp',
        'ForestFeatures','Delegations','SodGpos','DefaultPolicies',
        'WmiFilters','AdmxTemplates','SecurityBaselines','DnsReplication',
        'AuthPolicies','DomainHardening','ServerHardening'
    )]
    [string[]] $SkipStep,

    [switch] $Force
)

$ErrorActionPreference = 'Stop'

# -- OS patch-level pre-flight -----------------------------------------
# Windows LAPS (built-in) minimum builds:
#   Server 2025 (26100+)      - available OOB, no minimum revision
#   Server 2022 (20348.1668+) - April 2023 cumulative update
#   Server 2019 (17763.4252+) - April 2023 cumulative update
# If the current build is below the minimum the Schema step will skip LAPS.
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
    if ($_osBuild -eq 20348) {
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

# -- Infrastructure ---------------------------------------------------
if ($PSVersionTable.PSVersion.Major -lt 5) {
    throw 'PowerShell 5 or newer required'
}

$scriptDir = Split-Path -Parent $PSCommandPath

# Resolve DataPath relative to script location
if ([string]::IsNullOrWhiteSpace($DataPath)) {
    foreach ($candidate in @((Join-Path $scriptDir 'Data'), (Join-Path $scriptDir 'Objects'))) {
        if (Test-Path $candidate -PathType Container) {
            $DataPath = $candidate
            break
        }
    }
}
if (-not $DataPath) {
    throw "Could not find a data folder. Tried .\Data and .\Objects under $scriptDir"
}

# Resolve GpoPath relative to script location
if ([string]::IsNullOrWhiteSpace($GpoPath)) {
    foreach ($candidate in @((Join-Path $scriptDir 'Gpo\Backups'), (Join-Path $scriptDir 'gpobackup'))) {
        if (Test-Path $candidate -PathType Container) {
            $GpoPath = $candidate
            break
        }
    }
}

# -- Module import ----------------------------------------------------
$modulePath = Join-Path $scriptDir 'AdDehydrationKit\AdDehydrationKit.psd1'
if (-not (Test-Path $modulePath)) {
    throw "AdDehydrationKit module not found at $modulePath"
}
Import-Module $modulePath -Force

# -- Transcript -------------------------------------------------------
$transcript = Join-Path $scriptDir 'pstranscript.txt'
$transcriptStarted = $false

function Stop-AllTranscripts {
    param([int] $Max = 8)
    for ($i = 0; $i -lt $Max; $i++) {
        try {
            Stop-Transcript -ErrorAction Stop | Out-Null
        } catch {
            break
        }
    }
}

try {
    try {
        Start-Transcript -Path $transcript -Append -WhatIf:$false -ErrorAction Stop | Out-Null
        $transcriptStarted = $true
    } catch {
        Write-Host "Transcript not started: $($_.Exception.Message)"
    }

    # -- Wait for ADWS ---------------------------------------------------
    Write-Progress -Id 1 -Activity 'AD deploy' -CurrentOperation 'Waiting for ADWS..'
    $adReady = $false
    $i = -1
    while (-not $adReady) {
        $dots = if ($i++ -eq 2) { $i = 0; '..' } else { '.' }
        try {
            Import-Module ActiveDirectory | Out-Null
            Get-ChildItem AD:\ | Out-Null
            $adReady = $true
        } catch {
            try { Remove-Module ActiveDirectory | Out-Null } catch { }
            Write-Progress -Id 1 -Activity 'AD deploy' -Status "Waiting for ADWS$dots"
            Start-Sleep -Seconds 2
        }
    }
    Import-Module ActiveDirectory, GroupPolicy

    # -- DC pre-flight checks ----------------------------------------------
    # Verify critical services are running and the DC subsystems are
    # actually responding before handing off to the module orchestrator.
    # A failing check aborts early with a clear message instead of letting
    # the content seeding fail halfway through with a cryptic error.
    Write-Host ''
    Write-Host '  Domain controller pre-flight checks' -ForegroundColor Cyan
    Write-Host ''

    $_preflightFailed = $false

    # 1. Service state checks
    $_requiredServices = [ordered]@{
        'NTDS'     = 'Active Directory Domain Services'
        'Netlogon' = 'Netlogon (authentication & DC locator)'
        'kdc'      = 'Kerberos Key Distribution Center'
        'DNS'      = 'DNS Server'
        'ADWS'     = 'Active Directory Web Services'
    }
    foreach ($_svcEntry in $_requiredServices.GetEnumerator()) {
        $_svc = Get-Service -Name $_svcEntry.Key -ErrorAction SilentlyContinue
        if ($null -eq $_svc) {
            Write-Host "  [FAIL] $($_svcEntry.Value) - service not found" -ForegroundColor Red
            $_preflightFailed = $true
        } elseif ($_svc.Status -ne 'Running') {
            Write-Host "  [FAIL] $($_svcEntry.Value) - status: $($_svc.Status)" -ForegroundColor Red
            $_preflightFailed = $true
        } else {
            Write-Host "  [ OK ] $($_svcEntry.Value)" -ForegroundColor Green
        }
    }

    # 2. LDAP / directory access (Get-ADRootDSE is unauthenticated LDAP)
    $_rootDSE = $null
    try {
        $_rootDSE = Get-ADRootDSE -ErrorAction Stop
        Write-Host "  [ OK ] LDAP responding (rootDSE)" -ForegroundColor Green
    } catch {
        Write-Host "  [FAIL] LDAP not responding - Get-ADRootDSE failed" -ForegroundColor Red
        $_preflightFailed = $true
    }

    # 3. Domain object reachable
    try {
        $_dom = Get-ADDomain -ErrorAction Stop
        $_domDns = $_dom.DNSRoot
        Write-Host "  [ OK ] Domain object reachable ($_domDns)" -ForegroundColor Green
    } catch {
        Write-Host "  [FAIL] Get-ADDomain failed: $($_.Exception.Message)" -ForegroundColor Red
        $_preflightFailed = $true
        $_domDns = $null
    }

    # 4. DNS resolution - SOA record for the domain
    if ($_domDns) {
        try {
            $_soa = Resolve-DnsName $_domDns -Type SOA -DnsOnly -ErrorAction Stop
            Write-Host "  [ OK ] DNS resolves domain SOA record" -ForegroundColor Green
        } catch {
            Write-Host "  [FAIL] DNS cannot resolve SOA for $_domDns" -ForegroundColor Red
            $_preflightFailed = $true
        }
    }

    # 5. DNS SRV records - DC locator depends on these
    if ($_domDns) {
        try {
            $_srv = Resolve-DnsName "_ldap._tcp.$_domDns" -Type SRV -DnsOnly -ErrorAction Stop
            $_srvCount = @($_srv | Where-Object { $_.Type -eq 'SRV' }).Count
            Write-Host "  [ OK ] DNS SRV records present ($_srvCount _ldap._tcp entries)" -ForegroundColor Green
        } catch {
            Write-Host "  [FAIL] DNS SRV records missing (_ldap._tcp.$_domDns)" -ForegroundColor Red
            $_preflightFailed = $true
        }
    }

    # 6. Netlogon DC locator
    if ($_domDns) {
        $_nltest = nltest /dsgetdc:$_domDns 2>&1
        if ($LASTEXITCODE -eq 0) {
            $_dcName = ($_nltest | Select-String 'DC: \\\\(.+)' | ForEach-Object { $_.Matches[0].Groups[1].Value })
            if ($_dcName) {
                Write-Host "  [ OK ] DC locator found: $_dcName" -ForegroundColor Green
            } else {
                Write-Host "  [ OK ] DC locator responding" -ForegroundColor Green
            }
        } else {
            Write-Host "  [FAIL] DC locator failed (nltest /dsgetdc:$_domDns)" -ForegroundColor Red
            $_preflightFailed = $true
        }
    }

    # 7. SYSVOL share accessible
    if ($_domDns) {
        $_sysvolPath = "\\$_domDns\SYSVOL"
        if (Test-Path $_sysvolPath) {
            Write-Host "  [ OK ] SYSVOL share accessible ($_sysvolPath)" -ForegroundColor Green
        } else {
            Write-Host "  [WARN] SYSVOL share not accessible ($_sysvolPath)" -ForegroundColor Yellow
            Write-Host "         GPO import may fail until SYSVOL replication completes." -ForegroundColor Yellow
        }
    }

    Write-Host ''
    if ($_preflightFailed) {
        Write-Host '  One or more pre-flight checks failed.' -ForegroundColor Red
        Write-Host '  The domain controller may not be fully operational yet.' -ForegroundColor Red
        Write-Host ''
        $answer = Read-Host '  Continue anyway? [y/N]'
        if ($answer -notmatch '^[Yy]') { exit 1 }
        Write-Host ''
    } else {
        Write-Host '  All pre-flight checks passed.' -ForegroundColor Green
        Write-Host ''
    }

    Remove-Variable -Name '_preflightFailed','_requiredServices','_svc','_svcEntry',
        '_rootDSE','_dom','_domDns','_soa','_srv','_srvCount','_nltest','_dcName',
        '_sysvolPath' -ErrorAction SilentlyContinue

    Write-Progress -Id 1 -Activity 'AD deploy' -Completed

    # -- Delegate to module orchestrator ---------------------------------
    $splatParams = @{ Context = (Get-AdkContext -DataPath $DataPath -GpoPath $GpoPath) }
    if ($Step)     { $splatParams['Step']     = $Step }
    if ($SkipStep) { $splatParams['SkipStep'] = $SkipStep }
    if ($Force)    { $splatParams['Force']    = $true }

    Install-AdkContent @splatParams -WhatIf:$WhatIfPreference

} catch {
    Stop-AllTranscripts
    $transcriptStarted = $false
    $ex = $_.Exception
    while ($ex) {
        Write-Host ''
        Write-Host $ex.Message -ForegroundColor Red
        $ex = $ex.InnerException
    }
    if ($_.ScriptStackTrace) {
        Write-Host ''
        Write-Host 'Script stack trace:' -ForegroundColor Cyan
        Write-Host $_.ScriptStackTrace -ForegroundColor DarkGray
    }
    Read-Host 'Press key to continue'
    throw
} finally {
    Stop-AllTranscripts
}
