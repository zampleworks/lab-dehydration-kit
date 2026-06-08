# Build a context object that the orchestrator passes around. Captures
# the domain identity, the data path, settings, and the OU token map
# so each Public cmdlet doesn't have to re-resolve them.
#
# Settings.psd1 (optional) in the data folder provides environment-
# level knobs: renamed RID-500 account, hardening toggles, log level.
# Missing file or missing keys fall back to safe defaults.

function Get-AdkContext {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string] $DataPath,

        [string] $GpoPath
    )

    if (-not (Test-Path $DataPath -PathType Container)) {
        throw "DataPath not found: $DataPath"
    }

    $domain = Get-ADDomain

    # -- Load Settings.psd1 (optional) ------------------------------------
    $settingsPath = Join-Path $DataPath 'Settings.psd1'
    if (Test-Path $settingsPath -PathType Leaf) {
        $settings = Import-PowerShellDataFile $settingsPath
    } else {
        $settings = @{}
    }

    # -- Defaults for missing keys ----------------------------------------
    $builtinAdminName = if ($settings.BuiltinAdministratorName) {
        $settings.BuiltinAdministratorName
    } else { 'Administrator' }

    $localAdminName = if ($settings.LocalAdministratorName) {
        $settings.LocalAdministratorName
    } else { 'Administrator' }

    $logLevel = if ($settings.LogLevel) {
        $settings.LogLevel
    } else { 'Normal' }

    # Hardening sub-tables: merge with secure defaults so a missing
    # key means "enabled" / "hardened value".
    $hardeningDefaults = @{
        ClearPreWin2000              = $true
        ZeroMachineAccountQuota      = $true
        RedirectDefaultContainers    = $true
        EmptySchemaAdmins            = $true
        EnforceAccountNotDelegated   = $true
        EnforceAesEncryption         = $true
        ResetKrbtgt                  = $true
        ProtectDcOu                  = $true
        ClearBuiltinGroupsAdminCount = $true
        DsHeuristics                 = @{
            BlockAnonLdap           = '0'
            EnforceOwnerCheck       = '1'
            EnforceAddAttributeAuth = '1'
        }
    }
    $hardening = $hardeningDefaults.Clone()
    # Deep-clone the DsHeuristics sub-table so defaults are independent.
    $hardening.DsHeuristics = $hardeningDefaults.DsHeuristics.Clone()
    if ($settings.Hardening) {
        foreach ($k in $settings.Hardening.Keys) {
            if ($k -eq 'DsHeuristics' -and $settings.Hardening.DsHeuristics -is [hashtable]) {
                foreach ($dk in $settings.Hardening.DsHeuristics.Keys) {
                    $hardening.DsHeuristics[$dk] = $settings.Hardening.DsHeuristics[$dk]
                }
            } else {
                $hardening[$k] = $settings.Hardening[$k]
            }
        }
    }

    $serverHardeningDefaults = @{
        NtdsRpcPort               = 49151
        NetlogonRpcPort           = 49150
        KdcExtraLogLevel          = 0x1F
        LDAPServerIntegrity       = 2
        LdapEnforceChannelBinding = 2
        DisableServices           = @{
            Spooler          = $true
            PrintNotify      = $true
            RemoteRegistry   = $true
            WebClient        = $true
            SSDPSRV          = $true
            upnphost         = $true
            Fax              = $true
            TapiSrv          = $true
            WSearch          = $true
            DiagTrack        = $true
            dmwappushservice = $true
            MapsBroker       = $true
            lfsvc            = $true
            RetailDemo       = $true
            PhoneSvc         = $true
            icssvc           = $true
            WpnService       = $true
            PushToInstall    = $true
        }
    }
    $serverHardening = $serverHardeningDefaults.Clone()
    $serverHardening.DisableServices = $serverHardeningDefaults.DisableServices.Clone()
    if ($settings.ServerHardening) {
        foreach ($k in $settings.ServerHardening.Keys) {
            if ($k -eq 'DisableServices' -and $settings.ServerHardening.DisableServices -is [hashtable]) {
                foreach ($sk in $settings.ServerHardening.DisableServices.Keys) {
                    $serverHardening.DisableServices[$sk] = $settings.ServerHardening.DisableServices[$sk]
                }
            } else {
                $serverHardening[$k] = $settings.ServerHardening[$k]
            }
        }
    }

    return [PSCustomObject] @{
        DataPath                 = (Resolve-Path $DataPath).Path
        GpoPath                  = $GpoPath
        Domain                   = $domain
        DomainDn                 = $domain.DistinguishedName
        DomainDnsName            = $domain.DNSRoot
        DomainNetBios            = $domain.NetBIOSName
        BuiltinAdministratorName = $builtinAdminName
        LocalAdministratorName   = $localAdminName
        LogLevel                 = $logLevel
        Hardening                = $hardening
        ServerHardening          = $serverHardening
    }
}
