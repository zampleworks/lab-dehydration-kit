# Provision a single "app": per-app OUs, role/permission
# groups, GPO import + link, and optional per-app GpoEdit delegation.
#
# The "app" concept replaces hand-enumerated per-service rows in
# Groups.csv. Each app contributes:
#
#   OUs:
#     %T<Tier>ComputersOU%/<App>           combined App + Mgmt server OU
#     %T<Tier>ComputersOU%/<App> SAW       only when -HasSaw
#
#   Admin/role groups (Adm- prefix):
#     Adm-<Tier>-<App>-Admin
#     Adm-<Tier>-<App>-User
#   Service account role group (Svc- prefix):
#     Svc-<Tier>-<App>-ServiceAccount
#
#   Pm groups (server set, always):
#     Pm AD <Tier> Server <App> InteractiveLogon / RdpLogon /
#                              LocalAdmin / ServiceLogon /
#                              LapsReadPwd / LapsResetPwd / LapsDecryptPwd
#
#   Pm groups (SAW set, only when -HasSaw): same names with " SAW"
#
#   AMA groups (only when -HasAma):
#     Ama-<Tier>-<App>-Admin     Universal, lives in %T0AmaOU%
#     Ama-<Tier>-<App>-User      Universal, lives in %T0AmaOU%
#
#   GPOs:
#     Backup-name -> imported as "<Tier> SoD <App> Servers" linked to the
#     server OU. With -HasSaw, also "<Tier> SoD <App> SAW" linked to the
#     SAW OU.
#
#   Domain join Pm group (always):
#     Pm-AD-<Tier>-<App>-JoinComputer          DomainJoin on the app server OU.
#                                              For app-specific principals;
#                                              ServerDeploy groups use tier-level join.
#
#   GPO Edit Pm group (always):
#     Pm-AD-GPO-Edit-<Tier>-<App>-Servers      empty by default; operator
#                                              populates post-deploy.
#     Pm-AD-GPO-Edit-<Tier>-<App>-SAW          (only when -HasSaw)
#
# AD-namespace note: the JoinComputer and GPO-Edit Pm groups are AD
# operations, so they ALWAYS live in the T0 perms OU regardless of the
# per-app tier.
#
# This cmdlet is idempotent - existing objects are detected and reused.
#
# The OU.csv is *not* modified by this cmdlet; OU resolution goes
# through Get-ADOrganizationalUnit. New-AdkOuTree creates the static
# OU shell; New-AdkApp creates app-specific OUs below it.

function New-AdkApp {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        [PSObject] $Context,

        [Parameter(Mandatory)]
        [string] $AppName,

        [Parameter(Mandatory)]
        [ValidateSet('T0', 'T1', 'EA')]
        [string] $Tier,

        [switch] $HasSaw,

        [switch] $HasAma,

        [string] $ServerGpoBackup = 'T0 SoD DB Servers',
        [string] $SawGpoBackup    = 'T0 SoD DB SAW'
    )

    Initialize-AdkSchema | Out-Null
    $ouMap = Get-AdkOuMap -DataPath $Context.DataPath

    # Resolve the per-tier parent OU for app computer OUs
    $computersOuToken = switch ($Tier) {
        'T0' { '%T0ComputersOU%' }
        'T1' { '%T1ComputersOU%' }
        'EA' { '%EAComputersOU%' }
    }
    $rolesOuToken = switch ($Tier) {
        'T0' { '%T0RolesOU%' }
        'T1' { '%T1RolesOU%' }
        'EA' { '%EARolesOU%' }
    }
    # OS-level Pm groups (Pm-<tier>-<app>-Srv/SAW-*) go in the tier of
    # the actual devices/services. AD-namespace Pm groups (Pm-AD-GPO-Edit-*)
    # always go in T0 - see comment block at top.
    $permsOuToken = switch ($Tier) {
        'T0' { '%T0PermsOU%' }
        'T1' { '%T1PermissionsOU%' }
        'EA' { '%EAPermissionsOU%' }
    }
    $adNamespacePermsOuToken = '%T0PermsOU%'
    $amaOuToken              = '%T0AmaOU%'

    if (-not $ouMap.ContainsKey($computersOuToken)) {
        throw "Per-tier computers OU not resolved: $computersOuToken (has New-AdkOuTree run?)"
    }
    $computersOu       = $ouMap[$computersOuToken]
    $rolesOu           = $ouMap[$rolesOuToken]
    $permsOu           = $ouMap[$permsOuToken]
    $adNamespacePermsOu = $ouMap[$adNamespacePermsOuToken]
    $amaOu              = $ouMap[$amaOuToken]

    # ---------- App OUs ----------
    $serverOuName = $AppName
    $serverOuDn = "OU=$serverOuName,$computersOu"
    if ($PSCmdlet.ShouldProcess($serverOuDn, 'Create app server OU')) {
        try {
            Get-ADOrganizationalUnit -Identity $serverOuDn -ErrorAction Stop | Out-Null
            Write-Verbose "App server OU exists: $serverOuDn"
        } catch {
            New-ADOrganizationalUnit -Path $computersOu -Name $serverOuName `
                                     -DisplayName $serverOuName -PassThru -Confirm:$false | Out-Null
            Write-AdkLog "  created [$serverOuDn]"
        }
    }

    $sawOuDn = $null
    if ($HasSaw) {
        $sawOuName = "$AppName SAW"
        $sawOuDn = "OU=$sawOuName,$computersOu"
        if ($PSCmdlet.ShouldProcess($sawOuDn, 'Create app SAW OU')) {
            try {
                Get-ADOrganizationalUnit -Identity $sawOuDn -ErrorAction Stop | Out-Null
                Write-Verbose "App SAW OU exists: $sawOuDn"
            } catch {
                New-ADOrganizationalUnit -Path $computersOu -Name $sawOuName `
                                         -DisplayName $sawOuName -PassThru -Confirm:$false | Out-Null
                Write-AdkLog "  created [$sawOuDn]"
            }
        }
    }

    # ---------- Role groups ----------
    # Admin membership group uses the Adm- prefix.
    # User membership group (SAW logon only) is created when -HasSaw.
    # ServiceAccount membership group uses the Svc- prefix.
    _EnsureAdkGroup -Name "Adm-$Tier-$AppName-Admin" -Scope Universal -Path $rolesOu `
        -Description "$AppName administrators ($Tier)"
    _EnsureAdkGroup -Name "Svc-$Tier-$AppName-ServiceAccount" -Scope Universal -Path $rolesOu `
        -Description "$AppName service accounts ($Tier)"
    if ($HasSaw) {
        _EnsureAdkGroup -Name "Adm-$Tier-$AppName-User" -Scope Universal -Path $rolesOu `
            -Description "$AppName SAW users ($Tier) - interactive/RDP logon to SAW only"
    }

    # ---------- AMA groups (conditional; authentication mechanism assurance) ----------
    if ($HasAma) {
        _EnsureAdkGroup -Name "Ama-$Tier-$AppName-Admin" -Scope Universal -Path $amaOu `
            -Description "AMA: $AppName administrators ($Tier)"
        _EnsureAdkGroup -Name "Ama-$Tier-$AppName-User" -Scope Universal -Path $amaOu `
            -Description "AMA: $AppName standard users ($Tier)"
    }

    # ---------- Server groups ----------
    # Computer membership groups for the app's servers. Used for GPO
    # targeting, SoD scope, and LAPS policy application.
    _EnsureAdkGroup -Name "Srv-$Tier-$AppName-App Server" -Scope Universal -Path $rolesOu `
        -Description "$AppName application servers ($Tier)"
    _EnsureAdkGroup -Name "Srv-$Tier-$AppName-Mgmt Server" -Scope Universal -Path $rolesOu `
        -Description "$AppName management servers ($Tier)"
    _EnsureAdkGroup -Name "Srv-$Tier-$AppName-Db Server" -Scope Universal -Path $rolesOu `
        -Description "$AppName database servers ($Tier)"
    if ($HasSaw) {
        _EnsureAdkGroup -Name "SAW-$Tier-$AppName" -Scope Universal -Path $rolesOu `
            -Description "$AppName Secure Admin Workstations ($Tier)"
    }

    # ---------- Server-track Pm groups (always; class=Srv) ----------
    # Pattern: Pm-<tier>-<service>-<class>-<permission>
    $serverPmSuffixes = @{
        'InteractiveLogon' = 'Allow interactive logon to servers'
        'RdpLogon'         = 'Allow RDP logon to servers'
        'LocalAdmin'       = 'Local Administrators on servers'
        'ServiceLogon'     = 'Allow service logon on servers'
        'LapsReadPwd'      = 'Read LAPS passwords on servers'
        'LapsResetPwd'     = 'Reset LAPS passwords on servers'
        'LapsDecryptPwd'   = 'Decrypt LAPS passwords on servers'
    }
    foreach ($kv in $serverPmSuffixes.GetEnumerator()) {
        $name = "Pm-$Tier-$AppName-Srv-$($kv.Key)"
        _EnsureAdkGroup -Name $name -Scope DomainLocal -Path $permsOu `
            -Description "$($kv.Value) - $AppName ($Tier)"
    }

    # ---------- SAW-track Pm groups (conditional; class=SAW) ----------
    if ($HasSaw) {
        $sawPmSuffixes = @{
            'InteractiveLogon' = 'Allow interactive logon to SAW'
            'RdpLogon'         = 'Allow RDP logon to SAW'
            'LocalAdmin'       = 'Local Administrators on SAW'
            'ServiceLogon'     = 'Allow service logon on SAW'
            'LapsReadPwd'      = 'Read LAPS passwords on SAW'
            'LapsResetPwd'     = 'Reset LAPS passwords on SAW'
            'LapsDecryptPwd'   = 'Decrypt LAPS passwords on SAW'
        }
        foreach ($kv in $sawPmSuffixes.GetEnumerator()) {
            $name = "Pm-$Tier-$AppName-SAW-$($kv.Key)"
            _EnsureAdkGroup -Name $name -Scope DomainLocal -Path $permsOu `
                -Description "$($kv.Value) - $AppName ($Tier)"
        }
    }

    # ---------- Per-app domain join Pm group + delegation ----------
    # AD-namespace: lives in T0 perms OU regardless of tier.
    # The ServerDeploy groups (Adm/Svc) already have tier-level join via
    # Pm-T<n>-AD-JoinComputer on %T<n>ComputersOU% (with inheritance),
    # so they don't need per-app wiring. This Pm group exists for
    # app-specific principals that need join on just this OU.
    $joinPm = "Pm-AD-$Tier-$AppName-JoinComputer"
    _EnsureAdkGroup -Name $joinPm -Scope DomainLocal -Path $adNamespacePermsOu `
        -Description "Domain join to $AppName server OU ($Tier)"

    # Delegate DomainJoin on the app server OU
    $joinPmObj = $null
    try { $joinPmObj = Get-ADGroup $joinPm -ErrorAction Stop } catch { }
    if ($joinPmObj -and $serverOuDn) {
        if ($PSCmdlet.ShouldProcess($serverOuDn, "Delegate DomainJoin to [$joinPm]")) {
            Set-Verb-DomainJoin -ObjectDN $serverOuDn -SubjectDN $joinPmObj.DistinguishedName
        }
    } elseif ($WhatIfPreference) {
        Write-Verbose "  [WhatIf] would delegate DomainJoin for [$joinPm] on [$serverOuDn]"
    }

    # ---------- Per-app GpoEdit Pm groups ----------
    # GPO display names (not group names) stay with spaces - these are
    # what GPMC and the GPO backup folders refer to.
    #
    # GPO edit is an AD operation (delegates rights on the AD GPO
    # container object), so these Pm groups live in the T0 perms OU
    # regardless of the app's tier and carry the Pm-AD- prefix.
    $serverGpoName   = "$Tier SoD $AppName Servers"
    $sawGpoName      = "$Tier SoD $AppName SAW"
    $serverGpoEditPm = "Pm-AD-GPO-Edit-$Tier-$AppName-Servers"
    $sawGpoEditPm    = "Pm-AD-GPO-Edit-$Tier-$AppName-SAW"

    _EnsureAdkGroup -Name $serverGpoEditPm -Scope DomainLocal -Path $adNamespacePermsOu `
        -Description "Edit GPO [$serverGpoName] - $AppName ($Tier)"
    if ($HasSaw) {
        _EnsureAdkGroup -Name $sawGpoEditPm -Scope DomainLocal -Path $adNamespacePermsOu `
            -Description "Edit GPO [$sawGpoName] - $AppName ($Tier)"
    }

    # ---------- Structural memberships ----------
    # These follow directly from the app definition and apply to every app.
    #
    # Role -> Pm wiring:
    #   Admin -> LocalAdmin on servers (always) and SAW (HasSaw)
    #   User  -> InteractiveLogon + RDP on SAW (HasSaw)
    #   Svc   -> ServiceLogon on servers (always)
    #
    # LocalAdmin nesting (implication: local admin can also do everything below):
    #   Srv-LocalAdmin  -> Srv-InteractiveLogon, Srv-RdpLogon, Srv-Laps{Read,Reset,Decrypt}Pwd
    #   SAW-LocalAdmin  -> SAW-InteractiveLogon, SAW-RdpLogon, SAW-Laps{Read,Reset,Decrypt}Pwd
    _EnsureAdkMembership -Member "Adm-$Tier-$AppName-Admin" -MemberOf "Pm-$Tier-$AppName-Srv-LocalAdmin"
    _EnsureAdkMembership -Member "Svc-$Tier-$AppName-ServiceAccount" -MemberOf "Pm-$Tier-$AppName-Srv-ServiceLogon"

    # LocalAdmin implies interactive, RDP, and LAPS on servers
    foreach ($implied in @('InteractiveLogon','RdpLogon','LapsReadPwd','LapsResetPwd','LapsDecryptPwd')) {
        _EnsureAdkMembership -Member "Pm-$Tier-$AppName-Srv-LocalAdmin" -MemberOf "Pm-$Tier-$AppName-Srv-$implied"
    }

    # AMA -> Admin role nesting
    if ($HasAma) {
        _EnsureAdkMembership -Member "Ama-$Tier-$AppName-Admin" -MemberOf "Adm-$Tier-$AppName-Admin"
    }

    if ($HasSaw) {
        _EnsureAdkMembership -Member "Adm-$Tier-$AppName-Admin" -MemberOf "Pm-$Tier-$AppName-SAW-LocalAdmin"
        _EnsureAdkMembership -Member "Adm-$Tier-$AppName-User"  -MemberOf "Pm-$Tier-$AppName-SAW-InteractiveLogon"
        _EnsureAdkMembership -Member "Adm-$Tier-$AppName-User"  -MemberOf "Pm-$Tier-$AppName-SAW-RdpLogon"

        # LocalAdmin implies interactive, RDP, and LAPS on SAW
        foreach ($implied in @('InteractiveLogon','RdpLogon','LapsReadPwd','LapsResetPwd','LapsDecryptPwd')) {
            _EnsureAdkMembership -Member "Pm-$Tier-$AppName-SAW-LocalAdmin" -MemberOf "Pm-$Tier-$AppName-SAW-$implied"
        }
    }

    # ---------- GPO import + link ----------
    $gpoBackupPath = $Context.GpoPath
    if ($gpoBackupPath -and (Test-Path $gpoBackupPath)) {
        # Server GPO - migration table built dynamically from backup metadata.
        $adminName      = if ($Context.BuiltinAdministratorName) { $Context.BuiltinAdministratorName } else { 'Administrator' }
        $localAdminName = if ($Context.LocalAdministratorName)   { $Context.LocalAdministratorName }   else { 'Administrator' }
        _ImportAdkAppGpo `
            -GpoName $serverGpoName `
            -BackupGpoName $ServerGpoBackup `
            -GpoPath $gpoBackupPath `
            -DomainDnsName $Context.DomainDnsName `
            -TargetOu $serverOuDn `
            -PmPattern "Pm-$Tier-$AppName-Srv" `
            -BuiltinAdministratorName $adminName `
            -LocalAdministratorName $localAdminName `
            -ForceImport ([bool]$Context.Force)

        if ($HasSaw) {
            _ImportAdkAppGpo `
                -GpoName $sawGpoName `
                -BackupGpoName $SawGpoBackup `
                -GpoPath $gpoBackupPath `
                -DomainDnsName $Context.DomainDnsName `
                -TargetOu $sawOuDn `
                -PmPattern "Pm-$Tier-$AppName-SAW" `
                -BuiltinAdministratorName $adminName `
                -LocalAdministratorName $localAdminName `
                -ForceImport ([bool]$Context.Force)
        }
    } else {
        Write-Verbose 'No GPO backup path configured; skipping GPO import/link for this app.'
    }

    Write-AdkLog "App [$Tier/$AppName] provisioned (HasSaw=$HasSaw, HasAma=$HasAma)" -Success
}

# Helpers shared with the dispatcher. Underscore prefix marks them as
# module-private; they're not in the manifest's FunctionsToExport.

function _EnsureAdkGroup {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)] [string] $Name,
        [Parameter(Mandatory)] [string] $Scope,
        [Parameter(Mandatory)] [string] $Path,
        [string] $Description = ''
    )
    try {
        Get-ADGroup -Identity $Name -ErrorAction Stop | Out-Null
        Write-Verbose "  group exists: $Name"
    } catch {
        if (-not $PSCmdlet.ShouldProcess($Name, "Create $Scope group in $Path")) { return }
        $params = @{
            Name          = $Name
            DisplayName   = $Name
            GroupCategory = 'Security'
            GroupScope    = $Scope
            Path          = $Path
            Confirm       = $false
        }
        if ($Description) { $params['Description'] = $Description }
        try {
            New-ADGroup @params | Out-Null
            Write-AdkLog "  created group [$Name]"
        } catch {
            Write-AdkLog "  failed creating group [$Name] in [$Path]: $($_.Exception.Message)" -IsError
        }
    }
}

function _EnsureAdkMembership {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)] [string] $Member,
        [Parameter(Mandatory)] [string] $MemberOf
    )
    $memberObj = $null; $targetObj = $null
    try { $memberObj = Get-ADGroup $Member  -ErrorAction Stop } catch { }
    try { $targetObj = Get-ADGroup $MemberOf -ErrorAction Stop } catch { }

    if (-not $memberObj -or -not $targetObj) {
        if ($WhatIfPreference) {
            Write-Verbose "  [WhatIf] would add [$Member] -> [$MemberOf] (groups not yet provisioned)"
        }
        return
    }

    $currentMembers = @(Get-ADGroupMember $targetObj -ErrorAction SilentlyContinue |
                        Select-Object -ExpandProperty SamAccountName)
    if ($currentMembers -contains $Member) {
        Write-Verbose "  [$Member] already in [$MemberOf]"
        return
    }

    if ($PSCmdlet.ShouldProcess($MemberOf, "Add member [$Member]")) {
        try {
            Add-ADGroupMember $targetObj -Members $memberObj
        } catch {
            Write-AdkLog "  failed adding [$Member] to [$MemberOf]: $($_.Exception.Message)" -Warning
        }
    }
}

function _ImportAdkAppGpo {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)] [string]   $GpoName,
        [Parameter(Mandatory)] [string]   $BackupGpoName,
        [Parameter(Mandatory)] [string]   $GpoPath,
        [Parameter(Mandatory)] [string]   $DomainDnsName,
        [Parameter(Mandatory)] [string]   $TargetOu,
        [Parameter(Mandatory)] [string]   $PmPattern,
        [string] $BuiltinAdministratorName = 'Administrator',
        [string] $LocalAdministratorName = 'Administrator',
        [bool] $ForceImport = $false
    )

    $existing = Get-GPO -Name $GpoName -ErrorAction SilentlyContinue
    if ($existing -and -not $ForceImport) {
        Write-AdkLog "  [$GpoName] already exists" -Step
    } else {
        $migPath = Join-Path $GpoPath "$GpoName.migtable"

        # Build migration table dynamically from the backup's own metadata.
        New-AdkSodMigTable -GpoBackupPath $GpoPath `
                           -BackupGpoName $BackupGpoName `
                           -PmPattern $PmPattern `
                           -DomainDnsName $DomainDnsName `
                           -OutputPath $migPath `
                           -BuiltinAdministratorName $BuiltinAdministratorName `
                           -LocalAdministratorName $LocalAdministratorName

        if ($PSCmdlet.ShouldProcess($GpoName, "Import GPO from backup [$BackupGpoName]")) {
            try {
                Import-Gpo -BackupGpoName $BackupGpoName -Path $GpoPath `
                           -TargetName $GpoName -CreateIfNeeded `
                           -MigrationTable $migPath | Out-Null
                Write-AdkLog "  imported GPO [$GpoName]"
            } catch {
                Write-AdkLog "  failed importing GPO [$GpoName]: $($_.Exception.Message)" -Warning
            }
        }
    }

    # Link is idempotent - always ensure it exists.
    if ($PSCmdlet.ShouldProcess($TargetOu, "Link GPO [$GpoName]")) {
        try {
            New-GPLink -Name $GpoName -Target $TargetOu -LinkEnabled Yes | Out-Null
        } catch {
            if ($_.Exception.Message -notlike '*already linked*') {
                Write-AdkLog "  failed linking [$GpoName] to [$TargetOu]: $($_.Exception.Message)" -Warning
            }
        }
    }
}