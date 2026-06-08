# Auto-generate a human-readable description for a group based on its name.
#
# This keeps descriptions consistent without maintaining a parallel column
# in Groups.csv. The naming convention is deterministic enough to derive
# clear descriptions from the prefix and component tokens.
#
# Only Groups.csv / department-role groups go through this path. Per-app
# groups created by New-AdkApp already carry hand-written descriptions via
# _EnsureAdkGroup -Description.

function Get-AdkGroupDescription {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string] $Name
    )

    # ---- human-readable action suffixes ----
    $act = @{
        JoinComputer      = 'Join computers to domain'
        InteractiveLogon  = 'Allow interactive logon'
        RdpLogon          = 'Allow Remote Desktop logon'
        LocalAdmin        = 'Local Administrators'
        ServiceLogon      = 'Allow service logon'
        ManageComputer    = 'Manage computer accounts'
        ReadAllProperties = 'Read all properties'
        PwReset           = 'Reset passwords'
        Create            = 'Create'
        Delete            = 'Delete'
        Manage            = 'Manage'
        FullControl       = 'Full control'
        LapsReadPwd       = 'Read LAPS passwords'
        LapsResetPwd      = 'Reset LAPS passwords'
        LapsDecryptPwd    = 'Decrypt LAPS passwords'
    }

    # ---- AD object class descriptions ----
    $obj = @{
        'User-Employee'       = 'employee accounts'
        'User-External'       = 'external accounts'
        'User-Robot'          = 'robot accounts'
        'User-Shared'         = 'shared accounts'
        'User-ServiceAccount' = 'service accounts'
        'User-Admin'          = 'admin accounts'
        'User-User'           = 'tier user accounts'
        'Group-Role'          = 'role groups'
        'Group-Permission'    = 'permission groups'
        'Group-Claim'         = 'claim groups'
        'Group-AMA'           = 'AMA groups'
    }

    # ---- preposition per action (for AD object-class permissions) ----
    $prep = @{
        Create            = ''
        Delete            = ''
        Manage            = ''
        FullControl       = 'of'
        ReadAllProperties = 'of'
        PwReset           = 'for'
    }

    # ================================================================
    #  Claim groups
    # ================================================================
    if ($Name -eq 'Claim-SmartCardLogon') {
        return 'Claim: smart card logon required'
    }
    if ($Name -match '^Claim-(T\d|EA)-(Admin|User|ServiceAccount)$') {
        $map = @{ Admin = 'administrator'; User = 'user'; ServiceAccount = 'service' }
        return "Claim: $($Matches[1]) $($map[$Matches[2]]) accounts"
    }

    # ================================================================
    #  AMA groups
    # ================================================================
    # Per-app AMA (3+ parts): Ama-<Tier>-<App>-Admin/User
    if ($Name -match '^Ama-(T\d|EA)-(.+)-(Admin|User)$') {
        $r = if ($Matches[3] -eq 'Admin') { 'administrators' } else { 'users' }
        return "AMA: $($Matches[2]) $r ($($Matches[1]))"
    }
    # Tier-level AMA (no app): Ama-<Tier>-Admin/User
    if ($Name -match '^Ama-(T\d|EA)-(Admin|User)$') {
        $r = if ($Matches[2] -eq 'Admin') { 'administrators' } else { 'users' }
        return "AMA: $($Matches[1]) $r"
    }

    # ================================================================
    #  PAW / SAW computer groups
    # ================================================================
    if ($Name -match '^PAW-(T\d)$') {
        return "Privileged Access Workstations ($($Matches[1]))"
    }

    # ================================================================
    #  Server groups (Srv-)
    # ================================================================
    if ($Name -match '^Srv-(T\d|EA)-(.+)$') {
        return "$($Matches[2]) server group ($($Matches[1]))"
    }

    # ================================================================
    #  Service account roles (Svc-)
    # ================================================================
    if ($Name -match '^Svc-(T\d|EA)-(.+)-ServiceAccount$') {
        return "$($Matches[2]) service accounts ($($Matches[1]))"
    }

    # ================================================================
    #  Admin / user roles (Adm-)
    # ================================================================
    if ($Name -match '^Adm-(T\d|EA)-(.+)-(Admin|User)$') {
        $r = if ($Matches[3] -eq 'Admin') { 'administrators' } else { 'users' }
        return "$($Matches[2]) $r ($($Matches[1]))"
    }
    if ($Name -match '^Adm-(T\d|EA)-(.+)$') {
        return "$($Matches[2]) role ($($Matches[1]))"
    }

    # ================================================================
    #  Device groups (Device-Org-)
    # ================================================================
    if ($Name -match '^Device-Org-(.+)$') {
        return "Device group: $($Matches[1])"
    }

    # ================================================================
    #  Organisation roles (Role-Org-)
    # ================================================================
    if ($Name -match '^Role-Org-(.+)$') {
        return "Organisation role: $($Matches[1])"
    }

    # ================================================================
    #  Permission groups (Pm-)
    # ================================================================
    if ($Name -match '^Pm-') {

        # -- Entra Sync (space in name; must match before hyphen regexes) --
        if ($Name -match '^Pm-AD-Entra Sync-(.+)$') {
            $entra = @{
                DirSyncRead          = 'read directory sync attributes'
                DirSyncReadAll       = 'read all directory sync attributes'
                WriteConsistencyGuid = 'write mS-DS-ConsistencyGuid'
                PwWriteback          = 'password writeback'
                ExchangeWriteback    = 'Exchange attribute writeback'
                DeviceWriteback      = 'device writeback'
                GroupWriteback       = 'group writeback'
                SeamlessSso          = 'Seamless SSO computer account management'
            }
            $d = if ($entra.ContainsKey($Matches[1])) { $entra[$Matches[1]] } else { $Matches[1] }
            return "Entra Connect: $d"
        }

        # -- GPO link: Pm-AD-GPO-Link-<Scope> --
        if ($Name -match '^Pm-AD-GPO-Link-(.+)$') {
            return "Link GPOs at $($Matches[1]) scope"
        }
        # -- GPO link: Pm-AD-<Tier>-GPO-Link --
        if ($Name -match '^Pm-AD-(T\d|EA)-GPO-Link$') {
            return "Link GPOs to $($Matches[1]) OUs"
        }

        # -- AD-namespace, 5 tokens: Pm-<Tier>-AD-<Class>-<SubClass>-<Action> --
        #    e.g. Pm-T0-AD-User-Admin-FullControl, Pm-EA-AD-Group-Role-Create
        if ($Name -match '^Pm-(T\d|EA)-AD-(\w+)-(\w+)-(\w+)$') {
            $tier = $Matches[1]
            $key  = "$($Matches[2])-$($Matches[3])"
            $a    = $Matches[4]
            $od   = if ($obj.ContainsKey($key)) { $obj[$key] } else { "$($Matches[3]) $($Matches[2]) objects" }
            $ad   = if ($act.ContainsKey($a))   { $act[$a]   } else { $a }
            $p    = if ($prep.ContainsKey($a))   { $prep[$a]  } else { 'of' }
            if ($p) { return "$ad $p $tier $od" }
            return "$ad $tier $od"
        }

        # -- AD-namespace, 4 tokens: Pm-<Tier>-AD-<Target>-<Action> --
        #    e.g. Pm-T0-AD-PAW-LapsReadPwd, Pm-EA-AD-Client-ManageComputer
        if ($Name -match '^Pm-(T\d|EA)-AD-(\w+)-(\w+)$') {
            $tier   = $Matches[1]
            $target = $Matches[2]
            $a      = $Matches[3]
            $ad     = if ($act.ContainsKey($a)) { $act[$a] } else { $a }
            return "$ad on $tier ${target}s"
        }

        # -- AD-namespace, 3 tokens: Pm-<Tier>-AD-<Action> --
        #    e.g. Pm-T0-AD-JoinComputer
        if ($Name -match '^Pm-(T\d|EA)-AD-(\w+)$') {
            $tier = $Matches[1]
            $a    = $Matches[2]
            $ad   = if ($act.ContainsKey($a)) { $act[$a] } else { $a }
            return "$ad ($tier)"
        }

        # -- OS-namespace: Pm-<Tier>-<Resource>-<Action> --
        #    e.g. Pm-T0-PAW-InteractiveLogon, Pm-EA-Client-LocalAdmin
        if ($Name -match '^Pm-(T\d|EA)-(.+)-(\w+)$') {
            $tier = $Matches[1]
            $res  = $Matches[2]
            $a    = $Matches[3]
            $ad   = if ($act.ContainsKey($a)) { $act[$a] } else { $a }
            return "$ad on $tier ${res}s"
        }

        # -- Catch-all Pm --
        return "Permission: $($Name -replace '^Pm-', '')"
    }

    # ================================================================
    #  Fallback - return empty string (caller can decide)
    # ================================================================
    return ''
}
