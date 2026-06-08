# Verbs for Entra Connect / Cloud Sync hybrid identity wiring. These
# delegate the ACEs the Entra service account needs for each optional
# feature. The role group inherits whichever subset of these Pm groups
# is appropriate for the agent's configuration.
#
# Both Cloud Sync and Entra Connect Sync use these primitives; the union
# of permissions is what's granted by the kit. The agent install /
# configuration decides which features actually run.

# ----- EntraDirSyncRead ------------------------------------------------
# Replicating Directory Changes on the domain root. The baseline for all
# Entra hybrid sync (Cloud Sync, Connect Sync). ObjectDN is expected to
# be the domain root.
function Set-Verb-EntraDirSyncRead {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $ObjectDN,
        [Parameter(Mandatory)] [string] $SubjectDN,
        [hashtable] $Parameters = @{}
    )
    # The CN in CN=Extended-Rights is "DS-Replication-Get-Changes"; the
    # displayName (what GPMC shows) is "Replicating Directory Changes".
    $right = Get-AdkExtendedRightGuid -RightName 'DS-Replication-Get-Changes'
    Set-AdAce -ObjectDN $ObjectDN -SubjectDN $SubjectDN -RuleType Allow `
              -Rights ([System.DirectoryServices.ActiveDirectoryRights]::ExtendedRight) `
              -ExtendedRight $right
}

# ----- EntraDirSyncReadAll ---------------------------------------------
# Replicating Directory Changes All on the domain root. Needed when
# Password Hash Sync is enabled in the agent.
function Set-Verb-EntraDirSyncReadAll {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $ObjectDN,
        [Parameter(Mandatory)] [string] $SubjectDN,
        [hashtable] $Parameters = @{}
    )
    $right = Get-AdkExtendedRightGuid -RightName 'DS-Replication-Get-Changes-All'
    Set-AdAce -ObjectDN $ObjectDN -SubjectDN $SubjectDN -RuleType Allow `
              -Rights ([System.DirectoryServices.ActiveDirectoryRights]::ExtendedRight) `
              -ExtendedRight $right
}

# ----- EntraWriteConsistencyGuid ---------------------------------------
# Write mS-DS-ConsistencyGuid on User (and optionally Group) descendants.
# Required for stable sourceAnchor across re-installs.
function Set-Verb-EntraWriteConsistencyGuid {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $ObjectDN,
        [Parameter(Mandatory)] [string] $SubjectDN,
        [hashtable] $Parameters = @{}
    )
    $inhName = if ($Parameters['Inheritance']) { $Parameters['Inheritance'] } else { 'All' }
    $inh = [System.DirectoryServices.ActiveDirectorySecurityInheritance] $inhName

    $userClass  = Get-AdkClassGuid -LdapClassName 'User'
    $groupClass = Get-AdkClassGuid -LdapClassName 'Group'
    $cg         = Get-AdkAttributeGuid -AttributeName 'mS-DS-ConsistencyGuid'

    $rw = [System.DirectoryServices.ActiveDirectoryRights]::WriteProperty -bor `
          [System.DirectoryServices.ActiveDirectoryRights]::ReadProperty

    Set-AdAce -ObjectDN $ObjectDN -SubjectDN $SubjectDN -RuleType Allow `
              -Rights $rw -ObjectType $cg -InheritanceType $inh -InheritObjectType $userClass
    Set-AdAce -ObjectDN $ObjectDN -SubjectDN $SubjectDN -RuleType Allow `
              -Rights $rw -ObjectType $cg -InheritanceType $inh -InheritObjectType $groupClass
}

# ----- EntraPwWriteback ------------------------------------------------
# Password writeback: change/reset password + write lockoutTime/pwdLastSet
# on User descendants. Mirrors what Entra documentation calls out.
function Set-Verb-EntraPwWriteback {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $ObjectDN,
        [Parameter(Mandatory)] [string] $SubjectDN,
        [hashtable] $Parameters = @{}
    )
    $inhName = if ($Parameters['Inheritance']) { $Parameters['Inheritance'] } else { 'All' }
    $inh = [System.DirectoryServices.ActiveDirectorySecurityInheritance] $inhName

    $userClass     = Get-AdkClassGuid -LdapClassName 'User'
    $forceChange   = Get-AdkExtendedRightGuid -RightName 'User-Force-Change-Password'
    $changePwd     = Get-AdkExtendedRightGuid -RightName 'User-Change-Password'
    $pwdLastSet    = Get-AdkAttributeGuid -AttributeName 'pwdLastSet'
    $lockoutTime   = Get-AdkAttributeGuid -AttributeName 'lockoutTime'

    Set-AdAce -ObjectDN $ObjectDN -SubjectDN $SubjectDN -RuleType Allow `
              -Rights ([System.DirectoryServices.ActiveDirectoryRights]::ExtendedRight) `
              -ExtendedRight $forceChange -InheritanceType $inh -InheritObjectType $userClass

    Set-AdAce -ObjectDN $ObjectDN -SubjectDN $SubjectDN -RuleType Allow `
              -Rights ([System.DirectoryServices.ActiveDirectoryRights]::ExtendedRight) `
              -ExtendedRight $changePwd -InheritanceType $inh -InheritObjectType $userClass

    $rw = [System.DirectoryServices.ActiveDirectoryRights]::WriteProperty -bor `
          [System.DirectoryServices.ActiveDirectoryRights]::ReadProperty

    Set-AdAce -ObjectDN $ObjectDN -SubjectDN $SubjectDN -RuleType Allow `
              -Rights $rw -ObjectType $pwdLastSet -InheritanceType $inh -InheritObjectType $userClass

    Set-AdAce -ObjectDN $ObjectDN -SubjectDN $SubjectDN -RuleType Allow `
              -Rights $rw -ObjectType $lockoutTime -InheritanceType $inh -InheritObjectType $userClass
}

# ----- EntraExchangeWriteback ------------------------------------------
# Hybrid Exchange writeback: grant Read/Write on the Exchange-Information
# property set across User and Group descendants. The specific attributes
# this covers vary by Exchange schema version (proxyAddresses,
# msExchSafe/BlockedSendersHash, etc.).
function Set-Verb-EntraExchangeWriteback {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $ObjectDN,
        [Parameter(Mandatory)] [string] $SubjectDN,
        [hashtable] $Parameters = @{}
    )
    $inhName = if ($Parameters['Inheritance']) { $Parameters['Inheritance'] } else { 'All' }
    $inh = [System.DirectoryServices.ActiveDirectorySecurityInheritance] $inhName

    $userClass  = Get-AdkClassGuid -LdapClassName 'User'
    $groupClass = Get-AdkClassGuid -LdapClassName 'Group'

    # Exchange-Information property set may not exist on schemas that
    # haven't been extended by Exchange. Skip the grant if it's missing,
    # rather than failing the deploy.
    $schema = Get-AdkSchema
    if (-not $schema.ExtendedRights.ContainsKey('Exchange-Information')) {
        Write-AdkLog '  Exchange-Information property set not present in schema; skipping EntraExchangeWriteback' -Warning
        return
    }

    $exchInfo = Get-AdkExtendedRightGuid -RightName 'Exchange-Information'

    foreach ($cls in @($userClass, $groupClass)) {
        foreach ($access in @('Read','Write')) {
            Set-AdAce -ObjectDN $ObjectDN -SubjectDN $SubjectDN -RuleType Allow `
                      -Rights ([System.DirectoryServices.ActiveDirectoryRights]::ExtendedRight) `
                      -ExtendedRight $exchInfo `
                      -PropertyAccess ([System.DirectoryServices.PropertyAccess] $access) `
                      -InheritanceType $inh -InheritObjectType $cls
        }
    }
}

# ----- EntraDeviceWriteback --------------------------------------------
# Hybrid Azure AD Join: Create/Delete Computer in the registered-devices
# CN, plus writes on descendant Computer objects. The default target is
# CN=RegisteredDevices,<configurationNC> (this is configuration NC scoped,
# not domain NC).
function Set-Verb-EntraDeviceWriteback {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $ObjectDN,
        [Parameter(Mandatory)] [string] $SubjectDN,
        [hashtable] $Parameters = @{}
    )
    $inhName = if ($Parameters['Inheritance']) { $Parameters['Inheritance'] } else { 'All' }
    $inh = [System.DirectoryServices.ActiveDirectorySecurityInheritance] $inhName

    $computerClass = Get-AdkClassGuid -LdapClassName 'Computer'

    Set-AdAllowCreate -ObjectDN $ObjectDN -SubjectDN $SubjectDN -ObjectLdapClassName 'Computer' -Inheritance $inh
    Set-AdAllowDelete -ObjectDN $ObjectDN -SubjectDN $SubjectDN -ObjectLdapClassName 'Computer' -Inheritance $inh

    # Write the msDS device-* attributes if present (older schemas
    # lack them). Tolerate absence to keep older schemas deployable.
    $schema = Get-AdkSchema
    $optionalAttrs = @('msDS-IsCompromised', 'msDS-DeviceID', 'msDS-DeviceObjectVersion', 'msDS-DeviceOSType', 'msDS-DeviceOSVersion')
    $rw = [System.DirectoryServices.ActiveDirectoryRights]::WriteProperty -bor `
          [System.DirectoryServices.ActiveDirectoryRights]::ReadProperty

    foreach ($attr in $optionalAttrs) {
        if (-not $schema.GuidByName.ContainsKey($attr)) {
            Write-Verbose "  attribute [$attr] not present in schema; skipping"
            continue
        }
        $g = Get-AdkAttributeGuid -AttributeName $attr
        Set-AdAce -ObjectDN $ObjectDN -SubjectDN $SubjectDN -RuleType Allow `
                  -Rights $rw -ObjectType $g -InheritanceType $inh -InheritObjectType $computerClass
    }
}

# ----- EntraGroupWriteback ---------------------------------------------
# Group writeback v2: Create/Delete Group + write member/displayName/
# description + write msDS-WritebackEnabled (if schema present).
function Set-Verb-EntraGroupWriteback {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $ObjectDN,
        [Parameter(Mandatory)] [string] $SubjectDN,
        [hashtable] $Parameters = @{}
    )
    $inhName = if ($Parameters['Inheritance']) { $Parameters['Inheritance'] } else { 'All' }
    $inh = [System.DirectoryServices.ActiveDirectorySecurityInheritance] $inhName

    $groupClass = Get-AdkClassGuid -LdapClassName 'Group'

    Set-AdAllowCreate -ObjectDN $ObjectDN -SubjectDN $SubjectDN -ObjectLdapClassName 'Group' -Inheritance $inh
    Set-AdAllowDelete -ObjectDN $ObjectDN -SubjectDN $SubjectDN -ObjectLdapClassName 'Group' -Inheritance $inh

    $rw = [System.DirectoryServices.ActiveDirectoryRights]::WriteProperty -bor `
          [System.DirectoryServices.ActiveDirectoryRights]::ReadProperty

    foreach ($attr in @('member', 'displayName', 'description')) {
        $g = Get-AdkAttributeGuid -AttributeName $attr
        Set-AdAce -ObjectDN $ObjectDN -SubjectDN $SubjectDN -RuleType Allow `
                  -Rights $rw -ObjectType $g -InheritanceType $inh -InheritObjectType $groupClass
    }

    $schema = Get-AdkSchema
    if ($schema.GuidByName.ContainsKey('msDS-WritebackEnabled')) {
        $g = Get-AdkAttributeGuid -AttributeName 'msDS-WritebackEnabled'
        Set-AdAce -ObjectDN $ObjectDN -SubjectDN $SubjectDN -RuleType Allow `
                  -Rights $rw -ObjectType $g -InheritanceType $inh -InheritObjectType $groupClass
    }
}

# ----- EntraSeamlessSso ------------------------------------------------
# Seamless SSO: a one-time setup that creates the AZUREADSSOACC computer
# account in the chosen OU. Grant Create-Computer on that OU; nothing
# inherited.
function Set-Verb-EntraSeamlessSso {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $ObjectDN,
        [Parameter(Mandatory)] [string] $SubjectDN,
        [hashtable] $Parameters = @{}
    )
    Set-AdAllowCreate -ObjectDN $ObjectDN -SubjectDN $SubjectDN -ObjectLdapClassName 'Computer' `
                      -Inheritance ([System.DirectoryServices.ActiveDirectorySecurityInheritance]::None)
}
