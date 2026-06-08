# Smaller verbs lumped together. Each is a thin wrapper over Set-AdAce
# that targets a specific scenario.

# ----- ResetComputerPwd ------------------------------------------------
# User-Force-Change-Password extended right on Computer descendants.
# Distinct from full ManageComputers; useful for re-join workflows.
function Set-Verb-ResetComputerPwd {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $ObjectDN,
        [Parameter(Mandatory)] [string] $SubjectDN,
        [hashtable] $Parameters = @{}
    )
    $inhName = if ($Parameters['Inheritance']) { $Parameters['Inheritance'] } else { 'All' }
    $inh = [System.DirectoryServices.ActiveDirectorySecurityInheritance] $inhName

    $computerClass = Get-AdkClassGuid -LdapClassName 'Computer'
    $forceChange = Get-AdkExtendedRightGuid -RightName 'User-Force-Change-Password'

    Set-AdAce -ObjectDN $ObjectDN -SubjectDN $SubjectDN -RuleType Allow `
              -Rights ([System.DirectoryServices.ActiveDirectoryRights]::ExtendedRight) `
              -ExtendedRight $forceChange `
              -InheritanceType $inh -InheritObjectType $computerClass
}

# ----- MoveUser / MoveComputer -----------------------------------------
# Move a User/Computer into the OU (write cn/name on the moved object,
# plus Create-Child on the target so it can land here). Source-side
# delete-child is also required but is granted by the source OU's
# delegation, not this verb.
function _MoveObject {
    [CmdletBinding()]
    param(
        [string] $ObjectDN,
        [string] $SubjectDN,
        [string] $InheritName,
        [string] $LdapClassName
    )
    $inh = [System.DirectoryServices.ActiveDirectorySecurityInheritance] $InheritName

    $classGuid = Get-AdkClassGuid -LdapClassName $LdapClassName
    $cn        = Get-AdkAttributeGuid -AttributeName 'cn'
    $name      = Get-AdkAttributeGuid -AttributeName 'name'

    Set-AdAllowCreate -ObjectDN $ObjectDN -SubjectDN $SubjectDN `
                      -ObjectLdapClassName $LdapClassName -Inheritance $inh

    $rw = [System.DirectoryServices.ActiveDirectoryRights]::WriteProperty -bor `
          [System.DirectoryServices.ActiveDirectoryRights]::ReadProperty

    Set-AdAce -ObjectDN $ObjectDN -SubjectDN $SubjectDN -RuleType Allow `
              -Rights $rw -ObjectType $cn `
              -InheritanceType $inh -InheritObjectType $classGuid
    Set-AdAce -ObjectDN $ObjectDN -SubjectDN $SubjectDN -RuleType Allow `
              -Rights $rw -ObjectType $name `
              -InheritanceType $inh -InheritObjectType $classGuid
}

function Set-Verb-MoveUser {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $ObjectDN,
        [Parameter(Mandatory)] [string] $SubjectDN,
        [hashtable] $Parameters = @{}
    )
    $inh = if ($Parameters['Inheritance']) { $Parameters['Inheritance'] } else { 'All' }
    _MoveObject -ObjectDN $ObjectDN -SubjectDN $SubjectDN -InheritName $inh -LdapClassName 'User'
}

function Set-Verb-MoveComputer {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $ObjectDN,
        [Parameter(Mandatory)] [string] $SubjectDN,
        [hashtable] $Parameters = @{}
    )
    $inh = if ($Parameters['Inheritance']) { $Parameters['Inheritance'] } else { 'All' }
    _MoveObject -ObjectDN $ObjectDN -SubjectDN $SubjectDN -InheritName $inh -LdapClassName 'Computer'
}

# ----- WriteSpn --------------------------------------------------------
# Validated-write SPN on Computer descendants. Used by service teams
# that need to register Kerberos SPNs without holding full
# ManageComputers.
function Set-Verb-WriteSpn {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $ObjectDN,
        [Parameter(Mandatory)] [string] $SubjectDN,
        [hashtable] $Parameters = @{}
    )
    $inhName = if ($Parameters['Inheritance']) { $Parameters['Inheritance'] } else { 'All' }
    $inh = [System.DirectoryServices.ActiveDirectorySecurityInheritance] $inhName

    $computerClass = Get-AdkClassGuid -LdapClassName 'Computer'
    $validatedSpn = Get-AdkExtendedRightGuid -RightName 'Validated-SPN'
    $spn          = Get-AdkAttributeGuid -AttributeName 'servicePrincipalName'

    Set-AdAce -ObjectDN $ObjectDN -SubjectDN $SubjectDN -RuleType Allow `
              -Rights ([System.DirectoryServices.ActiveDirectoryRights]::Self) `
              -ObjectType $validatedSpn `
              -InheritanceType $inh -InheritObjectType $computerClass

    Set-AdAce -ObjectDN $ObjectDN -SubjectDN $SubjectDN -RuleType Allow `
              -Rights ([System.DirectoryServices.ActiveDirectoryRights]::WriteProperty) `
              -ObjectType $spn `
              -InheritanceType $inh -InheritObjectType $computerClass
}

# ----- ManageContacts --------------------------------------------------
# Same shape as ManageUsers but targeting Contact class. Used for
# Exchange-style mail contacts.
function Set-Verb-ManageContacts {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $ObjectDN,
        [Parameter(Mandatory)] [string] $SubjectDN,
        [hashtable] $Parameters = @{}
    )
    $inhName = if ($Parameters['Inheritance']) { $Parameters['Inheritance'] } else { 'All' }
    $inh = [System.DirectoryServices.ActiveDirectorySecurityInheritance] $inhName

    $contactClass = Get-AdkClassGuid -LdapClassName 'Contact'

    Set-AdAllowCreate -ObjectDN $ObjectDN -SubjectDN $SubjectDN -ObjectLdapClassName 'Contact' -Inheritance $inh
    Set-AdAllowDelete -ObjectDN $ObjectDN -SubjectDN $SubjectDN -ObjectLdapClassName 'Contact' -Inheritance $inh

    $rw = [System.DirectoryServices.ActiveDirectoryRights]::WriteProperty -bor `
          [System.DirectoryServices.ActiveDirectoryRights]::ReadProperty

    foreach ($attrName in @('displayName', 'mail', 'description', 'givenName', 'sn')) {
        $g = Get-AdkAttributeGuid -AttributeName $attrName
        Set-AdAce -ObjectDN $ObjectDN -SubjectDN $SubjectDN -RuleType Allow `
                  -Rights $rw -ObjectType $g `
                  -InheritanceType $inh -InheritObjectType $contactClass
    }
}

# ----- CreateChildOU ---------------------------------------------------
# Allow a role to create child organizationalUnit objects under the
# target OU. Used by department admins who want their own sub-OUs.
function Set-Verb-CreateChildOU {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $ObjectDN,
        [Parameter(Mandatory)] [string] $SubjectDN,
        [hashtable] $Parameters = @{}
    )
    $inhName = if ($Parameters['Inheritance']) { $Parameters['Inheritance'] } else { 'All' }
    $inh = [System.DirectoryServices.ActiveDirectorySecurityInheritance] $inhName

    Set-AdAllowCreate -ObjectDN $ObjectDN -SubjectDN $SubjectDN `
                      -ObjectLdapClassName 'organizationalUnit' -Inheritance $inh
}

# ----- ReadAllOnTier ---------------------------------------------------
# Generic read on all descendants of the target OU. Used for audit /
# read-only-admin roles. Pair with Pm AD * ReadAllProperties Pm groups.
function Set-Verb-ReadAllOnTier {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $ObjectDN,
        [Parameter(Mandatory)] [string] $SubjectDN,
        [hashtable] $Parameters = @{}
    )
    $inhName = if ($Parameters['Inheritance']) { $Parameters['Inheritance'] } else { 'All' }
    $inh = [System.DirectoryServices.ActiveDirectorySecurityInheritance] $inhName

    Set-AdAce -ObjectDN $ObjectDN -SubjectDN $SubjectDN -RuleType Allow `
              -Rights ([System.DirectoryServices.ActiveDirectoryRights]::GenericRead) `
              -InheritanceType $inh
}

# ----- ApplyPso --------------------------------------------------------
# Write msDS-PSOAppliesTo on a specific PSO (Password Settings Object).
# OuName in the CSV should be the FULL DN of the PSO object (this verb
# treats ObjectDN as a literal DN, not an OU token).
function Set-Verb-ApplyPso {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $ObjectDN,
        [Parameter(Mandatory)] [string] $SubjectDN,
        [hashtable] $Parameters = @{}
    )

    $schema = Get-AdkSchema
    if (-not $schema.GuidByName.ContainsKey('msDS-PSOAppliesTo')) {
        Write-AdkLog '  msDS-PSOAppliesTo not present in schema; skipping ApplyPso' -Warning
        return
    }
    $appliesTo = Get-AdkAttributeGuid -AttributeName 'msDS-PSOAppliesTo'

    $rw = [System.DirectoryServices.ActiveDirectoryRights]::WriteProperty -bor `
          [System.DirectoryServices.ActiveDirectoryRights]::ReadProperty

    Set-AdAce -ObjectDN $ObjectDN -SubjectDN $SubjectDN -RuleType Allow `
              -Rights $rw -ObjectType $appliesTo
}
