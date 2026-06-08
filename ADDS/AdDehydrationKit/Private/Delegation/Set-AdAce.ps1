# Add a single ACE to an AD object's ACL. Idempotent - does nothing if an
# equivalent ACE is already present. Replaces the old Set-Delegation
# function in Delegation-Functions.ps1 and folds in Section3.6 idempotency.
#
# Three families of ACE are constructed depending on the inputs:
#   * Extended right         - single control access (e.g. Reset Password)
#   * Property set           - read/write a named property set
#   * Property/object access - read/write a specific attribute or object
#                              class GUID, or generic rights
#
# The function picks the right constructor based on the combination of
# parameters supplied.

function Set-AdAce {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        [string] $ObjectDN,

        [Parameter(Mandatory)]
        [string] $SubjectDN,

        [System.Security.AccessControl.AccessControlType]
        $RuleType = [System.Security.AccessControl.AccessControlType]::Allow,

        [System.DirectoryServices.ActiveDirectoryRights]
        $Rights,

        [Guid] $ExtendedRight = [Guid]::Empty,

        [System.DirectoryServices.PropertyAccess]
        $PropertyAccess = [System.DirectoryServices.PropertyAccess]::Read,

        [Guid] $ObjectType = [Guid]::Empty,

        [System.DirectoryServices.ActiveDirectorySecurityInheritance]
        $InheritanceType = [System.DirectoryServices.ActiveDirectorySecurityInheritance]::None,

        [Guid] $InheritObjectType = [Guid]::Empty
    )

    $schema = Get-AdkSchema
    $nameByGuid = $schema.NameByGuid

    $isExtended    = $false
    $isPropertySet = $false

    if ($Rights -eq [System.DirectoryServices.ActiveDirectoryRights]::ExtendedRight) {
        $rightName = $nameByGuid[$ExtendedRight]
        if (Test-AdkIsPropertySet -Guid $ExtendedRight) {
            $isPropertySet = $true
            Write-Verbose "Assigning [$rightName] - $RuleType [$PropertyAccess] on [$ObjectDN] to [$SubjectDN]"
        } else {
            $isExtended = $true
            Write-Verbose "Assigning [$rightName] - $RuleType on [$ObjectDN] to [$SubjectDN]"
        }
    } else {
        $rn = $nameByGuid[$ObjectType]
        $on = if ($InheritObjectType -ne [Guid]::Empty) { "$($nameByGuid[$InheritObjectType])." } else { '' }
        $ot = if (-not ([string]::IsNullOrWhiteSpace($rn) -and [string]::IsNullOrWhiteSpace($on))) { "[$on$rn] - " } else { '' }
        Write-Verbose "Assigning $ot[$Rights] - $RuleType on [$ObjectDN] to [$SubjectDN]"
    }

    $adObject  = $null
    $adSubject = $null
    try {
        $adObject  = Get-ADObject $ObjectDN
        $adSubject = Get-ADObject $SubjectDN -Properties ObjectSid
    } catch {
        Write-AdkException $_
        throw
    }

    $subSid = $adSubject.ObjectSid

    $aclPath = "AD:\$($adObject.DistinguishedName)"
    $acl = Get-Acl $aclPath
    $ace = $null

    if ($isExtended) {
        if ($ExtendedRight -eq [Guid]::Empty) { throw 'Extended right is empty guid' }

        if ($InheritanceType -ne [System.DirectoryServices.ActiveDirectorySecurityInheritance]::None) {
            if ($InheritObjectType -ne [Guid]::Empty) {
                $ace = New-Object System.DirectoryServices.ExtendedRightAccessRule(
                    $subSid, $RuleType, $ExtendedRight, $InheritanceType, $InheritObjectType)
            } else {
                $ace = New-Object System.DirectoryServices.ExtendedRightAccessRule(
                    $subSid, $RuleType, $ExtendedRight, $InheritanceType)
            }
        } else {
            $ace = New-Object System.DirectoryServices.ExtendedRightAccessRule(
                $subSid, $RuleType, $ExtendedRight)
        }
    } elseif ($isPropertySet) {
        if ($InheritanceType -ne [System.DirectoryServices.ActiveDirectorySecurityInheritance]::None) {
            if ($InheritObjectType -ne [Guid]::Empty) {
                $ace = New-Object System.DirectoryServices.PropertySetAccessRule(
                    $subSid, $RuleType, $PropertyAccess, $ExtendedRight, $InheritanceType, $InheritObjectType)
            } else {
                $ace = New-Object System.DirectoryServices.PropertySetAccessRule(
                    $subSid, $RuleType, $PropertyAccess, $ExtendedRight, $InheritanceType)
            }
        } else {
            $ace = New-Object System.DirectoryServices.PropertySetAccessRule(
                $subSid, $RuleType, $PropertyAccess, $ExtendedRight)
        }
    } else {
        if ($InheritanceType -ne [System.DirectoryServices.ActiveDirectorySecurityInheritance]::None) {
            if ($InheritObjectType -ne [Guid]::Empty) {
                if ($ObjectType -ne [Guid]::Empty) {
                    $ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
                        $subSid, $Rights, $RuleType, $ObjectType, $InheritanceType, $InheritObjectType)
                } else {
                    $ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
                        $subSid, $Rights, $RuleType, $InheritanceType, $InheritObjectType)
                }
            } else {
                if ($ObjectType -ne [Guid]::Empty) {
                    $ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
                        $subSid, $Rights, $RuleType, $ObjectType, $InheritanceType)
                } else {
                    $ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
                        $subSid, $Rights, $RuleType, $InheritanceType)
                }
            }
        } else {
            if ($ObjectType -ne [Guid]::Empty) {
                $ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
                    $subSid, $Rights, $RuleType, $ObjectType)
            } else {
                $ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
                    $subSid, $Rights, $RuleType)
            }
        }
    }

    # Idempotency check: don't add a duplicate ACE.
    foreach ($existing in $acl.Access) {
        if ($existing.IsInherited) { continue }

        if ($existing.IdentityReference -isnot [System.Security.Principal.SecurityIdentifier]) {
            try {
                $existingSid = $existing.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier])
            } catch {
                continue
            }
        } else {
            $existingSid = $existing.IdentityReference
        }

        if ($existingSid -ne $subSid) { continue }
        if ($existing.AccessControlType   -ne $ace.AccessControlType)   { continue }
        if ($existing.ActiveDirectoryRights -ne $ace.ActiveDirectoryRights) { continue }
        if ($existing.ObjectType          -ne $ace.ObjectType)          { continue }
        if ($existing.InheritedObjectType -ne $ace.InheritedObjectType) { continue }
        if ($existing.InheritanceType     -ne $ace.InheritanceType)     { continue }

        Write-Verbose '  -> ACE already present, skipping'
        return
    }

    $shouldProcessTarget = $aclPath
    $shouldProcessAction = if ($isExtended) {
        "Add extended-right ACE [$($nameByGuid[$ExtendedRight])] for [$SubjectDN]"
    } elseif ($isPropertySet) {
        "Add property-set ACE [$($nameByGuid[$ExtendedRight])] / $PropertyAccess for [$SubjectDN]"
    } else {
        "Add ACE [$Rights] for [$SubjectDN]"
    }

    if (-not $PSCmdlet.ShouldProcess($shouldProcessTarget, $shouldProcessAction)) {
        return
    }

    $acl.AddAccessRule($ace)
    $acl | Set-Acl $aclPath
}

# Convenience wrappers used by verb implementations.

function Set-AdAllowCreate {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $ObjectDN,
        [Parameter(Mandatory)] [string] $SubjectDN,
        [Parameter(Mandatory)] [string] $ObjectLdapClassName,
        [System.DirectoryServices.ActiveDirectorySecurityInheritance]
        $Inheritance = [System.DirectoryServices.ActiveDirectorySecurityInheritance]::None
    )
    $objectType = Get-AdkClassGuid -LdapClassName $ObjectLdapClassName
    Set-AdAce -ObjectDN $ObjectDN -SubjectDN $SubjectDN -RuleType Allow `
              -Rights ([System.DirectoryServices.ActiveDirectoryRights]::CreateChild) `
              -InheritanceType $Inheritance -ObjectType $objectType
}

function Set-AdAllowDelete {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $ObjectDN,
        [Parameter(Mandatory)] [string] $SubjectDN,
        [Parameter(Mandatory)] [string] $ObjectLdapClassName,
        [System.DirectoryServices.ActiveDirectorySecurityInheritance]
        $Inheritance = [System.DirectoryServices.ActiveDirectorySecurityInheritance]::None
    )
    $objectType = Get-AdkClassGuid -LdapClassName $ObjectLdapClassName
    Set-AdAce -ObjectDN $ObjectDN -SubjectDN $SubjectDN -RuleType Allow `
              -Rights ([System.DirectoryServices.ActiveDirectoryRights]::DeleteChild) `
              -InheritanceType $Inheritance -ObjectType $objectType
}

function Set-AdAllowFullControl {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $ObjectDN,
        [Parameter(Mandatory)] [string] $SubjectDN,
        [Parameter(Mandatory)] [string] $ObjectLdapClassName,
        [System.DirectoryServices.ActiveDirectorySecurityInheritance]
        $Inheritance = [System.DirectoryServices.ActiveDirectorySecurityInheritance]::None
    )
    $objectType = Get-AdkClassGuid -LdapClassName $ObjectLdapClassName
    Set-AdAce -ObjectDN $ObjectDN -SubjectDN $SubjectDN -RuleType Allow `
              -Rights ([System.DirectoryServices.ActiveDirectoryRights]::GenericAll) `
              -InheritanceType $Inheritance -InheritObjectType $objectType
}
