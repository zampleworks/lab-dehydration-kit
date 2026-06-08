# Verb: ResetPwd
# Grants password-reset capability on User descendants of the target OU:
#   * User-Force-Change-Password extended right
#   * Unexpire-Password extended right
#   * Read/write pwdLastSet and lockoutTime
#   * Read/write the Domain-Password property set (covers
#     userAccountControl-driven 'user must change password at next logon')

function Set-Verb-ResetPwd {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $ObjectDN,
        [Parameter(Mandatory)] [string] $SubjectDN,
        [hashtable] $Parameters = @{}
    )

    $inherit = if ($Parameters['Inheritance']) { $Parameters['Inheritance'] } else { 'Descendents' }
    $inh = [System.DirectoryServices.ActiveDirectorySecurityInheritance] $inherit

    $userClass     = Get-AdkClassGuid -LdapClassName 'User'
    $forceChange   = Get-AdkExtendedRightGuid -RightName 'User-Force-Change-Password'
    $unexpire      = Get-AdkExtendedRightGuid -RightName 'Unexpire-Password'
    $domainPwd     = Get-AdkExtendedRightGuid -RightName 'Domain-Password'
    $pwdLastSet    = Get-AdkAttributeGuid -AttributeName 'pwdLastSet'
    $lockoutTime   = Get-AdkAttributeGuid -AttributeName 'lockoutTime'

    Set-AdAce -ObjectDN $ObjectDN -SubjectDN $SubjectDN -RuleType Allow `
              -Rights ([System.DirectoryServices.ActiveDirectoryRights]::ExtendedRight) `
              -ExtendedRight $forceChange -InheritanceType $inh -InheritObjectType $userClass

    Set-AdAce -ObjectDN $ObjectDN -SubjectDN $SubjectDN -RuleType Allow `
              -Rights ([System.DirectoryServices.ActiveDirectoryRights]::ExtendedRight) `
              -ExtendedRight $unexpire -InheritanceType $inh -InheritObjectType $userClass

    Set-AdAce -ObjectDN $ObjectDN -SubjectDN $SubjectDN -RuleType Allow `
              -Rights ([System.DirectoryServices.ActiveDirectoryRights]::WriteProperty -bor `
                       [System.DirectoryServices.ActiveDirectoryRights]::ReadProperty) `
              -ObjectType $pwdLastSet -InheritanceType $inh -InheritObjectType $userClass

    Set-AdAce -ObjectDN $ObjectDN -SubjectDN $SubjectDN -RuleType Allow `
              -Rights ([System.DirectoryServices.ActiveDirectoryRights]::WriteProperty -bor `
                       [System.DirectoryServices.ActiveDirectoryRights]::ReadProperty) `
              -ObjectType $lockoutTime -InheritanceType $inh -InheritObjectType $userClass

    Set-AdAce -ObjectDN $ObjectDN -SubjectDN $SubjectDN -RuleType Allow `
              -Rights ([System.DirectoryServices.ActiveDirectoryRights]::ExtendedRight) `
              -ExtendedRight $domainPwd `
              -PropertyAccess ([System.DirectoryServices.PropertyAccess]::Read -bor `
                               [System.DirectoryServices.PropertyAccess]::Write) `
              -InheritanceType $inh -InheritObjectType $userClass
}
