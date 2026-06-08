# Verbs operating on User descendants of an OU.

function Set-Verb-CreateUsers {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $ObjectDN,
        [Parameter(Mandatory)] [string] $SubjectDN,
        [hashtable] $Parameters = @{}
    )
    $inhName = if ($Parameters['Inheritance']) { $Parameters['Inheritance'] } else { 'All' }
    $inh = [System.DirectoryServices.ActiveDirectorySecurityInheritance] $inhName
    Set-AdAllowCreate -ObjectDN $ObjectDN -SubjectDN $SubjectDN `
                      -ObjectLdapClassName 'User' -Inheritance $inh
}

function Set-Verb-DeleteUsers {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $ObjectDN,
        [Parameter(Mandatory)] [string] $SubjectDN,
        [hashtable] $Parameters = @{}
    )
    $inhName = if ($Parameters['Inheritance']) { $Parameters['Inheritance'] } else { 'All' }
    $inh = [System.DirectoryServices.ActiveDirectorySecurityInheritance] $inhName
    Set-AdAllowDelete -ObjectDN $ObjectDN -SubjectDN $SubjectDN `
                      -ObjectLdapClassName 'User' -Inheritance $inh
}

function Set-Verb-FullControlUsers {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $ObjectDN,
        [Parameter(Mandatory)] [string] $SubjectDN,
        [hashtable] $Parameters = @{}
    )
    # FullControl on User class objects in the sub-tree. Note Inheritance
    # is Descendents because we're targeting User instances, not the OU.
    Set-AdAllowFullControl -ObjectDN $ObjectDN -SubjectDN $SubjectDN `
                           -ObjectLdapClassName 'User' `
                           -Inheritance ([System.DirectoryServices.ActiveDirectorySecurityInheritance]::Descendents)
}

function Set-Verb-ManageUsers {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $ObjectDN,
        [Parameter(Mandatory)] [string] $SubjectDN,
        [hashtable] $Parameters = @{}
    )

    $inhName = if ($Parameters['Inheritance']) { $Parameters['Inheritance'] } else { 'All' }
    $inh = [System.DirectoryServices.ActiveDirectorySecurityInheritance] $inhName

    $userClass = Get-AdkClassGuid -LdapClassName 'User'

    $exPersonal   = Get-AdkExtendedRightGuid -RightName 'Personal-Information'
    $exPublic     = Get-AdkExtendedRightGuid -RightName 'Public-Information'
    $exLogon      = Get-AdkExtendedRightGuid -RightName 'User-Logon'
    $exMembership = Get-AdkExtendedRightGuid -RightName 'Membership'

    $rightUac     = Get-AdkAttributeGuid -AttributeName 'userAccountControl'
    $displayName  = Get-AdkAttributeGuid -AttributeName 'displayName'
    $samProp      = Get-AdkAttributeGuid -AttributeName 'samaccountname'

    Set-Verb-ResetPwd -ObjectDN $ObjectDN -SubjectDN $SubjectDN -Parameters $Parameters

    Set-AdAllowCreate -ObjectDN $ObjectDN -SubjectDN $SubjectDN -ObjectLdapClassName 'User' -Inheritance $inh
    Set-AdAllowDelete -ObjectDN $ObjectDN -SubjectDN $SubjectDN -ObjectLdapClassName 'User' -Inheritance $inh

    $rw = [System.DirectoryServices.ActiveDirectoryRights]::WriteProperty -bor `
          [System.DirectoryServices.ActiveDirectoryRights]::ReadProperty

    Set-AdAce -ObjectDN $ObjectDN -SubjectDN $SubjectDN -RuleType Allow -Rights $rw -ObjectType $rightUac    -InheritanceType $inh -InheritObjectType $userClass
    Set-AdAce -ObjectDN $ObjectDN -SubjectDN $SubjectDN -RuleType Allow -Rights $rw -ObjectType $displayName -InheritanceType $inh -InheritObjectType $userClass
    Set-AdAce -ObjectDN $ObjectDN -SubjectDN $SubjectDN -RuleType Allow -Rights $rw -ObjectType $samProp     -InheritanceType $inh -InheritObjectType $userClass

    foreach ($psPair in @(
        @{ Right = $exLogon;      Access = 'Read'  }
        @{ Right = $exLogon;      Access = 'Write' }
        @{ Right = $exPublic;     Access = 'Read'  }
        @{ Right = $exPublic;     Access = 'Write' }
        @{ Right = $exPersonal;   Access = 'Read'  }
        @{ Right = $exPersonal;   Access = 'Write' }
        @{ Right = $exMembership; Access = 'Read'  }
        @{ Right = $exMembership; Access = 'Write' }
    )) {
        Set-AdAce -ObjectDN $ObjectDN -SubjectDN $SubjectDN -RuleType Allow `
                  -Rights ([System.DirectoryServices.ActiveDirectoryRights]::ExtendedRight) `
                  -ExtendedRight $psPair.Right `
                  -PropertyAccess ([System.DirectoryServices.PropertyAccess] $psPair.Access) `
                  -InheritanceType $inh -InheritObjectType $userClass
    }
}
