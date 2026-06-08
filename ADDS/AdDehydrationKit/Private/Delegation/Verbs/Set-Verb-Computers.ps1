# Verbs operating on Computer descendants of an OU.

function Set-Verb-ManageComputers {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $ObjectDN,
        [Parameter(Mandatory)] [string] $SubjectDN,
        [hashtable] $Parameters = @{}
    )

    $inhName = if ($Parameters['Inheritance']) { $Parameters['Inheritance'] } else { 'All' }
    $inh = [System.DirectoryServices.ActiveDirectorySecurityInheritance] $inhName

    $computerClass = Get-AdkClassGuid -LdapClassName 'Computer'

    $exPersonal   = Get-AdkExtendedRightGuid -RightName 'Personal-Information'
    $exPublic     = Get-AdkExtendedRightGuid -RightName 'Public-Information'
    $exLogon      = Get-AdkExtendedRightGuid -RightName 'User-Logon'
    $exMembership = Get-AdkExtendedRightGuid -RightName 'Membership'

    $displayName = Get-AdkAttributeGuid -AttributeName 'displayName'
    $samProp     = Get-AdkAttributeGuid -AttributeName 'samaccountname'
    $rightUac    = Get-AdkAttributeGuid -AttributeName 'userAccountControl'

    # Computer password reset is the same extended right as for users
    Set-Verb-ResetPwd -ObjectDN $ObjectDN -SubjectDN $SubjectDN -Parameters $Parameters

    Set-AdAllowCreate -ObjectDN $ObjectDN -SubjectDN $SubjectDN -ObjectLdapClassName 'Computer' -Inheritance $inh
    Set-AdAllowDelete -ObjectDN $ObjectDN -SubjectDN $SubjectDN -ObjectLdapClassName 'Computer' -Inheritance $inh

    $rw = [System.DirectoryServices.ActiveDirectoryRights]::WriteProperty -bor `
          [System.DirectoryServices.ActiveDirectoryRights]::ReadProperty

    foreach ($attr in @($rightUac, $displayName, $samProp)) {
        Set-AdAce -ObjectDN $ObjectDN -SubjectDN $SubjectDN -RuleType Allow `
                  -Rights $rw -ObjectType $attr -InheritanceType $inh -InheritObjectType $computerClass
    }

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
                  -InheritanceType $inh -InheritObjectType $computerClass
    }
}
