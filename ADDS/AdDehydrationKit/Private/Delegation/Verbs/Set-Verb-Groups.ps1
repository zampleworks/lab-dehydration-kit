# Verbs operating on Group descendants of an OU.

function Set-Verb-CreateGroups {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $ObjectDN,
        [Parameter(Mandatory)] [string] $SubjectDN,
        [hashtable] $Parameters = @{}
    )
    $inhName = if ($Parameters['Inheritance']) { $Parameters['Inheritance'] } else { 'All' }
    $inh = [System.DirectoryServices.ActiveDirectorySecurityInheritance] $inhName
    Set-AdAllowCreate -ObjectDN $ObjectDN -SubjectDN $SubjectDN `
                      -ObjectLdapClassName 'Group' -Inheritance $inh
}

function Set-Verb-DeleteGroups {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $ObjectDN,
        [Parameter(Mandatory)] [string] $SubjectDN,
        [hashtable] $Parameters = @{}
    )
    $inhName = if ($Parameters['Inheritance']) { $Parameters['Inheritance'] } else { 'All' }
    $inh = [System.DirectoryServices.ActiveDirectorySecurityInheritance] $inhName
    Set-AdAllowDelete -ObjectDN $ObjectDN -SubjectDN $SubjectDN `
                      -ObjectLdapClassName 'Group' -Inheritance $inh
}

function Set-Verb-FullControlGroups {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $ObjectDN,
        [Parameter(Mandatory)] [string] $SubjectDN,
        [hashtable] $Parameters = @{}
    )
    Set-AdAllowFullControl -ObjectDN $ObjectDN -SubjectDN $SubjectDN `
                           -ObjectLdapClassName 'Group' `
                           -Inheritance ([System.DirectoryServices.ActiveDirectorySecurityInheritance]::Descendents)
}

function Set-Verb-ManageGroups {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $ObjectDN,
        [Parameter(Mandatory)] [string] $SubjectDN,
        [hashtable] $Parameters = @{}
    )

    $inhName = if ($Parameters['Inheritance']) { $Parameters['Inheritance'] } else { 'All' }
    $inh = [System.DirectoryServices.ActiveDirectorySecurityInheritance] $inhName

    $groupClass = Get-AdkClassGuid -LdapClassName 'Group'

    $members     = Get-AdkAttributeGuid -AttributeName 'member'
    $rdn         = Get-AdkAttributeGuid -AttributeName 'name'
    $cn          = Get-AdkAttributeGuid -AttributeName 'cn'
    $samProp     = Get-AdkAttributeGuid -AttributeName 'samaccountname'
    $displayName = Get-AdkAttributeGuid -AttributeName 'displayName'
    $description = Get-AdkAttributeGuid -AttributeName 'description'
    $mail        = Get-AdkAttributeGuid -AttributeName 'mail'
    $notes       = Get-AdkAttributeGuid -AttributeName 'info'
    $scope       = Get-AdkAttributeGuid -AttributeName 'grouptype'
    $type        = Get-AdkAttributeGuid -AttributeName 'samaccounttype'

    Set-AdAllowCreate -ObjectDN $ObjectDN -SubjectDN $SubjectDN -ObjectLdapClassName 'Group' -Inheritance $inh
    Set-AdAllowDelete -ObjectDN $ObjectDN -SubjectDN $SubjectDN -ObjectLdapClassName 'Group' -Inheritance $inh

    $rw = [System.DirectoryServices.ActiveDirectoryRights]::WriteProperty -bor `
          [System.DirectoryServices.ActiveDirectoryRights]::ReadProperty

    foreach ($attr in @($members, $rdn, $cn, $samProp, $displayName, $description, $mail, $notes, $scope, $type)) {
        Set-AdAce -ObjectDN $ObjectDN -SubjectDN $SubjectDN -RuleType Allow `
                  -Rights $rw -ObjectType $attr -InheritanceType $inh -InheritObjectType $groupClass
    }
}
