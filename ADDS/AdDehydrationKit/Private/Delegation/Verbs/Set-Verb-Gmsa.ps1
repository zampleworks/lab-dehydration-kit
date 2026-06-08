# Verb: ManageGMSA
#
# Create / Delete msDS-GroupManagedServiceAccount descendants of an OU,
# plus write msDS-GroupMSAMembership on existing gMSAs. The KDS root
# key must already exist (Install-AddsContent.ps1 creates it).

function Set-Verb-ManageGMSA {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $ObjectDN,
        [Parameter(Mandatory)] [string] $SubjectDN,
        [hashtable] $Parameters = @{}
    )
    $inhName = if ($Parameters['Inheritance']) { $Parameters['Inheritance'] } else { 'All' }
    $inh = [System.DirectoryServices.ActiveDirectorySecurityInheritance] $inhName

    $schema = Get-AdkSchema
    if (-not $schema.GuidByName.ContainsKey('msDS-GroupManagedServiceAccount')) {
        Write-AdkLog '  gMSA schema not present; skipping ManageGMSA' -Warning
        return
    }

    $gmsaClass = Get-AdkClassGuid -LdapClassName 'msDS-GroupManagedServiceAccount'
    $membership = Get-AdkAttributeGuid -AttributeName 'msDS-GroupMSAMembership'

    Set-AdAllowCreate -ObjectDN $ObjectDN -SubjectDN $SubjectDN `
                      -ObjectLdapClassName 'msDS-GroupManagedServiceAccount' -Inheritance $inh
    Set-AdAllowDelete -ObjectDN $ObjectDN -SubjectDN $SubjectDN `
                      -ObjectLdapClassName 'msDS-GroupManagedServiceAccount' -Inheritance $inh

    $rw = [System.DirectoryServices.ActiveDirectoryRights]::WriteProperty -bor `
          [System.DirectoryServices.ActiveDirectoryRights]::ReadProperty

    Set-AdAce -ObjectDN $ObjectDN -SubjectDN $SubjectDN -RuleType Allow `
              -Rights $rw -ObjectType $membership `
              -InheritanceType $inh -InheritObjectType $gmsaClass
}
