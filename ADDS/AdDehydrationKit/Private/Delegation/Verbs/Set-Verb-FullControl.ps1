# Verb: FullControl
# Grants GenericAll on the target OU, optionally inherited to descendants.

function Set-Verb-FullControl {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $ObjectDN,
        [Parameter(Mandatory)] [string] $SubjectDN,
        [hashtable] $Parameters = @{}
    )

    $inherit = if ($Parameters['Inheritance']) { $Parameters['Inheritance'] } else { 'All' }
    $inh = [System.DirectoryServices.ActiveDirectorySecurityInheritance] $inherit

    Set-AdAce -ObjectDN $ObjectDN -SubjectDN $SubjectDN `
              -RuleType Allow `
              -Rights ([System.DirectoryServices.ActiveDirectoryRights]::GenericAll) `
              -InheritanceType $inh
}
