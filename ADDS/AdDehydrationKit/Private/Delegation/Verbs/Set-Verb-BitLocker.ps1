# Verb: BitLockerRecovery
#
# Read msFVE-RecoveryInformation objects under each Computer descendant.
# That's how MMC's BitLocker recovery tab surfaces recovery passwords.
#
# The relevant ACEs are:
#   - Read property on msFVE-RecoveryInformation descendants of Computer
#   - Read the msFVE-RecoveryPassword attribute (confidential, so the
#     read-property is also extended-right gated)

function Set-Verb-BitLockerRecovery {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $ObjectDN,
        [Parameter(Mandatory)] [string] $SubjectDN,
        [hashtable] $Parameters = @{}
    )
    $inhName = if ($Parameters['Inheritance']) { $Parameters['Inheritance'] } else { 'All' }
    $inh = [System.DirectoryServices.ActiveDirectorySecurityInheritance] $inhName

    $schema = Get-AdkSchema
    if (-not $schema.GuidByName.ContainsKey('msFVE-RecoveryInformation')) {
        Write-AdkLog '  msFVE schema not present; skipping BitLockerRecovery' -Warning
        return
    }

    $recoveryClass = Get-AdkClassGuid -LdapClassName 'msFVE-RecoveryInformation'

    # Generic read on every msFVE-RecoveryInformation descendant
    Set-AdAce -ObjectDN $ObjectDN -SubjectDN $SubjectDN -RuleType Allow `
              -Rights ([System.DirectoryServices.ActiveDirectoryRights]::GenericRead) `
              -InheritanceType $inh -InheritObjectType $recoveryClass

    # Plus the All-Extended-Rights on these objects (confidential bit)
    Set-AdAce -ObjectDN $ObjectDN -SubjectDN $SubjectDN -RuleType Allow `
              -Rights ([System.DirectoryServices.ActiveDirectoryRights]::ExtendedRight) `
              -InheritanceType $inh -InheritObjectType $recoveryClass
}
