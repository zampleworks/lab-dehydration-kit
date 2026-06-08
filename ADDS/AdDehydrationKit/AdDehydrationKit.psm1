# AdDehydrationKit module loader.
#
# Loads every .ps1 under Private/ and Public/ recursively. Public functions
# (as declared in the manifest) are exported. Private functions are visible
# only within the module scope.
#
# PS 5.1 compatible - no `using module`, no PowerShell classes.

$ErrorActionPreference = 'Stop'

# Load Private first so they're available to Public.
$private = Get-ChildItem -Path (Join-Path $PSScriptRoot 'Private') -Recurse -Filter '*.ps1' -ErrorAction SilentlyContinue
$public  = Get-ChildItem -Path (Join-Path $PSScriptRoot 'Public')  -Recurse -Filter '*.ps1' -ErrorAction SilentlyContinue

foreach ($file in @($private) + @($public)) {
    if ($null -eq $file) { continue }
    try {
        . $file.FullName
    } catch {
        Write-Error "Failed to import [$($file.FullName)]: $($_.Exception.Message)"
        throw
    }
}

# Module-scoped state. Filled in by Initialize-AdkContext on first use.
$Script:AdkContext = $null

Export-ModuleMember -Function @(
    'Install-AdkContent'
    'Install-AdkForest'
    'New-AdkOuTree'
    'New-AdkGroups'
    'New-AdkUsers'
    'Set-AdkGroupMembership'
    'Set-AdkDelegation'
    'Reset-AdkBuiltinDelegation'
    'Import-AdkGpos'
    'New-AdkWmiFilters'
    'Install-AdkAdmxTemplates'
    'Import-AdkSecurityBaselines'
    'Import-AdkDefaultPolicies'
    'Set-AdkAuthPolicy'
    'Set-AdkForestFeatures'
    'Set-AdkDnsReplication'
    'New-AdkApp'
    'Invoke-AdkApps'
    'Get-AdkContext'
    'Initialize-AdkSchema'
    'New-AdkFineGrainedPasswordPolicies'
    'Set-AdkDomainHardening'
    'Set-AdkServerHardening'
    'Test-AdkData'
)
