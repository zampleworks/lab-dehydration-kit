@{
    RootModule        = 'AdDehydrationKit.psm1'
    ModuleVersion     = '0.9.5'
    GUID              = 'a1d7c2f8-3b9c-4a25-8a7d-1f5c9e7c8b21'
    Author            = 'AdDehydrationKit'
    CompanyName       = 'AdDehydrationKit'
    Description       = 'Active Directory deployment toolkit. Builds a Tier 0 / Tier 1 / EA tiered forest with content, delegations, GPOs, and authentication policies.'

    PowerShellVersion = '5.1'

    RequiredModules   = @(
        'ActiveDirectory'
        'GroupPolicy'
    )

    FunctionsToExport = @(
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

    CmdletsToExport   = @()
    VariablesToExport = @()
    AliasesToExport   = @()

    PrivateData       = @{
        PSData = @{
            Tags       = @('ActiveDirectory', 'Delegation', 'Tier0')
            ProjectUri = 'https://github.com/anders/AdDehydrationKit'
        }
    }
}
