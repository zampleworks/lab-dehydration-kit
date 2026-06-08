# Returns the canonical step registry as an ordered hashtable.
# Each entry declares its label, dependency steps, and a Check scriptblock
# that returns $true when the step's artefacts already exist in the live AD.
#
# The Check scriptblock receives a $Context object (from Get-AdkContext).
# It is used by Resolve-AdkStepRunList to determine whether an unfulfilled
# dependency needs to be auto-added to the run list.

function Get-AdkStepRegistry {
    [CmdletBinding()]
    param()

    [ordered]@{
        OuTree            = @{
            Label = 'OU tree'
            Deps  = @()
            Check = {
                param($c)
                Test-Path (Join-Path $c.DataPath 'OUStructure.csv')
            }
        }
        Groups            = @{
            Label = 'Groups'
            Deps  = @('OuTree')
            Check = {
                param($c)
                $row = Import-Csv (Join-Path $c.DataPath 'Groups.csv') -Delimiter ';' |
                       Select-Object -First 1
                if (-not $row) { return $true }
                $null -ne (Get-ADGroup -Filter "Name -eq '$($row.Name)'" -ErrorAction SilentlyContinue)
            }
        }
        Apps              = @{
            Label = 'Apps (role groups, OUs, GPOs)'
            Deps  = @('OuTree', 'Groups')
            Check = {
                param($c)
                $null -ne (Get-ADGroup -Filter "Name -like 'Role *'" -ErrorAction SilentlyContinue |
                           Select-Object -First 1)
            }
        }
        Users             = @{
            Label = 'Users'
            Deps  = @('OuTree')
            Check = {
                param($c)
                $row = Import-Csv (Join-Path $c.DataPath 'Users.csv') -Delimiter ';' |
                       Select-Object -First 1
                if (-not $row) { return $true }
                $null -ne (Get-ADUser -Filter "SamAccountName -eq '$($row.SamAccountName)'" `
                                     -ErrorAction SilentlyContinue)
            }
        }
        Memberships       = @{
            Label = 'Group memberships'
            Deps  = @('Groups', 'Apps', 'Users')
            Check = { $true }
        }
        Fgpp              = @{
            Label = 'Fine-grained password policies'
            Deps  = @('Groups')
            Check = {
                param($c)
                $csvPath = Join-Path $c.DataPath 'FineGrainedPasswordPolicies.csv'
                if (-not (Test-Path $csvPath -PathType Leaf)) { return $true }
                $first = Import-Csv $csvPath -Delimiter ';' |
                         Where-Object { -not [string]::IsNullOrWhiteSpace($_.Name) } |
                         Select-Object -First 1
                if (-not $first) { return $true }
                $null -ne (Get-ADFineGrainedPasswordPolicy `
                               -Filter "Name -eq '$($first.Name)'" `
                               -ErrorAction SilentlyContinue)
            }
        }
        ForestFeatures    = @{
            Label = 'Forest features (Recycle Bin, KDS, LAPS)'
            Deps  = @()
            Check = {
                param($c)
                $sch = (Get-ADRootDSE).schemaNamingContext
                $null -ne (Get-ADObject -Filter "lDAPDisplayName -eq 'msLAPS-PasswordExpirationTime'" `
                                       -SearchBase $sch -ErrorAction SilentlyContinue)
            }
        }
        Delegations       = @{
            Label = 'Delegations'
            Deps  = @('OuTree', 'Groups', 'ForestFeatures')
            Check = { $true }
        }
        SodGpos           = @{
            Label = 'PAW GPOs (SoD)'
            Deps  = @('OuTree', 'Groups')
            Check = {
                param($c)
                $null -ne (Get-GPO -Name 'T0 SoD PAW' -ErrorAction SilentlyContinue)
            }
        }
        DefaultPolicies   = @{
            Label = 'Default domain policies'
            Deps  = @()
            Check = { $true }
        }
        WmiFilters        = @{
            Label = 'WMI filters'
            Deps  = @()
            Check = {
                param($c)
                $somPath = "CN=SOM,CN=WMIPolicy,CN=System,$($c.DomainDn)"
                $expected = @(Import-Csv (Join-Path $c.DataPath 'WmiFilters.csv') -Delimiter ';' |
                              Where-Object { -not [string]::IsNullOrWhiteSpace($_.Name) }).Count
                @(Get-ADObject -Filter "objectClass -eq 'msWMI-Som'" `
                               -SearchBase $somPath -ErrorAction SilentlyContinue).Count -ge $expected
            }
        }
        AdmxTemplates     = @{
            Label = 'ADMX templates (Central Store)'
            Deps  = @()
            Check = {
                param($c)
                # If no zip is supplied the step is optional - treat as already done.
                $zipPath = Join-Path $c.DataPath 'PolicyDefinitions.zip'
                if (-not (Test-Path $zipPath -PathType Leaf)) { return $true }
                $centralStore = "\\$($c.DomainDnsName)\SYSVOL\$($c.DomainDnsName)\Policies\PolicyDefinitions"
                (Test-Path $centralStore) -and
                (@(Get-ChildItem -Path $centralStore -Filter '*.admx' -ErrorAction SilentlyContinue).Count -gt 0)
            }
        }
        SecurityBaselines = @{
            Label = 'Security baselines'
            Deps  = @('OuTree', 'WmiFilters', 'AdmxTemplates')
            Check = { $true }
        }
        DnsReplication    = @{
            Label = 'DNS zone replication'
            Deps  = @()
            Check = { $true }
        }
        AuthPolicies      = @{
            Label = 'Authentication policies'
            Deps  = @('OuTree', 'Groups', 'Apps')
            Check = { $true }
        }
        DomainHardening   = @{
            Label = 'Domain-level hardening (run once)'
            Deps  = @('OuTree')
            Check = { $true }
        }
        ServerHardening   = @{
            Label = 'Server hardening (per DC)'
            Deps  = @()
            Check = { $true }
        }
    }
}
