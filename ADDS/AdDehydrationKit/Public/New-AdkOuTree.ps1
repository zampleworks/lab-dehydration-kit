# Create the OU tree described in OU.csv. Writes a companion
# OUStructure.csv that maps "%Token%" placeholders to resolved DNs.
# Idempotent: existing OUs are detected and skipped.
#
# OU.csv columns: Parent;Name;CN;DisplayName;Created
#   Parent      Token of the parent OU (%RootDN% for top-level)
#   Name        Logical token (without surrounding %), e.g. OrgGroupsOU
#   CN          The Common Name used in the DN (RDN value)
#   DisplayName The displayName attribute (supports %DomainNBName%)
#   Created     Updated to true after creation; ignored on read

function New-AdkOuTree {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        [PSObject] $Context,

        [string] $OuCsv,

        [string] $RootDn
    )

    if ([string]::IsNullOrWhiteSpace($OuCsv)) {
        $OuCsv = Join-Path $Context.DataPath 'OU.csv'
    }
    if (-not (Test-Path $OuCsv -PathType Leaf)) {
        throw "OU.csv not found at $OuCsv"
    }

    if ([string]::IsNullOrWhiteSpace($RootDn)) {
        $RootDn = $Context.DomainDn
    }

    $ouMapPath = Join-Path $Context.DataPath 'OUStructure.csv'

    # Snapshot existing OUs so we can detect duplicates
    # foreach (not ForEach-Object) - pipeline ForEach-Object with script
    # block errors when $WhatIfPreference is set in this scope.
    $existingOus = @{}
    foreach ($ouObj in (Get-ADOrganizationalUnit -Filter *)) {
        $existingOus[$ouObj.DistinguishedName] = $ouObj
    }
    $existingOuDns = @($existingOus.Keys)

    $ous = Import-Csv $OuCsv -Delimiter ';' | Where-Object { -not [string]::IsNullOrWhiteSpace($_.Name) }

    # Token replacements. %RootDN% is the configured root; per-OU tokens
    # are added as we resolve them, and %DomainNBName% is a string-level
    # substitution used in DisplayName / CN.
    $replacements = @{ '%RootDN%' = $RootDn }
    $stringReplacements = @{ '%DomainNBName%' = $Context.DomainNetBios }

    # Expand %DomainNBName% etc. on the in-memory OU rows
    foreach ($ou in $ous) {
        foreach ($rep in $stringReplacements.GetEnumerator()) {
            if ($ou.DisplayName.Contains($rep.Key)) {
                $ou.DisplayName = $ou.DisplayName.Replace($rep.Key, $rep.Value)
            }
            if ($ou.CN.Contains($rep.Key)) {
                $ou.CN = $ou.CN.Replace($rep.Key, $rep.Value)
            }
        }
    }

    # OUStructure.csv must be (re)written even under -WhatIf so downstream
    # cmdlets (which inherit $WhatIfPreference from this orchestrator)
    # read the *current* domain's DN map, not a stale committed copy.
    # -WhatIf:$false on each Out-File overrides the inherited preference.
    "Name;DN" | Out-File $ouMapPath -Encoding utf8 -Force -WhatIf:$false

    $created = 0
    $existed = 0

    Write-AdkLog 'Creating OU tree..' -Step
    $ouIndex = 0
    $ouTotal = $ous.Count
    foreach ($ou in $ous) {
        $ouIndex++
        Write-Progress -Id 10 -ParentId 1 -Activity 'OU tree' `
            -Status "$ouIndex of $ouTotal : $($ou.Name)" `
            -PercentComplete (($ouIndex / [Math]::Max($ouTotal, 1)) * 100)
        $parent = $null
        foreach ($entry in $replacements.GetEnumerator()) {
            if ($entry.Key -eq $ou.Parent) { $parent = $entry.Value; break }
        }

        if ([string]::IsNullOrWhiteSpace($parent)) {
            Write-Verbose "No replacement found for Parent [$($ou.Parent)] of OU [$($ou.Name)] - skipping"
            continue
        }

        $cn   = $ou.CN
        $name = $ou.Name
        $dn   = "OU=$cn,$parent"

        if ($existingOuDns -contains $dn) {
            $replacements["%$name%"] = $dn
            "%$name%;$dn" | Out-File $ouMapPath -Append -Encoding utf8 -NoClobber -WhatIf:$false
            $existed++
            continue
        }

        if (-not $PSCmdlet.ShouldProcess($dn, 'Create OU')) {
            # Record the *intended* DN in the OU map even on -WhatIf so that
            # downstream Resolve-AdkOuToken calls don't fail.
            $replacements["%$name%"] = $dn
            "%$name%;$dn" | Out-File $ouMapPath -Append -Encoding utf8 -NoClobber -WhatIf:$false
            continue
        }

        try {
            $new = New-ADOrganizationalUnit -Path $parent -Name $cn -DisplayName $ou.DisplayName `
                                            -PassThru -Confirm:$false
            $existingOus[$new.DistinguishedName] = $new
            $existingOuDns = @($existingOus.Keys)
            $replacements["%$name%"] = $dn
            "%$name%;$dn" | Out-File $ouMapPath -Append -Encoding utf8 -NoClobber -WhatIf:$false
            Write-AdkLog "  created [$dn]"
            $created++
        } catch {
            Write-AdkLog "  failed to create [$dn]: $($_.Exception.Message)" -IsError
        }
    }

    Write-Progress -Id 10 -ParentId 1 -Activity 'OU tree' -Completed

    # Append well-known system OUs that always exist in any AD domain.
    # These are not created by the kit but must be reachable as link targets.
    $domainDn = $Context.DomainDn
    @(
        "%DomainControllersOU%;OU=Domain Controllers,$domainDn"
    ) | ForEach-Object {
        $_ | Out-File $ouMapPath -Append -Encoding utf8 -NoClobber -WhatIf:$false
    }

    Write-AdkLog "OU tree: $created created, $existed already exist" -Success
}