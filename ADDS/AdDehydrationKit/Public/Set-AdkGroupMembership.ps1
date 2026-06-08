# Apply group memberships described in GroupMembers.csv.
#
# GroupMembers.csv columns: Member;MemberOf
#   Member   - sam name of a user OR group OR built-in identity
#   MemberOf - comma-separated list of group names to add the Member to
#
# The function tolerates rows that refer to built-in groups (e.g.
# Administrators, Enterprise Admins) which aren't in our Groups.csv but
# do resolve via Get-ADGroup. Under -WhatIf, missing members and groups
# are tolerated (they may not exist yet). In normal mode, any missing
# member or group is a terminating error.

function Set-AdkGroupMembership {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        [PSObject] $Context
    )

    $csvPath = Join-Path $Context.DataPath 'GroupMembers.csv'
    if (-not (Test-Path $csvPath)) {
        throw "GroupMembers.csv not found at $csvPath"
    }

    $rows = Import-Csv $csvPath -Delimiter ';' |
            Where-Object { -not [string]::IsNullOrWhiteSpace($_.Member) }

    # Under -WhatIf, members and groups gated by earlier ShouldProcess
    # calls don't actually exist. Pre-check existence so we can report
    # "would add" cleanly instead of letting Get-AD*/Add-ADGroupMember
    # throw terminating errors for each missing dependency.
    $inWhatIf  = $WhatIfPreference
    $gatedSkip = 0
    $added     = 0
    $existed   = 0

    Write-AdkLog "Applying $($rows.Count) group-membership rows.." -Step
    $rowIndex = 0
    $rowTotal = $rows.Count
    foreach ($row in $rows) {
        $rowIndex++
        Write-Progress -Id 50 -ParentId 1 -Activity 'Group memberships' `
            -Status "Row $rowIndex of $rowTotal" `
            -PercentComplete (($rowIndex / [Math]::Max($rowTotal, 1)) * 100)
        $memberName = $row.Member
        $groupNames = $row.MemberOf

        if ([string]::IsNullOrWhiteSpace($memberName) -or [string]::IsNullOrWhiteSpace($groupNames)) {
            Write-AdkLog "  malformed row: $($row | Format-Table | Out-String)" -Warning
            continue
        }

        # Resolve member as user, then group.
        $member = $null
        try { $member = Get-ADUser  -Identity $memberName -ErrorAction Stop } catch { }
        if (-not $member) {
            try { $member = Get-ADGroup -Identity $memberName -ErrorAction Stop } catch { }
        }
        if (-not $member) {
            if ($inWhatIf) {
                # Member doesn't exist yet because New-AdkUsers / -Groups
                # was -WhatIf gated. Treat the whole row as a "would add"
                # and skip with a count.
                foreach ($gn in $groupNames.Split(',')) {
                    $gn = $gn.Trim()
                    if (-not [string]::IsNullOrWhiteSpace($gn)) {
                        Write-Verbose "  [WhatIf] would add [$memberName] -> [$gn] (member not yet provisioned)"
                        $gatedSkip++
                    }
                }
            } else {
                throw "Group memberships failed: member [$memberName] not found in AD. Check GroupMembers.csv or run Users/Groups steps first."
            }
            continue
        }

        foreach ($gn in $groupNames.Split(',')) {
            $gn = $gn.Trim()
            if ([string]::IsNullOrWhiteSpace($gn)) { continue }

            $g = $null
            try { $g = Get-ADGroup -Identity $gn -Properties members -ErrorAction Stop } catch { }
            if (-not $g) {
                if ($inWhatIf) {
                    Write-Verbose "  [WhatIf] would add [$memberName] -> [$gn] (group not yet provisioned)"
                    $gatedSkip++
                } else {
                    throw "Group memberships failed: group [$gn] not found in AD (member: $memberName). Check GroupMembers.csv or run Groups/Apps steps first."
                }
                continue
            }

            if ($g.Members -contains $member.DistinguishedName) {
                $existed++
                continue
            }

            if ($PSCmdlet.ShouldProcess($gn, "Add member [$memberName]")) {
                try {
                    Add-ADGroupMember -Identity $g -Members $member -ErrorAction Stop
                    Write-AdkLog "  added [$memberName] -> [$gn]"
                    $added++
                } catch {
                    Write-AdkLog "  could not add [$memberName] to [$gn]: $($_.Exception.Message)" -Warning
                }
            }
        }
    }

    Write-Progress -Id 50 -ParentId 1 -Activity 'Group memberships' -Completed

    if ($inWhatIf -and $gatedSkip -gt 0) {
        # WhatIf-only informational; uncolored to match PowerShell's
        # native "What if:" output style.
        Write-AdkLog "  [WhatIf] $gatedSkip membership add(s) skipped because dependencies don't exist under -WhatIf"
    }

    Write-AdkLog "Group memberships: $added added, $existed already exist" -Success
}
