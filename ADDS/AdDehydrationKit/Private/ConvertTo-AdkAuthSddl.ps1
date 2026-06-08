# Parse a simplified AuthCondition expression and produce a full SDDL
# authentication policy condition string.
#
# Syntax:
#   GroupName           single group membership check
#   SmartCard           shorthand for Claim-SmartCardLogon
#   A AND B             both conditions must be true
#   A OR B              either group membership suffices
#   SmartCard AND A OR B    SmartCard AND (A or B)
#
# AND binds less tightly than OR, so "X OR Y AND Z" means
# "(X OR Y) AND Z".
#
# Returns the full SDDL string:
#   O:SYG:SYD:(XA;OICI;CR;;;WD;(<condition>))
#
# Under -WhatIf, unresolvable groups return $null so the caller
# can skip the policy.

function ConvertTo-AdkAuthSddl {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string] $AuthCondition
    )

    $inWhatIf = [bool]$WhatIfPreference

    # Split on AND (case-insensitive, space-padded)
    $andTerms = $AuthCondition -split '\s+AND\s+' |
                ForEach-Object { $_.Trim() } |
                Where-Object { $_ }

    $termParts = [System.Collections.Generic.List[string]]::new()

    foreach ($term in $andTerms) {
        # Split on OR within each term
        $orGroups = $term -split '\s+OR\s+' |
                    ForEach-Object { $_.Trim() } |
                    Where-Object { $_ }

        # Resolve each group name to SID
        $sids = [System.Collections.Generic.List[string]]::new()
        foreach ($gn in $orGroups) {
            $resolveName = if ($gn -eq 'SmartCard') { 'Claim-SmartCardLogon' } else { $gn }
            try {
                $sid = (Get-ADGroup -Identity $resolveName -ErrorAction Stop).SID.Value
                $sids.Add($sid)
            } catch {
                if ($inWhatIf) {
                    Write-AdkLog "  [$resolveName] not yet present (expected under -WhatIf)" -Step
                    return $null
                }
                throw "AuthCondition: group [$resolveName] not found in AD."
            }
        }

        if ($sids.Count -eq 1) {
            $termParts.Add("Member_of {SID($($sids[0]))}")
        } else {
            $sidList = ($sids | ForEach-Object { "SID($_)" }) -join ', '
            $termParts.Add("Member_of_any {$sidList}")
        }
    }

    if ($termParts.Count -eq 1) {
        $condition = $termParts[0]
    } else {
        # Wrap each term in parens and join with &&
        $condition = ($termParts | ForEach-Object { "($_)" }) -join ' && '
    }

    return "O:SYG:SYD:(XA;OICI;CR;;;WD;($condition))"
}
