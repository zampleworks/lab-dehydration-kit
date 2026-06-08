# Given an SDDL string and a hashtable of identity SIDs/short-aliases to
# strip, return the SDDL with matching ACEs removed. Used by
# Reset-AdkBuiltinDelegation to clean up default security descriptors
# on schema classes.

function Remove-BuiltinFromSDDLACE {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [hashtable] $RemoveIdentities,

        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string] $SddlAce
    )

    if ([string]::IsNullOrWhiteSpace($SddlAce)) {
        Write-Verbose 'Empty input string'
        return $SddlAce
    }

    $pre = ''
    $firstPar = $SddlAce.IndexOf('(')
    $sddl = $SddlAce
    if ($firstPar -gt 0) {
        $pre  = $SddlAce.Substring(0, $firstPar)
        $sddl = $SddlAce.Substring($firstPar)
    }

    $tokens = $sddl.Split(')(', [System.StringSplitOptions]::RemoveEmptyEntries)
    $result  = ''
    $altered = $false

    foreach ($t in $tokens) {
        $remove = $false
        foreach ($key in $RemoveIdentities.Keys) {
            if ($t.EndsWith(";$key")) {
                $remove = $true
                Write-Verbose "Removing [$($RemoveIdentities[$key])] ACE"
                break
            }
        }

        if (-not $remove) {
            $result = "$result($t)"
        } else {
            $altered = $true
        }
    }

    if ($altered) {
        return "$pre$result"
    }

    return $SddlAce
}
