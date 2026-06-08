# Resolve "%OuName%" token strings to their full distinguished names.
#
# The OU tree is built from OU.csv via New-AdkOuTree, which writes a
# companion OUStructure.csv mapping token -> DN. This helper loads that
# file (once per context) and provides token resolution to other cmdlets.

function Get-AdkOuMap {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string] $DataPath,

        [switch] $Force
    )

    $mapPath = Join-Path $DataPath 'OUStructure.csv'
    if (-not (Test-Path $mapPath -PathType Leaf)) {
        throw "OU map not found at $mapPath. Has New-AdkOuTree been run?"
    }

    if ($Force -or -not $Script:AdkOuMap -or $Script:AdkOuMapPath -ne $mapPath) {
        $map = @{}
        foreach ($row in (Import-Csv $mapPath -Delimiter ';')) {
            $map[$row.Name] = $row.DN
        }
        $Script:AdkOuMap     = $map
        $Script:AdkOuMapPath = $mapPath
    }

    return $Script:AdkOuMap
}

function Resolve-AdkOuToken {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string] $Token,

        [Parameter(Mandatory)]
        [string] $DataPath
    )

    $map = Get-AdkOuMap -DataPath $DataPath
    if (-not $map.ContainsKey($Token)) {
        throw "OU token [$Token] is not defined in OUStructure.csv"
    }
    return $map[$Token]
}

function ConvertFrom-AdkDelegationParameters {
    <#
    Parse a Delegations.csv "Parameters" cell of the form
        key=val;key=val
    into a hashtable. Empty input returns an empty hashtable.
    #>
    [CmdletBinding()]
    param(
        [AllowEmptyString()]
        [AllowNull()]
        [string] $ParametersString
    )

    $result = @{}
    if ([string]::IsNullOrWhiteSpace($ParametersString)) {
        return $result
    }

    foreach ($pair in $ParametersString.Split(';')) {
        if ([string]::IsNullOrWhiteSpace($pair)) { continue }
        $eq = $pair.IndexOf('=')
        if ($eq -lt 1) {
            throw "Malformed Parameters entry [$pair] (expected key=value)"
        }
        $key = $pair.Substring(0, $eq).Trim()
        $val = $pair.Substring($eq + 1).Trim()
        $result[$key] = $val
    }

    return $result
}
