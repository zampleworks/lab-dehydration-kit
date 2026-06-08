# Create WMI filters in AD for OS-version-specific GPO targeting.
#
# WMI filters are stored as msWMI-Som objects under
#   CN=SOM,CN=WMIPolicy,CN=System,<DomainDN>
#
# The GroupPolicy module has no cmdlet for this, so we create them
# directly via New-ADObject.  Each filter gets a stable GUID
# derived from its name so re-runs are idempotent.

function New-AdkWmiFilters {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        [PSObject] $Context
    )

    $csvPath = Join-Path $Context.DataPath 'WmiFilters.csv'
    $filters = @(Import-Csv $csvPath -Delimiter ';' |
                 Where-Object { -not [string]::IsNullOrWhiteSpace($_.Name) })

    $domainDn = $Context.DomainDn
    $somPath  = "CN=SOM,CN=WMIPolicy,CN=System,$domainDn"

    # Verify the SOM container exists (it should on any domain with GP)
    if (-not (Get-ADObject -Filter "distinguishedName -eq '$somPath'" -ErrorAction SilentlyContinue)) {
        throw "WMI filter container not found at $somPath"
    }

    $author   = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
    $created  = (Get-Date).ToUniversalTime().ToString('yyyyMMddHHmmss.ffffff-000')

    $forceUpdate = [bool]$Context.Force
    $cntCreated  = 0
    $cntUpdated  = 0
    $cntUpToDate = 0

    foreach ($f in $filters) {
        # Deterministic GUID from filter name so re-runs find the
        # existing object instead of creating duplicates.
        $guidBytes = [System.Text.Encoding]::UTF8.GetBytes("AdkWmiFilter:$($f.Name)")
        $md5       = [System.Security.Cryptography.MD5]::Create().ComputeHash($guidBytes)
        $filterGuid = [guid]::new($md5)
        $cn = "{$filterGuid}"

        # msWMI-Parm2 format:
        #   1;3;<nsLength>;<queryLength>;WQL;<namespace>;<query>;
        # Namespace defaults to root\CIMv2 when the CSV column is empty.
        $ns       = if ([string]::IsNullOrWhiteSpace($f.Namespace)) { 'root\CIMv2' } else { $f.Namespace.Trim() }
        $nsLen    = $ns.Length
        $queryLen = $f.Query.Length
        $parm2    = "1;3;$nsLen;$queryLen;WQL;$ns;$($f.Query);"

        $existing = Get-ADObject -Filter "objectClass -eq 'msWMI-Som' -and Name -eq '$cn'" `
                                 -SearchBase $somPath `
                                 -Properties 'msWMI-Parm1','msWMI-Parm2' `
                                 -ErrorAction SilentlyContinue

        if ($existing) {
            if ($forceUpdate) {
                $dirty = @{}
                if ($existing.'msWMI-Parm1' -ne $f.Description)  { $dirty['msWMI-Parm1'] = $f.Description }
                if ($existing.'msWMI-Parm2' -ne $parm2)    { $dirty['msWMI-Parm2'] = $parm2 }

                if ($dirty.Count -gt 0) {
                    if ($PSCmdlet.ShouldProcess($f.Name, 'Update WMI filter')) {
                        $dirty['msWMI-ChangeDate'] = $created
                        Set-ADObject -Identity $existing.DistinguishedName -Replace $dirty
                        Write-AdkLog "  updated WMI filter [$($f.Name)] ($cn)"
                        $cntUpdated++
                    }
                    continue
                }
            }
            Write-AdkLog "  WMI filter [$($f.Name)] up to date" -Step
            $cntUpToDate++
            continue
        }

        if ($PSCmdlet.ShouldProcess($f.Name, 'Create WMI filter')) {
            $attributes = @{
                'msWMI-Name'       = $f.Name
                'msWMI-Parm1'      = $f.Description
                'msWMI-Parm2'      = $parm2
                'msWMI-Author'     = $author
                'msWMI-ChangeDate' = $created
                'msWMI-CreationDate' = $created
                'msWMI-ID'         = $cn
            }

            New-ADObject -Name $cn -Type 'msWMI-Som' -Path $somPath `
                         -OtherAttributes $attributes
            Write-AdkLog "  created WMI filter [$($f.Name)] ($cn)"
            $cntCreated++
        }
    }

    Write-AdkLog "WMI filters: $cntCreated created, $cntUpdated updated, $cntUpToDate up to date" -Success
}

# Look up a WMI filter's object name ({GUID}) by its logical name (e.g. 'WS2025').
# Returns the {GUID} string (CN of the msWMI-Som object) or $null if not found.
# gPCWQLFilter uses [domain;{GUID};0] - not the full DN.
function Get-AdkWmiFilterId {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $Name,
        [Parameter(Mandatory)] [string] $DomainDn
    )

    $somPath = "CN=SOM,CN=WMIPolicy,CN=System,$DomainDn"

    # Same deterministic GUID logic as New-AdkWmiFilters.
    $guidBytes = [System.Text.Encoding]::UTF8.GetBytes("AdkWmiFilter:$Name")
    $md5       = [System.Security.Cryptography.MD5]::Create().ComputeHash($guidBytes)
    $filterGuid = [guid]::new($md5)
    $cn = "{$filterGuid}"

    $obj = Get-ADObject -Filter "objectClass -eq 'msWMI-Som' -and Name -eq '$cn'" `
                        -SearchBase $somPath -ErrorAction SilentlyContinue
    if ($obj) { return $obj.Name }   # e.g. {76c23708-39af-0c65-e282-61adc7d67f66}
    return $null
}
