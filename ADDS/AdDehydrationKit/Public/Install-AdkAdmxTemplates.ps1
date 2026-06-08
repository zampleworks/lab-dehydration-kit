# Deploy ADMX templates to the SYSVOL Central Store.
#
# The caller is expected to provide a PolicyDefinitions.zip next to the
# Data\ folder (i.e. in the same directory as Install-AddsContent.ps1).
# The zip must contain a PolicyDefinitions\ root folder whose contents
# are extracted verbatim into:
#   \\<domain>\SYSVOL\<domain>\Policies\PolicyDefinitions\
#
# If PolicyDefinitions.zip is absent the step logs a warning and returns
# without error so the rest of the deployment is not blocked.

function Install-AdkAdmxTemplates {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        [PSObject] $Context
    )

    $zipPath = Join-Path $Context.DataPath 'PolicyDefinitions.zip'

    if (-not (Test-Path $zipPath -PathType Leaf)) {
        Write-AdkLog "PolicyDefinitions.zip not found at $zipPath - ADMX templates skipped" -Warning
        return
    }

    $domainDns      = $Context.DomainDnsName
    $sysvolPolicies = "\\$domainDns\SYSVOL\$domainDns\Policies"

    if (-not (Test-Path $sysvolPolicies)) {
        throw "SYSVOL policies path not accessible: $sysvolPolicies"
    }

    $centralStore  = Join-Path $sysvolPolicies 'PolicyDefinitions'
    $forceImport   = [bool]$Context.Force
    $existingAdmx  = @(Get-ChildItem -Path $centralStore -Filter '*.admx' -ErrorAction SilentlyContinue)

    if ($existingAdmx.Count -gt 0 -and -not $forceImport) {
        Write-AdkLog "ADMX Central Store already populated ($($existingAdmx.Count) .admx files)" -Success
        return
    }

    Write-AdkLog "Extracting ADMX templates to $centralStore" -Step

    if (-not $PSCmdlet.ShouldProcess($centralStore, 'Extract ADMX templates to Central Store')) {
        return
    }

    Add-Type -AssemblyName System.IO.Compression.FileSystem

    $zip      = [System.IO.Compression.ZipFile]::OpenRead($zipPath)
    $cntFiles = 0

    try {
        foreach ($entry in $zip.Entries) {
            # Skip pure directory entries (FullName ends with /)
            if ($entry.FullName -match '[/\\]$') { continue }

            $destPath   = Join-Path $sysvolPolicies $entry.FullName
            $destFolder = Split-Path $destPath -Parent

            if (-not (Test-Path $destFolder)) {
                New-Item -ItemType Directory -Path $destFolder -Force | Out-Null
            }

            # ExtractToFile with $true = overwrite existing files
            [System.IO.Compression.ZipFileExtensions]::ExtractToFile($entry, $destPath, $true)
            $cntFiles++
        }
    } finally {
        $zip.Dispose()
    }

    Write-AdkLog "ADMX templates: $cntFiles files deployed to Central Store" -Success
}
