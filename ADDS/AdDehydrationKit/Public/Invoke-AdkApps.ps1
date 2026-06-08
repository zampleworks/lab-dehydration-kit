# Wrapper that walks Apps.csv and invokes New-AdkApp for each row.
# This is what Install-AddsContent.ps1 calls.

function Invoke-AdkApps {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        [PSObject] $Context,

        [string] $AppsCsv
    )

    if ([string]::IsNullOrWhiteSpace($AppsCsv)) {
        $AppsCsv = Join-Path $Context.DataPath 'Apps.csv'
    }
    if (-not (Test-Path $AppsCsv -PathType Leaf)) {
        Write-AdkLog "Apps.csv not found at $AppsCsv - skipping app provisioning" -Warning
        return
    }

    $appRows = @(Import-Csv $AppsCsv -Delimiter ';' | Where-Object { -not [string]::IsNullOrWhiteSpace($_.AppName) })
    $appIndex = 0
    $appTotal = $appRows.Count
    foreach ($row in $appRows) {
        $appIndex++
        Write-Progress -Id 30 -ParentId 1 -Activity 'Apps' `
            -Status "$appIndex of $appTotal : $($row.Tier)/$($row.AppName)" `
            -PercentComplete (($appIndex / [Math]::Max($appTotal, 1)) * 100)

        $params = @{
            Context         = $Context
            AppName         = $row.AppName
            Tier            = $row.Tier
            ServerGpoBackup = $row.ServerGpoBackup
            SawGpoBackup    = $row.SawGpoBackup
        }
        if ($row.HasSaw -eq 'true') { $params.HasSaw = $true }
        if ($row.HasAma -eq 'true') { $params.HasAma = $true }

        Write-AdkLog "Provisioning app [$($row.Tier)/$($row.AppName)] (HasSaw=$($row.HasSaw), HasAma=$($row.HasAma))"
        try {
            # Forward -WhatIf explicitly: $WhatIfPreference does not
            # auto-propagate across module function boundaries inside
            # the same module, and we want apps provisioning to honor
            # the orchestrator's WhatIf.
            New-AdkApp @params -WhatIf:$WhatIfPreference
        } catch {
            Write-AdkLog "  app [$($row.Tier)/$($row.AppName)] failed: $($_.Exception.Message)" -IsError
        }
    }

    Write-Progress -Id 30 -ParentId 1 -Activity 'Apps' -Completed
}
    