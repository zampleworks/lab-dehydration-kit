<#
.SYNOPSIS
Rebuild Global Catalog on this server. This typically takes about 5 minutes, and the script 
will monitor progress and notify you when the process has finished.

.NOTES
Author anders.runesson@enfogroup.com
#>
[CmdletBinding(
    SupportsShouldProcess = $True,
    ConfirmImpact = "High"
)]
Param()

$ErrorActionPreference = "Stop"

Try {

    $DomainCount = Get-ADForest | Select -ExpandProperty Domains | Measure-Object | Select-Object -ExpandProperty Count
    If($DomainCount -eq 1) {
        Write-Host ""
        Write-Host "Removing Global Catalog is not required in a single-domain forest. Exiting." -ForegroundColor Yellow
        
        If(-Not $psISE) {
            Read-Host "Press play on tape"
        }
        
        Return
    }

    $Hostname = hostname
    $ForestDN = Get-ADForest | Select-Object -ExpandProperty RootDomain
    $DsaOptions = & repadmin /options
    $IsGc = ($DsaOptions | Where-Object { $_ -like "*IS_GC*" } | Measure-Object | Select -ExpandProperty Count) -gt 0

    If($PSCmdlet.ShouldProcess($Hostname, "Rebuild GC for forest $ForestDN")) {
        Write-Host "Removing global catalog from server. Monitor Directory Service log for event id 1120"

        # Setting this value will allow logons to proceed even when GC is not available"
        If($IsGc) {
            $Demoted = $False
            Set-ItemProperty -Path "HKLM:SYSTEM\CurrentControlSet\Control\Lsa" -Name "IgnoreGCFailures" -Value 1
            repadmin.exe /options $(&hostname) -IS_GC

            Write-Host "Waiting for GC removal to finish. Please wait.."
            $t1 = Get-Date
            do {
                $Demoted = (Get-EventLog -LogName "Directory Service" -After (Get-Date).AddMinutes(-1) | Where-object { $_.EventID -eq 1120 } | Measure-Object | Select -expand Count) -gt 0

                Start-Sleep -Seconds 1
    
                $t2 = Get-Date
                $diff = $t2 - $t1

                Write-Progress -Activity "Waiting for GC removal to finish." -Status ("Time taken: {0:d2}:{1:d2}:{2:d2}" -f $diff.Hours,$diff.Minutes, $diff.Seconds)

            } While (-Not $Demoted)

            Write-Host ("GC removal finished in {0:d2}:{1:d2}:{2:d2}." -f $diff.Hours,$diff.Minutes, $diff.Seconds)
            Write-Host ""

        } Else {
        
            Write-Host "Adding this server as Global Catalog. Monitor Directory Service log for event id 1119"

            repadmin.exe /options $(&hostname) +IS_GC
    
            Write-Host "GC promotion will take a few minutes to allow the partial replica to be rebuilt. Please wait.."

            $Promoted = $False
            $t1 = Get-Date
            do {
                $Promoted = (Get-EventLog -LogName "Directory Service" -After (Get-Date).AddMinutes(-1) | Where-object { $_.EventID -eq 1119 } | Measure-Object | Select -expand Count) -gt 0
                Start-Sleep -Seconds 1
    
                $t2 = Get-Date
                $diff = $t2 - $t1

                Write-Progress -Activity "Waiting for GC promotion to finish." -Status ("Time taken: {0:d2}:{1:d2}:{2:d2}" -f $diff.Hours,$diff.Minutes, $diff.Seconds)
            } while (-not $Promoted)

            # Remove 'Allow logon without GC'
            Remove-ItemProperty -Path "HKLM:SYSTEM\CurrentControlSet\Control\Lsa" -Name "IgnoreGCFailures"

            Write-Host ""
            Write-Host "Promotion to GC complete"
        }
    }
    # Get-ItemProperty "HKLM:SYSTEM\CurrentControlSet\Control\Lsa" -Name "IgnoreGCFailures"
    # Get-ItemProperty "HKLM:System\CurrentControlSet\Services\NTDS\Parameters" -Name "Global Catalog Promotion Complete"

} Catch {
    Write-Host $_.Exception.Message
}

if(-not $psISE) {
    Write-Host ""
    Read-Host "Press play on tape"
}

