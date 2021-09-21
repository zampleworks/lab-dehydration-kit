<#
.SYNOPSIS
Reset this machines password

.AUTHOR
anders.runesson@enfogroup.com
#>
[CmdletBinding(
    SupportsShouldProcess = $True,
    ConfirmImpact = "High"
)]
Param()

$ErrorActionPreference = "Stop"

Try {
    If($PSCmdlet.ShouldProcess("local machine", "Reset computer password")) {
        Reset-ComputerMachinePassword
        Start-Sleep 2
        Reset-ComputerMachinePassword

        Write-Host "Server machine password reset (twice)" -ForegroundColor Green
    }
} Catch {
    Write-Host $_.Exception.Message
}

if(-not $psISE) {
    Write-Host ""
    Read-Host "Press play on tape"
}

