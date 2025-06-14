$ErrorActionPreference = "Stop"

If($PSVersionTable.PSVersion.Major -lt 5) {
    Write-Error "This script requires powershell 5 or newer to run"
}

$Script:Alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnpqrstuvwxyz0123456789!#@%&()[]{}=+?^*-_.:,<>|"

Function New-RandomPassword {
    param(
        [Parameter()]
        [int]$Length = 128,
        [Parameter()]
        [switch]$ConvertToSecureString
    )

    $PwdBytes = [byte[]]::New($Length)
    $i = 0
    while($i -lt $Length) {
        $PwdBytes[$i] = $Script:Alphabet[(Get-Random -Minimum 0 -Maximum $Script:Alphabet.Length)]
        $i = $i + 1
    }

    [string] $PwdStr = [string]::new($PwdBytes)
    If($ConvertToSecureString) {
        $Output = ConvertTo-SecureString $PwdStr -AsPlainText -Force
    } Else {
        $Output = [string]::new($PwdBytes)
    }
    Write-Output $Output
}
