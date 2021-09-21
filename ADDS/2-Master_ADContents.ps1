
Set-Location $PSScriptRoot

Import-Module ActiveDirectory

.\Reset-BuiltinDelegation.ps1

.\Create-ADContent.ps1

.\Create-Delegation.ps1

$GpoDir = Get-ChildItem .\gpobackup | Select -First 1
$MigTbl = Get-ChildItem $GpoDir.FullName -Filter "*.migtable"

.\Import_GPOs.ps1 -domain zwks.xyz -backupFolder $GpoDir.FullName -MigTable

$GpoDetails = [Xml] (Get-Content (Get-ChildItem $GpoDir.FullName Gpodetails.xml).FullName)

$Gpos = Import-Csv "$($GpoDir.FullName)\GpoInformation.csv" -Header "Name","Guid","LinkPath"
$GpoDetails.Objs.Obj | % {
    $Guid = "{$($_.MS.G.InnerText)}"
    $Path = "$($GpoDir.FullName)\$($Guid)"
    $Name = $_.MS.S[0].InnerText
    #Write-Host "Bid: $Guid $Name $Path"
    Import-GPO -CreateIfNeeded -Path $Path -MigrationTable $MigTbl -BackupId $Guid -TargetName $Name
}

