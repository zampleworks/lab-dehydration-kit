
Function Log {
    Param(
        [string] $Msg,
        [switch] $Error,
        [switch] $Warning
    )

    If($Error) {
        Write-Host "$Msg" -ForegroundColor Red
    } Elseif($Warning) {
        Write-Host "$Msg" -ForegroundColor Yellow
    } Else {
        Write-Host "$Msg"
    }
}

Function LogE {
    Param(
        $E
    )

    $Ex = $E
    
    Log "Exception caught" -Error
    Do {
        Log "Error code: $($Ex.Exception.HResult): " -Error
        Log "$($Ex.Exception.Message)" -Warning
        Log "$($Ex.Exception.StackTrace)`n" -Warning
        $Ex = $Ex.InnerException
    } While ($Ex -ne $Null)
}

Function Create-TestOus {
    Param(
        [Parameter(mandatory=$True)]
        [Hashtable[]] 
        $Ous,

        [Parameter(mandatory=$True)]
        [string]
        $ParentOUPath,

        [Parameter(mandatory=$True)]
        [string]
        $DomainRoot
    )

    If($Ous -eq $Null) {
        Log "Nothing to do"
        return
    }
    
    Foreach($childOu in $Ous) {
        
        Foreach($Entry in $childOu.GetEnumerator()) {
            $Name = $Entry.Key
            $Children = $Entry.Value
            $Path = "OU=$Name,$ParentOUPath"
            $ParentPath = "$ParentOUPath,$DomainRoot"

            $pOu = $Null
            Try { 
                $pOu = Get-ADOrganizationalUnit "$Path,$DomainRoot" 
            } Catch {
                If($_.Exception.HResult -eq -2146233088) {
                    Log "Creating $Path,$DomainRoot"
                    $pOu = New-ADOrganizationalUnit -Name $Name -Path $ParentPath -PassThru
                    Set-ADOrganizationalUnit $pOu -ProtectedFromAccidentalDeletion:$False
                } else {        
                    LogE $_
                    Return
                }
            }
            
            If($Children.Count -gt 0) {
                Create-TestOus -Ous $Children -ParentOUPath $Path -DomainRoot $DomainRoot
            }
        }
    }
}

$Ous = @(@{ 'Test-OU' = @(@{'Computers' = @()}, @{'Users' = @(@{'Employees' = @()}, @{'Service Accounts' = @()})}, @{'Groups' = @(@{'DL' = @()}, @{'Roles' = @()}, @{'IT Roles' = @()}, @{'Rights' = @()})})})

$Domain = Get-ADDomain

$Ouname = "Test-OU"
$OuPath = "OU=AD001,$($Domain.DistinguishedName)"
$OuFullPath = "OU=$OuName,$OuPath"
$Ou = $Null

Create-TestOus $Ous "OU=AD001" $($Domain.DistinguishedName)

$Pwd = ConvertTo-SecureString "P@ssw0rd" -AsPlainText -Force


New-ADUser -Name t1 -SamAccountName t1 -AccountPassword $Pwd -Path "OU=Employees,OU=Users,$OuFullPath" -Enabled:$True
New-ADUser -Name t2 -SamAccountName t2 -AccountPassword $Pwd -Path "OU=Employees,OU=Users,$OuFullPath" -Enabled:$True
New-ADUser -Name t3 -SamAccountName t3 -AccountPassword $Pwd -Path "OU=Service accounts,OU=Users,$OuFullPath" -Enabled:$True
New-ADUser -Name t4 -SamAccountName t4 -AccountPassword $Pwd -Path "OU=Service accounts,OU=Users,$OuFullPath" -Enabled:$True
New-ADUser -Name t5 -SamAccountName t5 -AccountPassword $Pwd -Path "OU=Users,$OuFullPath" -Enabled:$True
New-ADUser -Name t6 -SamAccountName t6 -AccountPassword $Pwd -Path "OU=Users,$OuFullPath" -Enabled:$True


return

Remove-ADOrganizationalUnit $OuFullPath -Recursive -Confirm:$False

