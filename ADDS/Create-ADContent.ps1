$ErrorActionPreference = "Stop"

If($PSVersionTable.PSVersion.Major -lt 5) {
    Write-Error "This script requires powershell 5 or newer to run"
}

If($Null -eq $LocalObjectsPath) {
    $LocalObjectsPath = Get-Item .\Objects | Select-Object -ExpandProperty FullName
}

If(-Not (Test-Path "$LocalObjectsPath\OU.csv" -PathType Leaf)) {
    Throw "File OU.csv is missing from $LocalObjectsPath"
}

. .\Functions.ps1

Import-Module ActiveDirectory -Verbose:$False

$PwdFilePath = ".\User-pwd.csv"
If(-Not (Test-Path $PwdFilePath -PathType Leaf)) {
    "Samaccountname;Password" | Out-File $PwdFilePath -Force
}

$PwdFilePath = Get-ChildItem ".\User-pwd.csv" | Select-Object -ExpandProperty FullName

$DomainNBName = Get-ADDomain | Select-Object -ExpandProperty NetbiosName
$DomainDNSName = Get-ADDomain | Select-Object -ExpandProperty DNSRoot
$DomainDN = Get-ADDomain | Select-Object -ExpandProperty DistinguishedName 

$RootDN = $DomainDN
#$RootDN = "OU=TestRoot,$DomainDN"

# This variable will change names of objects created. This is only for testing the Create-ADContent script.
# Deployed GPOs will not work if an actual deployment is done using a prefix.
$ObjectsPrefix = ""

$ExistingUsers = @{}
Get-ADUser -Filter * | ForEach-Object { $ExistingUsers[$_.Samaccountname] = $_}

$ExistingGroups = @{}
Get-ADGroup -Filter * | ForEach-Object { $ExistingGroups[$_.Samaccountname] = $_}

$ExistingOus = @{}
Get-ADOrganizationalUnit -Filter * | ForEach-Object { $ExistingOus[$_.DistinguishedName] = $_}

$Ous = Import-Csv $LocalObjectsPath\OU.csv -Delimiter ";"

# Replacements for parent OU names and paths
$Replacements = @{ 
    "%RootDN%" = $RootDN
}

# Generic search-and-replace strings
$StringReplacements = @{ 
    "%DomainNBName%" = $DomainNBName
}

# Overwrite oustructure.csv
"Name;DN" | Out-File "$LocalObjectsPath\OUStructure.csv" -Encoding utf8 -Force

<#
 # Convert characters with diacritic marks to ascii equivalent
#>
function Convert-DiacriticCharacters {
    param(
        [string]$inputString
    )
    [string]$formD = $inputString.Normalize(
            [System.text.NormalizationForm]::FormD
    )
    $stringBuilder = new-object System.Text.StringBuilder
    for ($i = 0; $i -lt $formD.Length; $i++){
        $unicodeCategory = [System.Globalization.CharUnicodeInfo]::GetUnicodeCategory($formD[$i])
        $nonSPacingMark = [System.Globalization.UnicodeCategory]::NonSpacingMark
        if($unicodeCategory -ne $nonSPacingMark){
            $stringBuilder.Append($formD[$i]) | out-null
        }
    }
    $stringBuilder.ToString().Normalize([System.text.NormalizationForm]::FormC)
}

#
# Build proper name and path for each OU 
#
Foreach($Ou in $Ous) {
    Foreach($Rep in $StringReplacements.GetEnumerator()) {
        $r = $Rep.Key
        $v = $Rep.Value

        If($Ou.DisplayName.Contains($r)) {
            $Ou.DisplayName = $Ou.DisplayName.Replace($r, $v)
        }

        If($Ou.CN.Contains($r)) {
            $Ou.CN = $Ou.CN.Replace($r, $v)
        }
    }
}

#
# Create each OU or read from AD if it already exists
#
Write-Host "Creating OUs"
Foreach($Ou in $Ous) {
    $Parent = $Replacements.GetEnumerator() | Where-Object { $_.Key -eq $Ou.Parent } | Select-Object -ExpandProperty Value

    If([string]::IsNullOrWhiteSpace($Parent)) {
        Write-Verbose "No replacement found in Parent for $($Ou.Name)"
        Continue
    }

    $Path = "$Parent"
    $Name = $Ou.Name
    $CN = $Ou.CN
    $DN = "OU=$($CN),$Path"
    
    If(-Not ($ExistingOus.Keys -contains $DN)) {
        Try {
            $NewOu = New-ADOrganizationalUnit -Path $Parent -DisplayName $Ou.DisplayName -Name $CN -PassThru -Confirm:$False
            $ExistingOus[$NewOu.DistinguishedName] = $NewOu
            Write-Verbose "Created OU for $Name : $DN"
        } Catch {
            Write-Error "Could not create OU [$DN]: $($_.Exception.Message)"
        }
    }

    $Replacements.Add("%$Name%", $DN)
    $Ou.Created = $True
    "%$Name%;$DN" | Out-File "$LocalObjectsPath\OUStructure.csv" -Append -Encoding utf8 -Force -NoClobber
}

$OuDefinitions = Import-csv "$LocalObjectsPath\OUStructure.csv" -Delimiter ";"

#$OperationsRootOU = $OuDefinitions | Where-Object { $_.Name -eq "%OperationsRootOU%" } | Select-Object -ExpandProperty DN
#$T0RootOU = $OuDefinitions | Where-Object { $_.Name -eq "%DSControlOU%" } | Select-Object -ExpandProperty DN
#$T1RootOU = $OuDefinitions | Where-Object { $_.Name -eq "%OperationsRootOU%" } | Select-Object -ExpandProperty DN
#$OrgRootOU = $OuDefinitions | Where-Object { $_.Name -eq "%OrgRoot%" } | Select-Object -ExpandProperty DN

$EmployeesOu = $OuDefinitions | Where-Object { $_.Name -eq "%OrgEmployeeAcctsOU%" } | Select-Object -ExpandProperty DN
$RolesOU = $OuDefinitions | Where-Object { $_.Name -eq "%OrgRolesOU%" } | Select-Object -ExpandProperty DN

$T1RolesOU = $OuDefinitions | Where-Object { $_.Name -eq "%T1RolesOU%" } | Select-Object -ExpandProperty DN
$T1PermissionsOU = $OuDefinitions | Where-Object { $_.Name -eq "%T1PermissionsOU%" } | Select-Object -ExpandProperty DN
$T1AdminsOU = $OuDefinitions | Where-Object { $_.Name -eq "%T1AdminsOU%" } | Select-Object -ExpandProperty DN
$T1StdUsersOU = $OuDefinitions | Where-Object { $_.Name -eq "%T1StdUsersOU%" } | Select-Object -ExpandProperty DN

$DsControlRolesOU = $OuDefinitions | Where-Object { $_.Name -eq "%DSControlRolesOU%" } | Select-Object -ExpandProperty DN
$DsControlPermissionsOU = $OuDefinitions | Where-Object { $_.Name -eq "%DSControlPermsOU%" } | Select-Object -ExpandProperty DN
$DsControlClaimsOU = $OuDefinitions | Where-Object { $_.Name -eq "%DSControlClaimsOU%" } | Select-Object -ExpandProperty DN
$DsControlAmaOU = $OuDefinitions | Where-Object { $_.Name -eq "%DSControlAmaOU%" } | Select-Object -ExpandProperty DN
$DsControlAdminsOU = $OuDefinitions | Where-Object { $_.Name -eq "%DSControlAdminsOU%" } | Select-Object -ExpandProperty DN
$DsControlStdUsersOU = $OuDefinitions | Where-Object { $_.Name -eq "%DSControlStdUsersOU%" } | Select-Object -ExpandProperty DN

$DsControlSvcAcctsOu = $OuDefinitions | Where-Object { $_.Name -eq "%DSControlSvcAcctsOU%" } | Select-Object -ExpandProperty DN
$T1SvcAcctsOu = $OuDefinitions | Where-Object { $_.Name -eq "%T1SvcAcctsOU%" } | Select-Object -ExpandProperty DN

$GroupMembers = Import-csv "$LocalObjectsPath\GroupMembers.csv" -Delimiter ";" | Where-Object { -not [string]::IsNullOrWhiteSpace($_.Member)}
$AdminUnits = Import-csv "$LocalObjectsPath\Admins.csv" -Delimiter ";" | Where-Object { $_.Type -eq "Dept" }
$AdminPersons = Import-csv "$LocalObjectsPath\Admins.csv" -Delimiter ";" | Where-Object { $_.Type -eq "Person" }
$Groups = Import-Csv "$LocalObjectsPath\Groups.csv" -Delimiter ";" | Where-Object { -not [string]::IsNullOrWhiteSpace($_.Name)}
$AccountDefinitions = Import-csv "$LocalObjectsPath\Accounts.csv" -Delimiter ";"
$DeptRoles = Get-Content "$LocalObjectsPath\DeptRoles.csv"

# Read employees and user ID series 
$Employees = Import-csv "$LocalObjectsPath\UserDB\Employee.csv" -Delimiter "`t" ` | Where-Object { $_.CurrentFlag -eq 1 }
$MaxId = $Employees | Select-Object -ExpandProperty BusinessEntityID | Select-Object -Last 1

# Build list of Persons to create accounts for
$Persons = Import-Csv "$LocalObjectsPath\UserDB\Person.csv" -delimiter "|" | Select-Object -first $MaxId | ForEach-Object {
    $_.BusinessEntityID = $_.BusinessEntityID.Replace("+", "")
    
    If([Int]::Parse($_.BusinessEntityID) -le $MaxId) {
        $_.FirstName = $_.FirstName.Replace("+", "")
        $_.LastName = $_.LastName.Replace("+", "")
        $_.Initial = $_.Initial.Replace("+", "")
        Write-Output $_
    }
}

# Read departments
$Departments = Import-Csv "$LocalObjectsPath\UserDB\Department.csv" -Delimiter "`t"

# Read active employments
$ActiveEmployments = Import-Csv "$LocalObjectsPath\UserDB\EmployeeDepartmentHistory.csv" -Delimiter "`t" | ForEach-Object { 
    If([string]::IsNullOrWhiteSpace($_.EndDate)) { Write-Output $_ }
}

$AdminDepartmentNames = $AdminUnits | Select-Object -ExpandProperty Name
$AdminPersonSamaccountnames = $AdminPersons | Select-Object -ExpandProperty Name
$AdminDepartments = $Departments | Where-Object { $AdminDepartmentNames -contains $_.Name }
$AdminDepartmentsIds = $AdminDepartments | Select-Object -ExpandProperty DepartmentID

$AdminAccounts = $Employees | ForEach-Object {
    $Employee = $_
    $Samaccountname = $Employee.UserNBAccount.Substring($Employee.UserNBAccount.IndexOf("\") + 1)
    $Employment = $ActiveEmployments | Where-Object { $_.BusinessEntityID -eq $Employee.BusinessEntityID }

    If($AdminDepartmentsIds -contains $Employment.DepartmentID) {
        $Dept = $AdminDepartments | Where-Object { $_.DepartmentID -eq $Employment.DepartmentID }
        $AdminUnit = $AdminUnits | Where-Object { $_.Name -eq $Dept.Name }
        $obj = [PSCustomObject]@{
            AccountName = $Samaccountname
            EmployeeTitle = $Employee.Position
            Department = $Dept.Name;
            AdminAccountTier = $AdminUnit.Tier
        }
        Write-Output $obj
    }
    
    If($AdminPersonSamaccountnames -contains $Samaccountname) {
        $AdminPerson = $AdminPersons | Where-Object { $_.Name -eq $Samaccountname }
        $Dept = $Departments | Where-Object { $_.DepartmentID -eq $Employment.DepartmentID }
        $obj = [PSCustomObject]@{
            AccountName = $Samaccountname
            EmployeeTitle = $Employee.Position
            Department = $Dept.Name;
            AdminAccountTier = $AdminPerson.Tier
        }
        Write-Output $obj
    }
}

<#
    TEST CODE - DELETE OU STRUCTURE

    Set-ADOrganizationalUnit $OperationsRootOU -ProtectedFromAccidentalDeletion $False
    Set-ADOrganizationalUnit $OrgRootOU -ProtectedFromAccidentalDeletion $False
    Remove-ADOrganizationalUnit $OrgRootOU -Confirm:$false -Recursive
    Remove-ADOrganizationalUnit $OperationsRootOU -Confirm:$false -Recursive
#>


Write-Host "Creating service accounts.."

# Create built-in Service accounts
Foreach($Account in $AccountDefinitions) {
    $n = $Account.Name
    $s = "$ObjectsPrefix$($Account.Samaccountname)"
    
    If($Account.Class -eq "T1") {
        $Ou = $T1SvcAcctsOu
    } Elseif($Account.Class -eq "T0") {
        $Ou = $DsControlSvcAcctsOu
    } Else {
        Write-Warning "Unknown account class on $($Account.Samaccountname): $($Account.Class). Skipping"
        Continue
    }

    If($ExistingUsers.ContainsKey($s)) {
        $u = Get-ADUser $s
        Write-Verbose "Account [$s] already exists" 
        continue
    }

    Try {
        $u = $Null
        $NewPwd = New-RandomPassword -Length 24
        $NewSecPwd = ConvertTo-SecureString $NewPwd -AsPlainText -Force
        $u = New-ADUser -name $n -displayname $n -Samaccountname $s -userprincipalname "$s@$DomainDNSName" -path $Ou -Enabled $false -KerberosencryptionType AES128,AES256 -AccountNotDelegated $true -Confirm:$False -AccountPassword $Pw -PassThru
        Set-ADAccountPassword $u -NewPassword $NewSecPwd -Reset
        Enable-ADAccount $u
        $ExistingUsers.Add($s, $u)

        "$s;$NewPwd" | Out-File $PwdFilePath -Append

        Write-Verbose "Created account $s"
    } Catch {
        Write-Error "Error creating service account $($s): $($_.Exception.Message)"
    }
}

Write-Host "Preparing role groups and employee data"

Write-Host "Creating business role groups"

# Create Role groups for each department - finance, management etc
Foreach($Dept in $Departments) {
    Foreach($DeptRole in $DeptRoles) {
        $GroupName = "$($ObjectsPrefix)Role Org $($Dept.Name) $DeptRole"
        
        If($ExistingGroups.ContainsKey($GroupName)) {
            Write-Verbose "Business role group [$GroupName] already exists"
            continue
        }
        
        Try {
            $NewGroup = $Null
            $NewGroup = New-ADGroup -Name $GroupName -DisplayName $GroupName -GroupCategory Security -GroupScope Global -Path $RolesOU -PassThru
            $ExistingGroups[$NewGroup.Samaccountname] = $NewGroup
            Write-Verbose "Created business role group $GroupName"
        } Catch {
            Write-Error "Error creating business role group ${GroupName}: $($_.Exception.Message)"
        }
    }
}

<#
#    Test code - Validate contents of Groups.csv and GroupMembers.csv

    # Build a list of all defined principal names to test against
    $MatchWithNames = & {
        Write-Output $Groups | Select-Object -ExpandProperty Name
        Write-Output $AdminAccounts | Where { $_.AdminAccountTier -eq "T0"} | Select-Object accountname | Foreach-Object { 
            $nm = $_.AccountName
            "at0_$nm" 
        }
        Write-Output $AdminAccounts | Where { $_.AdminAccountTier -eq "T1"} | Select-Object accountname | Foreach-Object { 
            $nm = $_.AccountName
            "at1_$nm" 
        }
        Write-Output $AdminAccounts | Where { $_.AdminAccountTier -eq "T0"}| Select-Object accountname | Foreach-Object { 
            $nm = $_.AccountName
            "t0_$nm" 
        }
        Write-Output $AdminAccounts | Where { $_.AdminAccountTier -eq "T1"}| Select-Object accountname | Foreach-Object { 
            $nm = $_.AccountName
            "t1_$nm" 
        }
        Write-Output $Employees | Select-Object -ExpandProperty UserNBAccount | Foreach-Object { $_.Substring($_.IndexOf("\") + 1)}
        Write-Output $AccountDefinitions | Select-Object -ExpandProperty Samaccountname
    }

    $ErrorActionPreference = "silentlycontinue"
    foreach($entry in $GroupMembers) {
        #$SamaccountName = "$ObjectsPrefix$($role.Username)"
        $SamaccountName = $entry.Member

        $memberRecord = $Null
        $memberRecord = $MatchWithNames | Where-Object { $_ -eq $SamaccountName }
        If($null -eq $memberRecord) {
            Write-Host "Member $SamaccountName not found in Groups.csv entries. Built-in group/principal?" -ForegroundColor DarkYellow
            Continue
        }
        
        $memberOfGroups = $entry.MemberOf.Split(",")
        foreach($group in $memberOfGroups) {
            $adGroup = $Null
            $adGroup = $Groups | Select-Object -ExpandProperty Name | Where-Object { $_ -eq $group}
            If($null -eq $adGroup) {
                Write-Host "$samaccountname - $group not found in Groups.csv entries. Built-in group/principal?" -ForegroundColor DarkYellow
                Continue
            }
        }
    }

#>

#
# Create groups from groups.csv
# 

Write-Host "Creating additional groups (permissions, IT roles, etc)"

Foreach($Group in $Groups) {
     
    If($Group.Type -eq "Role") {
        $CreateIn = $RolesOU
    } Elseif($Group.Type -eq "Permission") {
        $CreateIn = $T1PermissionsOU
    } Elseif($Group.Type -eq "DSPermission") {
        $CreateIn = $DsControlPermissionsOU
    } Elseif($Group.Type -eq "DSRole" -Or $Group.Type -eq "DSClientGroup" -Or $Group.Type -eq "DSServerGroup") {
        $CreateIn = $DsControlRolesOU
    } Elseif($Group.Type -eq "OpsServerGroup") {
        $CreateIn = $T1RolesOU
    } Elseif($Group.Type -eq "Claim") {
        $CreateIn = $DsControlClaimsOU
    } Elseif($Group.Type -eq "AMA") {
        $CreateIn = $DsControlAmaOU
    } Elseif($Group.Type -eq "ClientGroup") {
        $CreateIn = $RolesOU
    } Else {
        Write-Warning "Unknown group type: [$($Group.Type)]. [$GroupName] Skipping"
        Continue
    }

    $GroupName = "$ObjectsPrefix$($Group.Name)"
    
    If($ExistingGroups.ContainsKey($GroupName)) {
        Write-Verbose "Role group [$GroupName] already exists"
        continue
    }

    Try {
        $NewGroup = $Null
        $NewGroup = New-ADGroup -Name $GroupName -DisplayName $GroupName -GroupCategory Security -GroupScope $Group.Scope -Path $CreateIn -PassThru
        $ExistingGroups[$NewGroup.Samaccountname] = $NewGroup
        Write-Verbose "Created role group [$GroupName] in [$CreateIn]"
    } Catch {
        Write-Error "Error creating AD group [${GroupName}]: $($_.Exception.Message)"
    }
}

#
# Create employee accounts, and add them to department role groups
#

Write-Host "Creating employees"

Foreach($Emp in $Employees) { 
    $Person = $Persons | Where-Object { $_.BusinessEntityID -eq $Emp.BusinessEntityID }
    $Employment = $Null
    $Dept = $Null
    $JobTitle = $Null

    If($Null -ne $Person) {
        $Bid = $Emp.BusinessEntityID
        $Employment = $ActiveEmployments | Where-Object { $_.BusinessEntityID -eq $Bid }
        
        If($Null -ne $Employment) {
            $Dept = $Departments | Where-Object { $_.DepartmentID -eq $Employment.DepartmentID }
        }

        $Fn = $($Person.FirstName).Trim()
        $Sn = $($Person.LastName).Trim()
        $In = $($Person.Initial).Trim()
        $DeptName = $Dept.Name
        $DispN = "$Fn"
        $JobTitle = $Emp.Position

        If(-Not [string]::IsNullOrWhiteSpace($In)) {
            $DispN += " $In"
        }

        $DispN += " $Sn"

        $Sam = "$ObjectsPrefix$($Emp.UserNBAccount.Substring($Emp.UserNBAccount.IndexOf("\") + 1))"
        $Upn = Convert-DiacriticCharacters "$Fn.$Sn@$DomainDNSName"

        If($ExistingUsers.ContainsKey($Sam)) {
            $AdUser = $ExistingUsers | Where-Object { $_.Samaccountname -eq $Sam }
        } Else {
            Try {
                $AdUser = New-ADUser -name $DispN -displayname $DispN -GivenName $Fn -Surname $Sn -Samaccountname $Sam -userprincipalname $Upn -EmployeeNumber $Bid -Department $DeptName `
                     -Title $JobTitle -path $EmployeesOu -Enabled $false -KerberosencryptionType AES128,AES256 -AccountNotDelegated $true -Confirm:$False -AccountPassword $Pw -PassThru
                
                $NewPwd = New-RandomPassword -Length 24
                $NewSecPwd = ConvertTo-SecureString $NewPwd -AsPlainText -Force
                "$Sam;$NewPwd" | Out-File $PwdFilePath -Append
                Set-ADAccountPassword $AdUser -NewPassword $NewSecPwd -Reset
                
                Enable-ADAccount $AdUser

                $ExistingUsers[$Sam] = $AdUser
                
                Write-Verbose "Created: [$($AdUser.Name)] [$DeptName] [$JobTitle] [$DomainNBName\$($AdUser.SamAccountName)]"
            } Catch {
                Write-Warning "Error creating user [$Upn] [$DispN]: " -ForegroundColor Red
                Write-Warning $_.Exception.Message
            }
        } 

        $EmplGroup = Get-ADGroup "$($ObjectsPrefix)Role Org Employee" -Properties members
        If(-Not ($EmplGroup.Members -contains $AdUser)) {
            Write-Verbose  "Add to [$($EmplGroup.Samaccountname)]: [$($u.Name)] [$DomainNBName\$($AdUser.SamAccountName)]"
            Add-ADGroupMember $EmplGroup -Members $AdUser | Out-Null
        }

        $DgName = "$($ObjectsPrefix)Role Org $DeptName Employee"
        Try {
            $DeptGroup = Get-ADGroup $DgName -Properties members
            If(-Not ($DeptGroup.Members -contains $AdUser)) {
                Write-Verbose "Add to [$($DeptGroup.Samaccountname)]: [$($AdUser.Name)] [$DomainNBName\$($AdUser.SamAccountName)]"
                Add-ADGroupMember $DeptGroup -Members $AdUser | Out-Null
            }
        } Catch {
            Write-Warning "  --> Failed to add [$DomainNBName\$sam] to department group $($DgName): $($_.Exception.Message)"
        }
    }
}

#
# Create admin accounts for the users listed in admins.csv
#

Write-Host "Creating admin accounts"

Foreach($Admin in $AdminAccounts) {
    $EmployeeAccountName = $Admin.AccountName.Substring($Admin.AccountName.IndexOf("\") + 1)
    $EmployeeAccountName = $Admin.AccountName.Substring($Admin.AccountName.IndexOf("\") + 1)
    $Tier = $Admin.AdminAccountTier
    $un = "$($ObjectsPrefix)$EmployeeAccountName"
    If($Tier -eq "t0") {
        $TargetOu = $DSControlAdminsOU
    } Else {
        $TargetOu = $T1AdminsOU
    }

    If($ExistingUsers.ContainsKey($un)) {
        $AdUserOwner = $ExistingUsers[$un]
    } Else {
        Write-Warning "Could not find user account [$un] to create admin account for"
        continue
    }

    $an = "$($ObjectsPrefix)a$($Tier.ToLower())_$EmployeeAccountName"
    
    $excessLength = $an.Length - 15
    If($excessLength -gt 0) {
        $anOld = $an
        $an = $an.Substring(0, 15)
        Write-Warning "$anOld too long - trimmed to $an"
    }

    If($ExistingUsers.ContainsKey($an)) {
        Write-Verbose "Admin account [$an] for [$un] already exists."
        continue
    } 
    
    Try {
        $name = $AdUserOwner.Name
        $DisplayName = "$Tier Admin $name"
        $NewAdUser = $Null

        $NewPwd = New-RandomPassword -Length 24
        $NewSecPwd = ConvertTo-SecureString $NewPwd -AsPlainText -Force
        "$an;$NewPwd" | Out-File $PwdFilePath -Append
        
        $NewAdUser = New-ADUser -Name $DisplayName -SamAccountName $an -AccountPassword $NewSecPwd -GivenName $AdUserOwner.GivenName -Path $TargetOu -Surname $AdUserOwner.Surname -DisplayName $DisplayName `
            -Enabled $True -KerberosencryptionType AES128,AES256 -AccountNotDelegated $true -UserPrincipalName "$an@$DomainDNSName" -PassThru
    
        $ExistingUsers[$an] = $NewAdUser
        Write-Verbose "Created admin account [$an] for [$un]"
    } Catch {
        Write-Warning "Error creating admin [$an] account for $un"
        Write-Warning $_.Exception.Message
    }
}

Write-Host "Creating Tier 0/1 user accounts"

Foreach($Admin in $AdminAccounts) {
    $EmployeeAccountName = $Admin.AccountName.Substring($Admin.AccountName.IndexOf("\") + 1)
    $EmployeeAccountName = $Admin.AccountName.Substring($Admin.AccountName.IndexOf("\") + 1)
    $Tier = $Admin.AdminAccountTier
    $un = "$($ObjectsPrefix)$EmployeeAccountName"
    If($Tier -eq "t0") {
        $TargetOu = $DsControlStdUsersOU
    } Else {
        $TargetOu = $T1StdUsersOU
    }

    If($ExistingUsers.ContainsKey($un)) {
        $AdUserOwner = $ExistingUsers[$un]
    } Else {
        Write-Warning "Could not find user account [$un] to create secure user account for"
        continue
    }

    $an = "$($ObjectsPrefix)$($Tier.ToLower())_$EmployeeAccountName"
    
    $excessLength = $an.Length - 15
    If($excessLength -gt 0) {
        $anOld = $an
        $an = $an.Substring(0, 15)
        Write-Warning "$anOld too long - trimmed to $an"
    }

    If($ExistingUsers.ContainsKey($an)) {
        Write-Verbose "$Tier account [$an] for [$un] already exists."
        continue
    } 
    
    Try {
        $name = $AdUserOwner.Name
        $DisplayName = "$Tier $name"
        
        $NewPwd = New-RandomPassword -Length 24
        $NewSecPwd = ConvertTo-SecureString $NewPwd -AsPlainText -Force
        "$an;$NewPwd" | Out-File $PwdFilePath -Append
        
        $NewAdUser = $Null
        $NewAdUser = New-ADUser -Name $DisplayName -SamAccountName $an -AccountPassword $NewSecPwd -GivenName $AdUserOwner.GivenName -Path $TargetOu -Surname $AdUserOwner.Surname -DisplayName $DisplayName `
            -Enabled $True -KerberosencryptionType AES128,AES256 -AccountNotDelegated $true -UserPrincipalName "$an@$DomainDNSName" -PassThru

        $ExistingUsers[$an] = $NewAdUser

        Write-Verbose "Created admin account [$an] for [$un]"
    } Catch {
        Write-Warning "Error creating admin [$an] account for $un"
        Write-Warning $_.Exception.Message
        continue
    }
}

Write-Host "Setting email on all employee accounts"
get-aduser -filter * -Searchbase $EmployeesOu | ForEach-Object { 
    $Name = $_.UserPrincipalName.subString(0, $_.UserPrincipalName.IndexOf("@"))
	Set-aduser $_ -EmailAddress "$Name@zampleworks.com"
}

#
# Add users to roles in UserRoles.csv
# These are non-business roles
#

Write-Host "Adding users to role groups"

$GeneratedGroupNames = $Groups | Select-Object -ExpandProperty Name
Foreach($Entry in $GroupMembers) {
    $u = $Null
    $un = "$ObjectsPrefix$($Entry.Member)"
    $g = $Null
    $gns = $Entry.MemberOf

    If([string]::IsNullOrWhiteSpace($un) -Or [string]::IsNullOrWhiteSpace($gns)) {
        Write-Warning "Incorrect data in GroupMembers.csv: "
        Write-Warning $Role | Format-Table
        Continue
    }
    
    $gns = $gns.Split(",")

    If(-not ($ExistingUsers.ContainsKey($un) -Or $ExistingGroups.ContainsKey($un))) {
        Write-Warning "User [$un] not found"
        continue
    }
    
    If($ExistingUsers.ContainsKey($un)) {
        $u = $ExistingUsers[$un]
    } Else {
        $u = $ExistingGroups[$un]
    }

    Foreach($gn in $gns) {
        If($GeneratedGroupNames -contains $gn) {
            $gn = "$ObjectsPrefix$($gn)"
        }
        If(-Not ($ExistingGroups.ContainsKey($gn))) {
            Write-Error "Error adding member [$un] to group [$gn] - group does not exist"
        }

        Try {
            $g = Get-ADGroup $gn -Properties members
            If($u -notin $g.Members) {
                Write-Verbose "Adding [$un] to group [$gn]"
                Add-ADGroupMember -Identity $g -Members $u    
            }
        } Catch {
            Write-Warning "Error adding member [$un] to group [$gn]: $($_.Exception.Message)"
        }
    }
}