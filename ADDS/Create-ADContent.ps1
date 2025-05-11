$ErrorActionPreference = "Stop"
$VerbosePreference = "Continue"

$TestPrefix = ""

Import-Module ActiveDirectory -Verbose:$False

$Pw = ConvertTo-SecureString "P@ssw0rd" -AsPlainText -Force
$DomainNBName = Get-ADDomain | Select -ExpandProperty NetbiosName
$DomainDNSName = Get-ADDomain | Select -ExpandProperty DNSRoot
$DomainDN = Get-ADDomain | Select -ExpandProperty DistinguishedName 

$Ous = Import-Csv .\Objects\OU.csv -Delimiter ";"

# Replacements for parent OU names and paths
$Replacements = @{ 
    "%RootDN%" = $DomainDN
}

# Generic search-and-replace strings
$StringReplacements = @{ 
    "%DomainNBName%" = $DomainNBName
}

# Overwrite oustructure.csv
"Name;DN" | Out-File .\Objects\OUStructure.csv -Encoding utf8 -Force

<#
 # Convert characters with diacritic marks to ascii equivalent
 # For example, Ö will be O and é will be e
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
Foreach($Ou in $Ous) {
    $Parent = $Replacements.GetEnumerator() | ? { $_.Key -eq $Ou.Parent } | Select -ExpandProperty Value

    If([string]::IsNullOrWhiteSpace($Parent)) {
        Write-Verbose "No replacement found in Parent for $($Ou.Name)"
        Continue
    }

    $Path = "$Parent"
    $Name = $Ou.Name
    $CN = $Ou.CN
    $DN = "OU=$($CN),$Path"
    
    $OuExists = $False
    Try {
        $a = Get-ADOrganizationalUnit $DN 
        $OuExists = $True
        $Replacements.Add("%$Name%", $DN)
        $Ou.Created = $True
        "%$Name%;$DN" | Out-File .\Objects\OUStructure.csv -Append -Encoding utf8 -Force -NoClobber
    } Catch {   }

    If(-Not $OuExists) {
        Try {
            New-ADOrganizationalUnit -Path $Parent -DisplayName $Ou.DisplayName -Name $CN -Confirm:$False
            Write-Verbose "Created OU for $Name : $DN"
            $Replacements.Add("%$Name%", $DN)
            $Ou.Created = $True
            "%$Name%;$DN" | Out-File .\Objects\OUStructure.csv -Append -Encoding utf8 -Force -NoClobber
        } Catch {
            Write-Warning "Oops: $($_.Exception.Message)"
        }
    }
}

# Read Service Accounts OU from OUStructure file
$Ou = Import-csv .\Objects\OUStructure.csv -Delimiter ";" | ? { $_.Name -eq "%SvcAcctsOU%" } | select -ExpandProperty DN

# Create built-in Service accounts
Import-csv .\Objects\Accounts.csv -Delimiter ";" | % { 
    $n = $_.Name
    $s = "$TestPrefix$($_.Samaccountname)"
    
    Try {
        $u = Get-ADUser $s
        Write-Verbose "Account [$s] already exists"
    } Catch {
        Try {
            $u = New-ADUser -name $n -displayname $n -Samaccountname $s -userprincipalname "$s@$DomainDNSName" -path $ou -Enabled $false -Confirm:$False -AccountPassword $Pw -PassThru
            Set-ADAccountPassword $u -NewPassword $Pw -Reset
            Enable-ADAccount $u
            Write-Verbose "Created account $s"
        } Catch {
            Write-Error "Error account ${s}: $($_.Exception.Message)"
        }
    }
}

# Read employee OU
$EmployeesOu = Import-csv .\Objects\OUStructure.csv -Delimiter ";" | ? { $_.Name -eq "%EmployeeAcctsOU%" } | select -ExpandProperty DN

# Read employees and user ID series 
$Employees = Import-csv .\Objects\UserDB\Employee.csv -Delimiter "`t" `
-Header BusinessEntityID,NationalIdentifier,UserNBAccount,OrganizationNode,OrganizationLevel,Position,BirthDate,MaritalStatus,Sex,EmployeeDate,Salaried,VacationHours,SickleaveHours,CurrentFlag,RowGuid `
 | ? { $_.CurrentFlag -eq 1 }
$MaxId = $Employees | Select -ExpandProperty BusinessEntityID | Select -Last 1

# Build list of Persons to create accounts for
$Persons = Import-Csv .\Objects\UserDB\Person.csv -delimiter "|" -Header BusinessEntityID,U1,U2,U3,FirstName,Initial,LastName,U4,U5,U6,U7,U8,U9,U10 | Select -first $MaxId | % {
    $_.BusinessEntityID = $_.BusinessEntityID.Replace("+", "")
    
    If([Int]::Parse($_.BusinessEntityID) -le $MaxId) {
        $_.FirstName = $_.FirstName.Replace("+", "")
        $_.LastName = $_.LastName.Replace("+", "")
        $_.Initial = $_.Initial.Replace("+", "")
        Write-Output $_
    }
}

# Read departments
$Departments = Import-Csv .\Objects\UserDB\Department.csv -Delimiter "`t" -Header DepartmentID,Name,GroupName,ModifiedWhen

# Read active employments
$ActiveEmployments = Import-Csv .\Objects\UserDB\EmployeeDepartmentHistory.csv -Delimiter "`t" -Header BusinessEntityID,DepartmentID,ShiftID,StartDate,EndDate,ModifiedDate | % { 
    If([string]::IsNullOrWhiteSpace($_.EndDate)) { Write-Output $_ }
}

# Read Roles groups OU
$RolesOU = Import-csv .\Objects\OUStructure.csv -Delimiter ";" | ? { $_.Name -eq "%RolesOU%" } | select -ExpandProperty DN
Foreach($Dept in $Departments) {
    $DeptRoles = Get-Content .\Objects\DeptRoles.csv
    Foreach($DeptRole in $DeptRoles) {
        $GroupName = "$($TestPrefix)Role $($Dept.Name) $DeptRole"
        
        Try {
            $Group = Get-ADGroup $GroupName
            Write-Verbose "Business role group [$GroupName] already exists"
        } Catch {
            Try {
               New-ADGroup -Name $GroupName -DisplayName $GroupName -GroupCategory Security -GroupScope Global -Path $RolesOU
               Write-Verbose "Created business role group $GroupName"
            } Catch {
                Write-Error "Error creating business role group ${GroupName}: $($_.Exception.Message)"
            }
        }
    }
}

$AdminRolesOU = Import-csv .\Objects\OUStructure.csv -Delimiter ";" | ? { $_.Name -eq "%AdminRolesOU%" } | select -ExpandProperty DN
$AdminsOU = Import-csv .\Objects\OUStructure.csv -Delimiter ";" | ? { $_.Name -eq "%AdminAcctsOU%" } | select -ExpandProperty DN
$UsersOU = Import-csv .\Objects\OUStructure.csv -Delimiter ";" | ? { $_.Name -eq "%UsersOU%" } | select -ExpandProperty DN
$PermissionsOU = Import-csv .\Objects\OUStructure.csv -Delimiter ";" | ? { $_.Name -eq "%PermissionsOU%" } | select -ExpandProperty DN
$DsControlOU = Import-csv .\Objects\OUStructure.csv -Delimiter ";" | ? { $_.Name -eq "%DSControlOU%" } | select -ExpandProperty DN
$DsControlRolesOU = Import-csv .\Objects\OUStructure.csv -Delimiter ";" | ? { $_.Name -eq "%DSControlRolesOU%" } | select -ExpandProperty DN
$DsControlPermissionsOU = Import-csv .\Objects\OUStructure.csv -Delimiter ";" | ? { $_.Name -eq "%DSControlPermsOU%" } | select -ExpandProperty DN
$SvcAcctOU = Import-csv .\Objects\OUStructure.csv -Delimiter ";" | ? { $_.Name -eq "%DSControlPermsOU%" } | select -ExpandProperty DN
$CliGroupOu = Import-csv .\Objects\OUStructure.csv -Delimiter ";" | ? { $_.Name -eq "%ClientGroupsOU%" } | select -ExpandProperty DN
$SrvGroupOu = Import-csv .\Objects\OUStructure.csv -Delimiter ";" | ? { $_.Name -eq "%ServerGroupsOU%" } | select -ExpandProperty DN

$UserRoles = Import-csv .\Objects\UserRoles.csv -Delimiter ";"
$Admins = Import-csv .\Objects\Admins.csv -Delimiter ";"
$Groups = Import-Csv .\Objects\Groups.csv -Delimiter ";"
$Delegations = Import-csv .\Objects\Delegations.csv -Delimiter ";"

#
# Create groups from groups.csv
# 

Foreach($Group in $Groups) {

    $Scope = [Microsoft.ActiveDirectory.Management.ADGroupScope]::Universal

    If($Group.Type -eq "DSPermission" -Or $Group.Type -eq "Permission") {
        $Scope = [Microsoft.ActiveDirectory.Management.ADGroupScope]::DomainLocal
    }

    If(-Not [string]::IsNullOrWhiteSpace($Group.Scope)) {
        $Scope = [Microsoft.ActiveDirectory.Management.ADGroupScope] $Group.Scope
    }

    If($Group.Type -eq "Role") {
        $CreateIn = $RolesOU
    } ElseIf($Group.Type -eq "AdminRole") {
        $CreateIn = $AdminRolesOU
    } Elseif($Group.Type -eq "Permission") {
        $CreateIn = $PermissionsOU
    } Elseif($Group.Type -eq "DSPermission") {
        $CreateIn = $DsControlPermissionsOU
    } Elseif($Group.Type -eq "DSRole") {
        $CreateIn = $DsControlRolesOU
    } Elseif($Group.Type -eq "ClientGroup") {
        $CreateIn = $CliGroupOu
    } Elseif($Group.Type -eq "ServerGroup") {
        $CreateIn = $SrvGroupOu
    } Else {
        Write-Warning "Unknown group type: $($Group.Type)"
    }

    $GroupName = "$TestPrefix$($Group.Name)"
    
    Try {
        $Group = Get-ADGroup $GroupName
        Write-Verbose "Role group [$GroupName] already exists"
    } Catch {
        Try {
            New-ADGroup -Name $GroupName -DisplayName $GroupName -GroupCategory Security -GroupScope $Scope -Path $CreateIn
            Write-Verbose "Created role group $GroupName"
        } Catch {
            Write-Error "Error creating AD group ${GroupName}: $($_.Exception.Message)"
        }
    }    
}

#
# Create employee accounts, and add them to department role groups
#

Foreach($Emp in $Employees) { 
    $Person = $Persons | ? { $_.BusinessEntityID -eq $Emp.BusinessEntityID }
    $Employment = $Null
    $Dept = $Null
    $JobTitle = $Null

    If($Person -ne $Null) {
        $Bid = $Emp.BusinessEntityID
        $Employment = $ActiveEmployments | ? { $_.BusinessEntityID -eq $Bid }
        
        If($Employment -ne $Null) {
            $Dept = $Departments | ? { $_.DepartmentID -eq $Employment.DepartmentID }
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

        $Sam = "$TestPrefix$($Emp.UserNBAccount.Substring($Emp.UserNBAccount.IndexOf("\") + 1))"
        $Upn = Convert-DiacriticCharacters "$Fn.$Sn@$DomainDNSName"
        $Upn = $Upn.Replace(" ", "").Replace("'", "");

        $ExistingUser = $Null
        Try {
            $ExistingUser = Get-ADUser -Filter {userPrincipalName -eq $Upn}
            $ExistingUser = Get-ADUser $Sam
            Write-Verbose "User already exists: [$Sam]  [$JobTitle]"
        } Catch {}

        If($Null -eq $ExistingUser) {
            Try {
                $u = New-ADUser -name $DispN -displayname $DispN -GivenName $Fn -Surname $Sn -Samaccountname $Sam -userprincipalname $Upn -EmployeeNumber $Bid -Department $DeptName `
                     -Title $JobTitle -path $EmployeesOu -Enabled $false -Confirm:$False -AccountPassword $Pw -PassThru
                Set-ADAccountPassword $u -NewPassword $Pw -Reset
                Enable-ADAccount $u

                Write-Verbose "Created: [$DispN] [$DeptName] [$JobTitle] [$DomainNBName\$sam]"
            } Catch {
                Write-Host "Error creating user [$Upn] [$DispN]: " -ForegroundColor Red
                Write-Host $_.Exception.Message
            }
        } else {
            $u = Get-ADUser $Sam
        }

        $EmplGroup = Get-ADGroup "$($TestPrefix)Role Employee" -Properties members
        If(-Not $EmplGroup.Members -contains $u) {
            Add-ADGroupMember $EmplGroup -Members $u
        }

        $DgName = "$($TestPrefix)Role $DeptName Employee"
        Try {
            $DeptGroup = Get-ADGroup $DgName -Properties members
            If(-Not $DeptGroup.Members -contains $u) {
                Add-ADGroupMember $DeptGroup -Members $u
                Write-Verbose "  --> Added [$DomainNBName\$sam] to department group $DgName"
            }
        } Catch {
            Write-Warning "  --> Failed to add [$DomainNBName\$sam] to department group $($DgName): $($_.Exception.Message)"
        }
    }
}

#
# Create admin accounts for the users listed in admins.csv
#

Foreach($Admin in $Admins) {
    $un = "$TestPrefix$($Admin.Username)"
        
    Try {
        $u = Get-ADUser $un
    } Catch {
        Write-Warning "Could not find user account [$un] to create admin account for"
        Write-Warning $_.Exception.Message
        continue
    }

    $an = "$($TestPrefix)adm_$($Admin.Username)"
    
    Try {
        $adm = Get-ADUser $an
        Write-Verbose "Admin account [$an] for [$un] already exists."
        continue
    } Catch {}
       
    Try {
        $name = $u.Name
        $Adm = New-ADUser -Name "Admin $name" -SamAccountName $an -AccountPassword $pw -GivenName $u.GivenName -Path $AdminsOU `
            -Surname $u.Surname -DisplayName "Admin $name" -Enabled $True -UserPrincipalName "$an@$DomainDNSName"
        Write-Verbose "Created admin account [$an] for [$un]"
    } Catch {
        Write-Warning "Error creating admin [$un] account for $un"
        Write-Warning $_.Exception.Message
        continue
    }
}

get-aduser -filter * -Searchbase $UsersOU | % { 
    $Name = $_.UserPrincipalName.subString(0, $_.UserPrincipalName.IndexOf("@"))
	Set-aduser $_ -EmailAddress "$Name@zampleworks.com"
}


#
# Add users to roles in UserRoles.csv
# These are non-business roles
#

Foreach($Role in $UserRoles) {
    $u = $Null
    $un = "$TestPrefix$($Role.Username)"
    $g = $Null
    $gns = $Role.Roles
    $gp = $Null

    If([string]::IsNullOrWhiteSpace($un) -Or [string]::IsNullOrWhiteSpace($gns)) {
        Write-Warning "Incorrect data in UserRoles.csv: "
        Write-Warning $Role | ft
        Continue
    }
    
    $gns = $gns.Split(",")

    Try {
        $u = Get-ADUser $un
    } Catch {
        Write-Warning "User $un not found"
        continue
    }

    Foreach($gn in $gns) {
    $gn = "$TestPrefix$($gn)"
        Try {
            $g = Get-ADGroup $gn -Properties members
            If($u -notin $g.Members) {
                Write-Verbose "Adding [$un] to group [$gn]"
                Add-ADGroupMember -Identity $g -Members $u    
            }
        } Catch {
            Write-Warning "Error adding user $un to group $gn"
            Write-Warning $_.Exception.Message
            continue
        }
    }
}
