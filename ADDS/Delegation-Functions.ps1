
$ErrorActionPreference = "stop"

Set-Location $PSScriptRoot

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

$RootDSE = Get-ADRootDSE
$Forest = Get-ADForest
$Domain = Get-ADDomain

$GuidNames = @{}

$Guidmap = @{}
Get-ADObject -SearchBase $($RootDSe.schemaNamingContext) -LDAPFilter '(schemaidguid=*)' -Properties ldapdisplayname,schemaidguid | % { 
    $g = [guid] $_.SchemaIdGuid
    $n = $_.LdapDisplayName

    $Guidmap[$n] = $g
    $GuidNames[$g] = $n
}

$ExtendedRights = @{}
Get-ADObject -SearchBase "CN=Extended-Rights,$($RootDSE.configurationNamingContext)" -LDAPFilter "(objectClass=controlAccessRight)" -Properties cn,appliesTo,rightsGuid | % {
    $r = New-Object PSObject
    $r | Add-Member -MemberType NoteProperty -Name "Name" -Value $_.cn
    $r | Add-Member -MemberType NoteProperty -Name "AppliesTo" -Value $_.appliesTo
    $r | Add-Member -MemberType NoteProperty -Name "RightsGuid" -Value $_.rightsGuid

    $ExtendedRights[$_.cn] = $r

    $GuidNames[$_.rightsGuid] = $_.cn
}

$PropertySets = @(
    $ExtendedRights['DNS-Host-Name-Attributes'].RightsGuid,
    $ExtendedRights['Domain-Other-Parameters'].RightsGuid,
    $ExtendedRights['Domain-Password'].RightsGuid,
    $ExtendedRights['Email-Information'].RightsGuid,
    $ExtendedRights['General-Information'].RightsGuid,
    $ExtendedRights['Membership'].RightsGuid,
    $ExtendedRights['MS-TS-GatewayAccess'].RightsGuid,
    $ExtendedRights['Personal-Information'].RightsGuid,
    $ExtendedRights['Private-Information'].RightsGuid,
    $ExtendedRights['Public-Information'].RightsGuid,
    $ExtendedRights['RAS-Information'].RightsGuid,
    $ExtendedRights['Terminal-Server-License-Server'].RightsGuid,
    $ExtendedRights['User-Account-Restrictions'].RightsGuid,
    $ExtendedRights['User-Logon'].RightsGuid,
    $ExtendedRights['Web-Information'].RightsGuid
)


Function Get-ObjectClassGuid {
    Param(
        [string]
        $ClassName
    )
    If($Guidmap -ne $Null) {
        Write-Output $Guidmap[$ClassName]
    }
}

Function Set-Delegation {
    Param(
        [string]
        $ObjectDN,

        [string]
        $SubjectDN,

        [System.Security.AccessControl.AccessControlType]
        $RuleType,
        
        [System.DirectoryServices.ActiveDirectoryRights]
        $Rights,
        
        [Guid]
        $ExtendedRight = [Guid]::Empty,

        [System.DirectoryServices.PropertyAccess]
        $PropertyAccess = [System.DirectoryServices.PropertyAccess]::Read,

        [Guid]
        $ObjectType = [Guid]::Empty,

        [System.DirectoryServices.ActiveDirectorySecurityInheritance]
        $InheritanceType = [System.DirectoryServices.ActiveDirectorySecurityInheritance]::None,

        [Guid]
        $InheritObjectType = [Guid]::Empty
    )
    
    $IsExtended = $False
    $IsPropertySet = $False

    If($Rights -eq [System.DirectoryServices.ActiveDirectoryRights]::ExtendedRight) {
        $n = $GuidNames[$ExtendedRight.Guid]
        If($PropertySets -contains $ExtendedRight.Guid) {
            $IsPropertySet = $True
            Write-Verbose "Assigning [$n] - $RuleType [$PropertyAccess] on [$ObjectDN] to [$SubjectDN]"
        } Else {
            $IsExtended = $True
            Write-Verbose "Assigning [$n] - $RuleType on [$ObjectDN] to [$SubjectDN]"
        }
    } Else {
        
        $rn = $GuidNames[$ObjectType]
        If($InheritObjectType -ne [Guid]::Empty) {
            $on = "$($GuidNames[$InheritObjectType])."
        } Else {
            $on = ""
        }

        If(-Not ([string]::IsNullOrWhiteSpace($rn) -and [string]::IsNullOrWhiteSpace($on))) {
            $ot = "[$on$rn] - "
        } Else {
            $ot = ""
        }

        Write-Verbose "Assigning $ot[$Rights] - $RuleType on [$ObjectDN] to [$SubjectDN]"
    }
    
    
    $AdObject = $Null;
    $AdSubject = $Null;
    Try {
        $AdObject = Get-ADObject $ObjectDN
        $AdSubject = Get-ADObject $SubjectDN -Properties ObjectSid
    } Catch {
        LogE $_
    }

    $SubSid = $AdSubject.ObjectSid

    $AclPath = "AD:\$($AdObject.distinguishedName)"
    $Acl = Get-Acl $AclPath
    $Ace = $Null

    If($IsExtended) {
        If($ExtendedRight -eq [Guid]::Empty) { Throw "Extended right is empty guid" }

        If($InheritanceType -ne [System.DirectoryServices.ActiveDirectorySecurityInheritance]::None) {
            If($InheritObjectType -ne [Guid]::Empty) {
                $Ace = New-Object System.DirectoryServices.ExtendedRightAccessRule(
                    $SubSid, 
                    $RuleType,
                    $ExtendedRight,
                    $InheritanceType,
                    $InheritObjectType
                )
            } Else {
                $Ace = New-Object System.DirectoryServices.ExtendedRightAccessRule(
                    $SubSid, 
                    $RuleType,
                    $ExtendedRight,
                    $InheritanceType
                )
            }
        } Else {
            $Ace = New-Object System.DirectoryServices.ExtendedRightAccessRule(
                $SubSid, 
                $RuleType,
                $ExtendedRight
            )
        }
    } Elseif($IsPropertySet) {
        If($InheritanceType -ne [System.DirectoryServices.ActiveDirectorySecurityInheritance]::None) {
            If($InheritObjectType -ne [Guid]::Empty) {
                $Ace = New-Object System.DirectoryServices.PropertySetAccessRule(
                    $SubSid, 
                    $RuleType,
                    $PropertyAccess,
                    $ExtendedRight,
                    $InheritanceType,
                    $InheritObjectType
                )
            } Else {
                $Ace = New-Object System.DirectoryServices.PropertySetAccessRule(
                    $SubSid, 
                    $RuleType,
                    $PropertyAccess,
                    $ExtendedRight,
                    $InheritanceType
                )
            }
        } Else {
            $Ace = New-Object System.DirectoryServices.PropertySetAccessRule(
                $SubSid, 
                $RuleType,
                $PropertyAccess,
                $ExtendedRight
            )
        }
    } Else {
        If($InheritanceType -ne [System.DirectoryServices.ActiveDirectorySecurityInheritance]::None) { # Inheritance rule
            If($InheritObjectType -ne [Guid]::Empty) { # Inheritance & inherit object type
                If($ObjectType -ne [Guid]::Empty) { # Inheritance & inherit object type & Object type
                    $Ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
                        $SubSid, 
                        $Rights,
                        $RuleType,
                        $ObjectType,
                        $InheritanceType,
                        $InheritObjectType
                    )
                } Else {
                    $Ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
                        $SubSid, 
                        $Rights,
                        $RuleType,
                        $InheritanceType,
                        $InheritObjectType
                    )
                }
            } Else { # Inherit, but no Inherit Object Type
                If($ObjectType -ne [Guid]::Empty) {
                    $Ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
                        $SubSid, 
                        $Rights,
                        $RuleType,
                        $ObjectType,
                        $InheritanceType
                    )
                } Else {
                    $Ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
                        $SubSid, 
                        $Rights,
                        $RuleType,
                        $InheritanceType
                    )
                }
            }
        } Else {
            If($ObjectType -ne [Guid]::Empty) { # Inheritance & inherit object type & Object type
                $Ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
                    $SubSid, 
                    $Rights,
                    $RuleType,
                    $ObjectType
                )
            } Else {
                $Ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
                    $SubSid, 
                    $Rights,
                    $RuleType
                )
            }
        }
    }
    
    $Acl.AddAccessRule($Ace)
    $Acl | Set-Acl $AclPath
}

Function Set-AllowCreate {
    Param(
        [string]
        $ObjectDN,

        [string]
        $SubjectDN,

        [string]
        $ObjectLdapClassName,

        [System.DirectoryServices.ActiveDirectorySecurityInheritance]
        $Inheritance = [System.DirectoryServices.ActiveDirectorySecurityInheritance]::None,

        [Guid]
        $InheritObjectType = [Guid]::Empty
    )
    
    
    If(-Not $Guidmap.ContainsKey($ObjectLdapClassName)) {
        Throw "Invalid class name: [$ObjectLdapClassName]"
    }

    $ObjectType = $Guidmap[$ObjectLdapClassName]
    Set-Delegation -ObjectDN $ObjectDN -SubjectDN $SubjectDN -RuleType Allow -Rights Create -InheritanceType $Inheritance -ObjectType $ObjectType
}

Function Set-AllowDelete {
    Param(
        [string]
        $ObjectDN,

        [string]
        $SubjectDN,

        [string]
        $ObjectLdapClassName,

        [System.DirectoryServices.ActiveDirectorySecurityInheritance]
        $Inheritance = [System.DirectoryServices.ActiveDirectorySecurityInheritance]::None,

        [Guid]
        $InheritObjectType = [Guid]::Empty
    )
    
    If(-Not $Guidmap.ContainsKey($ObjectLdapClassName)) {
        Throw "Invalid class name: [$ObjectLdapClassName]"
    }

    $ObjectType = $Guidmap[$ObjectLdapClassName]
    Set-Delegation -ObjectDN $ObjectDN -SubjectDN $SubjectDN -RuleType Allow -Rights DeleteChild -InheritanceType $Inheritance -ObjectType $ObjectType
}

Function Set-OuAllowResetPw {
    Param(
        [string]
        $ObjectDN,

        [string]
        $SubjectDN,

        [System.DirectoryServices.ActiveDirectorySecurityInheritance]
        $Inheritance = [System.DirectoryServices.ActiveDirectorySecurityInheritance]::Descendents,

        [Guid]
        $InheritObjectType = [Guid]::Empty
    )
    
    $ExRightForceChange = [Guid] $ExtendedRights['User-Force-Change-Password'].RightsGuid
    $ExRightUnexpire = [Guid] $ExtendedRights['Unexpire-Password'].RightsGuid
    $ExRightDomainPasswd = [Guid] $ExtendedRights['Domain-Password'].RightsGuid
    $RightPwdLastSet = [Guid] $Guidmap['pwdLastSet']
    $RightLockoutTime = [Guid] $Guidmap['lockoutTime']
    
    $UserGuid = $Guidmap['User']
    
    Set-Delegation -ObjectDN $ObjectDN -SubjectDN $SubjectDN -RuleType Allow -Rights ExtendedRight -ExtendedRight $ExRightForceChange -InheritanceType $Inheritance -InheritObjectType $UserGuid
    Set-Delegation -ObjectDN $ObjectDN -SubjectDN $SubjectDN -RuleType Allow -Rights ExtendedRight -ExtendedRight $ExRightUnexpire -InheritanceType $Inheritance -InheritObjectType $UserGuid
    Set-Delegation -ObjectDN $ObjectDN -SubjectDN $SubjectDN -RuleType Allow -Rights WriteProperty,ReadProperty -ObjectType $RightPwdLastSet -InheritanceType $Inheritance -InheritObjectType $UserGuid
    Set-Delegation -ObjectDN $ObjectDN -SubjectDN $SubjectDN -RuleType Allow -Rights WriteProperty,ReadProperty -ObjectType $RightLockoutTime -InheritanceType $Inheritance -InheritObjectType $UserGuid
    
    Set-Delegation -ObjectDN $ObjectDN -SubjectDN $SubjectDN -RuleType Allow -Rights ExtendedRight -ExtendedRight $ExRightDomainPasswd -PropertyAccess Read,Write -InheritanceType $Inheritance -InheritObjectType $UserGuid
}

Function Set-ManageGroupsDelegation {
    Param(
        [string]
        $ObjectDN,

        [string]
        $SubjectDN,

        [switch]
        $Inherit
    )

    $Inh = [System.DirectoryServices.ActiveDirectorySecurityInheritance]::None
    If($Inherit) {
        $Inh = [System.DirectoryServices.ActiveDirectorySecurityInheritance]::All
    }
    
    # Group ldap class guid
    $GroupClassGuid = $Guidmap['Group']

    # Properties
    $Members = [Guid] $Guidmap['member']
    
    $Rdn = [Guid] $Guidmap['name']
    $cn = [Guid] $Guidmap['cn']
    $samProp = [Guid] $Guidmap['samaccountname']
    
    $DisplayName = [Guid] $Guidmap['displayName']
    $Description = [Guid] $Guidmap['description']
    $Mail = [Guid] $Guidmap['mail']
    $Notes = [Guid] $Guidmap['info']
    
    $Scope = [Guid] $Guidmap['grouptype']
    $Type = [Guid] $Guidmap['samaccounttype']

    # Allow Create & delete object type in OU and sub-OUs
    Set-AllowCreate -ObjectDN $ObjectDN -SubjectDN $SubjectDN -ObjectLdapClassName "Group" -Inheritance $Inh
    Set-AllowDelete -ObjectDN $ObjectDN -SubjectDN $SubjectDN -ObjectLdapClassName "Group" -Inheritance $Inh

    # Allow edit name properties on User objects in OU and sub-OUs
    Set-Delegation -ObjectDN $ObjectDN -SubjectDN $SubjectDN -RuleType Allow -Rights WriteProperty,ReadProperty -ObjectType $Members -InheritanceType $Inh -InheritObjectType $GroupClassGuid
    
    Set-Delegation -ObjectDN $ObjectDN -SubjectDN $SubjectDN -RuleType Allow -Rights WriteProperty,ReadProperty -ObjectType $Rdn -InheritanceType $Inh -InheritObjectType $GroupClassGuid
    Set-Delegation -ObjectDN $ObjectDN -SubjectDN $SubjectDN -RuleType Allow -Rights WriteProperty,ReadProperty -ObjectType $cn -InheritanceType $Inh -InheritObjectType $GroupClassGuid
    Set-Delegation -ObjectDN $ObjectDN -SubjectDN $SubjectDN -RuleType Allow -Rights WriteProperty,ReadProperty -ObjectType $samProp -InheritanceType $Inh -InheritObjectType $GroupClassGuid

    Set-Delegation -ObjectDN $ObjectDN -SubjectDN $SubjectDN -RuleType Allow -Rights WriteProperty,ReadProperty -ObjectType $DisplayName -InheritanceType $Inh -InheritObjectType $GroupClassGuid
    Set-Delegation -ObjectDN $ObjectDN -SubjectDN $SubjectDN -RuleType Allow -Rights WriteProperty,ReadProperty -ObjectType $Description -InheritanceType $Inh -InheritObjectType $GroupClassGuid
    Set-Delegation -ObjectDN $ObjectDN -SubjectDN $SubjectDN -RuleType Allow -Rights WriteProperty,ReadProperty -ObjectType $Mail -InheritanceType $Inh -InheritObjectType $GroupClassGuid
    Set-Delegation -ObjectDN $ObjectDN -SubjectDN $SubjectDN -RuleType Allow -Rights WriteProperty,ReadProperty -ObjectType $Notes -InheritanceType $Inh -InheritObjectType $GroupClassGuid
    
    Set-Delegation -ObjectDN $ObjectDN -SubjectDN $SubjectDN -RuleType Allow -Rights WriteProperty,ReadProperty -ObjectType $Scope -InheritanceType $Inh -InheritObjectType $GroupClassGuid
    Set-Delegation -ObjectDN $ObjectDN -SubjectDN $SubjectDN -RuleType Allow -Rights WriteProperty,ReadProperty -ObjectType $Type -InheritanceType $Inh -InheritObjectType $GroupClassGuid
}

Function Set-ManageComputersDelegation {
    Param(
        [string]
        $ObjectDN,

        [string]
        $SubjectDN,

        [switch]
        $Inherit
    )

    $Inh = [System.DirectoryServices.ActiveDirectorySecurityInheritance]::None
    If($Inherit) {
        $Inh = [System.DirectoryServices.ActiveDirectorySecurityInheritance]::All
    }
    
    # Computer ldap class guid
    $ComputerClassGuid = $Guidmap['Computer']

    # Property sets
    $ExRightPersonal = [Guid] $ExtendedRights['Personal-Information'].RightsGuid
    $ExRightPublic = [Guid] $ExtendedRights['Public-Information'].RightsGuid
    $ExRightLogon = [Guid] $ExtendedRights['User-Logon'].RightsGuid
    $ExRightMembership = [Guid] $ExtendedRights['Membership'].RightsGuid

    # Name properties
    $displayNameProp = [Guid]$Guidmap['displayName']
    $samProp = [Guid]$Guidmap['samaccountname']

    # userAccountControl attribute guid
    $RightUac = [Guid] $Guidmap['userAccountControl']
    
    Set-OuAllowResetPw -ObjectDN $ObjectDN -SubjectDN $SubjectDN -Inheritance $Inh

    # Allow Create & delete object type in OU and sub-OUs
    Set-AllowCreate -ObjectDN $ObjectDN -SubjectDN $SubjectDN -ObjectLdapClassName "Computer" -Inheritance $Inh
    Set-AllowDelete -ObjectDN $ObjectDN -SubjectDN $SubjectDN -ObjectLdapClassName "Computer" -Inheritance $Inh

    # Allow edit name properties on User objects in OU and sub-OUs
    Set-Delegation -ObjectDN $ObjectDN -SubjectDN $SubjectDN -RuleType Allow -Rights WriteProperty,ReadProperty -ObjectType $RightUac -InheritanceType $Inh -InheritObjectType $ComputerClassGuid
    Set-Delegation -ObjectDN $ObjectDN -SubjectDN $SubjectDN -RuleType Allow -Rights WriteProperty,ReadProperty -ObjectType $displayNameProp -InheritanceType $Inh -InheritObjectType $ComputerClassGuid
    Set-Delegation -ObjectDN $ObjectDN -SubjectDN $SubjectDN -RuleType Allow -Rights WriteProperty,ReadProperty -ObjectType $samProp -InheritanceType $Inh -InheritObjectType $ComputerClassGuid
    
    # Enable Read/write on Property sets on user objects in OU. Read/write must be assigned separately.
    Set-Delegation -ObjectDN $ObjectDN -SubjectDN $SubjectDN -RuleType Allow -Rights ExtendedRight -ExtendedRight $ExRightLogon -PropertyAccess Read -InheritanceType $Inh -InheritObjectType $ComputerClassGuid
    Set-Delegation -ObjectDN $ObjectDN -SubjectDN $SubjectDN -RuleType Allow -Rights ExtendedRight -ExtendedRight $ExRightLogon -PropertyAccess Write -InheritanceType $Inh -InheritObjectType $ComputerClassGuid
    Set-Delegation -ObjectDN $ObjectDN -SubjectDN $SubjectDN -RuleType Allow -Rights ExtendedRight -ExtendedRight $ExRightPublic -PropertyAccess Read -InheritanceType $Inh -InheritObjectType $ComputerClassGuid
    Set-Delegation -ObjectDN $ObjectDN -SubjectDN $SubjectDN -RuleType Allow -Rights ExtendedRight -ExtendedRight $ExRightPublic -PropertyAccess Write -InheritanceType $Inh -InheritObjectType $ComputerClassGuid
    Set-Delegation -ObjectDN $ObjectDN -SubjectDN $SubjectDN -RuleType Allow -Rights ExtendedRight -ExtendedRight $ExRightPersonal -PropertyAccess Read -InheritanceType $Inh -InheritObjectType $ComputerClassGuid
    Set-Delegation -ObjectDN $ObjectDN -SubjectDN $SubjectDN -RuleType Allow -Rights ExtendedRight -ExtendedRight $ExRightPersonal -PropertyAccess Write -InheritanceType $Inh -InheritObjectType $ComputerClassGuid

    Set-Delegation -ObjectDN $ObjectDN -SubjectDN $SubjectDN -RuleType Allow -Rights ExtendedRight -ExtendedRight $ExRightMembership -PropertyAccess Read -InheritanceType $Inh -InheritObjectType $ComputerClassGuid
    Set-Delegation -ObjectDN $ObjectDN -SubjectDN $SubjectDN -RuleType Allow -Rights ExtendedRight -ExtendedRight $ExRightMembership -PropertyAccess Write -InheritanceType $Inh -InheritObjectType $ComputerClassGuid
}

Function Set-ManageUsersDelegation {
    Param(
        [string]
        $ObjectDN,

        [string]
        $SubjectDN,

        [switch]
        $Inherit
    )

    $Inh = [System.DirectoryServices.ActiveDirectorySecurityInheritance]::None
    If($Inherit) {
        $Inh = [System.DirectoryServices.ActiveDirectorySecurityInheritance]::All
    }
    
    # User ldap class guid
    $UserClassGuid = $Guidmap['User']

    # userAccountControl attribute guid
    $RightUac = [Guid] $Guidmap['userAccountControl']
    
    # Property sets
    $ExRightPersonal = [Guid] $ExtendedRights['Personal-Information'].RightsGuid
    $ExRightPublic = [Guid] $ExtendedRights['Public-Information'].RightsGuid
    $ExRightLogon = [Guid] $ExtendedRights['User-Logon'].RightsGuid
    $ExRightMembership = [Guid] $ExtendedRights['Membership'].RightsGuid

    # Name properties
    $displayNameProp = [Guid]$Guidmap['displayName']
    $samProp = [Guid]$Guidmap['samaccountname']

    Set-OuAllowResetPw -ObjectDN $ObjectDN -SubjectDN $SubjectDN -Inheritance $Inh

    # Allow Create & delete object type in OU and sub-OUs
    Set-AllowCreate -ObjectDN $ObjectDN -SubjectDN $SubjectDN -ObjectLdapClassName "User" -Inheritance $Inh
    Set-AllowDelete -ObjectDN $ObjectDN -SubjectDN $SubjectDN -ObjectLdapClassName "User" -Inheritance $Inh

    # Allow edit name properties on User objects in OU and sub-OUs
    Set-Delegation -ObjectDN $ObjectDN -SubjectDN $SubjectDN -RuleType Allow -Rights WriteProperty,ReadProperty -ObjectType $RightUac -InheritanceType $Inh -InheritObjectType $UserClassGuid
    Set-Delegation -ObjectDN $ObjectDN -SubjectDN $SubjectDN -RuleType Allow -Rights WriteProperty,ReadProperty -ObjectType $displayNameProp -InheritanceType $Inh -InheritObjectType $UserClassGuid
    Set-Delegation -ObjectDN $ObjectDN -SubjectDN $SubjectDN -RuleType Allow -Rights WriteProperty,ReadProperty -ObjectType $samProp -InheritanceType $Inh -InheritObjectType $UserClassGuid
    
    # Enable Read/write on Property sets on user objects in OU. Read/write must be assigned separately.
    Set-Delegation -ObjectDN $ObjectDN -SubjectDN $SubjectDN -RuleType Allow -Rights ExtendedRight -ExtendedRight $ExRightLogon -PropertyAccess Read -InheritanceType $Inh -InheritObjectType $UserClassGuid
    Set-Delegation -ObjectDN $ObjectDN -SubjectDN $SubjectDN -RuleType Allow -Rights ExtendedRight -ExtendedRight $ExRightLogon -PropertyAccess Write -InheritanceType $Inh -InheritObjectType $UserClassGuid
    Set-Delegation -ObjectDN $ObjectDN -SubjectDN $SubjectDN -RuleType Allow -Rights ExtendedRight -ExtendedRight $ExRightPublic -PropertyAccess Read -InheritanceType $Inh -InheritObjectType $UserClassGuid
    Set-Delegation -ObjectDN $ObjectDN -SubjectDN $SubjectDN -RuleType Allow -Rights ExtendedRight -ExtendedRight $ExRightPublic -PropertyAccess Write -InheritanceType $Inh -InheritObjectType $UserClassGuid
    Set-Delegation -ObjectDN $ObjectDN -SubjectDN $SubjectDN -RuleType Allow -Rights ExtendedRight -ExtendedRight $ExRightPersonal -PropertyAccess Read -InheritanceType $Inh -InheritObjectType $UserClassGuid
    Set-Delegation -ObjectDN $ObjectDN -SubjectDN $SubjectDN -RuleType Allow -Rights ExtendedRight -ExtendedRight $ExRightPersonal -PropertyAccess Write -InheritanceType $Inh -InheritObjectType $UserClassGuid

    Set-Delegation -ObjectDN $ObjectDN -SubjectDN $SubjectDN -RuleType Allow -Rights ExtendedRight -ExtendedRight $ExRightMembership -PropertyAccess Read -InheritanceType $Inh -InheritObjectType $UserClassGuid
    Set-Delegation -ObjectDN $ObjectDN -SubjectDN $SubjectDN -RuleType Allow -Rights ExtendedRight -ExtendedRight $ExRightMembership -PropertyAccess Write -InheritanceType $Inh -InheritObjectType $UserClassGuid
}

Function Set-FullControlDelegation {
    Param(
        [string]
        $ObjectDN,

        [string]
        $SubjectDN,

        [switch]
        $Inherit
    )

    $Inh = [System.DirectoryServices.ActiveDirectorySecurityInheritance]::None
    If($Inherit) {
        $Inh = [System.DirectoryServices.ActiveDirectorySecurityInheritance]::All
    }
    
    Set-Delegation -ObjectDN $ObjectDN -SubjectDN $SubjectDN -RuleType Allow -Rights GenericAll -InheritanceType $Inh
}

Function Remove-IdsFromSDDLACE {
    Param(
        [Hashtable]
        $RemoveIdentities,

        [string]
        $SddlAce
    )

    If([string]::IsNullOrWhiteSpace($SddlAce)) {
        Write-Host "Empty input string" -ForegroundColor Red
        return
    }

    $Sections = [string[]] @()
    $SectionStartIdx = 0
    $SectionEndIdx = 0
    do {
        If($SectionEndIdx -gt 0) {
            $SectionStartIdx = $SectionEndIdx + 1
        } Else {
            $SectionStartIdx = $SddlAce.IndexOf(":") - 1
        }
        
        $SectionEndIdx = $SddlAce.IndexOf(":", $SectionStartIdx + 2) - 2
        If($SectionEndIdx -lt 0) {
            $Sections += ,($SddlAce.Substring($SectionStartIdx))
        } Else {
            $Sections += ,($SddlAce.Substring($SectionStartIdx, $SectionEndIdx - $SectionStartIdx + 1))
        }
        
    } While($SectionEndIdx -gt 0)

    $Result = ""
    $Updated = $False
    Foreach($Section in $Sections) {
        $Pre = ""
        $FirstPar = $Section.IndexOf("(")
        $Sddl = $Section
        If($FirstPar -gt 0) {
            $Pre = $Section.Substring(0, $FirstPar)
            $Sddl = $Section.Substring($FirstPar + 1, $Section.Length - $FirstPar - 2)
        }

        $tokens = $Sddl.Split(")(", [StringSplitOptions]::RemoveEmptyEntries)
        $SectionResult = ""
        $SectionAltered = $False
        Foreach($t in $Tokens) {
            $Remove = $False

            Foreach($Key in $RemoveIdentities.Keys) { 
                If($t.endsWith(";$Key")) {
                    $Remove = $True
                    Write-Host "Removing [$($RemoveIdentities[$Key])] ACE"
                    Break
                }
            }

            If(-Not $Remove) {
                $SectionResult = "$SectionResult($t)"
            } Else {
                $SectionAltered = $True
            }
        }

        If($SectionAltered) {
            $SectionResult = "$Pre$SectionResult"
            $Result = "$Result$SectionResult"
            $Updated = $True
        } Else {
            $Result = "$Result$Section"
        }
    }

    If($Updated) {
        Write-Output $Result
    } Else {
        Write-Output $SddlAce
    }
}
