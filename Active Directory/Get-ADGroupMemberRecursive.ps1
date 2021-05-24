function Get-ADGroupMemberRecursive {
    <#
    .SYNOPSIS
    Function for outputting members login (samAccountName) of given AD group and its nested groups.
    By default output only users.

    .DESCRIPTION
    Function for outputting members login (samAccountName) of given AD group and its nested groups.
    By default output only users.

    Does not need AD module.

    .PARAMETER name
    AD group name.

    .PARAMETER distinguishedName
    AD group distinguishedName.

    .PARAMETER justGroup
    Instead of member users, returns name of members groups.

    .PARAMETER userAndGroup
    Outputs member users and groups.

    .EXAMPLE
    Get-ADGroupMemberRecursive 'domain admins'

    Returns samAccountName of members of given AD group.

    .EXAMPLE
    Get-ADGroupMemberRecursive "CN=Domain Admins, CN=Users, DC=master, DC=contoso, DC=com"

    Returns samAccountName of members of given AD group.
    #>

    [CmdletBinding(DefaultParameterSetName = 'Default')]
    param (
        [Parameter(Mandatory = $true, Position = 0, ParameterSetName = "Default")]
        [ValidateScript( {
                If ($_ -match "=") {
                    throw "$_ is in DN format, use regular AD group name"
                } else {
                    $true
                }
            })]
        [ArgumentCompleter( {
                param ($Command, $Parameter, $WordToComplete, $CommandAst, $FakeBoundParams)

                $ADDN = ([ADSI]"LDAP://RootDSE").rootDomainNamingContext
                $searcher = [adsisearcher]"(objectCategory=group)"
                $searcher.PageSize = 500
                $searcher.PropertiesToLoad.AddRange('name')
                $searcher.searchRoot = [adsi]"LDAP://$ADDN"
                ($searcher.FindAll() | ? { $_.properties.name -like "*$WordToComplete*" }).properties.name
                $searcher.Dispose()
            })]
        [string] $name
        ,
        [Parameter(Mandatory = $true, Position = 0, ParameterSetName = "DN")]
        [ValidateScript( {
                If ($_ -match "^CN=") {
                    $true
                } else {
                    throw "$_ is not in DN format (example: CN=Domain Admins, CN=Users, DC=contoso, DC=com)"
                }
            })]
        [string] $distinguishedName
        ,
        [switch] $justGroup
        ,
        [switch] $userAndGroup
    )

    (Get-Variable name).Attributes.Clear()
    (Get-Variable distinguishedName).Attributes.Clear()

    if ($env:USERDOMAIN -eq $env:COMPUTERNAME) {
        throw "Run under domain user. Local users does not have right to query AD"
    }

    if ($justGroup -and $userAndGroup) {
        throw "You cannot use both justGroup and userAndGroup"
    }

    if ($name) {
        $ADDN = ([ADSI]"LDAP://RootDSE").rootDomainNamingContext
        $distinguishedName = (New-Object System.DirectoryServices.DirectorySearcher((New-Object System.DirectoryServices.DirectoryEntry("LDAP://$ADDN")) , "(&(objectCategory=group)(cn=$name))")).FindAll() | ForEach-Object { $_.Properties.distinguishedname }
        Write-Verbose "Name $name was translated to DN $distinguishedName"
        if (!$distinguishedName) {
            Write-Warning "Group with name $name doesn't exist."
            return
        }
    }

    $adobject = [adsi]"LDAP://$distinguishedName"
    if ($adobject.properties) {
        $adobject.properties.item("member") | % {
            $objMembermod = $_.replace("/", "\/")
            $objAD = [adsi]"LDAP://$objmembermod"
            $attObjClass = $objAD.properties.item("objectClass")
            if ($attObjClass -eq "group") {
                Write-Verbose "$($objAD.name) is group"
                if ($justGroup -or $userAndGroup) {
                    $objAD.name
                }

                $params = $PSBoundParameters
                $null = $params.remove("name")
                $params.distinguishedName = $_
                Get-ADGroupMemberRecursive @params
            } else {
                Write-Verbose "$($objAD.name) is account"
                if (!($justGroup) -or $userAndGroup) {
                    $objAD.sAMAccountName
                }
            }
        }
    } else {
        Write-Warning "Group with DN $distinguishedName doesn't exist."
        return
    }
}

