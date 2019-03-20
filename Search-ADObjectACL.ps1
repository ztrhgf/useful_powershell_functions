#Requires -Modules PowerShellAccessControl
function Search-ADObjectACL {
    <#
    .SYNOPSIS
    Funkce slouzi k najiti ACL odpovidajicich zadani nad yadanymi AD objekty.
    Pri spusteni bez dalsich parametru vypise vsechna ACL vsech objektu v domene.

    .DESCRIPTION
    Funkce slouzi k najiti ACL odpovidajicich zadani nad yadanymi AD objekty.
    Pri spusteni bez dalsich parametru vypise vsechna ACL vsech objektu v domene.
    DetailACL pripadne obsahuje, na co se pravo vztahuje (na jaky atribut atd).

    .PARAMETER distinguishedName
    Cesta k objektu v AD zadana v distinguished tvaru.
    Pokud nezadano, projde se cela AD.

    .PARAMETER recurse
    Prepinac rikajici, ze se maji projit i zanorene objekty pod cestou z distinguishedName parametru

    .PARAMETER allPartitions
    Prepinac rikajici, ze se maji vyhledat objekty ze vsech AD partition.
    Standardne se hleda jen v "Default naming context" partition.

    .PARAMETER objectType
    Umoznuje omezit, jake objekty se budou hledat. Min objektu == rychlejsi.
    Pokud je zaroven zadan distinguishedName, tak je nutne pouzit s prepinacem -Recurse.
    Jinak se nehledaji zanorene objekty a kontroluje se pouze ten jeden zadany.

    Na vyber je "Computer", "User", "Group", "OrganizationUnit"

    .PARAMETER account
    Pro vypis pouze prav, ktera ma zadany ucet (ucet/skupina/pocitac)

    .PARAMETER alsoByMembership
    Prepinac rikajici, ze se vypisi i prava nalezici skupinam, jichz je ucet definovany v parametru account clenem

    .PARAMETER right
    Nazev prava, ktere se ma hledat.
    Staci zadat cast nazvu.
    Hleda se skutecne konkretni vyskyt prava. Nefunguje tak, ze byste zadali genericRead a nasly se i zaznamy, kde ma uzivatel genericAll (tzn. full control) a je jedno, ze kdyz ma full control, ma tim padem i read.

    Nazvy neodpovidaji 1:1 tomu co je videt v GUI! Idealni je timto prikazem vyje prava k obejktu, kde vite, ze je pravo pouzito a tak ziskat jeho nazev

    .PARAMETER justExplicit
    Prepinac rikajici, ze se vypisi pouze explicitni prava (ne zdedena)

    .PARAMETER type
    Typ prava. Moznosti jsou Allow, Deny ci vychozi Both

    .EXAMPLE
    Search-ADObjectACL -distinguishedName "OU=Management,OU=Skupiny,DC=ad,DC=fi,DC=muni,DC=cz"

    Vypise vsechna prava, ktera jsou definovana na zadanem objektu.

    .EXAMPLE
    Search-ADObjectACL -distinguishedName "OU=Management,OU=Skupiny,DC=ad,DC=fi,DC=muni,DC=cz" -recurse

    Vypise vsechna prava, ktera jsou definovana na zadanem objektu a objektech v nem obsazenych

    .EXAMPLE
    Search-ADObjectACL -distinguishedName "OU=Management,OU=Skupiny,DC=ad,DC=fi,DC=muni,DC=cz" -justExplicit

    Vypise pouze explicitni prava, ktera jsou definovana na zadanem objektu


    .EXAMPLE
    Search-ADObjectACL -distinguishedName "OU=Management,OU=Skupiny,DC=ad,DC=fi,DC=muni,DC=cz" -right ms-Mcs-AdmPwd -account "domain admins" -alsoByMembership

    Vypise vsechny zaznam prav cist/zapisovat ms-Mcs-AdmPwd (tzn LAPS heslo), ktera ma skupina "Domain Admins" ci skupiny jiz je clenem na zadanem objektu


    .EXAMPLE
    Search-ADObjectACL -distinguishedName "OU=Management,OU=Skupiny,DC=ad,DC=fi,DC=muni,DC=cz" -type Deny

    Vypise vsechna deny prava, ktera jsou definovana na zadanem objektu

    .NOTES
    Vyzaduje modul PowerShellAccessControl, konkretne funkci Get-AdObjectAceGuid pro preklad extendedRight a schema prav
    #>

    [CmdletBinding()]
    param (
        [Parameter(Position = 0, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [ValidateScript( {
                If (($_ -match ',DC=\w+$')) {
                    $true
                } else {
                    Throw "Zadejte v distinguished name tvaru. Napr.: OU=Skupiny,DC=ad,DC=fi,DC=muni,DC=cz"
                }
            })]
        [string] $distinguishedName
        ,
        [switch] $recurse
        ,
        [switch] $allPartitions
        ,
        [ValidateSet("Computer", "User", "Group", "OrganizationUnit")]
        [string[]] $objectType
        ,
        [Parameter(Position = 1, ValueFromPipeline = $true)]
        [string] $account
        ,
        [switch] $alsoByMembership
        ,
        [Parameter(Position = 2, ValueFromPipeline = $true)]
        [string] $right
        ,
        [switch] $justExplicit
        ,
        [ValidateSet("Allow", "Deny", "Both")]
        [string] $type = "Both"
    )

    begin {
        if ($objectType -and $distinguishedName -and !$recurse) {
            Write-Warning "Filtr objectType se neaplikuje, protoze jste nepouzili -Recurse, takze se prohledaji pouze prava objektu '$distinguishedName'"
        }

        if ($allPartitions -and $distinguishedName) {
            Write-Warning "Parametr distinguishedName se nepouzije, protoze jste zadali hledani ve vsech partition AD"
            $distinguishedName = ''
        }

        if ($account) {
            $identityFilter = $account
        }

        if ($alsoByMembership) {
            if ($group = (Get-ADUser $account -Properties memberof | Select-Object -ExpandProperty memberof | % {($_ -split ',')[0] -replace "CN="}) -join '|') {
                $identityFilter = "$account|$group"
            }
        }

        #
        # ziskani seznamu objektu z AD, pro ktere pote ziskam jejich ACL
        $params = @{
            Properties  = 'distinguishedname'
            ErrorAction = 'stop'
        }
        $filter = "*"
        if ($objectType) {
            $filter = ""
            $objectType | % {
                if ($filter) {
                    $filter += " -or "
                }
                if ($_ -eq 'User') {
                    $filter += "(ObjectClass -eq `"$_`" -and objectCategory -eq `"Person`")"

                } else {
                    $filter += "ObjectClass -eq `"$_`""
                }
            }

        }

        if ($distinguishedName) {
            if ($recurse) {
                $params.SearchBase = $distinguishedName
                $params.Filter = $filter
            } else {
                $params.Identity = $distinguishedName
            }
        } else {
            $params.Filter = $filter
        }

        if ($allPartitions) {
            $params.searchBase = ""
            $gc = (Get-ADDomainController -Discover -Service "GlobalCatalog").name
            $params.server = "$gc`:3268"
        }

        try {
            $searchInObject = Get-ADObject @params
        } catch {
            throw "Pri ziskavani objektu z AD se objevila chyba:`n$_"
        }

        if (!$searchInObject) {
            Write-Warning "Zadny AD objekt neodpovida zadani. Ukoncuji."
            break
        }
    }

    process {
        $searchInObjectCount = $searchInObject.distinguishedname.count
        $count = 0

        #
        # pro vsechny zadane AD objekty zjistim jejich ACL
        $searchInObject | % {
            $dn = $_.distinguishedname
            Write-Progress -Activity "Zpracovavam objekt" -Status "$dn" -PercentComplete (( $count / $searchInObjectCount ) * 100) -Id 1
            try {
                $acl = Get-Acl -path "AD:\$dn" -errorAction stop | Select-Object -ExpandProperty Access
            } catch {
                # v AD jsou ruzne podivnosti jako 'CN=\#deprecated\#_InteractiveLogon,OU=Skupiny,DC=ad,DC=fi,DC=muni,DC=cz', ktere konnci chybou 'The object name has bad syntax'
            }

            foreach ($a in $acl) {
                Write-Progress -Activity "Zpracovavam jeho acl" -Status $a.ActiveDirectoryRights -ParentId 1

                if ($justExplicit -and $a.isInherited -eq $true) {
                    continue
                }
                if ($identityFilter -and $a.IdentityReference.value -notmatch $identityFilter) {
                    continue
                }
                if ($type -ne "Both" -and $a.AccessControlType -ne $type) {
                    continue
                }

                $output = $a | Select-Object IdentityReference, @{n = 'DistinguishedName'; e = {$dn}}, ActiveDirectoryRights, AccessControlType, IsInherited, objectType, @{n = 'detailedACL'; e = {Get-AdObjectAceGuid -Guid $a.objectType | select -exp name}}

                if ($right -and !($output.ActiveDirectoryRights -like "*$right*" -or $output.detailedACL -like "*$right*")) {
                    # pozadovane pravo nenalezeno
                    continue
                }

                $output
            }
            ++$count
        }
    }
}
