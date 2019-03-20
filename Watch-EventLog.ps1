function Watch-EventLog {
    <#
    .SYNOPSIS
    Funkce pro realtime sledovani vybranych udalosti v sys logu.
    Nalezene udalosti se budou vypisovat do konzole dokud funkci nneukoncite CTRL + C.

    .DESCRIPTION
    Funkce pro realtime sledovani vybranych udalosti v sys logu.
    Nalezene udalosti se budou vypisovat do konzole dokud funkci nneukoncite CTRL + C.
    Umoznuje hledat dle id a/nebo providera.

    .PARAMETER computerName
    Jmeno stroje, na kterem se maji logy sledovat.

    .PARAMETER eventToSearch
    Filtr ve specifickem tvaru definujici jake udalosti se maji hledat.
    Zapisujte ve tvaru: 'logName;eventId;providerName'. Takovychto stringu muze byt vic, oddelenych klasicky carkou.
    Sekce eventId a providerName mohou obsahovat vic polozek oddelenych carkou.
    Sekce logName je povinna!

    Napr.:
    'security;50' pro hledani udalosti s id 50 v logu security

    'security;50,100' pro hledani udalosti s id 50 ci 100 v logu security

    'security;50,100;Microsoft-Windows-Security-Auditing' pro hledani udalosti s id 50 ci 100 v logu security od providera Microsoft-Windows-Security-Auditing

    'security;;Microsoft-Windows-Security-Auditing' pro hledani udalosti od providera Microsoft-Windows-Security-Auditing v logu security

    .PARAMETER sleep
    Pocet vterin mezi jednotlivymi hledanimi.

    Vychozi je 60.

    .PARAMETER searchFrom
    Od kdy (do ted) se maji zacit hledat udalosti.
    Mozno pouzit, pokud chcete navazat na posledni mereni.

    .PARAMETER stopAfter
    Za kolik hodin se ma mereni ukoncit.

    Vychozi je undef tzn mereni pobezi do nekonecna.

    .EXAMPLE
    Watch-EventLog -eventToSearch "security;4672,4624,4798"

    Bude vypisovat udalosti 4672,4624 a 4798 v logu security.

    .EXAMPLE
    Watch-EventLog -eventToSearch "security;4672,4624,4798","application;;dbupdate"

    Bude vypisovat udalosti 4672,4624 a 4798 v logu security a zaroven vsechny udalosti z logu application, od providera dbupdate.

    .EXAMPLE
    Watch-EventLog -eventToSearch "security;4672,4624,4798" -searchFrom '15:00'

    Bude vypisovat udalosti 4672,4624 a 4798 v logu security. Vypise i udalosti od 15:00 doted.
    #>

    [cmdletbinding()]
    param (
        [Parameter(Position = 0)]
        [string] $computerName = $env:COMPUTERNAME
        ,
        [Parameter(Position = 1, Mandatory = $true)]
        [ValidateScript( {
                If ($_ -match '^[\w-/]+;?[\d, ]*;?[\w, -]*$') {
                    $true
                } else {
                    Throw "Zadavejte ve formatu: 'logName;eventId; provider'  Pr.: 'security;50' nebo 'security;50,100' nebo 'security;50,100;Microsoft-Windows-Security-Auditing' nebo 'security;;Microsoft-Windows-Security-Auditing'"
                }
            })]
        [string[]] $eventToSearch
        ,
        [int] $sleep = 60
        ,
        [ValidateScript( {
                If (($_.getType().name -eq "string" -and [DateTime]::Parse($_)) -or ($_.getType().name -eq "dateTime")) {
                    $true
                } else {
                    Throw "From zadejte ve formatu dle vaseho culture. Pro cs-CZ napr.: 15.2.2019 15:00. Pro en-US pak prohodit den a mesic."
                }
            })]
        $searchFrom
        ,
        [ValidateScript( {
                If ($_ -gt 0) {
                    $true
                } else {
                    Throw "stopAfter musi byt kladna hodnota."
                }
            })]
        [int] $stopAfter
    )

    if ($searchFrom) {
        if ($searchFrom.getType().name -eq "string") {
            $searchFrom = [DateTime]::Parse($searchFrom)
        }

        if ($searchFrom -gt (Get-Date)) {
            throw "searchFrom musi byt v minulosti"
        }
    }

    $isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")

    # nastavim odstup hledani (aby se mi nestalo, ze mi utece udalost, ktera se vyskytla ve stejne vterina, kdy jsem udelal mereni)
    # tzn vypisi udalosti do aktualni cas - vterina
    $delay = 1

    #
    # VYTVORENI XML FILTRU DLE ZADANI
    $filter = @"
<QueryList>
  <Query Id="0" Path="Application">
"@

    # ze zadani vyextrahuji jake udalosti se maji hledat a vytvorim odpovidajici xml filtr
    $eventToSearch | % {
        $s = $_ -split ';'

        $logName = $s[0]

        if ($logName -match 'security' -and !$isAdmin -and $computerName -eq $env:COMPUTERNAME) {
            throw "Pro prohlizeni security logu je potreba spustit s admin pravy"
        }

        if ($logName -match "forwardedEvents" -and !$delay) {
            # nastavim odstup hledani (60 vterin by melo staci, eventy se typicky forwarduji z klientu na server do 30 vterin)
            $delay = 60
            Write-Warning "Nastavuji zpozdeni hledani o $delay vterin, protoze se hleda ve forwardovanych eventech.`nAby se nestalo, ze se nejake eventy prehlednou, protoze se objevily az po prohledani daneho casoveho rozsahu daneho parametrem sleep. (Jejich TimeCreated atribut odpovida vytvoreni na puvodnim klientovi a ne kdy se objevi ve forwardedEvents logu)"
        }

        $id = $s[1]
        if ($id) {
            $id = $id -split ',' -replace "\s+"
        }

        $provider = $s[2]
        if ($provider) {
            $provider = $provider -split ',' -replace "\s+"
        }

        $idFilter = ""
        $id | ? {$_} | % {
            if ($idFilter) { $idFilter += " or "}
            $idFilter += "EventID=$_"
        }
        $providerFilter = ""
        $provider | ? {$_} | % {
            if ($providerFilter) { $providerFilter += " or "}
            $providerFilter += "@Name=`'$_`'"
        }

        $row = "`n<Select Path=`"$logname`">*[System["

        if ($providerFilter) {
            $row += "Provider[$providerFilter]"
        }

        if ($providerFilter -and $idFilter) {
            $row += " and "
        }

        if ($idFilter) {
            $row += "($idFilter)"
        }

        # DUMBFILTERTIME pozdeji nahrazuji potrebnym datem
        $row += " and TimeCreated[DUMBFILTERTIME]]]</Select>"
        $filter += $row
    }

    $filter += @"
`n</Query>
</QueryList>
"@

    Write-Verbose $filter

    # poznacim si spusteni skriptu, abych jej mohl pripadne po x hodinach ukoncit
    $start = Get-Date

    if ($searchFrom -and $delay -and $searchFrom.AddSeconds($delay) -gt (Get-Date)) {
        Write-Warning "Pockam $delay vterin kvuli moznemu zpozdeji eventu ve forwardedEvents logu a provedu prvni hledani"
        Start-Sleep -Seconds $delay
    }


    #
    # hledani udalosti
    while (1) {
        if (!$searchFrom) {
            Write-Warning "Pockam $($sleep + $delay) vterin a provedu prvni hledani"
            $searchFrom = Get-Date
            Start-Sleep -Seconds ($sleep + $delay)
            Write-Warning "Hledam.."
            continue
        }

        if ($stopAfter -and $start.AddHours($stopAfter) -lt (Get-Date)) {
            Write-Warning "Skript uz bezi $stopAfter hodin. Ukoncuji"
            break
        }

        $from = $searchFrom
        $to = (Get-Date).AddSeconds(-$delay)
        Write-Verbose "Hledam od $(Get-Date $from -Format "HH:mm:ss") do $(Get-Date $to -Format "HH:mm:ss")"
        # do searchFrom ulozim cas, po ktery ted budu hledat udalosti, abych priste od tohoto casu zacal hledat dalsi
        $searchFrom = $to
        # prevedu datum na format pouzivany v xml filtru event logu (vcetne nutne korekce casu o hodinu)
        $from = Get-Date (Get-Date $from).AddHours(-1) -Format s
        $to = Get-Date (Get-Date $to).AddHours(-1) -Format s

        # ve filtru musim pro kazdou iteraci while cyklu nastavit znovu od kdy a do kdy se maji hledat udalosti
        $xmlFilter = $filter -replace "DUMBFILTERTIME", "`@SystemTime&gt;=`'$from`' and `@SystemTime&lt;=`'$to`'"

        Write-Verbose $xmlFilter

        $params = @{
            FilterXml   = $xmlFilter
            ErrorAction = "Stop"
        }
        if ($computerName -ne $env:COMPUTERNAME) {
            $params.computerName = $computerName
        }

        # najdu a vypisu udalosti odpovidajici zadani
        try {
            Get-WinEvent @params
        } catch {
            if ($_ -notmatch "^No events were found that match the specified selection criteria") {
                throw $_
            } else {
                Write-Verbose "Nenalezen odpovidajici event"
            }
        }

        Write-Warning "Cekam"
        Start-Sleep -Seconds $sleep
    }
}