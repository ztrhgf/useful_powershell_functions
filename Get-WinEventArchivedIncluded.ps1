function Get-WinEventArchivedIncluded {
    <#
		.SYNOPSIS
			Slouzi k ziskani udalosti ze systemoveho logu i jeho archivu.

		.DESCRIPTION
			Slouzi k ziskani udalosti ze systemoveho logu i jeho archivu

			To jestli se budou udalosti hledat v "zivem" logu i/nebo jeho archivech urcuje inteligentne dle startTime a endTime v filterXML/filterHashTable.

            Hledam vzdy od nejnovejsich udalosti!

            Funkce meni nastaveni culture konzole na en-US, jinak Get-WinEvent nevracel message property udalosti.
            Pote je opet vraceno puvodni culture.
		.PARAMETER computerName
			Na jakem stroji se maji udalosti hledat.
			Vychozi je $EventCollector.

		.PARAMETER  filterXML
			XML filtr pro urceni, ktere zaznamy nas zajimaji.
			Slouzi jako hodnota parametru filterxml cmdletu Get-WinEvent.

			Ukazka:
				[xml]$xml = @"
					<QueryList>
					  <Query Id="0" Path="ForwardedEvents">
					    <Select Path="ForwardedEvents">
						*[System[Provider[@Name='Microsoft-Windows-Security-Auditing']
					</Select>
					  </Query>
					</QueryList>
				"@

		.PARAMETER  filterHashTable
			Hash filtr pro urceni, ktere zaznamy nas zajimaji.
			Slouzi jako hodnota parametru filterHashTable cmdletu Get-WinEvent.

            Ukazka:
                @{id=104; logName='forwardedEvents'}

		.PARAMETER maxEvents
            Kolik se ma najit udalosti. Jakmile ziskam potrebny pocet, ukoncim prohledavani.
            Hledam od nejnovejsich!
			Pokud nezadam a ani (v filterXML/filterHashTable) neomezim od kdy do kdy se maji udalosti hledat, tak se projdou vsechny archivovane logy!

		.PARAMETER howOutputPartialResult
			Retezec definujici, jak zobrazit mezivysledky (a ze je vubec zobrazovat).

            Tzn. $nalezeneudalosti | <howOutputPartialResult>
			Napriklad: sort timecreated -Descending -Unique | group machinename | sort count -Descending | select Count, Name, @{N="TimeCreated";E={$_.group.timecreated}}

        .EXAMPLE
            PS C:\> [xml]$xml = @"
                <QueryList>
                    <Query Id="0" Path="ForwardedEvents">
                    <Select Path="ForwardedEvents">
                    *[System[Provider[@Name='Microsoft-Windows-Security-Auditing']
                </Select>
                    </Query>
                </QueryList>
            "@

			PS C:\> Get-WinEventArchivedIncluded -filterXML $xml -maxEvents 20

			Vypise 20 nejnovejsich udalosti odpovidajicich XML filtru ulozenem v $xml.
            Pokud jich nebude dost v systemovem logu, projde postupne i archivovane logy.

        .EXAMPLE
            PS C:\> [xml]$xml = @"
                <QueryList>
                    <Query Id="0" Path="ForwardedEvents">
                    <Select Path="ForwardedEvents">
                    *[System[Provider[@Name='Microsoft-Windows-Security-Auditing']
                </Select>
                    </Query>
                </QueryList>
            "@

			PS C:\> Get-WinEventArchivedIncluded -filterXML $xml -howOutputPartialResult 'select id, timecreated, message'

			Vypise vsechny udalosti odpovidajici XML filtru v $xml.
            Pokud bude potreba prohledat i archivy, bude vypisovat i mezivysledky ziskane z jednotlivych archivu.

		.EXAMPLE
			PS C:\> Get-WinEventArchivedIncluded -filterHashTable @{id=104; logName='forwardedEvents'; startTime='8.25.2017'; endTime='10.13.2017'}

			Vypise vsechny udalosti serazene od nejnovejsich, odpovidajici hash filtru.
            Pokud jich nebude dost v systemovem logu, projde postupne i archivovane logy.

		.EXAMPLE
			PS C:\> Get-WinEventArchivedIncluded -filterHashTable @{id=104; logName='system'; startTime='8.25.2017'; endTime='10.13.2017'} -maxEvents 150

            Vypise 150 nejnovejsich udalosti odpovidajich hash filtru.
            Pokud jich nebude dost v systemovem logu, projde postupne i archivovane logy.

		.NOTES
			Author: Sebela, ztrhgf@seznam.cz.
    #>

    [CmdletBinding()]
    param(
        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [string] $computerName = $EventCollector
        ,
        [Parameter(Mandatory = $true, ParameterSetName = 'XML')]
        [ValidateNotNullOrEmpty()]
        [xml] $filterXML
        ,
        [Parameter(Mandatory = $true, ParameterSetName = 'HASH')]
        [ValidateNotNullOrEmpty()]
        [hashtable] $filterHashTable
        ,
        [int] $maxEvents
        ,
        [string] $howOutputPartialResult
    )

    begin {
        if (!$computerName) {
            $computerName = $env:computername
        }

        if ($filterHashTable -and !$filterhashTable.LogName) {
            throw "Parametr filterhashTable musi mit definovan klic logName.`nTzn kde se budou udalosti hledat"
        }

        # zjisteni, v jakem logu se budou udalosti hledat
        # abych pozdeji mohl prohledat odpovidajici archivy
        if ($filterXML) {
            $logName = $filterXML.QueryList.Query.Select.Path
        } else {
            $logName = $filterHashTable.LogName
        }

        if (!$logName) {
            throw "Nepodarilo se ziskat logName. Uvedli jste jej ve filtru eventu?"
        }

        # ulozim si aktualni culture, protoze jej pred pouzitim Get-WinEvent zmenim na en-US, tak abych pak vratil zpatky puvodni
        $actualCulture = [System.Threading.Thread]::CurrentThread.CurrentCulture.name
    }

    process {
        # vytvoreni hashe s parametry pro get-winevent
        $params = @{
            erroraction   = "silentlycontinue"
            errorVariable = "winEventErr"
        }
        if ($computerName -notin "localhost", $env:computerName) {
            $params.ComputerName = $computerName
        }
        if ($filterXML) {
            $params.filterxml = $filterXML
        } elseif ($filterHashTable) {
            $params.filterHashTable = $filterHashTable
        }
        if ($maxEvents) {
            $params.MaxEvents = $maxEvents
        }
        if ($VerbosePreference -eq 'continue') {
            $params.verbose = $true
        }

        Write-Verbose "Ziskavam zaznamy ze stroje $computerName."

        #
        # vyextrahuji od kdy do kdy se maji hledat eventy a podle toho nasledne vyfiltruji archivy k prohledani
        #

        $startTime = ''
        $endTime = ''
        # data schvalne ukladam jako datetime objekt, protoze to vynuti US culture tvar, ktery potrebuji pro Get-WinEvent
        # u Get-WinEvent potrebuji US culture, protoze jinak se nekdy nezobrazovala Message property udalosti
        try {
            $ErrorActionPreference = "stop"
            if ($filterXML) {
                # pri konverzi na [xml] se (nevim proc) &lt; prevede na < atd, proto match vuci < > znakum
                $filterText = $filterXML.QueryList.Query.Select.'#text'

                $matches = ''
                if ($filterText -match "@SystemTime\s*<=\s*'([^']+)'") {
                    [datetime]$endTime = $matches[1]
                }
                $matches = ''
                if ($filterText -match "@SystemTime>\s*=\s*'([^']+)'") {
                    [datetime]$startTime = $matches[1]
                }
                $matches = ''
                if ($filterText -match "\[timediff\(@SystemTime\)\s*<=\s*(\d+)\]") {
                    [datetime]$startTime = (Get-Date).AddMilliseconds( - $matches[1])
                }
            } elseif ($filterHashTable) {
                if ($filterHashTable.ContainsKey('startTime')) {
                    [datetime]$startTime = $filterHashTable.startTime
                }
                if ($filterHashTable.ContainsKey('endTime')) {
                    [datetime]$endTime = $filterHashTable.endTime
                }
            }
        } catch {
            if ($_ -match "Cannot bind parameter 'Date'") {
                throw "Chyba ve tvaru startTime/endTime. Datum je potreba zadat ve tvaru MM.dd.yyyy"
            } else {
                throw "Pri zpracovani startTime ci endTime se vyskytla chyba:`n$_"
            }
        }
        $ErrorActionPreference = "continue"


        if ($endTime) {
            # upravim cas v endTime datu tak, aby se pouzily i logy z daneho dne
            # pokud zadal jen datum bez casu, tak se vezme automaticky od 0:00
            # logicky ale chtel vcetne celeho zadaneho dne
            # TODO pri filtrovani udalosti se ale tato zmena neprojevi! doresit..
            if ($endTime.Hour -eq 0 -and $endTime.Minute -eq 0 -and $endTime.Second -eq 0) {
                $endTime = $endTime.AddHours(24)
            }
        }

        Write-Verbose "StartTime: $startTime EndTime: $endTime"



        #
        # seznam vsech dostupnych archivovanych logu (serazeny od nejnovejsiho)
        #
        if ($computerName -notin "localhost", $env:computerName) {
            $logPath = "\\$computerName\c$\windows\system32\winevt\logs"
        } else {
            $logPath = "C:\windows\system32\winevt\logs"
        }
        $archivedLogs = Get-ChildItem -File -Filter "Archive-$logName-*.evtx" -Path $logPath |
            select FullName, CreationTime | sort CreationTime -Descending
        $archivedLogsCopy = $archivedLogs

        $allArchivedLogsCount = ($archivedLogs.fullname).count

        # jaky nejstarsi zaznam je v systemem pouzivanem forwarded logu (zjistim neprimo dle stari nejstarsiho archivovaneho logu)
        $newestArchiveLogCreated = '1.1.1900' # nastavim dummy datum hodne v minulosti
        if ($archivedLogs) {
            $newestArchiveLogCreated = $archivedLogs | select -First 1 | select -ExpandProperty CreationTime
        }



        #
        # ziskani archivovanych logu, ktere mohou obsahovat hledane udalosti
        #

        $searchSystemLog = 1
        # je startTime > vsechny archivy po tomto datu
        if ($startTime) {
            $archivedLogs = $archivedLogs | where {$_.CreationTime -ge $startTime} #| sort CreationTime # jako prvni chci prohledavat nejstarsi logy?
        }
        # je endTime > vsechny archivy pred timto datem + eventlog pokud byl vytvoren pred timto datem
        if ($endTime) {
            $archivedLogs = $archivedLogs | where {$_.CreationTime -le $endTime}

            # vzdy pridam i prvni archiv, ktery vznikl po endTime, obsahuje totiz eventy z doby mezi vznikem posledniho archivu (pred endTime) az po endTime
            $archivedLogs = $archivedLogsCopy | where {$_.CreationTime -ge $endTime} | select -Last 1

            if ($endTime -lt $newestArchiveLogCreated) {
                Write-Verbose "Nema smysl prohledavat aktivni log. Obsazene eventy jsou mimo zadane rozsahy."
                $searchSystemLog = 0
            }
        }
        if (!$startTime -and !$endTime -and $archivedLogs) {
            Write-Warning "Prohleda se pouze aktivni log, zadne archivy. Nezadali jste totiz startTime ani endTime :)"
        }

        $filteredArchivedLogsCount = ($archivedLogs.fullname).count



        #
        # prohledam aktualni log s forwardovanymi eventy
        #

        if ($searchSystemLog) {
            Write-Verbose "Prohledavam log $logName"
            # ohackovani, aby se nevracela prazdna message property, pokud ma jiny nez en-US culture
            [System.Threading.Thread]::CurrentThread.CurrentCulture = 'en-US'
            [System.Collections.ArrayList] $result = @(Get-WinEvent @params)
            [System.Threading.Thread]::CurrentThread.CurrentCulture = $actualCulture
            # upozornim na pripadne chyby
            if ($winEventErr) {
                Write-Warning "Pri hledani udalosti se vyskytla tato chyba:`n$winEventErr"
            }
        }

        #
        # vypsani vysledku (+ dohledani z archivu pripadne)
        #

        # mam vse co jsem chtel, vypisi a ukoncim
        if ($result -and (($maxEvents -and ($($result.count) -ge $maxEvents) -or (!$maxEvents -and !$archivedLogs)))) {
            Write-Verbose "Mam dost udalosti. Ukoncuji"
            return $result | Sort-Object TimeCreated -Descending
        } else {
            # nemam dostatecny pocet udalosti
            # zkusim najit a nasledne prohledat i archivovane logy

            # nejsou zadne archivy, vratim co mam
            if (!$archivedLogs) {
                Write-Warning "Neexistuji zadne vhodne archivovane logy kde bych dohledal zbyle udalosti."
                return $result | Sort-Object TimeCreated -Descending
            } else {
                # mam nejake archivovane logy k prohledani
                if ($maxEvents) {
                    $pocet = ", (pozadovano $maxEvents) -> prohledam archivovane logy"
                }
                if ($result) {
                    Write-Host "Mam $($result.count) udalosti$pocet."
                }

                # vypisu mezivysledky
                if ($result -and $howOutputPartialResult) {
                    # vytvorim scriptblock, ktery stavajici mezivysledek vypise tak, jak je receno v HowOutputPartialResult
                    $partialResultOutput = (([scriptblock]::Create("`$result | $howOutputPartialResult")).invoke() | out-string).trim()
                    Write-Host $partialResultOutput # pouzit Write-Verbose pokud by bylo potreba s vystupem pracovat dal..
                }

                # vypsani informaci o poctu archivu k prohledani
                if ($allArchivedLogsCount -eq $filteredArchivedLogsCount -and !$maxEvents) {
                    Write-Warning "Neomezili jste nijak hledani. Prohledaji se vsechny ($(($archivedLogs.fullname).count)) archivovane logy!"
                } else {
                    # neprohledam vsechny dostupne archivy, nepotrebne jsem odfiltroval
                    if ($startTime) {
                        $txt = "Od $startTime "
                    }
                    if ($endTime) {
                        $txt += "do $endTime "
                    }
                    if (!$txt) {
                        $txt = "Existuje"
                    } else {
                        $txt += "existuje"
                    }

                    Write-Host "$txt $(($archivedLogs.fullname).count) archivu k prohledani."
                }

                Write-Host "`nZiskavam udalosti z:"

                #
                # prohledam postupne jednotlive archivovane logy
                #
                foreach ($path in $archivedLogs.FullName) {
                    if ($filterXML) {
                        $filterXML.QueryList.Query.path = "file://$path"
                        $filterXML.QueryList.Query.select.path = "file://$path"
                    } elseif ($filterHashTable) {
                        $filterhashTable["Path"] = $path
                    }

                    # vypisu jmeno aktualne prohledavaneho archivu
                    if ($archivedLogs[0].fullname -ne $path) {
                        $newLine = "`n"
                    }
                    Write-Host "$newLine  - $(Split-Path $path -leaf)"

                    # ke stavajicim vysledkum pridam co jsem nasel v archivovanem logu
                    $partialResult = @()
                    Write-Verbose "start ziskavani udalosti $(Get-Date -Format T)"
                    # ohackovani, aby se nevracela prazdna message property, pokud ma jiny nez en-US culture
                    [System.Threading.Thread]::CurrentThread.CurrentCulture = 'en-US'
                    $winEventErr = ''
                    $partialResult = Get-WinEvent @params
                    [System.Threading.Thread]::CurrentThread.CurrentCulture = $actualCulture
                    # upozornim na pripadne chyby
                    if ($winEventErr) {
                        Write-Warning "Pri hledani udalosti se vyskytla tato chyba:`n$winEventErr"
                    }
                    Write-Verbose "end ziskavani udalosti $(Get-Date -Format T)"

                    if ($partialResult) {
                        $partialResult | % { $null = $result.add($_) }
                    }

                    # pokud mam dost udalosti, ukoncim hledani
                    if ($maxEvents -and $($result.count) -ge $maxEvents) {
                        Write-Host "Uz mam dost udalosti, ukoncuji."
                        break
                    } else {
                        # nemam dost udalosti nebo hledam na zaklade datumu (projdu vsechny dostupne archivy)

                        # prohledavam posledni archiv
                        if ($archivedLogs[-1].fullname -eq $path) {
                            $t = 'prohledal jsem posledni archiv'
                        } else {
                            $t = 'pokracuji'
                        }
                        Write-Host "Mam $($result.count) udalosti, $t."

                        # chci zobrazovat mezivysledky
                        if ($howOutputPartialResult) {
                            # vytvorim scriptblock, ktery stavajici mezivysledek vypise tak jak je receno v HowOutputPartialResult
                            $partialResultOutput = (([scriptblock]::Create("`$partialResult | $howOutputPartialResult")).invoke() | out-string).Trim()
                            Write-Host $partialResultOutput # pouzit Write-Verbose pokud by bylo potreba s vystupem pracovat dal..
                        }
                    }
                }
            } # end mam archivy k prohledani

            if (!$result) {
                Write-Verbose "Nenalezl jsem zadne udalosti."
            }

            return $result | Sort-Object TimeCreated -Descending
        }
    }
}