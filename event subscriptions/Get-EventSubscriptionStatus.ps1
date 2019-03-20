function Get-EventSubscriptionStatus {
    <#
		.SYNOPSIS
			Fce pro vypsani stavu event subskripce/i.

        .DESCRIPTION
			Fce pro vypsani stavu event subskripce/i.

		.PARAMETER computername
            Na jakem stroji se maji subskripce hledat.

            Vychozi je obsah promenne eventCollector.

		.PARAMETER subscriptionName
            Jmeno subskripce.
            Nepovinny parametr.

		.PARAMETER eventSource
            Jmeno/a stroje/u, pro ktere chci vypsat stav aplikovani subskripce.
            Staci zadat cast jmena (hleda se pomoci like)
            Nepovinny parametr.

		.PARAMETER showSourceComputerStatus
            Misto celkoveho stavu subskripce vypise stav pro jednotlive zdrojove stroje, ktere ji na sebe aplikuji.

		.EXAMPLE
            Get-EventSubscriptionStatus -subscriptionName 'User logon logoff' | ft

			Z kolektoru ulozeneho v eventCollector promenne vypise stav subskripce 'User logon logoff'.

        .EXAMPLE
            Get-EventSubscriptionStatus -subscriptionName 'User logon logoff' -showSourceComputerStatus -eventSource titan | ft

			Z kolektoru ulozeneho v eventCollector promenne vypise stav subskripce 'User logon logoff' na source pocitacich, jejichz jmeno zacina titan.

		.NOTES
			Author: Ondřej Šebela - ztrhgf@seznam.cz
    #>

    [cmdletbinding()]
    param (
        [string] $subscriptionName
        ,
        [string] $eventSource
        ,
        [switch] $showSourceComputerStatus
        ,
        [ValidateNotNullOrEmpty()]
        [string] $computerName = $eventCollector
    )

    if ($eventSource -and $showSourceComputerStatus) {
        write-warning "Parametr eventSource se bude ignorovat. Filtrovat dle zdrojoveho stroje ma smysl pouze v kombinaci s parametrem showSourceComputerStatus"
    }

    Invoke-Command2 -computerName $computerName {
        param ($subscriptionName, $eventSource, $showSourceComputerStatus)

        # vykradeno z https://github.com/dotps1/PSWecutil/blob/master/PSWecutil
        function _result2Object {
            [CmdletBinding()]
            [OutputType([PSCustomObject])]

            param (
                [Parameter(Mandatory = $true)]
                [Array] $StringArray
                ,
                [switch] $showSourceComputerStatus
            )

            # zbavim se prazdnych radku
            $StringArray = $StringArray | where {$_}

            if ($showSourceComputerStatus) {
                # vypisi stav per source computer

                # najdu radek se jmenem subskripce
                $subscriptionName = ($StringArray | where {$_ -like 'subscription*'} | select -First 1).split(':')[1].trim()

                # zjistim na kolika radcich jsou ulozeny informace ke kazdemu source (vzdy zacina jmenem stroje (tzn radek neobsahuje ':'))
                $startLine = ($StringArray |
                        Select-String ":" -NotMatch |
                        Select-Object -ExpandProperty LineNumber -First 1) - 1
                $endLine = ($StringArray |
                        Select-String ":" -NotMatch |
                        Select-Object -ExpandProperty LineNumber -First 1 -Skip 1) - 2

                if ($endLine -lt 0) {
                    # neni k dispozici zadny stav per source computer (zadny danou subskripci neaplikoval?)
                    #$endLine = $StringArray.Count
                    return ''
                }
                $range = $endLine - $startLine

                # postupne projdustring s vystupem po balicich radku (range), ktere odpovidaji jednomu stroji
                # a prevedu na objekt
                $output = @()
                for ($i = $startLine; $i -lt $StringArray.Count; $i += $range + 1) {
                    $hashTable = [HashTable]::new()
                    $hashTable.Add("Subscription", $subscriptionName)
                    ($StringArray[$i..($i + $range)]).ForEach( {
                            $parts = $_ -split ":"
                            if ($parts.Count -eq 1) {
                                # jde o radek se jmenem stroje (ty neobsahuji dvojtecku)
                                try {
                                    # nekdy se stalo, ze eventSource byl prazdny == koncilo chybou
                                    $hashTable.Add("EventSource", $parts[0].Trim())
                                } catch {}
                            } else {
                                # radek s dvojici (pred dvojteckou je jmeno atributu, za dvojteckou pak jeho hodnota)
                                if ($lastHeartbeatTime = ($parts[1..$parts.count] -join ":").Trim() -as [datetime]) {
                                    # datum je ve tvaru 2018-06-27T08:06:36.826 tzn obsahuje :, proto ten join
                                    # hodnotou je datum, ulozim jako datetime objekt
                                    $hashTable.Add($parts[0].Trim(), $lastHeartbeatTime)
                                } else {
                                    $hashTable.Add($parts[0].Trim(), ($parts[1..$parts.count] -join ":").Trim() -replace '.ad.fi.muni.cz')
                                }
                            }
                        })

                    $output += [PSCustomObject]$hashTable
                }
            } else {
                # vypisi stav per subskripce
                $hashTable = [HashTable]::new()
                # z kazdeho vypisu vezmu pouze nekolik prvnich radku, ktere vim ze se vztahuji k celkovemu stavu subskripce
                $StringArray[0..2] | where {$_} | % {
                    $parts = $_ -split ":"
                    $key = ($parts[0]).Trim()
                    $value = ($parts[1]).Trim()
                    $hashTable[$key] = $value
                }
                # vypisi i jake stroje jsou zdroji dane subskripce
                $ErrorActionPreference = 'silentlyContinue'
                $eventSources = $StringArray | where {$_ -notmatch ':'} # vytahnu jen radky obsahujici jmena stroju (neobsahuji :)
                $eventSources = $eventSources | foreach {$_.trim() -replace '.ad.fi.muni.cz', ''} # zprehledneni vystupu
                $ErrorActionPreference = 'Continue'
                $hashTable['EventSources'] = $eventSources
                $hashTable['EventSourcesCount'] = ($eventSources).count

                $output += [PSCustomObject]$hashTable
            }

            Write-Output -InputObject $output
        } # konec funkce _result2Object

        # vychozi parametry pro _result2Object
        $params = @{}
        $params['showSourceComputerStatus'] = $showSourceComputerStatus

        if ($subscriptionName) {
            $errorPref = $ErrorActionPreference
            try {
                $ErrorActionPreference = 'stop'
                $result = wecutil get-subscriptionruntimestatus $subscriptionName | where {$_}
            } catch {
                throw "Subskripci $subscriptionName se nepodarilo na $env:COMPUTERNAME dohledat"
            }
            $ErrorActionPreference = $errorPref

            $params['StringArray'] = $result
            _result2Object @params | where {$_.eventSource -like "$eventSource*"}
        } else {
            wecutil enum-subscription | % {
                $result = wecutil get-subscriptionruntimestatus $_  | where {$_}

                $params['StringArray'] = $result
                _result2Object @params | where {$_.eventSource -like "$eventSource*"}
            }
        }
    } -argumentList $subscriptionName, $eventSource, $showSourceComputerStatus | Select-Object -Property * -ExcludeProperty RunspaceId, PSComputerName
}