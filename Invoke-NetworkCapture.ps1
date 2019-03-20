function Invoke-NetworkCapture {
    <#
    .SYNOPSIS
    Funkce slouzi k zachyceni sitove komunikace na zadanem stroji.
    Vystupem je etl soubor, ktery je mozne otevrit napr v Message Analyzer aplikaci.
    Pokud to jde, pouzije Powershell prikazy pro capture, pokud ne tak CMD obdobu tzn. netsh trace start capture.

    .DESCRIPTION
    Funkce slouzi k zachyceni sitove komunikace na zadanem stroji.
    Vystupem je etl soubor, ktery je mozne otevrit napr v Message Analyzer aplikaci.
    Pokud to jde, pouzije Powershell prikazy pro capture, pokud ne tak CMD obdobu tzn. netsh trace start capture.

    .PARAMETER computerName
    Jmeno stroje na kterem se ma provest.

    .PARAMETER runTimeMinutes
    Jak dlouho ma capture bezet.

    .PARAMETER outputFolder
    Kam se ma capture ulozit.

    Vychozi je "C:\temp".

    .PARAMETER ipAddress
    Filtrovani dle IP adres.

    .PARAMETER ipProtocol
    Filtrovani dle protokolu.

    .PARAMETER maxFileSizeMB
    Maximalni velikost capture souboru.

    Vychozi je 1GB

    .EXAMPLE
    Invoke-NetworkCapture

    Spusti zachytavani veskere sitove komunikace po dobu 5 minut na tomto stroji do "C:\temp".

    .EXAMPLE
    Invoke-NetworkCapture -computerName titan01 -runTimeMinutes 1

    Spusti zachytavani veskere sitove komunikace po dobu 1 minut na stroji titan01. Vysledne mereni se ulozi do "C:\temp" na tomto stroji.
    #>

    [cmdletbinding()]
    [Alias("Get-NetworkCapture", "Save-NetworkCapture")]
    param (
        $computerName = $env:computername
        ,
        [int] $runTimeMinutes = 5
        ,
        [string] $outputFolder = "C:\temp"
        # ,
        # [UInt16[]] $TCPPorts
        # ,
        # [UInt16[]] $UDPPorts
        ,
        [string[]] $ipAddress
        ,
        [ValidateSet(4, 6)]
        [int] $ipProtocol
        ,
        [int] $maxFileSizeMB = 1000
    )

    begin {
        if ($computerName -contains $env:computername -and ! ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
            Throw "Skript je potreba spusti s admin pravy"
        }

        if (!(Test-Path $outputFolder -ErrorAction SilentlyContinue)) {
            throw "Umisteni $outputFolder, kam se maji ukladat zachycene udaje neexistuje"
        }
    }

    process {
        Write-Output "Nyni pobezi $runTimeMinutes minut zachytavani sitove komunikace na $($computerName -join ', ')"

        $captures = Invoke-Command2 -ComputerName $computerName {
            param (
                $maxFileSizeMB
                ,
                $runTimeMinutes
                ,
                $ipAddress
                ,
                $ipProtocol
                ,
                $localhost
                ,
                $outputFolder
                ,
                $verbose
                # ,
                # [UInt16[]] $TCPPorts
                # ,
                # [UInt16[]] $UDPPorts
            )

            $VerbosePreference = $verbose
            $sessName = "capture_" + "$(Get-Random)"
            $fileName = "_$env:COMPUTERNAME`_$(get-date -f ddmmyyyyhhmm).etl"

            if ($env:COMPUTERNAME -eq $localhost) {
                # capture delam na localhostu (ne remote hostu) == etl ulozim rovnou do cilove slozky
                $etlFile = Join-Path $outputFolder $fileName
            } else {
                # capture delam na nejakem remote stroji
                $etlFile = "$env:windir\TEMP\$fileName"
            }

            $oldPC = !(Get-Command Start-NetEventSession -ErrorAction SilentlyContinue)


            if ($oldPC) {
                # nejsou dostupne PS cmdlety pro capture == pouziji netsh trace
                Write-Warning "Na stroji $env:COMPUTERNAME je stara Powershell verze. Pro zachyceni sitove komunikace pouziji CMD prikaz netsh trace start"
                try {
                    if ($ipAddress) {
                        $params = "ipv4.address=$($ipAddress -join',')"
                    }
                    if ($ipProtocol) {
                        Write-Warning "Protoze se nepouziji nativni Powershell cmdlety, nelze provest filtrovani dle protokolu"
                    }

                    $runningSession = netsh trace show status
                    if ($runningSession -and $runningSession -match "Status:\s+Running") {
                        throw "Na $env:COMPUTERNAME jiz existuje aktivni merici session.`n`n$runningSession`n`n Je potreba pockat na ukonceni nebo ukoncit prikazem: netsh trace stop"
                    } elseif ($runningSession -and $runningSession -match "Status:\s+") {
                        $null = netsh trace stop
                        Write-Warning "Na $env:COMPUTERNAME existovala neaktivni merici session. Ukoncil jsem ji, abych mohl pokracovat"
                    }

                    Write-Verbose "Spoustim session $sessName"
                    $null = netsh trace start capture=yes report=yes tracefile=$etlFile maxsize=$maxFileSizeMB correlation=yes $params

                    Start-Sleep -Seconds ($runTimeMinutes * 60)

                    # zastaveni capture
                    $null = netsh trace stop
                } catch {
                    throw "Na $env:COMPUTERNAME capture skoncil chybou:`n$_"
                    $null = netsh trace stop
                }
            } else {
                # jsou dostupne PS cmdlety pro capture
                try {
                    # invoke-command musi vratit jen cestu k etl souboru, proto vse zacina $null = ...
                    $ErrorActionPreference = "stop"

                    #TODO dodelat podporu pro starsi OS (netsh trace start)
                    #C:\Windows\system32>netsh trace start capture=yes report=yes maxsize=1024 correlation=yes tracefile=test.etl
                    #if ((Get-Command Get-NetEventSession -ErrorAction SilentlyContinue).module.name) {}
                    # zaroven muze bezet jen jedno mereni
                    # neaktivni ukoncim, na bezici upozornim
                    $runningSession = Get-NetEventSession
                    if ($runningSession -and $runningSession.SessionStatus -eq 'NotRunning') {
                        $null = Remove-NetEventSession -Name ($runningSession.name)
                        Write-Warning "Na $env:COMPUTERNAME existovala neaktivni merici session. Ukoncil jsem ji, abych mohl pokracovat"
                    } elseif ($runningSession) {
                        throw "Na $env:COMPUTERNAME jiz existuje merici session $($runningSession.name) (ve stavu: $($runningSession.SessionStatus)). Je potreba pockat na ukonceni nebo ukoncit prikazem: Stop-NetEventSession; Remove-NetEventSession"
                    }

                    Write-Verbose "Spoustim session $sessName"
                    $null = New-NetEventSession -Name $sessName -CaptureMode SaveToFile -LocalFilePath $etlFile -MaxFileSize $maxFileSizeMB # MaxFileSize je v MB (pri prekroceni se stare nahradi novymi)
                    if (!(Get-NetEventSession -Name $sessName)) {
                        throw "Nepodarilo se vytvorit monitorovaci session"
                    }

                    $null = Add-NetEventProvider -Name "Microsoft-Windows-TCPIP" -SessionName $sessName
                    # zachytim i SMB
                    $null = Add-NetEventProvider -Name 'Microsoft-Windows-SMBClient' -SessionName $sessName

                    #TODO zakomentovana cast to vzdy rozbije..bug??
                    # $null = Add-NetEventWFPCaptureProvider -SessionName $sessName
                    # if ($TCPPorts) {
                    #     #TODO filtrovani podle portu nefunguje !
                    #     $null = Set-NetEventWFPCaptureProvider -SessionName $sessName -TCPPorts $TCPPorts
                    # }
                    # if ($UDPPorts) {
                    #     #TODO filtrovani podle portu nefunguje !
                    #     $null = Set-NetEventWFPCaptureProvider -SessionName $sessName -UDPPorts $UDPPorts
                    # }

                    $null = Add-NetEventPacketCaptureProvider -SessionName $sessName
                    if ($ipAddress) {
                        $null = Set-NetEventPacketCaptureProvider -SessionName $sessName -IpAddresses $ipAddress
                    }
                    if ($ipProtocol) {
                        $null = Set-NetEventPacketCaptureProvider -SessionName $sessName -IpProtocols $ipProtocol
                    }

                    $null = Start-NetEventSession -Name $sessName

                    Start-Sleep -Seconds ($runTimeMinutes * 60)

                    # zastaveni capture
                    $null = Stop-NetEventSession -Name $sessName
                    $null = Remove-NetEventSession -Name $sessName
                } catch {
                    $null = Stop-NetEventSession -Name $sessName -ErrorAction SilentlyContinue
                    $null = Remove-NetEventSession -Name $sessName -ErrorAction SilentlyContinue
                    throw "Na $env:COMPUTERNAME capture skoncil chybou:`n$_"
                }
            }

            return $etlFile
        } -ArgumentList $maxFileSizeMB, $runTimeMinutes, $ipAddress, $ipProtocol, $localhost, $outputFolder, $VerbosePreference #, $TCPPorts, $UDPPorts
    }

    end {
        if ($captures) {
            Write-Output "Do $outputFolder se nyni nakopiruji etl soubory obsahujici zachycenou sitovou komunikaci.`n`t- etl se daji otevrit v aplikaci 'Message Analyzer'.`n"

            # ze stroju zkopiruji zachyceny sitovy provoz
            foreach ($etlFile in $captures) {
                if ($etlFile -match $env:COMPUTERNAME) {
                    # lokalne udelany capture rovnou kladam do ciloveho umisteni == netreba nic delat
                    continue
                }

                # zkopiruji capture z remote stroje
                $remoteMachine = ([regex]"\\_(\w+)_").Matches($etlFile).captures.groups[1].value
                # zmenim cestu na pouziti admin share
                $etlFile = $etlFile -replace ':', '$'
                try {
                    Write-Output "Kopiruji $(Split-Path $etlFile -Leaf)"
                    Copy-Item "\\$remoteMachine\$etlFile" $outputFolder -ErrorAction Stop
                } catch {
                    Write-Error "Zkopirovani se nezdarilo:`n$_"
                }

                # smazu jiz nepotrebny etl soubor z remote stroje
                try {
                    Remove-Item "\\$remoteMachine\$etlFile" -Force -ErrorAction Stop
                } catch {
                    Write-Error "Nepodarilo se z $remoteMachine smazat jiz nepotrebny $etlFile"
                }
            }
        } else {
            Write-Warning "Nepodarilo se ziskat zadne etl soubory"
        }
    }
}