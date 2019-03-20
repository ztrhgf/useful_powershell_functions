function Get-CurrentLoad {
    <#
    .SYNOPSIS
        Fce slouží k vypsání aktualniho zatizeni stroje. Konkretne CPU, RAM, GPU, HDD a NIC (sit).
        Vypis se automaticky aktualizuje.

	.DESCRIPTION
	 	Fce slouží k vypsání aktualniho zatizeni stroje. Konkretne CPU, RAM, GPU, HDD a NIC (sit).
        Vypis se automaticky aktualizuje.

        ! Na Server OS je potreba povolit diskove countery prikazem "diskperf –Y" !

	.PARAMETER computerName
	 	Jmeno stroje, na kterem se ma mereni provest.

    .PARAMETER includeGPU
        Prepinac rikajici, ze se ma merit i zatizeni GPU.
        Toto mereni ja trochu narocnejsi na CPU, proto jen na vyzadani.

    .PARAMETER topProcess
        Slouzi k vypsani 5 nejvic zatezujicich procesu pro vybranou oblast mereni.
        Mozne hodnoty jsou: CPU, GPU, HDD, RAM a NIC.

    .PARAMETER detailed
        U kterych oblasti mereni se maji vypsat dalsi/podrobnejsi countery.
        Mozne hodnoty jsou: HDD.
        U disku vypise Read/Write zatizeni jednotlivych disku.
        U Tiered Storage queue atd.

    .PARAMETER updateSpeed
        Po kolika veterinach se maji vysledky obnovovat.
        Vychozi je 1.

    .PARAMETER measure
        Co vse se ma merit. Je mozne neco ubrat kvuli prehlednosti/rychlosti/mensi narocnosti na dany stroj.
        Standardne se meri: CPU, RAM, HDD, NIC

    .PARAMETER captureOutput
        Prepinac rikajici, ze se ma vystup zazanemant do csv souboru.
        Cesta k csv se nastavuje v parametru path.

    .PARAMETER capturePath
        Cesta k csv souboru, do ktereho se maji namerene vysledky ulozit.
        Vychozi je C:\Windows\Temp\hostname_datummereni.csv.

        Pro zobrazeni vysledku lze pouzit prikaz:
        Import-Csv $capturePath -Delimiter ";"

        Pokud merim na lokalnim stroji, tak se po preruseni mereni (CTRL + C) vypise cesta s merenimi.
        Pokud na remote, tak se vypise pred samotnym merenim (neumim jednoduse odchytit CTRL + C)

    .EXAMPLE
        Get-CurrentLoad

        Vypise aktualni zatizeni na tomto stroji.

	.EXAMPLE
        Get-CurrentLoad -computername titan01

        Vypise aktualni zatizeni na stroji titan01.

    .EXAMPLE
        Get-CurrentLoad -topProcess CPU

        Vypise 5 procesu, ktere nejvic zatezuji CPU na tomto stroji.

    .EXAMPLE
        Get-CurrentLoad -measure CPU, HDD

        Vypise aktualni zatizeni CPU a HDD na tomto stroji.

    .EXAMPLE
        Get-CurrentLoad -measure CPU, HDD -detailed HDD

        Vypise aktualni zatizeni CPU a HDD na tomto stroji. Navic zobrazi i Read a Write zatizeni jednotlivych disku.

    .EXAMPLE
        Get-CurrentLoad -captureOutput

        Vypise aktualni zatizeni a navic vysledky ulozi do C:\Windows\TEMP\<jmenostroje>_<datummereni>.csv na stroji, kde probiha mereni.

        Pro jejich zobrazeni lze pouzit prikaz: Import-Csv C:\Windows\TEMP\<jmenostroje>_<datummereni>.csv -Delimiter ";"

	.NOTES
	 	Author: Ondřej Šebela - ztrhgf@seznam.cz
    #>

    [cmdletbinding()]
    [Alias("top")]
    param (
        [string] $computerName = $env:COMPUTERNAME
        ,
        [switch] $includeGPU
        ,
        [ValidateSet('CPU', 'RAM', 'HDD', 'NIC', 'GPU')]
        [string] $topProcess
        ,
        [ValidateSet('HDD')]
        [string] $detailed
        ,
        [ValidateSet('CPU', 'RAM', 'HDD', 'NIC', 'GPU')]
        [string[]] $measure = ('CPU', 'RAM', 'HDD', 'NIC')
        ,
        [int] $updateSpeed = 1
        ,
        [switch] $captureOutput
        ,
        [ValidateScript( {
                If ($_ -match '\.csv$' -and (Test-Path $_ -IsValid) -and (Split-Path $_ -Qualifier)) {
                    $true
                } else {
                    Throw "Zadejte cestu ve tvaru C:\temp\vysledky.csv."
                }
            })]
        [string] $capturePath = ''
    )

    begin {
        try {
            $null = Get-Command Invoke-Command2 -ea stop
        } catch {
            throw "Pro beh je potreba funkce Invoke-Command2"
        }

        if ($includeGPU) {
            # counter celkem zatezuje CPU, proto jen na vyzadani
            $measure += 'GPU'
        }
    }

    process {
        Invoke-Command2 -computerName $computerName -argumentList $measure, $topProcess, $updateSpeed, $detailed, $captureOutput, $capturePath, $env:computername {
            param ($measure, $topProcess, $updateSpeed, $detailed, $captureOutput, $capturePath, $computerName)

            if ($captureOutput -and !$capturePath) {
                $capturePath = "$env:windir\TEMP\$env:COMPUTERNAME`_$(Get-Date -f ddMMyyyyHHmms).csv"
            }

            if ($captureOutput -and $env:COMPUTERNAME -ne $computerName) {
                # nespoustim na localhostu == nebude fungovat odchyceni CTRL + C == vypisi info hned
                $capturePathUNC = "\\$env:COMPUTERNAME\" + ($capturePath -replace ":", "$")
                Write-Warning "Zachyceny vystup najdete v $capturePathUNC.`nPro zobrazeni pouzijte: Import-Csv `"$capturePathUNC`" -Delimiter `";`""
                Start-Sleep 3
            }

            # jmeno counteru musi byt dle jazyku OS
            # chtel jsem pro dynamicke zjisteni lokalizovaneho jmena counteru pouzit funkcihttp://www.powershellmagazine.com/2013/07/19/querying-performance-counters-from-powershell/ ale bylo to nespolehlive, napr u 'Bytes Sent/sec' to vratilo jine ID na ceskem a jine na anglickem OS
            $osLanguage = (Get-WmiObject -Class Win32_OperatingSystem -Property MUILanguages).MUILanguages
            if ($osLanguage -eq 'en-US') {
                $sent = 'sent'
                $process = 'Process'
                $IDprocess = 'ID Process'
                $percentProcessorTime = '% Processor Time'
                $workingSet = 'Working Set'
                $IODataOperationsSec = 'IO Data Operations/sec'
                $GPUEngine = 'GPU Engine'
                $utilizationPercentage = 'Utilization Percentage'
                $processor = 'Processor'
                $physicalDisk = 'PhysicalDisk'
                $percentDiskTime = '% Disk Time'
                $percentDiskReadTime = '% Disk Read Time'
                $percentDiskWriteTime = '% Disk Write Time'
                $memory = 'Memory'
                $availableMBytes = 'Available MBytes'
                $networkInterface = 'Network Interface'
                $bytesSentSec = 'Bytes Sent/sec'
                $bytesReceivedSec = 'Bytes Received/sec'
            } elseif ($osLanguage -eq 'cs-CZ') {
                $sent = 'odeslané'
                $process = 'Proces'
                $IDprocess = 'ID procesu'
                $percentProcessorTime = '% času procesoru'
                $workingSet = 'pracovní sada'
                $IODataOperationsSec = 'Vstupně-výstupní datové operace/s'
                $GPUEngine = 'GPU engine'
                $utilizationPercentage = 'Utilization Percentage'
                $processor = 'Procesor'
                $physicalDisk = 'Fyzický disk'
                $percentDiskTime = '% času disku'
                #TODO pridat detailed diskove countery
                $percentDiskReadTime = 'TODO'
                $percentDiskWriteTime = 'TODO'
                $memory = 'Paměť'
                $availableMBytes = 'počet MB k dispozici'
                $networkInterface = 'Rozhraní sítě'
                $bytesSentSec = 'Bajty odeslané/s'
                $bytesReceivedSec = 'Bajty přijaté/s'
            } else {
                throw "pro tento jazyk ($osLanguage) nejsou nastaveny lokalizovana jmena counteru"
            }

            # nastavim countery, ktere budu merit
            if ($topProcess) {
                switch ($topProcess) {
                    'CPU' { $counterList = @("\$process(*)\$percentProcessorTime") } # '\Process(*)\% Processor Time'
                    'RAM' { $counterList = @("\$process(*)\$workingSet") } # '\Process(*)\Working Set'
                    'HDD' { $counterList = @("\$process(*)\$IODataOperationsSec") } # '\Process(*)\IO Data Operations/sec'
                    'NIC' { $counterList = @("\$process(*)\$IODataOperationsSec")} # '\Process(*)\IO Data Operations/sec'
                    'GPU' { $counterList = @("\$GPUEngine(*)\$utilizationPercentage") } # '\GPU Engine(*)\Utilization Percentage'
                    Default { throw "nedefinovano" }
                }

                # na Hyper-V serveru chci u procesu vmwp vypsat, k jakemu VM patri
                # proto zjistim jmeno, ktere se pouziva v counterech a odpovidajici PID, abych umel pozdeji sparovat se zatezujicim procesem
                $isHyperVServer = (Get-WmiObject -Namespace "root\virtualization\v2" -Query 'select elementname, caption from Msvm_ComputerSystem where caption = "Virtual Machine"' -ErrorAction SilentlyContinue | select ElementName).count # pokud na nem bezi nejake virtualy, povazuji jej za Hyper-V server
                if ($isHyperVServer) {
                    $vmwpPID = (Get-Counter "\$process(*vmwp*)\$IDprocess" -ea SilentlyContinue).CounterSamples
                    $PID2VMName = Get-WmiObject Win32_Process -Filter "Name like '%vmwp%'" -property processid, commandline | Select-Object ProcessId, @{Label = "VMName"; Expression = {(Get-VM -Id $_.Commandline.split(" ")[1] | Select-Object VMName).VMName}}
                }
            } else {
                # vytvorim seznam counteru, ktere budu sledovat
                [System.Collections.ArrayList] $counterList = @()
                # countery pridam postupne kvuli specifickemu poradi
                if ('CPU' -in $measure -or 'CPU' -in $detailed) {
                    $null = $counterList.Add("\$processor(*)\$percentProcessorTime") # "\Processor(*)\% Processor Time"
                }

                if ('HDD' -in $measure -or 'HDD' -in $detailed) {
                    $null = $counterList.Add("\$physicalDisk(*)\$percentDiskTime") # "\PhysicalDisk(*)\% Disk Time"
                }

                # pridam extra countery pro Read a Write u jednotlivych disku
                if ('HDD' -in $detailed) {
                    $null = $counterList.Add("\$physicalDisk(*)\$percentDiskReadTime")
                    $null = $counterList.Add("\$physicalDisk(*)\$percentDiskWriteTime")
                    #TODO pridat i TIERED STORAGE countery POKUD EXISTUJI
                    #TODO pridat i queue
                }

                if ('RAM' -in $measure -or 'RAM' -in $detailed) {
                    $null = $counterList.Add("\$memory\$availableMBytes") # , "\Memory\Available MBytes"
                    $physicalRAMMB = ((Get-WmiObject -Class Win32_OperatingSystem -Property TotalVisibleMemorySize).TotalVisibleMemorySize / 1kb)
                }

                # countery pro sitova rozhrani pridavam per NIC
                if ('NIC' -in $measure -or 'NIC' -in $detailed) {
                    Get-WmiObject -Class Win32_NetworkAdapter -Property physicalAdapter, netEnabled, speed, name | where {$_.PhysicalAdapter -eq $true -and $_.NetEnabled -eq $true} | select @{n = 'name'; e = {$_.name -replace '\(', '[' -replace '\)', ']'}}, speed | % { # kulate zavorky nahrazuji za hranate, protoze v takovem tvaru je nazev v perf counteru
                        $null = $counterList.Add("\$networkInterface($($_.name))\$bytesSentSec") # "\Network Interface(*)\Bytes Sent/sec"
                        $null = $counterList.Add("\$networkInterface($($_.name))\$bytesReceivedSec") # "\Network Interface(*)\Bytes Received/sec"
                    }
                }

                if ('GPU' -in $measure) {
                    $null = $counterList.Add("\$gpuEngine(*)\$utilizationPercentage") # '\GPU Engine(*)\Utilization Percentage'
                }
            }

            # pokud predavam jen 1 counter, musim prevest na string kvuli Get-Counter
            if ($counterList.Count -eq 1) {
                [string] $counterList = $counterList[0]
            }

            # abych mohl po ukonceni mereni stickem CTRL+C vypsat jeste cestu k souboru s merenimi, musim upravit chovani teto zkratky
            if ($captureOutput -and $env:COMPUTERNAME -eq $computerName) {
                [console]::TreatControlCAsInput = $true
            }

            while (1) {
                # pokud se vystup mereni uklada do souboru, tak pri ukonceni skriptu zkratkou CTRL + C vypisi cestu k tomuto souboru
                if ($captureOutput -and $env:COMPUTERNAME -eq $computerName -and [console]::KeyAvailable) {
                    # spoustim na localhostu == bude fungovat odchyceni CTRL + C
                    $key = [system.console]::readkey($true)
                    if (($key.modifiers -band [consolemodifiers]"control") -and ($key.key -eq "C")) {
                        [console]::TreatControlCAsInput = $false
                        Write-Warning "Zachyceny vystup najdete v $capturePath.`nPro zobrazeni pouzijte: Import-Csv `"$capturePath`" -Delimiter `";`""
                        break
                    }
                }
                # ziskam vysledky pozadovanych perf. counteru
                $actualResults = Get-Counter $counterList -ErrorAction SilentlyContinue | Select-Object -ExpandProperty CounterSamples | Group-Object path | % {
                    $_ | Select-Object -Property Name, @{ n = 'Value'; e = { ($_.Group.CookedValue | Measure-Object -Average).Average }}
                }

                if (!$actualResults) { throw "Nejsou zadne vysledky mereni, existuji countery: $($CounterList -join ', ') na stroji: $env:COMPUTERNAME?" }

                Clear-Host

                # do result ulozim vysledky mereni kvuli exportu do csv
                try {
                    $result = [ordered] @{date = Get-Date}
                } catch {
                    # starsi PS verze neumi [ordered]
                    $result = @{date = Get-Date}
                }

                if ($topProcess) {
                    # upozornim, ze zobrazuji celkove IO zatizeni danymi procesy, ne pouze HDD ci NIC
                    if ($topProcess -in 'HDD', 'NIC') {
                        "zobrazeny !vsechny! typy IO operaci procesu (HDD + NIC + ...)"
                    }

                    # vypisi jen nejvic zatezujici procesy
                    $subResult = ''
                    $actualResults | where {$_.name -notlike "*idle*" -and $_.name -notlike "*_total*" -and $_.value -ne 0} |
                        Sort-Object value -Descending |
                        Select-Object -First 5 |
                        ForEach-Object {
                        $name = ([regex]"\(([^)]+)\)").Matches($_.name).Value
                        $value = [math]::Round($_.value, 2)
                        if ($topProcess -eq 'RAM') {
                            $value = ([math]::Round($_.value / 1MB, 2)).tostring() + ' MB'
                        } elseif ($topProcess -eq 'GPU') {
                            # GPU counter zobrazuje PID procesu,, prevedu na jmeno
                            $processId = ([regex]"\(pid_([^_)]+)").Matches($_.name).captures.groups[1].value
                            $processName = Get-WmiObject win32_process -Property name, ProcessId | where {$_.processId -eq $processId} | select -exp name

                            $name = $processName
                        }

                        # vypisi i jaky virtual reprezentuje proces vmwp
                        if ($name -like "*vmwp*" -and $isHyperVServer) {
                            $ppid = $vmwpPid | where {$_.path -like "*$name*"} | select -exp CookedValue
                            $vmName = $pid2VMName | where {$_.processid -eq $ppid} | select -exp vmname
                            $name = "$name (VM: $vmName)"
                        }

                        $name = $name -replace '\(|\)'

                        "{0}: {1}" -f $name, $value

                        if ($captureOutput) {
                            if ($subResult) { $subResult += ", " }
                            $subResult += $name, "$value%" -join ' '
                        }
                    }

                    if ($captureOutput) { $result['topProcess'] = $subResult }
                } else {
                    # vypisi celkove zatizeni CPU, HDD, RAM, ...

                    # zde si ulozim zatizeni GPU
                    $GPUTotal = 0

                    # pokud nejde o pole objektu, prevedu, abych mohl pouzit getenumerator()
                    if ($actualResults.GetType().basetype.name -ne 'Array') {
                        $actualResults = @(, $actualResults)
                    }

                    $actualResults.GetEnumerator() | % {
                        $item = $_
                        switch -Wildcard ($_.name) {
                            "*\$percentProcessorTime" {
                                $core = ([regex]"\(([^)]+)\)").Matches($_).Value
                                $name = "CPU $core %: "
                                $value = [math]::Round($item.Value, 2)

                                $name + $value

                                if ($captureOutput) { $result[$name] = $value }
                            }

                            "*\$availableMBytes" {
                                $name = "RAM used %: "
                                $value = [math]::Round((($physicalRAMMB - $item.Value) / ($physicalRAMMB / 100)), 2)

                                $name + $value

                                if ($captureOutput) { $result[$name] = $value }
                            }

                            "*\$percentDiskTime" {
                                if ($item.name -like "*_total*") {return}
                                $dName = ([regex]"\(([^)]+)\)").Matches($_).Value
                                $name = "DISK Total time $dName %: "
                                $value = [math]::Round($item.Value, 2)

                                $name + $value

                                if ($captureOutput) { $result[$name] = $value }
                            }

                            "*\$percentDiskReadTime" {
                                if ($item.name -like "*_total*") {return}
                                $dName = ([regex]"\(([^)]+)\)").Matches($_).Value
                                $name = "DISK Read time $dName %: "
                                $value = [math]::Round($item.Value, 2)

                                $name + $value

                                if ($captureOutput) { $result[$name] = $value }
                            }

                            "*\$percentDiskWriteTime" {
                                if ($item.name -like "*_total*") {return}
                                $dName = ([regex]"\(([^)]+)\)").Matches($_).Value
                                $name = "DISK Write time $dName %: "
                                $value = [math]::Round($item.Value, 2)

                                $name + $value

                                if ($captureOutput) { $result[$name] = $value }
                            }

                            "*\$networkInterface*" {
                                $nName = ([regex]"\(([^)]+)\)").Matches($_).Value

                                if ($item.name -like "*$sent*") {
                                    $action = 'sent'
                                } else {
                                    $action = 'received'
                                }

                                $name = "NIC $nName $action MB: "
                                $value = [math]::Round($item.Value / 1MB, 2)

                                $name + $value

                                if ($captureOutput) { $result[$name] = $value }
                            }

                            "*$GPUEngine*" {
                                # GPU nema zadny souhrny _total counter, sectu vsechny hodnoty a vypisi po ukonceni foreach loopu
                                $GPUTotal += $item.Value
                            }

                            Default {
                                #$item.name + ": " + [math]::Round($item.Value / 1MB, 2)
                                throw "nedefinovany counter"
                            }
                        }
                    } # konec foreach projiti ziskanych vysledku

                    if ($GPUTotal) {
                        $name = "GPU %: "
                        $value = [math]::Round($GPUTotal, 2)

                        $name + $value

                        if ($captureOutput) { $result[$name] = $value }
                    }
                } # konec else pro vypsani celkove zateze

                # vyexportovani vysledku do CSV
                if ($captureOutput) {
                    New-Object -TypeName PSObject -Property $result | Export-Csv $capturePath -Append -NoTypeInformation -Delimiter ';' -Force -Encoding UTF8
                }

                Start-Sleep $updateSpeed
            } # konec while
        } # konec Invoke-Command2
    } # konec process
}