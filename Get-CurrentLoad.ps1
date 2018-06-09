#TODO dodelat detailed switch ktery vypise i nejvic zatezujici procesy + zprumerovanou hodnotu ze vsech probehlych mereni?
function Get-CurrentLoad {
    <#
    .SYNOPSIS
        Fce slouží k vypsání aktualniho zatizeni stroje. Konkretne CPU, RAM, GPU, disky a sit.
        Vypis se automaticky aktualizuje. 	
	 
	.DESCRIPTION
	 	Fce slouží k vypsání aktualniho zatizeni stroje. Konkretne CPU, RAM, GPU, disky a sit.	
        Vypis se automaticky aktualizuje. 	
         
	.PARAMETER computerName
	 	Jmeno stroje, na kterem se ma mereni provest.
	
    .PARAMETER includeGPU
        Prepinac rikajici, ze se ma merit i zatizeni GPU.
        Toto mereni ja trochu narocnejsi na CPU, proto na vyzadani.

    .PARAMETER detailed
        Slouzi k vypsani 5 nejvic zatezujicich procesu pro vybranou oblast.
        Mozne hodnoty jsou CPU, GPU, HDD, RAM a NIC.

    .PARAMETER updateSpeed
        Po kolika veterinach se maji vysledky obnovovat.
        Vychozi je 1.

    .EXAMPLE
        Get-ActualPerformance

        Bude vypisovat aktualni zatizeni na tomto stroji.

	.EXAMPLE
        Get-ActualPerformance -computername titan01

        Bude vypisovat aktualni zatizeni na stroji titan01.

    .EXAMPLE
        Get-ActualPerformance -detailed CPU

        Bude vypisovat 5 procesu, ktere nejvic zatezuji CPU na tomto stroji.
    
	.NOTES  
	 	Author: Ondřej Šebela - ztrhgf@seznam.cz
    #>

    [cmdletbinding()]
    param (
        [string] $computerName = $env:COMPUTERNAME
        ,
        [switch] $includeGPU
        ,
        [ValidateSet('CPU', 'RAM', 'HDD', 'NIC', 'GPU')]        
        [string] $detailed
        ,
        [int] $updateSpeed = 1
    )

    begin {
        try {
            $null = Get-Command Invoke-Command2 -ea stop
        } catch {
            throw "Pro beh je potreba funkce Invoke-Command2"
        }

        
    }

    process {
        Invoke-Command2 -computerName $computerName -argumentList $includeGPU, $detailed, $updateSpeed {
            param ($includeGPU, $detailed, $updateSpeed)

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
                $memory = 'Paměť'
                $availableMBytes = 'počet MB k dispozici' 
                $networkInterface = 'Rozhraní sítě'
                $bytesSentSec = 'Bajty odeslané/s'
                $bytesReceivedSec = 'Bajty přijaté/s'
            } else {
                throw "pro tento jazyk ($osLanguage) nejsou nastaveny lokalizovana jmena counteru"
            }
           
            # nastavim countery, ktere budu merit
            if ($detailed) {
                switch ($detailed) {
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
                [System.Collections.ArrayList] $counterList = @("\$processor(*)\$percentProcessorTime", "\$physicalDisk(*)\$percentDiskTime", "\$memory\$availableMBytes") # "\Processor(*)\% Processor Time", "\PhysicalDisk(*)\% Disk Time", "\Memory\Available MBytes"

                Get-WmiObject -Class Win32_NetworkAdapter -Property physicalAdapter, netEnabled, speed, name | where {$_.PhysicalAdapter -eq $true -and $_.NetEnabled -eq $true} | select name, speed | % {
                    $null = $counterList.Add("\$networkInterface($($_.name))\$bytesSentSec") # "\Network Interface(*)\Bytes Sent/sec"
                    $null = $counterList.Add("\$networkInterface($($_.name))\$bytesReceivedSec") # "\Network Interface(*)\Bytes Received/sec"
                }
    
                if ($includeGPU) {
                    # counter celkem zatezuje CPU, proto jen na vyzadani
                    $null = $counterList.Add("\$gpuEngine(*)\$utilizationPercentage") # '\GPU Engine(*)\Utilization Percentage'
                }

                $physicalRAMMB = ((Get-WmiObject -Class Win32_OperatingSystem -Property TotalVisibleMemorySize).TotalVisibleMemorySize / 1kb)
            }

            # pokud predavam jen 1 counter, musim prevest na string
            if ($counterList.Count -eq 1) {
                $counterList = $counterList[0]
            }

            while (1) {
                $actualResults = Get-Counter $counterList -ErrorAction SilentlyContinue | Select-Object -ExpandProperty CounterSamples | Group-Object path | % {
                    $_ | Select-Object -Property Name, @{ n = 'Value'; e = { ($_.Group.CookedValue | Measure-Object -Average).Average }} 
                }

                if (!$actualResults) { throw "Nejsou zadne vysledky mereni, existuji countery: $($CounterList -join ', ') na stroji: $env:COMPUTERNAME?" }

                Clear-Host

                if ($detailed) {
                    # upozornim, ze zobrazuji celkove IO zatizeni danymi procesy, ne pouze HDD ci NIC
                    if ($detailed -in 'HDD', 'NIC') {
                        "zobrazeny !vsechny! typy IO operaci procesu (HDD + NIC + ...)"                            
                    }
                    
                    # vypisi jen nejvic zatezujici procesy
                    $actualResults | where {$_.name -notlike "*idle*" -and $_.name -notlike "*_total*" -and $_.value -ne 0} | 
                        Sort-Object value -Descending | 
                        Select-Object -First 5 | 
                        ForEach-Object {
                        $name = ([regex]"\(([^)]+)\)").Matches($_.name).Value
                        $value = [math]::Round($_.value, 2)
                        if ($detailed -eq 'RAM') {
                            $value = ([math]::Round($_.value / 1MB, 2)).tostring() + ' MB'
                        } elseif ($detailed -eq 'GPU') {
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
                        
                        "{0}: {1}" -f $name, $value                         
                    }
                } else {
                    # vypisi celkove zatizeni CPU, HDD, RAM, ...
                    $GPUTotal = 0

                    $actualResults.GetEnumerator() | % {
                        $item = $_
                        switch -Wildcard ($_.name) {
                            "*\$percentProcessorTime" {
                                $core = ([regex]"\(([^)]+)\)").Matches($_).Value
                                "CPU $core %: " + [math]::Round($item.Value, 2)
                            }

                            "*\$availableMBytes" {
                                "RAM used %: " + [math]::Round((($physicalRAMMB - $item.Value) / ($physicalRAMMB / 100)), 2)
                            }

                            "*\$percentDiskTime" {
                                if ($item.name -like "*_total*") {return}
                                $name = ([regex]"\(([^)]+)\)").Matches($_).Value
                                "DISK time $name %: " + [math]::Round($item.Value, 2)
                            }

                            "*\$networkInterface*" {
                                $name = ([regex]"\(([^)]+)\)").Matches($_).Value
                                
                                if ($item.name -like "*$sent*") {
                                    $action = 'sent'
                                } else {
                                    $action = 'received'
                                }

                                "NIC $name $action MB: " + [math]::Round($item.Value / 1MB, 2)
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
                        "GPU %: " + [math]::Round($GPUTotal, 2)
                    }
                }

                Start-Sleep $updateSpeed
            } # konec while
        } # konec Invoke-Command2
    } # konec process
}

Set-Alias top Get-CurrentLoad # obdoba linux prikazu top (a iotop)