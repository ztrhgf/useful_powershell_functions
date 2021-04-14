function Get-CurrentLoad {
    <#
    .SYNOPSIS
        Function for realtime outputting values of basic performance counters (CPU, RAM, GPU, HDD, NETWORK) to console.

	.DESCRIPTION
        Function for realtime outputting values of basic performance counters (CPU, RAM, GPU, HDD, NETWORK) to console.
        On Windows Server OS, you have to enable HDD counter by running "diskperf -Y" first!

	.PARAMETER computerName
	 	Name of the remote computer from which you want to get performance data.

    .PARAMETER includeGPU
        Switch for outputting also GPU counters
        This is little more CPU intense, so not by default included.

    .PARAMETER topProcess
        Changes output just to top 5 processes, that make the most load in specified domain.
        Possible domain values: CPU, GPU, HDD, RAM, NIC.

    .PARAMETER detailed
        Add more detailed counters for given domain.
        Possible values: HDD.

        For HDD it shows Read/Write load on every disk.
        For Tiered Storage queue etc.

    .PARAMETER updateSpeed
        How often to collect the perf. counters
        Default is 1 second.

    .PARAMETER measure
        What to measure.
        By default: CPU, RAM, HDD, NIC

    .PARAMETER captureOutput
        Switch for capturing output to csv file.
        Path to such csv is defined in capturePath parameter.

    .PARAMETER capturePath
        Path to csv file.
        Default is C:\Windows\Temp\hostname_date.csv.

        To show csv content: Import-Csv $capturePath -Delimiter ";"

    .EXAMPLE
        Get-CurrentLoad

        Output load on localhost.

	.EXAMPLE
        Get-CurrentLoad -computername titan01

        Output load on remote computer titan01.

    .EXAMPLE
        Get-CurrentLoad -topProcess CPU

        Output top 5 CPU heavy processes on localhost.

    .EXAMPLE
        Get-CurrentLoad -measure CPU, HDD

        Output CPU and HDD load on localhost.

    .EXAMPLE
        Get-CurrentLoad -measure CPU, HDD -detailed HDD

        Output CPU and HDD load on localhost. Moreover outputs Read/Write load of every disk here.

    .EXAMPLE
        Get-CurrentLoad -captureOutput

        Output load and save it to csv file too (C:\Windows\TEMP\<hostname>_<date>.csv)

	.NOTES
	 	Author: Ondřej Šebela - ztrhgf@seznam.cz
        https://github.com/ztrhgf
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
                    Throw "Enter path like: C:\temp\result.csv"
                }
            })]
        [string] $capturePath = ''
    )

    begin {
        if ($includeGPU) {
            $measure += 'GPU'
        }
    }

    process {
        $param = @{
            ArgumentList = $measure, $topProcess, $updateSpeed, $detailed, $captureOutput, $capturePath, $env:computername
            ScriptBlock  = {
                param ($measure, $topProcess, $updateSpeed, $detailed, $captureOutput, $capturePath, $computerName)

                if ($captureOutput -and !$capturePath) {
                    $capturePath = "$env:windir\TEMP\$env:COMPUTERNAME`_$(Get-Date -f ddMMyyyyHHmms).csv"
                }

                if ($captureOutput -and $env:COMPUTERNAME -ne $computerName) {
                    # run on remote computer i.e. capturing CTRL + C isn't possible i.e. output this information right now
                    $capturePathUNC = "\\$env:COMPUTERNAME\" + ($capturePath -replace ":", "$")
                    Write-Warning "Captured output will be in $capturePathUNC.`nFor import to console use: Import-Csv `"$capturePathUNC`" -Delimiter `";`""
                    Start-Sleep 3
                }

                # name of the counter is language specific!
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
                    throw "this language ($osLanguage) is not supported (just 'en-US' and 'cs-CZ')"
                }

                # set counters
                if ($topProcess) {
                    switch ($topProcess) {
                        'CPU' { $counterList = @("\$process(*)\$percentProcessorTime") } # '\Process(*)\% Processor Time'
                        'RAM' { $counterList = @("\$process(*)\$workingSet") } # '\Process(*)\Working Set'
                        'HDD' { $counterList = @("\$process(*)\$IODataOperationsSec") } # '\Process(*)\IO Data Operations/sec'
                        'NIC' { $counterList = @("\$process(*)\$IODataOperationsSec") } # '\Process(*)\IO Data Operations/sec'
                        'GPU' { $counterList = @("\$GPUEngine(*)\$utilizationPercentage") } # '\GPU Engine(*)\Utilization Percentage'
                        Default { throw "undefined" }
                    }

                    # on Hyper-V server I want for vmwp process the corresponding VM
                    # therefore I find the name in counters and corresponding PID, so I can later pair it
                    $isHyperVServer = (Get-WmiObject -Namespace "root\virtualization\v2" -Query 'select elementname, caption from Msvm_ComputerSystem where caption = "Virtual Machine"' -ErrorAction SilentlyContinue | select ElementName).count # if there are some VM, consider it as Hyper-V server
                    if ($isHyperVServer) {
                        $vmwpPID = (Get-Counter "\$process(*vmwp*)\$IDprocess" -ea SilentlyContinue).CounterSamples
                        $PID2VMName = Get-WmiObject Win32_Process -Filter "Name like '%vmwp%'" -Property processid, commandline | Select-Object ProcessId, @{Label = "VMName"; Expression = { (Get-VM -Id $_.Commandline.split(" ")[1] | Select-Object VMName).VMName } }
                    }
                } else {
                    # list of counter to monitor
                    [System.Collections.ArrayList] $counterList = @()
                    if ('CPU' -in $measure -or 'CPU' -in $detailed) {
                        $null = $counterList.Add("\$processor(*)\$percentProcessorTime") # "\Processor(*)\% Processor Time"
                    }

                    if ('HDD' -in $measure -or 'HDD' -in $detailed) {
                        $null = $counterList.Add("\$physicalDisk(*)\$percentDiskTime") # "\PhysicalDisk(*)\% Disk Time"
                    }

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

                    # counters for network adapter are added per adapter
                    if ('NIC' -in $measure -or 'NIC' -in $detailed) {
                        Get-WmiObject -Class Win32_NetworkAdapter -Property physicalAdapter, netEnabled, speed, name | where { $_.PhysicalAdapter -eq $true -and $_.NetEnabled -eq $true } | select @{n = 'name'; e = { $_.name -replace '\(', '[' -replace '\)', ']' } }, speed | % { # '(' replace for '[', because such are used in counter name
                            $null = $counterList.Add("\$networkInterface($($_.name))\$bytesSentSec") # "\Network Interface(*)\Bytes Sent/sec"
                            $null = $counterList.Add("\$networkInterface($($_.name))\$bytesReceivedSec") # "\Network Interface(*)\Bytes Received/sec"
                        }
                    }

                    if ('GPU' -in $measure) {
                        $null = $counterList.Add("\$gpuEngine(*)\$utilizationPercentage") # '\GPU Engine(*)\Utilization Percentage'
                    }
                }

                # if have just one counter, convert to string because of Get-Counter
                if ($counterList.Count -eq 1) {
                    [string] $counterList = $counterList[0]
                }

                # modify CTRL + C shortcut behaviour, so I can output path to csv file
                if ($captureOutput -and $env:COMPUTERNAME -eq $computerName) {
                    [console]::TreatControlCAsInput = $true
                }

                while (1) {
                    # if output to csv, than after CTRL + C print the csv path to console
                    if ($captureOutput -and $env:COMPUTERNAME -eq $computerName -and [console]::KeyAvailable) {
                        # running locally i.e. capturing CTRL + C will work
                        $key = [system.console]::readkey($true)
                        if (($key.modifiers -band [consolemodifiers]"control") -and ($key.key -eq "C")) {
                            [console]::TreatControlCAsInput = $false
                            Write-Warning "Captured output will be saved in $capturePath.`nTo import it into console: Import-Csv `"$capturePath`" -Delimiter `";`""
                            break
                        }
                    }
                    # get counter results
                    $actualResults = Get-Counter $counterList -ErrorAction SilentlyContinue | Select-Object -ExpandProperty CounterSamples | Group-Object path | % {
                        $_ | Select-Object -Property Name, @{ n = 'Value'; e = { ($_.Group.CookedValue | Measure-Object -Average).Average } }
                    }

                    if (!$actualResults) { throw "there are no results, does the counter: $($CounterList -join ', ') exists on computer: $env:COMPUTERNAME`?" }

                    Clear-Host

                    try {
                        $result = [ordered] @{date = Get-Date }
                    } catch {
                        # older PS version don't support [ordered]
                        $result = @{date = Get-Date }
                    }

                    if ($topProcess) {
                        if ($topProcess -in 'HDD', 'NIC') {
                            "contains !all! types of process IO operations (HDD + NIC + ...)"
                        }

                        $subResult = ''
                        $actualResults | where { $_.name -notlike "*idle*" -and $_.name -notlike "*_total*" -and $_.value -ne 0 } |
                        Sort-Object value -Descending |
                        Select-Object -First 5 |
                        ForEach-Object {
                            $name = ([regex]"\(([^)]+)\)").Matches($_.name).Value
                            $value = [math]::Round($_.value, 2)
                            if ($topProcess -eq 'RAM') {
                                $value = ([math]::Round($_.value / 1MB, 2)).tostring() + ' MB'
                            } elseif ($topProcess -eq 'GPU') {
                                # GPU counter shows process PID, convert it to process name
                                $processId = ([regex]"\(pid_([^_)]+)").Matches($_.name).captures.groups[1].value
                                $processName = Get-WmiObject win32_process -Property name, ProcessId | where { $_.processId -eq $processId } | select -exp name

                                $name = $processName
                            }

                            # show what VM corresponds to vmwp process
                            if ($name -like "*vmwp*" -and $isHyperVServer) {
                                $ppid = $vmwpPid | where { $_.path -like "*$name*" } | select -exp CookedValue
                                $vmName = $pid2VMName | where { $_.processid -eq $ppid } | select -exp vmname
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
                        # output load of CPU, HDD, RAM, ...

                        # GPU load
                        $GPUTotal = 0

                        # if it is not array, convert, to be able to use getenumerator()
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
                                    if ($item.name -like "*_total*") { return }
                                    $dName = ([regex]"\(([^)]+)\)").Matches($_).Value
                                    $name = "DISK Total time $dName %: "
                                    $value = [math]::Round($item.Value, 2)

                                    $name + $value

                                    if ($captureOutput) { $result[$name] = $value }
                                }

                                "*\$percentDiskReadTime" {
                                    if ($item.name -like "*_total*") { return }
                                    $dName = ([regex]"\(([^)]+)\)").Matches($_).Value
                                    $name = "DISK Read time $dName %: "
                                    $value = [math]::Round($item.Value, 2)

                                    $name + $value

                                    if ($captureOutput) { $result[$name] = $value }
                                }

                                "*\$percentDiskWriteTime" {
                                    if ($item.name -like "*_total*") { return }
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
                                    # GPU doesn't have summarizing _total counter, I will sum all received values
                                    $GPUTotal += $item.Value
                                }

                                Default {
                                    #$item.name + ": " + [math]::Round($item.Value / 1MB, 2)
                                    throw "undefined counter"
                                }
                            }
                        } # end of foreach

                        if ($GPUTotal) {
                            $name = "GPU %: "
                            $value = [math]::Round($GPUTotal, 2)

                            $name + $value

                            if ($captureOutput) { $result[$name] = $value }
                        }
                    } # end of else

                    # export results to CSV
                    if ($captureOutput) {
                        New-Object -TypeName PSObject -Property $result | Export-Csv $capturePath -Append -NoTypeInformation -Delimiter ';' -Force -Encoding UTF8
                    }

                    Start-Sleep $updateSpeed
                } # end of while
            }
        }
        if ($computerName -and $computerName -ne $env:computername) {
            $param.ComputerName = $computerName
        }
        Invoke-Command @param
    }
}