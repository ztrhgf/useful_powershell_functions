function Get-ReliabilityHistory {
    <#
    .SYNOPSIS
    Vypise stroje ze seznamu, ktere maji prumerny index spolehlivosti nizsi nez zadany. 
    Prumer se pocita za poslednich X dnu (kde X je hodnota daysOld)
    Zaroven i vysledek ulozi jako csv soubor.
    
    .DESCRIPTION
    Vypise stroje ze seznamu, ktere maji prumerny index spolehlivosti nizsi nez zadany. 
    Prumer se pocita za poslednich X dnu (kde X je hodnota daysOld).
    Ziskava udaje z nastroje reliability history dostupneho ze start menu.
    Vypise i prumerne hodnoty za kazdy den.
    Zaroven i vysledek ulozi jako csv soubor.

    .PARAMETER computerName
    Seznam stroju, ktere se maji zkontrolovat.
    
    .PARAMETER stabilityIndexUnder
    Stroje s nizsim prumernym indexem stability budou vypsany.
    Vychozi je hodnota 5 (z 10).
    
    .PARAMETER daysOld
    Pocet dnu, za ktere se maji posbirat data o spolehlivosti.
    Vychozi je 7.

    .PARAMETER exportCSV
    Prepinac, zdali se ma vyexportovat podrobna historie reliability systemu.

    .PARAMETER CSVPath
    Cesta k CSV souboru, do ktereho se budou exportovat podrobne vysledky.
    Vychozi je $env:TEMP\ErrorRecords.csv.

    .PARAMETER sendEmail
    Prepinac, zdali se ma poslat info i emailem.
    Posle se vcetne CSV s podrobnymi zaznamy o reliability systemu v priloze.
    
    .PARAMETER to
    Komu se ma email poslat. 
    Vychozi je aaa@bbb.cz.
    
    .PARAMETER returnObject
    Vystup se nenaformatuje pomoci Format-Table. Tzn potreba, pokud se ma s vystupem dale pracovat.
    Vystup standardne formatuji, aby byl prehledny.
    
    .EXAMPLE
    Get-ReliabilityHistory -computerName nox, demeter -stabilityIndexUnder 5 -sendEmail -to sebela@fi.muni.cz -daysOld 7

    Ziska informace o spolehlivosti stroju nox a demeter. Pokud je jejich index stability nizsi nez 5, 
    tak dojde k vypsani informaci o stabilite a poslani emailu s podrobnou csv prilohou.
    Index se pocita ze zaznamu za poslednich 7 dni.   

    .EXAMPLE
    Get-ReliabilityHistory -exportCSV

    Ziska informace o spolehlivosti localhostu. Pokud e index za poslednich 7 dnu nizsi nez 5, 
    tak dojde k vypsani informaci o stabilite a vygenerovani CSV s jednotlivymi udalostmi. 

    .NOTES
    https://4sysops.com/archives/monitoring-windows-system-stability-with-powershell/?utm_source=feedburner&utm_medium=feed&utm_campaign=Feed%3A+4sysops+%284sysops%29
    #>

    param (
        [ValidateNotNullOrEmpty()]
        [string[]] $computerName = $env:COMPUTERNAME
        ,
        [ValidateNotNullOrEmpty()]
        [int] $stabilityIndexUnder = 5
        ,
        [switch] $sendEmail
        ,
        [ValidateNotNullOrEmpty()]
        [int] $daysOld = 7
        ,
        [switch] $exportCSV
        ,
        [string] $CSVPath = (Join-Path $env:TEMP 'ErrorRecords.csv')
        ,
        [ValidateNotNullOrEmpty()]
        [string] $to = 'aaa@bbb.cz'
        ,
        [switch] $returnObject
    )

    begin {
        $startTime = (Get-Date (Get-Date).AddDays( - $daysOld) -Format "dd.MM.yyyy")
        $result = New-Object System.Collections.ArrayList
        $csv = New-Object System.Collections.ArrayList
        if ($sendEmail) { $exportCSV = $true }
    }

    process {
        foreach ($computer in $computerName) {
            $params = @{className = 'win32_reliabilitystabilitymetrics'; ComputerName = $computer; filter = "TimeGenerated > `'$startTime`'"; ErrorAction = 'SilentlyContinue'}
            if ($computer -eq $env:COMPUTERNAME) { $params.Remove("ComputerName") } # vuci localhostu nedelam remote
            $reliabilityStabilityMetrics = Get-CimInstance @params | Select-Object @{n = 'Computer'; e = {$computer}}, SystemStabilityIndex, TimeGenerated

            if (!$reliabilityStabilityMetrics) { Write-Host "Na $computer jsem neziskal zadne zaznamy."; continue }

            $averageStabilityIndex = [math]::Round(($reliabilityStabilityMetrics | Measure-Object -Property SystemStabilityIndex -Average).Average, 1)
            $lastStabilityIndex = [math]::Round(($reliabilityStabilityMetrics | select -first 1 | select -ExpandProperty systemStabilityIndex), 1)
            if ($averageStabilityIndex -le $stabilityIndexUnder) {
                $params = @{ComputerName = $computer; ClassName = 'win32_reliabilityRecords'; filter = "TimeGenerated > '$startTime'"}
                if ($computer -eq $env:COMPUTERNAME) { $params.Remove("ComputerName") } # vuci localhostu nedelam remote
                $reliabilityRecords = Get-CimInstance @params | Select-Object @{n = 'Computer'; e = {$computer}}, EventIdentifier, LogFile, Message, ProductName, RecordNumber, SourceName, TimeGenerated
            
                # ulozim zaznamy, ktere pozdeji vyexportuji do csv
                if ($exportCSV) {
                    $reliabilityRecords | % { $null = $csv.add($_) }
                }
            
                $txt += "`n`n$computer ma prumerny index $averageStabilityIndex (aktualne $lastStabilityIndex). Vypis po dnech:`n"
            
                # zobrazim i prumer za jednotlive dny at se z toho da pripadne neco vysledovat
                $obj = [PSCustomObject] @{computer = $computer; average = $averageStabilityIndex}
                $metricsGroupedByDay = $reliabilityStabilityMetrics | group {$_.timegenerated.date} | sort {$_.name -as [datetime]}
                foreach ($oneDayMatrics in $metricsGroupedByDay) {
                    $records = $oneDayMatrics.group.systemstabilityindex -split " "
                    $sum = 0
                    foreach ($record in $records) {
                        $sum += $record
                    }
                    # pridam informaci do objektu
                    $obj | Add-Member -MemberType NoteProperty -Name $(Get-Date ($oneDayMatrics.name) -Format dd.MM) -value $([math]::Round(($sum / $records.count), 1))
                    
                    $txt += "$(Get-Date ($oneDayMatrics.name) -Format dd.MM): $([math]::Round(($sum/$records.count), 1)) | "
                }
                $result += $obj
                
                # odmazani zbytecneho rozdelovace na konci
                $txt = $txt -replace " \| $"
            } else {
                "$computer ma index stability ($averageStabilityIndex) vyssi nez nastaveny limit."
            }
        } # end foreach computerName
    }

    end {
        if ($result) {
            # vypisu vysledky
            if ($returnObject) {
                # vrati objekt
                $result | sort average
            } else {
                # vrati text
                $result | sort average | Format-Table
            }

            if ($csv) {
                "CSV se zaznamy je ulozeno v $CSVPath"
                $csv | Export-CSV $CSVPath -Encoding UTF8 -NoTypeInformation -Force
            }
        }

        # poslu vysledky emailem
        if ($txt -and $sendEmail) {
            $body = "Hola,`nnize je seznam stroju, ktere maji prumerny reliability index nizsi nez $stabilityIndexUnder.`nMereni probihalo od $startTime dosud.$txt"
            $body += "`n`nKonkretni chyby naleznete v priloze."
            
            send-email -to $to -subject 'Stroje s nizkym reliability indexem' -body $body -attachment $CSVPath
        }
    }
}