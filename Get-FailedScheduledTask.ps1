function Get-FailedScheduledTask {
    <#
    .SYNOPSIS
    Vypise scheduled tasky, ktere skoncily neuspechem.
    
    .DESCRIPTION
    Vypise scheduled tasky, ktere skoncily neuspechem.
    Kontroluji se vsechny ci jen uzivateli vytvorene tasky na zadanych strojich,
    ktere byly naposledy spusteny pred X dny.
    Automaticky se ignoruji disablovane a stare tasky, neni-li receno jinak.

    Vyzaduje admin prava pokud ma byt spusteno vuci localhostu!

    .PARAMETER computerName
    Seznam stroju, na kterych se maji sched. tasky zkontrolovat 

    .PARAMETER justUserTasks
    Prepinac rikajici, ze se maji kontrolovat pouze uzivateli vytvorene tasky

    .PARAMETER justActive
    Prepinac rikajici, ze se maji vypsat pouze enablovane tasky, ktere skoncily chybou max pred lastRunBeforeDays dny
    nebo maji nastaveno opakovani a maji se znovu spustit behem 24 hodin

    .PARAMETER lastRunBeforeDays
    Pocet dnu dozadu, kdy mohl byt sched. task naposled spusten
    Limituji tak, jak stare tasky se maji kontrolovat

    .PARAMETER sendEmail
    Zdali se ma poslat email s nalezenymi chybami

    .PARAMETER to
    Na jakou adresu se ma email poslat.
    Vychozi je aaa@bbb.cz
    
    .EXAMPLE
    Import-Module Scripts,Computers -ErrorAction Stop
    Get-FailedScheduledTask -computerName $servers -JustUserTasks -LastRunBeforeDays 1 -sendEmail

    Na strojich z $servers zkontroluje user sched. tasky spustene za poslednich 24 hodin a pokud nalezne
    nejake skoncene chybou, posle jejich seznam na admin@fi.muni.cz
    
    .NOTES
    Author: Sebela Ondrej
    #>

    [cmdletbinding()]
    param (
        $computerName = @($env:COMPUTERNAME)
        ,
        [switch] $justUserTasks
        ,
        [int] $lastRunBeforeDays = 1
        ,
        [switch] $justActive
        ,
        [switch] $sendEmail
        ,
        [string] $to = 'aaa@bbb.cz'
    )

    begin {
        if (!(Get-Command Write-Log -ea SilentlyContinue)) {
            throw "Vyzaduje funkci Write-Log."
        }

        $Error.Clear()

        $ComputerName = {$ComputerName.tolower()}.invoke()

        Write-Log "Kontroluji failnute scheduled tasky na: $($ComputerName -join ', ')"

        # kontrola, ze bezi s admin pravy
        if ($env:COMPUTERNAME -in $computerName -and !([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
            throw "Nebezi s admin pravy, coz je vyzadovano, pokud spoustite vuci localhostu"
        }
        
    }

    process {
        # schtasks pouzivam takto zvlastne, aby nebyla zkomolena diakritika (deje se u nativnich prikazu spoustenych pres psremoting)
        $failedTasks = invoke-command2 -computername $computerName -ArgumentList $lastRunBeforeDays, $justUserTasks, $justActive {
            param($lastRunBeforeDays, $justUserTasks, $justActive)

            # pomocne funkce
            function ConvertTo-DateTime {
                [CmdletBinding()]
                param (
                    [Parameter(Mandatory = $true, Position = 0)]
                    [ValidateNotNullOrEmpty()]
                    [String] $date
                    , 
                    [Parameter(Mandatory = $false, Position = 1)]
                    [ValidateNotNullOrEmpty()]
                    [String[]] $format = ('d.M.yyyy', 'd.M.yyyy H:m', 'd.M.yyyy H:m:s')
                )

                $result = New-Object DateTime

                $convertible = [DateTime]::TryParseExact(
                    $Date,
                    $Format,
                    [System.Globalization.CultureInfo]::InvariantCulture,
                    [System.Globalization.DateTimeStyles]::None,
                    [ref]$result)

                if ($convertible) {
                    $result
                } else {
                }
            }

            # mohl bych pouzit Get-ScheduledTask a Get-ScheduledTaskInfo, ale na starsich OS neexistuji
            # pres Start-Job spoustim proto, ze nativni prikazy v remote session pri "klasickem" spusteni nevraci korektne diakritiku
            $job = Start-Job ([ScriptBlock]::Create('schtasks.exe /query /s localhost /V /FO CSV'))
            $null = Wait-Job $job 
            $tasks = Receive-Job $job | ConvertFrom-Csv
            Remove-Job $job

            # odfiltruji duplicitni zaznamy (kazdy task je tam tolikrat, kolik ma triggeru)
            [System.Collections.ArrayList] $uniqueTask = @()
            $tasks | % {
                if ($_.taskname -notin $uniqueTask.taskname) {
                    $null = $uniqueTask.add($_)
                }
            }
            $tasks = $uniqueTask
            
            if ($justUserTasks) {
                $domainName = $env:userdomain # netbios jmeno domeny (ntfi)
                $computer = $env:COMPUTERNAME
                if (!$domainName -or $domainName -eq $computer) { $domainName = 'ntfi' }
                $tasks = $tasks | where {($_.author -like "$domainName\*" -or $_.author -like "$computer\*")}
            }

            # tasky, ktere pri poslednim spusteni skoncily chybou
            # nektere nenulove result kody ignoruji, protoze nejde o skutecne chyby
            # 267009 = task is currently running 
            # 267014 = task task was terminated by user
            # 267011 = task has not yet run
            # -2147020576 = operator or administrator has refused the request
            # -2147216609 = an instance of this task is already running
            $tasks = $tasks | where {($_.'last Result' -ne 0 -and $_.'last Result' -notin (267009, 267014, 267011, -2147020576, -2147216609) -and $_.'last run time' -ne 'N/A')}

            #TODO tento zpusob filtrovani nezachyti problemy u tasku, ktere se vytvareji pomoci GPO v replace modu, protoze pri kazdem gpupdate dojde k replace tasku, tzn ztrate informaci
            # dalo by se vyresit tahanim informaci z event logu, kde se loguje historie per taskname

            if ($justActive) {
                # vratim jen enablovane tasky, ktere byly spusteny max pred $LastRunBeforeDays dny
                # nebo se opakuji a maji byt spusteny behem 24 hodin znovu
                $tasks = $tasks | where {
                    $_.'Scheduled Task State' -eq 'Enabled' `
                        -and (
                        ($(try {ConvertTo-DateTime $_.'last run time' -ea stop} catch {Get-Date 1.1.1999}) -gt [datetime]::now.AddDays( - $LastRunBeforeDays))`
                            -or 
                        ($_.'Repeat: Every' -ne "N/A" -and ($(try {ConvertTo-DateTime ($_.'Next Run Time') -ea stop} catch {Get-Date 1.1.9999}) -lt [datetime]::now.AddDays(1)))
                    )
                } 
            }

            # vypisi vysledek
            $tasks | select taskname, 'last result', 'last run time', 'next run time', @{n = 'Computer'; e = {$env:COMPUTERNAME}}
        } -ErrorAction SilentlyContinue
    }

    end {
        if ($Error) {
            Write-Log -ErrorRecord $Error
        }

        if ($failedTasks) {
            Write-Log -Message $($failedTasks | Format-List taskname, 'last result', 'last run time', computer | Out-String) 

            $body = "Ahoj,`nnize je seznam failnutych scheduled tasku za minuly den:`n`n"
            $body += $failedTasks | Format-List taskname, 'last result', 'last run time', computer | Out-String
            $body += "`n`n`nKontrola probiha na: $($computerName -join ', ')" 

            if ($Error) {
                $body += "`n`n`n Obevily se chyby:`n$($Error | out-string)"        
            }
            
            if ($sendEmail) {
                Send-Email -Subject "Failnute scheduled tasky spustene za $LastRunBeforeDays poslednich dnu" -Body $body -To $To
            }
        } else {
            if ($justActive) {
                $t = " (spustene od $([datetime]::now.AddDays( - $LastRunBeforeDays)))"
            }
            
            Write-Log "Zadne neuspesne spustene sched. tasky$t nenalezeny"
        }
    }
}
