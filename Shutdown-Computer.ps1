#Requires -Modules psasync,SplitPipeline
#TODO: pokud filtruji dle prihlaseneho uzivatele at se provede i kdyz je v disconnected stavu pokud tam uz neni nikdo jinz prihlasen
function Shutdown-Computer {
    <#
	.Synopsis
    Provede na vlastním či vzdáleném pocitaci jednu z vybranych akci:
    LogOff, Shutdown, Reboot, ForcedLogOff, ForcedShutdown, ForcedReboot, PowerOff, ForcedPowerOff

	.Description
	Provede na vlastním či vzdáleném pocitaci jednu z vybranych akci:
    LogOff, Shutdown, Reboot, ForcedLogOff, ForcedShutdown, ForcedReboot, PowerOff, ForcedPowerOff

	Pokud je někdo přihlášen je potřeba použít forced variantu. Forced varianty násilně ukončí běžící procesy - hrozí ztráta dat!
	Pokud zadám i parametr username, tak provede akci pouze na strojích, kde je zadaný uživatel aktuálně přihlášený. A to pouze v aktivní session, ne disconnected atp.

	Vyžaduje fci: Get-LoggedOnUser! Která vyfiltruje stroje s prihlášeným $userName.
	Vyžaduje moduly: splitPipeline, psasync

	.PARAMETER ComputerName
	Parametr udavajici seznam stroju.

	.PARAMETER Type
	Typ akce: LogOff, Shutdown, Reboot,ForcedLogOff,ForcedShutdown,ForcedReboot,PowerOff,ForcedPowerOff.

	.PARAMETER UserName
	Login uživatele. Akce se proveden pouze na strojích, kde je uživatel přihlášen.

	.PARAMETER DateTime
	Nepovinný parametr. Datum a čas kdy se má akce provést. Ve tvaru d.M H:m (13.1 12:25) či H:m (13:35).

	.PARAMETER YourPassword
	Povinný parametr, který je třeba pokud je definován parametr DateTime. Heslo uživatele pod kterým běží PS konzole a bude se pouštět scheduled task.

	.PARAMETER TaskPath
    Nepovinný parametr udávající cestu, do které se má uložit scheduled task.

    .PARAMETER Comment
    Nepovinny parametr udavajici komentar, ktery se zaloguje do sys logu jako duvod vypnuti.

    .PARAMETER TimeOut
    Nepovinny parametr udavajici o kolik vterin se ma vypnuti zpozdit.
    Vychozi je 0 vterin.

	.Example
	Shutdown-Computer -comp $B311 LogOff -username skoleni
	U strojů v B311 odhlásí uživatele skoleni.

	.Example
	$hala | Shutdown-Computer Shutdown
	Vypne stroje v hale.

	.Example
	Shutdown-Computer -computername $hala -type Reboot
	Restartuje pouze stroje, kde neni prihlasen zadny uzivatel.

	.Example
	Shutdown-Computer -computername $hala -type ForcedReboot
	Restartuje vsechny stroje v hale.

	.Example
	Shutdown-Computer -computername localhost -type PowerOff
	Shuts down the computer and turns off the power (if supported by the computer in question).

	.Notes
	Více o typech vypnutí http://msdn.microsoft.com/en-us/library/aa394058(v=vs.85).aspx
	Author: Ondřej Šebela - ztrhgf@seznam.cz
    #>

    [Alias("sdc")]
    [CmdletBinding(DefaultParameterSetName = 'Default', SupportsShouldProcess = $true, ConfirmImpact = 'High')]
    param (
        [Parameter(Mandatory = $false, Position = 0, ParameterSetName = "Default", ValueFromPipelinebyPropertyName = $true, ValueFromPipeline = $true, HelpMessage = "zadej jmeno stroje/ů k pingnutí")]
        [Parameter(Mandatory = $false, Position = 0, ParameterSetName = "Scheduled", ValueFromPipelinebyPropertyName = $true, ValueFromPipeline = $true, HelpMessage = "zadej jmeno stroje/ů k pingnutí")]
        [Alias("c", "name", "dnshostname")]
        [ValidateNotNullOrEmpty()]
        $ComputerName = $env:computername
        ,
        [Parameter(Mandatory = $true, Position = 1, ParameterSetName = "Default", HelpMessage = "zadej typ akce: LogOff, Shutdown, Reboot, ForcedReboot, ForcedLogOff,...viz help")]
        [Parameter(Mandatory = $true, Position = 1, ParameterSetName = "Scheduled", HelpMessage = "zadej typ akce: LogOff, Shutdown, Reboot, ForcedReboot, ForcedLogOff,...viz help")]
        [ValidateSet("LogOff", "Shutdown", "Reboot", "ForcedLogOff", "ForcedShutdown", "ForcedReboot", "PowerOff", "ForcedPowerOff")]
        $Type
        ,
        [Parameter(Mandatory = $false, Position = 2, ParameterSetName = "Default", HelpMessage = "Zadejte login, aby se akce vykonala pouze na strojích s přihlášeným uživatelem")]
        [ValidateNotNullOrEmpty()]
        [Alias("login")]
        $UserName
        ,
        [Parameter(Mandatory = $true, ParameterSetName = "Scheduled", HelpMessage = "Zadejte datum ve tvaru d.M H:m (13.1 12:25) či H:m (13:35)")]
        [Alias("schedule")]
        #		[ValidateScript({$_.hour -ne 0})] #za urcitych okolnosti i pri zadani hodin se nastavi 00:00, da se zadat i bez hodin-nastavi se 0:0
        #		[ValidateScript({try{[DateTime] $date = [DateTime]::ParseExact($_, "d.M. H:m", [System.Globalization.CultureInfo]::InvariantCulture);return $true}catch{return $false}})]
        [ValidateScript( {
                function Convert-DateString ([String]$Date, [String[]]$Format) {
                    $result = New-Object DateTime
                    $convertible = [DateTime]::TryParseExact($Date, $Format, [System.Globalization.CultureInfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::None, [ref]$result)
                    if ($convertible) {return $true}; else {return $false}
                }
                Convert-DateString -Date $_ -Format 'd.M. H:m', 'd.M.yy H:m', 'H:m', 'd.M H:m'
            })]
        [string]$DateTime
        #		,
        #		[Parameter(Mandatory=$false,ParameterSetName="Default")]
        #		[Parameter(ParameterSetName = "Scheduled")]
        #		$cred
        ,
        [Parameter(Mandatory = $true, ParameterSetName = "Scheduled", HelpMessage = "Zadejte heslo potřebné k vytvoření úkolu v task scheduleru.")]
        [SecureString]$YourPassword
        ,
        [Parameter(Mandatory = $false, ParameterSetName = "Scheduled")]
        $TaskPath = "\Planned_Shutdowns\"
        ,
        [string] $Comment = 'provedeno prikazem Shutdown-Computer'
        ,
        [int] $TimeOut = 0
    )

    BEGIN {
        # kontrola že je dostupná funkce get-loggedonuser
        if ($UserName) {
            try	{
                $null = Get-Command Get-LoggedOnUser -ErrorAction Stop
                $null = Get-Command Test-Connection2 -ErrorAction Stop
            } catch	{
                Write-Error "Pro běh tohoto skriptu je zapotřebí funkce: Get-LoggedOnUser a Test-Connection2"
                break
            }

            # Odfiltrovani nepingajicich stroju
            $PingajiciComputerName = Test-Connection2 $ComputerName -JustResponding
            # Zjištění, na kterých strojích ze seznamu je přihlášen daný uživatel, pokud nikde = konec
            try	{
                $ComputerName = glu -computername $PingajiciComputerName -UserName $UserName | where {$_.userName -eq $UserName -and $_.state -ne "Disc"} | select -exp computername
            } catch {
                Write-Output "Uživatel $username není přihlášen na žádném stroji ze seznamu "
                break
            }

            Write-Output "Uživatel $username je přihlášen na: $ComputerName = zde se provede: $type."
        }

        #	Převod securestring na plaintext
        if ($YourPassword) {
            [string]$YourPassword = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($YourPassword))
        }

        switch ($type) {
            'LogOff' {$ShutdownType = "0"}
            'Shutdown' {$ShutdownType = "1"}
            'Reboot' {$ShutdownType = "2"}
            'ForcedLogOff' {$ShutdownType = "4"}
            'ForcedShutdown' {$ShutdownType = "5"}
            'ForcedReboot' {$ShutdownType = "6"}
            'PowerOff' {$ShutdownType = "8"}
            'ForcedPowerOff' {$ShutdownType = "12"}
        }

        if ($datetime) {
            # aby datum bylo ve správném tvaru (den.měsíc. a ne měsíc.den.)
            try	{
                function Convert-DateString ([String]$Date, [String[]]$Format) {
                    $result = New-Object DateTime
                    $convertible = [DateTime]::TryParseExact($Date, $Format, [System.Globalization.CultureInfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::None, [ref]$result)
                    return $result
                }
                [datetime]$datetime = Convert-DateString -Date $datetime -Format 'd.M. H:m', 'd.M.yy H:m', 'H:m', 'd.M H:m'
            } catch	{
                Write-Error "Zadaný čas $datetime se nepodařilo převést"
                break
            }

            #		kontrola ze zadane datum neni v minulosti
            $date = $DateTime | get-date
            if ($date -le (Get-Date)) {
                Write-Error "Zadaný čas $date je v minulosti. Funkce se teď ukončí."
                break
            }

            #
            # ZADEFINOVANI VLASTNOSTI SCHEDULED TASKU
            # datum musi byt v ' zavorkach proto delam replace
            $OriginalCommand = $myinvocation.line -replace "`"", "`'"
            # kvůli -replace potřebuji původni argument $datetime a ne ten převedený na [datetime] tvar
            $OriginalDate = $psboundparameters.getenumerator() | where {$_.key -match "DateTime"} | select -exp value
            # pokud nastavuji scheduledjob tak uz musim prikaz volat bez -datetime jinak by misto provedeni zase udelal jen dalsi scheduledjob :)
            $ScheduledCommand = $OriginalCommand -replace "-datetime `'$OriginalDate`'", "" -replace "-datetime $OriginalDate", "" -replace "-password $YourPassword", "" -replace "$YourPassword", ""	# replace $YourPassword je pro jistotu aby tam urcite nebylo heslo za zadnych okolnosti
            $A = New-ScheduledTaskAction –Execute "powershell.exe" -argument "$ScheduledCommand"
            $T = New-ScheduledTaskTrigger -once -at $DateTime
            $S = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -RunOnlyIfNetworkAvailable
            $D = New-ScheduledTask -Action $A -Trigger $T -Settings $S
        } else {
            $AsyncPipelines = @()
            $pool = Get-RunspacePool 30
        }

        # scriptBlock, ktery provadi vypnuti
        $scriptblock = {
            param ($computer, $ShutdownType, $comment, $timeOut)

            If (Test-Connection $computer -count 1 -quiet) {
                $Error.Clear()
                if ($cred -eq $null) {
                    trap { continue }

                    # non-force akce se neprovedou pokud je nekdo prihlasen, informuji o tom
                    #TODO dodelat, quser ted nespoustim v remote session = chyba
                    #if ($ShutdownType -in 1, 2, 8) {
                    #    if ((quser.exe).count -ge 2) {
                    #        # neresim jestli jde pouze o disconnected session
                    #        Write-Output "Na $computer je nekdo prihlasen, neprovedu."
                    #        continue
                    #    }
                    #}

                    #
                    # PROVEDU VYPNUTI
                    # pozn.: Get-WmiObject nepouzivam, protoze pouziva RPC a zpusobovalo, ze po vypnuti klientu stroj zacal kontaktovat RPC na lokalnich adresach 192. 172. z nejakeho duvodu
                    $obj = Get-CimInstance win32_operatingsystem -ComputerName $computer
                    $null = Invoke-CimMethod -InputObject $obj -MethodName Win32ShutdownTracker -Arguments @{Comment = $comment; Flags = $ShutdownType; ReasonCode = 0; Timeout = $timeOut}
                    Write-Output "Provedeno na $computer"
                }

                #			    if ($cred -eq "other")
                #				{
                #			        trap { continue }
                #			        $null = (Get-WmiObject win32_operatingsystem -ComputerName $computer -ErrorAction SilentlyContinue -Credential (get-Credential)).Win32Shutdown($ShutdownType)
                #					Write-Output "Provedeno na $computer"
                #			    }
            } else {
                Write-Output "$computer nepingá"
            }
        }
    }

    PROCESS	{
        # ma se vykonat v zadany cas == vytvorim sched. task, ktery prikaz spusti
        if ($datetime) {
            $dd = $date | Get-Date -Format d.M.yyyy_HH.mm
            $TaskName = "$type-$($computername -join ',')-$dd"
            $ExistingJobs = Get-ScheduledTask -TaskName $TaskName -TaskPath $TaskPath -ErrorAction SilentlyContinue
            if ($ExistingJobs) {
                Write-Warning "`nScheduledTask se jménem $TaskName existuje - bude nahrazen."
            }

            try	{
                # nastaveni uziv. jmena a hesla pro dany task - aby mohl pristupovat i na zdroje na siti (stroje)
                $null = Register-ScheduledTask $TaskName -InputObject $D -user "$env:USERDOMAIN\$env:USERNAME" -password $YourPassword -force -erroraction stop -TaskPath $TaskPath
                Write-Output "`nByl vytvořen scheduledtask $TaskName."
            } catch {
                Get-ScheduledTask -TaskName $TaskName | Unregister-ScheduledTask -Confirm:$false
                Write-Output "`nPři nastavování scheduled tasku došlo k chybě, proto byl odstraněn.`n Chyba byla: $($_.Exception.Message) "
            }

            Write-Output "`nPro zrušení tasku spusťte:`nGet-ScheduledTask -TaskName $TaskName | Unregister-ScheduledTask"
        } else {
            # ma se vykonat okamzite
            if ($UserName) {
                while ($choice -notmatch "[A|N]") {
                    $choice = read-host "Pokračovat? (A|N)"
                }
                if ($choice -eq "N") {
                    break
                }
            }

            foreach ($computer in $ComputerName) {
                $AsyncPipelines += Invoke-Async -RunspacePool $pool -ScriptBlock $ScriptBlock -Parameters $computer, $ShutdownType, $comment, $timeOut
            }
        }
    }

    END	{
        # ma se vykonat v zadany cas == jen zkontroluji, ze se sched. task vytvoril
        if ($datetime) {
            try	{
                $null = Get-ScheduledTask –TaskName "$TaskName" -erroraction stop #-TaskPath "\Microsoft\Windows\PowerShell\ScheduledJobs\"
            } catch {
                Write-Output "Task $TaskName nebyl vytvořen! Zkontrolujte Task Scheduler"
            }
        } else {
            # ma se vykonat okamzite == jiz jsem spustil == nyni ziskam vysledek
            Receive-AsyncResults -Pipelines $AsyncPipelines -ShowProgress
        }
    }
}

Set-Alias sdc Shutdown-Computer
