#requires -modules psasync

<#
TODO:
- pridat moznost filtrovat dle zadaneho data
- vyresit ze nekdy je vic restartu za sebou po nekolika sekundach aniz by mezi nimi byl nejaky start, zrejme jen duplicita v logu
- zda se ze neukazuje hibernace!
	- http://techsupt.winbatch.com/webcgi/webbatch.exe?techsupt/nftechsupt.web+WinBatch/WMI+Detect~Standby~or~Hibernation~Event.txt
	- http://www.dreamincode.net/forums/topic/175535-detect-system-wake-up-from-sleephibernatestand-by/
	- http://blog.nirsoft.net/2013/07/04/new-utility-for-windows-vista782008-that-displays-the-logonlogoff-times/

!!!!!POZOR pokud u get-date 	pouziji -format tak vraci string jinak datetime!!!!

#>
function Get-Shutdown {
    <#
	.SYNOPSIS
		Fce vrati casy zapnuti|vypnuti|uspani|probuzeni|restartu|bsod|neocekavanych vypnuti zadaneho stroje.

	.DESCRIPTION
		U unexpected shutdowns eventu vraci v message jmeno tehdy prihlaseneho uzivatele. Pokud se nezobrazi, zvyste hodnotu days_to_search.
		Pokud je prvni vraceny event typu start, message bude obsahovat jeho uptime ve formatu dd:hh:mm:ss.
		BSOD se ziskavaji z minidump adresare (ziskavani z event logu nebylo spolehlive).
		Pro zobrazeni podrobnych informaci o BSOD je potreba mit v jedne z nastavenych cest bluescreenview.exe (ozkousena verze je 1.55 x64, starsi nefungovaly s UNC!)
		Pro zobrazeni podrobnych BSOD informaci je treba spustit s admin pravy.
		Message cas obsahuje uzivatele, ktery akci provedl, pokud je tato informace dostupna v eventu.

	.PARAMETER  ComputerName
		Jmeno stroje/u.

	.PARAMETER  Newest
		Pocet udalosti k vypsani. Vychozi hodnota je 4.

	.PARAMETER  Filter
		Pole stringu, ktere urcuji jake udalosti se maji vypsat. Ve vychozim nastaveni obsahuje vsechny moznosti.
		Mozne varianty jsou "start", "unexpected_shutdown", "shutdown_or_restart", "bsod", "wake_up", "sleep"

	.PARAMETER  days_to_search
		Číslo udávající kolik dnů před posledním unexp. shutdownem se má hledat přihlášení uživatele.
		Výchozí je 7 dnů.

	.PARAMETER	maxMinutes
		Číslo udávající o kolik minut po BSOD musí být unexp. event, aby došlo k jeho smazání.
		Předpokládáme, že oba záznamy reprezentují jeden pád systému.
		Výchozí je 10 minut.

	.PARAMETER bluescreenviewexe_path
		Obsahuje preddefinovane pole s moznymi cestami k nirsoft utilite bluescreenview. Nebo muzete zadat vlastni.
        Funguje 1.55 verze x64.

    .PARAMETER silent
        Prepinac rikajici, ze pokud nebude dostupny BluScreenView tool, tak se nebude poptavat jeho stazeni.
        Vhodne pri pouziti ve skriptech.

	.EXAMPLE
		Get-Shutdown kronos,titan05 5

	.EXAMPLE
		Get-Shutdown kronos,titan05 -newest 5 -filter "shutdown_or_restart","bsod"

	.EXAMPLE
		get-shutdown $hala -filter bsod | select computer,message | fl *

		pro zobrazeni podrobneho infa o poslednich ctyrech BSOD na strojich v hale
	#>
    [CmdletBinding()]
    param(
        [Parameter(Position = 0, Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        $computerName = $env:computername
        ,

        [Parameter(Position = 1)]
        [ValidateNotNull()]
        [int] $newest = 4
        ,
        [ValidateSet("start", "unexpected_shutdown", "shutdown_or_restart", "bsod", "wake_up", "sleep")]
        [ValidateNotNullOrEmpty()]
        $filter = @("start", "unexpected_shutdown", "shutdown_or_restart", "bsod", "wake_up", "sleep")
        ,
        [int] $days_to_search = 7
        ,
        [int] $maxMinutes = 10
        ,
        [string[]] $bluescreenviewexe_path = @("$env:tmp\bluescreenview-x64\bluescreenview.exe", '\\ad.fi.muni.cz\dfs\bin\NirSoft\bluescreenview.exe')
        ,
        [switch] $silent
    )

    BEGIN {
        $AsyncPipelines = @()
        $pool = Get-RunspacePool 20
        $Events = New-Object System.Collections.ArrayList

        # prevedu na arraylist abych mohl pouzivat remove
        $filter = {$filter}.invoke()

        # kontrola ze je dostupny bluescreenview
        if ($filter -contains "bsod") {
            $bsodViewerExists = 0
            foreach ($path in $bluescreenviewexe_path) {
                if (Test-Path $path -ErrorAction SilentlyContinue) {
                    $bsodViewerExists = 1
                    $bluescreenviewexe_path = $path
                    break
                }
            }

            if (!$bsodViewerExists -and !$silent) {
                write-warning "BlueScreenView.exe neni dostupny na zadne ze zadanych cest $bluescreenviewexe_path."
                $answer = Read-Host "Chcete jej stahnout z internetu (ne kazda verze funguje z CMD!) ? a|n"
                if ($answer -eq 'a') {
                    try {
                        $webAddress = 'http://www.nirsoft.net/utils/bluescreenview-x64.zip'
                        $DownloadDestination = "$env:tmp\bluescreenview-x64.zip"
                        [Void][System.IO.Directory]::CreateDirectory((Split-Path $DownloadDestination))
                        $ExtractedTools = $DownloadDestination -replace '.zip'
                        Invoke-WebRequest $webAddress -OutFile $DownloadDestination
                        if (Test-Path $ExtractedTools) {
                            Remove-Item $ExtractedTools -Confirm:$false -Recurse
                        }
                        [Void][System.IO.Directory]::CreateDirectory($ExtractedTools)

                        $null = Unzip-File $DownloadDestination $ExtractedTools
                        # s vychozim CFG souborem nefunguje ziskavani infa ze vzdalenych minidump souboru = upravim
                        $CFGFile = join-path $ExtractedTools 'BlueScreenView.cfg'
                        $CFGFileContent = @'
[General]
ShowGridLines=0
SaveFilterIndex=0
ShowInfoTip=1
ShowTimeInGMT=0
VerSplitLoc=16383
LowerPaneMode=1
MarkDriversInStack=1
AddExportHeaderLine=0
ComputersFile=
LoadFrom=3
DumpChkCommand=""%programfiles%\Debugging Tools for Windows\DumpChk.exe" "%1""
MarkOddEvenRows=0
SingleDumpFile=
WinPos=2C 00 00 00 00 00 00 00 01 00 00 00 FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF D0 00 00 00 D0 00 00 00 50 03 00 00 B0 02 00 00
Columns=B4 00 00 00 78 00 01 00 96 00 02 00 6E 00 03 00 6E 00 04 00 6E 00 05 00 6E 00 06 00 6E 00 07 00 96 00 08 00 78 00 09 00 8C 00 0A 00 82 00 0B 00 78 00 0C 00 78 00 0D 00 50 00 0E 00 78 00 0F 00 78 00 10 00 78 00 11 00 78 00 12 00 50 00 13 00 50 00 14 00 5A 00 15 00 5A 00 16 00 5A 00 17 00 5A 00 18 00 5A 00 19 00
Sort=4097
ModulesColumns=B4 00 00 00 78 00 01 00 78 00 02 00 78 00 03 00 78 00 04 00 78 00 05 00 78 00 06 00 78 00 07 00 78 00 08 00 78 00 09 00 78 00 0A 00 78 00 0B 00
ModulesSort=1
'@
                        Set-Content -Path $CFGFile -Value $CFGFileContent
                        $bluescreenviewexe_path = join-path $ExtractedTools bluescreenview.exe
                        $bsodViewerExists = 1
                    } catch {
                        # uklid
                        Remove-Item $DownloadDestination, $ExtractedTools -Confirm:$false -Recurse -Force
                        throw "Neco se pokazilo.`nChyba:`n$($_.Exception.Message)`nRadek:`n$($_.InvocationInfo.ScriptLineNumber) `n`n..koncim"
                    }
                }
            } elseif ($bsodViewerExists) {
                # $bsodview existuje, musim upravit konfiguraci, aby fungovalo ziskavani infa ze vzdalenych minidump souboru
                $CFGFile = Join-Path (Split-Path $bluescreenviewexe_path) 'BlueScreenView.cfg'
                if (Test-Path $CFGFile -ErrorAction SilentlyContinue) {
                    $content = Get-Content $CFGFile
                    if ($content -match 'LoadFrom=1') {
                        Write-Warning "Upravuji $CFGFile, aby slo pracovat s remote minidump soubory!"
                        $content | Foreach-Object {$_ -replace '^LoadFrom=1$', "LoadFrom=3"} | Set-Content $CFGFile
                    }
                } else {
                    Set-Content -Path $CFGFile -Value $CFGFileContent
                }
            }

            # BSOD viewer neni dostupny a uzivatel jej nechtel stahnout
            if (!$bsodViewerExists) {
                Write-Warning "Obsah BSOD se nezobrazi, BSODViewer neni k dispozici"
            }
        }




        #kontrola zdali skript bezi s admin pravy
        if ($filter -contains "bsod" -and $bsodViewerExists -and ($ComputerName -eq $env:computername) -and !([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
            write-warning "BSOD udalosti se nezobrazi! Je nutne spustit s admin pravy."
            [void]$Filter.remove('bsod')
        }

        $scriptblock = {
            param ($Computer, $newest, $Filter, $days_to_search, $maxMinutes, $bluescreenviewexe_path, $VerbosePreference)
            if (test-connection -computername $Computer -Count 1 -quiet) {
                $AllUnexpectedEvents = @()
                $AllUnexpectedEvents = {$AllUnexpectedEvents}.invoke()
                [System.Collections.ArrayList]$todelete = @()
                $BSODevents = @()
                $UnexpectedEvents = @()
                $WakeupEvents = @()
                $SleepEvents = @()

                #region pomocne funkce
                function Get-LogOnOff {
                    <#
					.SYNOPSIS
					Fce slouží k vypsání logon/off událostí na vybraných strojích uživatele/ů.

					.DESCRIPTION
					Fce vyhledá logon/off eventy na vybraných strojích.
					Defaultně vypíše 4 poslední logon/off.
					Vyžaduje povolený a modul psasync.

					.PARAMETER ComputerName
					Seznam strojů, na kterých zjistím logon/off akce.

					.PARAMETER Newest
					Číslo určující kolik logon/off událostí se má vypsat. Výchozí hodnota je 4.

					.PARAMETER UserName
					Parametr určující login uživatele, který se má na daných strojích hledat.

					.PARAMETER Type
					Seznam určující jaky typ eventu se ma hledat. Moznosti: logon, logoff.

					.PARAMETER After
					Parametr určující po jakém datu se mají eventy hledat.
					Zadavejte ve formatu: d.M.YYYY pripadne d.M.YYYY H:m, Pr.: 13.5.2015, 13.5.2015 6:00.
					Zadáte-li neexistující datum, tak filtr nebude fungovat!

					.PARAMETER Before
					Parametr určující před jakým datem se mají eventy hledat.
					Zadavejte ve formatu: d.M.YYYY pripadne d.M.YYYY H:m, Pr.: 13.5.2015, 13.5.2015 6:00.
					Zadáte-li neexistující datum, tak filtr nebude fungovat!

					.EXAMPLE
					$hala | Get-LogOnOff
					Na strojích z haly vypíše 4 poslední přihlášení/odhlášení.

					.EXAMPLE
					$hala | Get-LogOnOff -username sebela
					Vyhledá 4 nejnovější záznamy o přihlášení uživatele sebela na každém stroji v hale.

					.EXAMPLE
					$hala | Get-LogOnOff -username sebela -type logon -newest 10
					Vyhledá 10 nejnovějších přihlášení uživatele sebela na každém stroji v hale.

					.EXAMPLE
					$hala | Get-LogOnOff -username sebela -type logoff -newest 10 -after '14.1.2015 10:00' -before 20.2.2015
					Vyhledá 10 odhlášení uživatele sebela na každém stroji v hale mezi 14.1.2015 10:00 a 20.2.2015.

					.NOTES
					Author: Ondřej Šebela - ztrhgf@seznam.cz
					#>

                    [CmdletBinding()]
                    param (
                        [Parameter(Mandatory = $false, Position = 0, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true, HelpMessage = "zadej jmeno stroje/ů")]
                        [Alias("c", "CN", "__Server", "IPAddress", "Server", "Computer", "Name", "SamAccountName")]
                        [ValidateNotNullOrEmpty()]
                        [String[]] $ComputerName = $env:computername
                        ,
                        [Parameter(Mandatory = $false, Position = 1)]
                        [Alias("user", "login")]
                        [ValidateNotNullOrEmpty()]
                        [string]$UserName
                        ,
                        [Parameter(Mandatory = $false, Position = 2)]
                        [int]$newest
                        ,
                        [ValidateSet("logon", "logoff")]
                        [array]$type = @("logon", "logoff")
                        ,
                        [ValidateScript( {
                                If (($_ -match '^\d{1,2}\.\d{1,2}\.\d{4}( \d{1,2}:\d{1,2}(:\d{1,2}?)?)?$')) {
                                    $true
                                } else {
                                    Throw "$_ .Zadavejte ve formatu: d.M.yyyy, d.M.yyyy H:m, d.M.yyyy H:m:s Pr.: 13.5.2015, 13.5.2015 6:00, 13.5.2015 6:00:33"
                                }
                            })]
                        $after
                        ,
                        [ValidateScript( {
                                If (($_ -match '^\d{1,2}\.\d{1,2}\.\d{4}( \d{1,2}:\d{1,2}(:\d{1,2}?)?)?$')) {
                                    $true
                                } else {
                                    Throw "$_ .Zadavejte ve formatu: d.M.yyyy, d.M.yyyy H:m, d.M.yyyy H:m:s Pr.: 13.5.2015, 13.5.2015 6:00, 13.5.2015 6:00:33"
                                }
                            })]
                        $before
                    )

                    BEGIN {
                        try {
                            Import-Module psasync -ErrorAction Stop
                        } catch {
                            Write-Error "Nepodařilo se naimportovat psasync modul"
                            break
                        }

                        # ve vychozim stavu vypise 4 posledni udalosti
                        if (!$after -and !$newest -and !$before) {
                            $newest = 4
                        }

                        $AsyncPipelines = @()
                        $pool = Get-RunspacePool 20

                        $scriptblock = `
                        {
                            param($computer, $newest, $type, $UserName, $after, $before)

                            if (Test-Connection -ComputerName $computer -Count 1 -ErrorAction SilentlyContinue) {

                                $UserProperty = @{n = "User"; e = {(New-Object System.Security.Principal.SecurityIdentifier $_.properties[1].value.value).Translate([System.Security.Principal.NTAccount])}}
                                $TypeProperty = @{n = "Action"; e = {if ($_.ID -eq 7001) {"Logon"} else {"Logoff"}}}
                                $TimeProperty = @{n = "Time"; e = {$_.TimeCreated}}
                                $CompName = @{n = "Computer"; e = {$computer}}

                                # poskladani prikazu k vykonani
                                $command = "Get-WinEvent -ComputerName $Computer -ea silentlycontinue -FilterHashTable @{LogName='System'; ProviderName='Microsoft-Windows-Winlogon'"
                                if ($type -contains "logon" -and $type -contains "logoff") {
                                    $command += ""
                                } elseif ($type -contains "logon") {
                                    $command += ";id=7001"
                                } elseif ($type -contains "logoff") {
                                    $command += ";id=7002"
                                }
                                if ($after) {
                                    $command += ";starttime=`"$after`""
                                }
                                if ($before) {
                                    $command += ";endtime=`"$before`""
                                }
                                $command += "} "
                                if ($newest -and !$username) {
                                    $command += "-MaxEvents $Newest "
                                }
                                $command += '| select $CompName,$UserProperty,$TypeProperty,$TimeProperty '
                                if ($UserName) {
                                    if ($newest) {
                                        $command += '| where {$_.user -like "*$UserName*"} | select -First $Newest'
                                    } else {
                                        $command += '| where {$_.user -like "*$UserName*"}'
                                    }
                                }

                                #vykonani prikazu
                                Invoke-Expression $command
                            } else {
                                Write-Output "$computer nepinga."
                            }
                        }
                    }

                    PROCESS {
                        foreach ($computer in $ComputerName) {
                            $AsyncPipelines += Invoke-Async -RunspacePool $pool -ScriptBlock $ScriptBlock -Parameters $computer, $newest, $type, $UserName, $after, $before
                        }
                    }


                    END {
                        Receive-AsyncResults -Pipelines $AsyncPipelines -ShowProgress
                    }
                }



                # fce pro ziskani podrobnosti ohledne BSOD z DMP souboru, pouziva program bluescreenview
                function get-bsodinfo {
                    param (
                        $computer,
                        $bluescreenviewexe_path,
                        $bsodtime
                    )

                    $bsodtime = Get-Date $bsodtime
                    # ziskam cestu k DMP souboru s BSOD informacemi
                    $dmpFile = Get-ChildItem \\$computer\C$\Windows\Minidump -File | where { $_.creationtime -gt ($bsodtime).addseconds(-1) -and $_.creationtime -lt ($bsodtime).addseconds(2)} | select -ExpandProperty fullname
                    if ($dmpFile) {
                        $CsvFile = [System.IO.Path]::GetTempFileName()
                        & $bluescreenviewexe_path /singledumpfile $dmpFile /scomma $CsvFile
                        if ($?) {
                            $CsvFileFinal = [System.IO.Path]::GetTempFileName()
                            # pockam nez bude mit soubor nejaky obsah
                            do {
                                $CsvFileContent = Get-Content $CsvFile -Force -raw
                                sleep 1
                                ++$x
                            }
                            until ($CsvFileContent -or $x -ge 10)
                            # do finalniho csv souboru pridam hlavicku a obsah csv s bsod informacemi
                            Add-Content -path $CsvFileFinal -Value "Dump File,Crash Time,Bug Check String,Bug Check Code,Parameter 1,Parameter 2,Parameter 3,Parameter 4,Caused by driver,Caused by address,File description,Product name,Company,File version,Processor,Crash Address,Stack Address 1,Stack Address 2,Stack Address 3,Computer Name,Full path,Processors Count,Major Version,Dump File Size,Dump File Time `r`n$CsvFileContent" -Confirm:$false
                            # naimportuji obsah
                            $result = Import-Csv $CsvFileFinal
                            # smazani tmp souboru
                            Remove-Item $CsvFile, $CsvFileFinal -Confirm:$false -Force
                            # vypsani vysledku
                            $result
                        } else {
                            write-output "Nepodarilo se pomoci bluescreenview ziskat bsod informace."
                        }
                    } else {
                        Write-Error "DMP soubor s BSOD infem nenalezen. Cas vytvoreni $(($bsodtime).addseconds(-1)) do $(($bsodtime).addseconds(2))"
                    }
                }
                #endregion

                # shutdown | restart
                if ($filter -contains "shutdown_or_restart") {
                    #chystane vypnuti podrobne info (cas vypnuti neodpovida uplne realite = jde o pripravu na vypnuti)
                    $events += Get-WinEvent -FilterHashtable @{logname = "system"; providername = "User32"; id = 1074}`
                        -ComputerName $Computer -MaxEvents $newest -ea silentlycontinue | Select-Object @{Name = "Computer"; Expression = {$computer}}, @{Name = "Event"; Expression = {"$($_.Properties[4].Value)" -replace "power off|Napájení vypnuto", "Shutdown" -replace "Restartování", "Restart"}}, @{Name = "Time"; Expression = {$_.TimeCreated}}, @{Name = "Message"; Expression = {"KDO: $($_.properties[6].value), PROC: $($_.properties[5].value) | $($_.properties[2].value), PROCES: $($_.properties[0].value)"}}
                }

                # zapnuti
                if ($filter -contains "start") {
                    $events += Get-WinEvent -FilterHashtable @{logname = "system"; providername = "Microsoft-Windows-Kernel-General"; id = 12}`
                        -ComputerName $Computer -MaxEvents $newest -ea silentlycontinue | Select-Object @{Name = "Computer"; Expression = {$computer}}, @{Name = "Event"; Expression = {"Start"}}, @{Name = "Time"; Expression = {$_.TimeCreated}}, @{Name = "Message"; Expression = {''}}
                }

                # Wakeup events
                if ($filter -contains "wake_up") {
                    $events += Get-WinEvent -FilterHashtable @{providername = "Microsoft-Windows-Power-Troubleshooter"; logname = "system"}`
                        -MaxEvents $Newest -computername $computer -ea silentlycontinue | Select-Object @{Name = "Computer"; Expression = {$computer}}, @{Name = "Event"; Expression = {"WakeUp"}}, @{Name = "Time"; Expression = {$_.TimeCreated}}, @{Name = "Message"; Expression = {$_.User, $_.message}}
                }

                # Sleep events
                if ($filter -contains "sleep") {
                    $events += Get-WinEvent -FilterHashtable @{providername = "Microsoft-Windows-Kernel-Power"; logname = "system"; id = 42}`
                        -MaxEvents $Newest -computername $computer -ea silentlycontinue | Select-Object @{Name = "Computer"; Expression = {$computer}}, @{Name = "Event"; Expression = {"Sleep"}}, @{Name = "Time"; Expression = {$_.TimeCreated}}, @{Name = "Message"; Expression = {$_.User, $_.message}}
                }

                # BSOD
                # TODO kdyz neni $bsodViewerExists tak ziskat info z logu
                if ($filter -contains "bsod" -and $bsodViewerExists) {
                    # ziskani BSOD z minidump souboru (z event logu ukazuje vic smrtek nez je minidump souboru)
                    if (test-path "\\$computer\C$\windows\minidump" -ea silentlycontinue) {
                        $BSODevents = Get-ChildItem -path \\$computer\C$\windows\minidump\* -include *.dmp | sort -descending CreationTime | select -First $newest
                        if ($BSODevents) {
                            foreach ($bsod in $BSODevents) {
                                $message = ""
                                $message = get-bsodinfo $computer $bluescreenviewexe_path $($bsod.CreationTime) | Out-String # ziskany objekt prevedu na text pro snadnejsi cteni informaci, neocekavam potrebu filtrovani dle jednotlivych parametru
                                if (!$message) {
                                    $message = "vyskystl se problem pri ziskavani podrobneho BSOD infa."
                                }

                                $allUnexpectedEvents += $bsod | Select-Object @{Name = "Computer"; Expression = {$computer}}, @{Name = "Event"; Expression = {"BSOD"}}, @{Name = "Time"; Expression = {$_.CreationTime}}, @{Name = "Message"; Expression = {$message}}
                            }
                        }
                    }
                    #				# ziskani BSOD z event logu (zalozni moznost)
                    #				$BSODevents = Get-WinEvent -FilterHashtable @{logname="application";providername="Windows Error*";id=1001}`
                    #				-ComputerName $Computer | Select-Object timecreated, properties | where {$_.properties[2].value -eq "BlueScreen"} | Select-Object @{Name="Computer";Expression={$computer}}, @{Name="Event";Expression={"BSOD"}}, @{Name="Time";Expression={$_.TimeCreated}}, @{Name="Message";Expression={$_.message}}, User
                    #				$allUnexpectedEvents += $BSODevents
                }

                # unexpected shutdowns
                if ($filter -contains "unexpected_shutdown") {
                    $UnexpectedEvents = Get-WinEvent -FilterHashtable @{logname = "system"; providername = "Microsoft-Windows-Kernel-Power"; id = 41}`
                        -ComputerName $Computer -MaxEvents $newest -ea silentlycontinue | Select-Object @{Name = "Computer"; Expression = {$computer}}, @{Name = "Event"; Expression = {"Unexpected Shutdown"}}, @{Name = "Time"; Expression = {$_.TimeCreated}}, @{Name = "Message"; Expression = {""}}

                    if ($UnexpectedEvents) {
                        # ULOZENI KDO BYL PRIHLASEN DO USER PROPERTY OBJEKTU
                        # cas posledniho unexp. shut.
                        $last_unexpected_shutdown = $UnexpectedEvents | sort time -Descending | select -Last 1 | select -exp time
                        # posunuti cas dozadu kvuli dohledani tehdy prihlaseneho uzivatele (pokud se prihlasil jeste drive pred unexp. shut. tak se neukaze)
                        $last_unexpected_shutdown = $last_unexpected_shutdown.adddays( - $days_to_search)
                        # prevedeni na spravny format data
                        $last_unexpected_shutdown = (get-date $last_unexpected_shutdown -Format 'd.M.yyyy H:m')
                        #ziskat logon eventy do tohoto data
                        $LogonEvents2 = Get-LogOnOff -ComputerName $Computer -type 'logon' -after $last_unexpected_shutdown -Newest 100000
                        # upravit message cast kazdeho unexp. shut. s udajem kdo byl prihlasen
                        foreach ($event in $UnexpectedEvents) {
                            $logged_user = ($LogonEvents2 | where {$_.action -eq 'logon' -and $_.time -lt $($event.time)} | select -first 1 | select -exp user).value
                            $event.message = $logged_user
                        }
                        write-verbose "do `$allUnexpectedEvents pridavam unexp. shutdown eventy"
                        $allUnexpectedEvents += $UnexpectedEvents
                    }
                }

                # OSETRENI VARIANTY KDY PRO JEDEN PAR SYSTEMU JSOU V LOGU JAK UNEXP. SHUTDOWN UDALOST TAK BSOD UDALOST
                # ZISKANI UNEXP. SHUTDOWNS UDALOSTI, KTERE JSOU V LOGU TESNE PRED BSOD KVULI JEJICH POZDEJSIMU ODSTRANENI
                if ($filter -contains "unexpected_shutdown" -and $filter -contains "bsod") {
                    $allUnexpectedEvents = $allUnexpectedEvents | sort Time -Descending
                    $allUnexpectedEvents | % {$x = 0} {
                        $thisEvent = $allUnexpectedEvents[$x]
                        $nextEvent = $allUnexpectedEvents[$x + 1]
                        $previousEvent = $allUnexpectedEvents[$x - 1]
                        # tento IF osetruje variantu, kdy se unexp. zaradil pri sortu pred BSOD i kdyz ma stejny cas a za BSOD je dalsi unexp. ktery by odpovidal filtru = smazal by se nepravy
                        if (($previousEvent.event -eq "Unexpected Shutdown" -and $thisEvent.event -eq "BSOD") -and ($thisEvent.time -eq $previousEvent.time)) {
                            $nextEvent = $previousEvent
                        }
                        if (($thisEvent.event -eq "BSOD" -and $nextEvent.event -eq "Unexpected Shutdown") -and ($nextEvent.time -gt $thisEvent.time.addminutes( - $maxMinutes))) {
                            [void]$todelete.add($nextEvent.time)
                            write-verbose "do seznamu eventu ke smazani jsem pridal unexp. event $($nextEvent.time). Byl max $maxMinutes minut pred BSOD = zrejme jedna udalost.";
                        }
                        $x++
                    }

                    # ODSTRANENI ZISKANYCH UNEXP. SHUTDOWNU
                    $allUnexpectedEvents = {$allUnexpectedEvents}.invoke()
                    # smazu unexpected eventy po kterych nasleduje v seznamu BSOD event (realne jde o jednu udalost)
                    if ($todelete.count -gt 0) {
                        foreach ($time in $todelete) {
                            $event = $allUnexpectedEvents | where {$_.time -eq $time -and $_.event -eq "Unexpected Shutdown"}
                            #write-output "mazu $time tedy $event"
                            $allUnexpectedEvents.removeat($allUnexpectedEvents.indexof($event))
                        }
                    }
                }
                # (zeditovane) unexp. eventy spolu s BSOD nahraji k ostatnim udalostem
                write-verbose "do seznamu eventu pridavam unexp a bsod eventy"
                $events += $allUnexpectedEvents


                # PRIDANI UPTIME DO MESSAGE PROPERTY DO PRVNIHO START EVENTU
                $events	= $events | sort Time -Descending
                if ($events -and ($events[0]).event -eq "start") {
                    $Uptime = Get-WmiObject -Class Win32_OperatingSystem -ComputerName $Computer
                    $LastBootUpTime = $Uptime.ConvertToDateTime($Uptime.LastBootUpTime)
                    $Time = (Get-Date) - $LastBootUpTime
                    $Uptime = '{0:00}:{1:00}:{2:00}:{3:00}' -f $Time.Days, $Time.Hours, $Time.Minutes, $Time.Seconds
                    ($events[0]).message = "Uptime: $Uptime"
                }

                # VYPSANI ZISKANYCH UDALOSTI
                $ErrorActionPreference = "silentlycontinue"
                $events	| select -first $newest | select computer, event, Time, message
            } else {
                # stroj nepinga
                $property = @{"Computer" = $computer; "Event" = ""; "Time" = ""; "Message" = "nepinga"}
                $object = New-Object -TypeName PSObject -Property $property
                $object | select computer, event, Time, message
            }
        }
    }

    PROCESS {
        foreach ($Computer in $ComputerName) {
            $AsyncPipelines += Invoke-Async -RunspacePool $pool -ScriptBlock $ScriptBlock -Parameters $Computer, $Newest, $Filter, $days_to_search, $maxMinutes, $bluescreenviewexe_path, $VerbosePreference
        }
    }

    END {
        Receive-AsyncResults -Pipelines $AsyncPipelines -ShowProgress
        # uklid
        # if ($DownloadDestination) {
        #     Remove-Item $DownloadDestination, $ExtractedTools -Confirm:$false -Recurse -Force
        # }
    }
}