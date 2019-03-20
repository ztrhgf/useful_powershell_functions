Function Write-Log {
    <#
	.SYNOPSIS
		Zapise predany text do konzole i log souboru.

	.DESCRIPTION
		Zapise predany text do konzole i log souboru.
		Lze jej zapsat i do systemoveho event logu (ToEventLog) ci poslat mailem (SendEmail).
		Pokud log soubor prekroci velikost 5 MB, original se prejmenuje a vytvori se novy s identickym jmenem.
		Podrobnosti ohledne vysledne cesty k log souboru a jeho pojmenovani v popisu parametru Path. 

		TIP:
		Pokud Write-Log budete volat v nejake fci s nejakymi explicitnimi parametry (napr zadanou cestou k log souboru),
		muzete pro danou scope nastavit vychozi parametry teto funkce pomoci PS promenne $PSDefaultParameterValues takto:
		$PSDefaultParameterValues = @{'Write-Log:Path'= '.\output.log'}
		a pak se pri kazdem volani Write-Log nastavi v parametru Path hodnota '.\output.log' 

	.PARAMETER Message 
		Text, ktery se ma vypsat.

		Pokud dojde k predani neceho jineho nez stringu, tak se provede prevod pomoci Out-String
		
	.PARAMETER Level 
		Typ zpravy. Moznosti jsou: Error, Warning, Host (Info), Verbose a Output. Dle toho, jaky Write-X se ma pouzit a jaka systomova udalost se ma zapsat do logu.

		Vychozi je Host (tedy Write-Host).
	
	.PARAMETER NoConsoleOut 
		Prepinac zpusobi, ze se zprava jen zaloguje do souboru (pripadne systemoveho logu), ale do konzole se nevypise.
	
	.PARAMETER ConsoleForeground 
		Specifikuje, jaka barva textu se ma pouzit. Da se nastavit pouze pro level = Host.
		Tento level totiz pro vypis pouziva cmdlet Write-Host.
	
	.PARAMETER Indent 
		Pocet mezer, kterymi se ma odsadit text v log souboru.
	
	.PARAMETER Path 
		Cesta k souboru, do ktereho se ma zalogovat message. Napr.: C:\temp\MyLog.log

		Pokud nezadano, tak se postupuje nasledovne:
		Pokud bude volano z konzole, tak bude pojmenovan: psscript.log jinak dle skriptu/modulu, ze ktereho je volano napr.: scripts.ps1.log.
		Pokud je navic volano ve funkci umistene v skriptu/modulu, tak vysledne pojmenovani bude ve tvaru jmenoskriptu_jmenofunkce.log (napr. scripts.ps1_get-process.log)

		Umisti se do slozky Logs, umistene v adresari ve kterem je skript/modul, ze ktereho se volalo nebo do aktualniho pracovniho adresare (pri volani z konzole).
		Pokud se nepodari ulozit do slozky volaneho skriptu, tak se ulozi do uzivatelova TEMP\Logs adresare ($env:TEMP)
	
	.PARAMETER OverWrite 
		Prepinac rikajici, ze se existujici log prepise. Defaultne se text jen prida.
	
	.PARAMETER ToEventLog
		Prepinac rikajici, ze se ma vystup zalogovat i do systemoveho logu. 
		Vychozi je zapis do logu 'Application', source WSH. ID udalosti dle nastaveni Level parametru.

	.PARAMETER EventLogName 
		Jmeno systemoveho logu, do ktereho se ma zalogovat napr. 'System'.
		
		Vychozi je 'Application'.
	
	.PARAMETER EventSource 
		Source, jaky se ma pouzit pri vytvareni udalosti v systemovem logu.
		Pokud takovy Source nebude existovat, tak jej skript zkusi vytvorit a pouzit. Na to vsak musi byt spusten s admin pravy! (jinak skonci chybou)

		Vychozi je 'WSH' protoze jde o jediny Source, pod kterym se da zapisovat do Application logu. 
		A do nej chci zapisovat, protoze typicky ma velkou velikost a udalosti v nem vydrzi i nekolik mesicu narozdil napr. od Windows Powershell logu.
		Jeste lepsi by byl System log, ale do nej ne-admin nemuze zapisovat...
	
	.PARAMETER EventID  
		ID, jake se ma pouzit pri vytvareni udalosti v systemovem logu.

		Vychozi je 9999.
	
	.PARAMETER LogEncoding 
		Jak se ma kodovat obsah log souboru.
		Vychozi je UTF8.

	.PARAMETER ErrorRecord
		Do tohoto parametru mohu predat pouze objekt typu [System.Management.Automation.ErrorRecord] tzn. typicky zabudovanou powershell $Error promennou. 
		Kazdy zaznam obsazeny v $Error se rozparsuje, ulozi do souboru/posle mailem a vypise do konzole pod urovni Error
		Pokud chci vypsat jen konkretni chybu, musim ji predat ve tvaru: $Error[0].
		
	.PARAMETER SendEmail
		Prepinac rikajici, ze se dana zprava ma poslat i emailem.
		Urceno typicky pro pripady, kdy dojde k neocekavane chybe a ja to krome zalogovani ji chci i dostat mailem.
		Pouzije se k tomu custom fce Send-Email (vetsina parametru Send-Email je default).
		Tzn email se posle na aaa@bbb.cz z monitoring@fi.muni.cz pres relay.fi.muni.cz. 
		Subjekt je ve tvaru jmeno funkce, ze ktere se Write-Log volal a jmena pocitace.
		Body obsahuje to co se ma zapsat do log souboru.

	.PARAMETER To
		Seznam prijemcu emailu.
		
        Vychozi je dle nastaveni Send-Email (aaa@bbb.cz).
        
	.PARAMETER Subject
		Subject emailu.
		
        Vychozi je ve tvaru "co na jakem pc"
        
	.PARAMETER AttachLog
		Prepinac rikajici, ze se k emailu ma prilozit i log soubor, do ktereho aktualne loguji.

	.EXAMPLE
		Write-Log -Message "OK"

		Zpravu vypise jak do konzole, tak do souboru. Jeho umisteni a jmeno zalezi na okolnostech viz help k parametru Path.

	.EXAMPLE
		Write-Log -Message "OK" -Path C:\temp\MyLog.log -OverWrite -ForegroundColor Green

		Zpravu vypise jak do konzole (zelenou barvou), tak do C:\temp\MyLog.log. Pokud jiz existuje, tak jej prepise.

	.EXAMPLE
		Write-Log -Message "Neco se nepovedlo" -Path C:\temp\MyLog.log -Level Warning

		Zpravu vypise jak do konzole (skrze Write-Warning), tak do C:\temp\MyLog.log.

	.EXAMPLE
		Write-Log -Message "Objevila se chyba!" -Path C:\temp\MyLog.log -Level Error -ErrorRecord $Error[0]

		Zpravu vypise jak do konzole (skrze Write-Error), tak do C:\temp\MyLog.log a to vec tne podrobnosti ziskanych z $Error objektu.

	.EXAMPLE
		Write-Log -Message "NOK" -Path C:\temp\MyLog.log -ToEventLog -Level Verbose

		Zpravu vypise jak do konzole (skrze Write-Verbose), tak do C:\temp\MyLog.log a systemoveho logu, konkretne logu Application, s ID 9999 a Source 'WSH'.

	.EXAMPLE
		Write-Log -Message "NOK" -Path C:\temp\MyLog.log -SendEmail -Level Warning -AttachLog

		Zpravu vypise jak do konzole (skrze Write-Warning), tak do C:\temp\MyLog.log a posle ji emailem na aaa@bbb.cz (vychozi adresa ve fci Send-Email).
		
	.EXAMPLE
		Write-Log -Message "NOK" -Path C:\temp\MyLog.log -SendEmail -Level Error -to sebela@fi.muni.cz

		Zpravu vypise jak do konzole (skrze Write-Error), tak do C:\temp\MyLog.log a posle ji emailem na uvedenou adresu.
		
	.NOTES
		Pri pouziti SendEmail prepinace musi byt k dispozici custom funkce Send-Email!
	#>

    [cmdletbinding()]
    Param(
        [Parameter(ValueFromPipeline = $True, Position = 0)]
        $Message
        ,
        [Parameter(Position = 1)] 
        [ValidateSet("Error", "Warning", "Host", "Output", "Verbose", "Info")]
        [string] $Level = "Host"
        ,
        [Parameter(Position = 2)] 
        [ValidateSet("Black", "DarkBlue", "DarkGreen", "DarkCyan", "DarkRed", "DarkMagenta", "DarkYellow", "Gray", "DarkGray", "Blue", "Green", "Cyan", "Red", "Magenta", "Yellow", "White")]
        [Alias("ConsoleForeground")]
        [String] $ForegroundColor = 'White'
        ,
        [Parameter(Position = 3)] 
        [ValidateRange(1, 30)]
        [Int16] $Indent = 0
        ,
        [Parameter()]
        [Switch] $NoConsoleOut
        ,
        [Parameter()]
        [ValidateScript( {Test-Path $_ -IsValid})]
        [ValidateScript( {$_ -match '\.\w+'})] # melo by jit o cestu k souboru, ocekavam ve tvaru .txt ci neco podobneho
        [string] $Path
        ,
        [Parameter()]
        [Switch] $OverWrite
        ,
        [Parameter()]
        [Switch] $ToEventLog
        ,
        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [String] $EventLogName = 'Application'
        ,
        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [String] $EventSource = 'WSH'
        ,
        [Parameter()]
        [Int32] $EventID
        ,
        [Parameter()]
        [String] $LogEncoding = "UTF8"
        ,
        [Parameter()]
        [System.Management.Automation.ErrorRecord[]] $ErrorRecord
        ,
        [Parameter()]
        [Switch] $SendEmail
        ,
        [Parameter()]
        [string] $To
        ,
        [Parameter()]
        [string] $Subject
        ,
        [Parameter()]
        [switch] $AttachLog
    )

    Begin {
        if (!$Message -and !$ErrorRecord) {
            throw "Nezadali jste ani message ani ErrorRecord!"
        }

        # pokud bude omylem predano neco jineho nez string (typicky objekt), tak prevedu
        if ($Message -and $Message.gettype() -ne 'String') {
            $Message = $Message | Out-String
        }

        if (($To -or $Subject -or $AttachLog) -and !$SendEmail) {
            throw "Zadali jste to, subject ci attachlog, ale nezadali SendEmail. Nedava smysl"
        }

        # odvozeni pojmenovani logu z volaneho skriptu/funkce/modulu
        if (!$Path) {
            #
            # ziskam umisteni log souboru
            #

            # jmeno sebe sama (Write-Log)
            $MyName = $MyInvocation.MyCommand.Name
            # poznacim si, ze cestu k logu sestavuji ja, nebyla zadana uzivatelem
            ++ $calculatedPath

            # co zavolalo Write-Log (ze seznamu volajicich odeberu jmeno teto funkce (Write-Log) a <ScriptBlock>
            # a vyberu uplne posledniho volajiciho
            $lastCaller = Get-PSCallStack | where {$_.Command -ne $MyName -and $_.command -ne "<ScriptBlock>"} | select -Last 1

            # zkusim zjistit cestu skriptu/modulu odkud je write-log volano
            $scriptName = ($lastCaller).scriptName
            if ($scriptName) {
                try { $ScriptDirectory = Split-Path $scriptName -Parent -ea Stop } catch {}
            }
            # neni volano ze skriptu/modulu pouziji cestu aktualniho pracovniho adresare
            if (!$ScriptDirectory) { $ScriptDirectory = (Get-Location).path }
            # nepodarilo se ziskat aktualni pracovni adresar, ulozim do slozky kde je umistena tato funkce
            if (!$ScriptDirectory) { $ScriptDirectory = $PSScriptRoot }

            #
            # ziskam pojmenovani log souboru
            #

            # vychozi pojmenovani logu, pokud nenajdu presnejsi pojmenovani
            $CallerName = 'psscript'
            # volam li write-log z nadrazene fce, tak jeji jmeno pouziji pro pojmenovani log souboru
            if ($lastCaller) {
                # jmeno funkce/skriptu/modulu, ze ktereho se Write-Log zavolalo
                $CallerName = $lastCaller | select -exp command -Last 1 		 
                $command = $lastCaller.command

                # volano ze souboru
                if ($scriptName) {
                    $filename = (split-path $scriptName -Leaf)
                    if ($command -ne $filename) {
                        $CallerName = $($filename -replace "\.\w+$") + '_' + $command # odeberu koncovku souboru
                    } else {
                        $CallerName = $command 
                    }
                } else {
                    # volano z konzole/funkce
                    $CallerName = $command 
                }	
            }

            # aby pri volani z konzole nelogovalo do Write-Log.log
            if (!$CallerName -or $CallerName -eq $MyName) {
                $CallerName = 'psscript'
            } 
			
            $Path = Join-Path $ScriptDirectory "Logs\$CallerName.log"
        }

        # hodnotu 'Host' pouzivam pouze aby bylo zrejme, ze se pouzije Write-Host, pozdeji s hodnotou Level ale pracuji a vic se mi hodi 'Info'
        if ($Level -eq 'Host') { $Level = 'Info' }
    }

    Process {
        try {

            #	
            # vypisu do konzole
            #

            $ErrorActionPreference = 'continue'

            if ($NoConsoleOut -eq $False) {
                if ($Message) {
                    switch ($Level) {
                        'Error' { Write-Error $Message }
                        'Warning' { Write-Warning $Message }
                        'Info' { Write-Host $Message -ForegroundColor $ForegroundColor -NoNewline}
                        'Output' { Write-Output $Message }
                        'Verbose' { Write-Verbose $Message }
                    }
                }

                $ErrorActionPreference = 'stop' # musi byt az za Write-Error jinak se ukoncil tento try blok :)
                
                # vypisi i predane errory
                # nevypisuji pomoci write-host abych $Error neplnil duplicitnimi chybami
                if ($ErrorRecord -and $Message) {
                    # vypisu jen text chyby
                    $ErrorRecord | % { Write-Output $('{0}, {1}' -f $_.Exception.Message, $_.FullyQualifiedErrorId) } 
                } elseif ($ErrorRecord -and !$Message) {
                    # vypisu krome chyby i uvodni text
                    $ErrorRecord | % { Write-Output $('{0}{1}, {2}' -f "Objevily se chyby:`n", $_.Exception.Message, $_.FullyQualifiedErrorId) }
                }
            }

            #
            # zapisu text do log souboru
            #
			
            # vytvoreni finalniho textu, ktery se zapise do log souboru a pripadne i posle mailem
            $Message = $Message.TrimEnd()
            if ($Message -and $Message.contains("`n")) {
                # vsechny radky message budou odsazeny, ne jen prvni
                $Message = @($Message -split "`n")
                # prvni radek
                $msg = '{0}{1} : {2} : {3}' -f (" " * $Indent), (Get-Date -Format s), $Level.ToUpper(), $Message[0]
                # nasledujici radky message
                for ($i = 1; $i -le $Message.count; $i++) {
                    $msg += '{0}{1}{2}' -f "`n", (" " * $Indent), $Message[$i]
                }
            } else {
                # message neni viceradkovy
                $msg = '{0}{1} : {2} : {3}' -f (" " * $Indent), (Get-Date -Format s), $Level.ToUpper(), $Message
            }

            # pokud predal i $Error objekt, tak jej rozparsuji a pridam do vypisu
            if ($ErrorRecord) { 
                $ErrorRecord | % {
                    $msg += "`r`n" + '{0}{1} : {2} : {3}: {4}:{5} char:{6}' -f (" " * $Indent), (Get-Date -Format s), 'ERROR', $_.Exception.Message, 
                    $_.FullyQualifiedErrorId,
                    $_.InvocationInfo.ScriptName,
                    $_.InvocationInfo.ScriptLineNumber,
                    $_.InvocationInfo.OffsetInLine
                }
            }

            # mutex kvuli ochrane pred chybami pri pokusu o simultani zapis vice procesu do stejneho souboru
            try {
                $mutex = New-Object -TypeName 'Threading.Mutex' -ArgumentList $false, 'MyInterprocMutex' -ErrorAction Stop
            } catch {
                # uz se mi stalo, ze koncilo chybou Access Denied, ale s jinym jmenem mutexu vytvorit slo
                $mutex = New-Object -TypeName 'Threading.Mutex' -ArgumentList $false, 'MyInterprocMutex2'
            }

            $CommandParameters = @{
                FilePath    = $Path
                Encoding    = $LogEncoding
                ErrorAction = 'stop'
            }

            if ($OverWrite) {
                $CommandParameters.Add("Force", $true)
            } else {
                $CommandParameters.Add("Append", $true)
            }

            # vytvoreni log souboru
            # pokud cestu nezadal uzivatel, mel by se log zapsat do adresare se skriptem, kam ale nemusi mit uzivatel pravo zapisu
            # v tom pripade zkusim zapsat log do uzivatelova temp adresare (catch blok)
            if ($calculatedPath) {
                # uzivatel nezadal cestu k logu, zkousim ulozit v adresari se skriptem, ze ktereho se Write-Log volalo, v pripade chyby zkusim vytvorit log jeste v $env:TEMP
                $ErrorActionPreference = 'silentlycontinue'
            } else {
                # uzivatel zadal cestu k log souboru, pokud nepujde ulozit, tak nebudu zkouset jej ulozit jinam
                $ErrorActionPreference = 'stop'
            }

            # pokud se ma log ulozit do dosud neexistujiciho adresare, zkusim jej vytvorit
            [Void][System.IO.Directory]::CreateDirectory($(Split-Path $Path -Parent))
            if (!(Test-Path $Path)) {
                New-Item -Path $Path -ItemType File -Force | Out-Null
            } elseif (!$OverWrite) {
                # log soubor jiz existuje a nema se prepsat
                ++$Exists
            }	
                
            # overim, ze mam pravo zapisu
            if (Test-Path $Path) {   
                try {  
                    Write-Verbose "Cesta $Path existuje, otestuji jestli mam write pravo"
                    $oldErrPref = $ErrorActionPreference
                    $ErrorActionPreference = 'stop'
                    [io.file]::OpenWrite($Path).close() # bacha pokud by soubor neexistoval, tak jej vytvori
                } catch {
                    Write-Verbose "nemam"
                    ++$accessDenied
                }    
                $ErrorActionPreference = $oldErrPref
            }
            $ErrorActionPreference = 'stop'

            if (!(Test-Path $Path) -or $accessDenied) {
                Write-Verbose "Log se nepodarilo ulozit do $Path, zkusim to do $env:TEMP\Logs"
                # nepodarilo se vytvorit log v adresari se skriptem, ze ktereho byl spusten
                # zkusim to znovu, ale s cestou do uzivatelova TEMP adresare, kam by mel mit pravo zapisu
                $calculatedLogName = Split-Path $Path -leaf
                $Path = Join-Path "$env:TEMP\Logs" $calculatedLogName

                # vytvorim v danem adresari slozku Logs, do ktere pote ulozim vysledny log soubor
                [Void][System.IO.Directory]::CreateDirectory($(Split-Path $Path -Parent))

                $CommandParameters.FilePath = $Path

                if (!(Test-Path $Path -ErrorAction SilentlyContinue)) {
                    New-Item -Path $Path -ItemType File -Force | Out-Null
                } elseif (!$OverWrite) {
                    # log soubor jiz existuje a nema se prepsat
                    ++$Exists
                }
            }

            # pockam az bude mozne do souboru zapisovat
            Write-Verbose "Pockam nez se uvolni pripadny lock na souboru"
            try {
                $mutex.waitone() | Out-Null
            } catch {
                Write-Verbose "nepovedlo se"    
            }
            # log je jiz prilis velky, prejmenuji jej a vytvorim novy se stejnym jmenem
            # (aby logy nerostly neumerne a nebyl problem s jejich ctenim/posilani mailem)
            if ($Exists -and ((Get-Item $Path).Length / 1MB -gt 5)) {
                Rename-Item $Path ((Get-Item $Path).BaseName + '_' + (Get-Date -Format yyyyMMddHHmm) + (Get-Item $Path).Extension)
            }
            # zapisu info do logu
            Write-Verbose "zapisuji"
            $msg | Out-File @CommandParameters
            $mutex.ReleaseMutex() | Out-Null
			
            # zkontroluji ze se povedlo zapsat do log souboru
            if (!(Test-Path $Path -ErrorAction SilentlyContinue)) {
                throw "Nepovedlo se vytvorit/zapsat do log souboru $path"
            }


            #
            # zapsani do event logu
            #
            if ($ToEventLog) {
                # otestuji existenci zadaneho Source (ktery jakoze vytvari ten zaznam)
                if (-not [Diagnostics.EventLog]::SourceExists($EventSource)) { 
                    # neexistuje, tak otestuji jestli mam pravo jej vytvorit
                    if (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
                        throw "Bez admin prav neni mozne vytvaret EventSource. Zadejte existujici EventSource nebo spustte s admin pravy."
                    }
                    # vytvorim zadany Source
                    [Diagnostics.EventLog]::CreateEventSource($EventSource, $EventLogName) 
                } 

                # dle zadane urovne nastavim pomocne promenne pro pouziti k zapisu do systemoveho logu
                switch ($Level) {
                    "Error" { $lvl = 1; $entryType = 'Error' }
                    "Warning" { $lvl = 2; $entryType = 'Warning' }
                    "Info" { $lvl = 4; $entryType = 'Information' }
                    "Output" { $lvl = 4; $entryType = 'Information' }
                    "Verbose" { $lvl = 4; $entryType = 'Information' }
                }

                # uzivatel nezadal source, pod kterym se ma event zapsat
                # zapisu do aplikacniho logu pod source WSH a ID dle typu udalosti
                if ($EventSource -eq 'WSH') {
                    # vytvorim objekt wscript shellu
                    $WSH = New-Object -com WScript.Shell

                    # zapisu udalost do application systemoveho logu kde zdrojem je WSH (wscript shell), jde o jediny source, pod kterym muze do application zapisovat bezny uzivatel
                    # navic takto zalozka General v event logu u daneho eventu bude obsahovat pouze predany message a ne kecy typu "The description for Event ID 4 from source WSH cannot be found...."
                    $WSH.LogEvent($lvl, $msg.TrimStart()) | out-null

                    # zaloguji i predane chyby
                    if ($ErrorRecord) {
                        $WSH.LogEvent(1, $(($ErrorRecord | Out-String).TrimStart())) | out-null
                    }
                } else {
                    # uzivatel zmenil source, pod kterym se ma event zapsat
					
                    # uzivatel nezadal EventID, nastavim vlastni
                    if (!$EventID) { $EventID = 9999 }
					
                    # tento postup by mel fungovat i na systemech, kde neni write-eventlog cmdlet
                    # vytvorim objekt systemove udalosti
                    $log = New-Object System.Diagnostics.EventLog  
                    $log.set_log($EventLogName)  
                    $log.set_source($EventSource) 
                    # zapisu udalost do systemoveho logu
                    $log.WriteEntry($Message, $entryType, $EventID)

                    # zaloguji i predane chyby
                    if ($ErrorRecord) {
                        $log.WriteEntry($(($ErrorRecord | Out-String).TrimStart()), 'Error', $EventID)
                    }
					
                    if (! $?) {
                        # byla chyba
                        throw $error[0]
                    }
                }
            }


            #
            # poslani emailem
            #
            if ($SendEmail) {
                if (! (Get-Command Send-Email -ea SilentlyContinue)) {
                    throw "Neni k dispozici prikaz Send-Email pro poslani emailove zpravy!"
                }

                # nastavim parametry odeslani emailu
                # zamerne neumoznuji nic moc nastavit, aby tvar emailu byl standardizovan kvuli prehlednosti
                if (!$Subject) {
                    $Subject = "$CallerName na $($env:COMPUTERNAME)"
                }
                $Params = @{
                    Subject = $Subject
                    Body    = $msg.TrimStart() # pripadny indent zde nema smysl
                }

                # ma se prilozit i log soubor
                if ($AttachLog) { 
                    <# kontroly velikosti nejsou potreba, protoze pri prekroceni velikosti 5MB vytvorim novy log soubor, pokud bych zrusil, tak odkomentovat 
					$LogSize = (Get-Item $Path).length/1MB
					$MaxSize = 5
					# emaily mohou obsahovat jen omezenou velikost souboru, pro jistotu povoluji poslat max 5MB soubory (lepsi aby email prisel bez logu nez vubec)
					if ($LogSize -le $MaxSize) {
					#>
                    $Params.Add("Attachment", $Path) 

                    <#					
					} else {
						# log soubor je prilis velky pro poslani emailem
						# informuji o tom prijemce
						$Params.Body += "`n`n`nMel se poslat i log soubor, ale je prilis velky. Najdete jej zde: $Path."
					}
					#>				
                }

                # uzivatel explicitne zadal, komu se ma email poslat
                if ($To) { $Params.Add("To", $To) }
				
                Send-Email @params -ea stop
            }
        } catch {
            throw "Objevila se chyba: $_."
        }
    } #End Process

    End {}
}