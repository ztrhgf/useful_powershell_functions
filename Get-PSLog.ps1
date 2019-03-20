#TODO zrychlit cast, kdyz a dresaru zjistuji logy odpovidajici from/to (joby?)
function Get-PSLog {
    <#
    .SYNOPSIS
    Funkce slouzi k zjisteni, ktere PS log soubory obsahuji pozadovany text, ci byly vytvoreny v nejakem casovem obdobi.
    Ve vychozim nastaveni najde odpovidajici logy, vypise jejich cesty do konzole a zobrazi jejich obsah v notepadu.

    Vytvareni PS logu povolujeme skrze GPO. Do log souboru se uklada to same, jako byste ve skriptu pouzili Start-Transcript!

    .DESCRIPTION
    Funkce slouzi k zjisteni, ktere PS log soubory obsahuji pozadovany text, ci byly vytvoreny v nejakem casovem obdobi.
    Ve vychozim nastaveni najde odpovidajici logy a zobrazi jejich obsah v notepadu.

    Funkce prohledava i archivovane logy ze serveru nejakyserver.

    Vytvareni PS logu povolujeme skrze GPO. Do log souboru se uklada to same, jako byste ve skriptu pouzili Start-Transcript!

    .PARAMETER computerName
    Jmeno stroje z nehoz me zajimaji PS logy

    .PARAMETER searchCommand
    Nepovinny parametr.
    Umoznuje hledani dle nazvu skriptu/prikazu, ktery byl spusten (je uvedeny v atributu Command pri vypisu pomoci -asObject).
    Tzn hleda se prikaz, ktery nasledoval jako parametr procesu powershell.exe. Volani typicky vypada nejak takto:
    powershell.exe -executionpolicy bypass -noprofile -file \\ad.fi.muni.cz\dfs\data\scripts\backup_custom_scheduled_tasks.ps1

    Zadavejte bez wildcard (*) znaku!

    Parametry -searchXXX se pri hledani skladaji pomoci AND. Tzn log musi splnovat vsechny.

    .PARAMETER searchString
    Nepovinny parametr.
    Umoznuje zadat string, ktery se bude hledat v PS lozizch.

    Zadavejte bez wildcard (*) znaku!

    Parametry -searchXXX se pri hledani skladaji pomoci AND. Tzn log musi splnovat vsechny.

    .PARAMETER searchUser
    Nepovinny parametr.
    Umoznuje hledani dle jmena uzivatele, ktery skript spustil (je uvedeny v User atributu pri vypisu pomoci -asObject).

    Zadavejte bez wildcard (*) znaku!

    Parametry -searchXXX se pri hledani skladaji pomoci AND. Tzn log musi splnovat vsechny.

    .PARAMETER from
    Pokud nezadano, nastavi se cas pred hodinou.
    Muzete zadat jako string ve tvaru, ktery si PS umi prevest na DateTime objekt
    napr: 'MM.dd HH:mm' ci 'HH:mm'.
    Nebo predat primo DateTime objekt
    napr: (Get-Date).addHours(-5)

    .PARAMETER to
    Pokud nezadano, nastavi se aktualni cas.
    Muzete zadat jako string ve tvaru, ktery si PS umi prevest na DateTime objekt
    napr: 'MM.dd HH:mm' ci 'HH:mm'.
    Nebo predat primo DateTime objekt
    napr: (Get-Date).addHours(-5)

    .PARAMETER logPath
    Nepovinny parametr.
    Obsahuje cestu, kam ukladame PS logy.

    .PARAMETER asObject
    Prepinac rikajici, ze se ma namisto otevreni log souboru,
    vypsat jejich obsah jako psobjekt do konzole.

    .EXAMPLE
    Get-PSLog -computerName artemis -searchCommand set_PS_environment -from (Get-Date).addDays(-10)

    V notepadu otevre vsechny logy, ktere zaznamenavaji spusteni skriptu set_PS_environment na stroji artemis a to za poslednich 10 dnu.

    .EXAMPLE
    Get-PSLog -searchString error

    V notepadu otevre vsechny logy, ktere obsahuji "error" a byly vytvoreny za posledni hodinu.

    .EXAMPLE
    Get-PSLog -searchString error -searchUser sebela -from '15.12.2018' -to (Get-Date).addDays(-1)

    V notepadu otevre vsechny logy, ktere obsahuji string "error" a skript, ke kteremu log vznikl, spustil uzivatel sebela. A byly vytvoreny od 15.12.2018 do vcerejska.

    .EXAMPLE
    Get-PSLog -from '5:00' -to '8:00' -asObject

    Do konzole vypise objekty reprezentujici jednotlive logy. Ktere vznikly dnes mezi 5 a 8 hodinou na tomto stroji.
    Objekt obsahuje udaje jako: kdo, spustil, kdy, ID procesu, obsah logu,..
    #>

    [CmdletBinding()]
    param (
        [Parameter(Position = 0)]
        [string] $computerName = $env:COMPUTERNAME
        ,
        [string] $searchCommand
        ,
        [string] $searchString
        ,
        [string] $searchUser
        ,
        [ValidateScript( {
                If (($_.getType().name -eq "string" -and [DateTime]::Parse($_)) -or ($_.getType().name -eq "dateTime")) {
                    $true
                } else {
                    Throw "Zadejte ve formatu dle vaseho culture. Pro cs-CZ napr.: 15.2.2019 15:00. Pro en-US pak prohodit den a mesic."
                }
            })]
        $from
        ,
        [ValidateScript( {
                If (($_.getType().name -eq "string" -and [DateTime]::Parse($_)) -or ($_.getType().name -eq "dateTime")) {
                    $true
                } else {
                    Throw "Zadejte ve formatu dle vaseho culture. Pro cs-CZ napr.: 15.2.2019 15:00. Pro en-US pak prohodit den a mesic."
                }
            })]
        $to = (Get-Date)
        ,
        [string] $logPath = "C:\Windows\PSLog"
        ,
        [switch] $asObject
    )

    begin {
        if ($from -and $from.getType().name -eq "string") {$from = [DateTime]::Parse($from)}
        if ($to -and $to.getType().name -eq "string") {$to = [DateTime]::Parse($to)}
        if ($from -and $to -and $from -gt $to) {
            throw "From nesmi byt vetsi nez To"
        }
    }

    process {
        if (!$from) {
            Write-Warning "Nezadali jste from, dohledam maximalne hodinu stare logy"
            $from = (Get-Date).AddHours(-1)
        }

        if ($computerName -notmatch "$env:COMPUTERNAME|localhost|\.") {
            $logPath = "\\$computerName\" + $logPath -replace ":", "$"
        }

        $logToShow = @()
        $folderToSearch = @()

        if (Test-Path $logPath -ErrorAction SilentlyContinue) {
            $folderToSearch += $logPath
        }

        $logBackupFolder = "\\nejakyserver\e$\Backups\PowershellLogs\$computerName"

        if (Test-Path $logBackupFolder -ErrorAction SilentlyContinue) {
            $folderToSearch += $logBackupFolder
        }

        # kvuli rychlosti nejdriv vyfiltruji adresare, ktere mohou obsahovat logy dle zadaneho from/to
        # jak stare udalosti adresar s logy obsahuje detekuji dle jeho nazvu, ktery odpovida yyyMMdd tvaru
        # dle creatimtome ci lastwritetime to nejde, protoze adresare kopiruji a datumy nezachovavam
        Write-Verbose "V $($folderToSearch -join ',') dohledam adresare, ktere mohou obsahovat pozadovane logy"
        $folderToSearch = Get-ChildItem $folderToSearch -Directory | where {[System.DateTime]::ParseExact(($_.name + '2359'), "yyyyMMddHHmm", $null) -ge $from -and [System.DateTime]::ParseExact(($_.name + '0000'), "yyyyMMddHHmm", $null) -le $to} | Select-Object -ExpandProperty fullname
        Write-Verbose "Logy budu hledat v: $($folderToSearch -join ',')"
        # v adresarich dohledam logy, ktere odpovidaji zadanemu from/to
        $logs = Get-ChildItem $folderToSearch -Recurse -Filter "*.txt" -File -Force -ErrorAction SilentlyContinue | where {$_.CreationTime -ge $from -and $_.LastWriteTime -le $to} | Sort-Object LastWriteTime | Select-Object -ExpandProperty fullname
        if (!$logs) {
            Write-Warning "Nenalezen zadny log, ktery vznikl mezi `'$from`' a `'$to`'"
            return
        }

        # prohledam obsah a poznacim logy, ktere odpovidaji hledani
        if ($searchCommand -or $searchString -or $searchUser -or $asObject) {
            $logs | ForEach-Object -begin {$i = 0} -process {
                Write-Progress -Activity "Prohledavam logy" -Status "Progress:" -PercentComplete ($i / $logs.count * 100)
                Write-Verbose "Kontroluji $_"
                ++$i

                $content = Get-Content $_
                # ok znaci, jestli tento logo odpovida zadani
                $ok = 0

                # nekdy je v logu navic radek, pokud ano, posunu indexy nasledujicich radku
                # ! posunuti pouzit az u indexu vyssich jak 5 (nizsi nejsou ovlivneny)
                if ($content[5] -match "Configuration Name: ") {
                    $next = 1
                }

                #
                # poskladam vysledny filtr
                $filter = ''

                if ($searchCommand) {
                    # hledam pouze dle jmena volaneho skriptu

                    # sedmy radek obsahuje cestu k volanemu skriptu
                    $filter += '$content[6 + $next] -match [Regex]::Escape($searchCommand)'
                }
                if ($searchUser) {
                    # hledam dle uzivatele, ktery prikaz spustil
                    if ($filter) {
                        $filter += ' -and '
                    }
                    $filter += '$content[3] -match [Regex]::Escape($searchUser)'
                }
                if ($searchString) {
                    # hledam dle jmena volaneho skriptu nebo zadaneho retezce, ktery by mel byt nekde v danem logu
                    if ($filter) {
                        $filter += ' -and '
                    }
                    $filter += '$content -match [Regex]::Escape($searchString)'
                }

                if (!$filter) {
                    # obsah logu nekontroluji
                    ++$ok
                } elseif ($filter -and (Invoke-Expression $filter)) {
                    # provedu kontrolu obsahu logu, ze odpovida zadani
                    ++$ok
                }

                # tento log chci zobrazit
                if ($ok) {
                    if ($asObject) {
                        # chci obsah logu vratit jako objekt
                        $who = $content[3] -replace "Username: "
                        $who2 = $content[4] -replace "RunAs User: "
                        $what = $content | Select-Object -Skip (20 + $next)
                        $command = $content[6 + $next] -replace "Host Application: "
                        $processID = $content[7 + $next] -replace "Process ID: "
                        $startTime = [System.DateTime]::ParseExact(($content[18 + $next] -replace "Command start time: "), "yyyyMMddHHmmss", $null)
                        if ($content[-2] -match "End time: ") {
                            $endTime = [System.DateTime]::ParseExact(($content[-2] -replace "End time: "), "yyyyMMddHHmmss", $null)
                        }

                        [PSCustomObject] @{ 'User' = $who; 'RunAs' = $who2; 'Command' = $command; 'PID' = $processID; 'Computer' = $computerName; 'StartTime' = $startTime; 'EndTime' = $endTime; 'Content' = $what }
                    } else {
                        # chci log otevrit v notepadu
                        $logToShow += $_
                    }
                }
            }
        } else {
            # nic konkretniho uzivatel nehleda ani nechce vypsat jako objekt, zobrazim vsechny
            $logToShow = $logs
        }

        # nasel jsem nejake logy, vypisi jejich cesty do konzole + je otevru v notepadu
        if ($logToShow) {
            $logToShow = $logToShow | Select-Object -Unique

            "Zadani odpovidaji:"
            $logToShow

            # pokud jsem nalezl vetsi mnozstvi logu, radeji si vyzadam potvrzeni, ze je uzivatel skutecne chce vsechny otevrit
            if (($logToShow).count -gt 5) {
                while ($choice -notmatch "[A|N]") {
                    $choice = Read-Host "Nyni dojde k otevreni $(($logToShow).count) oken s logy. Pokračovat? (A|N)"
                }
                if ($choice -eq "N") {
                    break
                }
            } else {
                "Doslo k otevreni v aplikaci notepad..."
            }

            # otevru nalezene log soubory v aplikaci notepad
            $logToShow | % {
                notepad $_
            }
        }
    }

    end {
    }
}