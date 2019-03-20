#TODO log muze byt i najinem miste, dokonce kazdy fw profil jej muze mit jinde, zjistit prikazem: netsh advfirewall show allprofiles | Select-String Filename | % { $_ -replace "%systemroot%",$env:systemroot } ale to bych teda musel zjistovat na danem stroji (invoke-command)
function Get-FirewallLog {
    <#
    .SYNOPSIS
    Funkce do konzole, pomoci Out-GridView ci cmtrace vypise aktualni obsah FW logu na zadanem stroji.
    Podle zadaneho from/to se pripadne zaznamy zobrazi z archivu logu na zalohovacim serveru.

    .DESCRIPTION
    Funkce do konzole, pomoci Out-GridView ci cmtrace vypise aktualni obsah FW logu na zadanem stroji.
    Podle zadaneho from/to se pripadne zaznamy zobrazi z archivu logu na zalohovacim serveru.

    .PARAMETER computerName
    Jmeno stroje, z nehoz se vypise FW log.

    .PARAMETER live
    Prepinac rikajici, ze se bude do konzole vypisovat realtime obsah logu.
    Pro lepsi citelnost se obsah formatuje pomoci Format-Table.

    .PARAMETER ogv
    Prepinac rikajici, ze se ma vystup vypsat pomoci Out-GridView.
    Vyhoda je, ze Out-GridView umoznuje filtrovani, ale zase nebude realtime.

    .PARAMETER cmtrace
    Prepinac rikajici, ze se ma log otevrit v cmtrace toolu.
    Vyhoda je, ze cmtrace ukazuje realtime data, ale zase neumi pokrocile filtrovani.

    .PARAMETER from
    Od jakeho casu se ma vypisovat obsah logu.
    Zadavejte datum ve tvaru dle vaseho culture. Tzn pro ceske napr 15.3.2019 15:00. Pro anglicky pak prohodit mesic a den.

    .PARAMETER to
    Do jakeho casu se ma vypisovat obsah logu.
    Zadavejte datum ve tvaru dle vaseho culture. Tzn pro ceske napr 15.3.2019 15:00. Pro anglicky pak prohodit mesic a den.

    .PARAMETER dstPort
    Cislo ciloveho portu.

    .PARAMETER srcPort
    Cislo zdrojoveho portu.

    .PARAMETER dstIP
    Cilova IP.

    .PARAMETER srcIP
    Zdrojova IP.

    .PARAMETER action
    Typ FW akce.
    allow ci drop

    .PARAMETER protocol
    Jmeno pouziteho protokolu.
    tcp, udp, ...

    .PARAMETER path
    Smer komunikace.
    receive, send

    .PARAMETER logPath
    Lokalni cesta k firewall logu.
    Vychozi je "C:\System32\LogFiles\Firewall\pfirewall.log".
    Zmente pouze pokud se logy ukladaji jinde.

    .EXAMPLE
    Get-FirewallLog -live

    Zacne do konzole vypisovat realtime obsah FW logu ($env:windir\System32\LogFiles\Firewall\pfirewall.log).

    .EXAMPLE
    Get-FirewallLog -live -dstPort 3389 -protocol TCP -action allow

    Zacne do konzole vypisovat realtime obsah FW logu ($env:windir\System32\LogFiles\Firewall\pfirewall.log).
    A to pouze zaznamy kde cilovy port je 3389, protokol TCP a komunikace byla povolena.

    .EXAMPLE
    Get-FirewallLog -live -action drop

    Zacne do konzole vypisovat realtime obsah FW logu ($env:windir\System32\LogFiles\Firewall\pfirewall.log).
    A to pouze dropnutou komunikaci.

    .EXAMPLE
    Get-FirewallLog -computerName titan01

    Vypise do konzole obsah FW logu ($env:windir\System32\LogFiles\Firewall\pfirewall.log) ze stroje titan01.

    .EXAMPLE
    Get-FirewallLog -computerName titan01 -ogv

    Vypise pomoci Out-GridView obsah FW logu ($env:windir\System32\LogFiles\Firewall\pfirewall.log) ze stroje titan01.

    .EXAMPLE
    Get-FirewallLog -computerName titan01 -ogv -from ((Get-Date).addminutes(-10)) -srcIP 147.251.48.120

    Vypise pomoci Out-GridView obsah FW logu ($env:windir\System32\LogFiles\Firewall\pfirewall.log) ze stroje titan01.
    A to pouze zaznamy za poslednich 10 minut pochazejici z adresy 147.251.48.120.

    .EXAMPLE
    Get-FirewallLog -ogv -from "12/7/2018 6:59:42"

    Vypise pomoci Out-GridView obsah FW logu ($env:windir\System32\LogFiles\Firewall\pfirewall.log).
    A to pouze zaznamy od 7 prosince 6:59:42.

    .EXAMPLE
    Get-FirewallLog -computerName titan01 -cmtrace

    Vypise pomoci cmtrace.exe obsah FW logu ($env:windir\System32\LogFiles\Firewall\pfirewall.log) ze stroje titan01.
    #>

    [CmdletBinding(DefaultParameterSetName = "default")]
    param (
        [Parameter(Position = 0, ParameterSetName = "default")]
        [Parameter(Position = 0, ParameterSetName = "live")]
        [Parameter(Position = 0, ParameterSetName = "ogv")]
        [Parameter(Position = 0, ParameterSetName = "cmtrace")]
        [string] $computerName = $env:COMPUTERNAME
        ,
        [Parameter(ParameterSetName = "live")]
        [switch] $live
        ,
        [Parameter(ParameterSetName = "ogv")]
        [switch] $ogv
        ,
        [Parameter(ParameterSetName = "cmtrace")]
        [switch] $cmtrace
        ,
        [Parameter(ParameterSetName = "default")]
        [Parameter(ParameterSetName = "live")]
        [Parameter(ParameterSetName = "ogv")]
        [Parameter(ParameterSetName = "cmtrace")]
        [ValidateScript( {
                If (($_.getType().name -eq "string" -and [DateTime]::Parse($_)) -or ($_.getType().name -eq "dateTime")) {
                    $true
                } else {
                    Throw "Zadejte ve formatu dle vaseho culture. Pro cs-CZ napr.: 15.2.2019 15:00. Pro en-US pak prohodit den a mesic."
                }
            })]
        $from
        ,
        [Parameter(ParameterSetName = "default")]
        [Parameter(ParameterSetName = "live")]
        [Parameter(ParameterSetName = "ogv")]
        [Parameter(ParameterSetName = "cmtrace")]
        [ValidateScript( {
                If (($_.getType().name -eq "string" -and [DateTime]::Parse($_)) -or ($_.getType().name -eq "dateTime")) {
                    $true
                } else {
                    Throw "Zadejte ve formatu dle vaseho culture. Pro cs-CZ napr.: 15.2.2019 15:00. Pro en-US pak prohodit den a mesic."
                }
            })]
        $to
        ,
        [Parameter(ParameterSetName = "default")]
        [Parameter(ParameterSetName = "live")]
        [Parameter(ParameterSetName = "ogv")]
        [ValidateNotNullOrEmpty()]
        [int[]] $dstPort
        ,
        [Parameter(ParameterSetName = "default")]
        [Parameter(ParameterSetName = "live")]
        [Parameter(ParameterSetName = "ogv")]
        [ValidateNotNullOrEmpty()]
        [int[]] $srcPort
        ,
        [Parameter(ParameterSetName = "default")]
        [Parameter(ParameterSetName = "live")]
        [Parameter(ParameterSetName = "ogv")]
        [ValidateNotNullOrEmpty()]
        [ipaddress[]] $dstIP
        ,
        [Parameter(ParameterSetName = "default")]
        [Parameter(ParameterSetName = "live")]
        [Parameter(ParameterSetName = "ogv")]
        [ValidateNotNullOrEmpty()]
        [ipaddress[]] $srcIP
        ,
        [Parameter(ParameterSetName = "default")]
        [Parameter(ParameterSetName = "live")]
        [Parameter(ParameterSetName = "ogv")]
        [ValidateSet("allow", "drop")]
        [string] $action
        ,
        [Parameter(ParameterSetName = "default")]
        [Parameter(ParameterSetName = "live")]
        [Parameter(ParameterSetName = "ogv")]
        [ValidateScript( {$_ -match '^[a-z]+$'} )]
        [string[]] $protocol
        ,
        [Parameter(ParameterSetName = "default")]
        [Parameter(ParameterSetName = "live")]
        [Parameter(ParameterSetName = "ogv")]
        [ValidateSet("receive", "send")]
        [string] $path
        ,
        [Parameter(ParameterSetName = "default")]
        [Parameter(ParameterSetName = "live")]
        [Parameter(ParameterSetName = "ogv")]
        [Parameter(ParameterSetName = "cmtrace")]
        [ValidateNotNullOrEmpty()]
        $logPath = "C:\Windows\System32\LogFiles\Firewall\pfirewall.log"
    )

    begin {
        if ($from -and $from.getType().name -eq "string") {$from = [DateTime]::Parse($from)}
        if ($to -and $to.getType().name -eq "string") {$to = [DateTime]::Parse($to)}
        if ($from -and $to -and $from -gt $to) {
            throw "From nesmi byt vetsi nez To"
        }

        if ($computerName -notmatch "$env:COMPUTERNAME|localhost|\.") {
            $logPath = "\\$computerName\" + $logPath -replace ":", "$"
        }

        if (Test-Path $logPath -ErrorAction SilentlyContinue) {
            $logToShow = @($logPath)
        }

        if ($from -or $to) {
            # pokud uzivatele zajima konkretni datum, teprve zacnu resit moznost, ze budu muset prozkoumat i .old log ci archiv logu

            #
            # vytvorim seznam dostupnych logu pro zadany stroj
            # do seznamu pridavam od nejstarsich, abych jej nemusel pozdeji slozite radit
            $availableLogs = @()
            # pridam logy z CVT archivu
            $logBackupFolder = "\\nejakyserver\e$\Backups\FirewallLogs\$computerName"
            if (Test-Path $logBackupFolder -ErrorAction SilentlyContinue) {
                $availableLogs += Get-ChildItem $logBackupFolder -Filter *.log -ErrorAction SilentlyContinue | Sort-Object -Property LastWriteTime | Select-Object -ExpandProperty FullName
            }
            # Windows si automaticky uklada predchozi verzi logu do souboru s koncovkou .old
            # .old soubory automaticky zalohuji na backup server, proto uz v puvodnim umisteni nemusi byt
            $logOldpath = Join-Path $(Split-Path $logPath -Parent) "pfirewall.log.old"
            if (Test-Path $logOldpath -ErrorAction SilentlyContinue) {
                $availableLogs += $logOldpath
            }
            # pridam aktualni FW log soubor
            if (Test-Path $logPath -ErrorAction SilentlyContinue) {
                $availableLogs += $logPath
            }

            #
            # udelam si hash s lastwritetime a zejmena creationTime, ktery se neda ziskat z atributu souboru, protoze obsahuje nesmyslne udaje
            # creationTime teda plnim tak, ze pouziji  lastWriteTime predchoziho logu + 1 vterina
            $logProperty = @{}
            $availableLogs | % {
                $lastWriteTime = (Get-Item $_).LastWriteTime
                $position = $availableLogs.indexOf($_)
                if ($position -eq 0) {
                    $creationTime = (Get-Date ((Get-Item $_).LastWriteTime)).addDays(-1)
                } else {
                    $creationTime = (Get-Date ((Get-Item ($availableLogs[$position - 1])).LastWriteTime).AddSeconds(1))
                }

                $logProperty.$_ = [PSCustomObject] @{path = $_; CreationTime = $creationTime; LastWriteTime = $lastWriteTime}
            }

            #
            # do logToShow ulozim logy, ktere mohou realne obsahovat hledane udaje (dle from/to)
            $logToShow = $availableLogs
            if ($from) {
                $logToShow = $logToShow | Where-Object {
                    $logPath = $_
                    $logProperty.$logPath.LastWriteTime -ge $from
                }
            }
            if ($to) {
                $logToShow = $logToShow | Where-Object {
                    $logPath = $_
                    $logProperty.$logPath.CreationTime -le $to
                }
            }
        }

        Write-Verbose "Zobrazim obsah:`n$($logToShow -join ', ')"

        if (!$logToShow) {
            throw "Zadne logy k zobrazeni"
        }

        $command = "Get-Content $($logToShow -join ',') -ReadCount 10000"

        if ($live) {
            $command += ' -Wait'
        }

        $command += ' | ConvertFrom-Csv -Delimiter " " -Header "date", "time", "action", "protocol", "src-ip", "dst-ip", "src-port", "dst-port", "size", "tcpflags", "tcpsyn", "tcpack", "tcpwin", "icmptype", "icmpcode", "info", "path" | Select-Object @{n = "dateTime"; e = {($_.date -replace "[^\d-]") + " " + $_.time}}, * -ExcludeProperty date, time'

        $filter = ''

        if ($dstPort) {
            if ($filter) {
                $filter += " -and"
            }

            $i = 0
            $dstPort | % {
                if ($i) {
                    $filter += " -or"
                }
                ++$i

                $filter += " `$_.'dst-port' -eq $_"
            }
        }

        if ($srcPort) {
            if ($filter) {
                $filter += " -and"
            }

            $i = 0
            $srcPort | % {
                if ($i) {
                    $filter += " -or"
                }
                ++$i

                $filter += " `$_.'src-port' -eq $_"
            }
        }

        if ($dstIP) {
            if ($filter) {
                $filter += " -and"
            }

            $i = 0
            $dstIP | % {
                if ($i) {
                    $filter += " -or"
                }
                ++$i

                $filter += " `$_.'dst-ip' -eq `"$_`""
            }
        }

        if ($srcIP) {
            if ($filter) {
                $filter += " -and"
            }

            $i = 0
            $srcIP | % {
                if ($i) {
                    $filter += " -or"
                }
                ++$i

                $filter += " `$_.'src-ip' -eq `"$_`""
            }
        }

        if ($action) {
            if ($filter) {
                $filter += " -and"
            }

            $filter += " `$_.action -eq `"$action`""
        }

        if ($protocol) {
            if ($filter) {
                $filter += " -and"
            }

            $i = 0
            $protocol | % {
                if ($i) {
                    $filter += " -or"
                }
                ++$i

                $filter += " `$_.protocol -eq `"$protocol`""
            }
        }

        if ($path) {
            if ($filter) {
                $filter += " -and"
            }

            $filter += " `$_.path -eq `"$path`""
        }

        if ($from) {
            if ($filter) {
                $filter += " -and"
            }

            $filter += " `(Get-Date `$_.datetime) -ge `"$from`""
        }

        if ($to) {
            if ($to -gt (Get-Date)) {
                Write-Warning "Zadali jste cas v budoucnosti. Parametr To ignoruji"
            } else {
                if ($filter) {
                    $filter += " -and"
                }

                $filter += " `(Get-Date `$_.datetime) -le `"$to`""
            }
        }

        if ($filter) {
            $command += " | Where-Object {$filter}"
        }

        if ($live) {
            # pro lepsi prehlednost u realtime sledovani naformatuji pomoci Format-Table
            $command += ' | Format-Table'
        } elseif ($ogv) {
            $command += " | Out-GridView -Title `"FW log - $computerName`""
        }

        # pouziti cmtrace je vylucne s ostatnimi parametry
        if ($cmtrace) {
            $command = ''
            $logToShow | % {
                $command += "try { cmtrace.exe `"$_`" } catch { throw 'Nastroj cmtrace neni dostupny' };"
            }
        }
    }

    process {
        Write-Verbose "Spoustim prikaz:`n$command"
        Invoke-Expression $command
    }

    end {
    }
}