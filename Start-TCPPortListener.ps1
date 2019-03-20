function Start-TCPPortListener {
    <#
    .SYNOPSIS
    Funkce spusti naslouchani na zadanem TCP portu na zadanem pocitaci.
    Dobre pro testovani pruchodnosti komunikace skrze firewall.

    .DESCRIPTION
    Funkce spusti naslouchani na zadanem TCP portu na zadanem pocitaci.
    Dobre pro testovani pruchodnosti komunikace skrze firewall.

    .PARAMETER Computer
    IP ci DNS jmeno stroje, na kterem chceme spustit naslouchani na portu

    .PARAMETER PORT
    Cislo TCP portu

    .PARAMETER ListenSeconds
    Jak dlouho, se bude naslouchat.
    Vychozi je 600 sekund

    .PARAMETER KeepAlive
    Vychozi jsou 2 vteriny

    .EXAMPLE
    Start-TCPPortListener -computer 147.251.48.186 -PORT 4000

    .NOTES
    https://gallery.technet.microsoft.com/scriptcenter/PowerShell-Listen-TCP-Port-0bf882c2
    #>

    [CmdletBinding()]
    Param(
        [Parameter()]
        [ValidateNotNull()]
        [String] $Computer = $env:COMPUTERNAME,

        [Parameter(Mandatory = $True)]
        [ValidateNotNull()]
        [Int] $PORT,

        [Parameter()]
        [ValidateNotNull()]
        [Int] $ListenSeconds = 600,

        [Parameter()]
        [ValidateNotNull()]
        [Int] $KeepAlive = 2
    )

    # zadal IP, ziskam z ni DNS
    # hostname potrebuji kvuli kerb. autentizaci pouzivane v Invoke-Command
    if ($Computer -match "^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$") {
        try {
            [system.net.IPAddress]$Computer | Out-Null
        } catch {
            throw "Parametr IP musi obsahovat validni IP adresu"
        }
        $dnsName = ([System.Net.Dns]::gethostentry($Computer)).hostname # kvuli kerberos autentizaci potrebuju dns jmeno a ne IP
        $dnsName = ($dnsName).split('\.')[0]
        if (!$dnsName) {
            throw "Nepodarilo se z $computer ziskat DNS jmeno. Je zadana IP spravna?"
        }
        $IP = $Computer
    } else {
        # zadal DNS jmeno, ziskam z nej IP
        $IP = [System.Net.Dns]::GetHostAddresses($Computer).ipaddresstostring | select -Last 1 # prednostne chci pouzivat IPv4 adresy pred IPv6
        if (!$IP) {
            throw "Nepodarilo se ziskat IP adresu stroje $computer, zkuste ji rovnou zadat do parametru Computer."
        }
    }

    if ($Computer -eq $env:COMPUTERNAME) {
        Write-Warning "Pokud budete dostupnost zkouset z localhostu prikazem Test-Port, pouzijte v nem v parametru computerName hodnotu $computer (a ne localhost)"
    }
    
    Write-Output "Zkusim jestli uz na danem portu nahodou neco nebezi"
    if ((Test-Port -ComputerName $Computer -Port $PORT).result) {
        Write-Host "Na $Computer`:$PORT jiz neco bezi"; Break
    }

    $scriptBlock = {
        param ($IP, $port, $ListenSeconds, $KeepAlive)

        $ListenSecondst = New-TimeSpan -Seconds $ListenSeconds
        $TIME = [diagnostics.stopwatch]::StartNew()
        $EP = new-object System.Net.IPEndPoint ([system.net.IPAddress]::Parse($IP), $PORT)    
        $LSTN = new-object System.Net.Sockets.TcpListener $EP
        $LSTN.server.ReceiveTimeout = 300
        $LSTN.start()    

        try {
            Write-Host "`n$(Get-Date -f hh:mm) START naslouchani $IP`:$port po dobu $ListenSeconds vterin.`nCTRL + C pro ukonceni" # tolik prazdnych radku je schvalne, kvuli vypisu progresu test-netconnection, aby neprekryval tento text
            Write-Warning "Je take potreba mit port $port povolen na danem firewallu!"

            While ($TIME.elapsed -lt $ListenSecondst) {
                if (!$LSTN.Pending()) {Start-Sleep -Seconds 1; continue; }
                $CONNECT = $LSTN.AcceptTcpClient()
                $CONNECT.client.RemoteEndPoint | Add-Member -NotePropertyName Date -NotePropertyValue (get-date) -PassThru | Add-Member -NotePropertyName Status -NotePropertyValue Connected -PassThru | select Status, Date, Address, Port
                Start-Sleep -Seconds $KeepAlive;
                $CONNECT.client.RemoteEndPoint | Add-Member -NotePropertyName Date -NotePropertyValue (get-date) -PassThru -Force | Add-Member -NotePropertyName Status -NotePropertyValue Disconnected -PassThru -Force | select Status, Date, Address, Port
                $CONNECT.close()
            }
        } catch {
            Write-Error $_
        } finally {
            $LSTN.stop(); $end = get-date; Write-host "`n$end - ukonceno"
        }
    } # konec scriptblock

    $params = @{
        scriptBlock  = $scriptBlock
        computerName = $Computer
        ArgumentList = $IP, $port, $ListenSeconds, $KeepAlive
    }

    Invoke-Command2 @params

}