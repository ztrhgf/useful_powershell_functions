function Get-LogOnOff {
    <#
	.SYNOPSIS
	 	Fce slouží k vypsání logon/off událostí na vybraných strojích uživatele/ů.

	.DESCRIPTION
		Fce vyhledá logon/off eventy na vybraných strojích.
		Defaultně vypíše poslední 4 logon/off eventy.
		Vyžaduje modul psasync.

	.PARAMETER ComputerName
	 	Seznam strojů, na kterých zjistím logon/off akce.

	.PARAMETER Newest
	 	Číslo určující kolik logon/off událostí se má vypsat.

	.PARAMETER UserName
		Parametr určující login uživatele, který se má na daných strojích hledat.
		Standardně se hledá doménový účet.

	.PARAMETER LocalAccount
		Switch urcujici, ze hledame lokalni ucet.
		Tim padem se na kazdem stroji pokusime prelozit zadane UserName na SID a to najit v logu.

	.PARAMETER Type
	 	Seznam určující jaky typ eventu se ma hledat. Moznosti: logon, logoff.

	.PARAMETER After
		Parametr určující po jakém datu se mají eventy hledat.
		Zadavejte ve formatu: d.M.YYYY pripadne d.M.YYYY H:m, Pr.: 13.5.2015, 13.5.2015 6:00.
		Zadáte-li neexistující datum, tak filtr nebude fungovat!

	.PARAMETER Before
		Parametr určující před jakým datem se mají eventy hledat.
		Zadavejte ve formatu: d.M.YYYY pripadne d.M.YYYY H:m, Pr.: 13.5.2015, 13.5.2015 6:00.
		Zadáte-li neexistující datum, tak se filtrování dle času bude ignorovat!

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
		$hala | Get-LogOnOff -username sebela -type logoff -newest 10 -after '14.1.2015 10:00' -before '20.2.2015'
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
        [switch]$LocalAccount
        ,
        [Parameter(Mandatory = $false, Position = 2)]
        [int]$newest = 4
        ,
        [ValidateSet("logon", "logoff")]
        [array]$type = @("logon", "logoff")
        ,
        [ValidateScript( {
                If (($_ -match '^\d{1,2}\.\d{1,2}\.\d{4}( \d{1,2}:\d{1,2}(:\d{1,2}?)?)?$')) {
                    $true
                } else {
                    Throw "Zadavejte ve formatu: d.M.yyyy, d.M.yyyy H:m, d.M.yyyy H:m:s Pr.: 13.5.2015, 13.5.2015 6:00, 13.5.2015 6:00:33"
                }
            })]
        $after
        ,
        [ValidateScript( {
                If (($_ -match '^\d{1,2}\.\d{1,2}\.\d{4}( \d{1,2}:\d{1,2}(:\d{1,2}?)?)?$')) {
                    $true
                } else {
                    Throw "Zadavejte ve formatu: d.M.yyyy, d.M.yyyy H:m, d.M.yyyy H:m:s Pr.: 13.5.2015, 13.5.2015 6:00, 13.5.2015 6:00:33"
                }
            })]
        $before
    )

    BEGIN {
        if (! (Get-Module psasync)) {
            throw "Je potreba modul psasync."
        }

        $AsyncPipelines = @()
        $pool = Get-RunspacePool 20

        # pokud filtruji dle data, tak mne asi zajimaji vsechny udalosti
        if ($after -or $before) {
            Write-Warning "Hodnota v newest se nepouzije, filtrujete dle data vytvoreni."
            $newest = 0
        }

        # kontrola ze zadany ucet v domene existuje
        if (!$LocalAccount -and $UserName) {
            $sid = Get-SIDFromAccount $UserName -ErrorAction stop
            if (!$sid) { break }
        }

        # ziskam textovou definici funkci
        $FunctionString = Get-FunctionString -Function Get-SIDFromAccount

        $scriptblock = `
        {
            param($computer, $newest, $type, $UserName, $after, $before, $FunctionString, $LocalAccount)

            If (!(Test-Connection -ComputerName $computer -Count 1 -Quiet)) {
                Write-Output "$computer nepinga."
                Continue
            }

            if (!(Get-WmiObject win32_computersystem -ComputerName $Computer -ErrorAction SilentlyContinue)) {
                Write-Output "RPC connection on computer $Computer failed!"
                Continue
            }

            # dot sourcingem zpristupnim pomocne funkce z jejich textove definice
            $scriptblock = [System.Management.Automation.ScriptBlock]::Create($FunctionString)
            . $scriptblock

            $UserProperty = @{n = "User"; e = {
                    $sid = $_.properties[1].value.value
                    try {
                        (New-Object System.Security.Principal.SecurityIdentifier $sid).Translate([System.Security.Principal.NTAccount])
                    } catch {
                        # jde o lokalni ucet
                        try {
                            invoke-command -ComputerName $computer -ScriptBlock {((New-Object System.Security.Principal.SecurityIdentifier("$using:SID")).Translate([System.Security.Principal.NTAccount])).Value} -ArgumentList $sid -ErrorAction Stop
                        } catch [System.Management.Automation.Remoting.PSRemotingTransportException] {
                            "k $computer se nepodarilo pripojit, SID: $sid"
                        } catch {
                            # pravdepodobne doslo ke smazani lok. uctu
                            "SID $sid se nepodarilo prelozit."
                        }
                    }
                }
            }
            $TypeProperty = @{n = "Action"; e = {if ($_.ID -eq 7001) {"Logon"} else {"Logoff"}}}
            $TimeProperty = @{n = "Time"; e = {$_.TimeCreated}}
            $CompName = @{n = "Computer"; e = {$computer}}


            # poskladani prikazu k vykonani
            $zadani = 'LogName=system', 'Provider Name=Microsoft-Windows-Winlogon'

            if ($type -contains "logon" -and $type -contains "logoff") {
                $zadani += "EventID=7001,7002"
            } elseif ($type -contains "logon") {
                $zadani += "EventID=7001"
            } elseif ($type -contains "logoff") {
                $zadani += "EventID=7002"
            }

            if ($after -and $before) {
                $zadani += "TimeCreated SystemTime>=$after"
                $zadani += "TimeCreated SystemTime<=$before"
            } elseif ($before) {
                $zadani += "TimeCreated SystemTime<=$before"
            } elseif ($after) {
                $zadani += "TimeCreated SystemTime>=$after"
            }

            if ($UserName) {
                # SID hodnota je v eventdata casti eventu
                $zadani += 'eventdata'
                if ($LocalAccount) {
                    $sid = Get-SIDFromAccount $UserName -computerName $computer -ErrorAction SilentlyContinue
                } else {
                    $sid = Get-SIDFromAccount $UserName -ErrorAction SilentlyContinue
                }

                $zadani += "UserSid=$sid"
            }

            # vytvoreni XML dotazu na zaklade zadani
            $xml = New-XMLFilter -zadani $zadani
            #$xml.querylist.query.select.'#text'

            if ($newest) {
                Get-WinEvent -ComputerName $Computer -ea silentlycontinue -FilterXml $xml -MaxEvents $newest | select $CompName, $UserProperty, $TypeProperty, $TimeProperty #| select -First $newest
            } else {
                Get-WinEvent -ComputerName $Computer -ea silentlycontinue -FilterXml $xml | select $CompName, $UserProperty, $TypeProperty, $TimeProperty
            }
        }
    }

    PROCESS {
        foreach ($computer in $ComputerName) {
            $AsyncPipelines += Invoke-Async -RunspacePool $pool -ScriptBlock $ScriptBlock -Parameters $computer, $newest, $type, $UserName, $after, $before, $FunctionString, $LocalAccount -ErrorAction SilentlyContinue
        }
    }


    END {
        Receive-AsyncResults -Pipelines $AsyncPipelines -ShowProgress -ErrorAction SilentlyContinue
    }
}

# NASTAVENI ALIASU
Set-Alias gloo Get-LogOnOff

#gloo -ComputerName $HALA -LocalAccount -UserName _titan05

#Get-LogOnOff -username sebela -type logon -newest 10 -after '14.1.2015 10:00' -before 30.2.2015
#cls
#Get-LogOnOff -comp kronos