Function Test-Connection2 {
    <#
        .SYNOPSIS
            Funkce k otestovani dostupnosti stroju.

        .DESCRIPTION
            Funkce k otestovani dostupnosti stroju. Pouziva asynchronni ping.

        .PARAMETER Computername
            List of computers to test connection

        .PARAMETER DetailedTest
            Prepinac. Pomalejsi metoda testovani vyzadujici modul psasync.
            Krome pingu otestuje i dostupnost c$ sdileni a RPC.

            Aby melo smysl, je potreba mit na danych strojich prava pro pristup k c$ sdileni!

        .PARAMETER Repeat
            Prepinac. Donekonecna bude pingat vybrane stroje.
            Neda se pouzit spolu s DetailedTest

        .PARAMETER JustResponding
            Vypise jen stroje, ktere odpovidaji

        .PARAMETER JustNotResponding
            Vypise jen stroje, ktere neodpovidaji

        .NOTES
            Vychazi ze skriptu Test-ConnectionAsync od Boe Prox

        .EXAMPLE
            Test-Connection2 -Computername server1,server2,server3

            Computername                Result
            ------------                ------
            Server1                     Success
            Server2                     TimedOut
            Server3                     No such host is known

        .EXAMPLE
            $offlineStroje = Test-Connection2 -Computername server1,server2,server3 -JustNotResponding

        .EXAMPLE
            if (Test-Connection2 bumpkin -JustResponding) {"Bumpkin bezi"}
    #>

    [cmdletbinding(DefaultParameterSetName = 'Default')]
    Param (
        [Parameter(Mandatory = $true, Position = 0, ValueFromPipelinebyPropertyName = $true, ValueFromPipeline = $true)]
        [string[]] $Computername
        ,
        [Parameter(Mandatory = $false, ParameterSetName = "Online")]
        [switch] $JustResponding
        ,
        [Parameter(Mandatory = $false, ParameterSetName = "Offline")]
        [switch] $JustNotResponding
        ,
        [switch] $DetailedTest
        ,
        [Alias('t')]
        [switch] $Repeat
    )

    Begin {
        if ($DetailedTest -and $Repeat) {
            Write-Warning "Prepinac detailed, se neda pouzit v kombinaci s repeat."
            $DetailedTest = $false
        }

        if ($DetailedTest) {
            if (! (Get-Module psasync)) {
                throw "Pro detailni otestovani dostupnosti je potreba psasync modul"
            }

            $AsyncPipelines = @()
            $pool = Get-RunspacePool 30
            $scriptblock = `
            {
                param($computer, $JustResponding, $JustNotResponding)
                # vytvorim si objekt s atributy
                $Object = [pscustomobject] @{
                    ComputerName = $computer
                    Result       = ""
                }

                if (Test-Connection $computer -count 1 -quiet) {
                    if (! (Get-WmiObject win32_computersystem -ComputerName $Computer -ErrorAction SilentlyContinue)) {
                        $Object.Result = "RPC not available"
                    } elseif (Test-Path \\$computer\c$) {
                        $Object.Result = "Success"
                    } else {
                        $Object.Result = "c$ share not available"
                    }
                } else {
                    $Object.Result = "TimedOut"
                }

                if (($JustResponding -and $Object.Result -eq 'Success') -or ($JustNotResponding -and $Object.Result -ne 'Success')) {
                    $Object.ComputerName
                } elseif (!$JustResponding -and !$JustNotResponding) {
                    $Object
                }
            }
        }
    }

    Process {
        if ($DetailedTest) {
            foreach ($computer in $ComputerName) {
                $AsyncPipelines += Invoke-Async -RunspacePool $pool -ScriptBlock $ScriptBlock -Parameters $computer, $JustResponding, $JustNotResponding
            }
        }
    }

    End {
        if ($DetailedTest) {
            Receive-AsyncResults -Pipelines $AsyncPipelines -ShowProgress
        } else {
            while (1) {
                $job = Test-Connection -ComputerName $computername -AsJob -Count 1
                $job | Wait-Job | Receive-Job | % {
                    if ($_.responseTime -ge 0) {
                        $result = "Success"
                    } elseif ($_.PrimaryAddressResolutionStatus -ne 0) {
                        $result = "Unknown hostname"
                    } else {
                        $result = "TimedOut"
                    }

                    if (($JustResponding -and $result -eq 'Success') -or ($JustNotResponding -and $result -ne 'Success')) {
                        # vratim pouze hostname stroje
                        $_.address
                    } elseif (!$JustResponding -and !$JustNotResponding) {
                        [pscustomobject]@{
                            ComputerName = $_.address
                            Result       = $result
                        }
                    }
                }

                Remove-Job $job

                # ukoncim while cyklus pokud neni receno, ze se maji vysledky neustale vypisovat
                if (!$Repeat) {
                    break
                } else {
                    sleep 1
                }
            } # end while
        }
    }
}
Set-Alias pc Test-Connection2
Set-Alias ping2 Test-Connection2