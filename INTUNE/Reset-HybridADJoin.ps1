function Reset-HybridADJoin {
    <#
    .SYNOPSIS
    Function for resetting Hybrid AzureAD join connection.

    .DESCRIPTION
    Function for resetting Hybrid AzureAD join connection.
    It will:
     - un-join computer from AzureAD (using dsregcmd.exe)
     - remove leftover certificates
     - invoke rejoin (using sched. task 'Automatic-Device-Join')
     - inform user about the result

    .PARAMETER computerName
    (optional) name of the computer you want to rejoin.

    .EXAMPLE
    Reset-HybridADJoin

    Un-join and re-join this computer to AzureAD

    .NOTES
    https://www.maximerastello.com/manually-re-register-a-windows-10-or-windows-server-machine-in-hybrid-azure-ad-join/
    #>

    [CmdletBinding()]
    param (
        [string] $computerName
    )

    Write-Warning "For join AzureAD process to work. Computer account has to exists in AzureAD already (should be synchronized via 'AzureAD Connect')!"

    $allFunctionDefs = "function Invoke-AsSystem { ${function:Invoke-AsSystem} }"

    $param = @{
        scriptblock  = {
            param( $allFunctionDefs )

            $ErrorActionPreference = "Stop"

            foreach ($functionDef in $allFunctionDefs) {
                . ([ScriptBlock]::Create($functionDef))
            }

            $dsreg = dsregcmd.exe /status
            if (($dsreg | Select-String "DomainJoined :") -match "NO") {
                throw "Computer is NOT domain joined"
            }

            "Un-joining $env:COMPUTERNAME from Azure"
            Write-Verbose "by running: Invoke-AsSystem { dsregcmd.exe /leave /debug } -returnTranscript"
            Invoke-AsSystem { dsregcmd.exe /leave /debug } #-returnTranscript

            Start-Sleep 5
            Get-ChildItem 'Cert:\LocalMachine\My\' | ? { $_.Issuer -match "MS-Organization-Access|MS-Organization-P2P-Access \[\d+\]" } | % {
                Write-Host "Removing leftover Hybrid-Join certificate $($_.DnsNameList.Unicode)" -ForegroundColor Cyan
                Remove-Item $_.PSPath
            }

            $dsreg = dsregcmd.exe /status
            if (!(($dsreg | Select-String "AzureAdJoined :") -match "NO")) {
                throw "$env:COMPUTERNAME is still joined to Azure. Run again"
            }

            # join computer to Azure again
            "Joining $env:COMPUTERNAME to Azure"
            Write-Verbose "by running: Get-ScheduledTask -TaskName Automatic-Device-Join | Start-ScheduledTask"
            Get-ScheduledTask -TaskName "Automatic-Device-Join" | Start-ScheduledTask
            while ((Get-ScheduledTask "Automatic-Device-Join" -ErrorAction silentlyContinue).state -ne "Ready") {
                Start-Sleep -Milliseconds 1000
                "Waiting for sched. task 'Automatic-Device-Join' to complete"
            }

            # check certificates
            "Waiting for certificate creation"
            $i = 30
            Write-Verbose "two certificates should be created in Computer Personal cert. store (issuer: MS-Organization-Access, MS-Organization-P2P-Access [$(Get-Date -Format yyyy)]"
            while (!($hybridJoinCert = Get-ChildItem 'Cert:\LocalMachine\My\' | ? { $_.Issuer -match "MS-Organization-Access|MS-Organization-P2P-Access \[\d+\]" }) -and $i -gt 0) {
                Start-Sleep 1
                --$i
                $i
            }

            if (!$hybridJoinCert) {
                throw "Certificates weren't created. Is $env:COMPUTERNAME synced to AzureAD?"
            }

            if ($hybridJoinCert.count -eq 2) {
                ++$twoHybridJoinCert
            }

            # check AzureAd join status
            $dsreg = dsregcmd.exe /status
            if (($dsreg | Select-String "AzureAdJoined :") -match "YES") {
                ++$AzureAdJoined
            }

            if ($twoHybridJoinCert -and $AzureAdJoined) {
                "$env:COMPUTERNAME was successfully joined to AAD again. Now you should restart it and run Start-AzureADSync"
            } else {
                $problem = @()

                if (!$AzureAdJoined) {
                    $problem += " - computer is not AzureAD joined"
                }

                if (!$twoHybridJoinCert) {
                    $problem += " - certificates weren't created"
                }

                Write-Error "Join wasn't successful:`n$($problem -join "`n")"
                Write-Warning "Check if device $env:COMPUTERNAME exists in AAD"
                Write-Warning "Run:`ngpupdate /force /target:computer`nSync-ADtoAzure"
                Write-Warning "You can get failure reason via manual join by running: Invoke-AsSystem -scriptBlock {dsregcmd /join /debug} -returnTranscript"
                throw 1
            }
        }
        argumentList = $allFunctionDefs
    }

    if ($computerName -and $computerName -notin "localhost", $env:COMPUTERNAME) {
        $param.computerName = $computerName
    } else {
        if (! ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
            throw "You don't have administrator rights"
        }
    }

    Invoke-Command @param
}