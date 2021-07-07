function Connect-SCCM {
    <#
    .SYNOPSIS
    Helper function for making session to SCCM server, to be able to call locally any available command from SCCM module there.

    .DESCRIPTION
    Helper function for making session to SCCM server, to be able to call locally any available command from SCCM module there.

    .PARAMETER sccmServer
    Name of your SCCM server.

    .PARAMETER commandName
    (Optional)

    Name of command(s) you want to import instead of all.

    .EXAMPLE
    Connect-SCCM -sccmServer SCCM-01
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        $sccmServer = $_SCCMServer
        ,
        [string[]]$commandName
    )

    $correctlyConfSession = ""
    $sessionExist = Get-PSSession | ? { $_.computername -eq $sccmServer -and $_.state -eq "opened" }

    # remove broken sessions
    Get-PSSession | ? { $_.computername -eq $sccmServer -and $_.state -eq "broken" } | Remove-PSSession

    if ($commandName) {
        # check that pssession already exists and contains given commands
        $commandExist = try {
            Get-Command $commandName -ErrorAction Stop
        } catch {}

        if ($sessionExist -and $commandExist) {
            $correctlyConfSession = 1
            Write-Verbose "Session to $sccmServer is already created and contains required commands"
        }
    } else {
        # check that pssession already exists and that number of commands there is more than 50 (it is highly probable, that session contains all available commands)
        if ($sessionExist -and ((Get-Command -ListImported | ? { $_.name -like "*-cm*" -and $_.source -like "tmp_*" }).count -gt 50)) {
            $correctlyConfSession = 1
            Write-Verbose "Session to $sccmServer is already created"
        }
    }

    if (!$correctlyConfSession) {
        if (Test-Connection $sccmServer -ErrorAction SilentlyContinue) {
            # pssession doesn't contain necessary commands
            try {
                Write-Verbose "Removing existing sessions that doesn't contain required commands"
                Get-PSSession | ? { $_.computername -eq $sccmServer } | Remove-PSSession
            } catch {}

            $sccmSession = New-PSSession -ComputerName $sccmServer -Name "SCCM"

            try {
                $ErrorActionPreference = "stop"
                Invoke-Command -Session $sccmSession -ScriptBlock {
                    $ErrorActionPreference = "stop"

                    try {
                        Import-Module "$(Split-Path $Env:SMS_ADMIN_UI_PATH)\ConfigurationManager.psd1"
                    } catch {
                        throw "Unable to import SCCM module on $env:COMPUTERNAME"
                    }

                    try {
                        $sccmSite = (Get-PSDrive -PSProvider CMSite).name
                        Set-Location -Path ($sccmSite + ":\")
                    } catch {
                        throw "Unable to retrieve SCCM Site Code"
                    }
                }

                $Params = @{
                    'session'      = $sccmSession
                    'Module'       = 'ConfigurationManager'
                    'AllowClobber' = $true
                    'ErrorAction'  = "Stop"
                }
                if ($commandName) {
                    $Params.Add("CommandName", $CommandName)
                }

                # import-module is used, so the commands will be available even if Connect-SCCM is called from module
                Import-Module (Import-PSSession @Params) -Global -Force
            } catch {
                "To be able to use SCCM commands remotely you have to:`n1. Connect to $sccmServer using RDP.`n2. Run SCCM console under account, that should use commands remotely.`n3. In SCCM console run PowerShell console (Connect via PowerShell).`n4. In such PowerShell console enable import of certificate by selecting choice '[A] Always run'"

                "Second option should be to:`n1. Open file properties of 'C:\Program Files (x86)\Microsoft Configuration Manager\AdminConsole\bin\ConfigurationManager.psd1'.`n2. On tab Digital Signatures > Details > View Certificate > Install Certificate > Install such certificate to Trusted Publishers store"

                "Error was: $($_.Exception.Message)"
            }
        } else {
            "$sccmServer is offline"
        }
    }
}