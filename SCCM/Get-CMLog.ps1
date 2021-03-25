function Get-CMLog {
    <#
    .SYNOPSIS
    Function for opening of logs based on type of problem you have. So you don't have to remember which logs are for which problems.
    If possible, opens them in LogViewer or CMTrace or as last resort in default associated program.

    .DESCRIPTION
    Function for opening of logs based on type of problem you have. So you don't have to remember which logs are for which problems.
    If possible, opens them in LogViewer or CMTrace or as last resort in default associated program.
    Besides opening the log, function outputs the purpose of that log.

    List of all SCCM logs https://docs.microsoft.com/en-us/mem/configmgr/core/plan-design/hierarchy/log-files.

    .PARAMETER computerName
    Name of computer whose logs you are interested in.
    In case the problem is related to SCCM server, this parameter will be ommited.

    .PARAMETER problem
    Type of problem you are investigating.

    AppInstallation
    AppDiscovery
    AppDownload
    Client Discovery
    CMClientInstallation
    CMClientPush
    CMG
    CMGClient
    CMGDeployment
    Compliance
    Co-Management
    ContentDistribution
    Inventory
    PolicyProcessing
    PXE
    OSInstallation

    .PARAMETER maxHistory
    How much archived logs you want to see.
    Default is 0.

    .PARAMETER SCCMServer
    Name of SCCM server. Will be automatically used in case the problem is related to server, not the client.

    Default is $_SCCMServer

    .EXAMPLE
    Get-CMLog -computerName titan01 -problem AppInstallation

    Opens all logs related to application installation problems in computer titan01.


    .EXAMPLE
    Get-CMLog -problem PXE -SCCMServer mysccmservername

    Opens all logs related to PXE problem on SCCM server 'mysccmservername'.
    #>

    [CmdletBinding()]
    param (
        [Parameter(Position = 0)]
        [string] $computerName = $env:COMPUTERNAME
        ,
        [Parameter(Mandatory = $true, Position = 1)]
        [ValidateSet("AppInstallation", "AppDiscovery", "AppDownload", "PXE", "ContentDistribution", "OSInstallation", "CMClientInstallation", "CMClientPush", "Co-Management", "PolicyProcessing", "CMG", "CMGClient", "CMGDeployment", "Compliance", "Client Discovery", "Inventory")]
        [ValidateNotNullOrEmpty()]
        [string] $problem
        ,
        [int] $maxHistory = 0
        ,
        [ValidateNotNullOrEmpty()]
        [string] $SCCMServer = $_SCCMServer
    )

    begin {
        # list of 'problems' whose logs are stored on SCCM server
        $serverProblems = "PXE", "ContentDistribution", "CMClientPush", "CMG", "CMGClient", "CMGDeployment", "Client Discovery"
        if ($problem -in $serverProblems -and !$SCCMServer) {
            throw "Problem '$problem' is related to SCCM server, but you didn't specify SCCMServer parameter."
        }
        if ($problem -in $serverProblems -and $computerName -ne $SCCMServer) {
            $computerName = $SCCMServer
            Write-Warning "Problem '$problem' is related to SCCM server ($SCCMServer). Therefore ignoring computerName parameter."
        }

        $clLog = "\\$computerName\C$\Windows\CCM\Logs"
        $servLog = "\\$SCCMServer\C$\Program Files\SMS_CCM\Logs"
        $servLog2 = "\\$SCCMServer\C$\Program Files\Microsoft Configuration Manager\Logs"

        # use best possible log viewer
        $cmLogViewer = "C:\Program Files (x86)\Microsoft Endpoint Manager\AdminConsole\bin\CMLogViewer.exe"
        $cmTrace = "$env:windir\CCM\CMTrace.exe"
        if (Test-Path $cmLogViewer) {
            $viewer = $cmLogViewer
        } elseif (Test-Path $cmTrace) {
            $viewer = $cmTrace
        }
    }

    process {
        function _openLog {
            param (
                [string[]] $logs
            )

            # open even archived log
            if ($maxHistory) {
                $parent = Split-Path $logs -Parent | Select-Object -Unique
                $availableLogs = Get-ChildItem $parent -Filter "*.log" -Force -File | Select-Object -exp fullname
                $previousLogs = @()
                foreach ($log in $logs) {
                    $logName = (Split-Path $log -Leaf) -replace "\.log$"
                    # archived log in named with suffix originalLog-someNumbers.log or as originalLog.lo_
                    $previousLogs += $availableLogs | where { $_ -match ([Regex]::Escape("$logName") + "-|$logName\.lo_$") } | Select-Object -Last $maxHistory
                }
                $logs = @($logs) + @($previousLogs) | Select-Object -Unique
            }

            if ($viewer -and $viewer -match "CMLogViewer\.exe$") {
                # open all logs in one CMLogViewer instance
                $quotedLog = ($logs | % {
                        "`"$_`""
                    }) -join " "
                Start-Process $viewer -ArgumentList $quotedLog
            } else {
                # cmtrace (or notepad) don't support opening multiple logs in one instance, so open each log in separate viewer process
                foreach ($log in $logs) {
                    if (!(Test-Path $log -ErrorAction SilentlyContinue)) {
                        Write-Warning "Log $log wasn't found"
                        continue
                    }

                    Write-Verbose "Opening $log"
                    if ($viewer -and $viewer -match "CMTrace\.exe$") {
                        # in case CMTrace viewer exists, use it
                        Start-Process $viewer -ArgumentList "`"$log`""
                    } else {
                        # use associated viewer
                        & $log
                    }
                }
            }
        }

        switch ($problem) {
            "AppInstallation" {
                "https://docs.microsoft.com/en-us/mem/configmgr/core/plan-design/hierarchy/log-files#BKMK_AppManageLog"
                "AppDiscovery"
                "AppIntentEval"
                "AppEnforce"
                "Execmgr"
                "`nMore info at https://blogs.technet.microsoft.com/sudheesn/2011/01/31/troubleshooting-sccm-part-vi-software-distribution/"

                _openLog "$clLog\AppDiscovery.log", "$clLog\AppEnforce.log", "$clLog\AppIntentEval.log", "$clLog\Execmgr.log"
            }

            "AppDiscovery" {
                "https://docs.microsoft.com/en-us/mem/configmgr/core/plan-design/hierarchy/log-files#BKMK_InventoryLog"
                "AppDiscovery"

                _openLog "$clLog\AppDiscovery.log"
            }

            "AppDownload" {
                "DataTransferService"
                "Or try in PowerShell console: Get-BitsTransfer -AllUsers | sort jobid | fl *"

                _openLog "$clLog\DataTransferService.log"
            }

            "PXE" {
                "Distmgr"
                "Smspxe"
                "MP_ClientIDManager"

                _openLog "$servLog2\Distmgr.log", "$servLog\Smspxe.log", "$servLog2\Smspxe.log", "$servLog\MP_ClientIDManager.log"
            }

            "ContentDistribution" {
                "Distmgr"

                _openLog "$servLog2\Distmgr.log"
            }

            "OSInstallation" {
                "https://docs.microsoft.com/en-us/mem/configmgr/core/plan-design/hierarchy/log-files#BKMK_OSDLog"
                "MP_ClientIDManager"
                "Smsts"
                "Execmgr"

                _openLog "$servLog\MP_ClientIDManager.log", "$clLog\Smsts.log", "$clLog\Execmgr.log"
            }

            "CMClientInstallation" {
                "Ccmsetup"
                "Ccmsetup-ccmeval"
                "CcmRepair"
                "Client.msi"

                _openLog "$clLog\Ccmsetup.log", "$clLog\Ccmsetup-ccmeval.log", "$clLog\CcmRepair.log", "$clLog\Client.msi.log"
            }

            "CMClientPush" {
                "ccm"

                _openLog "$servLog2\ccm.log"
            }

            "AppMetering" {
                "mtrmgr"

                _openLog "$clLog\mtrmgr.log"
            }

            "Co-Management" {
                "CoManagementHandler"
                "Check also Event Viewer: 'Microsoft-Windows-DeviceManagement-Enterprise-Diagnostics-Provider/Admin' and 'Microsoft-Windows-AAD/Operational'"

                _openLog "$clLog\CoManagementHandler.log" #, "$clLog\ComplRelayAgent.log", "$clLog\CIAgent.log", "$clLog\WUAHandler.log"
            }

            "PolicyProcessing" {
                _openLog "$clLog\PolicyAgent.log"
            }

            "CMG" {
                "CloudMgr"
                "SMS_CLOUD_PROXYCONNECTOR"
                "CMGService"
                Write-Warning "CMGService.log is located on CMG machine, so open it there (location is stored in registry HKLM\SOFTWARE\Microsoft\SMS\Tracing)!"

                _openLog "$servLog2\CloudMgr.log", "$servLog2\SMS_CLOUD_PROXYCONNECTOR.log"
            }
            "CMGClient" {
                "SMS_CLOUD_PROXYCONNECTOR"
                "CMGService"
                Write-Warning "CMGService.log is located on CMG machine, so open it there (location is stored in registry HKLM\SOFTWARE\Microsoft\SMS\Tracing)!"
                "CMGHttpHandler"
                Write-Warning "CMGHttpHandler.log is located on CMG machine, so open it there (location is stored in registry HKLM\SOFTWARE\Microsoft\SMS\Tracing)!"

                _openLog "$servLog2\SMS_CLOUD_PROXYCONNECTOR.log"
            }
            "CMGDeployment" {
                "CloudMgr"
                "CMGSetup"
                Write-Warning "CMGSetup.log is located on CMG machine, so open it there (location is stored in registry HKLM\SOFTWARE\Microsoft\SMS\Tracing)!"

                _openLog "$servLog2\CloudMgr.log"
            }

            "Compliance" {
                "CIAgent"
                "CITaskManager"
                "DCMAgent"
                "DCMReporting"
                "DcmWmiProvider"

                _openLog "$clLog\CIAgent.log", "$clLog\CITaskManager.log", "$clLog\DCMAgent.log", "$clLog\DCMReporting.log", "$clLog\DcmWmiProvider.log"
            }

            "Client Discovery" {
                "https://docs.microsoft.com/en-us/mem/configmgr/core/plan-design/hierarchy/log-files#BKMK_DiscoveryLog"
                "adsgdis"
                "adsysdis"
                "adusrdis"
                "ADForestDisc"
                "ddm"
                "netdisc"

                _openLog "$servLog2\adsgdis.log", "$servLog2\adsysdis.log", "$servLog2\adusrdis.log", "$servLog2\ADForestDisc.log", "$servLog2\ddm.log", "$servLog2\netdisc.log"
            }

            "Inventory" {
                "InventoryAgent"

                _openLog "$clLog\InventoryAgent.log"
            }

            Default {
                throw "Undefined problem"
            }
        }
    }

    end {
    }
}