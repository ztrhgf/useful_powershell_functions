function Get-IntuneLog {
    <#
    .SYNOPSIS
    Function for Intune policies debugging on client.
    - opens Intune logs
    - opens event viewer with Intune log
    - generates & open MDMDiagReport.html report

    .DESCRIPTION
    Function for Intune policies debugging on client.
    - opens Intune logs
    - opens event viewer with Intune log
    - generates & open MDMDiagReport.html report

    .PARAMETER computerName
    Name of remote computer.

    .EXAMPLE
    Get-IntuneLog
    #>

    [CmdletBinding()]
    param (
        [string] $computerName
    )

    if ($computerName -and $computerName -in "localhost", $env:COMPUTERNAME) {
        $computerName = $null
    }

    function _openLog {
        param (
            [string[]] $logs
        )

        if (!$logs) { return }

        # use best possible log viewer
        $cmLogViewer = "C:\Program Files (x86)\Microsoft Endpoint Manager\AdminConsole\bin\CMLogViewer.exe"
        $cmTrace = "$env:windir\CCM\CMTrace.exe"
        if (Test-Path $cmLogViewer) {
            $viewer = $cmLogViewer
        } elseif (Test-Path $cmTrace) {
            $viewer = $cmTrace
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

    # open main Intune logs
    $log = "C:\ProgramData\Microsoft\IntuneManagementExtension\Logs"
    if ($computerName) {
        $log = "\\$computerName\" + ($log -replace ":", "$")
    }
    "opening logs in '$log'"
    _openLog (Get-ChildItem $log -File | select -exp fullname)

    # When a PowerShell script is run on the client from Intune, the scripts and the script output will be stored here, but only until execution is complete
    $log = "C:\Program files (x86)\Microsoft Intune Management Extension\Policies\Scripts"
    if ($computerName) {
        $log = "\\$computerName\" + ($log -replace ":", "$")
    }
    "opening logs in '$log'"
    _openLog (Get-ChildItem $log -File -ea SilentlyContinue | select -exp fullname)

    $log = "C:\Program files (x86)\Microsoft Intune Management Extension\Policies\Results"
    if ($computerName) {
        $log = "\\$computerName\" + ($log -replace ":", "$")
    }
    "opening logs in '$log'"
    _openLog (Get-ChildItem $log -File -ea SilentlyContinue | select -exp fullname)

    # open Event Viewer with Intune Log
    "opening event log 'Microsoft-Windows-DeviceManagement-Enterprise-Diagnostics-Provider/Admin'"
    if ($computerName) {
        Write-Warning "Opening remote Event Viewer can take significant time!"
        mmc.exe eventvwr.msc /computer:$computerName /c:"Microsoft-Windows-DeviceManagement-Enterprise-Diagnostics-Provider/Admin"
    } else {
        mmc.exe eventvwr.msc /c:"Microsoft-Windows-DeviceManagement-Enterprise-Diagnostics-Provider/Admin"
    }

    # generate & open MDMDiagReport
    "generating & opening MDMDiagReport"
    if ($computerName) {
        Write-Warning "TODO (zatim delej tak, ze spustis tuto fci lokalne pod uzivatelem, jehoz vysledky chces zjistit"
    } else {
        Start-Process MdmDiagnosticsTool.exe -Wait -ArgumentList "-out $env:TEMP\MDMDiag" -NoNewWindow
        & "$env:TEMP\MDMDiag\MDMDiagReport.html"
    }

    # vygeneruje spoustu bordelu do jednoho zip souboru vhodneho k poslani mailem (bacha muze mit vic jak 5MB)
    # Start-Process MdmDiagnosticsTool.exe -ArgumentList "-area Autopilot;DeviceEnrollment;DeviceProvisioning;TPM -zip C:\temp\aaa.zip" -Verb runas

    # show DM info
    $param = @{
        scriptBlock = { Get-ChildItem -Path HKLM:SOFTWARE\Microsoft\Enrollments -Recurse | where { $_.Property -like "*UPN*" } }
    }
    if ($computerName) {
        $param.computerName = $computerName
    }
    Invoke-Command @param | Format-Table

    # $regKey = "Computer\HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\IntuneManagementExtension\SideCarPolicies\Scripts"
    # if (!(Get-Process regedit)) {
    #     # set starting location for regedit
    #     Set-ItemProperty HKCU:\Software\Microsoft\Windows\CurrentVersion\Applets\Regedit LastKey $regKey
    #     # open regedit
    # } else {
    #     "To check script last run time and result check $regKey in regedit or logs located in C:\Program files (x86)\Microsoft Intune Management Extension\Policies"
    # }
    # regedit.exe
}