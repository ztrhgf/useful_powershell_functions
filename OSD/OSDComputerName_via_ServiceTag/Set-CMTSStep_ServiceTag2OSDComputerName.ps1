function Set-CMTSStep_ServiceTag2OSDComputerName {
    <#
    .SYNOPSIS
    Function for setting Task Sequence Step, that sets OSDCOMPUTERNAME variable based on device serial number (service tag).
    Serial tags and device names of all clients are received from SCCM REST API.

    .DESCRIPTION
    Function for setting Task Sequence Step, that sets OSDCOMPUTERNAME variable based on device serial number (service tag).
    Serial tags and device names of all clients are received from SCCM REST API.

    It will:
    - connect to SCCM server,
    - receive serial numbers and device names of all clients,
    - generate PowerShell script content that will return device name, based on its serial number
    - set PowerShell script content in given Task Sequence Step

    .PARAMETER sccmServer
    Name of the SCCM server.

    .PARAMETER sccmSiteCode
    SCCM site code.

    .PARAMETER tsName
    Name of Task Sequence you want to modify.

    .PARAMETER tsStepName
    Name of Task Sequence Step you want to modify.

    .EXAMPLE
    Set-CMTSStep_ServiceTag2OSDComputerName

    Will:
     - connect to SCCM server,
     - receive serial numbers and device names of all clients,
     - generate PowerShell script content that will return device name, based on its serial number
     - set PowerShell script content in given Task Sequence Step

    .NOTES
    Inspired by https://www.deploymentshare.com/rename-your-task-sequence-steps-with-powershell/
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string] $sccmServer = $_SCCMServer,

        [Parameter(Mandatory = $true)]
        [string] $sccmSiteCode = $_SCCMSiteCode,

        [Parameter(Mandatory = $true)]
        [string] $tsName = "SET OSDCOMPUTERNAME BASED ON SERIAL NUMBER",

        [Parameter(Mandatory = $true)]
        [string] $tsStepName = "Hardcoded OSDCOMPUTERNAME based on Serial Number"
    )

    if (!(Get-Command Invoke-CMAdminServiceQuery -ErrorAction SilentlyContinue)) {
        throw "Required command Invoke-CMAdminServiceQuery is missing."
    }

    # cannot use Connect-SCCM because of deserialization error :(
    $session = New-PSSession -ComputerName $sccmServer -ErrorAction Stop

    # create SCCM PSDrive & import SCCM PS module
    Invoke-Command -Session $session {
        param ($sccmSiteCode)

        if (!(Get-Module ConfigurationManager)) {
            Import-Module "$($ENV:SMS_ADMIN_UI_PATH)\..\ConfigurationManager.psd1"
        }

        if (!(Get-PSDrive -Name $sccmSiteCode -PSProvider CMSite -ErrorAction SilentlyContinue)) {
            New-PSDrive -Name $sccmSiteCode -PSProvider CMSite -Root $env:COMPUTERNAME | Out-Null
        }

        Set-Location "$($sccmSiteCode):\"
    } -ArgumentList $sccmSiteCode

    # prepare this remote session for working with Task Sequence
    Invoke-Command -Session $session {
        param ($tsName, $tsStepName)

        # get Task Sequence object
        $taskSequence = (Get-CMTaskSequence -Name $tsName -Fast)
        if (!$taskSequence) { throw "'$tsName' Task Sequence wasn't found" }

        # check Task Sequence Lock status
        $lockState = Get-CMObjectLockDetails -InputObject $taskSequence | select -ExpandProperty LockState
        if ($lockState -eq 1) {
            throw "Task Sequence $tsName is locked (probably someone has it open in SCCM console)"
        }

        # get Task Sequence Step
        $tsSteps = (Get-CMTaskSequenceStep -InputObject $taskSequence)
        $tsStep = $tsSteps | ? { $_.Name -eq $tsStepName }
        if (!$tsStep) { throw "Step '$tsStepName' wasn't found in Task Sequence '$tsName'" }
    } -ArgumentList $tsName, $tsStepName -ErrorAction Stop

    # get serial number and device name from SCCM Admin Service (REST API)
    $deviceSerialNumber = Invoke-CMAdminServiceQuery -Source "wmi/SMS_G_System_SYSTEM_ENCLOSURE" -Select SerialNumber, ResourceID
    $deviceName = Invoke-CMAdminServiceQuery -Source "wmi/SMS_R_SYSTEM" -Select Name, ResourceID, DistinguishedName
    if (!$deviceSerialNumber -or !$deviceName) { throw "Unable to receive information from SCCM Administration service" }

    #region prepare TS Step PowerShell script content
    $devicesArrayString = '$devices = @('
    $deviceName | Sort-Object -Property Name | % {
        $name = $_.Name
        $resourceID = $_.ResourceID
        $serial = $deviceSerialNumber | ? { $_.ResourceID -eq $resourceID } | select -ExpandProperty SerialNumber | select -First 1

        if ($serial) {
            $devicesArrayString += "`n[PSCustomObject]@{Name = '$name'; SerialNumber = '$serial'}"
        } else {
            Write-Warning "Skipped. $name device doesn't have record in SCCM database"
        }
    }
    # close array
    $devicesArrayString += "`n)"

    $sourceScript = @"
`$errorActionPreference = "Stop"

# array of all devices name and serial numbers that exists in SCCM
$devicesArrayString

# this computer serial number
`$serialNumber = (Get-WmiObject -Class WIN32_BIOS).SerialNumber

`$computerName = `$devices | ? {`$_.SerialNumber -eq `$serialNumber} | Select -expandProperty Name

if (`$computerName) {
    if (`$computerName.count -gt 1) { throw "For computer with serial `$serialNumber, there is more than one name (`$computerName)"}
    else { return `$computerName }
}
"@
    #endregion prepare TS Step PowerShell script content

    # customize content of PowerShell script called in Task Sequence Step
    Invoke-Command -Session $session {
        param ($sourceScript, $tsName, $tsStepName)
        Set-CMTSStepRunPowerShellScript -TaskSequenceName $tsName -StepName $tsStepName -OutputVariableName 'OSDComputerName' -SourceScript $sourceScript -ExecutionPolicy Bypass
    } -ArgumentList $sourceScript, $tsName, $tsStepName

    Remove-PSSession $session -ea SilentlyContinue
}