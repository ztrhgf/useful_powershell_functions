function Get-IntuneDeviceComplianceStatus {
    <#
    .SYNOPSIS
    Function for getting device compliance status from Intune.

    .DESCRIPTION
    Function for getting device compliance status from Intune.
    Devices can be selected by name or id. If omitted, all devices will be processed.

    .PARAMETER deviceName
    Name of device(s).

    Can be combined with deviceId parameter.

    .PARAMETER deviceId
    Id(s) of device(s).

    Can be combined with deviceName parameter.

    .PARAMETER header
    Authentication header.

    Can be created via New-IntuneAuthHeader.

    .PARAMETER justProblematic
    Switch for outputting only non-compliant items.

    .EXAMPLE
    $header = New-IntuneAuthHeader
    Get-IntuneDeviceComplianceStatus -header $header

    Will return compliance information for all devices in your Intune.

    .EXAMPLE
    $header = New-IntuneAuthHeader
    Get-IntuneDeviceComplianceStatus -header $header -deviceName PC-1, PC-2

    Will return compliance information for PC-1, PC-2 from Intune.
    #>

    [CmdletBinding()]
    param (
        [string[]] $deviceName,

        [string[]] $deviceId,

        [hashtable] $header,

        [switch] $justProblematic
    )

    $ErrorActionPreference = "Stop"

    if (!$header) {
        # authenticate
        $header = New-IntuneAuthHeader -ErrorAction Stop
    }

    if (!$deviceName -and !$deviceId) {
        # all devices will be processed
        Write-Warning "You haven't specified device name or id, all devices will be processed"
        $deviceId = (Invoke-RestMethod -Headers $header -Uri "https://graph.microsoft.com/beta/deviceManagement/managedDevices?`$select=id" -Method Get).value | select -ExpandProperty Id
    } elseif ($deviceName) {
        $deviceName | % {
            #TODO limit returned properties using select filter
            $id = (Invoke-RestMethod -Headers $header -Uri "https://graph.microsoft.com/beta/deviceManagement/managedDevices?`$filter=deviceName eq '$_'" -Method Get).value | select -ExpandProperty Id
            if ($id) {
                Write-Verbose "$_ was translated to $id"
                $deviceId += $id
            } else {
                Write-Warning "Device $_ wasn't found"
            }
        }
    }

    $deviceId = $deviceId | select -Unique

    foreach ($devId in $deviceId) {
        Write-Verbose "Processing device $devId"
        # get list of all compliance policies of this particular device
        $deviceCompliancePolicy = (Invoke-RestMethod -Headers $header -Uri "https://graph.microsoft.com/beta/deviceManagement/managedDevices('$devId')/deviceCompliancePolicyStates" -Method Get).value

        if ($deviceCompliancePolicy) {
            # get detailed information for each compliance policy (mainly errorDescription)
            $deviceCompliancePolicy | % {
                $deviceComplianceId = $_.id
                $deviceComplianceStatus = (Invoke-RestMethod -Headers $header -Uri "https://graph.microsoft.com/beta/deviceManagement/managedDevices('$devId')/deviceCompliancePolicyStates('$deviceComplianceId')/settingStates" -Method Get).value

                if ($justProblematic) {
                    $deviceComplianceStatus = $deviceComplianceStatus | ? { $_.state -ne "compliant" }
                }

                $name = (Invoke-RestMethod -Headers $header -Uri "https://graph.microsoft.com/beta/deviceManagement/manageddevices('$devId')?`$select=deviceName" -Method Get).deviceName

                $deviceComplianceStatus | select @{n = 'deviceName'; e = { $name } }, state, errorDescription, userPrincipalName , setting, sources
            }
        } else {
            Write-Warning "There are no compliance policies for $devId device"
        }
    }
}