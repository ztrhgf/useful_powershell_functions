function Get-IntuneReport {
    <#
    .SYNOPSIS
    Function for getting Intune Reports data. As zip file (csv) or PS object.

    .DESCRIPTION
    Function for getting Intune Reports data. As zip file (csv) or PS object.
    It uses Graph API for connection.

    .PARAMETER reportName
    Name of the report you want to get.

    POSSIBLE VALUES:
    https://docs.microsoft.com/en-us/mem/intune/fundamentals/reports-export-graph-available-reports

    reportName	                            Associated Report in Microsoft Endpoint Manager
    DeviceCompliance	                    Device Compliance Org
    DeviceNonCompliance	                    Non-compliant devices
    Devices	                                All devices list
    DetectedAppsAggregate	                Detected Apps report
    FeatureUpdatePolicyFailuresAggregate	Under Devices > Monitor > Failure for feature updates
    DeviceFailuresByFeatureUpdatePolicy	    Under Devices > Monitor > Failure for feature updates > click on error
    FeatureUpdateDeviceState	            Under Reports > Window Updates > Reports > Windows Feature Update Report 
    UnhealthyDefenderAgents	                Under Endpoint Security > Antivirus > Win10 Unhealthy Endpoints
    DefenderAgents	                        Under Reports > MicrosoftDefender > Reports > Agent Status
    ActiveMalware	                        Under Endpoint Security > Antivirus > Win10 detected malware
    Malware	                                Under Reports > MicrosoftDefender > Reports > Detected malware
    AllAppsList	                            Under Apps > All Apps
    AppInstallStatusAggregate	            Under Apps > Monitor > App install status
    DeviceInstallStatusByApp	            Under Apps > All Apps > Select an individual app
    UserInstallStatusAggregateByApp	        Under Apps > All Apps > Select an individual app

    .PARAMETER exportPath
    Path to folder, where report should be stored.

    Default is working folder.

    .PARAMETER asObject
    Switch that instead of exporting reports data to file, outputs the result to console as object.

    .EXAMPLE
    $header = New-IntuneAuthHeader -ErrorAction Stop
    $reportData = Get-IntuneReport -header $header -reportName Devices -asObject

    Return object with 'All devices list' report data.

    .EXAMPLE
    $header = New-IntuneAuthHeader -ErrorAction Stop
    Get-IntuneReport -header $header -reportName DeviceNonCompliance

    Download zip archive to current working folder containing csv file with 'Non-compliant devices' report.

    .NOTES
    You need to have Azure App registration with appropriate API permissions for Graph API for unattended usage!

    .LINK
    https://docs.microsoft.com/en-us/mem/intune/fundamentals/reports-export-graph-apis
    https://docs.microsoft.com/en-us/mem/intune/fundamentals/reports-export-graph-available-reports
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [ValidateSet('DeviceCompliance', 'DeviceNonCompliance', 'Devices', 'DetectedAppsAggregate', 'FeatureUpdatePolicyFailuresAggregate', 'DeviceFailuresByFeatureUpdatePolicy', 'FeatureUpdateDeviceState', 'UnhealthyDefenderAgents', 'DefenderAgents', 'ActiveMalware', 'Malware', 'AllAppsList', 'AppInstallStatusAggregate', 'DeviceInstallStatusByApp', 'UserInstallStatusAggregateByApp')]
        [string] $reportName
        ,
        [hashtable] $header
        ,
        [ValidateScript( {
                If (Test-Path $_ -PathType Container) {
                    $true
                } else {
                    Throw "$_ has to be existing folder"
                }
            })]
        [string] $exportPath = (Get-Location)
        ,
        [switch] $asObject
    )

    $ErrorActionPreference = "Stop"

    if (!$header) {
        # authenticate
        $header = New-IntuneAuthHeader -ErrorAction Stop
    }

    #region generate report
    $body = @{
        reportName = $reportName
        format     = "csv"
        # select     = "DeviceName", "managementAgent", "ownerType", "complianceState", "OS", "OSVersion", "LastContact", "UPN", "DeviceId"
        # filter     = "(IsManaged eq True)"
    }
    Write-Warning "Requesting the report $reportName"
    $result = Invoke-RestMethod -Headers $header -Uri "https://graph.microsoft.com/beta/deviceManagement/reports/exportJobs" -Body $body -Method Post

    # waiting for finish
    Write-Warning "Waiting report generating to finish"
    do {
        $export = Invoke-RestMethod -Headers $header -Uri "https://graph.microsoft.com/beta/deviceManagement/reports/exportJobs('$($result.id)')" -Method Get

        Start-Sleep 1
    } while ($export.status -eq "inProgress")
    #endregion generate report

    #region download generated report
    if ($export.status -eq "completed") {
        $originalFileName = $export.id + ".csv"
        $reportArchive = Join-Path $exportPath "$reportName`_$(Get-Date -Format dd-MM-HH-ss).zip"
        Write-Warning "Downloading the report to $reportArchive"
        $null = Invoke-WebRequest -Uri $export.url -Method Get -OutFile $reportArchive

        if ($asObject) {
            Write-Warning "Expanding $reportArchive to $env:TEMP"
            Expand-Archive $reportArchive -DestinationPath $env:TEMP -Force

            $reportCsv = Join-Path $env:TEMP $originalFileName
            Write-Warning "Importing $reportCsv"
            Import-Csv $reportCsv

            # delete zip and also extracted csv files
            Write-Warning "Removing archive and csv"
            Remove-Item $reportArchive, $reportCsv -Force
        }
    } else {
        throw "Export of $reportName failed.`n`n$export"
    }
    #endregion download generated report
}