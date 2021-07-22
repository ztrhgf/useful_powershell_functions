function Get-IntuneReport {
    <#
    .SYNOPSIS
    Function for getting Intune Reports data. As zip file (csv) or PS object.

    .DESCRIPTION
    Function for getting Intune Reports data. As zip file (csv) or PS object.
    It uses Graph API for connection.

    In case selected report needs additional information, like what application you want report for, GUI with available options will be outputted for you to choose.

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

    .PARAMETER header
    Authentication header.

    Can be created via New-IntuneAuthHeader.

    .PARAMETER filter
    String that represents Graph request API filter.

    For example: PolicyId eq 'a402829f-8ba2-4413-969b-077a97ba218c'

    PS: Some reports (FeatureUpdateDeviceState, DeviceInstallStatusByApp, UserInstallStatusAggregateByApp) requires filter to target the update/application. In case you don't specify it, list of available values will be given to choose.

    .PARAMETER exportPath
    Path to folder, where report should be stored.

    Default is working folder.

    .PARAMETER asObject
    Switch for getting results as PS object instead of zip file.

    .EXAMPLE
    $header = New-IntuneAuthHeader -ErrorAction Stop
    $reportData = Get-IntuneReport -header $header -reportName Devices -asObject

    Return object with 'All devices list' report data.

    .EXAMPLE
    $header = New-IntuneAuthHeader -ErrorAction Stop
    Get-IntuneReport -header $header -reportName DeviceNonCompliance

    Download zip archive to current working folder containing csv file with 'Non-compliant devices' report.

    .EXAMPLE
    $header = New-IntuneAuthHeader -ErrorAction Stop
    Get-IntuneReport -header $header -reportName FeatureUpdateDeviceState -filter "PolicyId eq 'a402829f-8ba2-4413-969b-077a97ba218c'"

    .NOTES
    You need to have Azure App registration with appropriate API permissions for Graph API for unattended usage!

    With these API permissions all reports work (but maybe not all are really needed!)
    Application.Read.All
    Device.Read.All
    DeviceManagementApps.Read.All
    DeviceManagementConfiguration.Read.All
    DeviceManagementManagedDevices.Read.All
    ProgramControl.Read.All
    Reports.Read.All

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
        [string] $filter
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

    begin {
        $ErrorActionPreference = "Stop"

        if (!$header) {
            # authenticate
            $header = New-IntuneAuthHeader -ErrorAction Stop
        }

        #region prepare filter for FeatureUpdateDeviceState report if not available
        if ($reportName -eq 'FeatureUpdateDeviceState' -and (!$filter -or $filter -notmatch "^PolicyId eq ")) {
            Write-Warning "Report FeatureUpdateDeviceState requires special filter in form: `"PolicyId eq '<somePolicyId>'`""
            $body = @{
                name = "FeatureUpdatePolicy"
            }
            $filterResponse = Invoke-RestMethod -Headers $header -Uri "https://graph.microsoft.com/beta/deviceManagement/reports/getReportFilters" -Body $body -Method Post
            $column = $filterResponse.schema.column
            $filterList = $filterResponse.values | % {
                $filterItem = $_

                $property = @{}
                $o = 0
                $column | % {
                    $property.$_ = $filterItem[$o]
                    ++$o
                }
                New-Object -TypeName PSObject -Property $property
            }

            $filter = $filterList | Out-GridView -Title "Select Update type you want the report for" -OutputMode Single | % { "PolicyId eq '$($_.PolicyId)'" }
            Write-Verbose "Filter will be: $filter"
        }
        #endregion prepare filter for FeatureUpdateDeviceState report if not available

        #region prepare filter for DeviceInstallStatusByApp/UserInstallStatusAggregateByApp report if not available
        if ($reportName -in ('DeviceInstallStatusByApp', 'UserInstallStatusAggregateByApp') -and (!$filter -or $filter -notmatch "^PolicyId eq ")) {
            Write-Warning "Report $reportName requires filter in form: `"ApplicationId eq '<someApplicationId>'`""
            # get list of all available applications
            $allApps = (Invoke-RestMethod -Headers $header -Uri "https://graph.microsoft.com/beta/deviceAppManagement/mobileApps?`$filter=(microsoft.graph.managedApp/appAvailability%20eq%20null%20or%20microsoft.graph.managedApp/appAvailability%20eq%20%27lineOfBusiness%27%20or%20isAssigned%20eq%20true)&`$orderby=displayName&" -Method Get).Value | select displayName, isAssigned, productVersion, id

            $filter = $allApps | Out-GridView -Title "Select Application you want the report for" -OutputMode Single | % { "ApplicationId eq '$($_.Id)'" }
            Write-Verbose "Filter will be: $filter"
        }
        #endregion prepare filter for DeviceInstallStatusByApp/UserInstallStatusAggregateByApp report if not available
    }

    process {
        #region request the report
        $body = @{
            reportName = $reportName
            format     = "csv"
            # select     = 'PolicyId', 'PolicyName', 'DeviceId'
        }
        if ($filter) { $body.filter = $filter }
        Write-Warning "Requesting the report $reportName"
        try {
            $result = Invoke-RestMethod -Headers $header -Uri "https://graph.microsoft.com/beta/deviceManagement/reports/exportJobs" -Body $body -Method Post
        } catch {
            switch ($_) {
                ($_ -like "*(400) Bad Request*") { throw "Faulty request. There has to be some mistake in this request" }
                ($_ -like "*(401) Unauthorized*") { throw "Unauthorized request (try different credentials?)" }
                ($_ -like "*Forbidden*") { throw "Forbidden access. Use account with correct API permissions for this request" }
                default { throw $_ }
            }
        }
        #endregion request the report

        #region wait for generating of the report to finish
        Write-Warning "Waiting for the report to finish generating"
        do {
            $export = Invoke-RestMethod -Headers $header -Uri "https://graph.microsoft.com/beta/deviceManagement/reports/exportJobs('$($result.id)')" -Method Get

            Start-Sleep 1
        } while ($export.status -eq "inProgress")
        #endregion wait for generating of the report to finish

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
                Write-Warning "Removing zip and csv files"
                Remove-Item $reportArchive, $reportCsv -Force
            }
        } else {
            throw "Export of $reportName failed.`n`n$export"
        }
        #endregion download generated report
    }
}