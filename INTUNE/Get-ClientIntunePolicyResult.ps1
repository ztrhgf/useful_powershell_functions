function Get-ClientIntunePolicyResult {
    <#
        .SYNOPSIS
        Function for getting gpresult/rsop like report but for local client Intune policies.
        Result can be PowerShell object or HTML report.

        .DESCRIPTION
        Function for getting gpresult/rsop like report but for local client Intune policies.
        Result can be PowerShell object or HTML report.

        .PARAMETER computerName
        (optional) Computer name from which you want to get data from.

        .PARAMETER intuneXMLReport
        (optional) PowerShell object returned by ConvertFrom-MDMDiagReportXML function.

        .PARAMETER asHTML
        Switch for returning HTML report instead of PowerShell object.
        PSWriteHTML module is needed!

        .PARAMETER HTMLReportPath
        (optional) Where the HTML report should be stored.

        Default is "IntunePolicyReport.html" in user profile.

        .PARAMETER getDataFromIntune
        Switch for getting additional data (policy names and account names instead of IDs) from Intune itself.
        Microsoft.Graph.Intune module is required!

        Account with READ permission for: Applications, Scripts, RemediationScripts, Users will be needed i.e.:
        - DeviceManagementApps.Read.All
        - DeviceManagementManagedDevices.Read.All
        - DeviceManagementConfiguration.Read.All
        - User.Read.All

        .PARAMETER credential
        Credentials for connecting to Intune.
        Account that has at least READ permissions has to be used.

        .PARAMETER tenantId
        String with your TenantID.
        Use only if you want use application authentication (instead of user authentication).
        You can get your TenantID at https://portal.azure.com/#blade/Microsoft_AAD_IAM/ActiveDirectoryMenuBlade/Overview.

        .PARAMETER showEnrollmentIDs
        Switch for showing EnrollmentIDs in the result.

        .PARAMETER showURLs
        Switch for showing policy/setting URLs in the result.
        Makes this function a little slower, because every URL is tested that it exists.

        .PARAMETER showConnectionData
        Switch for showing data related to client's connection to the Intune.

        .EXAMPLE
        Get-ClientIntunePolicyResult

        Will return PowerShell object containing Intune policy processing report data.

        .EXAMPLE
        Get-ClientIntunePolicyResult -showURLs -asHTML

        Will return HTML page containing Intune policy processing report data.
        URLs to policies/settings will be included.

        .EXAMPLE
        $intuneREADCred = Get-Credential
        Get-ClientIntunePolicyResult -showURLs -asHTML -getDataFromIntune -showConnectionData -credential $intuneREADCred

        Will return HTML page containing Intune policy processing report data and connection data.
        URLs to policies/settings and Intune policies names (if available) will be included.

        .EXAMPLE
        $intuneREADAppCred = Get-Credential
        Get-ClientIntunePolicyResult -showURLs -asHTML -getDataFromIntune -credential $intuneREADAppCred -tenantId 123456789

        Will return HTML page containing Intune policy processing report data.
        URLs to policies/settings will be included same as Intune policies names (if available).
        For authentication to Intune registered application secret will be used (AppID and secret stored in credentials object).

        .NOTES
        Author: Ondrej Sebela (ztrhgf@seznam.cz)
        URL: https://doitpsway.com/get-a-better-intune-policy-report-part-3
        #>

    [Alias("ipresult", "Get-IntunePolicyResult")]
    [CmdletBinding()]
    param (
        [string] $computerName,

        [ValidateScript( { $_.GetType().Name -eq 'Object[]' } )]
        $intuneXMLReport,

        [switch] $asHTML,

        [string] $HTMLReportPath = (Join-Path $env:USERPROFILE "IntunePolicyReport.html"),

        [switch] $getDataFromIntune,

        [System.Management.Automation.PSCredential] $credential,

        [string] $tenantId,

        [switch] $showEnrollmentIDs,

        [switch] $showURLs,

        [switch] $showConnectionData
    )

    # remove property validation
    (Get-Variable intuneXMLReport).Attributes.Clear()

    #region prepare
    if ($computerName) {
        $session = New-PSSession -ComputerName $computerName -ErrorAction Stop
    }

    if ($asHTML) {
        if (!(Get-Module 'PSWriteHtml') -and (!(Get-Module 'PSWriteHtml' -ListAvailable))) {
            throw "Module PSWriteHtml is missing. To get it use command: Install-Module PSWriteHtml -Scope CurrentUser"
        }
        [Void][System.IO.Directory]::CreateDirectory((Split-Path $HTMLReportPath -Parent))
    }

    if ($getDataFromIntune) {
        if (!(Get-Module 'Microsoft.Graph.Intune') -and !(Get-Module 'Microsoft.Graph.Intune' -ListAvailable)) {
            throw "Module 'Microsoft.Graph.Intune' is required. To install it call: Install-Module 'Microsoft.Graph.Intune' -Scope CurrentUser"
        }

        if ($tenantId) {
            # app logon
            if (!$credential) {
                $credential = Get-Credential -Message "Enter AppID and AppSecret for connecting to Intune tenant" -ErrorAction Stop
            }
            Update-MSGraphEnvironment -AppId $credential.UserName -Quiet
            Update-MSGraphEnvironment -AuthUrl "https://login.windows.net/$tenantId" -Quiet
            $null = Connect-MSGraph -ClientSecret $credential.GetNetworkCredential().Password -ErrorAction Stop
        } else {
            # user logon
            if ($credential) {
                $null = Connect-MSGraph -Credential $credential -ErrorAction Stop
                # $header = New-GraphAPIAuthHeader -credential $credential -ErrorAction Stop
            } else {
                $null = Connect-MSGraph -ErrorAction Stop
                # $header = New-GraphAPIAuthHeader -ErrorAction Stop
            }
        }

        Write-Verbose "Getting Intune data"
        # filtering by ID is as slow as getting all data
        # Invoke-MSGraphRequest -Url 'https://graph.microsoft.com/beta/deviceAppManagement/mobileApps?$filter=(id%20eq%20%2756695a77-925a-4df0-be79-24ed039afa86%27)'
        $intuneRemediationScript = Invoke-MSGraphRequest -Url "https://graph.microsoft.com/beta/deviceManagement/deviceHealthScripts?select=id,displayname" | Get-MSGraphAllPages
        $intuneScript = Invoke-MSGraphRequest -Url "https://graph.microsoft.com/beta/deviceManagement/deviceManagementScripts?select=id,displayname" | Get-MSGraphAllPages
        $intuneApp = Invoke-MSGraphRequest -Url "https://graph.microsoft.com/beta/deviceAppManagement/mobileApps?select=id,displayname" | Get-MSGraphAllPages
        $intuneUser = Invoke-MSGraphRequest -Url 'https://graph.microsoft.com/beta/users?select=id,userPrincipalName' | Get-MSGraphAllPages
    }
    #endregion prepare

    #region helper functions
    if (!(Get-Command 'ConvertFrom-MDMDiagReportXML' -ErrorAction SilentlyContinue)) {
        function ConvertFrom-MDMDiagReportXML {
            <#
    .SYNOPSIS
    Function for converting Intune XML report generated by MdmDiagnosticsTool.exe to a PowerShell object.

    .DESCRIPTION
    Function for converting Intune XML report generated by MdmDiagnosticsTool.exe to a PowerShell object.
    There is also option to generate HTML report instead.

    .PARAMETER computerName
    (optional) Computer name from which you want to get data from.

    .PARAMETER MDMDiagReport
    Path to MDMDiagReport.xml.

    If not specified, new report will be generated and used.

    .PARAMETER asHTML
    Switch for outputting results as a HTML page instead of PowerShell object.
    PSWriteHtml module is required!

    .PARAMETER HTMLReportPath
    Path to html file where HTML report should be stored.

    Default is '<yourUserProfile>\IntuneReport.html'.

    .PARAMETER showEnrollmentIDs
    Switch for adding EnrollmentID property i.e. property containing Enrollment ID of given policy.
    From my point of view its useless :).

    .PARAMETER showURLs
    Switch for adding PolicyURL and PolicySettingsURL properties i.e. properties containing URL with Microsoft documentation for given CSP.

    Make running the function slower! Because I test each URL and shows just existing ones.

    .PARAMETER showConnectionData
    Switch for showing Intune connection data.
    Beware that this will add new object type to the output (but it doesn't matter if you use asHTML switch).

    .EXAMPLE
    $intuneReport = ConvertFrom-MDMDiagReportXML
    $intuneReport | Out-GridView

    Generates new Intune report, converts it into PowerShell object and output it using Out-GridView.

    .EXAMPLE
    ConvertFrom-MDMDiagReportXML -asHTML -showURLs

    Generates new Intune report (policies documentation URL included), converts it into HTML web page and opens it.

    .NOTES
    Author: Ondrej Sebela (ztrhgf@seznam.cz)
    URL: https://doitpsway.com/get-a-better-intune-policy-report-part-2
    #>

            [CmdletBinding()]
            param (
                [string] $computerName,

                [ValidateScript( {
                        if ($_ -match "\.xml$") {
                            $true
                        } else {
                            throw "$_ is not a valid path to MDM xml report"
                        }
                    })]
                [string] $MDMDiagReport,

                [switch] $asHTML,

                [ValidateScript( {
                        if ($_ -match "\.html$") {
                            $true
                        } else {
                            throw "$_ is not a valid path to html file. Enter something like 'C:\destination\intune.html'"
                        }
                    })]
                [string] $HTMLReportPath = (Join-Path $env:USERPROFILE "IntuneReport.html"),

                [switch] $showEnrollmentIDs,

                [switch] $showURLs,

                [switch] $showConnectionData
            )

            if ($asHTML) {
                # array of results that will be in the end transformed into HTML report
                $results = @()

                if (!(Get-Module 'PSWriteHtml') -and (!(Get-Module 'PSWriteHtml' -ListAvailable))) {
                    throw "Module PSWriteHtml is missing. To get it use command: Install-Module PSWriteHtml -Scope CurrentUser"
                }

                # create parent directory if not exists
                [Void][System.IO.Directory]::CreateDirectory((Split-Path $HTMLReportPath -Parent))
            }

            if ($computerName) {
                $session = New-PSSession -ComputerName $computerName -ErrorAction Stop
            }

            if (!$MDMDiagReport) {
                ++$reportNotSpecified
                $MDMDiagReport = "$env:PUBLIC\Documents\MDMDiagnostics\MDMDiagReport.xml"
            }

            $MDMDiagReportFolder = Split-Path $MDMDiagReport -Parent

            # generate XML report if necessary
            if ($reportNotSpecified) {
                if ($computerName) {
                    # XML report is on remote computer, transform to UNC path
                    $MDMDiagReport = "\\$computerName\$($MDMDiagReport -replace ":", "$")"
                    Write-Verbose "Generating '$MDMDiagReport'..."

                    try {
                        Invoke-Command -Session $session {
                            param ($MDMDiagReportFolder)

                            Start-Process MdmDiagnosticsTool.exe -Wait -ArgumentList "-out `"$MDMDiagReportFolder`"" -NoNewWindow -ErrorAction Stop
                        } -ArgumentList $MDMDiagReportFolder -ErrorAction Stop
                    } catch {
                        throw "Unable to generate XML report`nError: $($_.Exception.Message) - Line Number: $($_.InvocationInfo.ScriptLineNumber)"
                    }
                } else {
                    Write-Verbose "Generating '$MDMDiagReport'..."
                    Start-Process MdmDiagnosticsTool.exe -Wait -ArgumentList "-out `"$MDMDiagReportFolder`"" -NoNewWindow
                }
            }
            if (!(Test-Path $MDMDiagReport -PathType Leaf)) {
                Write-Verbose "'$MDMDiagReport' doesn't exist, generating..."
                Start-Process MdmDiagnosticsTool.exe -Wait -ArgumentList "-out `"$MDMDiagReportFolder`"" -NoNewWindow
            }

            Write-Verbose "Converting '$MDMDiagReport' to XML object"
            [xml]$xml = Get-Content $MDMDiagReport -Raw -ErrorAction Stop

            #region get enrollmentID
            Write-Verbose "Getting EnrollmentID"
            $scriptBlock = {
                Get-ScheduledTask -TaskName "*pushlaunch*" -TaskPath "\Microsoft\Windows\EnterpriseMgmt\*" | Select-Object -ExpandProperty TaskPath | Split-Path -Leaf
            }
            $param = @{
                scriptBlock = $scriptBlock
            }
            if ($computerName) {
                $param.session = $session
            }

            $userEnrollmentID = Invoke-Command @param

            Write-Verbose "Your EnrollmentID is $userEnrollmentID"
            #endregion get enrollmentID

            #region connection data
            if ($showConnectionData) {
                Write-Verbose "Getting connection data"
                $connectionInfo = $xml.MDMEnterpriseDiagnosticsReport.DeviceManagementAccount.Enrollment | ? EnrollmentId -EQ $userEnrollmentID

                if ($connectionInfo) {
                    [PSCustomObject]@{
                        "EnrollmentId"          = $connectionInfo.EnrollmentId
                        "MDMServerName"         = $connectionInfo.ProtectedInformation.MDMServerName
                        "LastSuccessConnection" = [DateTime]::ParseExact(($connectionInfo.ProtectedInformation.ConnectionInformation.ServerLastSuccessTime -replace "Z$"), 'yyyyMMddTHHmmss', $null)
                        "LastFailureConnection" = [DateTime]::ParseExact(($connectionInfo.ProtectedInformation.ConnectionInformation.ServerLastFailureTime -replace "Z$"), 'yyyyMMddTHHmmss', $null)
                    }
                } else {
                    Write-Verbose "Unable to get connection data from $MDMDiagReport"
                }
            }
            #endregion connection data

            #region helper functions
            function _getTargetName {
                param ([string] $id)

                Write-Verbose "Translating $id"

                if (!$id) {
                    Write-Verbose "id was null"
                    return
                } elseif ($id -eq 'device') {
                    # xml nodes contains 'device' instead of 'Device'
                    return 'Device'
                }

                $errPref = $ErrorActionPreference
                $ErrorActionPreference = "Stop"
                try {
                    if ($id -eq '00000000-0000-0000-0000-000000000000' -or $id -eq 'S-0-0-00-0000000000-0000000000-000000000-000') {
                        return 'Device'
                    } elseif ($id -match "^S-1-5-21") {
                        # it is local account
                        if ($computerName) {
                            Invoke-Command -Session $session {
                                param ($id)

                                $ErrorActionPreference = "Stop"
                                try {
                                    return ((New-Object System.Security.Principal.SecurityIdentifier($id)).Translate([System.Security.Principal.NTAccount])).Value
                                } catch {
                                    throw 1
                                }
                            } -ArgumentList $id
                        } else {
                            return ((New-Object System.Security.Principal.SecurityIdentifier($id)).Translate([System.Security.Principal.NTAccount])).Value
                        }
                    } else {
                        # it is AzureAD account
                        if ($getDataFromIntune) {
                            return (Invoke-MSGraphRequest -Url "https://graph.microsoft.com/beta/users/$id").userPrincipalName
                        } else {
                            # unable to translate ID to name because there is no connection to the Intune Graph API
                            return $id
                        }
                    }
                } catch {
                    Write-Verbose "Unable to translate $id account name"
                    $ErrorActionPreference = $errPref
                    return $id
                }
            }

            function ConvertFrom-XML {
                <#
        .SYNOPSIS
        Function for converting XML object (XmlNode) to PSObject.

        .DESCRIPTION
        Function for converting XML object (XmlNode) to PSObject.

        .PARAMETER node
        XmlNode object (retrieved like: [xml]$xmlObject = (Get-Content C:\temp\file.xml -Raw))

        .EXAMPLE
        [xml]$xmlObject = (Get-Content C:\temp\file.xml -Raw)
        ConvertFrom-XML $xmlObject

        .NOTES
        Based on https://stackoverflow.com/questions/3242995/convert-xml-to-psobject
        #>

                [CmdletBinding()]
                param (
                    [Parameter(Mandatory = $true, ValueFromPipeline)]
                    [System.Xml.XmlNode] $node
                )

                #region helper functions

                function ConvertTo-PsCustomObjectFromHashtable {
                    param (
                        [Parameter(
                            Position = 0,
                            Mandatory = $true,
                            ValueFromPipeline = $true,
                            ValueFromPipelineByPropertyName = $true
                        )] [object[]]$hashtable
                    );

                    begin { $i = 0; }

                    process {
                        foreach ($myHashtable in $hashtable) {
                            if ($myHashtable.GetType().Name -eq 'hashtable') {
                                $output = New-Object -TypeName PsObject;
                                Add-Member -InputObject $output -MemberType ScriptMethod -Name AddNote -Value {
                                    Add-Member -InputObject $this -MemberType NoteProperty -Name $args[0] -Value $args[1];
                                };
                                $myHashtable.Keys | Sort-Object | % {
                                    $output.AddNote($_, $myHashtable.$_);
                                }
                                $output
                            } else {
                                Write-Warning "Index $i is not of type [hashtable]";
                            }
                            $i += 1;
                        }
                    }
                }
                #endregion helper functions

                $hash = @{}

                foreach ($attribute in $node.attributes) {
                    $hash.$($attribute.name) = $attribute.Value
                }

                $childNodesList = ($node.childnodes | ? { $_ -ne $null }).LocalName

                foreach ($childnode in ($node.childnodes | ? { $_ -ne $null })) {
                    if (($childNodesList.where( { $_ -eq $childnode.LocalName })).count -gt 1) {
                        if (!($hash.$($childnode.LocalName))) {
                            Write-Verbose "ChildNode '$($childnode.LocalName)' isn't in hash. Creating empty array and storing in hash.$($childnode.LocalName)"
                            $hash.$($childnode.LocalName) += @()
                        }
                        if ($childnode.'#text') {
                            Write-Verbose "Into hash.$($childnode.LocalName) adding '$($childnode.'#text')'"
                            $hash.$($childnode.LocalName) += $childnode.'#text'
                        } else {
                            Write-Verbose "Into hash.$($childnode.LocalName) adding result of ConvertFrom-XML called upon '$($childnode.Name)' node object"
                            $hash.$($childnode.LocalName) += ConvertFrom-XML($childnode)
                        }
                    } else {
                        Write-Verbose "In ChildNode list ($($childNodesList -join ', ')) is only one node '$($childnode.LocalName)'"

                        if ($childnode.'#text') {
                            Write-Verbose "Into hash.$($childnode.LocalName) set '$($childnode.'#text')'"
                            $hash.$($childnode.LocalName) = $childnode.'#text'
                        } else {
                            Write-Verbose "Into hash.$($childnode.LocalName) set result of ConvertFrom-XML called upon '$($childnode.Name)' $($childnode.Value) object"
                            $hash.$($childnode.LocalName) = ConvertFrom-XML($childnode)
                        }
                    }
                }

                Write-Verbose "Returning hash ($($hash.Values -join ', '))"
                return $hash | ConvertTo-PsCustomObjectFromHashtable
            }

            function Test-URLStatus {
                param ($URL)

                try {
                    $response = [System.Net.WebRequest]::Create($URL).GetResponse()
                    $status = $response.StatusCode
                    $response.Close()
                    if ($status -eq 'OK') { return $true } else { return $false }
                } catch {
                    return $false
                }
            }

            function _translateStatus {
                param ([int] $statusCode)

                $statusMessage = ""

                switch ($statusCode) {
                    '10' { $statusMessage = "Initialized" }
                    '20' { $statusMessage = "Download In Progress" }
                    '25' { $statusMessage = "Pending Download Retry" }
                    '30' { $statusMessage = "Download Failed" }
                    '40' { $statusMessage = "Download Completed" }
                    '48' { $statusMessage = "Pending User Session" }
                    '50' { $statusMessage = "Enforcement In Progress" }
                    '55' { $statusMessage = "Pending Enforcement Retry" }
                    '60' { $statusMessage = "Enforcement Failed" }
                    '70' { $statusMessage = "Enforcement Completed" }
                    default { $statusMessage = $statusCode }
                }

                return $statusMessage
            }
            #endregion helper functions

            if ($showURLs) {
                $clientIsOnline = Test-URLStatus 'https://google.com'
            }

            #region enrollments
            Write-Verbose "Getting Enrollments (MDMEnterpriseDiagnosticsReport.Resources.Enrollment)"
            $enrollment = $xml.MDMEnterpriseDiagnosticsReport.Resources.Enrollment | % { ConvertFrom-XML $_ }

            if ($enrollment) {
                Write-Verbose "Processing Enrollments"

                $enrollment | % {
                    <#
            <Resources>
                <Enrollment>
                    <EnrollmentID>5AFCD0A0-321F-4635-B3EB-2EBD28A0FD9A</EnrollmentID>
                    <Scope>
                    <ResourceTarget>device</ResourceTarget>
                    <Resources>
                        <Type>default</Type>
                        <ResourceName>./device/Vendor/MSFT/DeviceManageability/Provider/WMI_Bridge_Server</ResourceName>
                        <ResourceName>2</ResourceName>
                        <ResourceName>./device/Vendor/MSFT/VPNv2/K_AlwaysOn_VPN</ResourceName>
                    </Resources>
                    </Scope>
            #>
                    $policy = $_
                    $enrollmentId = $_.EnrollmentId

                    $policy.Scope | % {
                        $scope = _getTargetName $_.ResourceTarget

                        foreach ($policyAreaName in $_.Resources.ResourceName) {
                            # some policies have just number instead of any name..I don't know what it means so I ignore them
                            if ($policyAreaName -match "^\d+$") {
                                continue
                            }
                            # get rid of MSI installations (I have them with details in separate section)
                            if ($policyAreaName -match "/Vendor/MSFT/EnterpriseDesktopAppManagement/MSI") {
                                continue
                            }
                            # get rid of useless data
                            if ($policyAreaName -match "device/Vendor/MSFT/DeviceManageability/Provider/WMI_Bridge_Server") {
                                continue
                            }

                            Write-Verbose "`nEnrollment '$enrollmentId' applied to '$scope' configures resource '$policyAreaName'"

                            #region get policy settings details
                            $settingDetails = $null
                            #TODO zjistit co presne to nastavuje
                            # - policymanager.configsource.policyscope.Area

                            <#
                    <ErrorLog>
                        <Component>ConfigManager</Component>
                        <SubComponent>
                            <Name>BitLocker</Name>
                            <Error>-2147024463</Error>
                            <Metadata1>CmdType_Set</Metadata1>
                            <Metadata2>./Device/Vendor/MSFT/BitLocker/RequireDeviceEncryption</Metadata2>
                            <Time>2021-09-23 07:07:05.463</Time>
                        </SubComponent>
                    #>
                            Write-Verbose "Getting Errors (MDMEnterpriseDiagnosticsReport.Diagnostics.ErrorLog)"
                            # match operator used for metadata2 because for example WIFI networks are saved there as ./Vendor/MSFT/WiFi/Profile/<wifiname> instead of ./Vendor/MSFT/WiFi/Profile
                            foreach ($errorRecord in $xml.MDMEnterpriseDiagnosticsReport.Diagnostics.ErrorLog) {
                                $component = $errorRecord.component
                                $errorRecord.subComponent | % {
                                    $subComponent = $_

                                    if ($subComponent.name -eq $policyAreaName -or $subComponent.Metadata2 -match [regex]::Escape($policyAreaName)) {
                                        $settingDetails = $subComponent | Select-Object @{n = 'Component'; e = { $component } }, @{n = 'SubComponent'; e = { $subComponent.Name } }, @{n = 'SettingName'; e = { $policyAreaName } }, Error, @{n = 'Time'; e = { Get-Date $subComponent.Time } }
                                        break
                                    }
                                }
                            }

                            if (!$settingDetails) {
                                # try more "relaxed" search
                                if ($policyAreaName -match "/") {
                                    # it is just common setting, try to find it using last part of the policy name
                                    $policyAreaNameID = ($policyAreaName -split "/")[-1]
                                    Write-Verbose "try to find just ID part ($policyAreaNameID) of the policy name in MDMEnterpriseDiagnosticsReport.Diagnostics.ErrorLog"
                                    # I don't search substring of policy name in Metadata2 because there can be multiple similar policies (./user/Vendor/MSFT/VPNv2/VPN_Backup vs ./device/Vendor/MSFT/VPNv2/VPN_Backup)
                                    foreach ($errorRecord in $xml.MDMEnterpriseDiagnosticsReport.Diagnostics.ErrorLog) {
                                        $component = $errorRecord.component
                                        $errorRecord.subComponent | % {
                                            $subComponent = $_

                                            if ($subComponent.name -eq $policyAreaNameID) {
                                                $settingDetails = $subComponent | Select-Object @{n = 'Component'; e = { $component } }, @{n = 'SubComponent'; e = { $subComponent.Name } }, @{n = 'SettingName'; e = { $policyAreaName } }, Error, @{n = 'Time'; e = { Get-Date $subComponent.Time } }
                                                break
                                            }
                                        }
                                    }
                                } else {
                                    Write-Verbose "'$policyAreaName' doesn't contains '/'"
                                }

                                if (!$settingDetails) {
                                    Write-Verbose "No additional data was found for '$policyAreaName' (it means it was successfully applied)"
                                }
                            }
                            #endregion get policy settings details

                            # get CSP policy URL if available
                            if ($showURLs) {
                                if ($policyAreaName -match "/") {
                                    $pName = ($policyAreaName -split "/")[-2]
                                } else {
                                    $pName = $policyAreaName
                                }
                                $policyURL = "https://docs.microsoft.com/en-us/windows/client-management/mdm/$pName-csp"
                                # check that URL exists
                                if ($clientIsOnline) {
                                    if (!(Test-URLStatus $policyURL)) {
                                        # URL doesn't exist
                                        if ($policyAreaName -match "/") {
                                            # sometimes name of the CSP is not second from the end but third
                                            $pName = ($policyAreaName -split "/")[-3]
                                            $policyURL = "https://docs.microsoft.com/en-us/windows/client-management/mdm/$pName-csp"
                                            if (!(Test-URLStatus $policyURL)) {
                                                $policyURL = $null
                                            }
                                        } else {
                                            $policyURL = "https://docs.microsoft.com/en-us/windows/client-management/mdm/policy-csp-$pName"
                                            if (!(Test-URLStatus $policyURL)) {
                                                $policyURL = $null
                                            }
                                        }
                                    }
                                }
                            }

                            #region return retrieved data
                            $property = [ordered] @{
                                Scope          = $scope
                                PolicyName     = $policyAreaName
                                SettingName    = $policyAreaName
                                SettingDetails = $settingDetails
                            }
                            if ($showEnrollmentIDs) { $property.EnrollmentId = $enrollmentId }
                            if ($showURLs) { $property.PolicyURL = $policyURL }
                            $result = New-Object -TypeName PSObject -Property $property

                            if ($asHTML) {
                                $results += $result
                            } else {
                                $result
                            }
                            #endregion return retrieved data
                        }
                    }
                }
            }
            #endregion enrollments

            #region policies
            Write-Verbose "Getting Policies (MDMEnterpriseDiagnosticsReport.PolicyManager.ConfigSource)"
            $policyManager = $xml.MDMEnterpriseDiagnosticsReport.PolicyManager.ConfigSource | % { ConvertFrom-XML $_ }
            # filter out useless knobs
            $policyManager = $policyManager | ? { $_.policyScope.Area.PolicyAreaName -ne 'knobs' }

            if ($policyManager) {
                Write-Verbose "Processing Policies"

                # get policies metadata
                Write-Verbose "Getting Policies Area metadata (MDMEnterpriseDiagnosticsReport.PolicyManager.AreaMetadata)"
                $policyAreaNameMetadata = $xml.MDMEnterpriseDiagnosticsReport.PolicyManager.AreaMetadata
                # get admx policies metadata
                # there are duplicities, so pick just last one
                Write-Verbose "Getting Policies ADMX metadata (MDMEnterpriseDiagnosticsReport.PolicyManager.IngestedAdmxPolicyMetadata)"
                $admxPolicyAreaNameMetadata = $xml.MDMEnterpriseDiagnosticsReport.PolicyManager.IngestedAdmxPolicyMetadata | % { ConvertFrom-XML $_ }

                Write-Verbose "Getting Policies winning provider (MDMEnterpriseDiagnosticsReport.PolicyManager.CurrentPolicies.CurrentPolicyValues)"
                $winningProviderPolicyAreaNameMetadata = $xml.MDMEnterpriseDiagnosticsReport.PolicyManager.CurrentPolicies.CurrentPolicyValues | % {
                    $_.psobject.properties | ? { $_.Name -Match "_WinningProvider$" } | Select-Object Name, Value
                }

                $policyManager | % {
                    $policy = $_
                    $enrollmentId = $_.EnrollmentId

                    $policy.policyScope | % {
                        $scope = _getTargetName $_.PolicyScope
                        $_.Area | % {
                            <#
                    <ConfigSource>
                        <EnrollmentId>AB068787-67D2-4F7C-AA87-A9127A87411F</EnrollmentId>
                        <PolicyScope>
                            <PolicyScope>Device</PolicyScope>
                            <Area>
                                <PolicyAreaName>BitLocker</PolicyAreaName>
                                <AllowWarningForOtherDiskEncryption>0</AllowWarningForOtherDiskEncryption>
                                <AllowWarningForOtherDiskEncryption_LastWrite>1</AllowWarningForOtherDiskEncryption_LastWrite>
                                <RequireDeviceEncryption>1</RequireDeviceEncryption>
                    #>

                            $policyAreaName = $_.PolicyAreaName
                            Write-Verbose "`nEnrollment '$enrollmentId' applied to '$scope' configures area '$policyAreaName'"
                            $policyAreaSetting = $_ | Select-Object -Property * -ExcludeProperty 'PolicyAreaName', "*_LastWrite"
                            $policyAreaSettingName = $policyAreaSetting | Get-Member -MemberType NoteProperty | Select-Object -ExpandProperty name
                            if ($policyAreaSettingName.count -eq 1 -and $policyAreaSettingName -eq "*") {
                                # bug? when there is just PolicyAreaName and none other object than probably because of exclude $policyAreaSettingName instead of be null returns one empty object '*'
                                $policyAreaSettingName = $null
                                $policyAreaSetting = $null
                            }

                            #region get policy settings details
                            $settingDetails = @()

                            if ($policyAreaSetting) {
                                Write-Verbose "`tIt configures these settings:"

                                # $policyAreaSetting is object, so I have to iterate through its properties
                                foreach ($setting in $policyAreaSetting.PSObject.Properties) {
                                    $settingName = $setting.Name
                                    $settingValue = $setting.Value

                                    # PolicyAreaName property was already picked up so now I will ignore it
                                    if ($settingName -eq "PolicyAreaName") { continue }

                                    Write-Verbose "`t`t- $settingName ($settingValue)"

                                    # makes test of url slow
                                    # if ($clientIsOnline) {
                                    #     if (!(Test-URLStatus $policyDetailsURL)) {
                                    #         # URL doesn't exist
                                    #         $policyDetailsURL = $null
                                    #     }
                                    # }

                                    if ($showURLs) {
                                        if ($policyAreaName -match "~Policy~OneDriveNGSC") {
                                            # doesn't have policy csp url
                                            $policyDetailsURL = $null
                                        } else {
                                            $policyDetailsURL = "https://docs.microsoft.com/en-us/windows/client-management/mdm/policy-csp-$policyAreaName#$(($policyAreaName).tolower())-$(($settingName).tolower())"
                                        }
                                    }

                                    # define base object
                                    $property = [ordered]@{
                                        "SettingName"     = $settingName
                                        "Value"           = $settingValue
                                        "DefaultValue"    = $null
                                        "PolicyType"      = '*unknown*'
                                        "RegKey"          = '*unknown*'
                                        "RegValueName"    = '*unknown*'
                                        "SourceAdmxFile"  = $null
                                        "WinningProvider" = $null
                                    }
                                    if ($showURLs) { $property.PolicyDetailsURL = $policyDetailsURL }

                                    $additionalData = $policyAreaNameMetadata | ? PolicyAreaName -EQ $policyAreaName | Select-Object -ExpandProperty PolicyMetadata | ? PolicyName -EQ $settingName | Select-Object PolicyType, Value, RegKeyPathRedirect, RegValueNameRedirect

                                    if ($additionalData) {
                                        Write-Verbose "Additional data for '$settingName' was found in policyAreaNameMetadata"
                                        <#
                                <PolicyMetadata>
                                    <PolicyName>RecoveryEnvironmentAuthentication</PolicyName>
                                    <Behavior>49</Behavior>
                                    <highrange>2</highrange>
                                    <lowrange>0</lowrange>
                                    <mergealgorithm>3</mergealgorithm>
                                    <policytype>4</policytype>
                                    <RegKeyPathRedirect>Software\Policies\Microsoft\WinRE</RegKeyPathRedirect>
                                    <RegValueNameRedirect>WinREAuthenticationRequirement</RegValueNameRedirect>
                                    <value>0</value>
                                </PolicyMetadata>
                                #>
                                        $property.DefaultValue = $additionalData.Value
                                        $property.PolicyType = $additionalData.PolicyType
                                        $property.RegKey = $additionalData.RegKeyPathRedirect
                                        $property.RegValueName = $additionalData.RegValueNameRedirect
                                    } else {
                                        # no additional data was found in policyAreaNameMetadata
                                        # trying to get them from admxPolicyAreaNameMetadata

                                        <#
                                <IngestedADMXPolicyMetaData>
                                    <EnrollmentId>11120759-7CE3-4683-AB59-46C27FF40D35</EnrollmentId>
                                    <AreaName>
                                        <ADMXIngestedAreaName>OneDriveNGSCv2~Policy~OneDriveNGSC</ADMXIngestedAreaName>
                                        <PolicyMetadata>
                                            <PolicyName>BlockExternalSync</PolicyName>
                                            <SourceAdmxFile>OneDriveNGSCv2</SourceAdmxFile>
                                            <Behavior>224</Behavior>
                                            <MergeAlgorithm>3</MergeAlgorithm>
                                            <RegKeyPathRedirect>SOFTWARE\Policies\Microsoft\OneDrive</RegKeyPathRedirect>
                                            <RegValueNameRedirect>BlockExternalSync</RegValueNameRedirect>
                                            <PolicyType>1</PolicyType>
                                            <AdmxMetadataDevice>30313D0100000000323D000000000000</AdmxMetadataDevice>
                                        </PolicyMetadata>
                                #>
                                        $additionalData = ($admxPolicyAreaNameMetadata.AreaName | ? { $_.ADMXIngestedAreaName -eq $policyAreaName }).PolicyMetadata | ? { $_.PolicyName -EQ $settingName } | select -First 1 # sometimes there are duplicities in results

                                        if ($additionalData) {
                                            Write-Verbose "Additional data for '$settingName' was found in admxPolicyAreaNameMetadata"
                                            $property.PolicyType = $additionalData.PolicyType
                                            $property.RegKey = $additionalData.RegKeyPathRedirect
                                            $property.RegValueName = $additionalData.RegValueNameRedirect
                                            $property.SourceAdmxFile = $additionalData.SourceAdmxFile
                                        } else {
                                            Write-Verbose "No additional data found for $settingName"
                                        }
                                    }

                                    $winningProvider = $winningProviderPolicyAreaNameMetadata | ? Name -EQ "$settingName`_WinningProvider" | Select-Object -ExpandProperty Value
                                    if ($winningProvider) {
                                        if ($winningProvider -eq $userEnrollmentID) {
                                            $winningProvider = 'Intune'
                                        }

                                        $property.WinningProvider = $winningProvider
                                    }

                                    $settingDetails += New-Object -TypeName PSObject -Property $property
                                }
                            } else {
                                Write-Verbose "`tIt doesn't contain any settings"
                            }
                            #endregion get policy settings details

                            # get CSP policy URL if available
                            if ($showURLs) {
                                if ($policyAreaName -match "/") {
                                    $pName = ($policyAreaName -split "/")[-2]
                                } else {
                                    $pName = $policyAreaName
                                }
                                $policyURL = "https://docs.microsoft.com/en-us/windows/client-management/mdm/$pName-csp"
                                # check that URL exists
                                if ($clientIsOnline) {
                                    if (!(Test-URLStatus $policyURL)) {
                                        # URL doesn't exist
                                        if ($policyAreaName -match "/") {
                                            # sometimes name of the CSP is not second from the end but third
                                            $pName = ($policyAreaName -split "/")[-3]
                                            $policyURL = "https://docs.microsoft.com/en-us/windows/client-management/mdm/$pName-csp"
                                            if (!(Test-URLStatus $policyURL)) {
                                                $policyURL = $null
                                            }
                                        } else {
                                            $policyURL = "https://docs.microsoft.com/en-us/windows/client-management/mdm/policy-csp-$pName"
                                            if (!(Test-URLStatus $policyURL)) {
                                                $policyURL = $null
                                            }
                                        }
                                    }
                                }
                            }

                            #region return retrieved data
                            $property = [ordered] @{
                                Scope          = $scope
                                PolicyName     = $policyAreaName
                                SettingName    = $policyAreaSettingName
                                SettingDetails = $settingDetails
                            }
                            if ($showEnrollmentIDs) { $property.EnrollmentId = $enrollmentId }
                            if ($showURLs) { $property.PolicyURL = $policyURL }
                            $result = New-Object -TypeName PSObject -Property $property

                            if ($asHTML) {
                                $results += $result
                            } else {
                                $result
                            }
                            #endregion return retrieved data
                        }
                    }
                }
            }
            #endregion policies

            #region installations
            Write-Verbose "Getting MSI installations (MDMEnterpriseDiagnosticsReport.EnterpriseDesktopAppManagementinfo.MsiInstallations)"
            $installation = $xml.MDMEnterpriseDiagnosticsReport.EnterpriseDesktopAppManagementinfo.MsiInstallations | % { ConvertFrom-XML $_ }
            if ($installation) {
                Write-Verbose "Processing MSI installations"

                $settingDetails = @()

                $installation.TargetedUser | % {
                    <#
            <MsiInstallations>
                <TargetedUser>
                <UserSid>S-0-0-00-0000000000-0000000000-000000000-000</UserSid>
                <Package>
                    <Type>MSI</Type>
                    <Details>
                    <PackageId>{23170F69-40C1-2702-1900-000001000000}</PackageId>
                    <DownloadInstall>Ready</DownloadInstall>
                    <ProductCode>{23170F69-40C1-2702-1900-000001000000}</ProductCode>
                    <ProductVersion>19.00.00.0</ProductVersion>
                    <ActionType>1</ActionType>
                    <Status>70</Status>
                    <JobStatusReport>1</JobStatusReport>
                    <LastError>0</LastError>
                    <BITSJobId></BITSJobId>
                    <DownloadLocation></DownloadLocation>
                    <CurrentDownloadUrlIndex>0</CurrentDownloadUrlIndex>
                    <CurrentDownloadUrl></CurrentDownloadUrl>
                    <FileHash>A7803233EEDB6A4B59B3024CCF9292A6FFFB94507DC998AA67C5B745D197A5DC</FileHash>
                    <CommandLine>ALLUSERS=1</CommandLine>
                    <AssignmentType>1</AssignmentType>
                    <EnforcementTimeout>30</EnforcementTimeout>
                    <EnforcementRetryIndex>0</EnforcementRetryIndex>
                    <EnforcementRetryCount>5</EnforcementRetryCount>
                    <EnforcementRetryInterval>3</EnforcementRetryInterval>
                    <LocURI>./Device/Vendor/MSFT/EnterpriseDesktopAppManagement/MSI/{23170F69-40C1-2702-1900-000001000000}/DownloadInstall</LocURI>
                    <ServerAccountID>11120759-7CE3-4683-FB59-46C27FF40D35</ServerAccountID>
                    </Details>
            #>

                    $userSID = $_.UserSid
                    $type = $_.Package.Type
                    $details = $_.Package.details

                    $details | % {
                        Write-Verbose "`t$($_.PackageId) of type $type"

                        # define base object
                        $property = [ordered]@{
                            "Scope"          = _getTargetName $userSID
                            "Type"           = $type
                            "Status"         = _translateStatus $_.Status
                            "LastError"      = $_.LastError
                            "ProductVersion" = $_.ProductVersion
                            "CommandLine"    = $_.CommandLine
                            "RetryIndex"     = $_.EnforcementRetryIndex
                            "MaxRetryCount"  = $_.EnforcementRetryCount
                            "PackageId"      = $_.PackageId -replace "{" -replace "}"
                        }
                        $settingDetails += New-Object -TypeName PSObject -Property $property
                    }
                }

                #region return retrieved data
                $property = [ordered] @{
                    Scope          = $null
                    PolicyName     = "SoftwareInstallation" # made up!
                    SettingName    = $null
                    SettingDetails = $settingDetails
                }
                if ($showEnrollmentIDs) { $property.EnrollmentId = $null }
                if ($showURLs) { $property.PolicyURL = $null } # this property only to have same properties for all returned objects
                $result = New-Object -TypeName PSObject -Property $property

                if ($asHTML) {
                    $results += $result
                } else {
                    $result
                }
                #endregion return retrieved data
            }
            #endregion installations

            #region convert results to HTML and output
            if ($asHTML -and $results) {
                Write-Verbose "Converting to HTML"

                # split the results
                $resultsWithSettings = @()
                $resultsWithoutSettings = @()
                $results | % {
                    if ($_.settingDetails) {
                        $resultsWithSettings += $_
                    } else {
                        $resultsWithoutSettings += $_
                    }
                }

                New-HTML -TitleText "Intune Report" -Online -FilePath $HTMLReportPath -ShowHTML {
                    # it looks better to have headers and content in center
                    New-HTMLTableStyle -TextAlign center

                    New-HTMLSection -HeaderText 'Intune Report' -Direction row -HeaderBackGroundColor Black -HeaderTextColor White -HeaderTextSize 20 {
                        if ($resultsWithoutSettings) {
                            New-HTMLSection -HeaderText "Policies without settings details" -HeaderTextAlignment left -CanCollapse -BackgroundColor DeepSkyBlue -HeaderBackGroundColor DeepSkyBlue -HeaderTextSize 10 -HeaderTextColor EgyptianBlue -Direction row {
                                #region prepare data
                                # exclude some not significant or needed properties
                                # SettingName is empty (or same as PolicyName)
                                # settingDetails is empty
                                $excludeProperty = @('SettingName', 'SettingDetails')
                                if (!$showEnrollmentIDs) { $excludeProperty += 'EnrollmentId' }
                                if (!$showURLs) { $excludeProperty += 'PolicyURL' }
                                $resultsWithoutSettings = $resultsWithoutSettings | Select-Object -Property * -exclude $excludeProperty
                                # sort
                                $resultsWithoutSettings = $resultsWithoutSettings | Sort-Object -Property Scope, PolicyName
                                #endregion prepare data

                                # render policies
                                New-HTMLSection -HeaderText 'Policy' -HeaderBackGroundColor Wedgewood -BackgroundColor White {
                                    New-HTMLTable -DataTable $resultsWithoutSettings -WordBreak 'break-all' -DisableInfo -HideButtons -DisablePaging -FixedHeader -FixedFooter
                                }
                            }
                        }

                        if ($resultsWithSettings) {
                            New-HTMLSection -HeaderText "Policies with settings details" -HeaderTextAlignment left -CanCollapse -BackgroundColor DeepSkyBlue -HeaderBackGroundColor DeepSkyBlue -HeaderTextSize 10 -HeaderTextColor EgyptianBlue -Direction row {
                                # sort
                                $resultsWithSettings = $resultsWithSettings | Sort-Object -Property Scope, PolicyName

                                $resultsWithSettings | % {
                                    $policy = $_
                                    $policySetting = $_.settingDetails

                                    #region prepare data
                                    # exclude some not significant or needed properties
                                    # SettingName is useless in HTML report from my point of view
                                    # settingDetails will be shown in separate table, omit here
                                    if ($showEnrollmentIDs) {
                                        $excludeProperty = 'SettingName', 'SettingDetails'
                                    } else {
                                        $excludeProperty = 'SettingName', 'SettingDetails', 'EnrollmentId'
                                    }

                                    $policy = $policy | Select-Object -Property * -ExcludeProperty $excludeProperty
                                    #endregion prepare data

                                    New-HTMLSection -HeaderText $policy.PolicyName -HeaderTextAlignment left -CanCollapse -BackgroundColor White -HeaderBackGroundColor White -HeaderTextSize 12 -HeaderTextColor EgyptianBlue {
                                        # render main policy
                                        New-HTMLSection -HeaderText 'Policy' -HeaderBackGroundColor Wedgewood -BackgroundColor White {
                                            New-HTMLTable -DataTable $policy -WordBreak 'break-all' -HideFooter -DisableInfo -HideButtons -DisablePaging -DisableSearch -DisableOrdering
                                        }

                                        # render policy settings details
                                        if ($policySetting) {
                                            if (@($policySetting).count -eq 1) {
                                                $detailsHTMLTableParam = @{
                                                    DisableSearch   = $true
                                                    DisableOrdering = $true
                                                }
                                            } else {
                                                $detailsHTMLTableParam = @{}
                                            }
                                            New-HTMLSection -HeaderText 'Policy settings' -HeaderBackGroundColor PictonBlue -BackgroundColor White {
                                                New-HTMLTable @detailsHTMLTableParam -DataTable $policySetting -WordBreak 'break-all' -AllProperties -FixedHeader -HideFooter -DisableInfo -HideButtons -DisablePaging -WarningAction SilentlyContinue {
                                                    New-HTMLTableCondition -Name 'WinningProvider' -ComparisonType string -Operator 'ne' -Value 'Intune' -BackgroundColor Red -Color White #-Row
                                                    New-HTMLTableCondition -Name 'LastError' -ComparisonType number -Operator 'ne' -Value 0 -BackgroundColor Red -Color White # -Row
                                                    New-HTMLTableCondition -Name 'Error' -ComparisonType number -Operator 'ne' -Value 0 -BackgroundColor Red -Color White # -Row
                                                }
                                            }
                                        }
                                    }

                                    # hack for getting new line between sections
                                    New-HTMLText -Text '.' -Color DeepSkyBlue
                                }
                            }
                        }
                    } # end of main HTML section
                }
            }
            #endregion convert results to HTML and output

            if ($computerName) {
                Remove-PSSession $session
            }
        }
    }

    function _getTargetName {
        param ([string] $id)

        Write-Verbose "Translating $id"

        if (!$id) {
            Write-Verbose "id was null"
            return
        } elseif ($id -eq 'device') {
            # xml nodes contains 'device' instead of 'Device'
            return 'Device'
        }

        $errPref = $ErrorActionPreference
        $ErrorActionPreference = "Stop"
        try {
            if ($id -eq '00000000-0000-0000-0000-000000000000' -or $id -eq 'S-0-0-00-0000000000-0000000000-000000000-000') {
                return 'Device'
            } elseif ($id -match "^S-1-5-21") {
                # it is local account
                return ((New-Object System.Security.Principal.SecurityIdentifier($id)).Translate([System.Security.Principal.NTAccount])).Value
            } else {
                # it is AzureAD account
                if ($getDataFromIntune) {
                    return ($intuneUser | ? id -EQ $id).userPrincipalName
                } else {
                    # unable to translate ID to name because there is no connection to the Intune Graph API
                    return $id
                }
            }
        } catch {
            Write-Warning "Unable to translate $id to account name ($_)"
            $ErrorActionPreference = $errPref
            return $id
        }
    }
    function _getIntuneScript {
        param ([string] $scriptID)

        $intuneScript | ? id -EQ $scriptID
    }

    function _getIntuneApp {
        param ([string] $appID)

        $intuneApp | ? id -EQ $appID
    }

    function _getRemediationScript {
        param ([string] $scriptID)
        $intuneRemediationScript | ? id -EQ $scriptID
    }

    # create helper functions text definition for usage in remote sessions
    if ($computerName) {
        $allFunctionDefs = "function _getTargetName { ${function:_getTargetName} }; function _getIntuneScript { ${function:_getIntuneScript} }; function _getIntuneApp { ${function:_getIntuneApp} }; ; function _getRemediationScript { ${function:_getRemediationScript} }"
    }
    #endregion helper functions

    # get the core Intune data
    if (!$intuneXMLReport) {
        $param = @{}
        if ($showEnrollmentIDs) { $param.showEnrollmentIDs = $true }
        if ($showURLs) { $param.showURLs = $true }
        if ($showConnectionData) { $param.showConnectionData = $true }
        if ($computerName) { $param.computerName = $computerName }

        Write-Verbose "Getting client Intune data via ConvertFrom-MDMDiagReportXML"
        $intuneXMLReport = ConvertFrom-MDMDiagReportXML @param
    }

    #region enrich SoftwareInstallation section
    if ($intuneXMLReport | ? PolicyName -EQ 'SoftwareInstallation') {
        Write-Verbose "Modifying 'SoftwareInstallation' section"
        # list of installed MSI applications
        $scriptBlock = {
            Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\', 'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\' -ErrorAction SilentlyContinue -Recurse | % {
                Get-ItemProperty -Path $_.PSPath | select -Property DisplayName, DisplayVersion, UninstallString
            }
        }

        $param = @{
            scriptBlock  = $scriptBlock
            argumentList = ($VerbosePreference, $allFunctionDefs)
        }
        if ($computerName) {
            $param.session = $session
        }

        $installedMSI = Invoke-Command @param

        if ($installedMSI) {
            $intuneXMLReport = $intuneXMLReport | % {
                if ($_.PolicyName -EQ 'SoftwareInstallation') {
                    $softwareInstallation = $_

                    $softwareInstallationSettingDetails = $softwareInstallation.SettingDetails | ? { $_ } | % {
                        $item = $_
                        $packageId = $item.PackageId

                        Write-Verbose "`tPackageId $packageId"

                        Add-Member -InputObject $item -MemberType NoteProperty -Force -Name DisplayName -Value ($installedMSI | ? UninstallString -Match ([regex]::Escape($packageId)) | select -Last 1 -ExpandProperty DisplayName)

                        #return modified MSI object (put Displayname as a second property)
                        $item | select -Property Scope, DisplayName, Type, Status, LastError, ProductVersion, CommandLine, RetryIndex, MaxRetryCount, PackageId
                    }

                    # save results back to original object
                    $softwareInstallation.SettingDetails = $softwareInstallationSettingDetails

                    # return modified object
                    $softwareInstallation
                } else {
                    # no change necessary
                    $_
                }
            }
        }
    }
    #endregion enrich SoftwareInstallation section

    #region Win32App
    # https://oliverkieselbach.com/2018/10/02/part-3-deep-dive-microsoft-intune-management-extension-win32-apps/
    # HKLM\SOFTWARE\Microsoft\IntuneManagementExtension\Apps\ doesn't exists?
    Write-Verbose "Processing 'Win32App' section"
    #region get data
    $scriptBlock = {
        param($verbosePref, $getDataFromIntune, $intuneApp, $intuneUser, $allFunctionDefs)

        # inherit verbose settings from host session
        $VerbosePreference = $verbosePref

        # recreate functions from their text definitions
        . ([ScriptBlock]::Create($allFunctionDefs))

        Get-ChildItem "HKLM:\SOFTWARE\Microsoft\IntuneManagementExtension\Win32Apps" -ErrorAction SilentlyContinue | % {
            $userAzureObjectID = Split-Path $_.Name -Leaf

            $userWin32AppRoot = $_.PSPath
            $win32AppIDList = Get-ChildItem $userWin32AppRoot | select -ExpandProperty PSChildName | % { $_ -replace "_\d+$" } | select -Unique

            $win32AppIDList | % {
                $win32AppID = $_

                Write-Verbose "`tID $win32AppID"

                $newestWin32AppRecord = Get-ChildItem $userWin32AppRoot | ? PSChildName -Match ([regex]::escape($win32AppID)) | Sort-Object -Descending -Property PSChildName | select -First 1

                $lastUpdatedTimeUtc = Get-ItemPropertyValue $newestWin32AppRecord.PSPath -Name LastUpdatedTimeUtc
                try {
                    $complianceStateMessage = Get-ItemPropertyValue "$($newestWin32AppRecord.PSPath)\ComplianceStateMessage" -Name ComplianceStateMessage -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
                } catch {
                    Write-Verbose "`tUnable to get Compliance State Message data"
                }
                try {
                    $enforcementStateMessage = Get-ItemPropertyValue "$($newestWin32AppRecord.PSPath)\EnforcementStateMessage" -Name EnforcementStateMessage -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
                } catch {
                    Write-Verbose "`tUnable to get Enforcement State Message data"
                }

                $lastError = $complianceStateMessage.ErrorCode
                if (!$lastError) { $lastError = 0 } # because of HTML conditional formatting ($null means that cell will have red background)

                if ($getDataFromIntune) {
                    $property = [ordered]@{
                        "Scope"              = _getTargetName $userAzureObjectID
                        "DisplayName"        = (_getIntuneApp $win32AppID).DisplayName
                        "Id"                 = $win32AppID
                        "LastUpdatedTimeUtc" = $lastUpdatedTimeUtc
                        # "Status"            = $complianceStateMessage.ComplianceState
                        "ProductVersion"     = $complianceStateMessage.ProductVersion
                        "LastError"          = $lastError
                    }
                } else {
                    # no 'DisplayName' property
                    $property = [ordered]@{
                        "Scope"              = _getTargetName $userAzureObjectID
                        "Id"                 = $win32AppID
                        "LastUpdatedTimeUtc" = $lastUpdatedTimeUtc
                        # "Status"            = $complianceStateMessage.ComplianceState
                        "ProductVersion"     = $complianceStateMessage.ProductVersion
                        "LastError"          = $lastError
                    }
                }

                if ($showURLs) {
                    $property.IntuneWin32AppURL = "https://endpoint.microsoft.com/#blade/Microsoft_Intune_Apps/SettingsMenu/0/appId/$win32AppID"
                }

                New-Object -TypeName PSObject -Property $property
            }
        }
    }

    $param = @{
        scriptBlock  = $scriptBlock
        argumentList = ($VerbosePreference, $getDataFromIntune, $intuneApp, $intuneUser, $allFunctionDefs)
    }
    if ($computerName) {
        $param.session = $session
    }

    $settingDetails = Invoke-Command @param | select -Property * -ExcludeProperty PSComputerName, RunspaceId, PSShowComputerName
    #endregion get data

    if ($settingDetails) {
        $property = [ordered]@{
            "Scope"          = $null # scope is specified at the particular items level
            "PolicyName"     = 'SoftwareInstallation Win32App' # my custom made
            # SettingName    = 'Win32App' # my custom made
            "SettingDetails" = $settingDetails
        }

        if ($showURLs) {
            $property.PolicyURL = "https://endpoint.microsoft.com/#blade/Microsoft_Intune_DeviceSettings/AppsWindowsMenu/windowsApps"
        }

        $intuneXMLReport += New-Object -TypeName PSObject -Property $property
    }
    #endregion Win32App

    #region add Scripts section
    # https://oliverkieselbach.com/2018/02/12/part-2-deep-dive-microsoft-intune-management-extension-powershell-scripts/
    Write-Verbose "Processing 'Script' section"
    $scriptBlock = {
        param($verbosePref, $getDataFromIntune, $intuneScript, $intuneUser, $allFunctionDefs)

        # inherit verbose settings from host session
        $VerbosePreference = $verbosePref

        # recreate functions from their text definitions
        . ([ScriptBlock]::Create($allFunctionDefs))

        Get-ChildItem "HKLM:\SOFTWARE\Microsoft\IntuneManagementExtension\Policies" -ErrorAction SilentlyContinue | % {
            $userAzureObjectID = Split-Path $_.Name -Leaf

            Get-ChildItem $_.PSPath | % {
                $scriptRegPath = $_.PSPath
                $scriptID = Split-Path $_.Name -Leaf

                Write-Verbose "`tID $scriptID"

                $scriptRegData = Get-ItemProperty $scriptRegPath

                # get output of the invoked script
                if ($scriptRegData.ResultDetails) {
                    try {
                        $resultDetails = $scriptRegData.ResultDetails | ConvertFrom-Json -ErrorAction Stop | select -ExpandProperty ExecutionMsg
                    } catch {
                        Write-Verbose "`tUnable to get Script Output data"
                    }
                } else {
                    $resultDetails = $null
                }

                if ($getDataFromIntune) {
                    $property = [ordered]@{
                        "Scope"                   = _getTargetName $userAzureObjectID
                        "DisplayName"             = (_getIntuneScript $scriptID).DisplayName
                        "Id"                      = $scriptID
                        "Result"                  = $scriptRegData.Result
                        "ErrorCode"               = $scriptRegData.ErrorCode
                        "DownloadAndExecuteCount" = $scriptRegData.DownloadCount
                        "LastUpdatedTimeUtc"      = $scriptRegData.LastUpdatedTimeUtc
                        "RunAsAccount"            = $scriptRegData.RunAsAccount
                        "ResultDetails"           = $resultDetails
                    }
                } else {
                    # no 'DisplayName' property
                    $property = [ordered]@{
                        "Scope"                   = _getTargetName $userAzureObjectID
                        "Id"                      = $scriptID
                        "Result"                  = $scriptRegData.Result
                        "ErrorCode"               = $scriptRegData.ErrorCode
                        "DownloadAndExecuteCount" = $scriptRegData.DownloadCount
                        "LastUpdatedTimeUtc"      = $scriptRegData.LastUpdatedTimeUtc
                        "RunAsAccount"            = $scriptRegData.RunAsAccount
                        "ResultDetails"           = $resultDetails
                    }
                }

                if ($showURLs) {
                    $property.IntuneScriptURL = "https://endpoint.microsoft.com/#blade/Microsoft_Intune_DeviceSettings/ConfigureWMPolicyMenuBlade/properties/policyId/$scriptID/policyType/0"
                }

                New-Object -TypeName PSObject -Property $property
            }
        }
    }

    $param = @{
        scriptBlock  = $scriptBlock
        argumentList = ($VerbosePreference, $getDataFromIntune, $intuneScript, $intuneUser, $allFunctionDefs)
    }
    if ($computerName) {
        $param.session = $session
    }

    $settingDetails = Invoke-Command @param | select -Property * -ExcludeProperty PSComputerName, RunspaceId, PSShowComputerName

    if ($settingDetails) {
        $property = [ordered]@{
            "Scope"          = $null # scope is specified at the particular items level
            "PolicyName"     = 'Script' # my custom made
            "SettingName"    = $null
            "SettingDetails" = $settingDetails
        }

        if ($showURLs) {
            $property.PolicyURL = "https://endpoint.microsoft.com/#blade/Microsoft_Intune_DeviceSettings/DevicesMenu/powershell"
        }

        $intuneXMLReport += New-Object -TypeName PSObject -Property $property
    }
    #endregion add Scripts section

    #region remediation script
    Write-Verbose "Processing 'Remediation Script' section"
    $scriptBlock = {
        param($verbosePref, $getDataFromIntune, $intuneRemediationScript, $intuneUser, $allFunctionDefs)

        # inherit verbose settings from host session
        $VerbosePreference = $verbosePref

        # recreate functions from their text definitions
        . ([ScriptBlock]::Create($allFunctionDefs))

        Get-ChildItem "HKLM:\SOFTWARE\Microsoft\IntuneManagementExtension\SideCarPolicies\Scripts\Reports" -ErrorAction SilentlyContinue | % {
            $userAzureObjectID = Split-Path $_.Name -Leaf
            $userRemScriptRoot = $_.PSPath

            # $lastFullReportTimeUTC = Get-ItemPropertyValue $userRemScriptRoot -Name LastFullReportTimeUTC
            $remScriptIDList = Get-ChildItem $userRemScriptRoot | select -ExpandProperty PSChildName | % { $_ -replace "_\d+$" } | select -Unique

            $remScriptIDList | % {
                $remScriptID = $_

                Write-Verbose "`tID $remScriptID"

                $newestRemScriptRecord = Get-ChildItem $userRemScriptRoot | ? PSChildName -Match ([regex]::escape($remScriptID)) | Sort-Object -Descending -Property PSChildName | select -First 1

                try {
                    $result = Get-ItemPropertyValue "$($newestRemScriptRecord.PSPath)\Result" -Name Result | ConvertFrom-Json
                } catch {
                    Write-Verbose "`tUnable to get Remediation Script Result data"
                }

                $lastExecution = Get-ItemPropertyValue "HKLM:\SOFTWARE\Microsoft\IntuneManagementExtension\SideCarPolicies\Scripts\Execution\$userAzureObjectID\$($newestRemScriptRecord.PSChildName)" -Name LastExecution

                if ($getDataFromIntune) {
                    $property = [ordered]@{
                        "Scope"                             = _getTargetName $userAzureObjectID
                        "DisplayName"                       = (_getRemediationScript $remScriptID).DisplayName
                        "Id"                                = $remScriptID
                        "LastError"                         = $result.ErrorCode
                        "LastExecution"                     = $lastExecution
                        # LastFullReportTimeUTC               = $lastFullReportTimeUTC
                        "InternalVersion"                   = $result.InternalVersion
                        "PreRemediationDetectScriptOutput"  = $result.PreRemediationDetectScriptOutput
                        "PreRemediationDetectScriptError"   = $result.PreRemediationDetectScriptError
                        "RemediationScriptErrorDetails"     = $result.RemediationScriptErrorDetails
                        "PostRemediationDetectScriptOutput" = $result.PostRemediationDetectScriptOutput
                        "PostRemediationDetectScriptError"  = $result.PostRemediationDetectScriptError
                        "RemediationExitCode"               = $result.Info.RemediationExitCode
                        "FirstDetectExitCode"               = $result.Info.FirstDetectExitCode
                        "LastDetectExitCode"                = $result.Info.LastDetectExitCode
                        "ErrorDetails"                      = $result.Info.ErrorDetails
                    }
                } else {
                    # no 'DisplayName' property
                    $property = [ordered]@{
                        "Scope"                             = _getTargetName $userAzureObjectID
                        "Id"                                = $remScriptID
                        "LastError"                         = $result.ErrorCode
                        "LastExecution"                     = $lastExecution
                        # LastFullReportTimeUTC               = $lastFullReportTimeUTC
                        "InternalVersion"                   = $result.InternalVersion
                        "PreRemediationDetectScriptOutput"  = $result.PreRemediationDetectScriptOutput
                        "PreRemediationDetectScriptError"   = $result.PreRemediationDetectScriptError
                        "RemediationScriptErrorDetails"     = $result.RemediationScriptErrorDetails
                        "PostRemediationDetectScriptOutput" = $result.PostRemediationDetectScriptOutput
                        "PostRemediationDetectScriptError"  = $result.PostRemediationDetectScriptError
                        "RemediationExitCode"               = $result.Info.RemediationExitCode
                        "FirstDetectExitCode"               = $result.Info.FirstDetectExitCode
                        "LastDetectExitCode"                = $result.Info.LastDetectExitCode
                        "ErrorDetails"                      = $result.Info.ErrorDetails
                    }
                }

                New-Object -TypeName PSObject -Property $property
            }
        }
    }

    $param = @{
        scriptBlock  = $scriptBlock
        argumentList = ($VerbosePreference, $getDataFromIntune, $intuneRemediationScript, $intuneUser, $allFunctionDefs)
    }
    if ($computerName) {
        $param.session = $session
    }

    $settingDetails = Invoke-Command @param | select -Property * -ExcludeProperty PSComputerName, RunspaceId, PSShowComputerName

    if ($settingDetails) {
        $property = [ordered]@{
            "Scope"          = $null # scope is specified at the particular items level
            "PolicyName"     = 'RemediationScript' # my custom made
            "SettingName"    = $null # my custom made
            "SettingDetails" = $settingDetails
        }

        if ($showURLs) {
            $property.PolicyURL = "https://endpoint.microsoft.com/#blade/Microsoft_Intune_Enrollment/UXAnalyticsMenu/proactiveRemediations"
        }

        $intuneXMLReport += New-Object -TypeName PSObject -Property $property
    }
    #endregion remediation script

    if ($computerName) {
        Remove-PSSession $session
    }

    #region output the results (as object or HTML report)
    if ($asHTML -and $intuneXMLReport) {
        Write-Verbose "Converting to '$HTMLReportPath'"

        # split the results
        $resultsWithSettings = @()
        $resultsWithoutSettings = @()
        $resultsConnectionData = $null
        $intuneXMLReport | % {
            if ($_.settingDetails) {
                $resultsWithSettings += $_
            } elseif ($_.MDMServerName) {
                # MDMServerName property is only in object representing connection data
                $resultsConnectionData = $_
            } else {
                $resultsWithoutSettings += $_
            }
        }

        if ($computerName) { $title = "Intune Report - $($computerName.toupper())" }
        else { $title = "Intune Report - $($env:COMPUTERNAME.toupper())" }

        New-HTML -TitleText $title -Online -FilePath $HTMLReportPath -ShowHTML {
            # it looks better to have headers and content in center
            New-HTMLTableStyle -TextAlign center

            New-HTMLSection -HeaderText $title -Direction row -HeaderBackGroundColor Black -HeaderTextColor White -HeaderTextSize 20 {
                if ($resultsConnectionData) {
                    New-HTMLSection -HeaderText "Intune connection information" -HeaderTextAlignment left -CanCollapse -BackgroundColor DeepSkyBlue -HeaderBackGroundColor DeepSkyBlue -HeaderTextSize 10 -HeaderTextColor EgyptianBlue -Direction row {
                        # render policies
                        New-HTMLSection -BackgroundColor White {
                            New-HTMLTable -DataTable $resultsConnectionData -WordBreak 'break-all' -DisableInfo -HideButtons -DisablePaging -HideFooter -DisableSearch -DisableOrdering
                        }
                    }
                }

                if ($resultsWithoutSettings) {
                    New-HTMLSection -HeaderText "Policies without settings details" -HeaderTextAlignment left -CanCollapse -BackgroundColor DeepSkyBlue -HeaderBackGroundColor DeepSkyBlue -HeaderTextSize 10 -HeaderTextColor EgyptianBlue -Direction row {
                        #region prepare data
                        # exclude some not significant or needed properties
                        # SettingName is empty (or same as PolicyName)
                        # settingDetails is empty
                        $excludeProperty = @('SettingName', 'SettingDetails')
                        if (!$showEnrollmentIDs) { $excludeProperty += 'EnrollmentId' }
                        if (!$showURLs) { $excludeProperty += 'PolicyURL' }
                        $resultsWithoutSettings = $resultsWithoutSettings | Select-Object -Property * -exclude $excludeProperty
                        # sort
                        $resultsWithoutSettings = $resultsWithoutSettings | Sort-Object -Property Scope, PolicyName
                        #endregion prepare data

                        # render policies
                        New-HTMLSection -HeaderText 'Policy' -HeaderBackGroundColor Wedgewood -BackgroundColor White {
                            New-HTMLTable -DataTable $resultsWithoutSettings -WordBreak 'break-all' -DisableInfo -HideButtons -DisablePaging -FixedHeader -FixedFooter
                        }
                    }
                }

                if ($resultsWithSettings) {
                    # sort
                    $resultsWithSettings = $resultsWithSettings | Sort-Object -Property Scope, PolicyName

                    # modify inner sections margins
                    $innerSectionStyle = New-HTMLSectionStyle -RequestConfiguration
                    Add-HTMLStyle -Css @{
                        "$($innerSectionStyle.Section)" = @{
                            'margin-bottom' = '20px'
                        }
                    } -SkipTags

                    New-HTMLSection -HeaderText "Policies with settings details" -HeaderTextAlignment left -CanCollapse -BackgroundColor DeepSkyBlue -HeaderBackGroundColor DeepSkyBlue -HeaderTextSize 10 -HeaderTextColor EgyptianBlue -Direction row {
                        $resultsWithSettings | % {
                            $policy = $_
                            $policySetting = $_.settingDetails

                            #region prepare data
                            # exclude some not significant or needed properties
                            # SettingName is useless in HTML report from my point of view
                            # settingDetails will be shown in separate table, omit here
                            $excludeProperty = @('SettingName', 'SettingDetails')
                            if (!$showEnrollmentIDs) { $excludeProperty += 'EnrollmentId' }
                            if (!$showURLs) { $excludeProperty += 'PolicyURL' }

                            $policy = $policy | Select-Object -Property * -ExcludeProperty $excludeProperty
                            #endregion prepare data

                            New-HTMLSection -HeaderText $policy.PolicyName -HeaderTextAlignment left -CanCollapse -BackgroundColor White -HeaderBackGroundColor White -HeaderTextSize 12 -HeaderTextColor EgyptianBlue -StyleSheetsConfiguration $innerSectionStyle {
                                # render main policy
                                New-HTMLSection -HeaderText 'Policy' -HeaderBackGroundColor Wedgewood -BackgroundColor White {
                                    New-HTMLTable -DataTable $policy -WordBreak 'break-all' -HideFooter -DisableInfo -HideButtons -DisablePaging -DisableSearch -DisableOrdering
                                }

                                # render policy settings details
                                if ($policySetting) {
                                    if (@($policySetting).count -eq 1) {
                                        $detailsHTMLTableParam = @{
                                            DisableSearch   = $true
                                            DisableOrdering = $true
                                        }
                                    } else {
                                        $detailsHTMLTableParam = @{}
                                    }
                                    New-HTMLSection -HeaderText 'Policy settings' -HeaderBackGroundColor PictonBlue -BackgroundColor White {
                                        New-HTMLTable @detailsHTMLTableParam -DataTable $policySetting -WordBreak 'break-all' -AllProperties -FixedHeader -HideFooter -DisableInfo -HideButtons -DisablePaging -WarningAction SilentlyContinue {
                                            New-HTMLTableCondition -Name 'WinningProvider' -ComparisonType string -Operator 'ne' -Value 'Intune' -BackgroundColor Red -Color White #-Row
                                            New-HTMLTableCondition -Name 'LastError' -ComparisonType number -Operator 'ne' -Value 0 -BackgroundColor Red -Color White # -Row
                                            New-HTMLTableCondition -Name 'Error' -ComparisonType number -Operator 'ne' -Value 0 -BackgroundColor Red -Color White # -Row
                                            New-HTMLTableCondition -Name 'ErrorCode' -ComparisonType number -Operator 'ne' -Value 0 -BackgroundColor Red -Color White # -Row
                                            New-HTMLTableCondition -Name 'RemediationScriptErrorDetails' -ComparisonType string -Operator 'ne' -Value '' -BackgroundColor Red -Color White # -Row
                                            New-HTMLTableCondition -Name 'RemediationScriptErrorDetails' -ComparisonType string -Operator 'ne' -Value '' -BackgroundColor Red -Color White # -Row
                                            New-HTMLTableCondition -Name 'PreRemediationDetectScriptError' -ComparisonType string -Operator 'ne' -Value '' -BackgroundColor Red -Color White # -Row
                                            New-HTMLTableCondition -Name 'PostRemediationDetectScriptError' -ComparisonType string -Operator 'ne' -Value '' -BackgroundColor Red -Color White # -Row
                                            New-HTMLTableCondition -Name 'RemediationExitCode' -ComparisonType number -Operator 'ne' -Value 0 -BackgroundColor Red -Color White # -Row
                                            New-HTMLTableCondition -Name 'FirstDetectExitCode' -ComparisonType number -Operator 'ne' -Value 0 -BackgroundColor Red -Color White # -Row
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            } # end of main HTML section
        }
    } else {
        Write-Verbose "Returning PowerShell object"
        return $intuneXMLReport
    }
    #endregion output the results (as object or HTML report)
}