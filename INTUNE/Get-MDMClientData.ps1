#Requires -Module ActiveDirectory
function Get-MDMClientData {
    <#
    .SYNOPSIS
    Function for getting client management information from AD, Intune, AAD and SCCM and combine them together.

    .DESCRIPTION
    Function for getting client management information from AD, Intune, AAD and SCCM and combine them together.
    Resultant object will have several properties with prefix AD, INTUNE, AAD or SCCM according to source of such data.

    .PARAMETER computer
    Computer(s) you want to get data about from AD, AAD, SCCM and Intune.
    As object(s) with name, sid and ObjectGUID of AD computers OR just list of computer names (in case of duplicity records, additional data to uniquely identify the correct one will be gathered from AD).

    .PARAMETER combineDataFrom
    List of sources you want to gather data from.

    Possible values are: Intune, SCCM, AAD, AD

    By default all values are selected.

    .PARAMETER graphCredential
    AppID and AppSecret for Azure App registration that has permissions needed to read Azure and Intune clients data.

    .PARAMETER sccmAdminServiceCredential
    Credentials for SCCM Admin Service API authentication. Needed only if current user doesn't have correct permissions.

    .EXAMPLE
    # active AD Windows clients that belongs to some user
    $activeADClients = Get-ADComputer -Filter "enabled -eq 'True'" -Properties 'Name', 'sid', 'LastLogonDate', 'Enabled', 'DistinguishedName', 'Description', 'PasswordLastSet', 'ObjectGUID' | ? { $_.LastLogonDate -ge [datetime]::Today.AddDays(-90) }

    $problematic = Get-MDMClientData -computer $activeADClients -graphCredential (Get-Credential)

    From AD get all enabled (and probably live) computers and get data from AD, AAD, Intune and SCCM for them. For connecting SCCM your credentials will be used.

    .EXAMPLE
    # active AD Windows clients that belongs to some user
    $activeADClients = Get-ADComputer -Filter "enabled -eq 'True'" -Properties 'Name', 'sid', 'LastLogonDate', 'Enabled', 'DistinguishedName', 'Description', 'PasswordLastSet', 'ObjectGUID' | ? { $_.LastLogonDate -ge [datetime]::Today.AddDays(-90) }

    $problematic = Get-MDMClientData -computer $activeADClients -combineDataFrom 'SCCM', 'AD' -sccmAdminServiceCredential (Get-Credential)

    From AD get all enabled (and probably live) computers and get data just from AD and SCCM for them. For connecting SCCM entered credentials will be used.

    .NOTES
    Requires functions: New-GraphAPIAuthHeader, Invoke-CMAdminServiceQuery
    #>

    [CmdletBinding()]
    param (
        $computer = (Get-ADComputer -Filter "enabled -eq 'True'" -Properties 'Name', 'sid', 'LastLogonDate', 'Enabled', 'DistinguishedName', 'Description', 'PasswordLastSet', 'ObjectGUID' | ? { $_.LastLogonDate -ge [datetime]::Today.AddDays(-90) }),

        [ValidateSet('Intune', 'SCCM', 'AAD', 'AD')]
        [string[]] $combineDataFrom = ('Intune', 'SCCM', 'AAD', 'AD'),

        [System.Management.Automation.PSCredential] $graphCredential,

        [System.Management.Automation.PSCredential] $sccmAdminServiceCredential
    )

    #region helper functions
    function New-GraphAPIAuthHeader {
        <#
        .SYNOPSIS
        Function for generating header that can be used for authentication of Graph API requests.

        .DESCRIPTION
        Function for generating header that can be used for authentication of Graph API requests.

        .PARAMETER credential
        Credentials for Graph API authentication (AppID + AppSecret).

        .PARAMETER TenantDomainName
        Name of your Azure tenant.

        For example "contoso.onmicrosoft.com".

        .EXAMPLE
        $header = New-GraphAPIAuthHeader -credential $cred
        $URI = 'https://graph.microsoft.com/v1.0/deviceManagement/managedDevices/'
        $managedDevices = (Invoke-RestMethod -Headers $header -Uri $URI -Method Get).value

        .NOTES
        https://adamtheautomator.com/powershell-graph-api/#AppIdSecret
        https://thesleepyadmins.com/2020/10/24/connecting-to-microsoft-graphapi-using-powershell/
        https://github.com/microsoftgraph/powershell-intune-samples
        #>

        [CmdletBinding()]
        [Alias("New-IntuneAuthHeader", "Get-IntuneAuthHeader")]
        param (
            [System.Management.Automation.PSCredential] $credential = (Get-Credential -Message "Enter AppID as UserName and AppSecret as Password"),

            [ValidateNotNullOrEmpty()]
            FIXME: hardcode your Azure tenant name instead of $_tenantDomain
            $tenantDomainName = $_tenantDomain
        )

        if (!$credential) { throw "Credentials for creating Graph API authentication header is missing" }

        if (!$tenantDomainName) { throw "TenantDomainName is missing" }

        Write-Verbose "Getting token"

        $body = @{
            Grant_Type    = "client_credentials"
            Scope         = "https://graph.microsoft.com/.default"
            Client_Id     = $credential.username
            Client_Secret = $credential.GetNetworkCredential().password
        }

        $connectGraph = Invoke-RestMethod -Uri "https://login.microsoftonline.com/$tenantDomainName/oauth2/v2.0/token" -Method POST -Body $body

        $token = $connectGraph.access_token

        if ($token) {
            return @{ Authorization = "Bearer $($token)" }
        } else {
            throw "Unable to obtain token"
        }
    }

    function Invoke-GraphAPIRequest {
        <#
        .SYNOPSIS
        Function for creating request against Microsoft Graph API.

        .DESCRIPTION
        Function for creating request against Microsoft Graph API.

        It supports paging (needed in Azure).

        .PARAMETER uri
        Request URI.

        https://graph.microsoft.com/v1.0/me/
        https://graph.microsoft.com/v1.0/devices
        https://graph.microsoft.com/v1.0/users
        https://graph.microsoft.com/v1.0/groups

        .PARAMETER credential
        Credentials used for creating authentication header for request.

        .PARAMETER header
        Authentication header for request.

        .PARAMETER method
        Default is GET.

        .EXAMPLE
        $header = New-GraphAPIAuthHeader -credential $graphCredential
        $aadDevice = Invoke-GraphAPIRequest -Uri "https://graph.microsoft.com/v1.0/devices" -header $header

        .EXAMPLE
        $aadDevice = Invoke-GraphAPIRequest -Uri "https://graph.microsoft.com/v1.0/devices" -credential $graphCredential

        .NOTES
        https://configmgrblog.com/2017/12/05/so-what-can-we-do-with-microsoft-intune-via-microsoft-graph-api/
        #>

        [CmdletBinding()]
        param (
            [Parameter(Mandatory = $true)]
            [string] $uri,

            [Parameter(Mandatory = $true, ParameterSetName = "credential")]
            [System.Management.Automation.PSCredential] $credential,

            [Parameter(Mandatory = $true, ParameterSetName = "header")]
            $header,

            [ValidateSet('GET', 'POST')]
            [string] $method = "GET"
        )

        if ($credential) {
            $header = New-GraphAPIAuthHeader -credential $credential
        }

        try {
            $response = Invoke-RestMethod -Uri $uri -Headers $header -Method $method
        } catch {
            switch ($_) {
                ($_ -like "*(400) Bad Request*") { throw "Faulty request. There has to be some mistake in this request" }
                ($_ -like "*(401) Unauthorized*") { throw "Unauthorized request (new auth header has to be created?)" }
                ($_ -like "*Forbidden*") { throw "Forbidden access. Use account with correct API permissions for this request" }
                default { throw $_ }
            }
        }

        $response.Value

        $nextLink = $response.'@odata.nextLink'
        # Need to loop the requests because only 100 results are returned each time
        while ($nextLink) {
            $response = Invoke-RestMethod -Uri $NextLink -Headers $header -Method $method
            $nextLink = $response.'@odata.nextLink'
            $response.Value
        }
    }

    function Invoke-CMAdminServiceQuery {
        <#
        .SYNOPSIS
        Function for retrieving information from SCCM Admin Service REST API.
        Will connect to API and return results according to given query.
        Supports local connection and also internet through CMG.

        .DESCRIPTION
        Function for retrieving information from SCCM Admin Service REST API.
        Will connect to API and return results according to given query.
        Supports local connection and also internet through CMG.
        Use credentials with READ rights on queried source at least.
        For best performance defined filter and select parameters.

        .PARAMETER ServerFQDN
        For intranet clients
        The fully qualified domain name of the server hosting the AdminService

        .PARAMETER Source
        For specifying what information are we looking for. You can use TAB completion!
        Accept string representing the source in format <source>/<wmiclass>.
        SCCM Admin Service offers two base Source:
        - wmi = for WMI classes (use it like wmi/<className>)
            - examples:
                - wmi/ = list all available classes
                - wmi/SMS_R_System = get all systems (i.e. content of SMS_R_System WMI class)
                - wmi/SMS_R_User = get all users
        - v1.0 = for WMI classes, that were migrated to this new Source
            - example v1.0/ = list all available classes
            - example v1.0/Application = get all applications

        .PARAMETER Filter
        For filtering the returned results.
        Accept string representing the filter statement.
        Makes query significantly faster!

        Examples:
        - "name eq 'ni-20-ntb'"
        - "startswith(Name,'Drivers -')"

        Usable operators:
        any, all, cast, ceiling, concat, contains, day, endswith, filter, floor, fractionalseconds, hour, indexof, isof, length, minute, month, round, second, startswith, substring, tolower, toupper, trim, year, date, time

        https://docs.microsoft.com/en-us/graph/query-parameters

        .PARAMETER Select
        For filtering returned properties.
        Accept list of properties you want to return.
        Makes query significantly faster!

        Examples:
        - "MACAddresses", "Name"

        .PARAMETER ExternalUrl
        For internet clients
        ExternalUrl of the AdminService you wish to connect to. You can find the ExternalUrl by directly querying your CM database.
        Query: SELECT ProxyServerName,ExternalUrl FROM [dbo].[vProxy_Routings] WHERE [dbo].[vProxy_Routings].ExternalEndpointName = 'AdminService'
        It should look like this: HTTPS://<YOURCMG>.<FQDN>/CCM_Proxy_ServerAuth/<RANDOM_NUMBER>/AdminService

        .PARAMETER TenantId
        For internet clients
        Azure AD Tenant ID that is used for your CMG

        .PARAMETER ClientId
        For internet clients
        Client ID of the application registration created to interact with the AdminService

        .PARAMETER ApplicationIdUri
        For internet clients
        Application ID URI of the Configuration manager Server app created when creating your CMG.
        The default value of 'https://ConfigMgrService' should be good for most people.

        .PARAMETER BypassCertCheck
        Enabling this option will allow PowerShell to accept any certificate when querying the AdminService.
        If you do not enable this option, you need to make sure the certificate used by the AdminService is trusted by the device.

        .EXAMPLE
        Invoke-CMAdminServiceQuery -Source wmi/

        Use TAB for getting all available wmi sources.

        .EXAMPLE
        Invoke-CMAdminServiceQuery -Source v1.0/

        Use TAB for getting all available v1.0 sources.

        .EXAMPLE
        Invoke-CMAdminServiceQuery -Source "wmi/SMS_R_SYSTEM" -Filter "name eq 'ni-20-ntb'" -Select MACAddresses

        .EXAMPLE
        Invoke-CMAdminServiceQuery -Source "wmi/SMS_R_SYSTEM" -Filter "startswith(Name,'AE-')" -Select Name, MACAddresses

        .NOTES
        !!!Credits goes to author of https://github.com/CharlesNRU/mdm-adminservice/blob/master/Invoke-GetPackageIDFromAdminService.ps1 (I just generalize it and made some improvements)
        Lot of useful information https://www.asquaredozen.com/2019/02/12/the-system-center-configuration-manager-adminservice-guide
        #>

        [CmdletBinding()]
        param(
            [parameter(Mandatory = $false, HelpMessage = "Set the FQDN of the server hosting the ConfigMgr AdminService.", ParameterSetName = "Intranet")]
            [ValidateNotNullOrEmpty()]
            FIXME: hardcode your SCCM server name instead of $_SCCMServer
            [string] $ServerFQDN = $_SCCMServer
            ,
            [Parameter(Mandatory = $true)]
            [ValidateScript( {
                    If ($_ -match "(^wmi/)|(^v1.0/)") {
                        $true
                    } else {
                        Throw "$_ is not a valid source (for example: wmi/SMS_Package or v1.0/whatever"
                    }
                })]
            [ArgumentCompleter( {
                    param ($Command, $Parameter, $WordToComplete, $CommandAst, $FakeBoundParams)
                    $source = ($WordToComplete -split "/")[0]
                    $class = ($WordToComplete -split "/")[1]
                    Invoke-CMAdminServiceQuery -Source "$source/" | ? { $_.url -like "*$class*" } | select -exp url | % { "$source/$_" }
                })]
            [string] $Source
            ,
            [string] $Filter
            ,
            [string[]] $Select
            ,
            [parameter(Mandatory = $true, HelpMessage = "Set the CMG ExternalUrl for the AdminService.", ParameterSetName = "Internet")]
            [ValidateNotNullOrEmpty()]
            [string] $ExternalUrl
            ,
            [parameter(Mandatory = $true, HelpMessage = "Set your TenantID.", ParameterSetName = "Internet")]
            [ValidateNotNullOrEmpty()]
            [string] $TenantID
            ,
            [parameter(Mandatory = $true, HelpMessage = "Set the ClientID of app registration to interact with the AdminService.", ParameterSetName = "Internet")]
            [ValidateNotNullOrEmpty()]
            [string] $ClientID
            ,
            [parameter(Mandatory = $false, HelpMessage = "Specify URI here if using non-default Application ID URI for the configuration manager server app.", ParameterSetName = "Internet")]
            [ValidateNotNullOrEmpty()]
            [string] $ApplicationIdUri = 'https://ConfigMgrService'
            ,
            [parameter(Mandatory = $false, HelpMessage = "Specify the credentials that will be used to query the AdminService.", ParameterSetName = "Intranet")]
            [parameter(Mandatory = $true, HelpMessage = "Specify the credentials that will be used to query the AdminService.", ParameterSetName = "Internet")]
            [ValidateNotNullOrEmpty()]
            [System.Management.Automation.PSCredential] $Credential
            ,
            [parameter(Mandatory = $false, HelpMessage = "If set to True, PowerShell will bypass SSL certificate checks when contacting the AdminService.", ParameterSetName = "Intranet")]
            [parameter(Mandatory = $false, HelpMessage = "If set to True, PowerShell will bypass SSL certificate checks when contacting the AdminService.", ParameterSetName = "Internet")]
            [bool]$BypassCertCheck = $false
        )

        Begin {
            #region functions
            function Get-AdminServiceUri {
                switch ($PSCmdlet.ParameterSetName) {
                    "Intranet" {
                        if (!$ServerFQDN) { throw "ServerFQDN isn't defined" }
                        Return "https://$($ServerFQDN)/AdminService"
                    }
                    "Internet" {
                        if (!$ExternalUrl) { throw "ExternalUrl isn't defined" }
                        Return $ExternalUrl
                    }
                }
            }

            function Import-MSALPSModule {
                Write-Verbose "Checking if MSAL.PS module is available on the device."
                $MSALModule = Get-Module -ListAvailable MSAL.PS
                If ($MSALModule) {
                    Write-Verbose "Module is already available."
                } Else {
                    #Setting PowerShell to use TLS 1.2 for PowerShell Gallery
                    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

                    Write-Verbose "MSAL.PS is not installed, checking for prerequisites before installing module."

                    Write-Verbose "Checking for NuGet package provider... "
                    If (-not (Get-PackageProvider -Name NuGet -ListAvailable -ErrorAction SilentlyContinue)) {
                        Write-Verbose "NuGet package provider is not installed, installing NuGet..."
                        $NuGetVersion = Install-PackageProvider -Name NuGet -Force -ErrorAction Stop | Select-Object -ExpandProperty Version
                        Write-Verbose "NuGet package provider version $($NuGetVersion) installed."
                    }

                    Write-Verbose "Checking for PowerShellGet module version 2 or higher "
                    $PowerShellGetLatestVersion = Get-Module -ListAvailable -Name PowerShellGet | Sort-Object -Property Version -Descending | Select-Object -First 1 -ExpandProperty Version
                    If ((-not $PowerShellGetLatestVersion)) {
                        Write-Verbose "Could not find any version of PowerShellGet installed."
                    }
                    If (($PowerShellGetLatestVersion.Major -lt 2)) {
                        Write-Verbose "Current PowerShellGet version is $($PowerShellGetLatestVersion) and needs to be updated."
                    }
                    If ((-not $PowerShellGetLatestVersion) -or ($PowerShellGetLatestVersion.Major -lt 2)) {
                        Write-Verbose "Installing latest version of PowerShellGet..."
                        Install-Module -Name PowerShellGet -AllowClobber -Force
                        $InstalledVersion = Get-Module -ListAvailable -Name PowerShellGet | Sort-Object -Property Version -Descending | Select-Object -First 1 -ExpandProperty Version
                        Write-Verbose "PowerShellGet module version $($InstalledVersion) installed."
                    }

                    Write-Verbose "Installing MSAL.PS module..."
                    If ((-not $PowerShellGetLatestVersion) -or ($PowerShellGetLatestVersion.Major -lt 2)) {
                        Write-Verbose "Starting another powershell process to install the module..."
                        $result = Start-Process -FilePath powershell.exe -ArgumentList "Install-Module MSAL.PS -AcceptLicense -Force" -PassThru -Wait -NoNewWindow
                        If ($result.ExitCode -ne 0) {
                            Write-Verbose "Failed to install MSAL.PS module"
                            Throw "Failed to install MSAL.PS module"
                        }
                    } Else {
                        Install-Module MSAL.PS -AcceptLicense -Force
                    }
                }
                Write-Verbose "Importing MSAL.PS module..."
                Import-Module MSAL.PS -Force
                Write-Verbose "MSAL.PS module successfully imported."
            }
            #endregion functions
        }

        Process {
            Try {
                #region connect Admin Service
                Write-Verbose "Processing credentials..."
                switch ($PSCmdlet.ParameterSetName) {
                    "Intranet" {
                        If ($Credential) {
                            If ($Credential.GetNetworkCredential().password) {
                                Write-Verbose "Using provided credentials to query the AdminService."
                                $InvokeRestMethodCredential = @{
                                    "Credential" = ($Credential)
                                }
                            } Else {
                                throw "Username provided without a password, please specify a password."
                            }
                        } Else {
                            Write-Verbose "No credentials provided, using current user credentials to query the AdminService."
                            $InvokeRestMethodCredential = @{
                                "UseDefaultCredentials" = $True
                            }
                        }

                    }
                    "Internet" {
                        Import-MSALPSModule

                        Write-Verbose "Getting access token to query the AdminService via CMG."
                        $Token = Get-MsalToken -TenantId $TenantID -ClientId $ClientID -UserCredential $Credential -Scopes ([String]::Concat($($ApplicationIdUri), '/user_impersonation')) -ErrorAction Stop
                        Write-Verbose "Successfully retrieved access token."
                    }
                }

                If ($BypassCertCheck) {
                    Write-Verbose "Bypassing certificate checks to query the AdminService."
                    #Source: https://til.intrepidintegration.com/powershell/ssl-cert-bypass.html
                    Add-Type @"
using System.Net;
using System.Security.Cryptography.X509Certificates;
public class TrustAllCertsPolicy : ICertificatePolicy {
    public bool CheckValidationResult(
        ServicePoint srvPoint, X509Certificate certificate,
        WebRequest request, int certificateProblem) {
        return true;
    }
}
"@
                    [System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy
                    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Ssl3, [Net.SecurityProtocolType]::Tls, [Net.SecurityProtocolType]::Tls11, [Net.SecurityProtocolType]::Tls12
                }
                #endregion connect Admin Service

                #region make&execute query
                $URI = (Get-AdminServiceUri) + "/" + $Source

                $Body = @{}

                if ($Filter) {
                    $Body."`$filter" = $Filter
                }
                if ($Select) {
                    $Body."`$select" = ($Select -join ",")
                }

                switch ($PSCmdlet.ParameterSetName) {
                    'Intranet' {
                        Invoke-RestMethod -Method Get -Uri $URI -Body $Body @InvokeRestMethodCredential | Select-Object -ExpandProperty value
                    }
                    'Internet' {
                        $authHeader = @{
                            'Content-Type'  = 'application/json'
                            'Authorization' = "Bearer " + $token.AccessToken
                            'ExpiresOn'     = $token.ExpiresOn
                        }
                        $Packages = Invoke-RestMethod -Method Get -Uri $URI -Headers $authHeader -Body $Body | Select-Object -ExpandProperty value
                    }
                }
                #endregion make&execute query
            } Catch {
                throw "Error: $($_.Exception.HResult)): $($_.Exception.Message)`n$($_.InvocationInfo.PositionMessage)"
            }
        }
    }

    function _ClientCheckPass {
        # translates number code to message
        param ($ClientCheckPass)

        switch ($ClientCheckPass) {
            1 { return "Passed" }
            2 { return "Failed" }
            3 { return "No results" }
            default { return "Not evaluated" }
        }
    }

    function _computerHasValidHybridJoinCertificate {
        # extracted from Export-ADSyncToolsHybridAzureADjoinCertificateReport.ps1
        # https://github.com/azureautomation/export-hybrid-azure-ad-join-computer-certificates-report--updated-

        [CmdletBinding()]
        param ([string]$computerName)

        $searcher = [adsisearcher]"(&(objectCategory=computer)(name=$computerName))"
        $searcher.PageSize = 500
        $searcher.PropertiesToLoad.AddRange(('usercertificate', 'name'))
        $obj = $searcher.FindOne()
        $searcher.Dispose()
        if (!$obj) { throw "Unable to get $computerName" }

        $userCertificateList = @($obj.properties.usercertificate)
        $validEntries = @()
        $totalEntriesCount = $userCertificateList.Count
        Write-Verbose "'$computerName' has $totalEntriesCount entries in UserCertificate property."
        If ($totalEntriesCount -eq 0) {
            Write-Warning "'$computerName' has no Certificates - Skipped."
            return $false
        }
        # Check each UserCertificate entry and build array of valid certs
        ForEach ($entry in $userCertificateList) {
            Try {
                $cert = [System.Security.Cryptography.X509Certificates.X509Certificate2] $entry
            } Catch {
                Write-Verbose "'$computerName' has an invalid Certificate!"
                Continue
            }
            Write-Verbose "'$computerName' has a Certificate with Subject: $($cert.Subject); Thumbprint:$($cert.Thumbprint)."
            $validEntries += $cert

        }

        $validEntriesCount = $validEntries.Count
        Write-Verbose "'$computerName' has a total of $validEntriesCount certificates (shown above)."

        # Get non-expired Certs (Valid Certificates)
        $validCerts = @($validEntries | Where-Object { $_.NotAfter -ge (Get-Date) })
        $validCertsCount = $validCerts.Count
        Write-Verbose "'$computerName' has $validCertsCount valid certificates (not-expired)."

        # Check for AAD Hybrid Join Certificates
        $hybridJoinCerts = @()
        $hybridJoinCertsThumbprints = [string] "|"
        ForEach ($cert in $validCerts) {
            $certSubjectName = $cert.Subject
            If ($certSubjectName.StartsWith($("CN=$objectGuid")) -or $certSubjectName.StartsWith($("CN={$objectGuid}"))) {
                $hybridJoinCerts += $cert
                $hybridJoinCertsThumbprints += [string] $($cert.Thumbprint) + '|'
            }
        }

        $hybridJoinCertsCount = $hybridJoinCerts.Count
        if ($hybridJoinCertsCount -gt 0) {
            Write-Verbose "'$computerName' has $hybridJoinCertsCount AAD Hybrid Join Certificates with Thumbprints: $hybridJoinCertsThumbprints"
            if ($hybridJoinCertsCount.count -lt 15) {
                # more than 15 certificates would cause fail
                return $true
            } else {
                return $false
            }
        } else {
            Write-Verbose "'$computerName' has no AAD Hybrid Join Certificates"
            return $false
        }
    }
    #endregion helper functions

    #region checks
    if (!$computer) { throw "Computer parameter is missing" }

    if ($combineDataFrom -contains "Intune") {
        try {
            $null = Get-Command New-GraphAPIAuthHeader -ErrorAction Stop
        } catch {
            throw "New-GraphAPIAuthHeader command isn't available"
        }
    }

    if ($combineDataFrom -contains "SCCM") {
        try {
            $null = Get-Command Invoke-CMAdminServiceQuery -ErrorAction Stop
        } catch {
            throw "Invoke-CMAdminServiceQuery command isn't available"
        }
    }

    # it needs originally installed ActiveDirectory module, NOT copied/hacked one!
    if (!(Get-Module ActiveDirectory -ListAvailable)) {
        if ((Get-WmiObject win32_operatingsystem -Property caption).caption -match "server") {
            throw "Module ActiveDirectory is missing. Use: Install-WindowsFeature RSAT-AD-PowerShell -IncludeManagementTools"
        } else {
            throw "Module ActiveDirectory is missing. Use: Get-WindowsCapability -Name RSAT* -Online | Add-WindowsCapability -Online"
        }
    }
    #endregion checks

    #region get data
    if ($combineDataFrom -contains "Intune" -or $combineDataFrom -contains "AAD") {
        $header = New-GraphAPIAuthHeader -credential $graphCredential -ErrorAction Stop
    }

    if ($combineDataFrom -contains "Intune") {
        $intuneDevice = (Invoke-RestMethod -Headers $header -Uri "https://graph.microsoft.com/beta/deviceManagement/managedDevices" -Method Get).Value | select deviceName, deviceEnrollmentType, lastSyncDateTime, aadRegistered, azureADRegistered, deviceRegistrationState, azureADDeviceId, emailAddress
    }

    if ($combineDataFrom -contains "SCCM") {
        $properties = 'Name', 'Domain', 'IsClient', 'IsActive', 'ClientCheckPass', 'ClientActiveStatus', 'LastActiveTime', 'ADLastLogonTime', 'CoManaged', 'IsMDMActive', 'PrimaryUser', 'SerialNumber', 'MachineId', 'UserName'
        $param = @{
            source = "v1.0/Device"
            select = $properties
        }
        if ($sccmAdminServiceCredential) {
            $param.credential = $sccmAdminServiceCredential
        }
        $sccmDevice = Invoke-CMAdminServiceQuery @param | select $properties

        # add more information
        $properties = 'ResourceID', 'InstallDate'
        $param = @{
            source = "wmi/SMS_G_System_OPERATING_SYSTEM"
            select = $properties
        }
        if ($sccmAdminServiceCredential) {
            $param.credential = $sccmAdminServiceCredential
        }
        $additionalData = Invoke-CMAdminServiceQuery @param | select $properties

        $sccmDevice = $sccmDevice | % {
            $deviceAdtData = $additionalData | ? ResourceID -EQ $_.MachineId
            $_ | select *, @{n = 'InstallDate'; e = { if ($deviceAdtData.InstallDate) { Get-Date $deviceAdtData.InstallDate } } }, @{n = 'LastBootUpTime'; e = { if ($deviceAdtData.LastBootUpTime) { Get-Date $deviceAdtData.LastBootUpTime } } }
        }
    }

    if ($combineDataFrom -contains "AAD") {
        $aadDevice = Invoke-GraphAPIRequest -uri "https://graph.microsoft.com/v1.0/devices" -header $header | select displayName, accountEnabled, approximateLastSignInDateTime, deviceOwnership, enrollmentType, isCompliant, isManaged, managementType, onPremisesSyncEnabled, onPremisesLastSyncDateTime, profileType, deviceId
    }
    #endregion get data

    # fill object properties
    foreach ($cmp in $computer) {
        if ($cmp.name) {
            # it is object
            $name = $cmp.name
        } elseif ($cmp.gettype().Name -eq "String") {
            # it is string
            $name = $cmp
        } else {
            $cmp
            throw "THIS OBJECT DOESN'T CONTAIN NAME PROPERTY"
        }

        Write-Verbose $name

        $deviceGUID = $deviceSID = $null

        $deviceProperty = [ordered]@{
            Name                   = $name
            hasValidHybridJoinCert = _computerHasValidHybridJoinCertificate $name
        }

        if ($combineDataFrom -contains "AD") {
            $property = 'Enabled', 'LastLogonDate', 'DistinguishedName', 'Description', 'Sid', 'ObjectGUID', 'PasswordLastSet'
            $missingProperty = @()

            # try to get the value from input
            $property | % {
                $propertyName = "AD_$_"
                if ($cmp.$_) {
                    switch ($_) {
                        "SID" {
                            $deviceProperty.$propertyName = $cmp.$_.value
                        }
                        "ObjectGUID" {
                            $deviceProperty.$propertyName = $cmp.$_.guid
                        }
                        default {
                            $deviceProperty.$propertyName = $cmp.$_
                        }
                    }
                } else {
                    $missingProperty += $_
                }
            }

            if ($missingProperty) {
                Write-Verbose "Getting missing property: $($missingProperty -join ', ')"
                $deviceADData = Get-ADComputer -Filter "name -eq '$name'" -Property $missingProperty
                $missingProperty | % {
                    $propertyName = "AD_$_"
                    switch ($_) {
                        "SID" {
                            $deviceProperty.$propertyName = $deviceADData.$_.value
                        }
                        "ObjectGUID" {
                            $deviceProperty.$propertyName = $deviceADData.$_.guid
                        }
                        default {
                            $deviceProperty.$propertyName = $deviceADData.$_
                        }
                    }
                }
            }
        }

        # getting SCCM data has to be before Intune because of comparing co-managed status
        if ($combineDataFrom -contains "SCCM") {

            $deviceSCCMRecord = @($sccmDevice | ? Name -EQ $name)

            if (!$deviceSCCMRecord) {
                $deviceProperty.SCCM_InDatabase = $false
            } else {
                # device is in SCCM
                $deviceProperty.SCCM_InDatabase = $true

                if ($deviceSCCMRecord.count -gt 1) {
                    # more records with the same name

                    $deviceProperty.SCCM_MultipleRecords = $deviceSCCMRecord.count

                    Write-Verbose "Device $name is $($deviceSCCMRecord.count)x in SCCM database!"

                    # get the correct one by using SID
                    $deviceSID = $cmp.sid.value
                    if (!$deviceSID) {
                        $deviceSID = $deviceProperty.AD_SID
                    }
                    if (!$deviceSID) {
                        $deviceSID = (Get-ADComputer -Filter "name -eq '$name'" -Property SID).SID.Value
                    }
                    if ($deviceSID) {
                        Write-Verbose "Search for the $name with $deviceSID SID in SCCM database"

                        $param = @{
                            source = "wmi/SMS_R_SYSTEM"
                            select = 'ResourceId'
                            filter = "SID eq '$deviceSID'"
                        }
                        if ($sccmAdminServiceCredential) {
                            $param.credential = $sccmAdminServiceCredential
                        }
                        $resourceId = Invoke-CMAdminServiceQuery @param | select -ExpandProperty ResourceId
                        Write-Verbose "$name has resourceId $resourceId"

                        $deviceSCCMRecord = @($sccmDevice | ? MachineId -EQ $resourceId)
                    }

                    if ($deviceSCCMRecord.count -gt 1) {
                        # unable to narrow down the results

                        if (!$deviceSID) {
                            $erMsg = "No SID property was provided to identify the correct one, nor was found in AD."
                        } else {
                            $erMsg = "Unable to identify the correct one."
                        }
                        Write-Warning "Device $name is $($deviceSCCMRecord.count)x in SCCM database.`n$erMsg Therefore setting property deviceSCCMRecord as `$null"
                        $deviceSCCMRecord = $null
                    }
                } else {
                    $deviceProperty.SCCM_MultipleRecords = $false
                }

                if ($deviceSCCMRecord.count -eq 1) {
                    if (!$deviceSCCMRecord.IsClient) {
                        $deviceProperty.SCCM_ClientInstalled = $false
                    } else {
                        # SCCM client is installed

                        $deviceProperty.SCCM_ClientInstalled = $true
                        if ($deviceSCCMRecord.LastActiveTime) {
                            $deviceProperty.SCCM_LastActiveTime = (Get-Date $deviceSCCMRecord.LastActiveTime)
                        } else {
                            $deviceProperty.SCCM_LastActiveTime = $null
                        }
                        $deviceProperty.SCCM_IsActive = $deviceSCCMRecord.IsActive
                        $deviceProperty.SCCM_clientCheckPass = _ClientCheckPass $deviceSCCMRecord.ClientCheckPass
                        $deviceProperty.SCCM_clientActiveStatus = $deviceSCCMRecord.ClientActiveStatus
                        if ($deviceSCCMRecord.CoManaged -ne 1) {
                            $deviceProperty.SCCM_CoManaged = $false
                        } else {
                            $deviceProperty.SCCM_CoManaged = $true
                        }
                        $deviceProperty.SCCM_User = $deviceSCCMRecord.UserName
                        $deviceProperty.SCCM_SerialNumber = $deviceSCCMRecord.SerialNumber
                        $deviceProperty.SCCM_MachineId = $deviceSCCMRecord.MachineId
                        $deviceProperty.SCCM_OSInstallDate = $deviceSCCMRecord.InstallDate
                    }
                }
            }
        }

        if ($combineDataFrom -contains "Intune") {

            $deviceIntuneRecord = @($intuneDevice | ? DeviceName -EQ $name)

            if (!$deviceIntuneRecord) {
                Write-Verbose "$name wasn't found in Intune database, trying to get its GUID"

                # try to search for it using its GUID
                if (!$deviceGUID) {
                    $deviceGUID = $cmp.ObjectGUID.Guid
                }
                if (!$deviceGUID) {
                    $deviceGUID = $deviceProperty.AD_ObjectGUID
                }
                if (!$deviceGUID) {
                    $deviceGUID = (Get-ADComputer -Filter "name -eq '$name'" -Property ObjectGUID).ObjectGUID.Guid
                }
                if ($deviceGUID) {
                    Write-Verbose "Search for the $name using its $deviceGUID GUID in Intune database"
                    # search for Intune device with GUID instead of name
                    $deviceIntuneRecord = @($intuneDevice | ? { $_.AzureADDeviceId -eq $deviceGUID })
                }
            }

            if (!$deviceIntuneRecord) {
                $deviceProperty.INTUNE_InDatabase = $false
            } else {
                # device is in Intune
                $deviceProperty.INTUNE_InDatabase = $true

                if ($deviceIntuneRecord.count -gt 1) {
                    # more records with the same name

                    $deviceProperty.INTUNE_MultipleRecords = $deviceIntuneRecord.count

                    Write-Verbose "Device $name is $($deviceIntuneRecord.count)x in Intune database!"

                    # get the correct one by using GUID
                    if (!$deviceGUID) {
                        $deviceGUID = $cmp.ObjectGUID.Guid
                    }
                    if (!$deviceGUID) {
                        $deviceGUID = $deviceProperty.AD_ObjectGUID
                    }
                    if (!$deviceGUID) {
                        $deviceGUID = (Get-ADComputer -Filter "name -eq '$name'" -Property ObjectGUID).ObjectGUID.Guid
                    }
                    if ($deviceGUID) {
                        Write-Verbose "Search for the $name with $deviceGUID GUID in Intune database"
                        $deviceIntuneRecord = @($intuneDevice | ? azureADDeviceId -EQ $deviceGUID)
                    }

                    if ($deviceIntuneRecord.count -gt 1) {
                        # unable to narrow down the results

                        if (!$deviceGUID) {
                            $erMsg = "No GUID property was provided to identify the correct one, nor was found in AD."
                        } else {
                            $erMsg = "Unable to identify the correct one."
                        }
                        Write-Warning "Device $name is $($deviceIntuneRecord.count)x in Intune database.`n$erMsg Therefore setting property deviceIntuneRecord as `$null"
                        $deviceIntuneRecord = $null
                    }
                } else {
                    $deviceProperty.INTUNE_MultipleRecords = $false
                }

                if ($deviceIntuneRecord.count -eq 1) {
                    $deviceProperty.INTUNE_Name = $deviceIntuneRecord.deviceName
                    $deviceProperty.INTUNE_DeviceId = $deviceIntuneRecord.azureADDeviceId
                    $deviceProperty.INTUNE_LastSyncDateTime = $deviceIntuneRecord.lastSyncDateTime
                    $deviceProperty.INTUNE_DeviceRegistrationState = $deviceIntuneRecord.deviceRegistrationState

                    if ($deviceIntuneRecord.deviceEnrollmentType -ne "windowsCoManagement") {
                        $deviceProperty.INTUNE_CoManaged = $false
                    } else {
                        $deviceProperty.INTUNE_CoManaged = $true
                        if (!$deviceProperty.SCCM_CoManaged -and $deviceProperty.SCCM_InDatabase -and $deviceProperty.SCCM_ClientInstalled) {
                            Write-Verbose "According to Intune, $name is co-managed even though SCCM says otherwise"
                        }
                    }

                    if (!$deviceIntuneRecord.aadRegistered -or !$deviceIntuneRecord.azureADRegistered) {
                        $deviceProperty.INTUNE_Registered = $false
                    } else {
                        $deviceProperty.INTUNE_Registered = $true
                    }

                    $deviceProperty.INTUNE_User = $deviceIntuneRecord.emailAddress
                }
            }
        }

        if ($combineDataFrom -contains "AAD") {

            $deviceAADRecord = @($aadDevice | ? DisplayName -EQ $name)

            if (!$deviceAADRecord) {
                Write-Verbose "$name wasn't found in Intune database, trying to get its GUID"

                # try to search for it using its GUID
                if (!$deviceGUID) {
                    $deviceGUID = $cmp.ObjectGUID.Guid
                }
                if (!$deviceGUID) {
                    $deviceGUID = $deviceProperty.AD_ObjectGUID
                }
                if (!$deviceGUID) {
                    $deviceGUID = (Get-ADComputer -Filter "name -eq '$name'" -Property ObjectGUID).ObjectGUID.Guid
                }
                if ($deviceGUID) {
                    Write-Verbose "Search for the $name using its $deviceGUID GUID in AAD database"
                    # search for AAD device with GUID instead of name
                    $deviceAADRecord = @($aadDevice | ? { $_.deviceId -eq $deviceGUID })
                }
            }

            if (!$deviceAADRecord) {
                $deviceProperty.AAD_InDatabase = $false
            } else {
                # device is in AAD
                $deviceProperty.AAD_InDatabase = $true

                if ($deviceAADRecord.count -gt 1) {
                    # more records with the same name

                    $deviceProperty.AAD_MultipleRecords = $deviceAADRecord.count

                    Write-Verbose "Device $name is $($deviceAADRecord.count)x in AAD database!"

                    # get the correct one using GUID
                    if (!$deviceGUID) {
                        $deviceGUID = $cmp.ObjectGUID.Guid
                    }
                    if (!$deviceGUID) {
                        $deviceGUID = $deviceProperty.AD_ObjectGUID
                    }
                    if (!$deviceGUID) {
                        $deviceGUID = (Get-ADComputer -Filter "name -eq '$name'" -Property ObjectGUID).ObjectGUID.Guid
                    }
                    if ($deviceGUID) {
                        Write-Verbose "Search for the $name with $deviceGUID GUID in AAD database"
                        $deviceAADRecord = @($aadDevice | ? deviceID -EQ $deviceGUID)
                    }

                    if ($deviceAADRecord.count -gt 1) {
                        # unable to narrow down the results

                        if (!$deviceGUID) {
                            $erMsg = "No GUID property was provided to identify the correct one, nor was found in AD."
                        } else {
                            $erMsg = "Unable to identify the correct one."
                        }
                        Write-Warning "Device $name is $($deviceAADRecord.count)x in AAD database.`n$erMsg Therefore setting property deviceAADRecord as `$null"
                        $deviceAADRecord = $null
                    }
                } else {
                    $deviceProperty.AAD_MultipleRecords = $false
                }

                if ($deviceAADRecord.count -eq 1) {
                    $deviceProperty.AAD_Name = $deviceAADRecord.displayName
                    $deviceProperty.AAD_LastActiveTime = $deviceAADRecord.approximateLastSignInDateTime
                    $deviceProperty.AAD_Owner = $deviceAADRecord.deviceOwnership
                    $deviceProperty.AAD_IsCompliant = $deviceAADRecord.isCompliant
                    $deviceProperty.AAD_DeviceId = $deviceAADRecord.deviceId
                    $deviceProperty.AAD_EnrollmentType = $deviceAADRecord.enrollmentType
                    $deviceProperty.AAD_IsManaged = $deviceAADRecord.isManaged
                    $deviceProperty.AAD_ManagementType = $deviceAADRecord.managementType
                    $deviceProperty.AAD_OnPremisesSyncEnabled = $deviceAADRecord.onPremisesSyncEnabled
                    $deviceProperty.AAD_ProfileType = $deviceAADRecord.profileType
                }
            }
        }

        New-Object -TypeName PSObject -Property $deviceProperty
    } # end of foreach
}
