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
            If ($ServerFQDN) {
                Return "https://$($ServerFQDN)/AdminService"
            }
            If ($ExternalUrl) {
                Return $ExternalUrl
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