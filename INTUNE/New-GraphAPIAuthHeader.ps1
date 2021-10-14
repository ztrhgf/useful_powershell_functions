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