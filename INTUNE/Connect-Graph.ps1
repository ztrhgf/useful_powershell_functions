function Connect-Graph {
    <#
    .SYNOPSIS
    Function for connecting to Microsoft Graph.

    .DESCRIPTION
    Function for connecting to Microsoft Graph.
    Support interactive authentication or application authentication
    Without specifying any parameters, interactive auth. will be used.

    .PARAMETER TenantId
    ID of your tenant.

    .PARAMETER AppId
    Azure AD app ID (GUID) for the application that will be used to authenticate

    .PARAMETER AppSecret
    Specifies the Azure AD app secret corresponding to the app ID that will be used to authenticate.
    Can be generated in Azure > 'App Registrations' > SomeApp > 'Certificates & secrets > 'Client secrets'.

    .PARAMETER Beta
    Set schema to beta.

    .EXAMPLE
    Connect-Graph -TenantId <yourTenantId>

    .NOTES
    Requires module Microsoft.Graph.Intune
    #>

    [CmdletBinding()]
    [Alias("Connect-MSGraph2", "Connect-MSGraphApp2")]
    param (
        [Parameter(Mandatory = $true)]
        [string] $TenantId
        ,
        [string] $AppId
        ,
        [string] $AppSecret
        ,
        [switch] $beta
    )

    if (!(Get-Command Connect-MSGraph, Connect-MSGraphApp -ea silent)) {
        throw "Module Microsoft.Graph.Intune is missing"
    }

    if ($beta) {
        if ((Get-MSGraphEnvironment).SchemaVersion -ne "beta") {
            $null = Update-MSGraphEnvironment -SchemaVersion beta
        }
    }

    if ($TenantId -and $AppId -and $AppSecret) {
        $graph = Connect-MSGraphApp -Tenant $TenantId -AppId $AppId -AppSecret $AppSecret -ea Stop
        Write-Verbose "Connected to Intune tenant $TenantId using app-based authentication (Azure AD authentication not supported)"
    } else {
        $graph = Connect-MSGraph -ea Stop
        Write-Verbose "Connected to Intune tenant $($graph.TenantId)"
    }
}