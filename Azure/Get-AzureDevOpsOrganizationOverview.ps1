#Requires -Module MSAL.PS
function Get-AzureDevOpsOrganizationOverview {
    <#
    .SYNOPSIS
    Function for getting list of all Azure DevOps organizations that uses your AzureAD directory.

    .DESCRIPTION
    Function for getting list of all Azure DevOps organizations that uses your AzureAD directory.
    It is the same data as downloaded csv from https://dev.azure.com/<organizationName>/_settings/organizationAad.

    Function uses MSAL to authenticate (requires MSAL.PS module).

    .PARAMETER tenantId
    (optional) ID of your Azure tenant.
    Of omitted, tenantId from MSAL auth. ticket will be used.

    .EXAMPLE
    Get-AzureDevOpsOrganizationOverview

    Returns all DevOps organizations in your Azure tenant.

    .NOTES
    PowerShell module AzSK.ADO > ContextHelper.ps1 > GetCurrentContext
    https://stackoverflow.com/questions/56355274/getting-oauth-tokens-for-azure-devops-api-consumption
    https://stackoverflow.com/questions/52896114/use-azure-ad-token-to-authenticate-with-azure-devops
    #>

    [CmdletBinding()]
    param (
        [string] $tenantId = $_tenantId
    )

    if (!(Get-Module "MSAL.PS" -ListAvailable -ea SilentlyContinue)) {
        throw "Module MSAL.PS is missing.`n`nYou can install it via: Install-Module MSAL.PS -Scope CurrentUSer"
    }

    $clientId = "872cd9fa-d31f-45e0-9eab-6e460a02d1f1" # Visual Studio
    $adoResourceId = "499b84ac-1321-427f-aa17-267ca6975798" # Azure DevOps app ID

    $msalToken = Get-MsalToken -Scopes "$adoResourceId/.default" -ClientId $clientId -ErrorAction Stop

    if (!$tenantId) {
        $tenantId = $msalToken.tenantId
        Write-Verbose "Set TenantId to $tenantId (retrieved from MSAL token)"
    }

    $base64AuthInfo = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes(("{0}:{1}" -f "", $msalToken.accessToken)))

    # URL retrieved thanks to developer mod at page https://dev.azure.com/<organizationName>/_settings/organizationAad
    Invoke-WebRequest -Uri "https://aexprodweu1.vsaex.visualstudio.com/_apis/EnterpriseCatalog/Organizations?tenantId=$tenantId" -Method get -ContentType "application/json" -Headers @{Authorization = ("Basic {0}" -f $base64AuthInfo) } | select -ExpandProperty content | ConvertFrom-Csv
}