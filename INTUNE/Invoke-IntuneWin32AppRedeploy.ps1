function Invoke-IntuneWin32AppRedeploy {
    <#
    .SYNOPSIS
    Function for forcing redeploy of selected Win32App deployed from Intune.

    .DESCRIPTION
    Function for forcing redeploy of selected Win32App deployed from Intune.

    OutGridView is used to output found Apps.

    Redeploy means that corresponding registry keys will be deleted from registry and service IntuneManagementExtension will be restarted.

    .PARAMETER computerName
    Name of remote computer where you want to force the redeploy.

    .PARAMETER getDataFromIntune
    Switch for getting Apps and User names from Intune, so locally used IDs can be translated to them.

    .PARAMETER credential
    Credential object used for Intune authentication.

    .PARAMETER tenantId
    Azure Tenant ID for Intune App authentication.

    .PARAMETER excludeSystemApp
    Switch for excluding Apps targeted to SYSTEM.

    .EXAMPLE
    Invoke-IntuneWin32AppRedeploy

    Get and show Win32App(s) deployed from Intune to this computer. Selected ones will be then redeployed.

    .EXAMPLE
    Invoke-IntuneWin32AppRedeploy -computerName PC-01 -getDataFromIntune credential $creds

    Get and show Win32App(s) deployed from Intune to computer PC-01. IDs of apps and targeted users will be translated to corresponding names. Selected ones will be then redeployed.

    .EXAMPLE
    Invoke-IntuneWin32AppRedeploy -computerName PC-01 -getDataFromIntune credential $creds -tenantId 123456789

    Get and show Win32App(s) deployed from Intune to computer PC-01. App authentication will be used instead of user auth.
    IDs of apps and targeted users will be translated to corresponding names. Selected ones will be then redeployed.

    .NOTES
    Author: @AndrewZtrhgf
    #>

    [CmdletBinding()]
    param (
        [string] $computerName,

        [switch] $getDataFromIntune,

        [System.Management.Automation.PSCredential] $credential,

        [string] $tenantId,

        [switch] $excludeSystemApp
    )

    #region helper function
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

    function _getIntuneApp {
        param ([string] $appID)

        $intuneApp | ? id -EQ $appID
    }

    # create helper functions text definition for usage in remote sessions
    if ($computerName) {
        $allFunctionDefs = "function _getTargetName { ${function:_getTargetName} }; function _getIntuneApp { ${function:_getIntuneApp} }"
    }
    #endregion helper function

    #region prepare
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
        $intuneApp = Invoke-MSGraphRequest -Url "https://graph.microsoft.com/beta/deviceAppManagement/mobileApps?select=id,displayname" | Get-MSGraphAllPages
        $intuneUser = Invoke-MSGraphRequest -Url 'https://graph.microsoft.com/beta/users?select=id,userPrincipalName' | Get-MSGraphAllPages
    }

    if ($computerName) {
        $session = New-PSSession -ComputerName $computerName -ErrorAction Stop
    } else {
        if (! ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
            throw "Run as administrator"
        }
    }
    #endregion prepare

    #region get data
    $scriptBlock = {
        param($verbosePref, $excludeSystemApp, $getDataFromIntune, $intuneApp, $intuneUser, $allFunctionDefs)

        # inherit verbose settings from host session
        $VerbosePreference = $verbosePref

        # recreate functions from their text definitions
        . ([ScriptBlock]::Create($allFunctionDefs))

        foreach ($app in (Get-ChildItem "HKLM:\SOFTWARE\Microsoft\IntuneManagementExtension\Win32Apps" -ErrorAction SilentlyContinue)) {
            $userAzureObjectID = Split-Path $app.Name -Leaf

            if ($excludeSystemApp -and $userAzureObjectID -eq "00000000-0000-0000-0000-000000000000") {
                Write-Verbose "Skipping system deployments"
                continue
            }

            $userWin32AppRoot = $app.PSPath
            $win32AppIDList = Get-ChildItem $userWin32AppRoot | select -ExpandProperty PSChildName | % { $_ -replace "_\d+$" } | select -Unique

            $win32AppIDList | % {
                $win32AppID = $_

                Write-Verbose "Processing App ID $win32AppID"

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
                        "ScopeId"            = $userAzureObjectID
                    }
                } else {
                    # no 'DisplayName' property
                    $property = [ordered]@{
                        "ScopeId"            = _getTargetName $userAzureObjectID
                        "Id"                 = $win32AppID
                        "LastUpdatedTimeUtc" = $lastUpdatedTimeUtc
                        # "Status"            = $complianceStateMessage.ComplianceState
                        "ProductVersion"     = $complianceStateMessage.ProductVersion
                        "LastError"          = $lastError
                    }
                }

                New-Object -TypeName PSObject -Property $property
            }
        }
    }

    $param = @{
        scriptBlock  = $scriptBlock
        argumentList = ($VerbosePreference, $excludeSystemApp, $getDataFromIntune, $intuneApp, $intuneUser, $allFunctionDefs)
    }
    if ($computerName) {
        $param.session = $session
    }

    $win32App = Invoke-Command @param | select -Property * -ExcludeProperty PSComputerName, RunspaceId, PSShowComputerName
    #endregion get data

    #region let user redeploy chosen app
    if ($win32App) {
        $hasDisplayNameProp = $win32App | Get-Member -Name DisplayName
        $appToRedeploy = $win32App | ? { if ($hasDisplayNameProp) { if ($_.DisplayName) { $true } } else { $true } } | Out-GridView -PassThru -Title "Pick app(s) for redeploy"

        if ($appToRedeploy) {
            $scriptBlock = {
                param ($verbosePref, $appToRedeploy)

                # inherit verbose settings from host session
                $VerbosePreference = $verbosePref

                $win32AppKeys = Get-ChildItem "HKLM:\SOFTWARE\Microsoft\IntuneManagementExtension\Win32Apps" -Recurse -Depth 2 | select PSChildName, PSPath, PSParentPath

                $appToRedeploy | % {
                    $appId = $_.id
                    $scopeId = $_.scopeId
                    if ($scopeId -eq 'device') { $scopeId = "00000000-0000-0000-0000-000000000000" }
                    Write-Warning "Preparing redeploy for app $appId (scope $scopeId)"

                    $win32AppKeyToDelete = $win32AppKeys | ? { $_.PSChildName -Match "^$appId`_\d+" -and $_.PSParentPath -Match "\\$scopeId$" }

                    if ($win32AppKeyToDelete) {
                        $win32AppKeyToDelete | % {
                            Write-Verbose "Deleting $($_.PSPath)"
                            Remove-Item $_.PSPath -Force -Recurse
                        }
                    } else {
                        throw "BUG??? App $appId with scope $scopeId wasn't found in the registry"
                    }
                }

                Write-Warning "Invoking redeploy (by restarting service IntuneManagementExtension). Redeploy can take several minutes!"
                Restart-Service IntuneManagementExtension -Force
            }

            $param = @{
                scriptBlock  = $scriptBlock
                argumentList = ($VerbosePreference, $appToRedeploy)
            }
            if ($computerName) {
                $param.session = $session
            }

            Invoke-Command @param
        }
    } else {
        Write-Warning "No deployed Win32App detected"
    }
    #endregion let user redeploy chosen app

    if ($computerName) {
        Remove-PSSession $session
    }
}