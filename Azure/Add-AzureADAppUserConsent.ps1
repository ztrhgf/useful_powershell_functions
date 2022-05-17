#Requires -Module Microsoft.Graph.Authentication, Microsoft.Graph.Applications, Microsoft.Graph.Users, Microsoft.Graph.Identity.SignIns
function Add-AzureADAppUserConsent {
    <#
    .SYNOPSIS
    Function for granting consent on behalf of a user to chosen application over selected resource(s) (enterprise app(s)) and permission(s) and assign the user default app role to be able to see the app in his 'My Apps'.

    .DESCRIPTION
    Function for granting consent on behalf of a user to chosen application over selected resource(s) (enterprise app(s)) and permission(s) and assign the user default app role to be able to see the app in his 'My Apps'.

    Consent can be explicitly specified or copied from some existing one.

    .PARAMETER clientAppId
    ID of application you want to grant consent on behalf of a user.

    .PARAMETER consent
    Hashtable where:
    - key is objectId of the resource (enterprise app) you are granting permissions to
    - value is list of permissions strings (scopes)

    Both can be found at Permissions tab of the enterprise app in Azure portal, when you select particular permission.

    For example:
    $consent = @{
        "02ad85cd-02ce-4902-a319-1af611526021" = "User.Read", "Contacts.ReadWrite", "Calendars.ReadWrite", "Mail.Send", "Mail.ReadWrite", "EWS.AccessAsUser.All"
    }

    .PARAMETER copyExistingConsent
    Switch for getting consent details (resource ObjectId and permissions) from existing user consent.
    You will be asked for confirmation before proceeding.

    .PARAMETER userUpnOrId
    User UPN or ID.

    .EXAMPLE
    $consent = @{
        "88690023-f9e1-4728-9028-cdcc6bf67d22" = "User.Read"
        "02ad85cd-02ce-4902-a319-1af611526021" = "User.Read", "Contacts.ReadWrite", "Calendars.ReadWrite", "Mail.Send", "Mail.ReadWrite", "EWS.AccessAsUser.All"
    }

    Add-AzureADAppUserConsent -clientAppId "00b263e4-3497-4650-b082-3197cfdfdd7c" -consent $consent -userUpnOrId "dealdesk@contoso.onmicrosoft.com"

    Grants consent on behalf of the "dealdesk@contoso.onmicrosoft.com" user to application "Salesforce Inbox" (00b263e4-3497-4650-b082-3197cfdfdd7c) and given permissions on resource (ent. application) "Office 365 Exchange Online" (02ad85cd-02ce-4902-a319-1af611526021) and "Windows Azure Active Directory" (88690023-f9e1-4728-9028-cdcc6bf67d22).

    .EXAMPLE
    Add-AzureADAppUserConsent -clientAppId "00b263e4-3497-4650-b082-3197cfdfdd7c" -copyExistingConsent -userUpnOrId "dealdesk@contoso.onmicrosoft.com"

    Grants consent on behalf of the "dealdesk@contoso.onmicrosoft.com" user to application "Salesforce Inbox" (00b263e4-3497-4650-b082-3197cfdfdd7c) based on one of the existing consents.

    .NOTES
    https://docs.microsoft.com/en-us/azure/active-directory/manage-apps/grant-consent-single-user
    #>

    [CmdletBinding()]
    param (
        # The app for which consent is being granted
        [Parameter(Mandatory = $true)]
        [string] $clientAppId,

        [Parameter(Mandatory = $true, ParameterSetName = "explicit")]
        [hashtable] $consent,

        [Parameter(ParameterSetName = "copyConsent")]
        [switch] $copyExistingConsent,

        [Parameter(Mandatory = $true)]
        # The user on behalf of whom access will be granted. The app will be able to access the API on behalf of this user.
        [string] $userUpnOrId
    )

    $ErrorActionPreference = "Stop"

    #region connect to Microsoft Graph PowerShell
    # we need User.ReadBasic.All to get
    # users' IDs, Application.ReadWrite.All to list and create service principals,
    # DelegatedPermissionGrant.ReadWrite.All to create delegated permission grants,
    # and AppRoleAssignment.ReadWrite.All to assign an app role.
    # WARNING: These are high-privilege permissions!

    Import-Module Microsoft.Graph.Authentication
    Import-Module Microsoft.Graph.Applications
    Import-Module Microsoft.Graph.Users
    Import-Module Microsoft.Graph.Identity.SignIns

    Connect-AzureAD -asYourself

    $null = Connect-MgGraph -Scopes ("User.ReadBasic.All", "Application.ReadWrite.All", "DelegatedPermissionGrant.ReadWrite.All", "AppRoleAssignment.ReadWrite.All")
    #endregion connect to Microsoft Graph PowerShell

    $clientSp = Get-MgServicePrincipal -Filter "appId eq '$($clientAppId)'"
    if (-not $clientSp) {
        throw "Enterprise application with Application ID $clientAppId doesn't exist"
    }

    # prepare consent from the existing one
    if ($copyExistingConsent) {
        $consent = @{}

        Get-AzureADServicePrincipalOAuth2PermissionGrant -ObjectId $clientSp.id -All:$true | group resourceId | select @{n = 'ResourceId'; e = { $_.Name } }, @{n = 'ScopeToGrant'; e = { $_.group | select -First 1 | select -ExpandProperty scope } } | % {
            $consent.($_.ResourceId) = $_.ScopeToGrant
        }

        if (!$consent.Keys) {
            throw "There is no existing user consent that can be cloned. Use parameter consent instead."
        } else {
            "Following consent(s) will be added:"
            $consent.GetEnumerator() | % {
                $resourceSp = Get-MgServicePrincipal -Filter "id eq '$($_.key)'"
                if (!$resourceSp) {
                    throw "Resource with ObjectId $($_.key) doesn't exist"
                }
                " - resource '$($resourceSp.DisplayName)' permission: $(($_.value | sort) -join ', ')"
            }

            $choice = ""
            while ($choice -notmatch "^[Y|N]$") {
                $choice = Read-Host "`nContinue? (Y|N)"
            }
            if ($choice -eq "N") {
                break
            }
        }
    }

    #region create a delegated permission that grants the client app access to the API, on behalf of the user.
    $user = Get-MgUser -UserId $userUpnOrId
    if (!$user) {
        throw "User $userUpnOrId doesn't exist"
    }

    foreach ($item in $consent.GetEnumerator()) {
        $resourceId = $item.key
        $scope = $item.value

        if (!$scope) {
            throw "You haven't specified any scope for resource $resourceId"
        }

        $resourceSp = Get-MgServicePrincipal -Filter "id eq '$resourceId'"
        if (!$resourceSp) {
            throw "Resource with ObjectId $resourceId doesn't exist"
        }

        # convert scope string (perm1 perm2) i.e. permission joined by empty space (returned by Get-AzureADServicePrincipalOAuth2PermissionGrant) into array
        if ($scope -match "\s+") {
            $scope = $scope -split "\s+" | ? { $_ }
        }

        $scopeToGrant = $scope

        # check if user already granted some permissions to this app for such resource
        # and skip such permissions to avoid errors
        $scopeAlreadyGranted = Get-MgOauth2PermissionGrant -Filter "principalId eq '$($user.Id)' and clientId eq '$($clientSp.Id)' and resourceId eq '$resourceId'" | select -ExpandProperty Scope
        if ($scopeAlreadyGranted) {
            Write-Verbose "Some permission(s) ($($scopeAlreadyGranted.trim())) are already granted to an app '$($clientSp.Id)' and resourceId '$resourceId'"
            $scopeAlreadyGrantedList = $scopeAlreadyGranted.trim() -split "\s+"

            $scopeToGrant = $scope | ? { $_ } | % {
                if ($_ -in $scopeAlreadyGrantedList) {
                    Write-Warning "Permission '$_' is already granted. Skipping"
                } else {
                    $_
                }
            }

            if (!$scopeToGrant) {
                Write-Warning "All permissions for resource $resourceId are already granted. Skipping"
                continue
            }
        }

        Write-Warning "Grant user consent on behalf of '$userUpnOrId' for application '$($clientSp.DisplayName)' to have following permission(s) '$(($scopeToGrant.trim() | sort) -join ', ')' over API '$($resourceSp.DisplayName)'"

        $grant = New-MgOauth2PermissionGrant -ResourceId $resourceSp.Id -Scope ($scopeToGrant -join " ") -ClientId $clientSp.Id -ConsentType "Principal" -PrincipalId $user.Id
    }
    #endregion create a delegated permission that grants the client app access to the API, on behalf of the user.

    #region assign the app to the user.
    # this ensures that the user can sign in if assignment is required, and ensures that the app shows up under the user's My Apps.
    $userAssignableRole = $clientSp.AppRoles | ? { $_.AllowedMemberTypes -contains "User" }
    if ($userAssignableRole) {
        Write-Warning "A default app role assignment cannot be created because the client application exposes user-assignable app roles ($($userAssignableRole.DisplayName -join ', ')). You must assign the user a specific app role for the app to be listed in the user's My Apps access panel."
    } else {
        if (Get-MgServicePrincipalAppRoleAssignedTo -ServicePrincipalId $clientSp.Id -Property AppRoleId, PrincipalId | ? PrincipalId -EQ $user.Id) {
            # user already have some app role assigned
            Write-Verbose "User already have some app role assigned. Skipping default app role assignment."
        } else {
            # the app role ID 00000000-0000-0000-0000-000000000000 is the default app role
            # indicating that the app is assigned to the user, but not for any specific app role.
            Write-Verbose "Assigning default app role to the user"
            $assignment = New-MgServicePrincipalAppRoleAssignedTo -ServicePrincipalId $clientSp.Id -ResourceId $clientSp.Id -PrincipalId $user.Id -AppRoleId "00000000-0000-0000-0000-000000000000"
        }
    }
    #endregion assign the app to the user.
}