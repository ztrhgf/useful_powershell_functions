function New-JIRATicket {
    <#
    .SYNOPSIS
    Function for creating ticket.

    THIS IS JUST A proof-of-concept! You will have to customize this function for your own environment!
    To get more information about how to do it check https://doitpsway.com/how-to-create-a-jira-ticket-using-powershell.

    .DESCRIPTION
    Function for creating ticket.

    THIS IS JUST A proof-of-concept! You will have to customize this function for your own environment!
    To get more information about how to do it check https://doitpsway.com/how-to-create-a-jira-ticket-using-powershell.

    .PARAMETER summary
    Title of the ticket message.

    .PARAMETER description
    Description of the ticket message.

    .PARAMETER type
    Type of ticket. Case sensitive!

    .PARAMETER subType
    Subtype of the ticket. Case sensitive!

    .PARAMETER issueType
    Issue type of the ticket. Case sensitive!

    .PARAMETER confluenceUri
    Base uri for your confluence api requests.
    Something like 'https://contoso.atlassian.net'.

    .PARAMETER participantUPN
    UPN of confluence user(s) you want to add as participants.

    .PARAMETER credential
    Credentials for authentication against Jira environment.
    It should be UPN and API token of the account with permissions to create Jira ticket.

    .NOTES
    More information can be found at https://doitpsway.com/how-to-create-a-jira-ticket-using-powershell.
    #>

    [cmdletbinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string] $summary
        ,
        [string] $description = ""
        ,
        [Parameter(Mandatory = $true)]
        [string] $type
        ,
        [string] $subType
        ,
        [Parameter(Mandatory = $true)]
        [string] $issueType
        ,
        [ValidateScript( {
                if ($_ -match "@") {
                    $true
                } else {
                    throw "$_ isn't UPN (user@domain.xxx)"
                }
            })]
        [string[]] $participantUPN,

        [Parameter(Mandatory = $true)]
        [string] $project,

        [Parameter(Mandatory = $true)]
        [string] $confluenceUri,

        [System.Management.Automation.PSCredential] $credential
    )

    # authenticate
    if (!$credential) {
        try {
            $credential = Get-Credential -Message "Use API TOKEN instead of password!!!" -ErrorAction Stop
        } catch {
            throw "You didn't enter credentials"
        }
    }

    try {
        Set-JiraConfigServer $confluenceUri -ErrorAction Stop # required since version 2.10
        $s = New-JiraSession -Credential $credential -ErrorAction Stop
    } catch {
        throw "$_"
    }

    # set mandatory fields..
    $field = @{
        'customfield_13100' = @{
            value = $type
        }
    }

    # if ($type -and $subType) {
    #     $availableSubTypes = Get-JiraIssueCreateMetadata -Project $project -IssueType $issueType | ? { $_.id -eq "customfield_13100" } | select -exp allowedValues | ? { $_.value -eq $type } | select -exp children -ea silentlycontinue | select -exp value

    #     if ($subType -cnotin $availableSubTypes) {
    #         throw "Invalid subType (beware! names are case sensitive).`nValids for type $type are:`n$($availableSubTypes -join ', ')"
    #     }

    #     $field.customfield_13100.child = @{ value = $subType }
    # } elseif ($subType) {
    #     throw "You cannot use subType without type parameter"
    # }

    if ($participantUPN) {
        $customFieldId = Get-JiraIssueCreateMetadata -Project $project -IssueType $issueType | ? name -EQ "Request Participants" | select -exp Id
        if (!$customFieldId) { throw "Unable to find 'Request Participants' field id in the project $project" }

        $participantList = @()
        $participantUPN | % {
            # name cannot be used because of GDPR strict mode enabled
            $accountId = Invoke-JiraMethod "$confluenceUri/rest/api/3/user/search?query=$_" | select -ExpandProperty accountId
            if ($accountId) {
                $participantList += @{ accountId = $accountId }
            } else {
                Write-Warning "User $_ wasn't found i.e. wont be added as participant"
            }
        }

        $field.$customFieldId = @($participantList)
    }

    $params = @{
        Project     = $project
        IssueType   = $issueType
        Summary     = $summary
        Description = $description
        errorAction = "stop"
    }
    if ($field) {
        $params.Fields = $field
    }

    try {
        New-JiraIssue @params
    } catch {
        throw "Issue cannot be created:`n$_"
    }
}