####################  !MODIFY TO MATCH YOUR ORGANIZATION!  ####################
# $baseUri = 'https://contoso.atlassian.net/wiki'
$baseUri = Read-Host "Enter base URL of your Confluence wiki (something like 'https://contoso.atlassian.net/wiki'"

# $pageID = "2920906911"
$pageID = Read-Host "Enter ID of the Confluence page you want to work with (its the number part from page URL you want to work with i.e. 2920906911 for URL https://contoso.atlassian.net/wiki/spaces/IT/pages/2920906911/Edge+Network+Overview)"

# !MODIFY TO MATCH THE ZONE ID OF THE DNS ZONE YOU WANT TO WORK WITH!
# $domainZoneID = "Z01320692HE4O8HBIG967"
$domainZoneID = Read-Host "Enter ID of the AWS Zone Domain you want the records from (something like Z01320692HE4O8HBIG967)"
################################################################################


<#

Script will get DNS records from given AWS DNZ Zone and use them to create HTML table and save it to given Confluence wiki page.
In case there is already some HTML table there, extra information from it will be retained.

More information at https://doitpsway.com/how-to-createupdateread-html-table-on-confluence-wiki-page-using-powershell

#>


# confluence user account and its API key (NOT password!), that has appropriate permissions on given Confluence page
$confluenceCredential = Get-Credential -Message "Enter user login and his API key (NOT PASSWORD)"

Import-Module ConfluencePS -ErrorAction Stop

# authenticate to your Confluence space
Set-ConfluenceInfo -BaseURi $baseUri -Credential $confluenceCredential

Add-Type -AssemblyName System.Web

#region functions
function _getAWSDNSZoneRecord {
    # you have to use account, that has READ permissions over DNS zone you want to read records from
    param (
        [Parameter(Mandatory = $true)]
        [string] $domainZoneID
        ,
        [Parameter(Mandatory = $true)]
        [System.Management.Automation.PSCredential] $credential
    )

    # to download this modules use:
    # Install-Module -Name AWS.Tools.Installer -Force
    # Install-AWSToolsModule AWS.Tools.Common,AWS.Tools.Route53 -CleanUp
    Import-Module "$PSScriptRoot\AWS.Tools.Common" -ea stop
    Import-Module "$PSScriptRoot\AWS.Tools.Route53" -ea stop

    $accessKey = $credential.UserName
    $secretKey = $credential.GetNetworkCredential().password


    Set-AWSCredential -AccessKey $accessKey -SecretKey $secretKey

    # because results are returned by 100 items, you have to iterate (there is maxItem parameter but is limited to 300)
    # https://forums.aws.amazon.com/message.jspa?messageID=463427
    $nextIdentifier = $null
    $nextType = $null
    $nextName = $null

    [System.Collections.ArrayList] $result = @()

    do {
        $recordSet = Get-R53ResourceRecordSet -HostedZoneId "/hostedzone/$domainZoneID" -StartRecordIdentifier $nextIdentifier -StartRecordName $nextName -StartRecordType $nextType

        $recordSet.ResourceRecordSets | select @{n = "name"; e = { $name = $_.name; if ([string]::IsNullOrEmpty($name)) { "@" } else { $name } } }, type , @{n = "value"; e = { $_.ResourceRecords.value } } | % {
            $name = $_.name
            $type = $_.type
            if ($_.value.getType().name -ne "String") {
                # for each value create separate object
                $_.value | % {
                    [void] $result.add(
                        [PSCustomObject]@{
                            name  = $name
                            type  = $type
                            value = _optimizeValue $_
                        }
                    )
                }
            } else {
                # value is string, there is no need to expand it
                [void] $result.add(
                    [PSCustomObject]@{
                        name  = $name
                        type  = $type
                        value = _optimizeValue $_.value
                    }
                )
            }
        }

        # set up for the next call
        if ($recordSet.IsTruncated) {
            $nextIdentifier = $recordSet.NextRecordIdentifier
            $nextType = $recordSet.NextRecordType
            $nextName = $recordSet.NextRecordName
        }
    } while ($recordSet.IsTruncated)

    return $result
}

function _convertFromHTMLTable {
    # function convert html object to PS object
    # expects object returned by (Invoke-WebRequest).parsedHtml as input
    param ([System.__ComObject]$table)

    $columnName = $table.getElementsByTagName("th") | % { $_.innerText -replace "^\s*|\s*$" }

    $table.getElementsByTagName("tr") | % {
        # per row I read cell content and returns object
        $columnValue = $_.getElementsByTagName("td") | % { $_.innerText -replace "^\s*|\s*$" }
        if ($columnValue) {
            $property = [ordered]@{ }
            $i = 0
            $columnName | % {
                $property.$_ = $columnValue[$i]
                ++$i
            }

            New-Object -TypeName PSObject -Property $property
        } else {
            # row doesn't contain <td>, its probably headline
        }
    }
}

function _optimizeValue {
    param (
        [string] $text
        ,
        [int] $lengthLimit = 50
        ,
        [switch] $replaceNewLine
    )
    # replace | because it is delimiter in confluence
    $result = $text -replace "\|", "!" -join " "
    # TXT recoeds can be in quotes, so replace them, just in case
    $result = $text -replace '^"' -replace '"$'
    if ($replaceNewLine) {
        # multiline values are returned with \n on places where were linebreaks
        $result = $result -replace "\B\\n|\\n\s|\\n\B"
    }
    $result = $result.trim()
    if ($result.Length -gt $lengthLimit) {
        $result = $result.substring(0, $lengthLimit) + "..."
    }
    return $result
}

function _getCorrespondingData {
    param ($item)

    $resultByName = $confluenceContent | ? { $_.Name -eq $item.Name -and $_.Type -eq $item.Type }
    $resultByValue = $confluenceContent | ? { $_.Value -eq $item.Value -and $_.Type -eq $item.Type }
    $resultByNameAndValue = $confluenceContent | ? { $_.Name -eq $item.Name -and $_.Value -eq $item.Value -and $_.Type -eq $item.Type }

    if ($resultByNameAndValue) {
        if ( @($resultByNameAndValue).count -eq 1) {
            return $resultByNameAndValue
        } else {
            throw "There are multiple rows with same name '$($item.Name)' and value '$($item.Value)' of type '$($item.Type)' on $atlassianPage. Page sync cannot continue until you solve this duplicity."
        }
    }

    if ($resultByName -and @($resultByName).count -eq 1) {
        return $resultByName
    }
    if ($resultByValue -and @($resultByValue).count -eq 1) {
        return $resultByValue
    }

    Write-Warning "DNS record with name '$($item.Name)', value '$($item.Value)' and type '$($item.Type)' wasn't found on $atlassianPage.`nIt's new record or there was change of name or value in the existing one, that removed possibility to uniquely identify it.`n`nOwner and description will be therefore `$null."
}
#endregion functions

#region get data from AWS
$awsCredential = Get-Credential -Message "Enter credentials for AWS account"

$registratorContent = _getAWSDNSZoneRecord -domainZoneID $domainZoneID -credential $awsCredential
# filter non interesting records
$registratorContent = $registratorContent | ? { $_.type -notin "SOA", "NS" }

if (!$registratorContent) { throw "unable to receive DNS records" }
#endregion get data from AWS

#region get data from confluence page (table)
# authenticate to Confluence page
$Headers = @{"Authorization" = "Basic " + [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes(($confluenceCredential.UserName + ":" + [System.Runtime.InteropServices.marshal]::PtrToStringAuto([System.Runtime.InteropServices.marshal]::SecureStringToBSTR($confluenceCredential.Password)) ))) }

# Invoke-WebRequest instead of Get-ConfluencePage to be able to use ParsedHtml
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
try {
    $confluencePageContent = Invoke-WebRequest -Method GET -Headers $Headers -Uri "$baseUri/rest/api/content/$pageID`?expand=body.storage" -ea stop
} catch {
    if ($_.exception -match "The response content cannot be parsed because the Internet Explorer engine is not available") {
        throw "Error was: $($_.exception)`n Run following command on $env:COMPUTERNAME to solve this:`nSet-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Internet Explorer\Main' -Name DisableFirstRunCustomize -Value 2"
    } else {
        throw $_
    }
}

# from confluence page get content of the first html table
$table = $confluencePageContent.ParsedHtml.GetElementsByTagName('table')[0]

# convert HTML table to PS object
$confluenceContent = @(_convertFromHTMLTable $table)
#endregion get data from confluence page (table)

# merging registrator information with confluence user inputs
$mergedContent = $registratorContent | % {
    $item = $_
    $correspondingData = _getCorrespondingData $item
    $item | select Name, Type, Value, @{n = "Description"; e = { _optimizeValue $correspondingData.description -lengthLimit 1000 -replaceNewLine } }, @{ n = "Owner"; e = { $correspondingData.owner } }
}

# save the result back to confluence page
$body = $mergedContent | ConvertTo-ConfluenceTable | ConvertTo-ConfluenceStorageFormat
Set-ConfluencePage -PageID $pageID -Body $body