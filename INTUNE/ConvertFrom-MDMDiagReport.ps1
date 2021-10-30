function ConvertFrom-MDMDiagReport {
    <#
    .SYNOPSIS
    Function for converting MDMDiagReport.html to PowerShell object.

    .DESCRIPTION
    Function for converting MDMDiagReport.html to PowerShell object.

    .PARAMETER MDMDiagReport
    Path to MDMDiagReport.html file.
    It will be created if doesn't exist.

    By default "C:\Users\Public\Documents\MDMDiagnostics\MDMDiagReport.html" is checked.

    .PARAMETER showKnobs
    Switch for including knobs results in "Managed Policies" and "Enrolled configuration sources and target resources" tables.
    Knobs seems to be just some internal power related diagnostic data, therefore hidden by default.

    .EXAMPLE
    ConvertFrom-MDMDiagReport

    Converts content of "C:\Users\Public\Documents\MDMDiagnostics\MDMDiagReport.html" (if it doesn't exists, generates first) to PowerShell object.
    #>

    [CmdletBinding()]
    param (
        [ValidateScript( {
                If ($_ -match "\.html$") {
                    $true
                } else {
                    Throw "$_ is not a valid path to MDM html report"
                }
            })]
        [string] $MDMDiagReport = "C:\Users\Public\Documents\MDMDiagnostics\MDMDiagReport.html",

        [switch] $showKnobs
    )

    if (!(Test-Path $MDMDiagReport -PathType Leaf)) {
        Write-Warning "'$MDMDiagReport' doesn't exist, generating..."
        $MDMDiagReportFolder = Split-Path $MDMDiagReport -Parent
        Start-Process MdmDiagnosticsTool.exe -Wait -ArgumentList "-out `"$MDMDiagReportFolder`"" -NoNewWindow
    }

    # hardcoded titles from MDMDiagReport.html report
    $MDMDiagReportTable = @{
        1  = "Device Info"
        2  = "Connection Info"
        3  = "Device Management Account"
        4  = "Certificates"
        5  = "Enrolled configuration sources and target resources"
        6  = "Managed Policies"
        7  = "Managed applications"
        8  = "GPCSEWrapper Policies"
        9  = "Blocked Group Policies"
        10 = "Unmanaged policies"
    }

    $result = [ordered]@{}
    $tableOrder = 1

    $Source = Get-Content $MDMDiagReport -Raw
    $HTML = New-Object -Com "HTMLFile"
    $HTML.IHTMLDocument2_write($Source)
    $HTML.body.getElementsByTagName('table') | % {
        $tableName = $MDMDiagReportTable.$tableOrder -replace " ", "_"
        if (!$tableName) { throw "Undefined tableName" }

        $result.$tableName = ConvertFrom-HTMLTable $_ -tableName $tableName

        if ($tableName -eq "Managed_Policies" -and !$showKnobs) {
            $result.$tableName = $result.$tableName | ? { $_.Area -ne "knobs" }
        } elseif ($tableName -eq "Enrolled_configuration_sources_and_target_resources" -and !$showKnobs) {
            # all provisioning sources are knobs
            $result.$tableName = $result.$tableName | ? { $_.'Configuration source' -ne "Provisioning" }
        }

        ++$tableOrder
    }

    New-Object -TypeName PSObject -Property $result
}