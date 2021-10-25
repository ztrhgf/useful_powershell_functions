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

    .EXAMPLE
    ConvertFrom-MDMDiagReport

    Converts content of  "C:\Users\Public\Documents\MDMDiagnostics\MDMDiagReport.html" (if it doesn't exists, generates and converts) to PowerShell object.

    .NOTES
    Author: Ondrej Sebela (ztrhgf@seznam.cz)
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
        [string] $MDMDiagReport = "C:\Users\Public\Documents\MDMDiagnostics\MDMDiagReport.html"
    )

    if (!(Test-Path $MDMDiagReport -PathType Leaf)) {
        Write-Warning "'$MDMDiagReport' doesn't exist, generating..."
        $MDMDiagReportFolder = Split-Path $MDMDiagReport -Parent
        Start-Process MdmDiagnosticsTool.exe -Wait -ArgumentList "-out `"$MDMDiagReportFolder`"" -NoNewWindow
    }

    #region helper functions
    function _convertFromHTMLTable {
        param (
            # expects object created by Invoke-WebRequest parsedHtml() or IHTMLDocument2_write() method
            [System.__ComObject] $table,

            [string] $tableName
        )

        $twoColumnsWithoutName = 0

        if ($tableName) { $tableNameTxt = "'$tableName'" }

        $columnName = $table.getElementsByTagName("th") | % { $_.innerText -replace "^\s*|\s*$" }
        if (!$columnName) {
            $numberOfColumns = @($table.getElementsByTagName("tr")[0].getElementsByTagName("td")).count
            if ($numberOfColumns -eq 2) {
                ++$twoColumnsWithoutName
                Write-Verbose "Table $tableNameTxt has two columns without column names. Resultant object will use first column as objects property 'Name' and second as 'Value'"
            } elseif ($numberOfColumns) {
                Write-Warning "Table $tableNameTxt doesn't contain column names, numbers will be used instead"
                $columnName = 1..$numberOfColumns
            } else {
                throw "Table $tableNameTxt doesn't contain column names and summarization of columns failed"
            }
        }

        if ($twoColumnsWithoutName) {
            # table has two columns without names
            $property = [ordered]@{ }

            $table.getElementsByTagName("tr") | % {
                # read table per row and return object
                $columnValue = $_.getElementsByTagName("td") | % { $_.innerText -replace "^\s*|\s*$" }
                if ($columnValue) {
                    # use first column value as object property 'Name' and second as a 'Value'
                    $property.($columnValue[0]) = $columnValue[1]
                } else {
                    # row doesn't contain <td>
                }
            }
            if ($tableName) {
                $property.TableName = $tableName
            }

            New-Object -TypeName PSObject -Property $property
        } else {
            # table doesn't have two columns or they are named
            $table.getElementsByTagName("tr") | % {
                # read table per row and return object
                $columnValue = $_.getElementsByTagName("td") | % { $_.innerText -replace "^\s*|\s*$" }
                if ($columnValue) {
                    $property = [ordered]@{ }
                    $i = 0
                    $columnName | % {
                        $property.$_ = $columnValue[$i]
                        ++$i
                    }
                    if ($tableName) {
                        $property.TableName = $tableName
                    }

                    New-Object -TypeName PSObject -Property $property
                } else {
                    # row doesn't contain <td>, its probably row with column names
                }
            }
        }
    }
    #endregion helper functions

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
        $result.$tableName = _convertFromHTMLTable $_ -tableName $tableName
        ++$tableOrder
    }

    New-Object -TypeName PSObject -Property $result
}