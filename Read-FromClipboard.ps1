function Read-FromClipboard {
    <#
    .SYNOPSIS
    Read text from clipboard and tries to convert it to PSCUSTOMOBJECT.

    .DESCRIPTION
    Read text from clipboard and tries to convert it to PSCUSTOMOBJECT.
    At first it tries to convert clipboard data to XML, then JSON and as last resort to CSV.

    Content is trimmed! Because text can be indent etc.

    .PARAMETER delimiter
    Default is '`t' i.e. TABULATOR.

    If delimiter wont be found in header, you will be asked to provide the correct one.

    .PARAMETER headerCount
    Number of header columns. Can be used if content doesn't contain header itself and you don't want to specify header names. Will create numbered header columns starting from 1.
    In case you specify header parameter too and count of header columns will be lesser than headerCount, columns will be added with numbers.

    In case '1' is selected, result will be array of items instead of object with one property.

    So for: -header name, age -headerCount 5
    Resultant header will be: name, age, 3, 4, 5

    .PARAMETER header
    Columns that will be used for parsed clipboard content.

    Use if clipboard content doesn't contain header on its own. Or if you want to replace clipboards content header with your own, but in such case don't forget to use skipFirstLine parameter!

    .PARAMETER skipFirstLine
    Switch for skipping first clipboard content line.

    .PARAMETER regexDelimiter
    Switch for letting function know that used delimiter is regex.

    .EXAMPLE
    Clipboard contains:
    name, age, city
    Carl, 14, Prague
    John, 30, Boston

    You run:
    Read-FromClipboard -delimiter ","

    You get:
    name  age  city
    ---- ---- -----
    Carl  14   Prague
    John  30   Boston

    .EXAMPLE
    Clipboard contains:
    N4-01-NTB
    NG-06-NTB
    NG-07-NTB
    NG-18-NTB
    NG-30-NTB

    You run:
    Read-FromClipboard -headerCount 1

    You get:
    array of strings

    .EXAMPLE
    Clipboard contains:
    2002      89   144588      62016   1 893,42  33732   1 EXCEL
    5207     195   286136     109264  10 376,50  29220   1 explorer
    426      19     6552      10560      43,13  23356   1 FileCoAuth

    You run:
    Read-FromClipboard -delimiter "\s+" -regexDelimiter -headerCount 9 | Format-Table

    You get:
    1    2   3      4      5     6      7     8          9
    -    -   -      -      -     -      -     -          -
    2002 89  144588 62016  1     893,42 33732 1          EXCEL
    5207 195 286136 109264 10    376,50 29220 1          explorer
    426  19  6552   10560  43,13 23356  1     FileCoAuth

    .EXAMPLE
    Clipboard contains:
    2002      89   144588      62016   1 893,42  33732   1 EXCEL
    5207     195   286136     109264  10 376,50  29220   1 explorer
    426      19     6552      10560      43,13  23356   1 FileCoAuth

    You run:
    Read-FromClipboard -delimiter "\s+" -regexDelimiter -header handles, npm, pm, ws, cpu, id -headerCount 9 | Format-Table

    You get:
    handles npm pm     ws     cpu   id     7     8          9
    ------- --- --     --     ---   --     -     -          -
    2002    89  144588 62016  1     893,42 33732 1          EXCEL
    5207    195 286136 109264 10    376,50 29220 1          explorer
    426     19  6552   10560  43,13 23356  1     FileCoAuth

    .NOTES
    Based on https://www.powershellgallery.com/packages/ImportExcel/7.2.1 so kudos to that author.

    .LINK
    https://github.com/ztrhgf
    #>

    [CmdletBinding()]
    param (
        $delimiter = "`t",

        [ValidateRange(1, 999)]
        [int] $headerCount,

        [string[]] $header,

        [switch] $skipFirstLine,

        [switch] $regexDelimiter
    )

    # get clipboard as a text
    $data = Get-Clipboard -Raw

    if (!$data) { return }

    if ($header -and $skipFirstLine) {
        Write-Warning "Header parameter is used but skipFirstLine is not >> clipboard data cannot contain its own header!"
    } elseif ($headerCount -and $skipFirstLine) {
        Write-Warning "HeaderCount parameter is used but skipFirstLine is not >> clipboard data cannot contain its own header!"
    }

    #region helper functions
    function _delimiter {
        param ($d)

        if (!$regexDelimiter) {
            [regex]::escape($d)
        } else {
            $d
        }
    }

    function _readableDelimiter {
        param ($d)

        if ($regexDelimiter) {
            return "`"$d`""
        }

        switch ($d) {
            "`n" { '"`n"' }
            "`t" { '"`t"' }
            default { "`"$d`"" }
        }
    }
    #endregion helper functions

    # add numbers instead of missing headers column names
    if ($headerCount -and $headerCount -gt $header.count) {
        [int]($header.count + 1)..$headerCount | % {
            Write-Verbose "$_ was added instead of missing column name"
            $header += $_
        }
    }

    #region consider data as XML
    try {
        [xml]$data
        return
    } catch {
        Write-Verbose "It isn't XML"
    }
    #endregion consider data as XML

    #region consider data as JSON
    try {
        # at first try convert clipboard text as a JSON
        ConvertFrom-Json $data -ErrorAction Stop
        return
    } catch {
        Write-Verbose "It isn't JSON"
    }
    #endregion consider data as JSON

    #region consider data as CSV
    # split content line by line
    $data = $data.Split([Environment]::NewLine) | ? { $_ }

    if ($skipFirstLine) {
        Write-Verbose "Skipping first line of clipboard data ($($data[0]))"
        $data = $data | select -Skip 1
    }

    $firstLine = $data[0]

    $substringIndex = 20
    if ($firstLine.length -lt $substringIndex) { $substringIndex = $firstLine.length }

    # get correct delimiter
    if ($headerCount -ne 1) {
        while ($firstLine -notmatch (_delimiter $delimiter)) {
            $delimiter = Read-Host "Delimiter $(_readableDelimiter $delimiter) isn't used in clipboard text ($($firstLine.substring(0, $substringIndex))...). What delimiter should be used?"

            $delimiter = _delimiter $delimiter
        }
    } else {
        # only one property should be returned i.e. I will return array of strings instead of object with one property
        # and therefore none delimiter is needed
    }

    if (!$header) {
        # fix case when first line (header) ends with delimiter
        if ($firstLine[-1] -match (_delimiter $delimiter)) {
            $firstLine = $firstLine -replace ((_delimiter $delimiter) + "$")
        }

        # get header from first line of the clipboard text
        $header = $firstLine.trim() -split (_delimiter $delimiter)
        Write-Verbose "Header is $($header -join ', ') (count $($header.count))"
        # the rest of the lines is actual content
        $dataContent = $data.trim() | select -Skip 1
    } else {
        # I have header, so even first line of the clipboard text is content
        $dataContent = $data.trim()
    }

    $dataContent | % {
        $row = $_
        Write-Verbose "Processing row $row"
        # prepare empty object
        $property = [Ordered]@{}
        $header | % {
            Write-Verbose "Adding property $_"
            $property.$_ = $null
        }
        $object = New-Object -TypeName PSObject -Property $property

        # fill object properties
        $i = 0
        $row -split (_delimiter $delimiter) | % {
            if (($i + 1) -gt $header.count) {
                # number of splitted values is greater than number of columns in header
                # remaining values will be added to the last column
                $key = $header[($header.count - 1)]
                $object.$key += (_delimiter $delimiter) + $_
            } else {
                $key = $header[$i]
                $object.$key = $_
            }
            ++$i
        }

        if ($headerCount -eq 1) {
            # return objects property content (string) instead of object itself
            $object.1
        } else {
            # return object
            $object
        }
    }
    #endregion consider data as CSV
}