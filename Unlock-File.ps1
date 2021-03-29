function Unlock-File {
    <#
    .SYNOPSIS
    Function for closing open handles for specified file.

    .DESCRIPTION
    Function for closing open handles for specified file.
    Use sysinternals handle tool.

    .PARAMETER file
    Name or path to file which handles you want to close for.

    .PARAMETER force
    Switch for don't ask about closing handles.

    .PARAMETER handleExe
    Path to handle executable.
    If not specified, downloads handle tool from sysinternals page and use it.

    .EXAMPLE
    Unlock-File wordDocument.docx

    Finds open handles on file wordDocument.docx and offers them to close.

    .EXAMPLE
    Unlock-File wordDocument.docx -force

    Finds open handles on file wordDocument.docx and automatically closes them.
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string] $file
        ,
        [switch] $force
        ,
        [string] $handleExe = (Join-Path $env:TEMP "handle64.exe")
    )
    if (! ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
        # not running "as Administrator" - so relaunch as administrator

        # get command line arguments and reuse them
        $arguments = $myInvocation.line -replace [regex]::Escape($myInvocation.InvocationName), ""

        Start-Process powershell.exe -Verb RunAs -ArgumentList ('-noprofile -file "{0}" {1}' -f ($myinvocation.MyCommand.Definition), $arguments) # -noexit nebo -WindowStyle Hidden

        # exit from the current, unelevated, process
        exit
    }

    $ErrorActionPreference = "Stop"

    if (!(Test-Path $handleExe -ea SilentlyContinue)) {
        # download
        $handleZip = Join-Path $env:TEMP "handle.zip"
        Invoke-WebRequest "https://download.sysinternals.com/files/Handle.zip" -OutFile $handleZip -UseBasicParsing
        # extract
        Expand-Archive $handleZip $env:TEMP -Force
        $handleExe = Join-Path $env:TEMP "handle64.exe"
    }

    "Getting handles for '$file'"
    $handles = Start-Process2 $handleExe -argumentList "`"$file`" -nobanner -accepteula" -dontWait
    if ($handles) {
        $handles -split "`n" | ? { $_ } | % {
            Write-Verbose $_

            if ($_ -match "No matching handles found") {
                Write-Warning "No matching handles found"
                break
            }

            $processName = ([regex]"^\w+").Match($_)
            $processID = ([regex]"pid: (\d+)").Match($_).Groups[1].value
            $match = ([regex]"type: \w+ \s+ (\w+): (.+)").Match($_)
            $handleID = $match.Groups[1].value
            $file = $match.Groups[2].value
            $file = ($file -replace "`n" -replace "`r").trim()

            if ($processID -and $handleID) {
                if (!$force) {
                    $choice = ""
                    while ($choice -notmatch "^[Y|N]$") {
                        $choice = Read-Host "Close handle for file '$file' for process '$processName' with PID $processID? (Y|N)"
                    }
                }
                if ($force -or $choice -eq "Y") {
                    $result = Start-Process2 $handleExe -argumentList "-c $handleID -y -p $processID -nobanner -accepteula"
                    if ($result -notmatch "Handle closed") {
                        throw $result
                    } else {
                        if ($force) {
                            "Handle for '$file' closed (process $processName PID $processID)"
                        } else {
                            "Handle closed"
                        }
                    }
                }
            } else {
                Write-Warning "Unable to extract processID or handleID from:`n$_"
            }
        }
    }
}