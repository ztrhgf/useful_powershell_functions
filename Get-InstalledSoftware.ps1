function Get-InstalledSoftware {
    <#
    .SYNOPSIS
    Fce pro zjištění nainstalovaného software.

    .DESCRIPTION
    Fce získává jak 32 tak 64 bit aplikace.
    Pokud se zadá i parametr $ProgramName, tak dojde k vyhledání software s daným stringem v názvu
    Standardně nezobrazuje aktualizace ani bezpečností záplaty (tedy *Update for Microsoft* a *Security Update for Microsoft*)

    .PARAMETER  ComputerName
    Parametr určující kde se má fce spustit.

    .PARAMETER  ProgramName
    Nepovinný parametr, sloužící pro vyfiltrování konkrétního jména aplikace.

    .PARAMETER  DontIgnoreUpdates
    Switch pro zobrazení aktualizací.

    .PARAMETER Property
    Jaké vlastnosti klíče se mají vypsat.

    .PARAMETER Ogv
    Switch. Vystup se posle do out-gridview.

    .EXAMPLE
    $hala | get-installedsoftware -ProgramName winamp

    .NOTES
    Převzato z https://gallery.technet.microsoft.com/scriptcenter/Get-RemoteProgram-Get-list-de9fd2b4 a upraveno.
    #>

    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true, Position = 0)]
        [string[]] $computerName = $env:COMPUTERNAME
        ,
        [Parameter(Position = 1)]
        [string] $programName
        ,
        [switch] $dontIgnoreUpdates
        ,
        [string[]] $property = ('DisplayVersion', 'UninstallString')
        ,
        [switch] $ogv
    )

    BEGIN {
    }

    PROCESS {
        $result = Invoke-Command2 -ComputerName $computerName {
            param ($Property, $DontIgnoreUpdates, $ProgramName)

            $RegistryLocation = 'SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\', 'SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\'
            $HashProperty = @{}
            $SelectProperty = @('ProgramName', 'ComputerName')
            if ($Property) {
                $SelectProperty += $Property
            }

            $RegBase = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $env:COMPUTERNAME)
            foreach ($CurrentReg in $RegistryLocation) {
                if ($RegBase) {
                    $RegBase.OpenSubKey($CurrentReg).GetSubKeyNames() |
                        ForEach-Object {
                        if ($Property) {
                            foreach ($CurrentProperty in $Property) {
                                $HashProperty.$CurrentProperty = ($RegBase.OpenSubKey("$CurrentReg$_")).GetValue($CurrentProperty)
                            }
                        }
                        $HashProperty.ComputerName = $Computer
                        $HashProperty.ProgramName = ($DisplayName = ($RegBase.OpenSubKey("$CurrentReg$_")).GetValue('DisplayName'))
                        if ($DisplayName) {
                            if ($DontIgnoreUpdates) {
                                if ($ProgramName) {
                                    New-Object -TypeName PSCustomObject -Property $HashProperty |
                                        Select-Object -Property $SelectProperty | where { $_.ProgramName -like "*$ProgramName*" }
                                } else {
                                    New-Object -TypeName PSCustomObject -Property $HashProperty |
                                        Select-Object -Property $SelectProperty
                                }
                            } else {
                                if ($ProgramName) {
                                    New-Object -TypeName PSCustomObject -Property $HashProperty |
                                        Select-Object -Property $SelectProperty | where { $_.ProgramName -notlike "*Update for Microsoft*" -and $_.ProgramName -notlike "Security Update*" -and $_.ProgramName -like "*$ProgramName*" }
                                } else {
                                    New-Object -TypeName PSCustomObject -Property $HashProperty |
                                        Select-Object -Property $SelectProperty | where { $_.ProgramName -notlike "*Update for Microsoft*" -and $_.ProgramName -notlike "Security Update*" }
                                }
                            }
                        }
                    }
                }
            }
        } -argumentList $property, $dontIgnoreUpdates, $programName
    }

    END {
        if ($ogv) {
            $result | Out-GridView -PassThru -Title "Nainstalovany SW"
        } else {
            $result
        }
    }
}