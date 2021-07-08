function Set-CMDeviceDJoinBlobVariable {
    <#
    .SYNOPSIS
    Function for enabling Offline Domain Join in OSD process of given computer.

    .DESCRIPTION
    Function for enabling Offline Domain Join in OSD process of given computer.

    It will:
     - create Offline Domain Join blob using djoin.exe
     - save resultant blob content as computer variable DJoinBlob
        - so it can be used during OSD for domain join

    When the computer connects eventually to one of the DCs. It will automatically reset its password. So generated djoin blob will be invalidated (it contains password, that is being set, when computer joins the domain).

    .PARAMETER computerName
    Name of the computer, that should be joined to domain during the OSD.

    It doesn't matter, what name it actually has, it will be changed, to this one!

    .PARAMETER ou
    OU where should be computer placed (in case it doesn't already exists in AD).

    .PARAMETER reuse
    Switch that has to be used in case, such computer already exists in AD.

    Its password will be immediately reset!!!

    .PARAMETER domainName
    Name of domain.

    .EXAMPLE
    Set-CMDeviceDJoinBlobVariable -computerName PC-1 -reuse

    Function will generate offline domain join blob for joining computer PC-1.
    This blob will be saved as Task Sequence Variable in properties of given computer.
    In case computer already exists in AD, its password will be immediately reset.

    .NOTES
    # jak dat do unattend souboru https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/dd392267(v=ws.10)?redirectedfrom=MSDN#offline-domain-join-process-and-djoinexe-syntax
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string] $computerName,

        [ValidateScript( {
                If (!(Get-ADOrganizationalUnit -Filter "distinguishedname -eq '$_'")) {
                    $true
                } else {
                    Throw "$_ is not a valid OU distinguishedName."
                }
            })]
        [string] $ou,

        [switch] $reuse,

        [string] $domainName = $domainName
    )

    process {
        #region checks
        if ($reuse) {
            Write-Warning "Reuse parameter will immediately reset $computerName AD password!"
            $choice = ""
            while ($choice -notmatch "^[Y|N]$") {
                $choice = Read-Host "Continue? (Y|N)"
            }
            if ($choice -eq "N") {
                break
            }
        }

        if (!(Get-ADComputer -Filter "name -eq '$computerName'") -and !$ou) {
            do {
                $ou = Read-Host "Computer $computerName doesn't exist. Enter existing OU distinguishedName, where it should be created"
            } while (!(Get-ADOrganizationalUnit -Filter "distinguishedname -eq '$ou'"))
        }

        if ((Get-ADComputer -Filter "name -eq '$computerName'") -and !$reuse) {
            throw "$computerName already exists in AD so 'reuse' parameter has to be used!"
        }

        Connect-SCCM -commandName Get-CMDeviceVariable, Set-CMDeviceVariable, New-CMDeviceVariable, Get-CMDevice

        $device = Get-CMDevice -Name $computerName
        if (!$device) { throw "$computerName isn't in SCCM database" }
        if ($device.count -gt 1) { throw "There are $($device.count) devices in SCCM database with name $computerName" }
        #endregion checks


        #region create djoin connection blob
        "Creating djoin connection blob"
        $blobFile = (Get-Random)
        # /reuse provede reset computer hesla!
        # /rootcacerts /certtemplate "WorkstationAuthentication-PrimaryTPM"
        if ($reuse) {
            $djoin = djoin.exe /provision /domain $domainName /machine $computerName /savefile $blobFile /printblob /reuse
        } else {
            $djoin = djoin.exe /provision /domain $domainName /machine $computerName /savefile $blobFile /printblob
        }

        if (!($djoin -match "The operation completed successfully")) {
            throw $djoin
        }

        # I don't need this file
        Remove-Item $blobFile -Force

        # Get the blob
        $djoinBlob = $djoin[12]
        #endregion create djoin connection blob

        #region customize SCCM Device DJoinBlob TS Variable
        # variable name that should contain djoin blob for offline domain join
        $variableName = "DJoinBlob"

        "Setting variable '$variableName' for SCCM device $computerName"

        # !Get-CMDeviceVariable is case insensitive, but Set-CMDeviceVariable isn't! therefore I use existing name, just in case
        if ($foundVariableName = Get-CMDeviceVariable -DeviceName $computerName -VariableName $variableName | select -ExpandProperty Name) {
            # variable already exists, modify
            $variableName = $foundVariableName
            Set-CMDeviceVariable -DeviceName $computerName -VariableName $variableName -NewVariableValue $djoinBlob -IsMask $true
        } else {
            # variable doesn't exist, create
            New-CMDeviceVariable -DeviceName $computerName -VariableName $variableName -VariableValue $djoinBlob -IsMask $true | Out-Null
        }
        #endregion customize SCCM Device DJoinBlob TS Variable
    }

    end {
        Write-Warning "You can use this blob to join any computer, but $computerName will be new computer name, no matter what name computer already has"
    }
}