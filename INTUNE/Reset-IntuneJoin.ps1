function Reset-IntuneJoin {
    <#
    .SYNOPSIS
    Function for resetting device Intune management connection.

    .DESCRIPTION
    Function for resetting device Intune management connection.

    It will:
     - check actual Intune status on device
     - reset Hybrid AzureAD join
     - remove device records from Intune
     - remove Intune connection data and invoke re-enrollment

    .PARAMETER computerName
    (optional) Name of the computer.

    .EXAMPLE
    Reset-IntuneJoin

    .NOTES
    # How MDM (Intune) enrollment works https://techcommunity.microsoft.com/t5/intune-customer-success/support-tip-understanding-auto-enrollment-in-a-co-managed/ba-p/834780
    #>

    [CmdletBinding()]
    param (
        [string] $computerName = $env:COMPUTERNAME
    )

    $ErrorActionPreference = "Stop"

    Write-Host "Checking actual Intune connection status" -ForegroundColor Cyan
    if (Get-IntuneJoinStatus -computerName $computerName) {
        $choice = ""
        while ($choice -notmatch "^[Y|N]$") {
            $choice = Read-Host "It seems device has working Intune connection. Continue? (Y|N)"
        }
        if ($choice -eq "N") {
            break
        }
    }

    Write-Host "Resetting Hybrid AzureAD connection" -ForegroundColor Cyan
    Reset-HybridADJoin -computerName $computerName

    Write-Host "Waiting" -ForegroundColor Cyan
    Start-Sleep 10

    Write-Host "Removing $computerName records from Intune" -ForegroundColor Cyan
    # to discover cases when device is in Intune named as GUID_date
    if (Get-Command Get-ADComputer -ErrorAction SilentlyContinue) {
        $ADObj = Get-ADComputer -Filter "Name -eq '$computerName'" -Properties Name, ObjectGUID
    } else {
        Write-Verbose "AD module is missing, unable to obtain computer GUID"
    }

    #region get Intune data
    Connect-Graph

    $IntuneObj = @()

    $IntuneObj += Get-IntuneManagedDevice -Filter "DeviceName eq '$computerName'"

    if ($ADObj.ObjectGUID) {
        # because of bug? computer can be listed under guid_date name in cloud
        $IntuneObj += Get-IntuneManagedDevice -Filter "azureADDeviceId eq '$($ADObj.ObjectGUID)'" | ? DeviceName -NE $computerName
    }
    #endregion get Intune data

    #region remove computer record in Intune
    if ($IntuneObj) {
        $IntuneObj | ? { $_ } | % {
            Write-Host "Removing $($_.DeviceName) ($($_.id)) from Intune" -ForegroundColor Cyan
            Remove-IntuneManagedDevice -managedDeviceId $_.id
        }
    } else {
        Write-Host "$computerName nor its guid exists in Intune. Skipping removal." -ForegroundColor DarkCyan
    }
    #endregion remove computer record in Intune

    Write-Host "Invoking re-enrollment of Intune connection" -ForegroundColor Cyan
    Invoke-MDMReenrollment -computerName $computerName

    # check certificates
    $i = 30
    Write-Host "Waiting for Intune certificate creation"  -ForegroundColor Cyan
    Write-Verbose "two certificates should be created in Computer Personal cert. store (issuer: MS-Organization-Access, MS-Organization-P2P-Access [$(Get-Date -Format yyyy)]"
    while (!(Get-ChildItem 'Cert:\LocalMachine\My\' | ? { $_.Issuer -match "CN=Microsoft Intune MDM Device CA" }) -and $i -gt 0) {
        Start-Sleep 1
        --$i
        $i
    }

    if ($i -eq 0) {
        Write-Warning "Intune certificate (issuer: Microsoft Intune MDM Device CA) isn't created (yet?)"

        "Opening Intune logs"
        Get-IntuneLog -computerName $computerName
    } else {
        Write-Host "DONE :)" -ForegroundColor Green
    }
}