

#Requires -Module ActiveDirectory
function Get-ClientStatusReport {
    <#
    .SYNOPSIS
    Function will gather client information from AD, Intune, AAD and SCCM. Merge them together and output problems if any.

    .DESCRIPTION
    Function will gather client information from AD, Intune, AAD and SCCM. Merge them together and output problems if any.

    .PARAMETER computer
    Computer(s) you want to get data about.
    Use AD computer(s) object with name, sid and ObjectGUID properties OR just list of computer names.

    By default retrieve all enabled AD clients that have contacted AD in last activeBeforeThreshold days.

    .PARAMETER combineDataFrom
    List of services you want to gather clients data from.

    By default all of them are selected ('Intune', 'SCCM', 'AAD', 'AD').

    .PARAMETER graphCredential
    AppID and AppSecret for Azure App registration that has permissions needed to read Azure and Intune clients data.

    .PARAMETER sccmAdminServiceCredential
    Credentials for SCCM Admin Service API authentication. Needed only if current user doesn't have correct permissions.

    .PARAMETER activeBeforeThreshold
    Clients that contacted AD before this number of days will be ignored.

    Default is 90.

    .PARAMETER SCCMDiscoveryThreshold
    SCCM threshold for discovering AD clients.
    If client didn't contact AD for this number of days, it won't be discovered in SCCM.

    Default is 90.

    .PARAMETER SCCMLastContactThreshold
    When consider SCCM clients as problematic considering the date they have contacted SCCM server for the last time. In number of days.

    Default is 30.

    .PARAMETER intuneLastContactThreshold
    When consider Intune clients as problematic considering the date they have contacted Intune for the last time. In number of days.

    Default is 30.

    .PARAMETER installedOSThreshold
    To be able to ignore freshly installed clients. In number of days.
    If client install date is before entered number of days, it will be ignored.

    .EXAMPLE
    Get-ClientStatusReport -graphCredential (Get-Credential) -sccmAdminServiceCredential (Get-Credential)
    #>

    [CmdletBinding()]
    param (
        $computer,

        [string[]] $combineDataFrom = ('Intune', 'SCCM', 'AAD', 'AD'),

        # used application credentials expire periodically i.e. needs to be renewed from time to time!
        [System.Management.Automation.PSCredential] $graphCredential,

        [System.Management.Automation.PSCredential] $sccmAdminServiceCredential,

        [int] $activeBeforeThreshold = 90,

        [int] $SCCMDiscoveryThreshold = 90,

        [int] $SCCMLastContactThreshold = 30,

        [int] $intuneLastContactThreshold = 30,

        [int] $installedOSThreshold
    )

    $ErrorActionPreference = "Stop"

    if (!$computer) {
        # unable to use in param block because of missing activeBeforeThreshold
        $computer = (Get-ADComputer -Filter "enabled -eq 'True'" -Properties sid, ObjectGUID, description, LastLogonDate | ? { $_.LastLogonDate -ge [datetime]::Today.AddDays(-$activeBeforeThreshold) })
    }

    Write-Host "`n`n#####################################################################################" -BackgroundColor DarkGreen
    Write-Host "# Enabled AD computers that contacted domain in last $activeBeforeThreshold days are checked #" -BackgroundColor DarkGreen
    Write-Host "#####################################################################################`n" -BackgroundColor DarkGreen

    # get clients data
    $param = @{
        combineDataFrom = $combineDataFrom
        computer        = $computer
    }
    if ($graphCredential) {
        $param.graphCredential = $graphCredential
    }
    if ($sccmAdminServiceCredential) {
        $param.sccmAdminServiceCredential = $sccmAdminServiceCredential
    }
    $result = Get-MDMClientData @param | Sort-Object name

    # omit newly installed clients
    if ($installedOSThreshold) {
        $deviceCount = $result.count
        $result = $result | ? { $_.SCCM_OSInstallDate -lt [datetime]::Today.AddDays(-$installedOSThreshold) }
        $device2Count = $result.count
        if ($deviceCount -ne $device2Count) {
            Write-Warning "$($deviceCount - $device2Count) clients were omitted because OS was installed in last $installedOSThreshold days"
        }
    }

    #region summarize problems
    # AAD
    $notInAAD = $result | ? { !$_.AAD_InDatabase }

    # SCCM
    $notInSCCM = $result | ? { !$_.SCCM_InDatabase }
    $withoutSCCMClient = $result | ? { $_.SCCM_InDatabase -and !$_.SCCM_ClientInstalled }
    $SCCMClientProblem = $result | ? { $_.name -notin $withoutSCCMClient.name -and (!$_.SCCM_ClientCheckPass -or $_.SCCM_ClientCheckPass -eq "Failed") }

    # Intune
    $notInIntune = $result | ? { !$_.INTUNE_InDatabase }
    # some SCCM clients shows that device is NOT co-managed, but Intune says otherwise
    $notManagedByIntune = $result | ? { $_.SCCM_CoManaged -eq $false -and ($_.name -notin $notInIntune.name) -and !($_.INTUNE_InDatabase -and $_.INTUNE_CoManaged -eq $true) }
    # sometimes device is added to Intune (mostly with GUID instead of device name) but never contacts the Intune itself
    $intuneInactive = $result | ? { $_.INTUNE_InDatabase -and $_.INTUNE_LastSyncDateTime -and ($_.INTUNE_LastSyncDateTime -lt (Get-Date 1888)) }

    # Other
    $tooLongWithoutContactSCCM = $result | ? { ($_.name -notin $notInSCCM.name -and $_.name -notin $withoutSCCMClient.name) -and (!$_.SCCM_LastActiveTime -or ((Get-Date $_.SCCM_LastActiveTime) -lt [datetime]::Today.AddDays(-$SCCMLastContactThreshold))) }
    $tooLongWithoutContactIntune = $result | ? { $_.name -notin $notInIntune.name -and (!$_.INTUNE_lastSyncDateTime -or ((Get-Date $_.INTUNE_LastSyncDateTime) -lt [datetime]::Today.AddDays(-$intuneLastContactThreshold))) }
    # name of the device in cloud is different than in AD
    $GUIDInsteadOfNameAAD = $result | ? { $_.AAD_InDatabase -and $_.Name -ne $_.AAD_Name }
    $GUIDInsteadOfNameIntune = $result | ? { $_.INTUNE_InDatabase -and $_.Name -ne $_.INTUNE_Name }
    $wrongName = @($GUIDInsteadOfNameAAD) + @($GUIDInsteadOfNameIntune)
    # SCCM and Intune are in conflict whether client is co-managed
    $coManagedConflictData = $result | ? { ($_.INTUNE_CoManaged -and (!$_.SCCM_CoManaged -and $_.SCCM_InDatabase -and $_.SCCM_ClientInstalled)) -or ($_.SCCM_CoManaged -and !$_.INTUNE_CoManaged) }


    $SCCMMultipleRecords = $result | ? { $_.SCCM_MultipleRecords }

    $notValidHybridJoinCert = $result | ? { !$_.hasValidHybridJoinCert }
    #endregion summarize problems

    #region helper functions
    function _getDeviceExtraInfo {
        # generates string like: (missing from AAD too, missing SCCM client)
        param ($deviceName)

        $extraInfo = @()

        if ($deviceName -in $notValidHybridJoinCert.name) {
            $extraInfo += "no valid Hybrid-Join certificate"
        }

        if ($deviceName -in $GUIDInsteadOfNameIntune.Name) {
            $extraInfo += "in Intune under it's GUID instead of name"
        } elseif ($deviceName -in $GUIDInsteadOfNameAAD.Name) {
            $extraInfo += "in AAD under it's GUID instead of name"
        }

        if ($deviceName -in $notInAAD.name) {
            $extraInfo += "missing from AAD"
        }
        if ($deviceName -in $notInSCCM.name) {
            $extraInfo += "missing from SCCM"
        }
        if ($deviceName -in $withoutSCCMClient.name) {
            $extraInfo += "missing SCCM client"
        }
        if ($deviceName -in $SCCMClientProblem.name) {
            $extraInfo += "SCCM client has issues"
        }

        if ($extraInfo) { return " (" + ($extraInfo -join ', ') + ")" }
    }
    #endregion helper functions

    #region output results
    ""

    #region devices not managed by SCCM
    if ($notInSCCM -or $withoutSCCMClient -or $SCCMClientProblem) {
        Write-Host "`n`n##### Following devices are NOT managed by SCCM`n" -BackgroundColor DarkRed

        if ($notInSCCM) {
            Write-Host "Devices not existing in SCCM database:" -ForegroundColor Red
            if ($SCCMDiscoveryThreshold) {
                $notInSCCM | % {
                    $passwordLastSet = $_.AD_PasswordLastSet
                    if ($passwordLastSet -lt [datetime]::Today.AddDays(-$SCCMDiscoveryThreshold)) {
                        Write-Warning "$($_.name) hasn't connected to AD for more than $SCCMDiscoveryThreshold days i.e. SCCM discovery ignores it"
                    }
                }
            }

            $notInSCCM.name
        }

        if ($withoutSCCMClient) {
            Write-Host "Devices in SCCM database but without SCCM client (or marked as not having client because client haven't contacted SCCM server for a long time):" -ForegroundColor Red
            $withoutSCCMClient.name
        }

        if ($SCCMClientProblem) {
            Write-Host "`n`n##### Following devices MAY NOT be managed by SCCM`n" -BackgroundColor Red
            Write-Host "Devices with SCCM client problem:" -ForegroundColor Red
            $SCCMClientProblem.name
        }

        Write-Host "################################################################################" -BackgroundColor DarkRed
        Write-Host ""
    }
    #endregion devices not managed by SCCM

    #region not managed by Intune
    if ($notInIntune -or $notManagedByIntune -or $intuneInactive) {
        Write-Host "`n`n##### Following devices are NOT managed by Intune`n" -BackgroundColor DarkRed
        if ($notInIntune) {
            Write-Host "`nDevice missing from Intune:" -ForegroundColor Red

            $notInIntune | % {
                $deviceName = $_.name
                $deviceName + (_getDeviceExtraInfo $deviceName)
            }
        }

        if ($notManagedByIntune) {
            Write-Host "`nDevice(s) that are not Co-Managed:" -ForegroundColor Red
            $notManagedByIntune.name
        }

        if ($intuneInactive) {
            Write-Host "`nDevice(s) that've never contacted Intune:" -ForegroundColor Red
            $intuneInactive | % {
                $deviceName = $_.name
                $deviceName + (_getDeviceExtraInfo $deviceName)
            }
        }

        Write-Host "################################################################################" -BackgroundColor DarkRed
        Write-Host ""
    }
    #endregion not managed by Intune

    #region other problems
    if ($notInAAD -or $wrongName -or $tooLongWithoutContactSCCM -or $tooLongWithoutContactIntune -or $SCCMMultipleRecords -or $coManagedConflictData) {
        Write-Host "`n`n##### Other problems`n" -BackgroundColor Magenta
        # omit computers that were already pointed out in Intune problems section
        $notInAAD = $notInAAD | ? { $_.name -notin $notInIntune.name }
        if ($notInAAD) {
            Write-Host "`nNon-Intune devices missing from AAD:" -ForegroundColor Red
            $notInAAD.name
        }

        if ($wrongName) {
            Write-Host "`nDevices where cloud name differs from AD name:" -ForegroundColor Red
            $wrongName | % {
                $cloudName = $_.INTUNE_Name
                if (!$cloudName) {
                    $cloudName = $_.AAD_Name
                }
                "$($_.Name) ($cloudName)"
            }
        }

        if ($coManagedConflictData) {
            Write-Host "`nDevices where SCCM and Intune don't agree whether this device is co-managed:" -ForegroundColor Red
            $coManagedConflictData | % {
                "$($_.Name) (SCCM: $($_.SCCM_CoManaged) Intune: $($_.INTUNE_CoManaged))"
            }
        }


        if ($tooLongWithoutContactSCCM) {
            Write-Host "`nDevices that haven't contacted SCCM for last $SCCMLastContactThreshold days:" -ForegroundColor Red
            $tooLongWithoutContactSCCM.name
        }

        if ($tooLongWithoutContactIntune) {
            Write-Host "`nDevices that haven't contacted Intune for last $intuneLastContactThreshold days:" -ForegroundColor Red
            $tooLongWithoutContactIntune.name
        }

        if ($SCCMMultipleRecords) {
            Write-Host "`nDevices that are more than once in SCCM database:" -ForegroundColor Red
            $SCCMMultipleRecords.name
        }

        Write-Host "################################################################################" -BackgroundColor Magenta
        Write-Host ""
    }
    #endregion other problems
    #endregion output results
}