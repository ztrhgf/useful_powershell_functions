function New-VMFromTemplate {
    <#
    .SYNOPSIS
    Function for creation of VM from existing VM template through SCVMM and Hyper-V cluster.

    .DESCRIPTION
    Function for creation of VM from existing VM template through SCVMM and Hyper-V cluster.

    .PARAMETER VMName
    Name of created VM.

    .PARAMETER ManagedBy
    Who will be manager of the VM (set on VM AD object).

    .PARAMETER VMTemplateName
    Name of VM template to use.
    GUI will popup if not specified.

    .PARAMETER DestinationOU
    OU where AD computer object will be placed.

    Example: "OU=Tier_2,OU=Servers,OU=Computer_Accounts,DC=contoso,DC=com".

    .PARAMETER Description
    AD computer object description.

    .PARAMETER OperatingSystemName
    Operating system name.
    GUI will popup if not specified.

    .PARAMETER GuestOsProfileName
    Guest OS profile.
    GUI will popup if not specified.

    .PARAMETER ClusterName
    Name of cluster where VM wil be created.
    GUI will popup if not specified.

    .PARAMETER VMHostName
    Name of the cluster node, where will be VM hosted.
    If empty, one of the cluster nodes will be picked randomly.

    .PARAMETER VMAdminPass
    Credential object thats password will be used for built-in VM Administrator account.

    .PARAMETER JoinWorkgroup
    Switch that forces VM to join WORKGROUP (no matter what is set in used template)

    .PARAMETER NoNetwork
    Switch for removing all NIC adapters from VM, i.e. there will be no network connection available.

    Good for security reasons in case you test something on VM etc.

    .PARAMETER CPUCount
    Optional. Count of CPUs that will be assigned to VM.
    If not specified, count from used Hardware profile will be used.

    .PARAMETER MemoryMB
    Optional. RAM size in MB that will be assigned to VM.
    If not specified, size from usedHardware profile will be used.

    .PARAMETER OSDiskSize
    Optional. OS disk size in GB. Volume itself has to be manually expanded in OS itself!
    If not specified, disk size specified in template will be used.

    .PARAMETER VMNetworkName
    Name of the network, your VM should be connected to.
    GUI will popup if not specified.

    .PARAMETER PortClassification
    Name of the SCVMM port classification, that should be set on VM network card.
    GUI will popup if not specified.

    .PARAMETER VMLocation
    Path to share folder, where VM disk will be saved. SOFS etc.

    .PARAMETER VMMServerName
    Name of VMM server.

    .PARAMETER asJob
    Switch to run this as a job.

    .EXAMPLE
    New-VMFromTemplate -VMName test -description "just testing"

    Function will asks for any missing information like OS type, Network etc and then:
     - creates such VM on random cluster node
     - set "just testing" as computer AD object description

    .EXAMPLE
    New-VMFromTemplate -VMName test -VMAdminPass $cred -JoinWorkgroup -VMHostName core-01 -NoNetwork

    Function will asks for any missing information and then:
     - on random core-01 cluster node
     - create workgroup joined VM with name test
     - local Administrator account will have password taken from $cred
     - VM won't have any NIC (so no network connectivity)
    #>

    param (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [ValidateScript( {
                if ($_.length -gt 15) { throw "VMName length can be max. 15 chars. (is $($_.length))" }
                return $true
            })]
        [string] $VMName
        ,
        # [ValidateScript( {
        #         $adObj = Get-ADObject -Filter "samaccountname -eq `"$_`" -and (objectclass -eq `"user`" -or objectclass -eq `"group`")"
        #         if ($adObj.objectclass -eq "User") {
        #             $adUser = Get-ADUser $_ -Properties enabled
        #             if ($adUser.enabled -eq $true -and $adUser.distinguishedName -like "*OU=All,OU=User_Accounts,DC=contoso,DC=com") { return $true }
        #         }
        #         if ($adObj.objectclass -eq "Group" -and ($_ -match " RBAC$")) { return $true }
        #         throw "ManagedBy has to be employee or RBAC group"
        #     })]
        [string] $ManagedBy
        ,
        [ArgumentCompleter( {
                param($Command, $Parameter, $WordToComplete, $CommandAst, $FakeBoundParams)
                if ($VMMServerName = $FakeBoundParams.VMMServerName) {
                    $VMMServerObj = Get-SCVMMServer -ComputerName $VMMServerName
                    Get-SCVMTemplate -VMMServer $VMMServerObj | ? { $_.name -like "*$WordToComplete*" }
                }
            })]
        [string] $VMTemplateName
        ,
        [ValidateScript( { [adsi]::Exists("LDAP://$_") })]
        [string] $DestinationOU
        ,
        [string] $Description
        ,
        [string] $OperatingSystemName
        ,
        [string] $GuestOSProfileName
        ,
        [ValidateNotNullOrEmpty()]
        [string] $ClusterName
        ,
        [ArgumentCompleter( {
                param ($Command, $Parameter, $WordToComplete, $CommandAst, $FakeBoundParams)

                Get-SCVMHost | select -exp ComputerName | ? { $_ -like "*$WordToComplete*" }
            })]
        [string] $VMHostName
        ,
        [ValidateNotNullOrEmpty()]
        [pscredential] $VMAdminPass
        ,
        [switch] $JoinWorkgroup
        ,
        [switch] $NoNetwork
        ,
        [int] $CPUCount
        ,
        [int] $MemoryMB
        ,
        [int] $OSDiskSize
        ,
        [string] $VMNetworkName
        ,
        [string] $PortClassification
        ,
        [Parameter(Mandatory = $true)]
        [ValidateScript( {
                If (Test-Path -Path $_ -IsValid) {
                    $true
                } else {
                    Throw "$_ is not a valid path"
                }
            })]
        [string] $VMLocation = "\\SOMESHARE.contoso.com\whereVMshouldBeStored"
        ,
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string] $VMMServerName = "nameOfYourSCVMMServer"
        ,
        [switch] $asJob
    )

    $ErrorActionPreference = "stop"

    if ($ManagedBy -and $JoinWorkgroup) {
        Write-Warning "VM will be joined to workgroup, ManagedBy won't be used."
    }

    try {
        Import-Module VirtualMachineManager -ErrorAction Stop
    } catch {
        throw "Cannot import VirtualMachineManager module. Do you have VMM console installed?"
    }

    try {
        Import-Module FailoverClusters -ErrorAction Stop
    } catch {
        throw "Cannot import FailoverClusters module. Do you have FCM console installed?"
    }

    try {
        $VMMServerObj = Get-SCVMMServer -ComputerName $VMMServerName
    } catch {
        throw "Can't connect to the VMM server $VMServerName. Exiting..."
    }

    while (!$ClusterName) {
        $ClusterName = Get-Cluster -Domain $env:USERDNSDOMAIN -ErrorAction Stop | Select-Object -ExpandProperty Name | Sort-Object | Out-GridView -Title "Select Cluster to deploy your VM" -OutputMode Single
    }

    if (!$VMHostName) {
        Try {
            Get-Cluster $ClusterName | Out-Null
        } catch {
            throw "Can't connect to the cluster $ClusterName. Exiting..."
        }

        # pick random node from given cluster
        $VMHostName = Get-ClusterNode -Cluster $ClusterName | select -exp Name | Get-Random -Count 1
    }

    if ($VMObj = Get-SCVirtualMachine -Name $VMName) {
        Write-Warning "VM '$VMName' already exists."
        $choice = ""
        while ($choice -notmatch "^[Y|N]$") {
            $choice = Read-Host "Remove and create the new one? (Y|N)"
        }
        if ($choice -eq "N") {
            break
        }

        # remove existing VM
        $VMObj | % {
            Remove-SCVirtualMachine -VM $_ -Force -ErrorAction Stop | Out-Null
        }
    }

    #region ask for input
    while (!$VMTemplateName) {
        $VMTemplateName = Get-SCVMTemplate -VMMServer $VMMServerObj | Select-Object -ExpandProperty Name | Sort-Object | Out-GridView -Title "Select VM Template to deploy" -OutputMode Single
    }
    while (!$OperatingSystemName) {
        $OperatingSystemName = Get-SCOperatingSystem -VMMServer $VMMServerObj | Select-Object -ExpandProperty Name | Sort-Object | Out-GridView -Title "Select OS to deploy" -OutputMode Single
    }
    while (!$GuestOSProfileName) {
        $GuestOSProfileName = Get-SCGuestOSProfile -VMMServer $VMMServerObj | Select-Object -ExpandProperty Name | Sort-Object | Out-GridView -Title "Select Guest OS to deploy" -OutputMode Single
    }
    if (!$NoNetwork) {
        while (!$VMNetworkName) {
            $VMNetworkName = Get-SCVMNetwork -VMMServer $VMMServerObj | Select-Object -ExpandProperty Name | Sort-Object | Out-GridView -Title "Select one network for your VM to connect" -OutputMode Single
        }
        while (!$PortClassification) {
            $PortClassification = Get-SCPortClassification -VMMServer $VMMServerObj | Select-Object -ExpandProperty Name | Sort-Object | Out-GridView -Title "Select one port classification for your VM network card" -OutputMode Single
        }
    }
    #endregion ask for input

    #region checks
    if (!($t = Get-SCVMTemplate -VMMServer $VMMServerObj | ? { $_.name -eq $VMTemplateName })) {
        throw "VM template '$VMTemplateName' doesn't exist."
    }

    if (!($t = Get-SCOperatingSystem -VMMServer $VMMServerObj | ? { $_.Name -eq $OperatingSystemName })) {
        throw "VM Operating System '$OperatingSystemName' doesn't exist."
    }

    if (!$JoinWorkgroup) {
        if ($NoNetwork) {
            Write-Warning "VM $VMName should be joined to domain, but will be without network connectivity.`nSo following steps will be skipped:`n - create AD computer object`n - move object to destination OU`n - set managedBy`n - (restart of VM)"

            $choice = ""
            while ($choice -notmatch "^[Y|N]$") {
                $choice = Read-Host "Continue? (Y|N)"
            }
            if ($choice -eq "N") {
                break
            }
        }
    }
    #endregion checks

    # scriptblock to run
    $scriptblock = {
        param (
            $VMName,
            $VMAdminPass,
            $JoinWorkgroup,
            $NoNetwork,
            $CPUCount,
            $MemoryMB,
            $OSDiskSize,
            $VMMServerName,
            $VMTemplateName,
            $VMHostName,
            $VMLocation,
            $DestinationOU,
            $Description,
            $OperatingSystemName,
            $GuestOSProfileName,
            $managedBy,
            $VMNetworkName,
            $PortClassification
        )

        $VMMServerObj = Get-SCVMMServer -ComputerName $VMMServerName
        $VMHostObj = Get-SCVMHost -VMMServer $VMMServerObj -ComputerName $VMHostName

        $VMTemplateObj = Get-SCVMTemplate -VMMServer $VMMServerObj -Name $VMTemplateName
        $OperatingSystemObj = Get-SCOperatingSystem -VMMServer $VMMServerObj | ? { $_.Name -eq $OperatingSystemName }
        $GuestOsProfileObj = Get-SCGuestOSProfile -VMMServer $VMMServerObj -Name $GuestOsProfileName

        try {
            # to be able to customize VM template, create temporary one
            $RandomGUID = [guid]::NewGuid().guid
            $TemporaryName = "Tmp" + "-" + $VMName + "-" + $RandomGUID

            if (!$NoNetwork) {
                # VM should be connected to some network

                $VMNetwork = Get-SCVMNetwork -VMMServer $VMMServerObj -Name $VMNetworkName
                $VMSubnet = Get-SCVMSubnet -VMMServer $VMMServerObj -VMNetwork $VMNetwork
                if ($VMSubnet.count -gt 1) {
                    $VMSubnet = $VMSubnet | select -First 1
                }

                $PortClassification = Get-SCPortClassification -VMMServer $VMMServerObj | ? { $_.Name -eq $PortClassification }

                New-SCVirtualNetworkAdapter -VMMServer $VMMServerObj -JobGroup $RandomGUID -MACAddress "00:00:00:00:00:00" -MACAddressType Static -Synthetic -IPv4AddressType Static -IPv6AddressType Dynamic -VMSubnet $VMSubnet -VMNetwork $VMNetwork -PortClassification $PortClassification -DevicePropertiesAdapterNameMode Disabled
            }

            New-SCVirtualScsiAdapter -VMMServer $VMMServerObj -JobGroup $RandomGUID -AdapterID 7 -ShareVirtualScsiAdapter $false -ScsiControllerType DefaultTypeNoType

            if (!$CPUCount) {
                $CPUCount = $VMTemplateObj.CPUCount
            }
            if (!$MemoryMB) {
                $MemoryMB = $VMTemplateObj.Memory
            }

            # create new temporary HW profile
            $TemporaryHWTemplate = New-SCHardwareProfile -VMMServer $VMMServerObj -Name $TemporaryName -Description "Profile used to create a VM $VMName" -CPUCount $CPUCount -MemoryMB $MemoryMB -DynamicMemoryEnabled $false -CPUExpectedUtilizationPercent 20 -CPUMaximumPercent 100 -CPUReserve 0 -NumaIsolationRequired $false -NetworkUtilizationMbps 0 -CPURelativeWeight 100 -HighlyAvailable $true -HAVMPriority 2000 -DRProtectionRequired $false -SecureBootEnabled $true -SecureBootTemplate "MicrosoftWindows" -CPULimitFunctionality $false -CPULimitForMigration $false -CheckpointType Production -Generation 2 -JobGroup $RandomGUID

            $templateParams = @{
                Name            = $TemporaryName
                Template        = $VMTemplateObj
                GuestOSProfile  = $GuestOsProfileObj
                OperatingSystem = $OperatingSystemObj
                HardwareProfile = $TemporaryHWTemplate
                JobGroup        = $RandomGUID
            }
            if ($JoinWorkgroup) { $templateParams.workgroup = "WORKGROUP" }
            # create new temporary VM template
            $TemporaryTemplate = New-SCVMTemplate @templateParams

            if ($NoNetwork) {
                "Removing NIC adapters"
                Get-SCVirtualNetworkAdapter -VMTemplate $TemporaryName | Remove-SCVirtualNetworkAdapter -Confirm:$false | Out-Null
            }

            $TemporaryVMConfiguration = New-SCVMConfiguration -VMTemplate $TemporaryTemplate -Name $TemporaryName
            $null = Set-SCVMConfiguration -VMConfiguration $TemporaryVMConfiguration -ComputerName $VMName -VMHost $VMHostObj -VMLocation $VMLocation -PinVMLocation $true
            $null = Update-SCVMConfiguration -VMConfiguration $TemporaryVMConfiguration

            # create VM
            $vmParams = @{
                Name            = $VMName
                VMConfiguration = $TemporaryVMConfiguration
                StartVM         = $true
                StartAction     = "NeverAutoTurnOnVM"
                StopAction      = "ShutdownGuestOS"
            }
            if ($VMAdminPass) { $vmParams.LocalAdministratorCredential = $VMAdminPass }
            if ($JoinWorkgroup) { $vmParams.workgroup = "WORKGROUP" }
            if ($CPUCount) { $vmParams.CPUCount = $CPUCount }
            if ($MemoryMB) { $vmParams.MemoryMB = $MemoryMB }

            "Creating VM $VMName   (for cancellation, STOP the job in SCVMM\Jobs console)"
            $NewVMObj = New-SCVirtualMachine @vmParams

            $retries = 3
            while ($NewVMObj.MostRecentTask.Status -ne "Completed") {
                Write-Host "Creation failed ($($NewVMObj.MostRecentTask.Status)). For more information check SCVMM\Jobs console" -ForegroundColor Red
                $NewVMObj = Get-SCVirtualMachine -Name $VMName
                Stop-SCVirtualMachine -VM $NewVMObj -Force -ErrorAction SilentlyContinue | Out-Null
                Remove-SCVirtualMachine -VM $NewVMObj -ErrorAction SilentlyContinue | Out-Null
                if (Get-SCVirtualMachine -Name $VMName) {
                    Start-Sleep -Seconds 15
                    Remove-SCVirtualMachine -Name $VMName -Force -ErrorAction Stop | Out-Null
                }
                if ($retries -eq 0) { throw "Creation of VM $VMName failed several times. Exiting" }

                --$retries
                $message = "Recreating    ($retries more retries)"
                $message
                # Show-Notification "Creation of virtual machine $VMName failed.`n$message" -type Error

                $NewVMObj = New-SCVirtualMachine @vmParams
            }

            if ($OSDiskSize) {
                $OSDisk = Get-SCVirtualDiskDrive -VM $NewVMObj | ? { $_.VolumeType -eq "BootAndSystem" }
                if ($OSDisk) {
                    Write-Warning "OS disk is expanded to $OSDiskSize. Expand the volume also in diskmgmt.msc console in running VM!"
                    Expand-SCVirtualDiskDrive -VirtualDiskDrive $OSDisk -VirtualHardDiskSizeGB $OSDiskSize | Out-Null
                } else {
                    Write-Warning "OS disk wasn't found, so expanding was skipped!"
                }
            }

            Start-SCVirtualMachine $NewVMObj | Out-Null
        } catch {
            # Show-Notification "Creation of virtual machine $VMName failed.`n$_" -type Error
            throw $_
        } finally {
            # cleanup
            try {
                $null = Remove-SCVMConfiguration -VMConfiguration $TemporaryVMConfiguration
            } catch {}
            try {
                $null = Remove-SCVMTemplate $TemporaryName
            } catch {}
            try {
                $null = Remove-SCHardwareProfile $TemporaryHWTemplate
            } catch {}
        }

        # set AD properties
        if (!$JoinWorkgroup) {
            if (!$NoNetwork) {
                "Setting AD properties"
                $ADComputerObj = Get-ADComputer -Identity $VMName
                Set-ADComputer -Identity $ADComputerObj -ManagedBy $managedBy
                if ($Description) {
                    Set-ADComputer -Identity $ADComputerObj -Description $Description
                } else {
                    Write-Warning "Consider setting Description attribute on AD object"
                }

                if (Get-Command Reset-AdmPwdPassword -ea SilentlyContinue) {
                    "Resetting LAPS password"
                    $null = Reset-AdmPwdPassword $VMName
                }

                Move-ADObject -Identity $ADComputerObj.ObjectGUID -TargetPath $DestinationOU
            }

            # Show-Notification "Creation of virtual machine $VMName finished"
        }
    } # end of scriptblock

    $params = @{
        scriptBlock  = $scriptblock
        argumentList = (
            $VMName,
            $VMAdminPass,
            $JoinWorkgroup,
            $NoNetwork,
            $CPUCount,
            $MemoryMB,
            $OSDiskSize,
            $VMMServerName,
            $VMTemplateName,
            $VMHostName,
            $VMLocation,
            $DestinationOU,
            $Description,
            $OperatingSystemName,
            $GuestOSProfileName,
            $managedBy,
            $VMNetworkName,
            $PortClassification
        )
    }

    # start creation of VM
    if ($asJob) {
        # as job
        $params.name = $VMName
        Start-Job @params
    } else {
        # interactively
        Invoke-Command @params
    }
}