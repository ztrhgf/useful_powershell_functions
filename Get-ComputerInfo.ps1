<#
TODO:
dodelat propertyset pro snadne filtrovani informaci
#>
Function Get-ComputerInfo {
    <#
    .SYNOPSIS
    Fce pro získání základních informací o stroji.

    .DESCRIPTION
    Fce využívá WMI pro získání informací o HW (NIC, CPU, MB, BIOS, RAM, HDD,...), ale i OS (kdo je přihlášen, kdy byl OS nainstalován, verze, sdílené složky, uživatelé, administrátoři, tiskárny,...). Informace je možné získat i z remote strojů. Výpis do OGV nezobrazí všechny informace!

    .PARAMETER COMPUTERNAME
    Parametr udávající seznam strojů, pro získání informací.

    .PARAMETER DETAILED
    Switch určující množství vypsaných informací.

    .EXAMPLE
    Get-ComputerInfo

    Vypíše informace o tomto stroji.

    .EXAMPLE
    Get-ComputerInfo -ComputerName sirene13

    Vypíše informace o stroji sirene13

    .EXAMPLE
    Get-ComputerInfo -ComputerName $b311 -detailed

    Vypíše detailní informace o strojích v B311.

    .EXAMPLE
    Get-ComputerInfo -ComputerName $b311 -detailed | select computername,"OS version","CPU Name","Users"

    Vypíše hostname,verzi OS, jméno CPU a seznam lokálních uživatelů na strojích v B311.

    .EXAMPLE
    Get-ComputerInfo -ComputerName $b311 -detailed | where {$_.users -like "*_naiada10*"} | select computername,"Users"

    Vypíše hostname a seznam lokálních uživatelů na strojích v B311, které mezi uživateli mají účet se jménem _naiada10.

    .NOTES
    Author: Ondřej Šebela - ztrhgf@seznam.cz
    #>

    [CmdletBinding()]
    param (
        [Parameter(Position = 0, ValueFromPipeline = $true)]
        [Alias("CN", "Computer")]
        [ValidateNotNullOrEmpty()]
        [String[]] $computerName = "$env:COMPUTERNAME"
        ,
        [switch] $detailed
        #	,
        #	[ValidateSet("start","unexpected_shutdown","shutdown_or_restart","bsod","wake_up","sleep")]
        #	$Filter = @("start","unexpected_shutdown","shutdown_or_restart","bsod","wake_up","sleep")
    )

    BEGIN {
    }

    PROCESS {
        Invoke-Command2 $ComputerName -ArgumentList $detailed, $win10Version {
            param ($detailed, $win10Version)

            $computer = $env:COMPUTERNAME
            # Vytvoření objektu, do kterého později vložím property definované v hashtable $ht
            $object = New-Object PSObject
            # Vytvoření seřazeného hash table pro ukládání property a jejich hodnot
            $ht = [ordered]@{}

            if (([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
                ++$hasAdminRights
            }


            $ErrorActionPreference = 'SilentlyContinue'

            ### ziskani WMI dat
            $WMI_CPU = Get-WmiObject -Class Win32_Processor
            $WMI_BIOS = Get-WmiObject -Class Win32_BIOS
            $WMI_BASEBOARD = Get-WmiObject -Class Win32_BaseBoard
            $WMI_CS = Get-WmiObject -Class Win32_ComputerSystem
            $WMI_OS = Get-WmiObject -Class Win32_OperatingSystem
            $WMI_PMA = Get-WmiObject -Class win32_PhysicalMemoryArray
            $WMI_PM = Get-WmiObject -Class Win32_PhysicalMemory
            $WMI_HDD = Get-WmiObject -Class Win32_LogicalDisk -Filter "DriveType = '3'"
            $WMI_HDD2 = Get-WmiObject -Class Win32_DiskDrive
            $WMI_PARTITION = Get-WmiObject -Class Win32_DiskPartition
            if ($detailed) {
                # vcetne virtualnich adapteru
                $WMI_NIC = Get-WmiObject -Class Win32_NetworkAdapter | where {$_.PhysicalAdapter -eq $true}
            } else {
                $WMI_NIC = Get-WmiObject -Class Win32_NetworkAdapter | where {$_.PhysicalAdapter -eq $true -and $_.PNPDeviceID -notlike "ROOT\*"}
            }
            $WMI_NAC = Get-WmiObject -Class Win32_NetworkAdapterConfiguration | where {$_.IPEnabled -eq $true -or $_.Caption -like "*Hyper-V*" -or $_.MACAddress}
            $WMI_NICDRIVER = Get-WmiObject -Class win32_pnpsigneddriver -Filter "deviceclass='net'"
            $WMI_GPU = Get-WmiObject -Class Win32_VideoController
            $WMI_PageFile = Get-WmiObject Win32_PageFileusage | Select-Object Name, AllocatedBaseSize, PeakUsage
            if ($detailed) {
                $WMI_MONITOR = Get-WmiObject WmiMonitorID -Namespace root\wmi
                $WMI_DD = Get-WmiObject Win32_DiskDrive
                $WMI_DD2 = Get-WmiObject -namespace root\wmi –class MSStorageDriver_FailurePredictStatus | Select InstanceName, PredictFailure, Reason
                # Write-Progress -ParentId 1 -Activity "Collecting Data: Win32_UserAccount" -Status "Percent Complete: $([int](($n/$d)*100))%" -PercentComplete (($n/$d)*100);$n++
                $WMI_LU = Get-WmiObject -Class Win32_UserAccount -Namespace "root\cimv2" -Filter "LocalAccount='$True'"
                #			Write-Progress -ParentId 1 -Activity "Collecting Data: Win32_Printer" -Status "Percent Complete: $([int](($n/$d)*100))%" -PercentComplete (($n/$d)*100);$n++
                $WMI_PRT = Get-WmiObject -Class Win32_Printer
                #			Write-Progress -ParentId 1 -Activity "Collecting Data: Win32_PrintJob" -Status "Percent Complete: $([int](($n/$d)*100))%" -PercentComplete (($n/$d)*100);$n++
                #$WMI_PJ = Get-WmiObject "Win32_PrintJob"
                #			Write-Progress -ParentId 1 -Activity "Collecting Data: Win32_Share" -Status "Percent Complete: $([int](($n/$d)*100))%" -PercentComplete (($n/$d)*100);$n++
                $WMI_SF = Get-WmiObject -Class Win32_Share
                #$WMI_DRIVERS = Get-WmiObject Win32_PnPSignedDriver | where {$_.driverversion -ne $null} | select DeviceName, DriverVersion | sort devicename
                if ($hasAdminRights) { $WMI_BITLOCKER = Get-WmiObject -namespace root\CIMv2\Security\MicrosoftVolumeEncryption -class Win32_EncryptableVolume }
                $TPM = Get-WMIObject –class Win32_Tpm –Namespace root\cimv2\Security\MicrosoftTpm
            }

            #Write-Progress -ParentId 1 -Activity "Collecting Data: MSFT_DISK" -Status "Percent Complete: $([int](($n/$d)*100))%" -PercentComplete (($n/$d)*100);$n++
            #$WMI_MSFT = Get-WmiObject -Class MSFT_DISK -Namespace ROOT\Microsoft\Windows\Storage -computername $Computer | select FriendlyName,IsBoot

            #region zjisteni zdali je potreba restart
            $WinBuild = $WMI_OS.BuildNumber
            $CBSRebootPend, $RebootPending = $false, $false
            if ([int]$WinBuild -ge 6001) {
                $CBSRebootPend = Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing' | where {$_.pschildname -like 'RebootPending'}
                $OSArchitecture = $WMI_OS.OSArchitecture
            } else {
                $OSArchitecture = "**Unavailable**"
            }

            # Querying Session Manager for both 2K3 & 2K8 for the PendingFileRenameOperations REG_MULTI_SZ to set PendingReboot value.
            $RegValuePFRO = Get-ItemProperty 'HKLM:\system\CurrentControlSet\Control\Session Manager\' | select -exp pendingFileRenameOperations

            # Querying WindowsUpdate\Auto Update for both 2K3 & 2K8 for "RebootRequired"
            $WUAURebootReq = Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update' | where {$_.pschildname -like 'RebootRequired'}

            If ($CBSRebootPend -or $RegValuePFRO -or $WUAURebootReq) {
                $RebootPending = $true
            }


            ### naplneni objektu ziskanymi informacemi
            $ht.add("ComputerName", $computer.ToUpper())
            $ht.add("Domain", $WMI_CS.Domain)
            if ($detailed) {
                if ($BSOD = Get-WinEvent -FilterHashtable @{logname = "system"; providername = "Microsoft-Windows-WER-SystemErrorReporting"; id = "1001"} | select-object -property timecreated) {
                    $ht.add("BSOD Count", $BSOD.count)
                    $ht.add("BSOD Times", $BSOD.timecreated)
                }
            }

            # dostupne jazyky (per user bych musel vytahnout z jeho registru)
            $language = $WMI_OS.MUILanguages -join ", "

            $ht.add("OS Name", $WMI_OS.Caption + " ($language) " + $OSArchitecture)
            if ($detailed) { $ht.add('OS System Drive', $WMI_OS.SystemDrive) }
            if ($detailed) { $ht.add('OS System Device', $WMI_OS.SystemDevice) }

            # 1709, 1603 atp (tvar: rokmesic)
            $4digit_os_version = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion" -Name ReleaseId).ReleaseId

            [version] $detailedOsVersion = [System.Environment]::OSVersion.Version

            # $win10Version pochazi z modulu Computers a obsahuje jmeno a 4 ciselne oznaceni windows 10 verzi
            $human_os_version = "unknown"
            if ($win10Version) {
                try {
                    $human_os_version = $win10Version[$WMI_OS.Version]
                } catch {
                    Write-Warning "`$win10Version neobsahuje pozadovanou verzi Windows 10 ($($WMI_OS.Version)). Doplnte je v modulu Computers"
                }
            } else {
                Write-Warning "Neni naimportovan modul Computers obsahujici potrebnou promennou `$win10Version"
            }

            $ht.add("OS Version", ('{0} ({1} ({2}))' -f $detailedOsVersion.ToString(), $human_os_version, $4digit_os_version))
            if ($detailed) { $ht.add('OS Service Pack', [string]$WMI_OS.ServicePackMajorVersion + '.' + $WMI_OS.ServicePackMinorVersion) }
            if ($detailed) { $ht.add('OS Language', $WMI_OS.OSLanguage) }
            $ht.add('OS Boot Time', $WMI_OS.ConvertToDateTime($WMI_OS.LastBootUpTime))
            $ht.add('OS Install Date', $WMI_OS.ConvertToDateTime($WMI_OS.InstallDate))
            if ($detailed) { $ht.add('PageFile location', $WMI_PageFile.name) }
            $ht.add('PageFile size (MB)', $WMI_PageFile.AllocatedBaseSize)
            if ($detailed) { $ht.add('PageFile peak usage (MB)', $WMI_PageFile.PeakUsage)}
            $ht.add("Computer Hardware Manufacturer", $WMI_CS.Manufacturer)
            $ht.add("Computer Hardware Model", $WMI_CS.Model)
            $ht.add("BaseBoardManufacturer", $WMI_BASEBOARD.Manufacturer)
            $ht.add("BaseBoardName", $WMI_BASEBOARD.Product)
            $ht.add("BaseBoardSN", $WMI_BASEBOARD.SerialNumber)
            $ht.add("BaseBoardStatus", $WMI_BASEBOARD.Status)
            $ht.add("RebootPending", $RebootPending)
            if ($detailed) { $ht.add("RebootPendingKey", $RegValuePFRO) }
            $ht.add("CBSRebootPending", $CBSRebootPend)
            $ht.add("WinUpdRebootPending", $WUAURebootReq)

            # HDD
            if ($WMI_HDD) {
                $WMI_HDD | Select 'DeviceID', 'Size', 'FreeSpace' | Foreach {
                    $ht.add("HDD Volume $($_.DeviceID)", ('' + ($_.FreeSpace / 1GB).ToString('N') + ' GB free of ' + ($_.Size / 1GB).ToString('N') + ' GB'))  # with + ($_.Size/1GB - $_.FreeSpace/1GB).ToString('N') +' GB Used Space'
                }
            }
            # HDD 2
            if ($HDDModel = $WMI_HDD2 | where {$_.InterfaceType -notlike "*USB*"} | select -exp model | sort) {
                # pouzivam v monitor_HW_changes
                $ht.add("HDDs", $HDDModel)
            }

            # BITLOCKER
            if ($Detailed) {
                if ($WMI_BITLOCKER) {
                    $WMI_BITLOCKER | select DriveLetter, IsVolumeInitializedforProtection | ? {$_.DriveLetter} | sort DriveLetter| % {
                        $ht.add("Bitlocker on $($_.DriveLetter)", $_.IsVolumeInitializedforProtection)
                    }
                }
                if (!$hasAdminRights) {
                    Write-Warning "Bez admin prav neni mozne zjistit stav Bitlockeru"
                }
            }

            # ziskani IP adres pro dany stroj dle jeho DNS jmena
            if ($ips = [System.Net.Dns]::GetHostAddresses($computer) | foreach { $_.IPAddressToString} ) {
                $ht.add('IP Address(es) from DNS', ($ips -join ', '))
            } else {
                $ht.add('IP Address from DNS', 'Could not resolve')
            }

            # NIC
            if ($WMI_NIC) {
                $i = 1
                $WMI_NIC | Foreach {
                    $index = $_.Index
                    $name = $_.name
                    $NetAdap = $WMI_NAC | Where-Object {$index -eq $_.Index}
                    $NetAdapDriver = $WMI_NICDRIVER | Where-Object {$_.devicename -eq $name}
                    If ([int]$WMI_OS.BuildNumber -ge 6001) {
                        $PhysAdap = $_.PhysicalAdapter
                        $Speed = "{0:0} Mbit" -f $($_.Speed / 1000000)
                    } Else {
                        $PhysAdap = "**Unavailable**"
                        $Speed = "**Unavailable**"
                    }

                    $ht.add("NIC$i Name", $_.Name)
                    $ht.add("NIC$i FriendlyName", $_.NetConnectionID)
                    if ($detailed) {
                        $ht.add("NIC$i Manufacturer", $_.Manufacturer)
                        $ht.add("NIC$i DriverProviderName", $NetAdapDriver.DriverProviderName)
                        $ht.add("NIC$i DriverVersion", $NetAdapDriver.DriverVersion)
                        $ht.add("NIC$i InfName", $NetAdapDriver.InfName)
                        $ht.add("NIC$i InstallDate", $NetAdapDriver.InstallDate)
                        $ht.add("NIC$i DHCPEnabled", $NetAdap.DHCPEnabled)
                        $ht.add("NIC$i DHCPServer", $NetAdap.DHCPServer)
                    }
                    $ht.add("NIC$i MACAddress", $NetAdap.MACAddress)
                    $ht.add("NIC$i IPAddress", $NetAdap.IPAddress)
                    if ($detailed) {
                        $ht.add("NIC$i IPSubnetMask", $NetAdap.IPSubnet)
                        $ht.add("NIC$i DefaultGateway", $NetAdap.DefaultIPGateway)
                        $ht.add("NIC$i DNSServerOrder", $NetAdap.DNSServerSearchOrder)
                        $ht.add("NIC$i DNSSuffixSearch", $NetAdap.DNSDomainSuffixSearchOrder)
                        $ht.add("NIC$i PhysicalAdapter", $PhysAdap)
                        $ht.add("NIC$i Speed", $Speed)
                    }
                    $i = $i + 1
                }
            }

            # CPU
            if ($WMI_CPU) {
                $ht.add('CPU Physical Processors', @($WMI_CPU).count)
                $i = 1

                $WMI_CPU | Foreach {
                    $ht.add("CPU$i Name", ($_.Name -replace '\s+', ' '))
                    $ht.add("CPU$i Cores", $($_.NumberOfCores))

                    if ($detailed) {
                        $ht.add("CPU$i Logical Processors", $($_.NumberOfLogicalProcessors))
                        $ht.add("CPU$i Clock Speed", "$($_.MaxClockSpeed) MHz")
                        $ht.add("CPU$i Description", $($_.Description))
                        $ht.add("CPU$i Socket", $($_.SocketDesignation))
                        $ht.add("CPU$i Status", $($_.Status))
                        $ht.add("CPU$i Manufacturer", $($_.Manufacturer))
                    }
                    ++$i
                }
            }

            # RAM
            if ($WMI_OS) {
                $WMI_OS | Foreach {
                    $TotalRAM = “{0:N2}” -f ($_.TotalVisibleMemorySize / 1MB)
                    $FreeRAM = “{0:N2}” -f ($_.FreePhysicalMemory / 1MB)
                    $UsedRAM = “{0:N2}” -f ($_.TotalVisibleMemorySize / 1MB - $_.FreePhysicalMemory / 1MB)
                    $RAMPercentFree = “{0:N2}” -f (($FreeRAM / $TotalRAM) * 100)
                    $TotalVirtualMemorySize = “{0:N2}” -f ($_.TotalVirtualMemorySize / 1MB)
                    $FreeVirtualMemory = “{0:N2}” -f ($_.FreeVirtualMemory / 1MB)
                    $FreeSpaceInPagingFiles = “{0:N2}” -f ($_.FreeSpaceInPagingFiles / 1MB)
                }
                $ht.add('RAM Total GB', $TotalRAM)
                $ht.add('RAM Free GB', $FreeRAM)
                $ht.add('RAM Used GB', $UsedRAM)
                $ht.add('RAM Percentage Free', $RAMPercentFree)
                if ($detailed) {
                    $ht.add('RAM TotalVirtualMemorySize', $TotalVirtualMemorySize)
                    $ht.add('RAM FreeVirtualMemory', $FreeVirtualMemory)
                    $ht.add('RAM FreeSpaceInPagingFiles', $FreeSpaceInPagingFiles)
                    $WMI_PMA | ForEach { $RAMSlots += $_.MemoryDevices }
                    $ht.add("RAM Slots", $RAMSlots)
                    $ht.add("RAM Slots Occupied", (@($WMI_PM).count))

                    if ($WMI_PM) {
                        $i = 1
                        $WMI_PM | Foreach {
                            $ht.add("RAM$i BankLabel", $_.BankLabel)
                            $ht.add("RAM$i DeviceLocator", $_.DeviceLocator)
                            $ht.add("RAM$i Capacity MB", ($_.Capacity / 1MB))
                            $ht.add("RAM$i Manufacturer", $_.Manufacturer)
                            $ht.add("RAM$i PartNumber", $_.PartNumber)
                            $ht.add("RAM$i SerialNumber", $_.SerialNumber)
                            $ht.add("RAM$i Speed", $_.Speed)
                            ++$i
                        }
                    }
                }
            }

            # GPU
            if ($WMI_GPU) {
                $ht.add('GPU Name', $WMI_GPU.name)
                $ht.add('GPU Driver Version', $WMI_GPU.driverversion)
                $ht.add('GPU Driver Date', $WMI_GPU.ConvertToDateTime($WMI_GPU.DriverDate))
                $ht.add('Resolution', $WMI_GPU.VideoModeDescription)
            }

            if ($Detailed -and $WMI_MONITOR) {
                function Decode {
                    If ($args[0] -is [System.Array]) {
                        [System.Text.Encoding]::ASCII.GetString($args[0])
                    }
                }

                $i = 1
                $WMI_MONITOR | Foreach {
                    # informace nejsou uplne presne, brat s rezervou
                    $ht.add("MONITOR$i Name", (Decode $_.UserFriendlyName -notmatch 0))
                    $ht.add("MONITOR$i SN", (Decode $_.SerialNumberID -notmatch 0))
                }
            }

            # BIOS/UEFI type
            if ($Detailed) {
                if ($hasAdminRights -and (Get-Command Confirm-SecureBootUEFI -ErrorAction SilentlyContinue)) {
                    try {
                        $secureBoot = Confirm-SecureBootUEFI -ErrorAction Stop
                        $type = 'UEFI'
                    } catch {
                        # Get-SecureBootUEFI konci chybou, pokud se spousti na OS v BIOS rezimu
                        $type = 'BIOS'
                    }
                } else {
                    $type = 'BIOS'
                    # urcuji neprimo podle toho jestli existuje GPT systemove oddil (v BIOS rezimu by z toho neslo nabootovat)
                    if ($WMI_PARTITION -and ($WMI_PARTITION | where {$_.Type -eq "GPT: System" -and $_.Bootable -eq $True -and $_.BootPartition -eq $True})) {
                        $type = 'UEFI'
                    }
                }
                $ht.add('BIOS Type', $type)
            }

            # BIOS
            if ($WMI_BIOS) {
                $ht.add('BIOS Manufacturer', $WMI_BIOS.Manufacturer)
                $ht.add('BIOS Name', $WMI_BIOS.Name)
                $ht.add('BIOS Version', $WMI_BIOS.SMBIOSBIOSVersion)
            }

            if ($Detailed) {
                # SecureBoot
                if ($secureBoot -eq $true) {
                    # pozor, $secureBoot se plni pouze u Detailed vypisu
                    $ht.add('SecureBoot', 'enabled')
                } elseif ($secureBoot -eq $false) {
                    $ht.add('SecureBoot', 'disabled')
                } else {
                    $ht.add('SecureBoot', '**unknown**')
                }

                # TPM cip
                $ht.add('TPM', $TPM.SpecVersion)
            }

            # dalsi detailni informace
            if ($detailed) {
                # HDD
                $i = 1
                $WMI_DD | foreach {
                    # $model = $_.model
                    $ht.add("HDD$i Model", $_.model)
                    $ht.add("HDD$i SN", $_.SerialNumber)
                    $ht.add("HDD$i InterfaceType", $_.InterfaceType)
                    $ht.add("HDD$i Size", (“{0:N1}” -f ($_.size / 1gb)))
                    $ht.add("HDD$i Partitions", $_.Partitions)
                    # $ht.add("HDD$i IsBoot",($WMI_MSFT | where {$_.FriendlyName -eq "$model"} | select IsBoot))
                    $i = $i + 1
                }

                $WMI_DD2 | foreach {
                    if ($_.PredictFailure -eq $true) {
                        $ht.add("HDD InstanceName", $_.InstanceName)
                        $ht.add("HDD PredictFailure", $_.PredictFailure)
                        $ht.add("HDD Reason", $_.Reason)
                    }
                }

                # Local Administrators
                $AdministratorsMembers = net localgroup administrators | where {$_ -AND $_ -notmatch "command completed successfully"} | select -skip 4
                $ht.add("Local Administrators", $AdministratorsMembers)

                # Local Users
                if ($WMI_LU) {
                    $ht.add("Users", ($WMI_LU | select -exp name | Out-String))
                }

                # Printers
                if ($WMI_PRT) {
                    $i = 1
                    $WMI_PRT | foreach {
                        $ht.add("Printer$i Name", $_.Name)
                        $ht.add("Printer$i Default", $_.Default)
                        $ht.add("Printer$i DriverName", $_.DriverName)
                        $ht.add("Printer$i PortName", $_.PortName)
                        $ht.add("Printer$i Shared", $_.Shared)
                        if ($_.Shared) {$ht.add("Printer$i ShareName", $_.ShareName)}
                        $i = $i + 1
                    }
                }

                #region vypsani zaseknutych print jobu
                #				pro Win8
                #				if($WinBuild -gt 7601)
                #				{
                #					$PrinterWithError = Get-Printer -ComputerName $Computer | where PrinterStatus -eq Error
                #					if($PrinterWithError)
                #					{
                #						$PrinterWithError | Get-PrintJob
                #					}
                #				}
                ##				pro jine OS
                #				else
                #				{
                #						viz https://sites.google.com/site/godunder/powershell/ultimate-printer-print-queue-print-job-error-stuck-status-monitor-repair-report
                #			$i = 1
                #			$PrinterWithError = $WMI_PJ | where {($_.jobstatus -ne $null) -and ($_.jobstatus -ne "") -and ($_.jobstatus -ne "Printing") -and ($_.jobstatus -ne "Spooling") -and ($_.jobstatus -ne "Spooling | Printing")} |
                #			foreach {
                #				$ht.add("PrinterWithError$i",$_)
                #				$i = $i + 1
                #			}
                #endregion

                # Shares
                if ($WMI_SF) {
                    $Paths = @{}
                    $WMI_SF | Foreach { $Paths.$($_.Name -join ', ') = $_.Path }

                    $i = 0
                    $Paths.GetEnumerator() | Foreach {
                        $i++; $ht.add("Share$i", '' + $_.Name + ' (' + $_.Value + ')')
                    }
                }

                #			#region ovladace a jejich verze
                #			if ($WMI_DRIVERS) {
                #				$ht.add("DRIVERS:",'')
                #				$WMI_DRIVERS | foreach {
                #					if ($_.DeviceName -and $_.DriverVersion) {
                #						$ht.add($_.DeviceName,$_.DriverVersion)
                #					}
                #				}
                #			}
                #			#endregion
            }

            # opetovna aktivace vypisovani chyb
            $ErrorActionPreference = 'Continue'

            # PRIDANI ZISKANYCH PROPERTY DO OBJEKTU $OBJECT
            $object | Add-Member -NotePropertyMembers $ht

            # VYTVORENI PROPERTYSET PRO SNADNEJSI FILTROVANI VYSLEDKU
            $object | Add-Member PropertySet "LOU" @("ComputerName", "Logged On User")
            $object | Add-Member PropertySet "RAM" @("ComputerName", "RAM*")
            $object | Add-Member PropertySet "CPU" @("ComputerName", "CPU*")

            $object
        }
    }

    END {
    }
}