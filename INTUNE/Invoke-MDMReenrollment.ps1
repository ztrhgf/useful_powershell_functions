function Invoke-MDMReenrollment {
    <#
    .SYNOPSIS
    Function for resetting device Intune management connection.

    .DESCRIPTION
	Force re-enrollment of Intune managed devices.

    It will:
     - remove Intune certificates
     - remove Intune scheduled tasks & registry keys
     - force re-enrollment via DeviceEnroller.exe

    .EXAMPLE
    Invoke-MDMReenrollment

	.NOTES
    https://www.maximerastello.com/manually-re-enroll-a-co-managed-or-hybrid-azure-ad-join-windows-10-pc-to-microsoft-intune-without-loosing-current-configuration/

	Based on work of: MauriceDaly
    #>

    [Alias("Invoke-IntuneReenrollment")]
    [CmdletBinding()]
    param (
        [string] $computerName
    )

    if ($computerName -and $computerName -notin "localhost", $env:COMPUTERNAME) {
        if (! ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
            throw "You don't have administrator rights"
        }
    }

    $scriptBlock = {
        try {
            Write-Host "Checking for MDM certificate in computer certificate store"

            # Check&Delete MDM device certificate
            Get-ChildItem 'Cert:\LocalMachine\My\' | ? Issuer -EQ "CN=Microsoft Intune MDM Device CA" | % {
                Write-Host " - Removing Intune certificate $($_.DnsNameList.Unicode)"
                Remove-Item $_.PSPath
            }

            Write-Host "Starting forced on-boarding process"

            # Obtain current management GUID from Task Scheduler
            $EnrollmentGUID = Get-ScheduledTask | Where-Object { $_.TaskPath -like "*Microsoft*Windows*EnterpriseMgmt\*" } | Select-Object -ExpandProperty TaskPath -Unique | Where-Object { $_ -like "*-*-*" } | Split-Path -Leaf

            # Start clean up process
            if (-not [string]::IsNullOrEmpty($EnrollmentGUID)) {
                Write-Host "Current enrollment GUID detected as $([string]$EnrollmentGUID)"

                # Stop Intune Management Exention Agent and CCM Agent services
                Write-Host "Stopping MDM services"
                if (Get-Service -Name IntuneManagementExtension -ErrorAction SilentlyContinue) {
                    Write-Host " - Stopping IntuneManagementExtension service..."
                    Stop-Service -Name IntuneManagementExtension
                }
                if (Get-Service -Name CCMExec -ErrorAction SilentlyContinue) {
                    Write-Host " - Stopping CCMExec service..."
                    Stop-Service -Name CCMExec
                }

                # Remove task scheduler entries
                Write-Host "Removing task scheduler Enterprise Management entries for GUID - $([string]$EnrollmentGUID)"
                Get-ScheduledTask | Where-Object { $_.Taskpath -match $EnrollmentGUID } | Unregister-ScheduledTask -Confirm:$false
                # delete also parent folder
                Remove-Item -Path "$env:WINDIR\System32\Tasks\Microsoft\Windows\EnterpriseMgmt\$EnrollmentGUID" -Force

                $RegistryKeys = "HKLM:\SOFTWARE\Microsoft\Enrollments", "HKLM:\SOFTWARE\Microsoft\Enrollments\Status", "HKLM:\SOFTWARE\Microsoft\EnterpriseResourceManager\Tracked", "HKLM:\SOFTWARE\Microsoft\PolicyManager\AdmxInstalled", "HKLM:\SOFTWARE\Microsoft\PolicyManager\Providers", "HKLM:\SOFTWARE\Microsoft\Provisioning\OMADM\Accounts", "HKLM:\SOFTWARE\Microsoft\Provisioning\OMADM\Logger", "HKLM:\SOFTWARE\Microsoft\Provisioning\OMADM\Sessions"
                foreach ($Key in $RegistryKeys) {
                    Write-Host "Processing registry key $Key"
                    # Remove registry entries
                    if (Test-Path -Path $Key) {
                        # Search for and remove keys with matching GUID
                        Write-Host " - GUID entry found against key $Key. Removing.."
                        Get-ChildItem -Path $Key | Where-Object { $_.Name -match $EnrollmentGUID } | Remove-Item -Recurse -Force -Confirm:$false -ErrorAction SilentlyContinue
                    }
                }

                # Start Intune Management Extension Agent service
                Write-Host "Starting MDM services"
                if (Get-Service -Name IntuneManagementExtension -ErrorAction SilentlyContinue) {
                    Write-Host " - Starting IntuneManagementExtension service..."
                    Start-Service -Name IntuneManagementExtension
                }
                if (Get-Service -Name CCMExec -ErrorAction SilentlyContinue) {
                    Write-Host " - Starting CCMExec service..."
                    Start-Service -Name CCMExec
                }

                # Sleep
                Write-Host "Waiting for 30 seconds prior to running DeviceEnroller"
                Start-Sleep -Seconds 30

                # Start re-enrollment process
                Write-Host "Calling: DeviceEnroller.exe /C /AutoenrollMDM"
                Invoke-AsSystem -runAs SYSTEM -scriptBlock { Start-Process -FilePath "$env:WINDIR\System32\DeviceEnroller.exe" -ArgumentList "/C /AutoenrollMDM" -NoNewWindow -Wait -PassThru }
            } else {
                throw "Unable to obtain enrollment GUID value from task scheduler. Aborting"
            }
        } catch [System.Exception] {
            throw "Error message: $($_.Exception.Message)"
        }
    }

    $param = @{
        scriptBlock = $scriptBlock
    }

    if ($computerName -and $computerName -notin "localhost", $env:COMPUTERNAME) {
        $param.computerName = $computerName
    }

    Invoke-Command @param
}