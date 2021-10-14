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

    .PARAMETER computerName
    (optional) Name of the remote computer, which you want to re-enroll.

    .PARAMETER asSystem
    Switch for invoking re-enroll as a SYSTEM instead of logged user.

    .EXAMPLE
    Invoke-MDMReenrollment

    Invoking re-enroll to Intune on local computer under logged user.

    .EXAMPLE
    Invoke-MDMReenrollment -computerName PC-01 -asSystem

    Invoking re-enroll to Intune on computer PC-01 under SYSTEM account.

	.NOTES
    https://www.maximerastello.com/manually-re-enroll-a-co-managed-or-hybrid-azure-ad-join-windows-10-pc-to-microsoft-intune-without-loosing-current-configuration/

	Based on work of MauriceDaly.
    #>

    [Alias("Invoke-IntuneReenrollment")]
    [CmdletBinding()]
    param (
        [string] $computerName,

        [switch] $asSystem
    )

    if ($computerName -and $computerName -notin "localhost", $env:COMPUTERNAME) {
        if (! ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
            throw "You don't have administrator rights"
        }
    }

    $allFunctionDefs = "function Invoke-AsSystem { ${function:Invoke-AsSystem} }"

    $scriptBlock = {
        param ($allFunctionDefs, $asSystem)

        try {
            foreach ($functionDef in $allFunctionDefs) {
                . ([ScriptBlock]::Create($functionDef))
            }

            Write-Host "Checking for MDM certificate in computer certificate store"

            # Check&Delete MDM device certificate
            Get-ChildItem 'Cert:\LocalMachine\My\' | ? Issuer -EQ "CN=Microsoft Intune MDM Device CA" | % {
                Write-Host " - Removing Intune certificate $($_.DnsNameList.Unicode)"
                Remove-Item $_.PSPath
            }

            # Obtain current management GUID from Task Scheduler
            $EnrollmentGUID = Get-ScheduledTask | Where-Object { $_.TaskPath -like "*Microsoft*Windows*EnterpriseMgmt\*" } | Select-Object -ExpandProperty TaskPath -Unique | Where-Object { $_ -like "*-*-*" } | Split-Path -Leaf

            # Start cleanup process
            if ($EnrollmentGUID) {
                $EnrollmentGUID | % {
                    $GUID = $_

                    Write-Host "Current enrollment GUID detected as $GUID"

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
                    Write-Host "Removing task scheduler Enterprise Management entries for GUID - $GUID"
                    Get-ScheduledTask | Where-Object { $_.Taskpath -match $GUID } | Unregister-ScheduledTask -Confirm:$false
                    # delete also parent folder
                    Remove-Item -Path "$env:WINDIR\System32\Tasks\Microsoft\Windows\EnterpriseMgmt\$GUID" -Force

                    $RegistryKeys = "HKLM:\SOFTWARE\Microsoft\Enrollments", "HKLM:\SOFTWARE\Microsoft\Enrollments\Status", "HKLM:\SOFTWARE\Microsoft\EnterpriseResourceManager\Tracked", "HKLM:\SOFTWARE\Microsoft\PolicyManager\AdmxInstalled", "HKLM:\SOFTWARE\Microsoft\PolicyManager\Providers", "HKLM:\SOFTWARE\Microsoft\Provisioning\OMADM\Accounts", "HKLM:\SOFTWARE\Microsoft\Provisioning\OMADM\Logger", "HKLM:\SOFTWARE\Microsoft\Provisioning\OMADM\Sessions"
                    foreach ($Key in $RegistryKeys) {
                        Write-Host "Processing registry key $Key"
                        # Remove registry entries
                        if (Test-Path -Path $Key) {
                            # Search for and remove keys with matching GUID
                            Write-Host " - GUID entry found in $Key. Removing..."
                            Get-ChildItem -Path $Key | Where-Object { $_.Name -match $GUID } | Remove-Item -Recurse -Force -Confirm:$false -ErrorAction SilentlyContinue
                        }
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
                if ($asSystem) {
                    Invoke-AsSystem -runAs SYSTEM -scriptBlock { Start-Process -FilePath "$env:WINDIR\System32\DeviceEnroller.exe" -ArgumentList "/C /AutoenrollMDM" -NoNewWindow -Wait -PassThru }
                } else {
                    Start-Process -FilePath "$env:WINDIR\System32\DeviceEnroller.exe" -ArgumentList "/C /AutoenrollMDM" -NoNewWindow -Wait -PassThru
                }
            } else {
                throw "Unable to obtain enrollment GUID value from task scheduler. Aborting"
            }
        } catch [System.Exception] {
            throw "Error message: $($_.Exception.Message)"
        }
    }

    $param = @{
        scriptBlock  = $scriptBlock
        argumentList = $allFunctionDefs, $asSystem
    }

    if ($computerName -and $computerName -notin "localhost", $env:COMPUTERNAME) {
        $param.computerName = $computerName
    }

    Invoke-Command @param
}