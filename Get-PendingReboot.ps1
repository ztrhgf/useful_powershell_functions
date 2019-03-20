function Get-PendingReboot {
    <#
 	.SYNOPSIS
        The PowerShell script which can be used to check if the server is pending reboot.
    .DESCRIPTION
        The PowerShell script which can be used to check if the server is pending reboot.
    .PARAMETER  ComputerName
		Gets the server reboot status on the specified computer.
    .EXAMPLE
        C:\PS> C:\Script\FindServerIsPendingReboot.ps1 -ComputerName "WIN-VU0S8","WIN-FJ6FH","WIN-FJDSH","WIN-FG3FH"

		ComputerName                                          RebootIsPending
        ------------                                          ---------------
        WIN-VU0S8                                             False
        WIN-FJ6FH                                             True
        WIN-FJDSH                                             True
        WIN-FG3FH                                             True

        This command will get the reboot status on the specified remote computers.
	#>

    param
    (
        [Parameter(Mandatory = $false, ValueFromPipeline = $true)]
        [ValidateNotNullOrEmpty()]
        [String[]]$ComputerName = $env:COMPUTERNAME
    )

    process {
        $result = Invoke-Command2 -ComputerName $ComputerName -ScriptBlock {
            #$PendingFile = $false
            $AutoUpdate = $false
            $CBS = $false 
            $SCCMPending = $false
            $ErrorActionPreference = 'silentlycontinue'

            $AutoUpdate = Test-Path -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired"
        
            # Determine SCCM 2012 reboot require
            $SCCMReboot = Invoke-CimMethod -Namespace 'Root\ccm\clientSDK' -ClassName 'CCM_ClientUtilities' -Name 'DetermineIfRebootPending'

            If ($SCCMReboot) {
                If ($SCCMReboot.RebootPending -or $SCCMReboot.IsHardRebootPending) {
                    $SCCMPending = $true
                }
            }

            # Determine PendingFileRenameOperations exists of not 
            # Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\PendFileKeyPath' -name PendingFileRenameOperations}

            # The servicing stack is available on all Windows Vista and Windows Server 2008 installations.
            $CBS = Test-Path -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending"

            If ($AutoUpdate -or $CBS -or $SCCMPending) {
                $RebootIsPending = $true
            } else {
                $RebootIsPending = $false
            }

            return New-Object -TypeName PSObject -Property @{ComputerName = $env:COMPUTERNAME; RebootIsPending = $RebootIsPending} 
        }

        $result | Select-Object -Property * -ExcludeProperty PSComputerName, RunspaceID
    }
}

