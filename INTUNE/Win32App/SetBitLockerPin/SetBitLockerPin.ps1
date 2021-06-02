# https://oliverkieselbach.com/2019/08/02/how-to-enable-pre-boot-bitlocker-startup-pin-on-windows-with-intune/
# Author: Oliver Kieselbach (oliverkieselbach.com)
# Date: 08/01/2019
# Description: Starts the Windows Forms Dialog for BitLocker PIN entry and receives the PIN via exit code to set the additional key protector
# - 10/21/2019 changed PIN handover
# - 02/10/2020 added content length check

# shows GUI for entering PIN for Bitlocker and than sets it as TPMPin protector plus removes TPM protector if such exists
# if entering the PIN fails, the process will start again


# shouldn't happen (because of detection script), but just for sure
if ((Get-BitLockerVolume -MountPoint $env:SystemDrive).KeyProtector | where { $_.KeyProtectorType -eq 'TpmPin' }) {
    throw "PIN is already set"
}

$pathPINFile = $(Join-Path -Path $([Environment]::GetFolderPath("CommonDocuments")) -ChildPath "PIN-prompted.txt")

while (1) {
    # just for sure
    if (Test-Path $pathPINFile) {
        Remove-Item $pathPINFile -Force -ErrorAction Stop
    }

    .\ServiceUI.exe -process:Explorer.exe "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -WindowStyle Hidden -Ex bypass -file "$PSScriptRoot\Popup.ps1"
    $exitCode = $LASTEXITCODE

    If ($exitCode -eq 0 -And (Test-Path -Path $pathPINFile)) {
        $encodedText = Get-Content -Path $pathPINFile
        if ($encodedText.Length -gt 0) {
            $PIN = [System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String($encodedText))

            Add-BitLockerKeyProtector -MountPoint $env:SystemDrive -Pin $(ConvertTo-SecureString $PIN -AsPlainText -Force) -TpmAndPinProtector -ErrorAction Stop

            # remove TPM protector if exists and adding of the TPMPin protector was successful
            $null = Get-BitLockerVolume -MountPoint $env:SystemDrive | select -exp KeyProtector | ? { $_.KeyProtectorType -eq "Tpm" } | select -exp KeyProtectorId | % { Remove-BitLockerKeyProtector -KeyProtectorId $_ -MountPoint $env:SystemDrive }

            # everything is ok, exit
            break
        }
    }

    sleep 5
}

# Cleanup
Remove-Item -Path $pathPINFile -Force -ErrorAction SilentlyContinue