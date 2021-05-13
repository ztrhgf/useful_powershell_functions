<#
script will set up new Windows Server as FTP server:
- install FTP, IIS roles
- create FTP site
- create READ and WRITE users and grant them permissions to IIS
- set Window Updates
- if finds RAW disk, format and assign E: letter and use it as FTP root otherwise 'C:\FTP_Root'
- in FTP root creates WRITE and READ folders and set appropriate NTFS permissions
- change ports for passive FTP to 60000-65535
- enable FTPS (using self-signed certificate)
- enable FTP on firewall

inspired by:
https://blogs.iis.net/jaroslad/windows-firewall-setup-for-microsoft-ftp-publishing-service-for-iis-7-0
http://fabriccontroller.net/passive-ftp-and-dynamic-ports-in-iis8-and-windows-azure-virtual-machines/
https://4sysops.com/archives/install-and-configure-an-ftp-server-with-powershell/
#>

param (
    $FTPSiteName = (Read-Host 'Enter FTP site name')
    ,
    $readFTPuser = (Read-Host "Enter name of READ FTP account")
    ,
    $writeFTPuser = (Read-Host "Enter name of WRITE FTP account")
)

if (! ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    throw "Run with administrator rights"
}

Write-Warning "Public IP of this server has to remain the same, so in AWS use elastic IP, otherwise after each start, VM gets new IP!!!`n"
Write-Warning "For FTP in passive mode to work correctly, public IP of this computer will be set in IIS. In case this computer doesn't have it's final IP (you will set Elastic IP etc), DO NOT CONTINUE!"
$choice = ""
while ($choice -notmatch "^[Y|N]$") {
    $choice = Read-Host "Continue? (Y|N)"
}
if ($choice -eq "N") {
    break
}

$dnsName = Read-Host "Enter DNS name of this FTP server (e.g. ftp.contoso.com). It will be used for certificate creation."

# create user accounts
$readFTPuser, $writeFTPuser | % {
    $Password = Read-Host "Password for '$_' user account" -AsSecureString
    $null = New-LocalUser $_ -Password $Password -FullName $_ -Description $_
    $null = Set-LocalUser -Name $_ -PasswordNeverExpires:$true -UserMayChangePassword:$false
}
Add-LocalGroupMember -Group "IIS_IUSRS" -Member $writeFTPuser

# nastavit autoinstalaci updatu + restart
# https://docs.microsoft.com/en-us/windows-server/administration/server-core/server-core-servicing

# Stop-Service wuauserv
# cmd /c "%systemroot%\system32\Cscript %systemroot%\system32\scregedit.wsf /AU 4"
# # $WUregistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU"
# # New-ItemProperty -Path $WUregistryPath -Name ScheduledInstallDay -Value 0 -PropertyType DWORD -Force | Out-Null # kazdy den
# # New-ItemProperty -Path $WUregistryPath -Name ScheduledInstallTime -Value 3 -PropertyType DWORD -Force | Out-Null # ve 3 rano
# # New-ItemProperty -Path $WUregistryPath -Name NoAutoRebootWithLoggedOnUsers -Value 0 -PropertyType DWORD -Force | Out-Null # reboot i kdyz je nekdo prihlasen
# Start-Service wuauserv

#region create sched task for Windows Update
$scriptBlock = {
    # find updates
    $ScanResult = Invoke-CimMethod -Namespace "root/Microsoft/Windows/WindowsUpdate" -ClassName "MSFT_WUOperations" -MethodName ScanForUpdates -Arguments @{SearchCriteria = "IsInstalled=0 AND Type='Software'" } # s AutoSelectOnWebSites=1 koncilo chybou instalace updatu
    # apply updates
    if ($ScanResult.Updates) {
        $result = Invoke-CimMethod -Namespace "root/Microsoft/Windows/WindowsUpdate" -ClassName "MSFT_WUOperations" -MethodName InstallUpdates -Arguments @{Updates = $ScanResult.Updates }
    }
    $pendingReboot = Invoke-CimMethod -Namespace "root/Microsoft/Windows/WindowsUpdate" -ClassName "MSFT_WUSettings" -MethodName IsPendingReboot | select -exp pendingReboot
    if ($pendingReboot) {
        shutdown /r /t 30 /c "restarting because of newly installed updates"
    }
}

$bytes = [System.Text.Encoding]::Unicode.GetBytes($scriptBlock.ToString())
$encodedString = [Convert]::ToBase64String($bytes)

$action = New-ScheduledTaskAction -Execute 'Powershell.exe' -Argument "-ExecutionPolicy Bypass -NoProfile -encodedcommand $encodedString"

$trigger = New-ScheduledTaskTrigger -Daily -At 3am

Register-ScheduledTask -User "SYSTEM" -Action $action -Trigger $trigger -TaskName "WindowsUpdate" -Description "regular updating of Windows" -Force
#endregion create sched task for Windows Update

#region format raw disk and assign it E letter
$rawDisk = Get-Disk | ? { $_.partitionstyle -eq "raw" }
$rawDisk | Initialize-Disk -PartitionStyle MBR
$rawDisk | New-Partition -DriveLetter E -UseMaximumSize | Format-Volume -FileSystem NTFS -NewFileSystemLabel "DATA" -Confirm:$false
#endregion format raw disk and assign E letter

#region install FTP, IIS roles
Install-WindowsFeature Web-FTP-Server -IncludeAllSubFeature -IncludeManagementTools
Install-WindowsFeature Web-Server -IncludeAllSubFeature -IncludeManagementTools
#endregion install FTP, IIS roles

#region set FTP
Import-Module WebAdministration -ea Stop # creates IIS: drive too

#region create the FTP site
if ($rawDisk) {
    $FTPRootDir = 'E:\FTP_Root'
} else {
    $FTPRootDir = 'C:\FTP_Root'
}
$FTPPort = 21
$null = New-Item $FTPRootDir -ItemType Directory
New-WebFtpSite -Name $FTPSiteName -Port $FTPPort -PhysicalPath $FTPRootDir
#endregion create the FTP site

# enable basic authentication
$FTPSitePath = "IIS:\Sites\$FTPSiteName"
$BasicAuth = 'ftpServer.security.authentication.basicAuthentication.enabled'
Set-ItemProperty -Path $FTPSitePath -Name $BasicAuth -Value $True

#region set authorization rules for FTP users
# READ-WRITE
$writeFTPuser | % {
    $Param = @{
        Filter   = "/system.ftpServer/security/authorization"
        Value    = @{
            accessType  = "Allow"
            Users       = "$_"
            permissions = 3
        }
        PSPath   = 'IIS:\'
        Location = $FTPSiteName
    }
    Add-WebConfiguration @param
}
# READ
$readFTPuser | % {
    $Param = @{
        Filter   = "/system.ftpServer/security/authorization"
        Value    = @{
            accessType  = "Allow"
            Users       = "$_"
            permissions = 1
        }
        PSPath   = 'IIS:\'
        Location = $FTPSiteName
    }
    Add-WebConfiguration @param
}
#endregion set authorization rules for FTP users

#region set custom NTFS to FTP_Root\WRITE
$NoneSID = ((New-Object System.Security.Principal.NTAccount("", "none")).Translate([System.Security.Principal.SecurityIdentifier])).Value

$writeFTPSDDL = ""
$writeFTPuser | % {
    $SID = ((New-Object System.Security.Principal.NTAccount("", "$_")).Translate([System.Security.Principal.SecurityIdentifier])).Value
    $writeFTPSDDL += "(A;OICI;0x1301bf;;;$SID)"
}
$readFTPSDDL = ""
$readFTPuser | % {
    $SID = ((New-Object System.Security.Principal.NTAccount("", "$_")).Translate([System.Security.Principal.SecurityIdentifier])).Value
    $readFTPSDDL += "(A;;0x1200a9;;;$SID)"
}
$sddl = "O:BAG:$NoneSID`D:PAI(A;OICI;FA;;;SY)(A;OICI;0x1301bf;;;NS)(A;OICI;FA;;;BA)$writeFTPSDDL$readFTPSDDL"

$_ClientWRITE = Join-Path $FTPRootDir "WRITE"
$null = New-Item $_ClientWRITE -ItemType Directory
$securityDescriptor = Get-Acl -Path $_ClientWRITE
$securityDescriptor.SetSecurityDescriptorSddlForm($sddl)
Set-Acl -Path $_ClientWRITE -AclObject $securityDescriptor
#endregion set custom NTFS to FTP_Root\WRITE

#region set custom NTFS to FTP_Root\READ
$writeFTPSDDL = ""
$writeFTPuser | % {
    $SID = ((New-Object System.Security.Principal.NTAccount("", "$_")).Translate([System.Security.Principal.SecurityIdentifier])).Value
    $writeFTPSDDL += "(A;OICIIO;0x1301bf;;;$SID)(A;;0x1200ad;;;$SID)"
}
$readFTPSDDL = ""
$readFTPuser | % {
    $SID = ((New-Object System.Security.Principal.NTAccount("", "$_")).Translate([System.Security.Principal.SecurityIdentifier])).Value
    $readFTPSDDL += "(A;OICI;0x1200a9;;;$SID)"
}
$sddl = "O:BAG:$NoneSID`D:PAI(A;OICI;FA;;;SY)(A;OICIIO;0x1301bf;;;NS)(A;OICI;FA;;;BA)$writeFTPSDDL$readFTPSDDL"

$_ClientREAD = Join-Path $FTPRootDir "READ"
$null = New-Item $_ClientREAD -ItemType Directory
$securityDescriptor = Get-Acl -Path $_ClientREAD
$securityDescriptor.SetSecurityDescriptorSddlForm($sddl)
Set-Acl -Path $_ClientREAD -AclObject $securityDescriptor
#endregion set custom NTFS to FTP_Root\READ

#region set SSL (FTPS)

# force FTPS
Set-ItemProperty -Path $FTPSitePath -Name ftpServer.security.ssl.controlChannelPolicy -Value 1
Set-ItemProperty -Path $FTPSitePath -Name ftpServer.security.ssl.dataChannelPolicy -Value 1
$newCert = New-SelfSignedCertificate -FriendlyName "FTP Server" -CertStoreLocation "Cert:\LocalMachine\My" -DnsName $dnsName -NotAfter (Get-Date).AddMonths(120)
#TODO use LetsEncrypt i.e. https://github.com/win-acme/win-acme

# https://stackoverflow.com/questions/32390097/powershell-set-ssl-certificate-on-https-binding
# bind certificate to FTP site
Set-ItemProperty -Path $FTPSitePath -Name ftpServer.security.ssl.serverCertHash -Value $newCert.GetCertHashString()

# SSL has to be set identically per SITE and per SERVER (in IIS) http://www.vsysad.com/2013/06/install-and-configure-ftp-over-ssl-ftps-in-iis-7-5/
# otherwise error:
# Response: 534 Local policy on server does not allow TLS secure connections.
# Error: Critical error
# Error: Could not connect to server

# set server public IP because of passive FTP(S)
$publicIP = Invoke-RestMethod http://ipinfo.io/json | Select-Object -exp ip
if (!$publicIP) { $publicIP = Read-Host "Enter !PUBLIC! IP address of this FTP server" }
Set-ItemProperty -Path $FTPSitePath -Name ftpServer.firewallSupport.externalIp4Address -Value $publicIP
#endregion set SSL (FTPS)

# change range of ports for passive FTP to 60000-65535 (default contains even 3389 i.e. RDP!)
cmd /c "$env:windir\System32\inetsrv\appcmd set config /section:system.ftpServer/firewallSupport /lowDataChannelPort:60000 /highDataChannelPort:65535"
#endregion set FTP

# restart site to apply the changes
Restart-WebItem "IIS:\Sites\$FTPSiteName" -Verbose

# set FW
# default FTP rule seems to not work...
New-NetFirewallRule -Name "FTP 21" -DisplayName "FTP 21" -Description "default rule seems to not work" -Profile private, public, domain -Direction Inbound -Action Allow -Protocol TCP -LocalPort 21 -Program "%windir%\system32\svchost.exe"
netsh advfirewall set global Statefulftp disable
Restart-Service ftpsvc -Force

Write-Warning "Don't forget to:`n - set FW (Security Groups) in AWS (use existing 'FTP server')`n - set Elastic IP of this server in it's DNS record"

Write-Warning "Check NTFS permission on $FTPRootDir if it suit your needs!"