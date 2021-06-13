function Invoke-ADPasswordsAudit {
    <#
    .SYNOPSIS
    Function for offline audit of AD user passwords using DSinternals and haveibeenpwnd password database.

    .DESCRIPTION
    Function for offline audit of AD user passwords using DSinternals and haveibeenpwnd password database.

    Function will:
    - check if there is newer version of haveibeenpwnd database
    - export ntds.dit and syskey on random DC
    - creates VM on node core-01 (without network connection)
    - to cluster node core-01 copy
        - exported ntds and syskey
        - DSinternals and haveibeenpwnd database
    - delete ntds.dit and syskey on DC
    - from cluster node to VM copy
        - exported ntds and syskey
        - DSinternals and haveibeenpwnd database
    - delete this copied data on cluster node
        - ntds.dit and syskey
        - deprecated haveibeenpwnd databases
    - run AD audit inside the VM
    - get the results
    - remove VM

    Result will be outputted to console and saved to resultDestination as txt file.

    .PARAMETER pwnedPasswordsNTLMOrdered
    Path to downloaded database of haveibeenpwnd password hashes.
    Download it from https://haveibeenpwned.com/Passwords and !always! pick NTLM ordered by hash version!

    .PARAMETER weakPasswordsFile
    Path to txt file with your custom plaintext passwords to check.
    Each on new line!

    .PARAMETER DSInternals
    Path to DSInternals PS module.
    If not specified but found on system, uses that path.

    .PARAMETER VMName
    Name of VM, that will be created and where the magic happens.

    .PARAMETER VMHostName
    Name of Hyper-V cluster node, which will host the VM.

    .PARAMETER VMMServerName
    Name of your SCVMM server.

    .PARAMETER resultDestination
    Path, where the results should be saved in txt form.

    .EXAMPLE
    Invoke-ADPasswordsAudit -pwnedPasswordsNTLMOrdered "C:\AD_audit\pwned-passwords-ntlm-ordered-by-hash-v7.txt" -DSInternals "C:\AD_audit\modules\DSInternals"

    Check passwords of all AD users against pwned database.

    .EXAMPLE
    Invoke-ADPasswordsAudit -pwnedPasswordsNTLMOrdered "C:\AD_audit\pwned-passwords-ntlm-ordered-by-hash-v7.txt" -weakPasswordsFile "C:\AD_audit\weakPasswordsFile.txt" -DSInternals "C:\AD_audit\DSInternals"

    Check passwords of all AD users against pwned database and weakPasswordsFile.txt.
    #>

    [Alias("Check-ADPasswords")]
    param (
        [Parameter(Mandatory = $true)]
        [ValidateScript( {
                If ($_ -match "pwned-passwords-ntlm-ordered-by-hash.+\.txt" -and (Test-Path -Path $_ -PathType Leaf)) {
                    $true
                } else {
                    Throw "$_ is not a path to pwned-passwords-ntlm-ordered-by-hash-v5.txt file"
                }
            })]
        [string] $pwnedPasswordsNTLMOrdered
        ,
        [ValidateScript( {
                If ($_ -match "weakPasswordsFile\.txt$" -and (Test-Path -Path $_ -PathType Leaf)) {
                    $true
                } else {
                    Throw "$_ is not a path to existing weakPasswordsFile.txt file"
                }
            })]
        [string] $weakPasswordsFile
        ,
        [ValidateScript( {
                If ($_ -match "DSInternals" -and (Test-Path -Path $_ -PathType Container)) {
                    $true
                } else {
                    Throw "$_ is not a path to PS module DSInternals"
                }
            })]
        [string] $DSInternals = (Get-Module "DSInternals" -ListAvailable | select -exp ModuleBase)
        ,
        [string] $VMName = "AD_audit"
        ,
        [Parameter(Mandatory = $true)]
        [string] $VMHostName = (Read-Host "Enter name of one of your Hyper-V cluster servers")
        ,
        [Parameter(Mandatory = $true)]
        [string] $VMMServerName
        ,
        [ValidateScript( {
                If (Test-Path -Path $_ -PathType Container) {
                    $true
                } else {
                    Throw "$_ doesn't exists"
                }
            })]
        [string] $resultDestination = ""
    )

    BEGIN {
        If ((Invoke-Command -ComputerName $VMMServerName -arg $VMName { Get-SCVirtualMachine $args[0] })) {
            Throw "VM $VMName already exists"
        }

        #
        #region functions
        #
        function Remove-ItemSecure {
            <#
            .SYNOPSIS
            Function for secure overwrite and deletion of file(s).
            It will overwrite file(s) in a secure way by using a cryptographically strong sequence of random values using .NET functions.

            .DESCRIPTION
            Function for secure overwrite and deletion of file(s).
            It will overwrite file(s) in a secure way by using a cryptographically strong sequence of random values using .NET functions.

            .PARAMETER item
            Path to file or folder that should be securely deleted.

            .EXAMPLE
            Remove-FileSecure C:\temp\passwords.txt

            Securely overwrite content of passwords.txt and than delete it.

            .EXAMPLE
            Remove-FileSecure C:\temp

            Securely overwrite all files in C:\temp and than delete whole folder.

            .EXAMPLE
            Get-ChildItem $path -Filter *.txt | Remove-FileSecure

            Securely overwrite all txt files in given folder and than delete them.

            .NOTES
            https://gallery.technet.microsoft.com/scriptcenter/Secure-File-Remove-by-110adb68
            #>

            [CmdletBinding()]
            [Alias("Remove-FileSecure")]
            param (
                [Parameter(Mandatory = $true)]
                [ValidateScript( {
                        If (Test-Path -Path $_) {
                            $true
                        } else {
                            Throw "$_ doesn't exist"
                        }
                    })]
                [string] $item
            )

            function _Remove-FileSecure {
                <#
                .SYNOPSIS
                Function for secure overwrite and deletion of file(s).
                It will overwrite file(s) in a secure way by using a cryptographically strong sequence of random values using .NET functions.

                .DESCRIPTION
                Function for secure overwrite and deletion of file(s).
                It will overwrite file(s) in a secure way by using a cryptographically strong sequence of random values using .NET functions.

                .PARAMETER File
                Path to file that should be overwritten.

                .OUTPUTS
                Boolean. True if successful else False.

                .NOTES
                https://gallery.technet.microsoft.com/scriptcenter/Secure-File-Remove-by-110adb68
                #>

                [CmdletBinding()]
                [OutputType([boolean])]
                param(
                    [Parameter(Mandatory = $true, ValueFromPipeline = $true )]
                    [System.IO.FileInfo] $File
                )

                BEGIN {
                    $r = New-Object System.Security.Cryptography.RNGCryptoServiceProvider
                }

                PROCESS {
                    $retObj = $null

                    if ((Test-Path $file -PathType Leaf) -and $pscmdlet.ShouldProcess($file)) {
                        $f = $file
                        if ( !($f -is [System.IO.FileInfo]) ) {
                            $f = New-Object System.IO.FileInfo($file)
                        }

                        $l = $f.length

                        $s = $f.OpenWrite()

                        try {
                            $w = New-Object system.diagnostics.stopwatch
                            $w.Start()

                            Write-Progress -Activity $f.FullName -Status "Write" -PercentComplete 0 -CurrentOperation ""

                            [long]$i = 0
                            $b = New-Object byte[](1024 * 1024)
                            while ( $i -lt $l ) {
                                $r.GetBytes($b)

                                $rest = $l - $i

                                if ( $rest -gt (1024 * 1024) ) {
                                    $s.Write($b, 0, $b.length)
                                    $i += $b.LongLength
                                } else {
                                    $s.Write($b, 0, $rest)
                                    $i += $rest
                                }

                                [double]$p = [double]$i / [double]$l

                                [long]$remaining = [double]$w.ElapsedMilliseconds / $p - [double]$w.ElapsedMilliseconds

                                Write-Progress -Activity $f.FullName -Status "Write" -PercentComplete ($p * 100) -CurrentOperation "" -SecondsRemaining ($remaining / 1000)
                            }
                            $w.Stop()
                        } finally {
                            $s.Close()

                            $null = Remove-Item $f.FullName -Force -Confirm:$false -ErrorAction Stop
                        }
                    } else {
                        Write-Warning "$($f.FullName) wasn't found"
                        return $false
                    }

                    return $true
                }
            }

            if ((Get-Item $item).PSIsContainer) {
                # is directory
                # remove files securely
                Get-ChildItem $item -Recurse -File | % {
                    $ok = _Remove-FileSecure $_.FullName
                    if (!$ok) {
                        throw "Secure deletion of $($_.FullName) failed"
                    }
                }
                # remove the folder itself
                Remove-Item $item -Recurse -Force -Confirm:$false
            } else {
                # is file

                # remove file securely
                $ok = _Remove-FileSecure $item
                if (!$ok) {
                    throw "Secure deletion of $item failed"
                }
            }
        }
        #endregion functions

        $allFunctionDefs = "function Remove-ItemSecure { ${function:Remove-ItemSecure} }"

        # generate VM Administrator credentials, that will be used to create VM and than connect to it
        # (when creating VM, just password will be used, because login will be always Administrator)
        $u = "$VMName\Administrator"
        [securestring] $p = ConvertTo-SecureString (Generate-Password -length 30 -outputToConsole -ea stop) -AsPlainText -Force
        [pscredential] $VMadminCredential = New-Object System.Management.Automation.PSCredential ($u, $p)

        # check invoker permissions
        $domainAdmins = Get-ADGroupMemberRecursive -name "Domain Admins"
        if ($env:USERNAME -notin $domainAdmins) {
            Throw "Insufficient rights. Run as Domain Admin."
        }

        # check newest password database from haveibennpwnd
        $url = "https://haveibeenpwned.com/Passwords"
        $web = Invoke-WebRequest $url
        $webPwndVer = $web.ParsedHtml.getelementsbytagname('a') | ? { $_.textContent -match "cloudflare" -and $_.nameProp -match "pwned-passwords-ntlm-ordered-by-hash" } | select -exp nameProp
        $webPwndVer = [System.IO.Path]::GetFileNameWithoutExtension($webPwndVer)
        $usedPwndVer = [System.IO.Path]::GetFileNameWithoutExtension($pwnedPasswordsNTLMOrdered)
        if ($webPwndVer -and $usedPwndVer -notmatch [regex]::Escape($webPwndVer)) {
            throw "On $url is newer version on pwnedPasswordsNTLMOrdered database ($webPwndVer). Download and use NTLM (ordered by hash) version!"
        }

        # path where data will be saved (on DC, cluster node even VM)
        $IFMPath = "C:\Windows\x89u111k890dnkfdjk3o2hrnfds9"
        $DC = ((Get-ADDomain | Select-Object -exp PDCEmulator) -split "\.")[0] # to get DC with PDCEmulator role, because why not
        Write-Warning "In case this function will end unexpectedly, make sure that folder '$IFMPath' is deleted on $DC, $VMHostName and VM $VMName on SCVMM server!`nUse function Remove-ItemSecure for secure deletion."
    }

    PROCESS {
        #
        #region export ntds and syskey on DC
        #

        "Exporting NTDS and syskey on $DC"

        Invoke-Command $DC {
            param ($IFMPath)

            if (Test-Path $IFMPath -ea SilentlyContinue) { Remove-Item $IFMPath -Recurse -Force }

            $IFM = ntdsutil "activate instance ntds" ifm "create full `"$IFMPath`"" q q

            if (!($IFM -like "*IFM media created successfully*")) {
                Remove-Item $IFMPath -Recurse -Force # just for sure
                throw "Export failed`n`n$IFM"
            }
        } -ArgumentList $IFMPath
        #endregion export ntds and syskey on DC

        #
        #region create VM (nondomain, without network, with local admin)
        #
        "Creating VM $VMName (in background)"
        TODO
        $null = New-VMFromTemplate -VMName $VMName -VMHostName $VMHostName -VMAdminPass $VMadminCredential -JoinWorkgroup -NoNetwork -asJob -Tier 0
        #endregion create VM

        #
        #region copy ntds to cluster node, that hosts VM
        #
        # it has to be on that node because of powershell direct

        # ensure, that we don't fill all disk space on cluster node
        $disk = Get-WmiObject Win32_LogicalDisk -ComputerName $VMHostName -Filter "DeviceID='C:'" | Select-Object FreeSpace
        if ($disk.FreeSpace / 1gb -lt 30) {
            throw "$VMHostName has too little free space $($disk.FreeSpace/1gb)GB. Unsafe to continue.`n`nRemove folder $IFMPath from $DC. It contains sensitive data!"
        }

        $VMnodeDest = Join-Path "\\$VMHostName\c$" (Split-Path $IFMPath -NoQualifier)
        "Copying NTDS and syskey from $DC to $VMHostName"
        $r = Copy-Folder (Join-Path "\\$DC\c$" (Split-Path $IFMPath -NoQualifier)) $VMnodeDest
        if ($r.failures) { throw "Copy failed" }
        #endregion copy ntds to cluster node, that hosts VM

        # delete ntds and syskey from DC
        "Deleting exported NTDS and syskey from $DC"
        Invoke-Command $DC {
            param ($IFMPath)
            Remove-Item $IFMPath -Recurse -Force
        } -ArgumentList $IFMPath

        #
        #region copy necessary tools to cluster node, that hosts VM
        #
        "Copying DSInternals module to $VMHostName"
        $r = Copy-Folder $DSInternals "$VMnodeDest\DSInternals"
        if ($r.failures) { throw "Copy failed" }

        "Copying haveibeenpwnd password database to $VMHostName"
        $null = xcopy $pwnedPasswordsNTLMOrdered $VMnodeDest /d # to copy only if the file is newer
        if ($weakPasswordsFile) {
            "Copying weak password database to $VMHostName"
            $null = xcopy $weakPasswordsFile $VMnodeDest /d # to copy only if the file is newer
        }
        #endregion copy necessary tools to cluster node, that hosts VM

        "Waiting for establishing session to VM (minimum wait time is 5 minutes)"
        # waiting, because VM restarts itself after creation and I don't want the connection to hit this online window
        Start-Sleep -Seconds 300

        Invoke-Command -ComputerName $VMHostName {
            param ($VMName, $VMadminCredential)

            while (!$VMsession) {
                try {
                    # session to VM through Powershell Direct
                    $VMsession = New-PSSession -VMName $VMName -Credential $VMadminCredential -ErrorAction Stop
                } catch {
                    Write-Host "." -NoNewline
                }

                Start-Sleep 5
            }

            Remove-PSSession $VMsession
        } -ArgumentList $VMName, $VMadminCredential

        #
        #region copy ntds and tools from cluster node to VM and run audit
        #
        "Copying necessary data to VM $VMName"
        $result = Invoke-Command -ComputerName $VMHostName {
            param ($VMName, $IFMPath, $VMadminCredential, $allFunctionDefs)

            foreach ($functionDef in $allFunctionDefs) {
                . ([ScriptBlock]::Create($functionDef))
            }

            # session to VM through Powershell Direct
            $VMsession = $null
            while (!$VMsession) {
                try {
                    $VMsession = New-PSSession -VMName $VMName -Credential $VMadminCredential -ErrorAction Stop
                } catch {
                    Write-Host "." -NoNewline
                }

                Start-Sleep 5
            }

            # copy folder with all data to VM
            # remove existing folder
            # in case folder exists, copy-item copy content to the same named subfolder ..bleh
            Invoke-Command -Session $VMsession -ScriptBlock {
                param ($IFMPath, $allFunctionDefs)

                foreach ($functionDef in $allFunctionDefs) {
                    . ([ScriptBlock]::Create($functionDef))
                }

                try {
                    Remove-ItemSecure $IFMPath -ea SilentlyContinue
                } catch {}
            } -ArgumentList $IFMPath, $allFunctionDefs
            Copy-Item -ToSession $VMsession -Path $IFMPath -Destination $IFMPath -Recurse

            # delete sensitive data from cluster node
            (Join-Path $IFMPath "Active Directory"), (Join-Path $IFMPath "registry") | % {
                $toDel = $_
                try {
                    Write-Warning "Removing sensitive data '$toDel' from $env:COMPUTERNAME"
                    Remove-ItemSecure $toDel -ea Stop
                } catch {
                    Write-Error "Deletion of sensitive data '$toDel' on $env:COMPUTERNAME failed. Delete it manually!`n`nError was: $_"
                }
            }

            # delete deprecated haveibeenpwnd databases
            $pwnedPasswords = Get-ChildItem $IFMPath -Filter "pwned-passwords-ntlm-ordered-by-hash*.txt" | sort lastwrite | select -Skip 1 -exp fullname | % {
                Write-Warning "Removing deprecated pwd database $_"
                Remove-ItemSecure $_
            }


            #
            #region run AD audit on data stored in VM
            #
            Write-Warning "Running security checks on $VMName"
            $result = Invoke-Command -Session $VMsession -ScriptBlock {
                param ($IFMPath)

                Import-Module (Join-Path $IFMPath "DSinternals") -ErrorAction Stop

                $pwnedPasswords = Get-ChildItem $IFMPath -Filter "pwned-passwords-ntlm-ordered-by-hash*.txt" | select -Last 1 | select -exp fullname
                if (!$pwnedPasswords) { throw "Couldn't find pwned-passwords-ntlm-ordered-by-hash*.txt" }

                $weakPasswords = Get-ChildItem $IFMPath -Filter "*weakPasswordsFile.txt" | select -Last 1 | select -exp fullname
                if (!$weakPasswords) { Write-Warning "Couldn't find weakPasswords.txt" }

                $key = Get-BootKey -SystemHivePath (Join-Path $IFMPath 'registry\SYSTEM')
                if (!$key) { throw "Couldn't get syskey" }

                $params = @{
                    WeakPasswordHashesSortedFile = $pwnedPasswords
                }
                if ($weakPasswords) {
                    $params.WeakPasswordsFile = $weakPasswords
                }

                $result = Get-ADDBAccount -All -DatabasePath (Join-Path $IFMPath 'Active Directory\ntds.dit') -BootKey $key | Test-PasswordQuality @params

                return ($result | Out-String) # to get nice human readable output
            } -ArgumentList $IFMPath
            #endregion run AD audit on data stored in VM

            Remove-PSSession $VMsession -ErrorAction SilentlyContinue

            return $result
        } -ArgumentList $VMName, $IFMPath, $VMadminCredential, $allFunctionDefs
        #endregion copy ntds and tools from cluster node to VM and run audit
    }

    END {
        #
        #region save the results
        #
        if ($result) {
            $rFileName = "$(Get-Date -Format 'dd.MM.yyyy_HH.mm')_ADpwdAudit.txt"
            # output the result to console
            $result | Out-String
            # save output to given destination
            $rFile = Join-Path $resultDestination $rFileName
            "Saving output to $rFile"
            $result | Out-String | Out-File $rFile -Force # file isn't encrypted, because I don't want to copy&use any binaries on our cluster servers
        } else {
            Write-Error "Something went wrong."
        }
        #endregion save the results

        #
        #region cleanup
        #

        # Deleting VM
        "Deleting VM $VMName"
        try {
            Invoke-Command -ComputerName $VMMServerName {
                param ($VMName)

                $ErrorActionPreference = "Stop"
                Stop-SCVirtualMachine $VMName -Force | Out-Null
                Get-SCVirtualMachine $VMName | Remove-SCVirtualMachine | Out-Null
            } -ArgumentList $VMName -ErrorAction Stop
        } catch {
            throw "Deletion of $VMName failed: $_`n`n`nDelete it manually. It contains extremely sensitive data!"
        }

        # Deleting exported NTDS and syskey from DC
        Invoke-Command $DC {
            param ($IFMPath)

            if (Test-Path $IFMPath) {
                "Deleting exported NTDS and syskey from $env:COMPUTERNAME"
                Remove-Item $IFMPath -Recurse -Force
            }
        } -ArgumentList $IFMPath

        # Deleting sensitive data from cluster node
        Invoke-Command -ComputerName $VMHostName {
            param ($IFMPath, $allFunctionDefs)

            foreach ($functionDef in $allFunctionDefs) {
                . ([ScriptBlock]::Create($functionDef))
            }

            (Join-Path $IFMPath "Active Directory"), (Join-Path $IFMPath "registry") | % {
                $toDel = $_
                if (Test-Path $toDel) {
                    try {
                        "Removing sensitive data '$toDel' from $env:COMPUTERNAME"
                        Remove-ItemSecure $toDel -ea Stop
                    } catch {
                        Write-Error "Deletion of sensitive data '$toDel' on $env:COMPUTERNAME failed. Delete it manually!`n`nError was: $_"
                    }
                }
            }
        } -ArgumentList $IFMPath, $allFunctionDefs
        #endregion cleanup
    }
}