function Reset-IntuneEnrollment {
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
    Reset-IntuneEnrollment

    .NOTES
    # How MDM (Intune) enrollment works https://techcommunity.microsoft.com/t5/intune-customer-success/support-tip-understanding-auto-enrollment-in-a-co-managed/ba-p/834780
    #>

    [CmdletBinding()]
    param (
        [string] $computerName = $env:COMPUTERNAME
    )

    $ErrorActionPreference = "Stop"

    #region helper functions
    function Connect-Graph {
        <#
        .SYNOPSIS
        Function for connecting to Microsoft Graph.

        .DESCRIPTION
        Function for connecting to Microsoft Graph.
        Support interactive authentication or application authentication
        Without specifying any parameters, interactive auth. will be used.

        .PARAMETER TenantId
        ID of your tenant.

        Default is "e4fb6bec-b1f4-46dc-9ab8-c67549adc56d"

        .PARAMETER AppId
        Azure AD app ID (GUID) for the application that will be used to authenticate

        .PARAMETER AppSecret
        Specifies the Azure AD app secret corresponding to the app ID that will be used to authenticate.
        Can be generated in Azure > 'App Registrations' > SomeApp > 'Certificates & secrets > 'Client secrets'.

        .PARAMETER Beta
        Set schema to beta.

        .EXAMPLE
        Connect-Graph

        .NOTES
        Requires module Microsoft.Graph.Intune
        #>

        [CmdletBinding()]
        [Alias("Connect-MSGraph2", "Connect-MSGraphApp2")]
        param (
            [string] $TenantId = "e4fb6bec-b1f4-46dc-9ab8-c67549adc56d"
            ,
            [string] $AppId
            ,
            [string] $AppSecret
            ,
            [switch] $beta
        )

        if (!(Get-Command Connect-MSGraph, Connect-MSGraphApp -ea silent)) {
            throw "Module Microsoft.Graph.Intune is missing"
        }

        if ($beta) {
            if ((Get-MSGraphEnvironment).SchemaVersion -ne "beta") {
                $null = Update-MSGraphEnvironment -SchemaVersion beta
            }
        }

        if ($TenantId -and $AppId -and $AppSecret) {
            $graph = Connect-MSGraphApp -Tenant $TenantId -AppId $AppId -AppSecret $AppSecret -ea Stop
            Write-Verbose "Connected to Intune tenant $TenantId using app-based authentication (Azure AD authentication not supported)"
        } else {
            $graph = Connect-MSGraph -ea Stop
            Write-Verbose "Connected to Intune tenant $($graph.TenantId)"
        }
    }

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
                if (![string]::IsNullOrEmpty($EnrollmentGUID)) {
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
                            Write-Host " - GUID entry found in $Key. Removing..."
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

    function Get-IntuneLog {
        <#
        .SYNOPSIS
        Function for Intune policies debugging on client.
        - opens Intune logs
        - opens event viewer with Intune log
        - generates & open MDMDiagReport.html report

        .DESCRIPTION
        Function for Intune policies debugging on client.
        - opens Intune logs
        - opens event viewer with Intune log
        - generates & open MDMDiagReport.html report

        .PARAMETER computerName
        Name of remote computer.

        .EXAMPLE
        Get-IntuneLog
        #>

        [CmdletBinding()]
        param (
            [string] $computerName
        )

        if ($computerName -and $computerName -in "localhost", $env:COMPUTERNAME) {
            $computerName = $null
        }

        function _openLog {
            param (
                [string[]] $logs
            )

            if (!$logs) { return }

            # use best possible log viewer
            $cmLogViewer = "C:\Program Files (x86)\Microsoft Endpoint Manager\AdminConsole\bin\CMLogViewer.exe"
            $cmTrace = "$env:windir\CCM\CMTrace.exe"
            if (Test-Path $cmLogViewer) {
                $viewer = $cmLogViewer
            } elseif (Test-Path $cmTrace) {
                $viewer = $cmTrace
            }

            if ($viewer -and $viewer -match "CMLogViewer\.exe$") {
                # open all logs in one CMLogViewer instance
                $quotedLog = ($logs | % {
                        "`"$_`""
                    }) -join " "
                Start-Process $viewer -ArgumentList $quotedLog
            } else {
                # cmtrace (or notepad) don't support opening multiple logs in one instance, so open each log in separate viewer process
                foreach ($log in $logs) {
                    if (!(Test-Path $log -ErrorAction SilentlyContinue)) {
                        Write-Warning "Log $log wasn't found"
                        continue
                    }

                    Write-Verbose "Opening $log"
                    if ($viewer -and $viewer -match "CMTrace\.exe$") {
                        # in case CMTrace viewer exists, use it
                        Start-Process $viewer -ArgumentList "`"$log`""
                    } else {
                        # use associated viewer
                        & $log
                    }
                }
            }
        }

        # open main Intune logs
        $log = "C:\ProgramData\Microsoft\IntuneManagementExtension\Logs"
        if ($computerName) {
            $log = "\\$computerName\" + ($log -replace ":", "$")
        }
        "opening logs in '$log'"
        _openLog (Get-ChildItem $log -File | select -exp fullname)

        # When a PowerShell script is run on the client from Intune, the scripts and the script output will be stored here, but only until execution is complete
        $log = "C:\Program files (x86)\Microsoft Intune Management Extension\Policies\Scripts"
        if ($computerName) {
            $log = "\\$computerName\" + ($log -replace ":", "$")
        }
        "opening logs in '$log'"
        _openLog (Get-ChildItem $log -File -ea SilentlyContinue | select -exp fullname)

        $log = "C:\Program files (x86)\Microsoft Intune Management Extension\Policies\Results"
        if ($computerName) {
            $log = "\\$computerName\" + ($log -replace ":", "$")
        }
        "opening logs in '$log'"
        _openLog (Get-ChildItem $log -File -ea SilentlyContinue | select -exp fullname)

        # open Event Viewer with Intune Log
        "opening event log 'Microsoft-Windows-DeviceManagement-Enterprise-Diagnostics-Provider/Admin'"
        if ($computerName) {
            Write-Warning "Opening remote Event Viewer can take significant time!"
            mmc.exe eventvwr.msc /computer:$computerName /c:"Microsoft-Windows-DeviceManagement-Enterprise-Diagnostics-Provider/Admin"
        } else {
            mmc.exe eventvwr.msc /c:"Microsoft-Windows-DeviceManagement-Enterprise-Diagnostics-Provider/Admin"
        }

        # generate & open MDMDiagReport
        "generating & opening MDMDiagReport"
        if ($computerName) {
            Write-Warning "TODO (zatim delej tak, ze spustis tuto fci lokalne pod uzivatelem, jehoz vysledky chces zjistit"
        } else {
            Start-Process MdmDiagnosticsTool.exe -Wait -ArgumentList "-out $env:TEMP\MDMDiag" -NoNewWindow
            & "$env:TEMP\MDMDiag\MDMDiagReport.html"
        }

        # vygeneruje spoustu bordelu do jednoho zip souboru vhodneho k poslani mailem (bacha muze mit vic jak 5MB)
        # Start-Process MdmDiagnosticsTool.exe -ArgumentList "-area Autopilot;DeviceEnrollment;DeviceProvisioning;TPM -zip C:\temp\aaa.zip" -Verb runas

        # show DM info
        $param = @{
            scriptBlock = { Get-ChildItem -Path HKLM:SOFTWARE\Microsoft\Enrollments -Recurse | where { $_.Property -like "*UPN*" } }
        }
        if ($computerName) {
            $param.computerName = $computerName
        }
        Invoke-Command @param | Format-Table

        # $regKey = "Computer\HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\IntuneManagementExtension\SideCarPolicies\Scripts"
        # if (!(Get-Process regedit)) {
        #     # set starting location for regedit
        #     Set-ItemProperty HKCU:\Software\Microsoft\Windows\CurrentVersion\Applets\Regedit LastKey $regKey
        #     # open regedit
        # } else {
        #     "To check script last run time and result check $regKey in regedit or logs located in C:\Program files (x86)\Microsoft Intune Management Extension\Policies"
        # }
        # regedit.exe
    }

    function Reset-HybridADJoin {
        <#
        .SYNOPSIS
        Function for resetting Hybrid AzureAD join connection.

        .DESCRIPTION
        Function for resetting Hybrid AzureAD join connection.
        It will:
        - un-join computer from AzureAD (using dsregcmd.exe)
        - remove leftover certificates
        - invoke rejoin (using sched. task 'Automatic-Device-Join')
        - inform user about the result

        .PARAMETER computerName
        (optional) name of the computer you want to rejoin.

        .EXAMPLE
        Reset-HybridADJoin

        Un-join and re-join this computer to AzureAD

        .NOTES
        https://www.maximerastello.com/manually-re-register-a-windows-10-or-windows-server-machine-in-hybrid-azure-ad-join/
        #>

        [CmdletBinding()]
        param (
            [string] $computerName
        )

        Write-Warning "For join AzureAD process to work. Computer account has to exists in AzureAD already (should be synchronized via 'AzureAD Connect')!"

        #region helper functions
        function Invoke-AsSystem {
            <#
            .SYNOPSIS
            Function for running specified code under SYSTEM account.

            .DESCRIPTION
            Function for running specified code under SYSTEM account.

            Helper files and sched. tasks are automatically deleted.

            .PARAMETER scriptBlock
            Scriptblock that should be run under SYSTEM account.

            .PARAMETER computerName
            Name of computer, where to run this.

            .PARAMETER returnTranscript
            Add creating of transcript to specified scriptBlock and returns its output.

            .PARAMETER cacheToDisk
            Necessity for long scriptBlocks. Content will be saved to disk and run from there.

            .PARAMETER argument
            If you need to pass some variables to the scriptBlock.
            Hashtable where keys will be names of variables and values will be, well values :)

            Example:
            [hashtable]$Argument = @{
                name = "John"
                cities = "Boston", "Prague"
                hash = @{var1 = 'value1','value11'; var2 = @{ key ='value' }}
            }

            Will in beginning of the scriptBlock define variables:
            $name = 'John'
            $cities = 'Boston', 'Prague'
            $hash = @{var1 = 'value1','value11'; var2 = @{ key ='value' }

            ! ONLY STRING, ARRAY and HASHTABLE variables are supported !

            .PARAMETER runAs
            Let you change if scriptBlock should be running under SYSTEM, LOCALSERVICE or NETWORKSERVICE account.

            Default is SYSTEM.

            .EXAMPLE
            Invoke-AsSystem {New-Item $env:TEMP\abc}

            On local computer will call given scriptblock under SYSTEM account.

            .EXAMPLE
            Invoke-AsSystem {New-Item "$env:TEMP\$name"} -computerName PC-01 -ReturnTranscript -Argument @{name = 'someFolder'} -Verbose

            On computer PC-01 will call given scriptblock under SYSTEM account i.e. will create folder 'someFolder' in C:\Windows\Temp.
            Transcript will be outputted in console too.
            #>

            [CmdletBinding()]
            param (
                [Parameter(Mandatory = $true)]
                [scriptblock] $scriptBlock,

                [string] $computerName,

                [switch] $returnTranscript,

                [hashtable] $argument,

                [ValidateSet('SYSTEM', 'NETWORKSERVICE', 'LOCALSERVICE')]
                [string] $runAs = "SYSTEM",

                [switch] $CacheToDisk
            )

            (Get-Variable runAs).Attributes.Clear()
            $runAs = "NT Authority\$runAs"

            #region prepare Invoke-Command parameters
            # export this function to remote session (so I am not dependant whether it exists there or not)
            $allFunctionDefs = "function Create-VariableTextDefinition { ${function:Create-VariableTextDefinition} }"

            $param = @{
                argumentList = $scriptBlock, $runAs, $CacheToDisk, $allFunctionDefs, $VerbosePreference, $ReturnTranscript, $Argument
            }

            if ($computerName -and $computerName -notmatch "localhost|$env:COMPUTERNAME") {
                $param.computerName = $computerName
            } else {
                if (! ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
                    throw "You don't have administrator rights"
                }
            }
            #endregion prepare Invoke-Command parameters

            Invoke-Command @param -ScriptBlock {
                param ($scriptBlock, $runAs, $CacheToDisk, $allFunctionDefs, $VerbosePreference, $ReturnTranscript, $Argument)

                foreach ($functionDef in $allFunctionDefs) {
                    . ([ScriptBlock]::Create($functionDef))
                }

                $TranscriptPath = "$ENV:TEMP\Invoke-AsSYSTEM_$(Get-Random).log"

                if ($Argument -or $ReturnTranscript) {
                    # define passed variables
                    if ($Argument) {
                        # convert hash to variables text definition
                        $VariableTextDef = Create-VariableTextDefinition $Argument
                    }

                    if ($ReturnTranscript) {
                        # modify scriptBlock to contain creation of transcript
                        $TranscriptStart = "Start-Transcript $TranscriptPath"
                        $TranscriptEnd = 'Stop-Transcript'
                    }

                    $ScriptBlockContent = ($TranscriptStart + "`n`n" + $VariableTextDef + "`n`n" + $ScriptBlock.ToString() + "`n`n" + $TranscriptStop)
                    Write-Verbose "####### SCRIPTBLOCK TO RUN"
                    Write-Verbose $ScriptBlockContent
                    Write-Verbose "#######"
                    $scriptBlock = [Scriptblock]::Create($ScriptBlockContent)
                }

                if ($CacheToDisk) {
                    $ScriptGuid = New-Guid
                    $null = New-Item "$($ENV:TEMP)\$($ScriptGuid).ps1" -Value $ScriptBlock -Force
                    $pwshcommand = "-ExecutionPolicy Bypass -Window Hidden -noprofile -file `"$($ENV:TEMP)\$($ScriptGuid).ps1`""
                } else {
                    $encodedcommand = [Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($ScriptBlock))
                    $pwshcommand = "-ExecutionPolicy Bypass -Window Hidden -noprofile -EncodedCommand $($encodedcommand)"
                }

                $OSLevel = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion").CurrentVersion
                if ($OSLevel -lt 6.2) { $MaxLength = 8190 } else { $MaxLength = 32767 }
                if ($encodedcommand.length -gt $MaxLength -and $CacheToDisk -eq $false) {
                    throw "The encoded script is longer than the command line parameter limit. Please execute the script with the -CacheToDisk option."
                }

                try {
                    #region create&run sched. task
                    $A = New-ScheduledTaskAction -Execute "$($ENV:windir)\system32\WindowsPowerShell\v1.0\powershell.exe" -Argument $pwshcommand
                    if ($runAs -match "\$") {
                        # pod gMSA uctem
                        $P = New-ScheduledTaskPrincipal -UserId $runAs -LogonType Password
                    } else {
                        # pod systemovym uctem
                        $P = New-ScheduledTaskPrincipal -UserId $runAs -LogonType ServiceAccount
                    }
                    $S = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -DontStopOnIdleEnd
                    $taskName = "RunAsSystem_" + (Get-Random)
                    try {
                        $null = New-ScheduledTask -Action $A -Principal $P -Settings $S -ea Stop | Register-ScheduledTask -Force -TaskName $taskName -ea Stop
                    } catch {
                        if ($_ -match "No mapping between account names and security IDs was done") {
                            throw "Account $runAs doesn't exist or cannot be used on $env:COMPUTERNAME"
                        } else {
                            throw "Unable to create helper scheduled task. Error was:`n$_"
                        }
                    }

                    # run scheduled task
                    Start-Sleep -Milliseconds 200
                    Start-ScheduledTask $taskName

                    # wait for sched. task to end
                    Write-Verbose "waiting on sched. task end ..."
                    $i = 0
                    while (((Get-ScheduledTask $taskName -ErrorAction silentlyContinue).state -ne "Ready") -and $i -lt 500) {
                        ++$i
                        Start-Sleep -Milliseconds 200
                    }

                    # get sched. task result code
                    $result = (Get-ScheduledTaskInfo $taskName).LastTaskResult

                    # read & delete transcript
                    if ($ReturnTranscript) {
                        # return just interesting part of transcript
                        if (Test-Path $TranscriptPath) {
                            $transcriptContent = (Get-Content $TranscriptPath -Raw) -Split [regex]::escape('**********************')
                            # return command output
                            ($transcriptContent[2] -split "`n" | Select-Object -Skip 2 | Select-Object -SkipLast 3) -join "`n"

                            Remove-Item $TranscriptPath -Force
                        } else {
                            Write-Warning "There is no transcript, command probably failed!"
                        }
                    }

                    if ($CacheToDisk) { $null = Remove-Item "$($ENV:TEMP)\$($ScriptGuid).ps1" -Force }

                    try {
                        Unregister-ScheduledTask $taskName -Confirm:$false -ea Stop
                    } catch {
                        throw "Unable to unregister sched. task $taskName. Please remove it manually"
                    }

                    if ($result -ne 0) {
                        throw "Command wasn't successfully ended ($result)"
                    }
                    #endregion create&run sched. task
                } catch {
                    throw $_.Exception
                }
            }
        }
        #endregion helper functions

        $allFunctionDefs = "function Invoke-AsSystem { ${function:Invoke-AsSystem} }"

        $param = @{
            scriptblock  = {
                param( $allFunctionDefs )

                $ErrorActionPreference = "Stop"

                foreach ($functionDef in $allFunctionDefs) {
                    . ([ScriptBlock]::Create($functionDef))
                }

                $dsreg = dsregcmd.exe /status
                if (($dsreg | Select-String "DomainJoined :") -match "NO") {
                    throw "Computer is NOT domain joined"
                }

                "Un-joining $env:COMPUTERNAME from Azure"
                Write-Verbose "by running: Invoke-AsSystem { dsregcmd.exe /leave /debug } -returnTranscript"
                Invoke-AsSystem { dsregcmd.exe /leave /debug } #-returnTranscript

                Start-Sleep 5
                Get-ChildItem 'Cert:\LocalMachine\My\' | ? { $_.Issuer -match "MS-Organization-Access|MS-Organization-P2P-Access \[\d+\]" } | % {
                    Write-Host "Removing leftover Hybrid-Join certificate $($_.DnsNameList.Unicode)" -ForegroundColor Cyan
                    Remove-Item $_.PSPath
                }

                $dsreg = dsregcmd.exe /status
                if (!(($dsreg | Select-String "AzureAdJoined :") -match "NO")) {
                    throw "$env:COMPUTERNAME is still joined to Azure. Run again"
                }

                # join computer to Azure again
                "Joining $env:COMPUTERNAME to Azure"
                Write-Verbose "by running: Get-ScheduledTask -TaskName Automatic-Device-Join | Start-ScheduledTask"
                Get-ScheduledTask -TaskName "Automatic-Device-Join" | Start-ScheduledTask
                while ((Get-ScheduledTask "Automatic-Device-Join" -ErrorAction silentlyContinue).state -ne "Ready") {
                    Start-Sleep 1
                    "Waiting for sched. task 'Automatic-Device-Join' to complete"
                }
                if ((Get-ScheduledTask -TaskName "Automatic-Device-Join" | Get-ScheduledTaskInfo | select -exp LastTaskResult) -ne 0) {
                    throw "Sched. task Automatic-Device-Join failed. Is $env:COMPUTERNAME synchronized to AzureAD?"
                }

                # check certificates
                "Waiting for certificate creation"
                $i = 30
                Write-Verbose "two certificates should be created in Computer Personal cert. store (issuer: MS-Organization-Access, MS-Organization-P2P-Access [$(Get-Date -Format yyyy)]"

                Start-Sleep 3

                while (!($hybridJoinCert = Get-ChildItem 'Cert:\LocalMachine\My\' | ? { $_.Issuer -match "MS-Organization-Access|MS-Organization-P2P-Access \[\d+\]" }) -and $i -gt 0) {
                    Start-Sleep 3
                    --$i
                    $i
                }

                # check AzureAd join status
                $dsreg = dsregcmd.exe /status
                if (($dsreg | Select-String "AzureAdJoined :") -match "YES") {
                    ++$AzureAdJoined
                }

                if ($hybridJoinCert -and $AzureAdJoined) {
                    "$env:COMPUTERNAME was successfully joined to AAD again."
                } else {
                    $problem = @()

                    if (!$AzureAdJoined) {
                        $problem += " - computer is not AzureAD joined"
                    }

                    if (!$hybridJoinCert) {
                        $problem += " - certificates weren't created"
                    }

                    Write-Error "Join wasn't successful:`n$($problem -join "`n")"
                    Write-Warning "Check if device $env:COMPUTERNAME exists in AAD"
                    Write-Warning "Run:`ngpupdate /force /target:computer"
                    Write-Warning "You can get failure reason via manual join by running: Invoke-AsSystem -scriptBlock {dsregcmd /join /debug} -returnTranscript"
                    throw 1
                }
            }
            argumentList = $allFunctionDefs
        }

        if ($computerName -and $computerName -notin "localhost", $env:COMPUTERNAME) {
            $param.computerName = $computerName
        } else {
            if (! ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
                throw "You don't have administrator rights"
            }
        }

        Invoke-Command @param
    }

    function Get-IntuneEnrollmentStatus {
        <#
        .SYNOPSIS
        Function for checking whether computer is managed by Intune (fulfill all requirements).

        .DESCRIPTION
        Function for checking whether computer is managed by Intune (fulfill all requirements).
        What is checked:
        - device is AAD joined
        - device is joined to Intune
        - device has valid Intune certificate
        - device has Intune sched. tasks
        - device has Intune registry keys
        - Intune service exists

        Returns true or false.

        .PARAMETER computerName
        (optional) name of the computer to check.

        .PARAMETER checkIntuneToo
        Switch for checking Intune part too (if device is listed there).

        .EXAMPLE
        Get-IntuneEnrollmentStatus

        Check Intune status on local computer.

        .EXAMPLE
        Get-IntuneEnrollmentStatus -computerName ae-50-pc

        Check Intune status on computer ae-50-pc.

        .EXAMPLE
        Get-IntuneEnrollmentStatus -computerName ae-50-pc -checkIntuneToo

        Check Intune status on computer ae-50-pc, plus connects to Intune and check whether ae-50-pc exists there.
        #>

        [CmdletBinding()]
        param (
            [string] $computerName,

            [switch] $checkIntuneToo
        )

        if (!$computerName) { $computerName = $env:COMPUTERNAME }

        #region get Intune data
        if ($checkIntuneToo) {
            $ErrActionPreference = $ErrorActionPreference
            $ErrorActionPreference = "Stop"

            try {
                if (Get-Command Get-ADComputer -ErrorAction SilentlyContinue) {
                    $ADObj = Get-ADComputer -Filter "Name -eq '$computerName'" -Properties Name, ObjectGUID
                } else {
                    Write-Verbose "Get-ADComputer command is missing, unable to get device GUID"
                }

                Connect-Graph

                $intuneObj = @()

                $intuneObj += Get-IntuneManagedDevice -Filter "DeviceName eq '$computerName'"

                if ($ADObj.ObjectGUID) {
                    # because of bug? computer can be listed under guid_date name in cloud
                    $intuneObj += Get-IntuneManagedDevice -Filter "azureADDeviceId eq '$($ADObj.ObjectGUID)'" | ? DeviceName -NE $computerName
                }
            } catch {
                Write-Warning "Unable to get information from Intune. $_"

                # to avoid errors that device is missing from Intune
                $intuneObj = 1
            }

            $ErrorActionPreference = $ErrActionPreference
        }
        #endregion get Intune data

        $scriptBlock = {
            param ($checkIntuneToo, $intuneObj)

            $intuneNotJoined = 0

            #region Intune checks
            if ($checkIntuneToo) {
                if (!$intuneObj) {
                    ++$intuneNotJoined
                    Write-Warning "Device is missing from Intune!"
                }

                if ($intuneObj.count -gt 1) {
                    Write-Warning "Device is listed $($intuneObj.count) times in Intune"
                }

                $wrongIntuneName = $intuneObj.DeviceName | ? { $_ -ne $env:COMPUTERNAME }
                if ($wrongIntuneName) {
                    Write-Warning "Device is named as $wrongIntuneName in Intune"
                }

                $correctIntuneName = $intuneObj.DeviceName | ? { $_ -eq $env:COMPUTERNAME }
                if ($intuneObj -and !$correctIntuneName) {
                    ++$intuneNotJoined
                    Write-Warning "Device has no record in Intune with correct device name"
                }
            }
            #endregion Intune checks

            #region dsregcmd checks
            $dsregcmd = dsregcmd.exe /status
            $azureAdJoined = $dsregcmd | Select-String "AzureAdJoined : YES"
            if (!$azureAdJoined) {
                ++$intuneNotJoined
                Write-Warning "Device is NOT AAD joined"
            }

            $tenantName = $dsregcmd | Select-String "TenantName : .+"
            $MDMUrl = $dsregcmd | Select-String "MdmUrl : .+"
            if (!$tenantName -or !$MDMUrl) {
                ++$intuneNotJoined
                Write-Warning "Device is NOT Intune joined"
            }
            #endregion dsregcmd checks

            #region certificate checks
            $MDMCert = Get-ChildItem 'Cert:\LocalMachine\My\' | ? Issuer -EQ "CN=Microsoft Intune MDM Device CA"
            if (!$MDMCert) {
                ++$intuneNotJoined
                Write-Warning "Intune certificate is missing"
            } elseif ($MDMCert.NotAfter -lt (Get-Date) -or $MDMCert.NotBefore -gt (Get-Date)) {
                ++$intuneNotJoined
                Write-Warning "Intune certificate isn't valid"
            }
            #endregion certificate checks

            #region sched. task checks
            $MDMSchedTask = Get-ScheduledTask | ? { $_.TaskPath -like "*Microsoft*Windows*EnterpriseMgmt\*" -and $_.TaskName -eq "PushLaunch" }
            $enrollmentGUID = $MDMSchedTask | Select-Object -ExpandProperty TaskPath -Unique | ? { $_ -like "*-*-*" } | Split-Path -Leaf
            if (!$enrollmentGUID) {
                ++$intuneNotJoined
                Write-Warning "Synchronization sched. task is missing"
            }
            #endregion sched. task checks

            #region registry checks
            if ($enrollmentGUID) {
                $missingRegKey = @()
                $registryKeys = "HKLM:\SOFTWARE\Microsoft\Enrollments", "HKLM:\SOFTWARE\Microsoft\Enrollments\Status", "HKLM:\SOFTWARE\Microsoft\EnterpriseResourceManager\Tracked", "HKLM:\SOFTWARE\Microsoft\PolicyManager\AdmxInstalled", "HKLM:\SOFTWARE\Microsoft\PolicyManager\Providers", "HKLM:\SOFTWARE\Microsoft\Provisioning\OMADM\Accounts", "HKLM:\SOFTWARE\Microsoft\Provisioning\OMADM\Logger", "HKLM:\SOFTWARE\Microsoft\Provisioning\OMADM\Sessions"
                foreach ($key in $registryKeys) {
                    if (!(Get-ChildItem -Path $key -ea SilentlyContinue | Where-Object { $_.Name -match $enrollmentGUID })) {
                        Write-Warning "Registry key $key is missing"
                        ++$intuneNotJoined
                    }
                }
            }
            #endregion registry checks

            #region service checks
            $MDMService = Get-Service -Name IntuneManagementExtension -ErrorAction SilentlyContinue
            if (!$MDMService) {
                ++$intuneNotJoined
                Write-Warning "Intune service IntuneManagementExtension is missing"
            }
            if ($MDMService -and $MDMService.Status -ne "Running") {
                Write-Warning "Intune service IntuneManagementExtension is not running"
            }
            #endregion service checks

            if ($intuneNotJoined) {
                return $false
            } else {
                return $true
            }
        }

        $param = @{
            scriptBlock  = $scriptBlock
            argumentList = $checkIntuneToo, $intuneObj
        }
        if ($computerName -and $computerName -notin "localhost", $env:COMPUTERNAME) {
            $param.computerName = $computerName
        }

        Invoke-Command @param
    }
    #endregion helper functions

    Write-Host "Checking actual Intune connection status" -ForegroundColor Cyan
    if (Get-IntuneEnrollmentStatus -computerName $computerName) {
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
    Invoke-MDMReenrollment -computerName $computerName -asSystem

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