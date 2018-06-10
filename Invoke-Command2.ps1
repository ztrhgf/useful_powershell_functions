function Invoke-Command2 {
    [CmdletBinding(DefaultParameterSetName = 'InProcess', HelpUri = 'https://go.microsoft.com/fwlink/?LinkID=135225', RemotingCapability = 'OwnedByCommand')]
    param(
        [Parameter(ParameterSetName = 'FilePathRunspace', Position = 0)]
        [Parameter(ParameterSetName = 'Session', Position = 0)]
        [ValidateNotNullOrEmpty()]
        [System.Management.Automation.Runspaces.PSSession[]]
        ${Session},

        [Parameter(ParameterSetName = 'ComputerName', Position = 0)]
        [Parameter(ParameterSetName = 'FilePathComputerName', Position = 0)]
        [Alias('Cn')]
        [ValidateNotNullOrEmpty()]
        [string[]]
        ${ComputerName},

        [Parameter(ParameterSetName = 'FilePathComputerName', ValueFromPipelineByPropertyName = $true)]
        [Parameter(ParameterSetName = 'Uri', ValueFromPipelineByPropertyName = $true)]
        [Parameter(ParameterSetName = 'ComputerName', ValueFromPipelineByPropertyName = $true)]
        [Parameter(ParameterSetName = 'FilePathUri', ValueFromPipelineByPropertyName = $true)]
        [Parameter(ParameterSetName = 'VMId', Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
        [Parameter(ParameterSetName = 'VMName', Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
        [Parameter(ParameterSetName = 'FilePathVMId', Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
        [Parameter(ParameterSetName = 'FilePathVMName', Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
        [pscredential]
        [System.Management.Automation.CredentialAttribute()]
        ${Credential},

        [Parameter(ParameterSetName = 'ComputerName')]
        [Parameter(ParameterSetName = 'FilePathComputerName')]
        [ValidateRange(1, 65535)]
        [int]
        ${Port},

        [Parameter(ParameterSetName = 'FilePathComputerName')]
        [Parameter(ParameterSetName = 'ComputerName')]
        [switch]
        ${UseSSL},

        [Parameter(ParameterSetName = 'VMId', ValueFromPipelineByPropertyName = $true)]
        [Parameter(ParameterSetName = 'Uri', ValueFromPipelineByPropertyName = $true)]
        [Parameter(ParameterSetName = 'FilePathComputerName', ValueFromPipelineByPropertyName = $true)]
        [Parameter(ParameterSetName = 'FilePathUri', ValueFromPipelineByPropertyName = $true)]
        [Parameter(ParameterSetName = 'ContainerId', ValueFromPipelineByPropertyName = $true)]
        [Parameter(ParameterSetName = 'ComputerName', ValueFromPipelineByPropertyName = $true)]
        [Parameter(ParameterSetName = 'VMName', ValueFromPipelineByPropertyName = $true)]
        [Parameter(ParameterSetName = 'FilePathContainerId', ValueFromPipelineByPropertyName = $true)]
        [Parameter(ParameterSetName = 'FilePathVMId', ValueFromPipelineByPropertyName = $true)]
        [Parameter(ParameterSetName = 'FilePathVMName', ValueFromPipelineByPropertyName = $true)]
        [string]
        ${ConfigurationName},

        [Parameter(ParameterSetName = 'ComputerName', ValueFromPipelineByPropertyName = $true)]
        [Parameter(ParameterSetName = 'FilePathComputerName', ValueFromPipelineByPropertyName = $true)]
        [string]
        ${ApplicationName},

        [Parameter(ParameterSetName = 'FilePathVMId')]
        [Parameter(ParameterSetName = 'Session')]
        [Parameter(ParameterSetName = 'Uri')]
        [Parameter(ParameterSetName = 'FilePathComputerName')]
        [Parameter(ParameterSetName = 'FilePathRunspace')]
        [Parameter(ParameterSetName = 'FilePathUri')]
        [Parameter(ParameterSetName = 'VMId')]
        [Parameter(ParameterSetName = 'VMName')]
        [Parameter(ParameterSetName = 'ContainerId')]
        [Parameter(ParameterSetName = 'ComputerName')]
        [Parameter(ParameterSetName = 'FilePathVMName')]
        [Parameter(ParameterSetName = 'FilePathContainerId')]
        [int]
        ${ThrottleLimit},

        [Parameter(ParameterSetName = 'Uri', Position = 0)]
        [Parameter(ParameterSetName = 'FilePathUri', Position = 0)]
        [Alias('URI', 'CU')]
        [ValidateNotNullOrEmpty()]
        [uri[]]
        ${ConnectionUri},

        [Parameter(ParameterSetName = 'ComputerName')]
        [Parameter(ParameterSetName = 'Session')]
        [Parameter(ParameterSetName = 'Uri')]
        [Parameter(ParameterSetName = 'FilePathComputerName')]
        [Parameter(ParameterSetName = 'FilePathRunspace')]
        [Parameter(ParameterSetName = 'FilePathUri')]
        [Parameter(ParameterSetName = 'VMId')]
        [Parameter(ParameterSetName = 'VMName')]
        [Parameter(ParameterSetName = 'ContainerId')]
        [Parameter(ParameterSetName = 'FilePathVMId')]
        [Parameter(ParameterSetName = 'FilePathVMName')]
        [Parameter(ParameterSetName = 'FilePathContainerId')]
        [switch]
        ${AsJob},

        [Parameter(ParameterSetName = 'ComputerName')]
        [Parameter(ParameterSetName = 'FilePathComputerName')]
        [Parameter(ParameterSetName = 'Uri')]
        [Parameter(ParameterSetName = 'FilePathUri')]
        [Alias('Disconnected')]
        [switch]
        ${InDisconnectedSession},

        [Parameter(ParameterSetName = 'FilePathComputerName')]
        [Parameter(ParameterSetName = 'ComputerName')]
        [ValidateNotNullOrEmpty()]
        [string[]]
        ${SessionName},

        [Parameter(ParameterSetName = 'FilePathUri')]
        [Parameter(ParameterSetName = 'Session')]
        [Parameter(ParameterSetName = 'Uri')]
        [Parameter(ParameterSetName = 'FilePathComputerName')]
        [Parameter(ParameterSetName = 'FilePathRunspace')]
        [Parameter(ParameterSetName = 'ComputerName')]
        [Parameter(ParameterSetName = 'VMId')]
        [Parameter(ParameterSetName = 'VMName')]
        [Parameter(ParameterSetName = 'ContainerId')]
        [Parameter(ParameterSetName = 'FilePathVMId')]
        [Parameter(ParameterSetName = 'FilePathVMName')]
        [Parameter(ParameterSetName = 'FilePathContainerId')]
        [Alias('HCN')]
        [switch]
        ${HideComputerName},

        [Parameter(ParameterSetName = 'Session')]
        [Parameter(ParameterSetName = 'ComputerName')]
        [Parameter(ParameterSetName = 'Uri')]
        [Parameter(ParameterSetName = 'FilePathComputerName')]
        [Parameter(ParameterSetName = 'FilePathRunspace')]
        [Parameter(ParameterSetName = 'FilePathUri')]
        [Parameter(ParameterSetName = 'ContainerId')]
        [Parameter(ParameterSetName = 'FilePathContainerId')]
        [string]
        ${JobName},

        [Parameter(ParameterSetName = 'Session', Mandatory = $true, Position = 1)]
        [Parameter(ParameterSetName = 'ComputerName', Mandatory = $true, Position = 1)]
        [Parameter(ParameterSetName = 'Uri', Mandatory = $true, Position = 1)]
        [Parameter(ParameterSetName = 'InProcess', Mandatory = $true, Position = 0)]
        [Parameter(ParameterSetName = 'VMId', Mandatory = $true, Position = 1)]
        [Parameter(ParameterSetName = 'VMName', Mandatory = $true, Position = 1)]
        [Parameter(ParameterSetName = 'ContainerId', Mandatory = $true, Position = 1)]
        [Alias('Command')]
        [ValidateNotNull()]
        [scriptblock]
        ${ScriptBlock},

        [Parameter(ParameterSetName = 'InProcess')]
        [switch]
        ${NoNewScope},

        [Parameter(ParameterSetName = 'FilePathVMName', Mandatory = $true, Position = 1)]
        [Parameter(ParameterSetName = 'FilePathRunspace', Mandatory = $true, Position = 1)]
        [Parameter(ParameterSetName = 'FilePathUri', Mandatory = $true, Position = 1)]
        [Parameter(ParameterSetName = 'FilePathVMId', Mandatory = $true, Position = 1)]
        [Parameter(ParameterSetName = 'FilePathComputerName', Mandatory = $true, Position = 1)]
        [Parameter(ParameterSetName = 'FilePathContainerId', Mandatory = $true, Position = 1)]
        [Alias('PSPath')]
        [ValidateNotNull()]
        [string]
        ${FilePath},

        [Parameter(ParameterSetName = 'Uri')]
        [Parameter(ParameterSetName = 'FilePathUri')]
        [switch]
        ${AllowRedirection},

        [Parameter(ParameterSetName = 'ComputerName')]
        [Parameter(ParameterSetName = 'Uri')]
        [Parameter(ParameterSetName = 'FilePathComputerName')]
        [Parameter(ParameterSetName = 'FilePathUri')]
        [System.Management.Automation.Remoting.PSSessionOption]
        ${SessionOption},

        [Parameter(ParameterSetName = 'ComputerName')]
        [Parameter(ParameterSetName = 'FilePathComputerName')]
        [Parameter(ParameterSetName = 'Uri')]
        [Parameter(ParameterSetName = 'FilePathUri')]
        [System.Management.Automation.Runspaces.AuthenticationMechanism]
        ${Authentication},

        [Parameter(ParameterSetName = 'FilePathUri')]
        [Parameter(ParameterSetName = 'FilePathComputerName')]
        [Parameter(ParameterSetName = 'Uri')]
        [Parameter(ParameterSetName = 'ComputerName')]
        [switch]
        ${EnableNetworkAccess},

        [Parameter(ParameterSetName = 'FilePathContainerId')]
        [Parameter(ParameterSetName = 'ContainerId')]
        [switch]
        ${RunAsAdministrator},

        [Parameter(ValueFromPipeline = $true)]
        [psobject]
        ${InputObject},

        [Alias('Args')]
        [System.Object[]]
        ${ArgumentList},

        [Parameter(ParameterSetName = 'FilePathVMId', Mandatory = $true, Position = 0, ValueFromPipelineByPropertyName = $true)]
        [Parameter(ParameterSetName = 'VMId', Mandatory = $true, Position = 0, ValueFromPipelineByPropertyName = $true)]
        [Alias('VMGuid')]
        [ValidateNotNullOrEmpty()]
        [guid[]]
        ${VMId},

        [Parameter(ParameterSetName = 'FilePathVMName', Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
        [Parameter(ParameterSetName = 'VMName', Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
        [ValidateNotNullOrEmpty()]
        [string[]]
        ${VMName},

        [Parameter(ParameterSetName = 'ContainerId', Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
        [Parameter(ParameterSetName = 'FilePathContainerId', Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
        [ValidateNotNullOrEmpty()]
        [string[]]
        ${ContainerId},

        [Parameter(ParameterSetName = 'ComputerName')]
        [Parameter(ParameterSetName = 'Uri')]
        [string]
        ${CertificateThumbprint})

    begin {
        # umozneni zadat hostname do ComputerName parametru (jinak konci chybou access denied)
        # je potreba hostname nahradit za localhost a povolit parametr EnableNetworkAccess
        if ($PSBoundParameters.computerName) {
            $computers = {$PSBoundParameters.computerName.ToLower()}.invoke() # prevedu na pole ze ktereho se daji odstranovat prvky
        }
        
        if ($computers.Count -eq 1 -and $Computers[0] -eq $env:COMPUTERNAME) {
            # spoustim pouze vuci sobe samemu
            # odstranim parametr computerName, aby fungovalo i na strojich bez povoleneho ps remotingu

            Write-Verbose "ComputerName obsahoval pouze jmeno tohoto stroje, odstranil jsem, aby neskoncilo chybou access denied"
            $null = $PSBoundParameters.remove("computerName")
        } else {
            # spoustim vuci vice strojum nebo vuci nejakemu remote stroji
            # pokud seznam obsahuje i muj hostname (ci jeho fqdn variantu), tak je odstranim a pridam misto toho localhost + povolim enableNetworkAccess
            # takto pujde spustit i vuci tomuto stroji (ale nefunguje pokud neni povolen ps remoting!)

            $loopback = $env:COMPUTERNAME.ToLower()
            $loopback2 = $env:COMPUTERNAME.ToLower() + ".fi.muni.cz"
            $loopback3 = $env:COMPUTERNAME.ToLower() + ".ad.fi.muni.cz"
            if ($computers -and ($computers.Contains($loopback) -or $computers.Contains($loopback2) -or $computers.Contains($loopback3))) {
                Write-Verbose "ComputerName obsahoval $loopback, nahradim jej za localhost a povolim EnableNetworkAccess"
                $null = $computers.Remove($loopback)
                $null = $computers.Remove($loopback2)
                $null = $computers.Remove($loopback3)
                $null = $computers.Add('localhost')
                $PSBoundParameters.computerName = $computers
            }

            if ($computers -and $computers.Contains('localhost')) {
                $PSBoundParameters.EnableNetworkAccess = $true
            }
        }

        try {
            $outBuffer = $null
            if ($PSBoundParameters.TryGetValue('OutBuffer', [ref]$outBuffer)) {
                $PSBoundParameters['OutBuffer'] = 1
            }
            $wrappedCmd = $ExecutionContext.InvokeCommand.GetCommand('Microsoft.PowerShell.Core\Invoke-Command', [System.Management.Automation.CommandTypes]::Cmdlet)
            $scriptCmd = {& $wrappedCmd @PSBoundParameters }
            $steppablePipeline = $scriptCmd.GetSteppablePipeline($myInvocation.CommandOrigin)
            $steppablePipeline.Begin($PSCmdlet)
        } catch {
            throw
        }
    }

    process {
        try {
            $steppablePipeline.Process($_)
        } catch {
            throw
        }
    }

    end {
        try {
            $steppablePipeline.End()
        } catch {
            throw
        }
    }
    <#

    .ForwardHelpTargetName Microsoft.PowerShell.Core\Invoke-Command
    .ForwardHelpCategory Cmdlet

    #>

}