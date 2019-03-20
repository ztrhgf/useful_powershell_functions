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
        ${CertificateThumbprint}
    )

    begin {
        # povoleni verbose vystupu pokud byl explicitne vyzadan switchem -verbose pri volani teto nebo nadrazene funkce
        $MyName = $MyInvocation.MyCommand.Name
        $lastCaller = Get-PSCallStack | where {$_.Command -ne $MyName -and $_.command -ne "<ScriptBlock>"} | select -Last 1
        if ($PSBoundParameters.verbose -or $lastCaller.arguments -like '*Verbose=True*') {
            Write-Debug "povolim verbose vypis v Invoke-Command2 i uvnitr jim vykonavaneho scriptblocku"

            # povoleni verbose v Invoke-Command
            $VerbosePreference = 'continue'

            # povoleni verbose ve scriptblocku, ktery se ma na strojich vykonat
            # a to co nejdriv, ale zaroven, abych nerozbil jeho strukturu
            # tzn zkusim pridat do begin, process ci end bloku
            # pokud ani jeden z nich neni definovan, tak pridam pred text scriptblocku, ale vzdy az za definici parametru
            $scriptBlockText = $ScriptBlock.tostring()
            $paramBlockText = $scriptBlock.ast.Paramblock.Extent.Text
            $dynamicParamBlock = $scriptBlock.ast.DynamicParamblock.Extent.Text
            $scriptRequirements = $scriptBlock.ast.ScriptRequirements.Extent.Text
            $beginBlockText = $scriptBlock.ast.BeginBlock.Extent.Text                
            $processBlockText = $scriptBlock.ast.ProcessBlock.Extent.Text
            $endBlockText = $scriptBlock.ast.EndBlock.Extent.Text

            if ($beginBlockText) {
                # je definovan BEGIN blok, verbose povolim v nem
                Write-Debug "verbose povolim v begin bloku"
                [regex]$pattern = "(BEGIN)?\s*{"
                $string = $pattern.replace($scriptBlockText, "BEGIN {`$VerbosePreference = 'continue'`n", 1) # nahradim pouze prvni vyskyt
    #TODO udelat nejak lip, pattern.replace je case sensitive proto pokud je BEGIN napr malym, tak vynecha pri replace == je tam 2x
    $string = $string -replace "beginbegin\s*{", "BEGIN {"
                #$string  = $scriptBlockText -replace "^(BEGIN)?\s*{", "BEGIN {`$VerbosePreference = 'continue'`n" # vim, ze kod musi byt uzavren v {}
            } elseif ($processBlockText) {
                # neni BEGIN blok, ale je PROCESS blok, verbose povolim v nem
                Write-Debug "verbose povolim v process bloku"
                [regex]$pattern = "(PROCESS)?\s*{"
                $string = $pattern.replace($scriptBlockText, "PROCESS {`$VerbosePreference = 'continue'`n", 1) # nahradim pouze prvni vyskyt
    #TODO udelat nejak lip, pattern.replace je case sensitive proto pokud je PROCESS napr malym, tak vynecha pri replace == je tam 2x
    $string = $string -replace "processprocess\s*{", "PROCESS {"
            } elseif ($endBlockText) {
                # je definovan pouze END blok, verbose povolim v nem
                Write-Debug "verbose povolim v end bloku"
                [regex]$pattern = [Regex]::Escape($scriptRequirements)
                $endBlockTextWithoutParam = $pattern.replace($scriptBlockText, '', 1) # nahradim pouze prvni vyskyt
                [regex]$pattern = [Regex]::Escape($paramBlockText)
                $endBlockTextWithoutParam = $pattern.replace($endBlockTextWithoutParam, '', 1) # nahradim pouze prvni vyskyt
                [regex]$pattern = [Regex]::Escape($dynamicParamBlock)
                $endBlockTextWithoutParam = $pattern.replace($endBlockTextWithoutParam, '', 1) # nahradim pouze prvni vyskyt
                $endBlockTextWithoutParam = $endBlockTextWithoutParam -replace "^;*" -replace "^\s*"
                if ($endBlockTextWithoutParam -match '^END|^{') {
                    # END block je uzavren ve scriptblocku {}
                    Write-Debug "je uzavren ve scriptblock"
                    [regex]$pattern = "(END)?\s*{"
                    $string = $pattern.replace($scriptBlockText, "END {`$VerbosePreference = 'continue'`n", 1) # nahradim pouze prvni vyskyt
    #TODO udelat nejak lip, pattern.replace je case sensitive proto pokud je END napr malym, tak vynecha pri replace == je tam 2x
    # END tam zaroven byt musi, jinak se bere jako scriptblock a vnitrek se nevykona
    $string = $string -replace "endend\s*{", "END {"
                } else {
                    # END blok neni uzavren ve scriptblocku {}
                    Write-Debug "neni uzavren ve scriptblock"
                    if ($paramBlockText -or $dynamicParamBlock) {
                        # END blok zacina param blokem == povoleni verbose musim dat az za nej
                        Write-Debug "zacina param() blokem"
                        $string = $scriptRequirements + "`n" + $paramBlockText + "`n" + $dynamicParamBlock + "`n" + '$VerbosePreference = "continue"' + "`n" + $endBlockTextWithoutParam
                    } else {
                        # END blok nezacina param blokem a neni uzavren ve scriptblocku {}
                        Write-Debug "nezacina param() blokem"
                        $string  = '$VerbosePreference = "continue"' + "`n" + $scriptBlockText
                    }
                }
            } else {
                throw "Invoke-Command2: nemelo by nastat"
            }

            Write-Debug "po uprave mam:`n$string"
            $PSBoundParameters.scriptBlock = [scriptblock]::Create($string)
        } # konec povoleni verbose

        if ($PSBoundParameters.computerName) {
            $computers = {$PSBoundParameters.computerName.ToLower()}.invoke() # prevedu na Collection`1 (umoznuje odstranovat prvky)

            # pokud seznam obsahuje i muj hostname (ci jeho fqdn variantu), tak je odstranim a pridam misto toho localhost + povolim enableNetworkAccess
            # takto pujde spustit i vuci sobe samemu, jinak by Invoke-Command skoncil chybou Access Denied
            # (ale ani po teto uprave nebude fungovat, pokud neni na tomto stroji povolen ps remoting!)
            $myself = $env:COMPUTERNAME.ToLower() # kronos
            $myself2 = $myself + ".fi.muni.cz" # kronos.fi.muni.cz
            $myself3 = $myself + "." + $env:USERDNSDOMAIN # kronos.ad.fi.muni.cz
            if ($computers.Contains($myself) -or $computers.Contains($myself2) -or $computers.Contains($myself3)) {
                Write-Verbose "ComputerName obsahoval $myself, nahradim jej za localhost"
                $null = $computers.Remove($myself)
                $null = $computers.Remove($myself2)
                $null = $computers.Remove($myself3)
                $null = $computers.Add('localhost')
            }

            # spustim pouze vuci pingajicim strojum a upozornim na nepingajici
            if (($computers.Count -eq 1 -and $Computers[0] -ne $env:COMPUTERNAME) -or ($computers.Count -gt 1)) {
                # spoustim vuci nejakemu remote stroji ci vice strojum
                try {
                    $computersStatus = Test-Connection2 $computers -ErrorAction Stop
                } catch {
                    throw "Prikaz Test-Connection2 neexistuje nebo skoncil chybou:`n$_"
                }
        
                if ($offline = $computersStatus | Where-Object {$_.result -ne 'Success'} | select-Object -ExpandProperty ComputerName) {
                    if ($offline.count -eq $computers.count) {
                        Write-Warning "Zadny ze stroju neni online."
                        return ''
                    } else {
                        Write-Warning "Nasledujici stroje jsou offline: $($offline -join ', ')"
                    }

                    # v seznamu ponecham pouze online stroje
                    $computers = {$computersStatus | Where-Object {$_.result -eq 'Success'} | select-Object -ExpandProperty ComputerName}.invoke() # prevedu na Collection`1 (umoznuje odstranovat prvky)
                    # ulozim zpet do parametru
                    $PSBoundParameters.computerName = $computers
                }
            }

            # nastavim vysledne stroje zpatky do Computername parametru Invoke-Commandu
            $PSBoundParameters.computerName = $computers

            if ($computers.Count -eq 1 -and $computers.Contains('localhost') -and $PSBoundParameters.AsJob -ne $true) {
                # spoustim pouze vuci sobe samemu a neni pouzit asJob switch
                Write-Verbose "ComputerName obsahoval pouze jmeno tohoto stroje, odstranil jsem, aby neskoncilo chybou access denied"
                $null = $PSBoundParameters.remove("computerName")
            }

            if ($computers.Count -gt 1 -and $computers.Contains('localhost')) {
                # spoustim vuci sobe samemu a nejakym dalsim strojum
                Write-Verbose "ComputerName obsahuje take localhost = povolim EnableNetworkAccess"
                $PSBoundParameters.EnableNetworkAccess = $true
            }

            # odstranim prepinac HideComputerName pokud spoustim pouze vuci sobe samemu
            if ($computers.Count -eq 1 -and $computers.Contains('localhost')) {
                Write-Verbose "ComputerName obsahuje pouze localhost = odstranim HideComputerName"
                $null = $PSBoundParameters.remove("HideComputerName")
            }
        } # konec if ($PSBoundParameters.computerName)
    
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
        if ($steppablePipeline) {
            try {
                $steppablePipeline.Process($_)
            } catch {
                throw
            }
        }
    }

    end {
        if ($steppablePipeline) {
            try {
                $steppablePipeline.End()
            } catch {
                throw
            }   
        }
    }
    <#

.ForwardHelpTargetName Microsoft.PowerShell.Core\Invoke-Command
.ForwardHelpCategory Cmdlet

#>

}