function Test-Port {
    <#
    .SYNOPSIS
        This function tests for open TCP/UDP ports.
    .DESCRIPTION
        This function tests any TCP/UDP port to see if it's open or closed.
    .NOTES
        Known Issue: If this function is called within 10-20 consecutively on the same port
            and computer, the UDP port check will output $false when it can be
            $true.  I haven't figured out why it does this.
    .PARAMETER Computername
        One or more remote, comma-separated computer names
    .PARAMETER Port
        One or more comma-separated port numbers you'd like to test.
    .PARAMETER Protocol
        The protocol (UDP or TCP) that you'll be testing
    .PARAMETER TcpTimeout
        The number of milliseconds that the function will wait until declaring
        the TCP port closed.
    .PARAMETER
        The number of millieconds that the function will wait until declaring
        the UDP port closed.
    .EXAMPLE
        PS> Test-Port -Computername 'LABDC','LABDC2' -Protocol TCP 80,443
         
        This example tests the TCP network ports 80 and 443 on both the LABDC
        and LABDC2 servers.
    #>
    [CmdletBinding(DefaultParameterSetName='TCP')]
    [OutputType([System.Management.Automation.PSCustomObject])]
    param (
        [Parameter(Mandatory=$true,Position=0,ValueFromPipeline=$true,ValueFromPipelineByPropertyName=$true,HelpMessage="zadej jmeno stroje/ů")]
        [string[]]$ComputerName
		,
        [Parameter(Mandatory=$true,Position=1)]
        [int[]]$Port
		,
        [Parameter(Mandatory=$false,Position=2)]
        [ValidateSet('TCP', 'UDP')]
        [string]$Protocol="TCP"
		,
        [Parameter(ParameterSetName='TCP')]
        [int]$TcpTimeout = 1000
		,
        [Parameter(ParameterSetName = 'UDP')]
        [int]$UdpTimeout = 1000
    )
    process {
        foreach ($Computer in $ComputerName) {
            foreach ($Portx in $Port) {
                $Output = @{ 'Computername' = $Computer; 'Port' = $Portx; 'Protocol' = $Protocol; 'Result' = '' }
                Write-Verbose "$($MyInvocation.MyCommand.Name) - Beginning port test on '$Computer' on port '$Protocol`:$Portx'"
                if ($Protocol -eq 'TCP') {
                    $TcpClient = New-Object System.Net.Sockets.TcpClient
                    $Connect = $TcpClient.BeginConnect($Computer, $Portx, $null, $null)
                    $Wait = $Connect.AsyncWaitHandle.WaitOne($TcpTimeout, $false)
                    if (!$Wait) {
                        $TcpClient.Close()
                        Write-Verbose "$($MyInvocation.MyCommand.Name) - '$Computer' failed port test on port '$Protocol`:$Portx'"
                        $Output.Result = $false
                    } else {
                        $TcpClient.EndConnect($Connect)
                        $TcpClient.Close()
                        Write-Verbose "$($MyInvocation.MyCommand.Name) - '$Computer' passed port test on port '$Protocol`:$Portx'"
                        $Output.Result = $true
                    }
                    $TcpClient.Close()
                    $TcpClient.Dispose()
                } elseif ($Protocol -eq 'UDP') {
                    $UdpClient = New-Object System.Net.Sockets.UdpClient
                    $UdpClient.Client.ReceiveTimeout = $UdpTimeout
                    $UdpClient.Connect($Computer, $Portx)
                    Write-Verbose "$($MyInvocation.MyCommand.Name) - Sending UDP message to computer '$Computer' on port '$Portx'"
                    $a = new-object system.text.asciiencoding
                    $byte = $a.GetBytes("$(Get-Date)")
                    [void]$UdpClient.Send($byte, $byte.length)
                    #IPEndPoint object will allow us to read datagrams sent from any source.
                    Write-Verbose "$($MyInvocation.MyCommand.Name) - Creating remote endpoint"
                    $remoteendpoint = New-Object system.net.ipendpoint([system.net.ipaddress]::Any, 0)
                    try {
                        #Blocks until a message returns on this socket from a remote host.
                        Write-Verbose "$($MyInvocation.MyCommand.Name) - Waiting for message return"
                        $receivebytes = $UdpClient.Receive([ref]$remoteendpoint)
                        [string]$returndata = $a.GetString($receivebytes)
                        If ($returndata) {
                            Write-Verbose "$($MyInvocation.MyCommand.Name) - '$Computer' passed port test on port '$Protocol`:$Portx'"
                            $Output.Result = $true
                        }
                    } catch {
                        Write-Verbose "$($MyInvocation.MyCommand.Name) - '$Computer' failed port test on port '$Protocol`:$Portx' with error '$($_.Exception.Message)'"
                        $Output.Result = $false
                    }
                    $UdpClient.Close()
                    $UdpClient.Dispose()
                }
                [pscustomobject]$Output
            }
        }
    }
}


#stary ktery zobrazi i response

#Function Test-Port 
#{	
#	<#
#	.SYNOPSIS
#	  Fce slouží k zjištění, zdali je daný TCP port otevřený.	 
#	.PARAMETER ComputerName
#	  seznam stroju u kterych zjistim prihlasene uzivatele
#	.PARAMETER Port
#	  parametr slouží k zadání čísla TCP portu/ů. Výchozí hodnota je 902.
#	.PARAMETER  TCPTimeout
#	  Určuje, jak dlouho (v milisekundách) se má čekat na odpověď. Výchozí hodnota je 1000 ms.
#	.EXAMPLE
#	  Test-Port -computername $hala -port 80
#	##>
#    [OutputType('Net.TCPResponse')]
#    [cmdletbinding()]
#    Param 
#	(
#        [parameter(ValueFromPipeline,ValueFromPipelineByPropertyName)]
#        [Alias('__Server','IPAddress','IP')]
#        [string[]]$Computername = $env:Computername,
#        [int[]]$Port = 902,
#        [int]$TCPTimeout = 1000
#    )
#	
#    Process 
#	{
#        ForEach ($Computer in $Computername) 
#		{
#            ForEach ($_port in $Port) 
#			{
#                $stringBuilder = New-Object Text.StringBuilder
#                $tcpClient = New-Object System.Net.Sockets.TCPClient
#                $connect = $tcpClient.BeginConnect($Computer,$_port,$null,$null) 
#                $wait = $connect.AsyncWaitHandle.WaitOne($TCPtimeout,$false) 
#                If (-NOT $wait) 
#				{
#                    $object = [pscustomobject] @{
#                        Computername = $Computer
#                        Port = $_Port
#                        IsOpen = $False
#                        Response = $Null
#                    }
#                } 
#				Else 
#				{
#                    While ($True) 
#					{
#                        #Let buffer
#                        Start-Sleep -Milliseconds 1000
#                        Write-Verbose "Bytes available: $($tcpClient.Available)"
#                        If ([int64]$tcpClient.Available -gt 0) {
#                            $stream = $TcpClient.GetStream()
#                            $bindResponseBuffer = New-Object Byte[] -ArgumentList $tcpClient.Available
#                            [Int]$response = $stream.Read($bindResponseBuffer, 0, $bindResponseBuffer.count)  
#                            $Null = $stringBuilder.Append(($bindResponseBuffer | ForEach {[char][int]$_}) -join '')
#                        } 
#						Else 
#						{
#                            Break
#                        }
#                    } 
#                    $object = [pscustomobject] @{
#                        Computername = $Computer
#                        Port = $_Port
#                        IsOpen = $True
#                        Response = $stringBuilder.Tostring()
#                    }
#                }
#                $object.pstypenames.insert(0,'Net.TCPResponse')
#                Write-Output $object | ft -AutoSize
#                If ($Stream) 
#				{
#                    $stream.Close()
#                    $stream.Dispose()
#                }
#                $tcpClient.Close()
#                $tcpClient.Dispose()
#            }
#        }
#    }
#}