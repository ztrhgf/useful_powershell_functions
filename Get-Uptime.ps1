Function Get-Uptime {
    <#
	.SYNOPSIS
    Vypise uptime zadaneho stroje.
    
	.DESCRIPTION
    Vypise uptime zadaneho stroje. Podle posledniho casu bootu OS.
    
	.PARAMETER computerName
    Jmeno stroje
    
	.EXAMPLE
    Get-Uptime

    vypise, jak dlouho je lokalni stroj online
    
	.EXAMPLE
    Get-Uptime -ComputerName $hala
    
    vypise, jak dlouho jsou jednotlive stroje v hale online
    #>
    
    param (
        [Parameter(Position = 0, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [alias("cn")]
        [string[]]$computerName = $env:COMPUTERNAME
    )

    PROCESS {
        Invoke-Command2 -computerName $computerName {
            $Uptime = Get-WmiObject -Class Win32_OperatingSystem -Property LastBootUpTime
            $LastBootUpTime = $Uptime.ConvertToDateTime($Uptime.LastBootUpTime)
            $Time = (Get-Date) - $LastBootUpTime
            New-Object PSObject -Property @{
                ComputerName = $env:COMPUTERNAME.ToUpper()
                Uptime       = '{0:00}:{1:00}:{2:00}:{3:00}' -f $Time.Days, $Time.Hours, $Time.Minutes, $Time.Seconds
            }
        } | Select-Object -property * -excludeProperty PSComputerName, RunspaceId
    }
}