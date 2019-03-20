function Test-Path2 {
	<#
	.Synopsis
	 Fce slouží ke zjištění, zdali existuje zadaná cesta. 	 
	.Description
	.PARAMETER $ComputerName
	 seznam stroju u kterych zjistim prihlasene uzivatele
	.PARAMETER  $path
	 Parametr určující jaká cesta se bude testovat.
	.EXAMPLE
	 test-path2 $hala -p C:\temp
	#>

	[CmdletBinding()]
	param (
	    [Parameter(Mandatory=$true,Position=0,ValueFromPipeline=$true,ValueFromPipelineByPropertyName=$true,HelpMessage="zadej jmeno stroje/ů")]
	    [Alias("c","CN","__Server","IPAddress","Server","Computer","Name","SamAccountName")]
	    [String[]] $ComputerName
		,
		[Parameter(Mandatory=$true,Position=1,HelpMessage="zadej cestu např.: C:\TEMP")]
		[Alias("p")]
		[string] $path		
	)
	
	BEGIN {
		# adresa ke kontrole
		$path = $path -replace ":", "$" -Replace("`"","")
		# nazev souboru
		$filename = $path.substring($path.lastindexofany("\") +1 )
		
		$AsyncPipelines = @()
		$pool = Get-RunspacePool 20
		
		$scriptblock = {
			param($Computer,$Path)
			if (Test-Connection -ComputerName $computer -Count 1 -quiet -ErrorAction SilentlyContinue) {
				If(test-Path "\\$computer\$path") {
					write-output "na $computer $filename nalezen"
				} else {
					write-output "na $computer $filename nenalezen"
				}
			} else {
				write-output "$computer nepingá"
			}
		}
	}
	
	PROCESS {	
		foreach ($computer in $ComputerName) {
			$AsyncPipelines += Invoke-Async -RunspacePool $pool -ScriptBlock $ScriptBlock -Parameters $Computer,$Path			
		}
	}
	
	END	{
		Receive-AsyncResults -Pipelines $AsyncPipelines -ShowProgress
	}
}

# NASTAVENI ALIASU
Set-Alias tp test-path2
