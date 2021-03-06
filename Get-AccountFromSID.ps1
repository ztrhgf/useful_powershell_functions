function Get-AccountFromSID {
	<#
	.SYNOPSIS
	 Fce pro zjisteni jmena uctu uzivatele ci skupiny z SID.
	.DESCRIPTION
	 Funguje pouze pro preklad domenovych/lokalnich uctu a skupin. Neumí najít lokální účet/skupinu na jiném stroji v doméně.
	.PARAMETER SID
	 SID uzivatele ci skupiny.
	.PARAMETER COMPUTERNAME
	 Jméno stroje, pokud chcete přeložit nějaké jeho lokální SID
	.EXAMPLE
	 Get-AccountFromSID S-1-5-21-1441145396-4061174792-1235317837-1001
	.EXAMPLE
	 Get-AccountFromSID -comp pc1 -sid S-1-5-21-1441145396-4061174792-1235317837-1001	  
	#>
	
	[CmdletBinding()]
	param(
    [Parameter(Mandatory=$true,Position=0,ValueFromPipeline=$true,ValueFromPipelineByPropertyName=$true,HelpMessage="zadej SID uctu uzivatele ci skupiny")]
	$SID
	,
	[Parameter(Mandatory=$false,Position=1)]
	$ComputerName
	)

#	$objSID = New-Object System.Security.Principal.SecurityIdentifier ("$SID") 
#	$objUser = $objSID.Translate( [System.Security.Principal.NTAccount]) 
#	$objUser.Value
	if ($ComputerName) {
		invoke-command -ComputerName $computername -ScriptBlock {((New-Object System.Security.Principal.SecurityIdentifier("$using:SID")).Translate([System.Security.Principal.NTAccount])).Value} -ArgumentList $SID
	} else {
		((New-Object System.Security.Principal.SecurityIdentifier("$SID")).Translate([System.Security.Principal.NTAccount])).Value
	}
}
