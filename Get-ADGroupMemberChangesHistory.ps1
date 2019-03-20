Function Get-ADGroupMemberChangesHistory {
    <#
		.SYNOPSIS
            Vypise historii zmen ve clenstvi dane AD skupiny.
            Informace ziskava z replikacnich metadat.

		.DESCRIPTION
            Vypise historii zmen ve clenstvi dane AD skupiny.
            Informace ziskava z replikacnich metadat.
            Pro kazdeho clena zobrazuje pouze jednu posledni kaci (pridani/odebrani)

		.PARAMETER groupName
            Jmeno AD skupiny.

		.PARAMETER hour
            Jak stare zmeny clenstvi me zajimaji.

            Vychozi je 24 hodin.

        .PARAMETER server
            Z jakeho serveru se maji ziskat replikacni metadata.

            Vychozi je PDC emulator v AD.        
            
        .PARAMETER rawOutput
            Prepinac rikajici, ze se maji vypsat vsechny dostupne atributy.
            Muze byt dobre pri diagnostice?

		.EXAMPLE
			Get-ADGroupMemberChangesHistory -groupName ucebnyRemoteDesktop

            Vypise zmeny ve skupine ucebnyRemoteDesktop za poslednich 24 hodin.

		.EXAMPLE
			Get-ADGroupMemberChangesHistory -groupName ucebnyRemoteDesktop -hour (365*24)

            Vypise zmeny ve skupine ucebnyRemoteDesktop za posledni rok.

		.NOTES
			cerpano z https://blogs.technet.microsoft.com/ashleymcglone/2014/12/17/forensics-monitor-active-directory-privileged-groups-with-powershell/
    #>
    
    [CmdletBinding()]   
    Param (
        [Parameter(Position = 0, Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]        
        [ValidateNotNullOrEmpty()]
        [string] $groupName
        ,
        [int] $hour = 24
        ,       
        [ValidateNotNullOrEmpty()]           
        [string] $server = (Get-ADDomainController -Discover | Select-Object -ExpandProperty HostName)
        ,
        [switch] $rawOutput        
    )        

    begin {
        Write-Warning "Vypise zmeny ve skupine $groupname za poslednich $hour hodin.`nPro kazdeho clena skupiny zobrazuje pouze jednu posledni akci!"

        try {
            $group = Get-ADGroup $groupName -Property name, distinguishedname -ErrorAction Stop
        } catch {
            throw "Nepodarilo se dohledat informace ke skupine $groupName. Existuje?"
        }
    }

    process {
        $Members = Get-ADReplicationAttributeMetadata -Object $Group.DistinguishedName -ShowAllLinkedValues -Server $server |
            Where-Object {$_.IsLinkValue -and $_.AttributeName -eq 'member'}

        if (!$rawOutput) {
            $members = $members | Select-Object @{name = 'Member'; expression = {$_.AttributeValue}}, @{name = 'Changed'; expression = {$_.LastOriginatingChangeTime}}, @{name = 'Action'; expression = {
                    if ($_.LastOriginatingDeleteTime -eq '1/1/1601 1:00:00 AM') {'added'} else {'removed'}}
            }
        }
        
        if (!$rawOutput) {
            $Members | Where-Object {$_.Changed -gt (Get-Date).AddHours(-1 * $Hour)} | Sort-Object Changed -Descending
        } else {
            $Members | Where-Object {$_.LastOriginatingChangeTime -gt (Get-Date).AddHours(-1 * $Hour)} | Sort-Object LastOriginatingChangeTime -Descending
        }
    }
}