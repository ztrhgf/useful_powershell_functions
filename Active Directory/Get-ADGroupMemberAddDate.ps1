function Get-ADGroupMemberAddDate {
    <#
		.SYNOPSIS
            Vypise kdy byl dany uzivatel/skupina pridan do skupin, jichz je aktualne clenem.
            Informace ziskava z replikacnich metadat.

        .DESCRIPTION
            Vypise kdy byl dany uzivatel/skupina pridan do skupin, jichz je aktualne clenem.
            Informace ziskava z replikacnich metadat.

		.PARAMETER userName
            Jmeno AD uzivatele, jehoz vysledky mne zajimaji.

        .PARAMETER groupName
            Jmeno AD skupiny, jejiz vysledky mne zajimaji.

        .PARAMETER server
            Z jakeho serveru se maji ziskat replikacni metadata.

            Vychozi je PDC emulator v AD.        

		.EXAMPLE
			Get-ADGroupMemberAddDate -username sebela

            Vypise kdy byl ad ucet sebela pridan do AD skupin, jichz je aktualne clenem.

		.NOTES
			cerpano z https://blogs.technet.microsoft.com/ashleymcglone/2012/10/17/ad-group-history-mystery-powershell-v3-repadmin/
    #>

    [CmdletBinding(DefaultParameterSetName = 'Default')]
    param (
        [Parameter(Position = 0, Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true, ParameterSetName = "Default")]        
        [ValidateNotNullOrEmpty()]
        $userName            
        ,
        [Parameter(Position = 1, Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true, ParameterSetName = "Group")]        
        [ValidateNotNullOrEmpty()]
        $groupName
        ,   
        [ValidateNotNullOrEmpty()]           
        [string] $server = (Get-ADDomainController -Discover | Select-Object -ExpandProperty HostName)
    )

    if ($userName) {
        try {
            $obj = Get-ADUser $userName -ErrorAction Stop             
        } catch {
            throw "Zadany uzivatel nebyl v AD nalezen"
        }

        $objectMemberOf = Get-ADUser $obj.DistinguishedName -Properties memberOf
    } else {
        try {
            $obj = Get-ADGroup $groupName -ErrorAction Stop             
        } catch {
            throw "Zadana skupina nebyla v AD nalezena"
        }

        $objectMemberOf = Get-ADGroup $obj.DistinguishedName -Properties memberOf      
    }

    $objectMemberOf | Select-Object -ExpandProperty memberOf |            
        ForEach-Object {            
        Get-ADReplicationAttributeMetadata $_ -Server $server -ShowAllLinkedValues |             
            Where-Object {$_.AttributeName -eq 'member' -and             
            $_.AttributeValue -eq $obj.DistinguishedName} |            
            Select-Object @{n = 'Added'; e = {$_.FirstOriginatingCreateTime}}, Object            
    } | Sort-Object Added -Descending
}