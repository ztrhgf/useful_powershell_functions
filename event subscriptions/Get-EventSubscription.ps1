function Get-EventSubscription {
    <#
		.SYNOPSIS
			Fce pro vypsani event subskripci. Pripadne nastaveni nejake konkretni subskripce.

        .DESCRIPTION
			Fce pro vypsani event subskripci. Pripadne nastaveni nejake konkretni subskripce.
            Na radku AllowedSourceDomainComputersTranslated vypise na jake stroje, je subskripce aplikovana (prevodem SDDL z AllowedSourceDomainComputers)

		.PARAMETER computername
            Na jakem stroji se maji subskripce ziskat.

            Vychozi je obsah promenne eventCollector.

		.PARAMETER subscriptionName
            Jmeno subskripce, jejich nastaveni chceme vypsat.
            Pokud nezadano, vypisi se vsechny.

        .PARAMETER includeSource
            Prepinac pro zobrazeni i stroju, ktere subskripci aplikuji.

		.NOTES
			Author: Ondřej Šebela - ztrhgf@seznam.cz
    #>

    [cmdletbinding()]
    param (
        [ValidateNotNullOrEmpty()]
        [string] $subscriptionName
        ,
        [ValidateNotNullOrEmpty()]
        [string] $computerName = $eventCollector
        ,
        [switch] $includeSource
    )

    Invoke-Command2 -computerName $computerName {
        param ($subscriptionName, $includeSource)

        if ($subscriptionName) {
            if ($includeSource) {
                $result = wecutil get-subscription $subscriptionName
                # krom vypisu wecutil vratim i prelozene SDDL stroju, ktere maji subskripci aplikovat
                $sddl = ConvertFrom-SddlString -sddl (($result | Select-String AllowedSourceDomainComputers) -replace 'AllowedSourceDomainComputers:\s+') | select -ExpandProperty DiscretionaryAcl
                $result + "AllowedSourceDomainComputersTranslated:" + "`t$($sddl -join ', ')"
            } else {
                # zobrazim bez stroju, ktere danou subskripci aplikuji
                $result = wecutil get-subscription $subscriptionName
                $startOfSources = $result.IndexOf('EventSource[0]:')
                if ($startOfSources -and $startOfSources -ne -1) {
                    $r = $result | Select-Object -First $startOfSources
                } else {
                    $r = $result
                }
                # krom vypisu wecutil vratim i prelozene SDDL stroju, ktere maji subskripci aplikovat
                $sddl = ConvertFrom-SddlString -sddl (($r | Select-String AllowedSourceDomainComputers) -replace 'AllowedSourceDomainComputers:\s+') | select -ExpandProperty DiscretionaryAcl
                ($r | where {$_}) + "AllowedSourceDomainComputersTranslated:" + "`t$($sddl -join ', ')"
            }
        } else {
            wecutil enum-subscription
        }
    } -argumentList $subscriptionName, $includeSource
}