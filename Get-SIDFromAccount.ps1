function Get-SIDFromAccount {
    <#
.SYNOPSIS
Fce pro zjisteni SID zadaneho uzivatele ci skupiny.
.DESCRIPTION
Ve vychozim nastaveni preklada lokalni ucty. Pro domenove je potreba zadat i nepovinny parametr domain.
Ale pozor, pokud dany ucet nebude nalezen lokalne, tak se zkusi nalezt v domene.
.PARAMETER AccountName
Jmeno uzivatele ci skupiny.
.PARAMETER Domain
Switch, ktery se pouziva pokud chci prekladat domenove ucty.
.PARAMETER ComputerName
Jmeno stroje, na kterem ma dojit k prekladu loginu.
.EXAMPLE
Get-SIDFromAccount administrator
.EXAMPLE
Get-SIDFromAccount administrator -domain
.EXAMPLE
Get-SIDFromAccount -accountname _sokrates05 -computername sokrates05
#>

    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, Position = 0, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true, HelpMessage = "zadej jmeno uzivatele ci skupiny")]
        $AccountName
        ,
        [switch]$Domain
        ,
        [string]$computerName
    )

    if ($computerName) {
        Invoke-Command -ComputerName $ComputerName -ScriptBlock {
            if ($using:Domain)	{
                # ziskani jmena domeny do ktere je stroj zapojeny
                $DomainName = (gwmi WIN32_ComputerSystem).Domain
            } else {
                $DomainName = ""
            }

            try {
                ((New-Object System.Security.Principal.NTAccount("$DomainName", "$using:AccountName")).Translate([System.Security.Principal.SecurityIdentifier])).Value
            } catch {
                throw "Ucet $using:AccountName se nepodarilo prelozit. Bud neexistuje nebo jste spatne zvolili jeho typ (lokalni|domenovy)."
            }
        }
    } else {
        if ($Domain)	{
            # ziskani jmena domeny do ktere je stroj zapojeny
            $DomainName = (gwmi WIN32_ComputerSystem).Domain
        } else {
            $DomainName = ""
        }

        try {
            ((New-Object System.Security.Principal.NTAccount("$DomainName", "$AccountName")).Translate([System.Security.Principal.SecurityIdentifier])).Value
        } catch {
            throw "Ucet $AccountName se nepodarilo prelozit. Bud neexistuje nebo jste spatne zvolili jeho typ (lokalni|domenovy).`nPokud jde o computer ucet, nezapomente dat za jmeno $"
        }
    }
}
