function Set-EnvVariable {
    <#
	.SYNOPSIS
	Nastavuje hodnoty v jedne ze systemovych/uzivatelskych promennych (PATH, TMP, JAVA_HOME, ...)

	.DESCRIPTION
	Nastavuje hodnoty v jedne ze systemovych/uzivatelskych promennych (PATH, TMP, JAVA_HOME, ...)
	Ve vychozim nastaveni pridava hodnoty do systemove PATH.

	.PARAMETER ComputerName
	Parametr udavajici seznam stroju.

    .PARAMETER VarName
    Nepovinny parametr. 
    Udava jmeno promenne, kterou budeme modifikovat. PATH, TMP,...
    
    Vychozi je PATH.
	
	.PARAMETER Path
	Seznam cest, ktere se maji pridat.
	
	.PARAMETER Scope
    Nepovinny parametr. 
    Urcuje, zdali se modifikuji uzivatelske ci systemove promenne.
    
    Mozne hodnoty jsou User/Machine. Vychozi je Machine.
	
	.PARAMETER Separator
    Nepovinny parametr. 
    Udava jakym znakem jsou cesty oddeleny. Vychozi je strednik (;).
	
	.PARAMETER Replace
	Switch rikajici jestli se maji ponechat puvodni hodnoty nebo nahradit novymi. 
	
	.EXAMPLE
	Set-EnvVariable -Path 'C:\git','C:\temp' -ComputerName $b116 
	Prida do systemove PATH zadane cesty na vsech strojich v $b116.

	.EXAMPLE
	Set-EnvVariable -Path 'C:\Program Files\Java\jdk1.8.0_74' -VarName JAVA_HOME -replace
	V systemove promenne JAVA_HOME nahradi pripadnou stavajici cestu za novou.

    .NOTES
    Je mozne pouzit alias set-path ci add-path
	Prevzato od Jason Morgan
	tipy http://blogs.splunk.com/2013/07/29/powershell-profiles-and-add-path/
	
    #>

    [cmdletbinding(DefaultParameterSetName = 'Default')]
    Param
    (
        [Parameter(Mandatory = $false, ValueFromPipeline = $True, ValueFromPipelineByPropertyName)]
        [string[]] $ComputerName = $env:COMPUTERNAME
        ,
        [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName, ParameterSetName = 'Default')]
        [Parameter(ParameterSetName = 'Concat')]
        [string] $VarName = "PATH"
        ,
        [Parameter(Mandatory, ValueFromPipelineByPropertyName, ParameterSetName = 'Default')]
        [Parameter(ParameterSetName = 'Concat')]
        [array] $Path
        ,
        [Parameter(ParameterSetName = 'Default')]
        [Parameter(ParameterSetName = 'Concat')]
        [ValidateSet('Machine', 'User')]
        [string] $Scope = 'Machine'
        ,
        [Parameter(ParameterSetName = 'Concat')]
        [ValidateLength(0, 1)]
        [string] $Separator = ';'
        ,
        [Parameter(ParameterSetName = 'Concat')]
        [switch] $Replace
    )

    begin {
    }
    
    process {
        Invoke-Command2 -ComputerName $ComputerName -argumentList $Replace, $Path, $VarName, $Scope, $Separator -ScriptBlock {	
            param (
                $Replace,
                $Path,
                $VarName,
                $Scope,
                $Separator
            )

            $computer = $env:COMPUTERNAME
            $firstRun = 1

            foreach ($Value in $Path) {
                # prevedu vysledek na pole abych mohl pouzit metodu contains kvuli exact match porovnani
                $CurrentValue2 = @([Environment]::GetEnvironmentVariable($VarName, $Scope) -replace "$Separator$Separator", "$Separator" -split "$Separator")
                $CurrentValue = {$CurrentValue2}.invoke()
                # pokud stavajici hodnoty prepisuji, tak nema smysl delat kontrolu, zdali tam uz jsou, musim vse nastavit znovu
                # vsechno zmensim protoze contains je case sensitive
                if (!$Replace -and ($CurrentValue.tolower().Contains("$Value".tolower()))) { 
                    Write-Warning "Folder ""$Value"" is already in the path"
                    continue
                } 

                # aktualni hodnoty ukoncim separatorem
                $Current = $CurrentValue -join "$Separator"
                if ($Current) {
                    $Current = $Current + $Separator
                }
                
                if (!$Replace) {
                    # ke stavajicim cestam pridam dalsi
                    [Environment]::SetEnvironmentVariable($VarName, ($Current + $Value), $Scope)
                } else {
                    # stavajici hodnoty prepisi novymi
                    
                    if ($Path.Count -gt 1) {
                        # pridavam vic cest
                        if ($firstRun) {
                            # prepisu stavajici cesty novou hodnotou
                            [Environment]::SetEnvironmentVariable($VarName, $Value, $Scope)
                        } else {
                            # pridavam vic cest a toto je nejmene druha pridavana cesta (puvodni jsou jiz vymazane)
                            [Environment]::SetEnvironmentVariable($VarName, ($Current + $Value), $Scope)
                        }
                    } else {
                        # prepisu stavajici cesty novou hodnotou
                        [Environment]::SetEnvironmentVariable($VarName, $Value, $Scope)
                    }

                }
            
                if ($? -eq $true) {
                    Write-Output "Na $computer OK."
                } else {
                    Write-Warning "Na $computer NOK."
                }

                $firstRun = 0
            }

        }
    }
    
    end {
        if ($VarName -ne "path") { Write-Warning "Projevi se pravdepodobne az po restartu" }
    }
}

set-alias Set-Path Set-EnvVariable
set-alias Add-Path Set-EnvVariable
