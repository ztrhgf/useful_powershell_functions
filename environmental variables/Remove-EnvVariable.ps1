function Remove-EnvVariable {
    <#
	.SYNOPSIS
	Maze cesty z sys. promennych/cele sys. promenne. Pouziva se napr. pro upravu PATH.

	.DESCRIPTION
	Maze cesty z sys. promennych/cele sys. promenne. Pouziva se napr. pro upravu PATH.
	Maze hodnoty z jedne ze systemovych/uzivatelskych promennych (PATH, TMP, JAVA_HOME, ...)
	Ve vychozim nastaveni upravuje hodnoty PATH.

	.PARAMETER ComputerName
    Parametr udavajici seznam stroju.
    Vychozi je localhost.
	
	.PARAMETER VarName
    Nepovinny parametr. 
    Udava jmeno promenne, kterou budeme modifikovat. PATH, TMP,...
    Vychozi je PATH.
	
	.PARAMETER Path
	Seznam cest, ktere se maji odebrat.
	
	.PARAMETER Scope
    Nepovinny parametr. 
    Urcuje, zdali se modifikuji uzivatelske ci systemove promenne.
    Mozne hodnoty jsou User/Machine. 
    Vychozi je Machine.
	
	.PARAMETER Separator
    Nepovinny parametr. 
    Udava jakym znakem jsou cesty oddeleny. 
    Vychozi je strednik (;).
	
	.EXAMPLE
	Remove-EnvVariable -VarName PATH -Path 'C:\git','C:\temp' -ComputerName $b116 
	Odebere ze systemove PATH zadane cesty na vsech strojich v $b116.

	.EXAMPLE
	Remove-EnvVariable -VarName JAVA_HOME
	Odstrani na tomto stroji systemovou promennou JAVA_HOME.

    .NOTES
	Inspirovano http://blogs.splunk.com/2013/07/29/powershell-profiles-and-add-path/
    #>

    [cmdletbinding()]
    Param
    (
        [Parameter(ValueFromPipeline = $True, ValueFromPipelineByPropertyName)]
        [string[]] $ComputerName = $env:COMPUTERNAME
        ,
        [Parameter(ValueFromPipelineByPropertyName)]
        [array] $Path
        ,
        [Parameter(ValueFromPipelineByPropertyName)]
        [string] $VarName = "PATH"
        ,
        [ValidateSet('Machine', 'User')]
        [string] $Scope = 'Machine'
        ,
        [ValidateLength(0, 1)]
        [string] $Separator = ';'
    )

    begin {
        if ($VarName -eq 'PATH' -and !$Path) {
            Write-Error "Nezadali jste Path, doslo by ke smazani cele sys. promenne PATH"
            break
        }
    }
    
    process {
        Invoke-Command2 -ComputerName $ComputerName -argumentList $path, $VarName, $Scope, $Separator -scriptBlock {	
            param (
                $Path,
                $VarName,
                $Scope,
                $Separator
            )

            $computer = $env:COMPUTERNAME

            if ($Path) {
                $CurrentValue = @([Environment]::GetEnvironmentVariable($VarName, $Scope) -replace "$Separator$Separator", "$Separator" -split "$Separator")

                $Path | % {
                    $p = $_ -replace "\\", "\\" # prvni se expanduje na \ druhe uz se nebere jako regulak a bere se tak jako \\
                    $CurrentValue = $CurrentValue -replace "^$p$"
                }
                    
                # zbavim se prazdnych radku po replace
                $NewValue = $CurrentValue | where {$_}

                $NewValue = $NewValue -join $Separator
            } else {
                # mazu komplet sys. promennou
                $NewValue = ''
            }


            # nastavim nove hodnoty
            [Environment]::SetEnvironmentVariable($VarName, $NewValue, $Scope)

            if ($? -eq $true) {
                Write-Output "Na $computer OK."
            } else {
                Write-Warning "Na $computer NOK."
            }
        } # konec scriptBlock
    }
    
    end {
        if ($VarName -ne "PATH") { Write-Warning "Projevi se pravdepodobne az po restartu" }
    }
}