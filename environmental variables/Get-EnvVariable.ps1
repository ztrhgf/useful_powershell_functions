function Get-EnvVariable {
    <#
		.SYNOPSIS
		Fce slouzi k ziskani obsahu vybrane systemove/uzivatelske promenne. 

		.DESCRIPTION
		Fce slouzi k ziskani obsahu vybrane systemove/uzivatelske promenne. 
		Standardne fce vypisuje/prohledava PATH.

       	.PARAMETER ComputerName
        Nepovinny parametr. Udava pocitac/pocitace, se kterymi budeme pracovat. Prijima i vstup z pipe.
    
		.PARAMETER VarName
		Nepovinny parametr. Udava jmeno promenne, jejiz hodnoty budeme ziskavat. PATH, TMP,...
		
		Defaultne je PATH.

		.PARAMETER Path
		Pokud zadano, tak se dana cesta bude hledat v zadane promenne (VarName)
		Nepovinny parametr.

		.PARAMETER Scope
		Nepovinny parametr. Udava typ promenne: User/Machine. 
		
		Vychozi je Machine.
	        
        .PARAMETER Separator
        Nepovinny parametr. 
        Udava jakym znakem jsou cesty oddeleny. Vychozi je strednik (;).

		.EXAMPLE
		Get-EnvVariable -computername kronos,demeter | ft -AutoSize -Wrap

		Vypise obsah PATH na strojich kronos a demeter.

		.EXAMPLE
		Get-EnvVariable -computername $b116 -name \\home\share\texlive2010 | ft

		Na strojich z promenne $b116 bude hledat zadanou cestu.

		.EXAMPLE
		Get-EnvVariable -computername kronos,demeter -VarName TMP

		Vypise obsah systemove promenne TMP na strojich kronos a demeter.

        .NOTES  
        Author: Ondřej Šebela - ztrhgf@seznam.cz
	#>

    [cmdletbinding()]
    Param
    (
        [Parameter(Mandatory = $false, ValueFromPipeline = $True, Position = 0)]
        [ValidateNotNullOrEmpty()]
        $ComputerName = $Env:computername
        ,
        [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName)]
        [ValidateNotNullOrEmpty()]
        [string] $VarName = "PATH"
        ,
        [Parameter(Mandatory = $false, Position = 1)]
        [string] $Path
        ,
        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [ValidateSet('Machine', 'User')]
        [string] $Scope = 'Machine'
        ,
        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [string] $Separator = ";"
    )
    
    begin {
        if ($ComputerName -ne 'localhost') {
            $ComputerName = Test-Connection2 $ComputerName -JustResponding -ErrorAction Stop
            $nepingaji = (Test-Connection2 $ComputerName -JustNotResponding) -join ", "
            if ($nepingaji) {
                Write-Host "Tyto stroje nepingaji:`n$nepingaji"
            }
        }

        if ($Path -match '\*') {
            Write-Warning "Path nepodporuje wildcardy (*)"
            break
        }
    }

    process {	
        Invoke-Command2 -hidecomputername -ComputerName $ComputerName -EnableNetworkAccess {
            param (
                $VarName,
                $Scope,
                $Path,
                $Separator,                
                $computer = $Env:computername
            )

            $actualEnv = [Environment]::GetEnvironmentVariable($VarName, $Scope) -replace ('"', '') -Split "$Separator"

            # vytvoreni objektu, který ponese výsledek
            $result = [PSCustomObject]@{Computer = $Computer} 
                
            if ($Path) {
                # hledam konkretni cestu
                $containPath = $actualEnv.ToLower().contains("$Path".ToLower()) # contains je case-sensitive proto volam toLower
                # pokud nemam shodu, zkusim dohledat variantu s/bez lomitka na konci
                if (!$containPath) {
                    if ($Path -match "\\$") {
                        # zadal s lomitkem na konci, zkusim dohledat variantu bez
                        $Path = $Path -replace "\\$"
                        $containPath = $actualEnv.ToLower().contains("$Path".ToLower())
                    } else {
                        # zadal bez lomitka na konci, zkusim dohledat variantu s lomitkem
                        $Path = $Path + "\"
                        $containPath = $actualEnv.ToLower().contains("$Path".ToLower())
                    }
                }
                $PropertyName = "Je $Path v $($VarName.toUpper())"
                $result | Add-Member -type NoteProperty -name $PropertyName -value ""
                if ($containPath) {
                    $result | select Computer, @{N = "$PropertyName"; E = {$True}}
                } else {
                    $result | select Computer, @{N = "$PropertyName"; E = {$False}}
                }
            } else {
                # nehledam konkretni cestu
                $result | select @{N = "Computer"; E = {$computer}}, @{N = "Count"; E = {$actualEnv.count}}, @{N = "$VarName"; E = {$actualEnv}}
            }
        } -argumentList $VarName, $Scope, $Path, $Separator | Select * -ExcludeProperty RunspaceID   
    }
}

Set-Alias Get-Path Get-EnvVariable 