function Get-LoggedOnUser {
    <#
		.Synopsis
			Fce pro zjištění, kdo je na stroji přihlášen.

		.Description
			Ke zjištění kdo je přihlášen používá příkaz quser. Jeho výstup převede na objekt a ten vypíše.
			Proto, že quser má problém s použitím parametru /remote se používá invoke-command.

		.Parameter ComputerName
			Povinný parametr udávající seznam strojů.

		.Parameter UserName
			Nepovinný parametr. Udává login uživatele.
			Pokud je zadán, tak se vypíší jen stroje, kde je uživatel přihlášen.

		.EXAMPLE
			$hala | glu
			Vypíše přihlášené uživatele v hale

		.EXAMPLE
			glu $b311 sebela
			Vypíše, na kterých strojích v B311, je přihlášen uživatel sebela

		.NOTES
			Převzato od Jaap Brasser a vylepšeno o asynchronní spouštění + použití invoke-command.
			Formatovani vystupu se dela pomoci souboru My.GetLoggedOnUser.Format.ps1xml (pozor urcuje i vystupni parametry!)

		.LINK
			http://www.jaapbrasser.com
			http://www.petri.com/powershell-script-find-system-uptime-formatting-results.htm
	#>

    param(
        [CmdletBinding()]
        [Parameter(Mandatory = $true, Position = 0, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [string[]] $ComputerName
        ,
        [Parameter(Mandatory = $false, Position = 1)]
        [String] $UserName
    )

    BEGIN {
    }

    PROCESS {
        Invoke-Command2 -ComputerName $ComputerName -HideComputerName -ScriptBlock {
            $ErrorActionPreference = "silentlycontinue"
            quser | Select-Object -Skip 1 | ForEach-Object {
                $CurrentLine = $_.Trim() -Replace '\s+', ' ' -Split '\s'
                $HashProps = @{
                    UserName     = $CurrentLine[0]
                    ComputerName = $env:COMPUTERNAME
                }

                # If session is disconnected different fields will be selected
                if ($CurrentLine[2] -eq 'Disc') {
                    $HashProps.SessionName = $null
                    $HashProps.Id = $CurrentLine[1]
                    $HashProps.State = $CurrentLine[2]
                    $HashProps.IdleTime = $CurrentLine[3]
                    $HashProps.LogonTime = $CurrentLine[4..6] -join ' '
                } else {
                    $HashProps.SessionName = $CurrentLine[1]
                    $HashProps.Id = $CurrentLine[2]
                    $HashProps.State = $CurrentLine[3]
                    $HashProps.IdleTime = $CurrentLine[4]
                    $HashProps.LogonTime = $CurrentLine[5..7] -join ' '
                }

                $obj = New-Object -TypeName PSCustomObject -Property $HashProps | Select-Object -Property UserName, ComputerName, SessionName, Id, State, IdleTime, LogonTime
                #insert a new type name for the object
                $obj.psobject.Typenames.Insert(0, 'My.GetLoggedOnUser')
                $obj
            }
        }
    }

    END {
    }
}
Set-Alias glu Get-LoggedOnUser