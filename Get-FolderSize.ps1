# TODO: fce neumí přistupovat do systémových adresářů jako System Volume Information, ošetřit.
function Get-FolderSize {
    <#
	.SYNOPSIS
	    Fce vypisuje velikost adresáře a počet v něm obsažených souborů.

	.DESCRIPTION
        Fce vypisuje velikost adresáře a počet v něm obsažených souborů.
        Využívá robocopy.

	.PARAMETER ComputerName
	    Povinný parametr, udává seznam strojů. Akceptuje i input pipeline.

	.PARAMETER FolderPath
	    Povinný parametr udávající cestu. Např.: C:\temp

	.PARAMETER Unit
	    Parametr udávající v jakých jednotkách chceme výstup. Výchozí je MB, ale možné jsou i KB a GB.
		Dle toho se i pojmenuje sloupec obsahujici velikost (napr.: Size (MB))

	.PARAMETER Exclude
		Filtr udavajici, jake soubory se maji ignorovat.
		Je mozne pouzivat wildcard * a v pripade vice koncovek oddelit mezerou.

		Napr.: '*.ps1 *.txt'

	.PARAMETER Include
		Filtr udavajici, pouze jake soubory se maji pocitat.
		Je mozne pouzivat wildcard * a v pripade vice koncovek oddelit mezerou.

		Napr.: '*.ps1 *.txt'

	.EXAMPLE
        $b311 | Get-FolderSize -d C:\temp

        Ukáže velikost C:\temp na strojích v B311.

	.EXAMPLE
        Get-FolderSize sirene01, bympkin C:\temp

        Ukáže velikost C:\temp na strojich sirene01 a bumpkin.

	.EXAMPLE
        Get-FolderSize sirene01, bympkin C:\temp -exclude '*.exe *.msi'

        Ukáže velikost C:\temp na strojich sirene01 a bumpkin. Ale nezapocitaji se exe a msi soubory.

	.EXAMPLE
        Get-FolderSize sirene01, bympkin C:\temp -include '*.txt'

        Ukáže velikost vsech txt souboru v C:\temp na strojich sirene01 a bumpkin.

	.NOTES
	    Author: Ondřej Šebela - ztrhgf@seznam.cz
	#>

    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $false, Position = 0, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true, HelpMessage = "zadej jmeno stroje/ů")]
        [ValidateNotNullOrEmpty()]
        [Alias("c", "CN", "__Server", "IPAddress", "Server", "Computer", "Name", "SamAccountName")]
        [string[]] $computerName = $env:computername
        ,
        [Parameter(Mandatory = $true, Position = 1)]
        [Alias("f", "d", "path", "dir", "directory")]
        [ValidateScript( {
                If ($_ -match '^[a-z][$:]\\\w+') {
                    $true
                } else {
                    Throw "$_ zadana cesta neni ve spravnem tvaru, tzn: C:\neco"
                }
            })]
        [string] $folderPath
        ,
        [Parameter(Mandatory = $false, Position = 2, HelpMessage = "V jakých jednotkách chceš vidět výslednou velikost. Výchozí je MB, ale může být i GB či KB")]
        [ValidateSet('GB', 'MB', 'KB')]
        [String] $unit = 'MB'
        ,
        [ValidateScript( {
                If ($_ -notmatch ',') {
                    $true
                } else {
                    Throw "`nZadany filtr: $_ obsahuje carku. Jednotlive prvky filtru oddelujte mezerou!`nNapriklad: '*.ps1 *.txt'"
                }
            })]
        [string] $include
        ,
        [ValidateScript( {
                If ($_ -notmatch ',') {
                    $true
                } else {
                    Throw "`nZadany filtr: $_ obsahuje carku. Jednotlive prvky filtru oddelujte mezerou!`nNapriklad: '*.ps1 *.txt'"
                }
            })]
        [string] $exclude
    )

    BEGIN {
        # odstranim zaverecne lomitko, protoze zpusobovalo problem u robocopy
        # stejne tak $ nahradim za : (abych mohl rovnou vkladat vykopirovane UNC cesty s $ namisto dvojtecky)
        $folderPath = $folderPath -replace "\\$" -replace '$\\', ':\'
    }

    PROCESS {
        Invoke-Command2 -computerName $computerName {
            param ($folderPath, $Unit, $Exclude, $Include)

            $Computer = $env:computername

            if (test-connection -computername $Computer -Count 1 -quiet) {
                # prevod lokalni cesty na sitovou
                $folderUNCPath = "\\" + $Computer + "\" + $folderPath -replace ":", "$"

                if (Test-Path $folderUNCPath) {
                    if ($Exclude) {
                        # pridam robocopy parametr /xF k zadanemu filtru
                        $Exclude = "/xF $Exclude"
                    }

                    # pomoci robocopy spocitam velikost zadane cesty
                    # cestu zadavam explicitne aby se nepouzila nejaka starsi verze napr. z 'Windows Resource Kits'
                    $robocopyPath = join-path $env:windir 'System32\Robocopy.exe'

                    $result = invoke-expression "$robocopyPath `"$folderUNCPath`" NULL $Include /L /XJ /R:0 /W:1 /NP /E /BYTES /NFL /NDL /NJH /MT:64 /NC $Exclude"
                    if (! $?) { ++$chyba }

                    # naplnim ziskanymi udaji objekt
                    $object = [PSCustomObject]@{
                        ComputerName   = $Computer
                        FilesCount     = ($result[-5] -replace "Files :\s+\d+\s+(\d+) .+", '$1').trim() # beru az druhy pocet, protoze az ten ukazuje soubory prosle pripadnym filtrem
                        "Size ($Unit)" = [math]::Round(($result[-4] -replace "Bytes :\s+\d+\s+(\d+) .+", '$1').trim() / "1$Unit", 2) # beru az druhou velikost, protoze az ta odpovida vyfiltrovanym souborum
                        Path           = $folderPath
                    }

                    if ($chyba) {
                        $object.FilesCount = NULL
                        $object."Size ($Unit)" = "Error"
                    }

                    if ($result -like "*ERROR 5 *") {
                        $object.FilesCount = NULL
                        $object."Size ($Unit)" = "Access denied"
                    }

                    # vypisu na vystup
                    $object

                } else {
                    Write-Output "$Computer nema pozadovany adresar"
                }
            } else {
                Write-Output "$Computer nepinga"
            }
        } -ArgumentList $folderPath, $Unit, $Exclude, $Include
    }
    END {
    }
}

# NASTAVENI ALIASU
Set-Alias gfs Get-FolderSize