function Export-ScriptsToModule {
    <#
    .SYNOPSIS
        Funkce pro vytvoreni PS modulu z PS funkci ulozenych v ps1 souborech v zadanem adresari.

        !!! Aby se v generovanych modulech korektne exportovaly funkce je potreba,
        mit funkce ulozene v ps1 souboru se shodnym nazvem (Invoke-Command2 funkci v Invoke-Command2.ps1 souboru)

        !!! POZOR v PS konzoli musi byt vybran font, ktery nekazi UTF8 znaky, jinak zpusobuje problemy!!!

    .PARAMETER configHash
        Hash obsahujici dvojice, kde klicem je cesta k adresari se skripty a hodnotou cesta k adresari, do ktereho se vygeneruje modul.
        napr.: @{"$PowershellProfileStore\scripts" = "$PowershellProfileStore\Modules\Scripts"}

    .PARAMETER enc
        Jake kodovani se ma pouzit pro vytvareni modulu a cteni skriptu

        Vychozi je UTF8.

    .PARAMETER includeUncommitedUntracked
        Vyexportuje i necomitnute a untracked funkce z repozitare

    .PARAMETER dontCheckSyntax
        Prepinac rikajici, ze se u vytvoreneho modulu nema kontrolovat syntax.
        Kontrola muze byt velmi pomala, pripadne mohla byt uz provedena v ramci kontroly samotnych skriptu

    .EXAMPLE
        Export-ScriptsToModule @{"C:\DATA\POWERSHELL\repo\CVT_repo\scripts\scripts" = "c:\DATA\POWERSHELL\repo\CVT_repo\modules\Scripts"}
    #>

    [CmdletBinding()]
    param (
        [ValidateNotNullOrEmpty()]
        $configHash
        ,
        $enc = 'utf8'
        ,
        [switch] $includeUncommitedUntracked
        ,
        [switch] $dontCheckSyntax
    )

    if (!(Get-Command Invoke-ScriptAnalyzer -ErrorAction SilentlyContinue) -and !$dontCheckSyntax) {
        Write-Warning "Syntaxe se nezkontroluje, protoze neni dostupna funkce Invoke-ScriptAnalyzer (soucast modulu PSScriptAnalyzer)"
    }
    function _generatePSModule {
        [CmdletBinding()]
        param (
            [Parameter(Mandatory = $true)]
            [ValidateNotNullOrEmpty()]
            $scriptFolder
            ,
            [Parameter(Mandatory = $true)]
            [ValidateNotNullOrEmpty()]
            $moduleFolder
            ,
            [switch] $includeUncommitedUntracked
        )

        if (!(Test-Path $scriptFolder)) {
            throw "Cesta $scriptFolder neexistuje"
        }

        $modulePath = Join-Path $moduleFolder ((Split-Path $moduleFolder -Leaf) + ".psm1")
        $function2Export = @()
        $alias2Export = @()
        $lastCommitFileContent = @{}
        # necomitnute zmenene skripty a untracked do modulu nepridam, protoze nejsou hotove
        $location = Get-Location
        Set-Location $scriptFolder
        $unfinishedFile = @()
        try {
            # necomitnute zmenene soubory
            $unfinishedFile += @(git ls-files -m --full-name)
            # untracked
            $unfinishedFile += @(git ls-files --others --exclude-standard --full-name)
        } catch {
            throw "Zrejme neni nainstalovan GIT, nepodarilo se ziskat seznam zmenenych souboru v repozitari $scriptFolder"
        }
        Set-Location $location

        #
        # existuji modifikovane necomitnute/untracked soubory
        # abych je jen tak nepreskocil pri generovani modulu, zkusim dohledat verzi z posledniho commitu a tu pouzit
        if ($unfinishedFile) {
            [System.Collections.ArrayList] $unfinishedFile = @($unfinishedFile)

            # Start-Process2 umi vypsat vystup (vcetne chyb) primo do konzole, takze se da pres Select-String poznat, jestli byla chyba
            function Start-Process2 {
                [CmdletBinding()]
                param (
                    [string] $filePath = 'notepad.exe',
                    [string] $argumentList = '/c dir',
                    [string] $workingDirectory = (Get-Location)
                )

                $p = New-Object System.Diagnostics.Process
                $p.StartInfo.UseShellExecute = $false
                $p.StartInfo.RedirectStandardOutput = $true
                $p.StartInfo.RedirectStandardError = $true
                $p.StartInfo.WorkingDirectory = $workingDirectory
                $p.StartInfo.FileName = $filePath
                $p.StartInfo.Arguments = $argumentList
                [void]$p.Start()
                # $p.WaitForExit() # s timto pokud git show HEAD:$file neco vratilo, se proces nikdy neukoncil..
                $p.StandardOutput.ReadToEnd()
                $p.StandardError.ReadToEnd()
            }

            Set-Location $scriptFolder
            $unfinishedFile2 = $unfinishedFile.Clone()
            $unfinishedFile2 | % {
                $file = $_
                $lastCommitContent = Start-Process2 git "show HEAD:$file"
                if (!$lastCommitContent -or $lastCommitContent -match "exists on disk, but not in 'HEAD'") {
                    Write-Warning "Preskakuji zmeneny ale necomitnuty/untracked soubor: $file"
                } else {
                    $fName = [System.IO.Path]::GetFileNameWithoutExtension($file)
                    # upozornim, ze pouziji verzi z posledniho commitu, protoze aktualni je nejak upravena
                    Write-Warning "$fName ma necommitnute zmeny. Pro vygenerovani modulu pouziji jeho verzi z posledniho commitu"
                    # ulozim obsah souboru tak jak vypadal pri poslednim commitu
                    $lastCommitFileContent.$fName = $lastCommitContent
                    # z $unfinishedFile odeberu, protoze obsah souboru pridam, i kdyz z posledniho commitu
                    $unfinishedFile.Remove($file)
                }
            }
            Set-Location $location

            # unix / nahradim za \
            $unfinishedFile = $unfinishedFile -replace "/", "\"
            $unfinishedFileName = $unfinishedFile | % { [System.IO.Path]::GetFileName($_) }

            if ($includeUncommitedUntracked -and $unfinishedFileName) {
                Write-Warning "Vyexportuji i tyto zmenene, ale necomitnute/untracked funkce: $($unfinishedFileName -join ', ')"
                $unfinishedFile = @()
            }
        }

        #
        # v seznamu ps1 k exportu do modulu ponecham pouze ty, ktere jsou v konzistentnim stavu
        # odfiltruji sablony funkci (zacinaji _) a skripty/funkce, ktere delaji v modulu problemy (CredMan)
        $script2Export = (Get-ChildItem (Join-Path $scriptFolder "*.ps1") -File).FullName | where {
            $fName = [System.IO.Path]::GetFileNameWithoutExtension($_)
            if (($unfinishedFile -and $unfinishedFile -match ($_ -replace "\\", "\\" -replace "\.", "\.")) -or $fName -match "^_.*" -or $fName -match "^CredMan") {
                return $false
            } else {
                return $true
            }
        }

        if (!$script2Export -and $lastCommitFileContent.Keys.Count -eq 0) {
            return "V $scriptFolder neni zadna vyhovujici funkce k exportu do $moduleFolder. Ukoncuji"
        }

        # smazu existujici modul
        if (Test-Path $modulePath -ErrorAction SilentlyContinue) {
            Remove-Item $moduleFolder -Recurse -Confirm:$false -ErrorAction SilentlyContinue
        }

        # vytvorim slozku modulu
        [Void][System.IO.Directory]::CreateDirectory($moduleFolder)

        Write-Verbose "Do $modulePath`n"

        # do hashe $lastCommitFileContent pridam dvojice, kde klic je jmeno funkce a hodnotou jeji textova definice
        $script2Export | % {
            $fName = [System.IO.Path]::GetFileNameWithoutExtension($_)
            if (!$lastCommitFileContent.containsKey($fName)) {
                # obsah souboru z disku pridam pouze pokud jiz neni pridan, abych si neprepsal fce vytazene z posledniho commitu
                $content = Get-Content $_ -Encoding $enc
                $lastCommitFileContent.$fName = $content
            }
        }

        #
        # z hodnot v hashi (jmeno funkce a jeji textovy obsah) vygeneruji psm modul
        # poznacim jmeno funkce a pripadne aliasy pro Export-ModuleMember
        $lastCommitFileContent.GetEnumerator() | % {
            $fName = $_.Key
            $content = $_.Value

            Write-Verbose "- exportuji funkci: $fName"

            $function2Export += $fName
            # ulozim si pripadne nastaveni aliasu (Set-Alias), pro Export-ModuleMember
            $setAliasRow = $content | where {$_ -match "^\s*Set-Alias"}
            $setAliasRow | % {
                $parts = $_ -split "\s+"

                if ($_ -match "-na") {
                    # alias nastaven jmennym parametrem
                    # ziskam hodnotu parametru
                    $i = 0
                    $parPosition
                    $parts | % {
                        if ($_ -match "-na") {
                            $parPosition = $i
                        }
                        ++$i
                    }

                    $alias2Export += $parts[$parPosition + 1]
                    Write-Verbose "- exportuji alias: $($parts[$parPosition + 1])"
                } else {
                    # alias nastaven pozicnim parametrem
                    $alias2Export += $parts[1]
                    Write-Verbose "- exportuji alias: $($parts[1])"
                }
            }

            # odstraneni requires pozadavku na verzi
            $content = $content -replace "^#requires -version \d+[\d\.\d]*" # konci cislem nebo cislo.cislo

            $content | Out-File $modulePath -Append $enc
            #"#endregion" | Out-File $modulePath -Append $enc
            "" | Out-File $modulePath -Append $enc
        }

        # nastavim, co se ma z modulu exportovat
        # rychlejsi (pri naslednem importu modulu) je, pokud se exportuji jen explicitne vyjmenovane funkce/aliasy nez pouziti *
        # 300ms vs 15ms :)

        if (!$function2Export) {
            throw "Neexistuji zadne funkce k exportu! Spatne zadana cesta??"
        } else {
            if ($function2Export -match "#") {
                Remove-Item $modulePath -recurse -force -confirm:$false
                throw "Exportovane funkce obsahuji v nazvu nepovoleny znak #. Modul jsem smazal."
            }

            "Export-ModuleMember -function $($function2Export -join ', ')" | Out-File $modulePath -Append $enc
        }

        if ($alias2Export) {
            if ($alias2Export -match "#") {
                Remove-Item $modulePath -recurse -force -confirm:$false
                throw "Exportovane aliasy obsahuji v nazvu nepovoleny znak #. Modul jsem smazal."
            }
            "Export-ModuleMember -alias $($alias2Export -join ', ')" | Out-File $modulePath -Append $enc
        }
    } # konec funkce _generatePSModule

    # ze skriptu vygeneruji modul
    $configHash.GetEnumerator() | % {
        $scriptFolder = $_.key
        $moduleFolder = $_.value

        $param = @{
            scriptFolder = $scriptFolder
            moduleFolder = $moduleFolder
            verbose      = $true
        }
        if ($includeUncommitedUntracked) {
            $param["includeUncommitedUntracked"] = $true
        }

        Write-Output "Generuji modul $moduleFolder ze skriptu v $scriptFolder"
        _generatePSModule @param

        if (!$dontCheckSyntax -and (Get-Command Invoke-ScriptAnalyzer -ErrorAction SilentlyContinue)) {
            # zkontroluji syntax vytvoreneho modulu
            $syntaxError = Invoke-ScriptAnalyzer $moduleFolder -Severity Error
            if ($syntaxError) {
                Write-Warning "V modulu $moduleFolder byly nalezeny tyto problemy:"
                $syntaxError
            }
        }
    }
}