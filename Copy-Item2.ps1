function Copy-Item2 {
    <#
    .SYNOPSIS
    Fce slouzi k chytremu kopirovani souboru/adresaru. Umoznuje i zabaleni zdroje a kopirovani ZIP souboru misto originalu.

    .DESCRIPTION
    Pro kopirovani velkeho mnozstvi malych souboru na vic stroju je lepsi pouzit prepinac copyZipped. Kdy se zdroj nejdrive zabali, kopiruje se dany ZIP a na cilovych strojich se pote opet rozbali.

    .PARAMETER ComputerName
    Seznam stroju na ktere budu kopirovat.

    .PARAMETER Source
    Uvadi zdroj odkud se bude kopirovat. Musi byt zadano jako UNC cesta. Napr. \\titan01\temp ci \\titan01\temp\program.exe

    .PARAMETER Destination
    Uvadi kam se bude kopirovat. Pokud adresar neexistuje, tak se automaticky vytvori. Musi byt zadano jako lokalni cesta. Napr. C:\temp.

    .PARAMETER giveUsersModifyPerm
    Prepínač rikajici, ze na cilovem objektu se jeste nastavi pro skupinu Users Modify NTFS prava (vcetne dedeni na podobjekty).

    .PARAMETER copyZipped
    Prepinac rikajici, ze kopirovana slozka se nejdrive zabali na zdrojovem stroji, zip archiv se skopiruje na cil a tam se opet rozbali.
    Efektivni pouze u adresaru s vetsim poctem souboru a kopirovani na vetsi pocet stroju.
    Prepinac se neda pouzit v kombinaci s kopirovanim souboru.

    .PARAMETER noConfirm
    Prepinac rikajici, ze neni potreba potvrzovat akci kopirovani.

    .PARAMETER EmailReport
    Prepinac rikajici, ze pokud se behem kopirovani vyskytnou chyby, tak budou zaslany na $emailAddress.

    .PARAMETER emailAddress
    Parametr udavajici adresu, na kterou budou zaslany pripadne chyby, ktere se objevily pri kopirovani.

    .EXAMPLE
    $hala | copy-item2 -s "\\titan01\c$\qtsdk" -d "C:\qtsdk"
    Do C:\qtsdk na kazdem stroji v hale nakopiruje obsah adresare "\\titan01\c$\qtsdk".

    .EXAMPLE
    copy-item2 -c "titan05","titan06" -s "\\titan01\c$\qtsdk" -d "C:\qtsdk"
    Do C:\qtsdk na titan05,titan06 nakopiruje obsah adresare "\\titan01\c$\qtsdk".

    .EXAMPLE
    $hala | ogv2 | copy-item2 -s "\\titan01\c$\qtsdk\rad.log" -d "C:\temp"
    Na vybrané stroje z haly nakopíruje do C:\temp soubor rad.log

    .NOTES
    Author: Ondřej Šebela - ztrhgf@seznam.cz
    Povoleni CredSSP by melo byt reseno skrze GPO: Windows Remote Management a Enable CredSSP.
    Vice zde http://dustinhatch.tumblr.com/post/24589312635/enable-powershell-remoting-with-credssp-using-group
    #>

    #[CmdletBinding(SupportsShouldProcess=$true)]
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true, Position = 0, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true, HelpMessage = "zadej jmeno stroje/ů")]
        [Alias("c", "CN", "__Server", "IPAddress", "Server", "Computer", "Name", "SamAccountName")]
        [ValidateNotNullOrEmpty()]
        [String[]] $ComputerName
        ,
        [Parameter(Mandatory = $true, Position = 1, HelpMessage = "zadej cestu ke zdroji v UNC tvaru!")]
        [ValidateScript( {$_ -match "^\\\\[.\w]+\\\w+"})] # kontrola jestli jde o UNC cestu a to vcetne tecek v prvni casti adresy
        #	[ValidateScript({Test-Path $_})] # kontrola jestli $source existuje
        [Alias("s")]
        [string] $source
        ,
        [Parameter(Mandatory = $true, Position = 2, HelpMessage = "zadej cilovy adresar (jako lokalni cestu!)")]
        #		[ValidateScript({$_ -match "^[a-z]:\\"})]
        [Alias("d")]
        [string] $destination
        ,
        [switch] $giveUsersModifyPerm
        ,
        [ValidateScript( {
                If (Get-Command zip-folder, unzip-file -errorAction Stop) {
                    $true
                } else {
                    Throw "Jedna z potrebnych funkci (zip-folder,unzip-file) v prostredi chybi."
                }
            })]
        [ValidateScript( {
                If ($source -match "\\[^\.]+\.[\w]{2,4}$") {
                    Throw "Snazite se kopirovat soubor! Pro soubory neni kopirovani ZIP podporovano."
                } else {
                    $true
                }
            })]
        [switch] $copyZipped
        ,
        [switch] $noConfirm
        ,
        [switch] $emailReport
        ,
        $emailAddress = "sebela@fi.muni.cz"

    )

    BEGIN {
        $error.clear()

        #region preruseni skriptu pokud kopiruji soubor a dal jsem copyZipped (duplicitni kontrola, protoze pokud $source zadam jako pozicni a ne named parametr tak se validace par. nespusti)
        If ($source -match "\\[^\.]+\.[\w]{2,4}$" -and $copyZipped) {
            Throw "Snazite se kopirovat soubor! Pro soubory neni kopirovani ZIP podporovano."
        }
        #endregion

        #region pomocne promenne
        $originalSource = $source
        $SourceCompName = $source.Split("\\")[2]
        $SourceObjectName = Split-Path $source -Leaf
        $sourceIsFolder = test-path $source -pathType container
        $destinationIsFile = $destination -match "\\[^\.]+\.[\w]{2,4}$"
        $destinationObjectName = Split-Path $destination -Leaf
        $destinationFolderName = Split-Path $destination -Parent
        [array]$global:CompletedSources = ($SourceCompName)
        $jobs = @()
        #endregion

        #region potvrzeni akce
        function chcete-pokracovat {
            while ($choice -notmatch "[A|N]") {
                $choice = read-host "Pokračovat? (A|N)"
            }
            if ($choice -eq "N") {
                break
            }
        }

        if ($sourceIsFolder) {
            write-output "Obsah adresáře $source se nakopíruje do adresáře $(Split-Path $destination -Leaf)"
            if (!$noConfirm) {
                chcete-pokracovat
            }
        }

        if (!$sourceIsFolder) {
            if ($destinationIsFile) {
                Write-Output "Soubor $SourceObjectName se nakopíruje do adresáře $destinationFolderName se jménem $destinationObjectName"
                if (!$noConfirm) {
                    chcete-pokracovat
                }
            } else {
                Write-Output "Soubor $SourceObjectName se nakopíruje do adresáře $destination"
                if (!$noConfirm) {
                    chcete-pokracovat
                }
            }
        }
        #endregion

        #region info o zaslani emailu
        if ($emailReport) {
            write-output "Na $emailAddress dojde na konci k zaslani vysledku kopirovani."
        }
        #endregion

        #region odstraneni zdrojoveho pc ze seznamu cilu
        # do pole matches ulozim cast X:\
        $null = $source -match "[a-z]{1}\$\\[\w\\.]+"
        #pokud pristupuji primo na disk$
        if ($matches) {
            # v ziskanem matchi nahradim $ za : a \ na konci za prazdny retezec
            $SourceLocalPath = $matches[0] -replace "\$", ":" -replace "\\$", ""
            # v destination nahradim \ na konci za prazdny retezec
            $DestinationLocalPath = $destination -replace "\\$", ""
            if ($ComputerName -like "*$SourceCompName*" -and ($SourceLocalPath -eq $DestinationLocalPath)) {
                $ComputerName = $ComputerName -replace "$SourceCompName", $null | ? {$_}  # ? {$_} zahodi prazdne radky
                Write-Warning "Ze seznamu cilu byl odstranen stroj $SourceCompName protoze se shodovala zdrojova a cilova slozka"
            }
        } elseif ($ComputerName -like "*$SourceCompName*") {
            # pokud pristupuji na klasickou UNC cestu bez pismene disku (nepoznam jestli se shoduji = radeji odstranim)
            $ComputerName = $ComputerName -replace "$SourceCompName", $null | ? {$_}
            Write-Warning "Ze seznamu cilu byl odstranen stroj $SourceCompName protoze je zdrojem dat"
        }
        #endregion

        #region scriptblock pro invoke-command
        $ScriptBlock = {
            [CmdletBinding()]
            param
            (
                $VerbosePreference
                ,
                $source
                ,
                $SourceObjectName
                ,
                $destination
                ,
                $destinationIsFile
                ,
                $destinationObjectName
                ,
                $destinationFolderName
                ,
                $computer
                ,
                $global:CompletedSources
                ,
                $giveUsersModifyPerm
                ,
                $copyZipped
                ,
                $UnzipFileFunctionDef
            )

            # nastaveni verbose
            if ($VerbosePreference.value) {
                $VerbosePreference = $VerbosePreference.value
            }

            #region kdyz zdrojem je adresar
            $sourceIsFolder = test-path $source -pathType container
            if ($sourceIsFolder) {
                # pokud je zdrojem adresar a zaroven cilova cesta existuje, tak se osetri tvar $source. Kvuli chovani cmdletu copy-item, kdy pokud zdrojova adresa nekonci \* a zadany cilovy adresar existuje, tak se v nem vytvori subfolder s obsahem zdroje coz nechceme
                if (test-path $destination)	{
                    switch -regex ($source)	{
                        '\\$' {$source = "$source*"; break} # kdyz konci "\" tak se prida "*"
                        '\w$' {$source = "$source\*"; break} # kdyz konci alfanumerickym znakem tak se prida "\*"
                        default {break}
                    }
                }
            }
            #endregion

            #region kdyz zdrojem je soubor
            else {
                # oprava toho, ze pokud posledni cast $destination adresy neexistuje, tak copy-item misto aby ho vytvoril, vytvori soubor s jeho nazvem a obsahem $source souboru

                # pokud $destination je soubor a adresar ve kterem by se mel vytvorit neexistuje, tak jej vytvorim
                if ($destinationIsFile -and !(Test-Path $destinationFolderName) -and !($copyZipped)) {
                    Write-output "na stroji $computer vytvarim adresar $destinationFolderName abych do nej mohl nakopirovat zdrojovy soubor"
                    $null = New-Item -Path $destinationFolderName -ItemType directory -Confirm:$false -Force
                }

                # pokud $destination je adresar a zaroven neexistuje
                if (!($destinationIsFile) -and !(Test-Path $destination) -and !($copyZipped)) {
                    Write-output "na stroji $computer vytvarim adresar $destination , abych do nej mohl nakopirovat zdrojovy soubor"
                    $null = New-Item -Path $destination -ItemType directory -Confirm:$false -Force
                }
            }
            #endregion

            #region uprava destination adresy kvuli kopirovani ZIP souboru
            if ($copyZipped) {
                # jelikoz budu kopirovat ZIP archiv a ne puvodni data, tak do $ZipDestination ulozim originalni $destination abych ho nasledne mohl zmenit
                $ZipDestination = $destination
                # $destination zmenim na root disku kde mel byt puvodni $destination + nazev ZIP archivu
                if ($destination -match "^\\\\[.\w]+\\\w+") {
                    # destination je v UNC tvaru
                    if ($destination -match "^\\\\[.\w]+\\[a-z]{1}\$") {
                        # destination je v UNC tvaru a obsahuje pismeno disku
                        $destination = Join-Path -Path $Matches[0] -ChildPath "archive_to_copy.zip"
                    } else {
                        # destination je v UNC tvaru a neobsahuje pismeno disku
                        $destination = "\\" + "$computer" + "\c$\" + "archive_to_copy.zip"
                    }
                } else {
                    # destination je v lokalnim tvaru
                    $destination = Join-Path -Path (Split-Path $destination -Qualifier) -ChildPath "archive_to_copy.zip"
                }
                Write-Verbose "Puvodni cestu $ZipDestination jsem upravil na $destination kvuli nakopirovani ZIP souboru"
            }
            #endregion

            if ($VerbosePreference -eq "Continue" -or $VerbosePreference -eq 2) {
                Write-Output "Kopíruji na $computer z $source do $destination"
            } else {
                Write-Output "Kopíruji na $computer"
            }

            Copy-Item $source $destination -recurse -force

            #region nastaveni opravneni
            if (!$copyZipped) {
                # pokud kopiruji ZIP tak opravneni zmenim az po rozbaleni
                if ($giveUsersModifyPerm) {
                    # pokud jsem kopiroval ZIP, tak jsem upravil $destination, musim vratit zpet
                    if ($copyZipped) {
                        $destination = $ZipDestination
                    }
                    Write-Verbose "Ziskavam aktualni opravneni na $destination."
                    $Acl = Get-Acl $destination
                    $inheritance = [int]([System.Security.AccessControl.InheritanceFlags]::ContainerInherit) + [int]([System.Security.AccessControl.InheritanceFlags]::ObjectInherit)
                    $propagation = [System.Security.AccessControl.PropagationFlags]::None
                    if ($destinationIsFile) {
                        $AccessRule = New-Object System.Security.AccessControl.FileSystemAccessRule("Users", "Modify", "Allow")
                    } else {
                        $AccessRule = New-Object System.Security.AccessControl.FileSystemAccessRule("Users", "Modify", $inheritance, $propagation, "Allow")
                    }
                    $Acl.SetAccessRule($AccessRule)
                    Write-Verbose "Upravuji opravneni na $destination."

                    Set-Acl $destination $Acl
                }
            }
            #endregion
        } # konec scriptblock
        #endregion

        if ($copyZipped) {
            #region vytvoreni definice funkci pro invoke-command
            $ZipFileFunctionDef = "function zip-folder { ${function:zip-folder} }"
            $UnzipFileFunctionDef = "function unzip-file { ${function:unzip-file} }"
            #endregion

            #region definice scriptblocku pro vytvoreni ZIP archivu
            $ScriptBlock2 = {
                Param( $ZipFileFunctionDef, $source, $SourceDriveLetter, $SourceCompName )
                # z definice predane jako argument opetovne vytvorim funkce a nactu pomoci dot source (tecka)
                . ([ScriptBlock]::Create($ZipFileFunctionDef))

                # dle tvaru source adresy zvolim
                if ($SourceDriveLetter) {
                    # pokud source v nazvu obsahuje i pismeno disku, tak ZIP bude v rootu daneho disku
                    $ZipDestination = $SourceDriveLetter + ":\" + "archive_to_copy.zip"
                } else {
                    # pokud source neobsahuje pismeno disku, tak umistim ZIP archiv do rootu C:\
                    $ZipDestination = "C:\archive_to_copy.zip"
                }
                Zip-Folder $source $ZipDestination -IncludeBaseFolder:$true
            }
            #endregion

            #region vytvoreni ZIP archivu na zdrojovem stroji v rootu disku, na kterem je umisten $source + uprava $source adresy
            try {
                # match automaticky ulozi do pole $matches vsechny shody umistene v ()
                try {
                    $null = $source -match '^(\\\\([\w]+)[^$]+([a-z])\$).*'
                    $SourceDriveLetter = $matches[3]
                    $SourceCompNameWithLetter = $matches[1]
                    #				$SourceCompName = $matches[2]
                } catch {}

                # vytvorim na stroji v rootu ZIP archiv
                Write-Output "na $SourceCompName vytvarim ZIP archiv $ZipDestination"
                Invoke-Command -ComputerName $SourceCompName -ScriptBlock $ScriptBlock2 -ArgumentList $ZipFileFunctionDef, $source, $SourceDriveLetter, $SourceCompName -ErrorAction Stop

                #region uprava $source adresy (nepracuji s originalnim zdrojem ale ZIP archivem)
                # upravim $source adresu aby odpovidala umisteni ZIP archivu
                if ($SourceDriveLetter) {
                    # pokud source v nazvu obsahuje i pismeno disku, tak ZIP bude v rootu daneho disku
                    $source = Join-Path -path $SourceCompNameWithLetter -child "archive_to_copy.zip"
                } else {
                    # pokud source neobsahuje pismeno disku, tak umistim ZIP archiv do rootu C:\
                    $source = "\\" + $SourceCompName + "\" + "c$\archive_to_copy.zip"
                }
                #endregion

            } catch {
                Write-Output "Pri vytvareni archivu se vyskytla chyba"
                Write-Error -Message "Error: $($_.Exception.Message) - Line Number: $($_.InvocationInfo.ScriptLineNumber)"
                #TODO zvolit vhodne reseni problemu..
            }
            #endregion
        }

        #region definice scriptblocku pro akce provadene po nakopirovani ZIP archivu (rozbaleni, nastaveni prav,...)
        if ($copyZipped) {
            $CopyZippedScriptblock = {
                param (
                    $VerbosePreference,
                    $UnzipFileFunctionDef,
                    $destination,
                    $SourceObjectName,
                    $DestinationObjectName,
                    $giveUsersModifyPerm,
                    $copyzipped
                )
                #region uprava destination adresy kvuli kopirovani ZIP souboru
                # jelikoz budu kopirovat ZIP archiv a ne puvodni data, tak do $ZipDestination ulozim originalni $destination abych ho nasledne mohl zmenit
                $ZipDestination = $destination
                # $destination zmenim na root disku kde mel byt puvodni $destination + nazev ZIP archivu
                if ($destination -match "^\\\\[.\w]+\\\w+") {
                    # destination je v UNC tvaru
                    if ($destination -match "^\\\\[.\w]+\\[a-z]{1}\$") {
                        # destination je v UNC tvaru a obsahuje pismeno disku
                        $destination = Join-Path -Path $Matches[0] -ChildPath "archive_to_copy.zip"
                    } else {
                        # destination je v UNC tvaru a neobsahuje pismeno disku
                        $destination = "\\" + "$computer" + "\c$\" + "archive_to_copy.zip"
                    }
                } else {
                    # destination je v lokalnim tvaru
                    $destination = Join-Path -Path (Split-Path $destination -Qualifier) -ChildPath "archive_to_copy.zip"
                }
                Write-Verbose "Puvodni cestu $ZipDestination jsem upravil na $destination kvuli nakopirovani ZIP souboru"
                #endregion

                #region rozbaleni nakopirovaneho ZIP archivu
                # z definice predane jako argument opetovne vytvorim funkci a nactu pomoci dot source (tecka)
                . ([ScriptBlock]::Create($UnzipFileFunctionDef))
                $ZipDestinationFolder = $ZipDestination | Split-Path -Parent
                if (!(Test-Path $ZipDestinationFolder)) {
                    Write-Output "vytvarim adresar $ZipDestinationFolder protoze neexistuje"
                    $null = New-Item -ItemType "directory" -Path $ZipDestinationFolder -Confirm:$false
                }

                Write-Verbose "rozbaluji $destination do $ZipDestinationFolder"
                unzip-file $destination $ZipDestinationFolder
                #endregion

                #region prejmenovani rozbaleneho adresare aby odpovidal zadani
                # rozbaleny adresar ma stejny nazev jako ten zdrojovy (ze ktereho byl ZIP archiv vytvoren), proto je potreba jej rozbalit pokud $source a $destination adresare nejsou shodne
                if ($SourceObjectName -ne $DestinationObjectName) {
                    $ActualZipDestinationFolderName = $ZipDestination -replace $DestinationObjectName, $SourceObjectName
                    $CorrectZipDestinationFolderName = Join-Path (Split-Path $ActualZipDestinationFolderName -parent) $DestinationObjectName
                    # pokud jiz na stroji existuje adresar s cilovym jmenem, tak jej musim pred prejmenovanim smazat
                    if (Test-Path $CorrectZipDestinationFolderName -ErrorAction SilentlyContinue) {
                        try {
                            Write-Verbose "Adresar $CorrectZipDestinationFolderName jiz existoval, smazal jsem."
                            Remove-Item $CorrectZipDestinationFolderName -Force -Recurse -Confirm:$false
                        } catch {
                            Write-Warning "Pri mazani $CorrectZipDestinationFolderName na $computer se vyskytla chyba. Je tam tedy jak puvodni, tak neprejmenovany novy. Akci prejmenovani tedy musim preskocit, stejne by skoncila chybou."
                            continue
                        }
                    }

                    Write-Verbose "V adresari $ActualZipDestinationFolderName prejmenuji $SourceObjectName na $DestinationObjectName"
                    Rename-Item $ActualZipDestinationFolderName $DestinationObjectName -Force -Confirm:$false -ErrorAction Stop
                }
                #endregion

                #region nastaveni opravneni
                if ($giveUsersModifyPerm) {
                    # pokud jsem kopiroval ZIP, tak jsem upravil $destination, musim vratit zpet
                    if ($copyZipped) {
                        $destination = $ZipDestination
                    }
                    Write-Verbose "Ziskavam aktualni opravneni na $destination."
                    $Acl = Get-Acl $destination
                    $inheritance = [int]([System.Security.AccessControl.InheritanceFlags]::ContainerInherit) + [int]([System.Security.AccessControl.InheritanceFlags]::ObjectInherit)
                    $propagation = [System.Security.AccessControl.PropagationFlags]::None
                    if ($destinationIsFile) {
                        $AccessRule = New-Object System.Security.AccessControl.FileSystemAccessRule("Users", "Modify", "Allow")
                    } else {
                        $AccessRule = New-Object System.Security.AccessControl.FileSystemAccessRule("Users", "Modify", $inheritance, $propagation, "Allow")
                    }
                    $Acl.SetAccessRule($AccessRule)
                    Write-Verbose "Upravuji opravneni na $destination."

                    Set-Acl $destination $Acl
                }
                #endregion

                #TODO: pokud source pinga, pokud ne tak z nej udelat source?
                #region smazani ZIP archivu z ciloveho stroje
                Write-Verbose "mazu ZIP soubor $destination"
                sleep -Milliseconds 200
                Remove-Item $destination -Confirm:$false -Force
                #endregion
            }
        }
        #endregion

        #region promenne, ktere je potreba definovat az na konci BEGIN ci obnovit jejich hodnoty
        $sourceIsFolder = test-path $source -pathType container
        $destinationIsFile = $destination -match "\\[^\.]+\.[\w]{2,4}$"
        $destinationObjectName = Split-Path $destination -Leaf
        $destinationFolderName = Split-Path $destination -Parent
        #endregion
    }

    PROCESS {
        foreach ($computer in $ComputerName) {
            if (Test-Connection -ComputerName $computer -Count 2 -ErrorAction SilentlyContinue) {
                #region vybrani nahodneho zdroje z dostupnych a uprava $source adresy dle potreby
                if (!$copyZipped) {
                    #TODO: nezajistuji ze se otestuji vsechny polozky v $CompletedSources (get-random v kombinaci s poctem prvku v poli)
                    $NewSourceCompName = ""
                    $PreviousSourceCompName = ""
                    $CompletedSourcesCount = $global:CompletedSources.count
                    $private:PocetPokusu = 0
                    $private:destination = $destination

                    #TODO zmena source funguje chybne ..opravit
                    # Write-Verbose "Vyberu jiny zdroj dat a zmenim source adresu"
                    # z pole stroju, kam jsem uspesne nakopiroval data nahodne vyberu jeden a upravim source adresu
                    # uvazuji i variantu kdy source a destination neukazuji na stejny adresar + vyberu po case za source zase originalni zdroj
                    # do {
                    #     $NewSourceCompName = get-random $global:CompletedSources -Count 1
                    #     $PreviousSourceCompName = $source.Split("\\")[2]

                    #     # kopiruji z originalniho zdroje
                    #     if ($NewSourceCompName -eq $SourceCompName) {
                    #         $source = $originalSource
                    #         Write-Verbose "	Novy source je $source (kopiruji z puvodniho zdroje)"
                    #     } else {
                    #         # kopiruji z NEoriginalniho zdroje
                    #         $oldSource = $source
                    #         $NewSourceCompName
                    #         $destination
                    #         $source = (join-path "\\$NewSourceCompName" $destination) -replace ":", "$"
                    #         Write-Verbose "	Novy source je $source (puvodne $oldSource)"
                    #     }

                    #     $private:PocetPokusu++
                    # } until ((Test-Connection $NewSourceCompName -Count 1 -Quiet) -or ($private:PocetPokusu = $CompletedSourcesCount))

                    # ukonceni skriptu pokud nemohu pouzit zadny z dostupnych zdroju
                    if ($private:PocetPokusu -eq $CompletedSourcesCount -and ($NewSourceCompName -ne $PreviousSourceCompName)) {
                        Write-Warning "Neni dostupny zadny zdroj dat!"
                        break
                    }
                }
                #endregion

                #region vytvoreni hashe s parametry pro invoke-command
                $InvokeCommandParams = @{
                    ScriptBlock  = $ScriptBlock
                    ErrorAction  = "Stop"
                    ArgumentList = $VerbosePreference, $source, $SourceObjectName, $destination, $destinationIsFile,
                    $destinationObjectName, $destinationFolderName, $computer, $global:CompletedSources, $giveUsersModifyPerm, $copyZipped, $UnzipFileFunctionDef
                }
                #endregion

                try {
                    # upravim cesty aby byly v UNC tvaru
                    $InvokeCommandParams2 = $InvokeCommandParams.clone()
                    $InvokeCommandParams2.ArgumentList[3] = (Join-Path "\\$computer" $destination) -replace ":", "$"
                    $InvokeCommandParams2.ArgumentList[6] = (Join-Path "\\$computer" $destinationFolderName) -replace ":", "$"
                    Invoke-Command @InvokeCommandParams2
                    # v pripade uspesneho zkopirovani pridam cil do seznamu potencialnich zdroju
                    if (!$copyZipped) {
                        if ($? -and $global:CompletedSources -notlike "*$computer*") {
                            $global:CompletedSources += $computer
                        }
                    }
                } catch {
                    Write-Warning "Nepovedlo se ani klasicke kopirovani iniciovane z lokalniho stroje"
                    Write-Warning "Chyba byla: $($_.Exception.Message) Cislo radku: $($_.InvocationInfo.ScriptLineNumber)"
                }
            } else {
                Write-Warning "$computer nepingá"
            }
        }
    }

    END {
        if ($copyZipped) {
            #region smazani ZIP archivu ze zdrojoveho stroje
            Write-Verbose "mazu zdrojovy ZIP soubor $source"
            Remove-Item $source -Confirm:$false -Force
            #endregion

            #region ziskani vysledku akce: rozbaleni, nastaveni prav,..
            if ($jobs) {
                Write-Output "Ziskavam vysledky jobu (rozbaleni, nastaveni prav,...)"
                Wait-Job -Job $jobs | Out-Null
                foreach ($job in $jobs) {
                    if ($job.State -eq 'Failed') {
                        Write-Host "Job na $($job.location) skoncil neuspechem: $($job.ChildJobs[0].JobStateInfo.Reason.Message)" -ForegroundColor Red # pozuti radeji $job.ChildJobs[0].Error ?
                    } else {
                        Write-Host "Job na $($job.location) skoncil uspechem $(Receive-Job $job)" -ForegroundColor Green
                        Write-Verbose ($job | fl *)
                    }
                }
            }
            #endregion
        }

        if ($emailReport) {
            #vytvorim si hash s parametry
            $CommandParameters = @{
                From    = "copy@fi.muni.cz"
                To      = $emailAddress
                ReplyTo = $emailAddress
            }
            # nastavim zbyle parametry
            if ($Error) {
                $CommandParameters.Add("Body", "PŘÍKAZ:`n$($myinvocation.line) `n`nCHYBY:`n$Error")
                $CommandParameters.Add("Subject", 'Chyby z copy-item2')
            } else {
                $CommandParameters.Add("Body", "PŘÍKAZ:`n$($myinvocation.line) `n`nskončil bez chyb.")
                $CommandParameters.Add("Subject", 'copy-item2')
            }

            Send-Email @CommandParameters
        }
    }
}