function Search-GPOSetting {
    <#
    .SYNOPSIS
    Slouzi k vyhledani zadaneho stringu v nastavenich vsech AD GPO.

    .DESCRIPTION
    Slouzi k vyhledani zadaneho stringu v nastavenich vsech AD GPO.

    Funguje tak, ze si vygeneruje html reporty s nastavenimi kazde GPO v AD a ty pote prohleda.
    Pokud je report neaktulni ci chybi, tak se nageneruje znovu.

    Reporty se ukladaji v uzivatelskem profilu a mohou zabirat desitky MB (dle poctu GPO v domene).

    .PARAMETER string
    Text, ktery se bude hledat v nastavenich GPO.

    .PARAMETER reports
    Cesta k adresari, do ktereho se budou ukladat html reporty jednotlivych GPO.

    .EXAMPLE
    Search-GPOSetting -string "Always install with elevated privileges"

    Vyhleda v nagenerovanych HTML reportech s nastavenimi vsech domenovych GPO zadany text.
    Pokud nejaky report chybi nebo nebude aktualni, tak se nageneruje znovu.
    #>

    [cmdletbinding()]
    param (
        [Parameter(Position = 0, Mandatory = $True)]
        [string] $string
        ,
        [string] $reports = (Join-Path $env:LOCALAPPDATA "GPOsReports")
    )

    if (!(Test-Path $reports)) {
        Write-Verbose "Vytvorim adresar pro ukladani reportu: $reports"
        $null = New-Item $reports -itemType directory
        # vygeneruji report s nastavenimi
        Write-Warning "Nyni se vytvori cache obsahujici reporty s nastavenimi vsech GPO. To muze trvat i 10 minut!`nPote v ni dojde k vyhledani zadaneho retezce."
    }

    # zruseni specialniho vyznamu znaku
    $string = [regex]::Escape($string)

    Write-Verbose "Reporty se ukladaji do: $reports"

    try {
        $GPOs = Get-GPO -All -ErrorAction Stop
    } catch {
        throw "Nepovedlo se ziskat seznam GPO. Chyba byla $_"
    }


    foreach ($gpo in $GPOs) {
        $path = (Join-Path $reports $gpo.id) + ".html"
        if ((Test-Path $path -ErrorAction SilentlyContinue) -and (Get-Item $path).lastWriteTime -ge $gpo.modificationtime) {
            # report je aktualni
            continue
        }

        Write-Verbose "Generuji report pro $($gpo.displayName)"
        try {
            Get-GPOReport -Guid $gpo.id -path $path -ReportType Html -ea Stop
        } catch {
            Write-Error "Nepovedlo se ziskat nastaveni GPO. Chyba byla $_"
        }
    }

    $foundReports = @()
    foreach ($report in (Get-ChildItem $reports -Filter *.html).FullName) {
        Write-Verbose "Kontroluji obsah nastaveni $report"
        # po radcich hledam v kazdem reportu zadany string
        $match = (Get-Content $report) -split "`n" | Select-String $string -AllMatches
        if ($match) {
            $guid = (Split-Path $report -Leaf) -replace '.html'
            $foundReports += $report
            try {
                $GPOName = (Get-GPO -Guid $guid).displayName
            } catch {
                Write-Output "GPO s GUID $guid se nepodarilo dohledat, zrejme jiz v AD neexistuje == html report z cache smazu"
                Remove-Item $report -Force
                continue
            }

            Write-Host "V GPO $GPOName bylo nalezeno zde:" -ForegroundColor Green
            Write-Host "$match`n`n"
        }
    }

    if ($foundReports) {
        $a = Read-Host "Chcete dane GPO zobrazit? A|N"
        if ($a -eq 'a') {
            $foundReports | % {Invoke-Expression $_}
        }
    }
}