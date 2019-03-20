function Get-AdministrativeEvents {
    <#
	.SYNOPSIS
        Fce slouží k vypsani Warning, Error a Critical eventu z vybranych logu.
        Seznam logu by mel vicemene odpovidat view Administrative Events.

    .DESCRIPTION
        Fce slouží k vypsani Warning, Error a Critical eventu z vybranych logu.
        Seznam logu by mel vicemene odpovidat view Administrative Events.

        Defaultně se vypíší eventy za posledních 24 hodin.
        Ignoruji se eventy z logu ForwardedEvents!

    .PARAMETER ComputerName
        Seznam strojů, ze kterých vytahnu chybova hlaseni.

    .PARAMETER Newest
        Kolik událostí se má ziskat.

    .PARAMETER After
        Po jakém datu se mají eventy hledat.

    .PARAMETER Before
        Před jakým datem se mají eventy hledat.

    .PARAMETER LogName
        Tyto logy budou pridany ke standardne zobrazovanym.

    .PARAMETER JustLogNames
        Prepinac slouzici k vypsani nazvu logu, ze kterych by se na danem stroji vypisovaly chybove udalosti.

    .PARAMETER severity
        Jake typy eventu se maji vypsat.
        Vychozi jsou vsechny.

        1 = critical
        2 = error
        3 = warning

    .EXAMPLE
        Get-AdministrativeEvents $hala
        vypise chybove eventy na vsech strojich v hale

    .NOTES
        Author: Ondřej Šebela - ztrhgf@seznam.cz
	#>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false, Position = 0, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true, HelpMessage = "zadej jmeno stroje/ů")]
        [Alias("c", "CN", "__Server", "IPAddress", "Server", "Computer", "SamAccountName")]
        [ValidateNotNullOrEmpty()]
        [String[]] $ComputerName = $env:computername
        ,
        [Parameter(Mandatory = $false, Position = 2)]
        [int] $Newest
        ,
        [ValidateScript( {
                If (($_.getType().name -eq "string" -and [DateTime]::Parse($_)) -or ($_.getType().name -eq "dateTime")) {
                    $true
                } else {
                    Throw "Zadejte ve formatu dle vaseho culture. Pro cs-CZ napr.: 15.2.2019 15:00. Pro en-US pak prohodit den a mesic."
                }
            })]
        [Alias("from")]
        $After
        ,
        [ValidateScript( {
                If (($_.getType().name -eq "string" -and [DateTime]::Parse($_)) -or ($_.getType().name -eq "dateTime")) {
                    $true
                } else {
                    Throw "Zadejte ve formatu dle vaseho culture. Pro cs-CZ napr.: 15.2.2019 15:00. Pro en-US pak prohodit den a mesic."
                }
            })]
        [Alias("to")]
        $Before
        ,
        [ValidateNotNullOrEmpty()]
        [string[]] $LogName
        ,
        [switch] $JustLogNames
        ,
        [ValidateSet(1, 2, 3)]
        [ValidateNotNullOrEmpty()]
        [array] $severity = @(1, 2, 3)
    )

    BEGIN {
        #test
        $ComputerName = $ComputerName | % {$_.tolower()} # PS 2.0 neumi tolower na [string[]]
        if ($ComputerName -contains ($env:COMPUTERNAME).ToLower() -and !([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
            Write-Error "Vyzaduje admin prava. Ukoncuji."
            Break
        }

        # ve vychozim stavu vypise udalosti za posledni den
        if (!$after -and !$newest -and !$before) {
            $after = (Get-Date).addDays(-1)
            Write-Warning "Vyhledaji se udalosti za posledni den"
        }

        if ($after -and $after.getType().name -eq "string") {$after = [DateTime]::Parse($after)}
        if ($before -and $before.getType().name -eq "string") {$before = [DateTime]::Parse($before)}

        if ($after -and $before -and $after -gt $before) {
            throw "From nesmi byt vetsi nez To"
        }
        if ($after -and $before -and $after -eq $before) {
            throw "After je stejne jako before. Ukoncuji."
        }

        $functionString = Get-FunctionString -Function Convert-DateToXmlDate, Format-XMLIndent
    }

    PROCESS {
        Invoke-Command2 -computerName $ComputerName {
            param ($newest, $after, $before, $logName, $justLogNames, $functionString, $severity)

            if ($PSVersionTable.PSVersion.Major -lt 3) {
                # pouzite funkce pouzivaji nepodporovane operatory atd
                Write-Warning "Ukoncuji. Na $env:COMPUTERNAME je nepodporovana verze PS (je potreba alespon verze 3.0)"
                return
            }

            # dot sourcingem zpristupnim pomocne funkce z jejich textove definice
            $scriptblock = [System.Management.Automation.ScriptBlock]::Create($functionString)
            . $scriptblock

            ### vytvoreni XML dotazu
            # zjistim vsechny dostupne logy
            $allLogs = Get-WinEvent -ListLog * -ea silentlycontinue | select isenabled, logname
            if (!$allLogs) { throw "Na $env:COMPUTERNAME se nepodarilo ziskat seznam logu" }

            # do include davejte Microsoft-* logy, ktere, chcete do vysledku zahrnout (koncici /Admin se pridavaji automaticky)
            # obsah include je potreba (pri vydani noveho OS) aktualizovat
            # pozn.: bohuzel se nedaji pridat vsechny dostupne logy, protoze je horni limit na jejich pocet v XML query
            $include = 'Microsoft-AppV-Client/Virtual Applications', 'Microsoft-Windows-DataIntegrityScan/CrashRecovery', 'Microsoft-Windows-WindowsBackup/ActionCenter', "Microsoft-Windows-Hyper-V-VMMS-Networking", "Microsoft-Windows-Hyper-V-VMMS-Storage", 'Microsoft-Windows-StorageSpaces-Driver/Operational', 'Microsoft-Windows-Ntfs/Operational', 'Microsoft-Windows-Ntfs/WHC', 'Microsoft-Windows-Disk/Operational', 'Microsoft-Windows-Storage-Disk/Admin', 'Microsoft-Windows-Storage-Disk/Analytic', 'Microsoft-Windows-Storage-Disk/Debug', 'Microsoft-Windows-Storage-Disk/Operational'
            $adminViewLogs = $allLogs | where { $_.isenabled -eq $true } | % {
                if ($include -contains $_.logname) {$_}
                elseif (($_.logname -match "^Microsoft-" -and $_.logname -notmatch '/Admin$') -or $_.logname -match 'ForwardedEvents') {}
                else {$_}
            } | select -exp logname

            Write-Verbose "Seznam logu k prohledani:`n$($adminViewLogs -join "`n")"

            # pridam zadane logy z LogName do seznamu logu, pokud existuji
            if ($logName) {
                foreach ($log in $logName) {
                    if ($allLogs.logname -contains $log) {
                        $adminViewLogs += $log
                    } else {
                        Write-Warning "Zadany log $log z parametru LogName na $env:COMPUTERNAME neexistuje, ignoruji"
                    }
                }
            }

            # zajimaji mne pouze nazvy logu, ze kterych budu vypisovat chyby
            if ($justLogNames) {
                return New-Object PSObject -Property ([Ordered]@{Computer = $env:COMPUTERNAME; Logs = $adminViewLogs })
            }

            # vygeneruji XML filtr pro jednotlive logy
            # vracim pouze Warning, Error a Critical udalosti
            $severity | % {
                if ($severityFilter) {$severityFilter += " or "}
                $severityFilter += "Level=$_"
            }
            $adminViewLogs | % { $filterLogs += "<Select Path=`"$_`">*[System[($severityFilter)]]</Select>" }

            # zakladni XML dotaz
            [xml] $xml = "
			<QueryList>
                <Query Id=`"0`" Path=`"Application`">
                    $filterLogs
                </Query>
			</QueryList>
			"
            # pridani filtrovani dle data do XML dotazu
            if ($after -and $before) {
                $startDate = Convert-DateToXmlDate $after
                $endDate = Convert-DateToXmlDate $before
                $dateFilter = " and TimeCreated[@SystemTime>=`'$startDate`' and @SystemTime<=`'$endDate`']]]"
            } elseif ($before) {
                $endDate = Convert-DateToXmlDate $before
                $dateFilter = " and TimeCreated[@SystemTime<=`'$endDate`']]]"
            } elseif ($after) {
                $startDate = Convert-DateToXmlDate $after
                $dateFilter = " and TimeCreated[@SystemTime>=`'$startDate`']]]"
            }
            if ($dateFilter) {
                # upravim kazdy select v XML v nodu Query
                for ($i = 0; $i -lt $xml.QueryList.Query.Select.'#text'.length; $i++) {
                    $xml.QueryList.Query.childnodes.item($i).'#text' = $xml.QueryList.Query.childnodes.item($i).'#text'.replace(']]', $dateFilter)
                }
            }

            Write-Verbose "Vysledny XML dotaz:`n$(Format-XMLIndent $xml)"

            ### nachystani parametru pro Get-WinEvent
            $params = @{
                erroraction	= 'silentlycontinue' # nekdy se objevovaly nonterminating chyby s chybejicimi popisky u eventu atd
                FilterXml   = $xml
            }
            # omezeni na pocet vracenych zaznamu
            if ($newest) {
                $params.MaxEvents = $newest
            }

            ### vypsani pozadovanych udalosti ze systemoveho logu
            Get-WinEvent @params | Select-Object @{n = 'Computer'; e = {$_.Machinename}}, Message, TimeCreated, Id, LevelDisplayName, LogName, ProviderName
        } -argumentList $newest, $after, $before, $LogName, $JustLogNames, $functionString, $severity | Select-Object -Property * -ExcludeProperty PSComputerName, RunspaceId
    }
}