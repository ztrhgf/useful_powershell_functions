function New-EventSubscription {
    <#
    .SYNOPSIS
        Fce pro vytvoreni event subskripce. Akceptuje bud soubor s XML konfiguraci nebo klasicky vyplnenim potrebnych parametru.

    .DESCRIPTION
        Fce pro vytvoreni event subskripce. Akceptuje bud soubor s XML konfiguraci nebo klasicky vyplnenim potrebnych parametru.

    .PARAMETER computername
        Na jakem stroji se ma subskripce vytvorit.

        Vychozi je obsah promenne eventCollector.

    .PARAMETER subscriptionXMLFile
        Cesta ke XML souboru s konfiguraci subskripce. Typicky jde o zalohu jiz existujici subskripce.

        Tento parametr je vylucny s ostatnimi, tzn bud se pouzije XML soubor nebo se vsechna nastaveni vezmou ze zadanych parametru.

    .PARAMETER subscriptionName
        Jmeno subskripce.

    .PARAMETER description
        Nepovinny popis subskripce, pro lepsi pochopeni k cemu slouzi.

    .PARAMETER type
        Kdo iniciuje poslani eventu. Mozne hodnoty: SourceInitiated, CollectorInitiated.

        Vychozi je SourceInitiated.

    .PARAMETER configurationMode
        Jak rychle se event posle. Mozne hodnoty: Normal, MinLatency, MinBandwidth
        Pro kriticke eventy je doporuceno MinLatency.

        Vychozi je Normal.

    .PARAMETER query
        XML query ktera rika, jake eventy se maji odesilat.
        Nejjednodussi je v event vieweru vytvorit rucne pozadovany filtr a ze zalozky XML vykopirovat odpovidajici XML dotaz.
        Ten ulozit do promenne a tu predat parametru query.

        Melo by vypadat nejak takto:
        <QueryList>
            <Query Path=`"Application`">
                <Select>Event[System/EventID='999']</Select>
            </Query>
        </QueryList>

    .PARAMETER readExistingEvents
        Prepinac rikajici jestli se maji poslat i existujici eventy nebo az nove vytvorene.

    .PARAMETER sourceComputer
        Jmena AD stroju/skupin stroju, ktere maji dane udalosti posilat.
        Automaticky se vzdy navic prida 'Local Network Service'.

        Vychozi je 'Domain Computers', 'Local Network Service'

    .EXAMPLE
        New-EventSubscription -name bsod_error -query $xml -description 'sbira BSOD chyby z event logu na strojich v domene'

        Na kolektoru ulozenem v eventCollector promenne vytvori subskripci bsod_error jejimz vysledkem bude, ze clenove 'domain computers' budou posilat na kolektor udalosti uvedene v query.

    .EXAMPLE
        New-EventSubscription -computerName kolektorServer -name logon_failures -query $xml -sourceComputer 'domain controllers' -configurationMode MinLatency

        Na kolektoru kolektorServer vytvori subskripci logon_failures jejimz vysledkem bude, ze clenove 'domain controllers' budou posilat na kolektor udalosti uvedene v query a to co nejrychleji.

    .NOTES
        Author: Ondřej Šebela - ztrhgf@seznam.cz
    #>

    [CmdletBinding(DefaultParameterSetName = 'Default')]
    param (
        [Parameter(Mandatory = $false, ParameterSetName = "XML")]
        [ValidateScript( {
                if (!(Test-Path $_)) {
                    throw "Zadany soubor neexistuje"
                } else {
                    $true
                }
            })]
        [string] $subscriptionXMLFile
        ,
        [Parameter(Mandatory = $false, ParameterSetName = "Default")]
        [ValidateNotNullOrEmpty()]
        [string] $subscriptionName
        ,
        [Parameter(Mandatory = $false, ParameterSetName = "Default")]
        [string] $description
        ,
        [Parameter(Mandatory = $false, ParameterSetName = "Default")]
        [ValidateSet('SourceInitiated', 'CollectorInitiated')]
        [string] $type = 'SourceInitiated'
        ,
        [Parameter(Mandatory = $false, ParameterSetName = "Default")]
        [ValidateSet('Normal', 'MinLatency', 'MinBandwidth')]
        [string] $configurationMode = 'Normal'
        ,
        [Parameter(Mandatory = $true, ParameterSetName = "Default")]
        [ValidateScript( {
                if ($_ -notmatch '^<QueryList>' -or $_ -notmatch '</QueryList>$') {
                    throw "Query je v nekorektnim tvaru. Musi byt uzavrena do tagu <QueryList>"
                } else {
                    $true
                }
            })]
        [ValidateScript( { $_ -match '</QueryList>$' })]
        [string] $query
        ,
        [Parameter(Mandatory = $false, ParameterSetName = "Default")]
        [switch] $readExistingEvents
        ,
        [Parameter(Mandatory = $false, ParameterSetName = "Default")]
        [string[]] $sourceComputer
        ,
        [ValidateNotNullOrEmpty()]
        [string] $computerName = $eventCollector
    )

    if ($subscriptionXMLFile) {
        $xml = Get-Content $subscriptionXMLFile -Encoding UTF8

        if (!$xml) {
            throw "Zadane XML nic neobsahuje"
        }

        # pri exportu subskripce pomoci wcutil se exportuje i uvodni tag '<?xml version="1.0" encoding="UTF-8"?>', ktery tam ale pri importu byt nesmi
        # kodovani se asi muze lisit, proto ten while
        while ($xml[0] -ne '<Subscription xmlns="http://schemas.microsoft.com/2006/03/windows/events/subscription">') {
            $xml = $xml[1..($xml.Length)]
        }

        if (!$xml) {
            throw "Nezadali jste validni XML"
        }

        # ted je xml pole objektu, potrebuji ale jako string
        $xml | % {$xmlString += "$_`n"}
        $xml = $xmlString
    } else {
        if ($query -notmatch '^<QueryList>' -or $query -notmatch '</QueryList>$') {
            throw "Query je v nekorektnim tvaru. Musi byt ve tvaru`n`n
        <QueryList>
            <Query Path=`"Application`">
                <Select>Event[System/EventID='999']</Select>
            </Query>
        </QueryList>
        "
        }

        if ($readExistingEvents) {
            [string] $readExistingEvents = 'true'
        } else {
            [string] $readExistingEvents = 'false'
        }

        if ($sourceComputer) {
            $acl = ''
            $sourceComputer | % {
                $sid = Get-SIDFromAccount $_
                if ($sid) {
                    $acl += "(A;;GA;;;$sid)"
                }
            }
            if ($acl) {
                # pridam jeste local network service group
                $acl += "(A;;GA;;;NS)"
                $sourceComputerSDDL = "O:NSG:NSD:$acl"
            } else {
                throw "Zadny ze zadanych uctu se nepodarilo prelozit na SID"
            }
        } else {
            # vychozi prava: domain computers + local network service group
            $sourceComputerSDDL = 'O:NSG:NSD:(A;;GA;;;DC)(A;;GA;;;NS)'
        }

        $xml = @"
        <Subscription xmlns="http://schemas.microsoft.com/2006/03/windows/events/subscription">
        <SubscriptionId>$subscriptionName</SubscriptionId>
        <SubscriptionType>$type</SubscriptionType>
        <Description>$description</Description>
        <Enabled>true</Enabled>
        <Uri>http://schemas.microsoft.com/wbem/wsman/1/windows/EventLog</Uri>

        <ConfigurationMode>$configurationMode</ConfigurationMode>

        <Query>
            <![CDATA[
                $query
            ]]>
        </Query>

        <ReadExistingEvents>$readExistingEvents</ReadExistingEvents>
        <TransportName>http</TransportName>
        <ContentFormat>RenderedText</ContentFormat>
        <Locale Language="en-US"/>
        <LogFile>ForwardedEvents</LogFile>
        <AllowedSourceNonDomainComputers></AllowedSourceNonDomainComputers>
        <AllowedSourceDomainComputers>$sourceComputerSDDL</AllowedSourceDomainComputers>
    </Subscription>
"@
    }

    Invoke-Command2 -computerName $computerName {
        param ($xml)
        $tmpXML = Join-Path $env:TEMP (Get-Random)
        $xml | Out-File $tmpXML

        wecutil create-subscription $tmpXML

        Remove-Item $tmpXML -Force
    } -argumentList $xml
}