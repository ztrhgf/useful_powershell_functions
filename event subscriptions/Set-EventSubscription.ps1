function Set-EventSubscription {
    [cmdletbinding()]
    param (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string] $subscriptionName
        ,
        [string] $subscriptionXml
        ,
        [ValidateSet('true', 'false')]
        [string] $enabled
        ,
        [string] $description
        ,
        [string[]] $sourceComputer
        ,
        [ValidateSet('Normal', 'MinLatency', 'MinBandwidth')]
        [string] $configurationMode
        ,
        [ValidateSet('Events', 'RenderedText')]
        [string] $contentFormat
        ,
        [ValidateNotNullOrEmpty()]
        [string] $computerName = $eventCollector
    )

    if ($subscriptionXml) {
        Invoke-Command2 -computerName $computerName {
            param ($subscriptionXml)

            $tmpXML = $env:TEMP + (Get-Random)
            $subscriptionXml | Out-File $tmpXML

            wecutil set-subscription /c:$tmpXML

            Remove-Item $tmpXML -Force
        } -argumentList $subscriptionXml
    } else {
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
        }

        Invoke-Command2 -computerName $computerName {
            param ($subscriptionName, $enabled, $description, $sourceComputerSDDL, $configurationMode, $contentFormat)

            if ($enabled) {
                $params += " /e:$enabled"
            }
            if ($description) {
                $params += " /d:`"$description`""
            }
            if ($sourceComputerSDDL) {
                $params += " /adc:`"$sourceComputerSDDL`""
            }
            if ($configurationMode) {
                $params += " /cm:`"$configurationMode`""
            }

            if ($contentFormat) {
                $params += " /cf:`"$contentFormat`""
            }

            # parametry nesmi zacinat mezerou, jinak chyba: Too many arguments are specified. Error = 0x57
            $params = $params.TrimStart()

            wecutil set-subscription `"$subscriptionName`" $params

        } -argumentList $subscriptionName, $enabled, $description, $sourceComputerSDDL, $configurationMode, $contentFormat
    }
}