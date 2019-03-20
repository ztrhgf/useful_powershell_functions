#TODO dodelat propertysety na name a direction, ktere nemohou byt spolu!
#TODO displayName a action take nemohou byt spolu!
#TODO domenove GPO nejsou z nejakeho duvodu videt pokud taham info z activeStore, ale v rsop store videt jsou
# prijde mi ale ze jen ty, ktere maji i svou lokalni variantu, tzn pokud lokalne takove pravidlo se stejnym jmenem neexistuje, tak se ukaze viz "Remote Administration (NP-In)" na aeneas1
<#
$rules=Get-NetFirewallRule -PolicyStore activestore -Direction Inbound -Action Allow,Block,NotConfigured -Enabled True|?{$_.Name -like '*desktop*'}
$rules | % {
    $_|Get-NetFirewallAddressFilter
}

vs

$rules2=Get-NetFirewallRule -PolicyStore rsop -Direction Inbound -Action Allow,Block,NotConfigured -Enabled True|?{$_.Name -like '*desktop*'}
$rules2 | % {
    $_|Get-NetFirewallAddressFilter
}

A MOZNA JESTE LEPSI PRIKLAD

$rules=Get-NetFirewallRule -PolicyStore activestore -all|?{$_.Name -like '*desktop*' -and $_.PolicyStoreSourceType -eq "grouppolicy"}
$rules | % { $_|Get-NetFirewallAddressFilter -PolicyStore rsop }

vs 

$rules | % { $_|Get-NetFirewallAddressFilter -PolicyStore activeStore }

#>
function Get-FirewallRules {
    [CmdletBinding()]
    param (
        $computername = $env:COMPUTERNAME
        #,
        #[string] $name = "*"
        ,
        [ValidateSet('inbound', 'outbound')]        
        [string []] $direction
        ,
        [ValidateSet('true', 'false')]        
        [string] $enabled = 'true'
        ,
        [ValidateSet('Allow', 'Block', 'NotConfigured')]        
        [string []] $action = ('Allow', 'Block', 'NotConfigured')
        ,
        [switch] $justGPORules
        ,
        [switch] $inactiveIncluded
    )

    begin {
        # odkud se maji FW pravidla nacist
        # ActiveStore by mel obsahovat merge domenovych a lokalnich pravidel, tzn vsechna ktera se realne aplikuji
        $policyStore = "ActiveStore"
        if ($justGPORules) {
            # RSOP store obsahuje pouze FW pravidla vytvorena pomoci domenovych GPO
            $policyStore = "RSOP"
        }
    }
    
    process {
        Invoke-Command2 -computerName $computerName {

            param ($name, $direction, $enabled, $action, $policyStore, $inactiveIncluded)

            # nactu odpovidajici FW pravidla
            if ($direction) {
                $FirewallRules = Get-NetFirewallRule -direction $direction -PolicyStore $policyStore -action $action -enabled $enabled
            } else {
                $FirewallRules = Get-NetFirewallRule -PolicyStore $policyStore -action $action -enabled $enabled
                # $FirewallRules = Get-NetFirewallRule -DisplayName $name -PolicyStore $policyStore -action $action -enabled $enabled
            }
            if (!$inactiveIncluded) {
                # odfiltruji neaktivni pravidla (napr ptoto, ze jde o lokalni a jejich aplikace je zakazana)
                $FirewallRules = $FirewallRules | ? {$_.primarystatus -eq "OK"}
            }
            $FirewallRuleSet = @()
            $ErrorActionPreference = 'silentlyContinue' # nektere cmdlety koncily chybou, protoze FW pravidlo nenalezly?

            ForEach ($Rule In $FirewallRules) {
                # iteruji skrze nalezena FW pravidla a pro kazde zjistim vsechny dostupna nastaveni

                # aby se zobrazily spravna nastaveni, divam se do odpovidajiciho storu (v RSOP jsou ulozene domenove definovane FW pravidla)
                # v cmdletech je totiz zrejme bug, kdy opkud existuje pravidlo se shodnym nzavem lokalne i def. skrze GPO, tak se zobrazi pro domenove pravidlo nastaveni toho lokalniho
                $store = "ActiveStore"
                if ($Rule.PolicyStoreSourceType -eq "groupPolicy") {
                    $store = "RSOP"
                }

                Write-Verbose "Zpracovavam `"$($Rule.DisplayName)`" ($($Rule.Name)) ze storu $store"

                $AdressFilter = $Rule | Get-NetFirewallAddressFilter -PolicyStore $store
                $PortFilter = $Rule | Get-NetFirewallPortFilter -PolicyStore $store
                $ApplicationFilter = $Rule | Get-NetFirewallApplicationFilter -PolicyStore $store
                $ServiceFilter = $Rule | Get-NetFirewallServiceFilter -PolicyStore $store
                $InterfaceFilter = $Rule | Get-NetFirewallInterfaceFilter -PolicyStore $store
                $InterfaceTypeFilter = $Rule | Get-NetFirewallInterfaceTypeFilter -PolicyStore $store
                $SecurityFilter = $Rule | Get-NetFirewallSecurityFilter -PolicyStore $store

                $HashProps = [PSCustomObject]@{
                    Name                = $Rule.Name
                    DisplayName         = $Rule.DisplayName
                    Description         = $Rule.Description
                    Group               = $Rule.Group
                    Enabled             = $Rule.Enabled
                    Profile             = $Rule.Profile
                    Platform            = $Rule.Platform -join ', '
                    Direction           = $Rule.Direction
                    Action              = $Rule.Action
                    EdgeTraversalPolicy = $Rule.EdgeTraversalPolicy
                    LooseSourceMapping  = $Rule.LooseSourceMapping
                    LocalOnlyMapping    = $Rule.LocalOnlyMapping
                    Owner               = $Rule.Owner
                    LocalAddress        = $AdressFilter.LocalAddress -join ', '
                    RemoteAddress       = $AdressFilter.RemoteAddress -join ', '
                    Protocol            = $PortFilter.Protocol
                    LocalPort           = $PortFilter.LocalPort -join ', '
                    RemotePort          = $PortFilter.RemotePort -join ', '
                    IcmpType            = $PortFilter.IcmpType -join ', '
                    DynamicTarget       = $PortFilter.DynamicTarget
                    Program             = $ApplicationFilter.Program -Replace "$($ENV:SystemRoot.Replace("\","\\"))\\", "%SystemRoot%\" -Replace "$(${ENV:ProgramFiles(x86)}.Replace("\","\\").Replace("(","\(").Replace(")","\)"))\\", "%ProgramFiles(x86)%\" -Replace "$($ENV:ProgramFiles.Replace("\","\\"))\\", "%ProgramFiles%\"
                    Package             = $ApplicationFilter.Package
                    Service             = $ServiceFilter.Service
                    InterfaceAlias      = $InterfaceFilter.InterfaceAlias -join ', '
                    InterfaceType       = $InterfaceTypeFilter.InterfaceType
                    LocalUser           = $SecurityFilter.LocalUser
                    RemoteUser          = $SecurityFilter.RemoteUser
                    RemoteMachine       = $SecurityFilter.RemoteMachine
                    Authentication      = $SecurityFilter.Authentication
                    Encryption          = $SecurityFilter.Encryption
                    OverrideBlockRules  = $SecurityFilter.OverrideBlockRules
                }

                $FirewallRuleSet += $HashProps
            }  
            
            $FirewallRuleSet
        } -argumentList $name, $direction, $enabled, $action, $policyStore, $inactiveIncluded
    }
}