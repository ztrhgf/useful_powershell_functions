function Update-CMClientPolicy {
    <#
    .SYNOPSIS
    Function for invoking update of SCCM client policy.

    .DESCRIPTION
    Function for invoking update of SCCM client policy.

    .PARAMETER computerName
    Name of the computer where you want to make update.

    .PARAMETER evaluateBaseline
    Switch for invoking evaluation of compliance policies.

    .PARAMETER resetPolicy
    Switch for resetting policies (Machine Policy Agent Cleanup).

    .NOTES
    Author: Ondřej Šebela - ztrhgf@seznam.cz
    #>

    [cmdletbinding()]
    [Alias("Invoke-CMClientPolicyUpdate")]
    Param (
        [Parameter(Mandatory = $false, ValueFromPipeline = $True, Position = 0)]
        [ValidateNotNullOrEmpty()]
        [string[]]$computerName = $env:COMPUTERNAME
        ,
        [switch] $evaluateBaseline
        ,
        [switch] $resetPolicy
    )

    BEGIN {
        if ($env:COMPUTERNAME -in $computerName) {
            if (! ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
                throw "Run with administrator rights!"
            }
        }

        $allFunctionDefs = "function Invoke-CMComplianceEvaluation { ${function:Invoke-CMComplianceEvaluation} }"
    }

    PROCESS {

        $param = @{
            scriptBlock  = {
                param ($resetPolicy, $evaluateBaseline, $allFunctionDefs)

                $ErrorActionPreference = 'stop'
                # list of triggers https://blogs.technet.microsoft.com/charlesa_us/2015/03/07/triggering-configmgr-client-actions-with-wmic-without-pesky-right-click-tools/
                try {
                    foreach ($functionDef in $allFunctionDefs) {
                        . ([ScriptBlock]::Create($functionDef))
                    }

                    if ($resetPolicy) {
                        $null = ([wmiclass]'ROOT\ccm:SMS_Client').ResetPolicy(1)
                        # invoking Machine Policy Agent Cleanup
                        $null = Invoke-WmiMethod -Class SMS_client -Namespace "root\ccm" -Name TriggerSchedule -ArgumentList "{00000000-0000-0000-0000-000000000040}"
                        Start-Sleep -Seconds 5
                    }
                    # invoking receive of computer policies
                    $null = Invoke-WmiMethod -Class SMS_client -Namespace "root\ccm" -Name TriggerSchedule -ArgumentList "{00000000-0000-0000-0000-000000000021}"
                    Start-Sleep -Seconds 1
                    # invoking Machine Policy Evaluation Cycle
                    $null = Invoke-WmiMethod -Class SMS_client -Namespace "root\ccm" -Name TriggerSchedule -ArgumentList "{00000000-0000-0000-0000-000000000022}"
                    if (!$resetPolicy) {
                        # after hard reset I have to wait a little bit before this method can be used again
                        Start-Sleep -Seconds 5
                        # invoking Application Deployment Evaluation Cycle
                        $null = Invoke-WmiMethod -Class SMS_client -Namespace "root\ccm" -Name TriggerSchedule -ArgumentList "{00000000-0000-0000-0000-000000000121}"
                    }

                    # invoke evaluation of compliance policies
                    if ($evaluateBaseline) {
                        Invoke-CMComplianceEvaluation
                    }

                    Write-Output "Policy update started on $env:COMPUTERNAME"
                } catch {
                    throw "$env:COMPUTERNAME is probably missing SCCM client.`n`n$_"
                }
            }

            ArgumentList = $resetPolicy, $evaluateBaseline, $allFunctionDefs
        }
        if ($computerName -and $computerName -notin "localhost", $env:COMPUTERNAME) {
            $param.computerName = $computerName
        }

        Invoke-Command @param
    }

    END {
        if ($resetPolicy) {
            Write-Warning "Is is desirable to run Update-CMClientPolicy again after a few minutes to get new policies ASAP"
        }
    }
}