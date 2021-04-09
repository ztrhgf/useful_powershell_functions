function Invoke-CMComplianceEvaluation {
    <#
    .SYNOPSIS
    Function triggers evaluation of available SCCM compliance baselines.

    .DESCRIPTION
    Function triggers evaluation of available SCCM compliance baselines.
    On remote computers can trigger only computer targeted baselines (doesn't contain any per user CI)! Per user baselines won't be even shown.

    .PARAMETER computerName
    Default is localhost.

    .PARAMETER baselineName
    Optional parameter for filtering baselines to evaluate.

    .EXAMPLE
    Invoke-CMComplianceEvaluation

    Trigger evaluation of all compliance baselines on localhost targeted to device and user, that run this function.

    .EXAMPLE
    Invoke-CMComplianceEvaluation -computerName ae-01 -baselineName "XXX_compliance_policy"

    Trigger evaluation of just XXX_compliance_policy compliance baseline on ae-01. But only in case, such baseline is targeted to device, not user.

    .NOTES
    Inspired by https://social.technet.microsoft.com/Forums/en-US/76afbba5-065e-4809-9720-024ea05d6cee/trigger-baseline-evaluation?forum=configmanagersdk
    #>

    [CmdletBinding()]
    param (
        [string] $computerName = "localhost"
        ,
        [string[]] $baselineName
    )

    $Baselines = Get-CimInstance -ComputerName $ComputerName -Namespace root\ccm\dcm -Class SMS_DesiredConfiguration
    ForEach ($Baseline in $Baselines) {
        $displayName = $Baseline.DisplayName
        if ($baselineName -and $displayName -notin $baselineName) {
            Write-Warning "Skipping $displayName baseline"
            continue
        }

        $name = $Baseline.Name
        $IsMachineTarget = $Baseline.IsMachineTarget
        $IsEnforced = $Baseline.IsEnforced
        $PolicyType = $Baseline.PolicyType
        $version = $Baseline.Version

        $MC = [WmiClass]"\\$ComputerName\root\ccm\dcm:SMS_DesiredConfiguration"

        $Method = "TriggerEvaluation"
        $InParams = $mc.psbase.GetMethodParameters($Method)
        $InParams.IsEnforced = $IsEnforced
        $InParams.IsMachineTarget = $IsMachineTarget
        $InParams.Name = $name
        $InParams.Version = $version
        $InParams.PolicyType = $PolicyType

        Write-Output "Evaluating $displayName"
        Write-Verbose "Last status: $($Baseline.LastComplianceStatus) Last evaluated: $($Baseline.LastEvalTime)"

        $result = $MC.InvokeMethod($Method, $InParams, $null)

        if ($result.ReturnValue -eq 0) {
            Write-Verbose "OK"
        } else {
            Write-Error "There was an error.`n$result"
        }
    }
}