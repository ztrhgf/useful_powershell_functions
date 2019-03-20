function Remove-EventSubscription {
    [cmdletbinding()]
    param (
        [ValidateNotNullOrEmpty()]
        [string] $subscriptionName
        ,
        [ValidateNotNullOrEmpty()]
        [string] $computerName = $eventCollector
    )

    Invoke-Command2 -computerName $computerName {
        param ($subscriptionName)
        wecutil delete-subscription $subscriptionName
    } -argumentList $subscriptionName
}