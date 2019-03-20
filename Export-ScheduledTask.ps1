function Export-ScheduledTasks {
    <#
		.SYNOPSIS
			Exportuje scheduled tasky ve formě XML souborů.

		.DESCRIPTION
			Ve výchozím nastavení exportuje tasky z rootu do adresáře C:\temp\backup.

		.PARAMETER  Computername
			Stroje ze kterých se budou zálohovat scheduled tasky.

		.PARAMETER  TaskPath
			Cesta ze které se budou exportovat tasky. Výchozí hodnota je "\" tedy root. Zapisovat ve tvaru "\Správa" "\Microsoft\Windows" atp.

		.PARAMETER  BackupPath
			Kam se budou XML ukládat.
			
		.EXAMPLE
			Export-ScheduledTasks
			Vyexportuje tasky z rootu do adresáře C:\temp\backup

		.EXAMPLE
			Export-ScheduledTasks -comp sirene01 -taskPath "\Správa"
			Vyexportuje tasky z "\Správa" do adresáře C:\temp\backup na stroji sirene01

		.NOTES
			Author: Ondřej Šebela - ztrhgf@seznam.cz

		.LINK
			about_functions_advanced

		.LINK
			about_comment_based_help
	#>
    [CmdletBinding()]
    param
    (
        [Parameter(Position = 0, Mandatory = $false, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [ValidateNotNullOrEmpty()]
        $Computername = $env:COMPUTERNAME
        ,
        [Parameter(Position = 1)]
        [ValidateNotNull()]
        [ValidatePattern('(?# Cesta musí začít znakem \)^\\')] # kontrola ze zacina lomitkem
        $TaskPath = "\"
        ,
        [Parameter(Position = 2)]
        [ValidateNotNull()]
        [ValidateScript( {Test-Path $_})] # kontrola jestli cesta existuje
        #		[ValidateScript({$_ -match "^\\\\\w+\\\w+"})] # kontrola jestli jde o UNC cestu
        $BackupPath = "C:\temp\backup"
		
    )

    PROCESS {
        ForEach ($Computer in $Computername) {
            if (!(Test-Path $BackupPath )) { New-Item -type directory "$BackupPath" }
            $sch = New-Object -ComObject("Schedule.Service")
            $sch.Connect("$Computer")
            $tasks = $sch.GetFolder("$TaskPath").GetTasks(0)
            $tasks | % {
                $xml = $_.Xml
                $task_name = $_.Name
                $outfile = "$BackupPath\{0}.xml" -f $task_name
                $xml | Out-File $outfile
            }
        }	
    }
}
