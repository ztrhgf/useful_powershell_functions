#region Dependencies
# Load the ConfluencePS namespace from C#
if (!("ConfluencePS.Space" -as [Type])) {
    Add-Type -Path (Join-Path $PSScriptRoot ConfluencePS.Types.cs) -ReferencedAssemblies Microsoft.CSharp, Microsoft.PowerShell.Commands.Utility, System.Management.Automation
}

# Load Web assembly when needed
# PowerShell Core has the assembly preloaded
if (!("System.Web.HttpUtility" -as [Type])) {
    Add-Type -Assembly System.Web
}
function Add-Attachment {
    [CmdletBinding(
        ConfirmImpact = 'Low',
        SupportsShouldProcess = $true
    )]
    [OutputType([ConfluencePS.Attachment])]
    param(
        [Parameter( Mandatory = $true )]
        [uri]$ApiUri,

        [Parameter( Mandatory = $false )]
        [PSCredential]$Credential,

        [Parameter( Mandatory = $false )]
        [ValidateNotNull()]
        [System.Security.Cryptography.X509Certificates.X509Certificate]
        $Certificate,

        [Parameter(
            Position = 0,
            Mandatory = $true,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true
        )]
        [ValidateRange(1, [uint64]::MaxValue)]
        [Alias('ID')]
        [uint64]$PageID,

        [Parameter( Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName )]
        [ValidateScript(
            {
                if (-not (Test-Path $_ -PathType Leaf)) {
                    $errorItem = [System.Management.Automation.ErrorRecord]::new(
                        ([System.ArgumentException]"File not found"),
                        'ParameterValue.FileNotFound',
                        [System.Management.Automation.ErrorCategory]::ObjectNotFound,
                        $_
                    )
                    $errorItem.ErrorDetails = "No file could be found with the provided path '$_'."
                    $PSCmdlet.ThrowTerminatingError($errorItem)
                } else {
                    return $true
                }
            }
        )]
        [Alias('InFile', 'FullName', 'Path', 'PSPath')]
        [String[]]
        $FilePath
    )

    begin {
        Write-Verbose "[$($MyInvocation.MyCommand.Name)] Function started"
    }

    process {
        Write-DebugMessage "[$($MyInvocation.MyCommand.Name)] ParameterSetName: $($PsCmdlet.ParameterSetName)"
        Write-DebugMessage "[$($MyInvocation.MyCommand.Name)] PSBoundParameters: $($PSBoundParameters | Out-String)"

        $iwParameters = Copy-CommonParameter -InputObject $PSBoundParameters
        $iwParameters['Uri'] = "$ApiUri/content/{0}/child/attachment" -f $PageID
        $iwParameters['Method'] = 'Post'
        $iwParameters['OutputType'] = [ConfluencePS.Attachment]

        foreach ($file in $FilePath) {
            $iwParameters["InFile"] = $file

            Write-Debug "[$($MyInvocation.MyCommand.Name)] Invoking Add Attachment Method with `$parameter"
            if ($PSCmdlet.ShouldProcess($PageID, "Adding attachment(s) '$($file)'.")) {
                Invoke-Method @iwParameters
            }
        }
    }

    end {
        Write-Verbose "[$($MyInvocation.MyCommand.Name)] Complete"
    }
}

function Add-Label {
    [CmdletBinding(
        ConfirmImpact = 'Low',
        SupportsShouldProcess = $true
    )]
    [OutputType([ConfluencePS.ContentLabelSet])]
    param (
        [Parameter( Mandatory = $true )]
        [uri]$ApiUri,

        [Parameter( Mandatory = $false )]
        [PSCredential]$Credential,

        [Parameter( Mandatory = $false )]
        [ValidateNotNull()]
        [System.Security.Cryptography.X509Certificates.X509Certificate]
        $Certificate,

        [Parameter(
            Position = 0,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true
        )]
        [ValidateRange(1, [uint64]::MaxValue)]
        [Alias('ID')]
        [uint64[]]$PageID,

        [Parameter(
            Mandatory = $true,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true
        )]
        [Alias('Labels')]
        $Label
    )

    BEGIN {
        Write-Verbose "[$($MyInvocation.MyCommand.Name)] Function started"

        $resourceApi = "$ApiUri/content/{0}/label"
    }

    PROCESS {
        Write-Debug "[$($MyInvocation.MyCommand.Name)] ParameterSetName: $($PsCmdlet.ParameterSetName)"
        Write-Debug "[$($MyInvocation.MyCommand.Name)] PSBoundParameters: $($PSBoundParameters | Out-String)"

        # Validade input object from Pipeline
        if (($_) -and -not($_ -is [ConfluencePS.Page] -or $_ -is [uint64] -or $_ -is [ConfluencePS.ContentLabelSet])) {
            $message = "The Object in the pipe is not a Page."
            $exception = New-Object -TypeName System.ArgumentException -ArgumentList $message
            Throw $exception
        }

        # The parameter "Label" has no type declared. Because of this, a piped object of
        # type "ConfluencePS.ContentLabelSet" will be assigned to "Label". Lets fix this:
        if ($_ -and $Label -is [ConfluencePS.ContentLabelSet]) {
            $Label = $Label.Labels
        }

        # Test if Label is String[]
        [String[]]$_label = $Label
        $_label = $_label | Where-Object { $_ -ne "ConfluencePS.Label" }
        if ($_label) {
            [String[]]$Label = $_label
        }
        # Allow only for Label to be a [String[]] or [ConfluencePS.Label[]]
        $allowedLabelTypes = @(
            "System.String"
            "System.String[]"
            "ConfluencePS.Label"
            "ConfluencePS.Label[]"
        )
        if ($Label.GetType().FullName -notin $allowedLabelTypes) {
            $message = "Parameter 'Label' is not a Label or a String. It is $($Label.gettype().FullName)"
            $exception = New-Object -TypeName System.ArgumentException -ArgumentList $message
            Throw $exception
        }

        $iwParameters = Copy-CommonParameter -InputObject $PSBoundParameters
        $iwParameters['Method'] = 'Post'
        $iwParameters['OutputType'] = [ConfluencePS.Label]

        # Extract name if an Object is provided
        if (($Label -is [ConfluencePS.Label]) -or $Label -is [ConfluencePS.Label[]]) {
            $Label = $Label | Select-Object -ExpandProperty Name
        }

        foreach ($_page in $PageID) {
            if ($_ -is [ConfluencePS.Page]) {
                $InputObject = $_
            } elseif ($_ -is [ConfluencePS.ContentLabelSet]) {
                $InputObject = $_.Page
            } else {
                $authAndApiUri = Copy-CommonParameter -InputObject $PSBoundParameters -AdditionalParameter "ApiUri"
                $InputObject = Get-Page -PageID $_page @authAndApiUri
            }

            $iwParameters["Uri"] = $resourceApi -f $_page
            $iwParameters["Body"] = ($Label | ForEach-Object { @{prefix = 'global'; name = $_ } }) | ConvertTo-Json

            Write-Debug "[$($MyInvocation.MyCommand.Name)] Content to be sent: $($iwParameters["Body"] | Out-String)"
            if ($PSCmdlet.ShouldProcess("Label $Label, PageID $_page")) {
                $output = [ConfluencePS.ContentLabelSet]@{ Page = $InputObject }
                $output.Labels += (Invoke-Method @iwParameters)
                $output
            }
        }
    }

    END {
        Write-Verbose "[$($MyInvocation.MyCommand.Name)] Function ended"
    }
}

function ConvertTo-StorageFormat {
    [CmdletBinding()]
    [OutputType([String])]
    param (
        [Parameter( Mandatory = $true )]
        [uri]$ApiUri,

        [Parameter( Mandatory = $false )]
        [PSCredential]$Credential,

        [Parameter( Mandatory = $false )]
        [ValidateNotNull()]
        [System.Security.Cryptography.X509Certificates.X509Certificate]
        $Certificate,

        [Parameter(
            Position = 0,
            Mandatory = $true,
            ValueFromPipeline = $true
        )]
        [string[]]$Content
    )

    BEGIN {
        Write-Verbose "[$($MyInvocation.MyCommand.Name)] Function started"
    }

    PROCESS {
        Write-Debug "[$($MyInvocation.MyCommand.Name)] ParameterSetName: $($PsCmdlet.ParameterSetName)"
        Write-Debug "[$($MyInvocation.MyCommand.Name)] PSBoundParameters: $($PSBoundParameters | Out-String)"

        $iwParameters = Copy-CommonParameter -InputObject $PSBoundParameters
        $iwParameters['Uri'] = "$ApiUri/contentbody/convert/storage"
        $iwParameters['Method'] = 'Post'

        foreach ($_content in $Content) {
            $iwParameters['Body'] = @{
                value          = "$_content"
                representation = 'wiki'
            } | ConvertTo-Json

            Write-Debug "[$($MyInvocation.MyCommand.Name)] Content to be sent: $($_content | Out-String)"
            (Invoke-Method @iwParameters).value
        }
    }

    END {
        Write-Verbose "[$($MyInvocation.MyCommand.Name)] Function ended"
    }
}

function ConvertTo-Table {
    [CmdletBinding()]
    [System.Diagnostics.CodeAnalysis.SuppressMessage('PSUseDeclaredVarsMoreThanAssignments', '')]
    param (
        [Parameter(
            Mandatory = $true,
            ValueFromPipeline = $true
        )]
        $Content,

        [Switch]$Vertical,

        [Switch]$NoHeader
    )

    BEGIN {
        Write-Verbose "[$($MyInvocation.MyCommand.Name)] Function started"

        $sb = [System.Text.StringBuilder]::new()

        $HeaderGenerated = $NoHeader
    }

    PROCESS {
        Write-Debug "[$($MyInvocation.MyCommand.Name)] ParameterSetName: $($PsCmdlet.ParameterSetName)"
        Write-Debug "[$($MyInvocation.MyCommand.Name)] PSBoundParameters: $($PSBoundParameters | Out-String)"

        # This ForEach needed if the content wasn't piped in
        $Content | ForEach-Object {
            if ($Vertical) {
                if ($HeaderGenerated) { $pipe = '|' }
                else { $pipe = '||' }

                # Put an empty row between multiple tables (objects)
                if ($Spacer) {
                    $null = $sb.AppendLine('')
                }

                $_.PSObject.Properties | ForEach-Object {
                    $row = ("$pipe {0} $pipe {1} |" -f $_.Name, $_.Value) -replace "\|\s\s", "| "
                    $null = $sb.AppendLine($row)
                }

                $Spacer = $true
            } else {
                # Header row enclosed by ||
                if (-not $HeaderGenerated) {
                    $null = $sb.AppendLine("|| {0} ||" -f ($_.PSObject.Properties.Name -join " || "))
                    $HeaderGenerated = $true
                }

                # All other rows enclosed by |
                $row = ("| " + ($_.PSObject.Properties.Value -join " | ") + " |") -replace "\|\s\s", "| "
                $null = $sb.AppendLine($row)
            }
        }
    }

    END {
        # Return the array as one large, multi-line string
        $sb.ToString()

        Write-Verbose "[$($MyInvocation.MyCommand.Name)] Function ended"
    }
}

function Get-Attachment {
    [CmdletBinding( SupportsPaging = $true )]
    [OutputType([ConfluencePS.Attachment])]
    param (
        [Parameter( Mandatory = $true )]
        [uri]$ApiUri,

        [Parameter( Mandatory = $false )]
        [PSCredential]$Credential,

        [Parameter( Mandatory = $false )]
        [ValidateNotNull()]
        [System.Security.Cryptography.X509Certificates.X509Certificate]
        $Certificate,

        [Parameter(
            Position = 0,
            Mandatory = $true,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true
        )]
        [ValidateRange(1, [uint64]::MaxValue)]
        [Alias('ID')]
        [uint64[]]$PageID,

        [String]$FileNameFilter,

        [String]$MediaTypeFilter,

        [ValidateRange(1, [uint64]::MaxValue)]
        [uint64]$PageSize = 25
    )

    BEGIN {
        Write-Verbose "[$($MyInvocation.MyCommand.Name)] Function started"
    }

    PROCESS {
        Write-DebugMessage "[$($MyInvocation.MyCommand.Name)] ParameterSetName: $($PsCmdlet.ParameterSetName)"
        Write-DebugMessage "[$($MyInvocation.MyCommand.Name)] PSBoundParameters: $($PSBoundParameters | Out-String)"

        if (($_) -and -not($_ -is [ConfluencePS.Page] -or $_ -is [uint64])) {
            $message = "The Object in the pipe is not a Page."
            $exception = New-Object -TypeName System.ArgumentException -ArgumentList $message
            Throw $exception
        }

        $iwParameters = Copy-CommonParameter -InputObject $PSBoundParameters
        $iwParameters['Method'] = 'Get'
        $iwParameters['GetParameters'] = @{
            expand = "version"
            limit  = $PageSize
        }
        $iwParameters['OutputType'] = [ConfluencePS.Attachment]

        if ($FileNameFilter) {
            $iwParameters["GetParameters"]["filename"] = $FileNameFilter
        }

        if ($MediaTypeFilter) {
            $iwParameters["GetParameters"]["mediaType"] = $MediaTypeFilter
        }

        # Paging
        ($PSCmdlet.PagingParameters | Get-Member -MemberType Property).Name | ForEach-Object {
            $iwParameters[$_] = $PSCmdlet.PagingParameters.$_
        }

        foreach ($_PageID in $PageID) {
            $iwParameters['Uri'] = "$ApiUri/content/{0}/child/attachment" -f $_PageID

            Invoke-Method @iwParameters
        }
    }

    END {
        Write-Verbose "[$($MyInvocation.MyCommand.Name)] Function ended"
    }
}

function Get-AttachmentFile {
    [CmdletBinding()]
    [OutputType([Bool])]
    param (
        [Parameter( Mandatory = $true )]
        [uri]$ApiUri,

        [Parameter( Mandatory = $false )]
        [PSCredential]$Credential,

        [Parameter( Mandatory = $false )]
        [ValidateNotNull()]
        [System.Security.Cryptography.X509Certificates.X509Certificate]
        $Certificate,

        [Parameter(
            Position = 0,
            Mandatory = $true,
            ValueFromPipeline = $true
        )]
        [ConfluencePS.Attachment[]]$Attachment,

        [ValidateScript(
            {
                if (-not (Test-Path $_)) {
                    $errorItem = [System.Management.Automation.ErrorRecord]::new(
                        ([System.ArgumentException]"Path not found"),
                        'ParameterValue.FileNotFound',
                        [System.Management.Automation.ErrorCategory]::ObjectNotFound,
                        $_
                    )
                    $errorItem.ErrorDetails = "Invalid path '$_'."
                    $PSCmdlet.ThrowTerminatingError($errorItem)
                } else {
                    return $true
                }
            }
        )]
        [String]$Path
    )

    BEGIN {
        Write-Verbose "[$($MyInvocation.MyCommand.Name)] Function started"
    }

    PROCESS {
        Write-DebugMessage "[$($MyInvocation.MyCommand.Name)] ParameterSetName: $($PsCmdlet.ParameterSetName)"
        Write-DebugMessage "[$($MyInvocation.MyCommand.Name)] PSBoundParameters: $($PSBoundParameters | Out-String)"

        if (($_) -and -not($_ -is [ConfluencePS.Attachment])) {
            $message = "The Object in the pipe is not an Attachment."
            $exception = New-Object -TypeName System.ArgumentException -ArgumentList $message
            Throw $exception
        }

        $iwParameters = Copy-CommonParameter -InputObject $PSBoundParameters
        $iwParameters['Method'] = 'Get'

        foreach ($_Attachment in $Attachment) {
            $iwParameters['Uri'] = $_Attachment.URL
            $iwParameters['Headers'] = @{"Accept" = $_Attachment.MediaType }
            $iwParameters['OutFile'] = if ($Path) { Join-Path -Path $Path -ChildPath $_Attachment.Filename } else { $_Attachment.Filename }

            $result = Invoke-Method @iwParameters
            (-not $result)
        }
    }

    END {
        Write-Verbose "[$($MyInvocation.MyCommand.Name)] Function ended"
    }
}

function Get-ChildPage {
    [CmdletBinding( SupportsPaging = $true )]
    [OutputType([ConfluencePS.Page])]
    param (
        [Parameter( Mandatory = $true )]
        [uri]$ApiUri,

        [Parameter( Mandatory = $false )]
        [PSCredential]$Credential,

        [Parameter( Mandatory = $false )]
        [ValidateNotNull()]
        [System.Security.Cryptography.X509Certificates.X509Certificate]
        $Certificate,

        [Parameter(
            Position = 0,
            Mandatory = $true,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true
        )]
        [ValidateRange(1, [uint64]::MaxValue)]
        [Alias('ID')]
        [uint64]$PageID,

        [switch]$Recurse,

        [ValidateRange(1, [uint64]::MaxValue)]
        [uint64]$PageSize = 25
    )

    BEGIN {
        Write-Verbose "[$($MyInvocation.MyCommand.Name)] Function started"
    }

    PROCESS {
        Write-Debug "[$($MyInvocation.MyCommand.Name)] ParameterSetName: $($PsCmdlet.ParameterSetName)"
        Write-Debug "[$($MyInvocation.MyCommand.Name)] PSBoundParameters: $($PSBoundParameters | Out-String)"

        #Fix: See fix statement below. These two fix statements are tied together
        if (($_) -and -not($_ -is [ConfluencePS.Page] -or $_ -is [uint64])) {
            $message = "The Object in the pipe is not a Page."
            $exception = New-Object -TypeName System.ArgumentException -ArgumentList $message
            Throw $exception
        }

        #Fix: This doesn't get called since there are no parameter sets for this function. It must be
        #copy paste from another function. This function doesn't really accept ConfluencePS.Page objects, it only
        #works due to powershell grabbing the 'ID' from ConfluencePS.Page using the
        #'ValueFromPipelineByPropertyName = $true' and '[Alias('ID')]' on the PageID Parameter.
        if ($PsCmdlet.ParameterSetName -eq "byObject") {
            $PageID = $InputObject.ID
        }

        $iwParameters = Copy-CommonParameter -InputObject $PSBoundParameters
        $iwParameters['Uri'] = if ($Recurse.IsPresent) { "$ApiUri/content/{0}/descendant/page" -f $PageID } else { "$ApiUri/content/{0}/child/page" -f $PageID }
        $iwParameters['Method'] = 'Get'
        $iwParameters['GetParameters'] = @{
            expand = "space,version,body.storage,ancestors"
            limit  = $PageSize
        }
        $iwParameters['OutputType'] = [ConfluencePS.Page]

        # Paging
        ($PSCmdlet.PagingParameters | Get-Member -MemberType Property).Name | ForEach-Object {
            $iwParameters[$_] = $PSCmdlet.PagingParameters.$_
        }

        Invoke-Method @iwParameters
    }

    END {
        Write-Verbose "[$($MyInvocation.MyCommand.Name)] Function ended"
    }
}

function Get-Label {
    [CmdletBinding(
        SupportsPaging = $true
    )]
    [OutputType([ConfluencePS.ContentLabelSet])]
    param (
        [Parameter( Mandatory = $true )]
        [uri]$ApiUri,

        [Parameter( Mandatory = $false )]
        [PSCredential]$Credential,

        [Parameter( Mandatory = $false )]
        [ValidateNotNull()]
        [System.Security.Cryptography.X509Certificates.X509Certificate]
        $Certificate,

        [Parameter(
            Position = 0,
            Mandatory = $true,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true
        )]
        [ValidateRange(1, [uint64]::MaxValue)]
        [Alias('ID')]
        [uint64[]]$PageID,

        [ValidateRange(1, [uint64]::MaxValue)]
        [uint64]$PageSize = 25
    )

    BEGIN {
        Write-Verbose "[$($MyInvocation.MyCommand.Name)] Function started"

        $resourceApi = "$ApiUri/content/{0}/label"
    }

    PROCESS {
        Write-Debug "[$($MyInvocation.MyCommand.Name)] ParameterSetName: $($PsCmdlet.ParameterSetName)"
        Write-Debug "[$($MyInvocation.MyCommand.Name)] PSBoundParameters: $($PSBoundParameters | Out-String)"

        if (($_) -and -not($_ -is [ConfluencePS.Page] -or $_ -is [uint64])) {
            $message = "The Object in the pipe is not a Page."
            $exception = New-Object -TypeName System.ArgumentException -ArgumentList $message
            Throw $exception
        }

        $iwParameters = Copy-CommonParameter -InputObject $PSBoundParameters
        $iwParameters['Method'] = 'Get'
        $iwParameters['GetParameters'] = @{
            limit = $PageSize
        }
        $iwParameters['OutputType'] = [ConfluencePS.Label]

        # Paging
        ($PSCmdlet.PagingParameters | Get-Member -MemberType Property).Name | ForEach-Object {
            $iwParameters[$_] = $PSCmdlet.PagingParameters.$_
        }

        foreach ($_page in $PageID) {
            if ($_ -is [ConfluencePS.Page]) {
                $InputObject = $_
            } else {
                $authAndApiUri = Copy-CommonParameter -InputObject $PSBoundParameters -AdditionalParameter "ApiUri"
                $InputObject = Get-Page -PageID $_page @authAndApiUri
            }
            $iwParameters["Uri"] = $resourceApi -f $_page
            $output = New-Object -TypeName ConfluencePS.ContentLabelSet
            $output.Page = $InputObject
            $output.Labels += (Invoke-Method @iwParameters)
            $output
        }
    }

    END {
        Write-Verbose "[$($MyInvocation.MyCommand.Name)] Function ended"
    }
}

function Get-Page {
    [CmdletBinding(
        SupportsPaging = $true,
        DefaultParameterSetName = "byId"
    )]
    [OutputType([ConfluencePS.Page])]
    param (
        [Parameter( Mandatory = $true )]
        [uri]$ApiUri,

        [Parameter( Mandatory = $false )]
        [PSCredential]$Credential,

        [Parameter( Mandatory = $false )]
        [ValidateNotNull()]
        [System.Security.Cryptography.X509Certificates.X509Certificate]
        $Certificate,

        [Parameter(
            Position = 0,
            Mandatory = $true,
            ParameterSetName = "byId",
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true
        )]
        [ValidateRange(1, [uint64]::MaxValue)]
        [Alias('ID')]
        [uint64[]]$PageID,

        [Parameter(
            ParameterSetName = "bySpace"
        )]
        [Parameter(
            ParameterSetName = "bySpaceObject"
        )]
        [Alias('Name')]
        [string]$Title,

        [Parameter(
            Mandatory = $true,
            ParameterSetName = "bySpace"
        )]
        [Parameter(
            ParameterSetName = "byLabel"
        )]
        [Alias('Key')]
        [string]$SpaceKey,

        [Parameter(
            Mandatory = $true,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            ParameterSetName = "bySpaceObject"
        )]
        [Parameter(
            ValueFromPipeline = $true,
            ParameterSetName = "byLabel"
        )]
        [ConfluencePS.Space]$Space,

        [Parameter(
            Mandatory = $true,
            ParameterSetName = "byLabel"
        )]
        [string[]]$Label,

        [Parameter(
            Position = 0,
            Mandatory = $true,
            ParameterSetName = "byQuery"
        )]
        [string]$Query,

        [ValidateRange(1, [uint64]::MaxValue)]
        [uint64]$PageSize = 25
    )

    BEGIN {
        Write-Verbose "[$($MyInvocation.MyCommand.Name)] Function started"

        $resourceApi = "$ApiUri/content{0}"

        #setup defaults that don't change based on the pipeline or the parameter set
        $iwParameters = Copy-CommonParameter -InputObject $PSBoundParameters
        $iwParameters['Method'] = 'Get'
        $iwParameters['GetParameters'] = @{
            expand = "space,version,body.storage,ancestors"
            limit  = $PageSize
        }
        $iwParameters['OutputType'] = [ConfluencePS.Page]
    }

    PROCESS {
        Write-Debug "[$($MyInvocation.MyCommand.Name)] ParameterSetName: $($PsCmdlet.ParameterSetName)"
        Write-Debug "[$($MyInvocation.MyCommand.Name)] PSBoundParameters: $($PSBoundParameters | Out-String)"

        if ($Space -is [ConfluencePS.Space] -and ($Space.Key)) {
            $SpaceKey = $Space.Key
        }

        # Paging
        ($PSCmdlet.PagingParameters | Get-Member -MemberType Property).Name | ForEach-Object {
            $iwParameters[$_] = $PSCmdlet.PagingParameters.$_
        }

        switch -regex ($PsCmdlet.ParameterSetName) {
            "byId" {
                foreach ($_pageID in $PageID) {
                    $iwParameters["Uri"] = $resourceApi -f "/$_pageID"

                    Invoke-Method @iwParameters
                }
                break
            }
            "bySpace" {
                # This includes 'bySpaceObject'
                $iwParameters["Uri"] = $resourceApi -f ''
                $iwParameters["GetParameters"]["type"] = "page"
                if ($SpaceKey) { $iwParameters["GetParameters"]["spaceKey"] = $SpaceKey }

                if ($Title) {
                    Invoke-Method @iwParameters | Where-Object { $_.Title -like "$Title" }
                } else {
                    Invoke-Method @iwParameters
                }
                break
            }
            "byLabel" {
                $iwParameters["Uri"] = $resourceApi -f "/search"

                $CQLparameters = @("type=page", "label=$Label")
                if ($SpaceKey) { $CQLparameters += "space=$SpaceKey" }
                $cqlQuery = ConvertTo-URLEncoded ($CQLparameters -join (" AND "))

                $iwParameters["GetParameters"]["cql"] = $cqlQuery

                Invoke-Method @iwParameters
                break
            }
            "byQuery" {
                $iwParameters["Uri"] = $resourceApi -f "/search"

                $cqlQuery = ConvertTo-URLEncoded $Query
                $iwParameters["GetParameters"]["cql"] = "type=page AND $cqlQuery"

                Invoke-Method @iwParameters
            }
        }
    }

    END {
        Write-Verbose "[$($MyInvocation.MyCommand.Name)] Function ended"
    }
}

function Get-Space {
    [CmdletBinding(
        SupportsPaging = $true
    )]
    [OutputType([ConfluencePS.Space])]
    param (
        [Parameter( Mandatory = $true )]
        [uri]$ApiUri,

        [Parameter( Mandatory = $false )]
        [PSCredential]$Credential,

        [Parameter( Mandatory = $false )]
        [ValidateNotNull()]
        [System.Security.Cryptography.X509Certificates.X509Certificate]
        $Certificate,

        [Parameter(
            Position = 0
        )]
        [Alias('Key')]
        [string[]]$SpaceKey,

        [ValidateRange(1, [uint64]::MaxValue)]
        [uint64]$PageSize = 25
    )

    BEGIN {
        Write-Verbose "[$($MyInvocation.MyCommand.Name)] Function started"

        $resourceApi = "$ApiUri/space{0}"
    }

    PROCESS {
        Write-Debug "[$($MyInvocation.MyCommand.Name)] ParameterSetName: $($PsCmdlet.ParameterSetName)"
        Write-Debug "[$($MyInvocation.MyCommand.Name)] PSBoundParameters: $($PSBoundParameters | Out-String)"

        $iwParameters = Copy-CommonParameter -InputObject $PSBoundParameters
        $iwParameters['Method'] = 'Get'
        $iwParameters['GetParameters'] = @{
            expand = "description.plain,icon,homepage,metadata.labels"
            limit  = $PageSize
        }
        $iwParameters['OutputType'] = [ConfluencePS.Space]

        # Paging
        ($PSCmdlet.PagingParameters | Get-Member -MemberType Property).Name | ForEach-Object {
            $iwParameters[$_] = $PSCmdlet.PagingParameters.$_
        }

        if ($SpaceKey) {
            foreach ($_space in $SpaceKey) {
                $iwParameters["Uri"] = $resourceApi -f "/$_space"

                Invoke-Method @iwParameters
            }
        } else {
            $iwParameters["Uri"] = $resourceApi -f ""

            Invoke-Method @iwParameters
        }
    }

    END {
        Write-Verbose "[$($MyInvocation.MyCommand.Name)] Function ended"
    }
}

function Invoke-Method {
    [CmdletBinding(SupportsPaging = $true)]
    [OutputType(
        [PSObject],
        [ConfluencePS.Page],
        [ConfluencePS.Space],
        [ConfluencePS.Label],
        [ConfluencePS.Icon],
        [ConfluencePS.Version],
        [ConfluencePS.User],
        [ConfluencePS.Attachment]
    )]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute( "PSAvoidUsingEmptyCatchBlock", "" )]
    param (
        [Parameter(Mandatory = $true)]
        [uri]$Uri,

        [Microsoft.PowerShell.Commands.WebRequestMethod]$Method = "GET",

        [ValidateNotNullOrEmpty()]
        [String]$Body,

        [Switch]$RawBody,

        [Hashtable]$Headers,

        [Hashtable]$GetParameters,

        [String]$InFile,

        [String]$OutFile,

        [ValidateSet(
            [ConfluencePS.Page],
            [ConfluencePS.Space],
            [ConfluencePS.Label],
            [ConfluencePS.Icon],
            [ConfluencePS.Version],
            [ConfluencePS.User],
            [ConfluencePS.Attachment]
        )]
        [System.Type]$OutputType,

        [Parameter( Mandatory = $false )]
        [PSCredential]$Credential,

        [Parameter( Mandatory = $false )]
        [ValidateNotNull()]
        [System.Security.Cryptography.X509Certificates.X509Certificate]
        $Certificate,

        $Caller = $PSCmdlet
    )

    BEGIN {
        Write-Verbose "[$($MyInvocation.MyCommand.Name)] Function started"

        Set-TlsLevel -Tls12

        # Sanitize double slash `//`
        # Happens when the BaseUri is the domain name
        # [Uri]"http://google.com" vs [Uri]"http://google.com/foo"
        $Uri = $Uri -replace '(?<!:)\/\/', '/'

        # pass input to local variable
        # this allows to use the PSBoundParameters for recursion
        $_headers = @{   # Set any default headers
            "Accept"         = "application/json"
            "Accept-Charset" = "utf-8"
        }
        $Headers.Keys.foreach( { $_headers[$_] = $Headers[$_] })
    }

    Process {
        Write-DebugMessage "[$($MyInvocation.MyCommand.Name)] ParameterSetName: $($PsCmdlet.ParameterSetName)"
        Write-DebugMessage "[$($MyInvocation.MyCommand.Name)] PSBoundParameters: $($PSBoundParameters | Out-String)"

        # load DefaultParameters for Invoke-WebRequest
        # as the global PSDefaultParameterValues is not used
        $PSDefaultParameterValues = $global:PSDefaultParameterValues

        $splatParameters = Copy-CommonParameter -InputObject $PSBoundParameters -AdditionalParameter @("Uri", "Method", "InFile", "OutFile")
        $splatParameters['Headers'] = $_headers
        $splatParameters['ContentType'] = "application/json; charset=utf-8"
        $splatParameters['UseBasicParsing'] = $true
        $splatParameters['ErrorAction'] = 'Stop'
        $splatParameters['Verbose'] = $false     # Overwrites verbose output

        #add 'start' query parameter if Paging with Skip is being used
        if (($PSCmdlet.PagingParameters) -and ($PSCmdlet.PagingParameters.Skip)) {
            $GetParameters["start"] = $PSCmdlet.PagingParameters.Skip
        }
        # Append GET parameters to Uri, aka query Parameters
        if ($GetParameters -and ($Uri.Query -eq "")) {
            Write-Debug "[$($MyInvocation.MyCommand.Name)] Using `$GetParameters: $($GetParameters | Out-String)"
            $splatParameters['Uri'] = [uri]"$Uri$(ConvertTo-GetParameter $GetParameters)"
            # Prevent recursive appends
            $PSBoundParameters.Remove('GetParameters') | Out-Null
            $GetParameters = $null
        }

        if ($_headers.ContainsKey("Content-Type")) {
            $splatParameters["ContentType"] = $_headers["Content-Type"]
            $_headers.Remove("Content-Type")
            $splatParameters["Headers"] = $_headers
        }

        if ($Body) {
            if ($RawBody) {
                $splatParameters["Body"] = $Body
            } else {
                # Encode Body to preserve special chars
                # http://stackoverflow.com/questions/15290185/invoke-webrequest-issue-with-special-characters-in-json
                $splatParameters["Body"] = [System.Text.Encoding]::UTF8.GetBytes($Body)
            }
        }

        # Invoke the API
        Write-Verbose "[$($MyInvocation.MyCommand.Name)] Invoking method $Method to URI $URi"
        Write-Verbose "[$($MyInvocation.MyCommand.Name)] Invoke-WebRequest with: $(([PSCustomObject]$splatParameters) | Out-String)"
        try {
            $webResponse = Invoke-WebRequest @splatParameters
        } catch {
            Write-Verbose "[$($MyInvocation.MyCommand.Name)] Failed to get an answer from the server"
            $webResponse = $_
            if ($webResponse.ErrorDetails) {
                # In PowerShellCore (v6+), the response body is available as string
                $responseBody = $webResponse.ErrorDetails.Message
            } else {
                $webResponse = $webResponse.Exception.Response
            }
        }

        # Test response Headers if Confluence requires a CAPTCHA
        Test-Captcha -InputObject $webResponse

        Write-Debug "[$($MyInvocation.MyCommand.Name)] Executed WebRequest. Access `$webResponse to see details"

        if ($webResponse) {
            # In PowerShellCore (v6+) the StatusCode of an exception is somewhere else
            if (-not ($statusCode = $webResponse.StatusCode)) {
                $statusCode = $webresponse.Exception.Response.StatusCode
            }
            Write-Verbose "[$($MyInvocation.MyCommand.Name)] Status code: $($statusCode)"

            if ($statusCode.value__ -ge 400) {
                Write-Warning "Confluence returned HTTP error $($statusCode.value__) - $($statusCode)"

                if ((!($responseBody)) -and ($webResponse | Get-Member -Name "GetResponseStream")) {
                    # Retrieve body of HTTP response - this contains more useful information about exactly why the error occurred
                    $readStream = New-Object -TypeName System.IO.StreamReader -ArgumentList ($webResponse.GetResponseStream())
                    $responseBody = $readStream.ReadToEnd()
                    $readStream.Close()
                }

                Write-Verbose "[$($MyInvocation.MyCommand.Name)] Retrieved body of HTTP response for more information about the error (`$responseBody)"
                Write-Debug "[$($MyInvocation.MyCommand.Name)] Got the following error as `$responseBody"

                $errorItem = [System.Management.Automation.ErrorRecord]::new(
                    ([System.ArgumentException]"Invalid Server Response"),
                    "InvalidResponse.Status$($statusCode.value__)",
                    [System.Management.Automation.ErrorCategory]::InvalidResult,
                    $responseBody
                )

                try {
                    $responseObject = ConvertFrom-Json -InputObject $responseBody -ErrorAction Stop
                    if ($responseObject.message) {
                        $errorItem.ErrorDetails = $responseObject.message
                    } else {
                        $errorItem.ErrorDetails = "An unknown error ocurred."
                    }

                } catch {
                    $errorItem.ErrorDetails = "An unknown error ocurred."
                }

                $Caller.WriteError($errorItem)
            } else {
                if ($webResponse.Content) {
                    try {
                        # API returned a Content: lets work with it
                        $response = ConvertFrom-Json ([Text.Encoding]::UTF8.GetString($webResponse.RawContentStream.ToArray()))

                        if ($null -ne $response.errors) {
                            Write-Verbose "[$($MyInvocation.MyCommand.Name)] An error response was received from; resolving"
                            # This could be handled nicely in an function such as:
                            # ResolveError $response -WriteError
                            Write-Error $($response.errors | Out-String)
                        } else {
                            if ($PSCmdlet.PagingParameters.IncludeTotalCount) {
                                [double]$Accuracy = 0.0
                                $PSCmdlet.PagingParameters.NewTotalCount($response.size, $Accuracy)
                            }
                            # None paginated results / first page of pagination
                            $result = $response
                            if (($response) -and ($response | Get-Member -Name results)) {
                                $result = $response.results
                            }
                            if ($OutputType) {
                                # Results shall be casted to custom objects (see ValidateSet)
                                Write-Verbose "[$($MyInvocation.MyCommand.Name)] Outputting results as $($OutputType.FullName)"
                                $converter = "ConvertTo-$($OutputType.Name)"
                                $result | & $converter
                            } else {
                                $result
                            }

                            # Detect if result is paginated
                            if ($response._links.next) {
                                Write-Verbose "[$($MyInvocation.MyCommand.Name)] Invoking pagination"

                                # Remove Parameters that don't need propagation
                                $script:PSDefaultParameterValues.Remove("$($MyInvocation.MyCommand.Name):GetParameters")
                                $script:PSDefaultParameterValues.Remove("$($MyInvocation.MyCommand.Name):IncludeTotalCount")

                                $parameters = Copy-CommonParameter -InputObject $PSBoundParameters -AdditionalParameter @("Method", "Headers", "OutputType")
                                $parameters['Uri'] = "{0}{1}" -f $response._links.base, $response._links.next

                                Write-Verbose "NEXT PAGE: $($parameters["Uri"])"

                                Invoke-Method @parameters
                            }
                        }
                    } catch {
                        throw $_
                    }
                } else {
                    # No content, although statusCode < 400
                    # This could be wanted behavior of the API
                    Write-Verbose "[$($MyInvocation.MyCommand.Name)] No content was returned from."
                }
            }
        } else {
            Write-Verbose "[$($MyInvocation.MyCommand.Name)] No Web result object was returned from. This is unusual!"
        }
    }

    END {
        Set-TlsLevel -Revert

        Write-Verbose "[$($MyInvocation.MyCommand.Name)] Function ended"
    }
}

function New-Page {
    [CmdletBinding(
        ConfirmImpact = 'Low',
        SupportsShouldProcess = $true,
        DefaultParameterSetName = 'byParameters'
    )]
    [OutputType([ConfluencePS.Page])]
    param (
        [Parameter( Mandatory = $true )]
        [uri]$ApiUri,

        [Parameter( Mandatory = $false )]
        [PSCredential]$Credential,

        [Parameter( Mandatory = $false )]
        [ValidateNotNull()]
        [System.Security.Cryptography.X509Certificates.X509Certificate]
        $Certificate,

        [Parameter(
            Mandatory = $true,
            ValueFromPipeline = $true,
            ParameterSetName = 'byObject'
        )]
        [ConfluencePS.Page]$InputObject,

        [Parameter(
            Mandatory = $true,
            ValueFromPipeline = $true,
            ParameterSetName = 'byParameters'
        )]
        [Alias('Name')]
        [string]$Title,

        [Parameter(ParameterSetName = 'byParameters')]
        [ValidateRange(1, [uint64]::MaxValue)]
        [uint64]$ParentID,
        [Parameter(ParameterSetName = 'byParameters')]
        [ConfluencePS.Page]$Parent,

        [Parameter(ParameterSetName = 'byParameters')]
        [string]$SpaceKey,
        [Parameter(ParameterSetName = 'byParameters')]
        [ConfluencePS.Space]$Space,

        [Parameter(ParameterSetName = 'byParameters')]
        [string]$Body,

        [Parameter(ParameterSetName = 'byParameters')]
        [switch]$Convert
    )

    BEGIN {
        Write-Verbose "[$($MyInvocation.MyCommand.Name)] Function started"

        $resourceApi = "$ApiUri/content"

        #this is the splat hashtable that passes the auth and uri to calls but not Invoke-Method, i.e. Get-Page
        $authAndApiUri = Copy-CommonParameter -InputObject $PSBoundParameters -AdditionalParameter "ApiUri"
    }

    PROCESS {
        Write-Debug "[$($MyInvocation.MyCommand.Name)] ParameterSetName: $($PsCmdlet.ParameterSetName)"
        Write-Debug "[$($MyInvocation.MyCommand.Name)] PSBoundParameters: $($PSBoundParameters | Out-String)"

        $iwParameters = Copy-CommonParameter -InputObject $PSBoundParameters
        $iwParameters['Uri'] = $resourceApi
        $iwParameters['Method'] = 'Post'
        $iwParameters['OutputType'] = [ConfluencePS.Page]

        $Content = [PSObject]@{
            type      = "page"
            space     = [PSObject]@{ key = "" }
            title     = ""
            body      = [PSObject]@{
                storage = [PSObject]@{
                    representation = 'storage'
                }
            }
            ancestors = @()
        }

        switch ($PsCmdlet.ParameterSetName) {
            "byObject" {
                $Content.title = $InputObject.Title
                $Content.space.key = $InputObject.Space.Key
                $Content.body.storage.value = $InputObject.Body
                if ($InputObject.Ancestors) {
                    $Content.ancestors += @( $InputObject.Ancestors | ForEach-Object { @{ id = $_.ID } } )
                }
            }
            "byParameters" {
                if (($Parent -is [ConfluencePS.Page]) -and ($Parent.ID)) {
                    $ParentID = $Parent.ID
                }
                if (($Space -is [ConfluencePS.Space]) -and ($Space.Key)) {
                    $SpaceKey = $Space.Key
                }

                if (($ParentID) -and !($SpaceKey)) {
                    Write-Verbose "[$($MyInvocation.MyCommand.Name)] SpaceKey not specified. Retrieving from Get-ConfluencePage -PageID $ParentID"
                    $SpaceKey = (Get-Page -PageID $ParentID @authAndApiUri).Space.Key
                }

                # If -Convert is flagged, call ConvertTo-ConfluenceStorageFormat against the -Body
                if ($Convert) {
                    Write-Verbose '[$($MyInvocation.MyCommand.Name)] -Convert flag active; converting content to Confluence storage format'
                    $Body = ConvertTo-StorageFormat -Content $Body @authAndApiUri
                }

                $Content.title = $Title
                $Content.space = @{ key = $SpaceKey }
                $Content.body.storage.value = $Body
                if ($ParentID) {
                    $Content.ancestors = @( @{ id = $ParentID } )
                }
            }
        }

        $iwParameters["Body"] = $Content | ConvertTo-Json

        Write-Debug "[$($MyInvocation.MyCommand.Name)] Content to be sent: $($Content | Out-String)"
        If ($PSCmdlet.ShouldProcess("Space $($Content.space.key)")) {
            Invoke-Method @iwParameters
        }
    }

    END {
        Write-Verbose "[$($MyInvocation.MyCommand.Name)] Function ended"
    }
}

function New-Space {
    [CmdletBinding(
        ConfirmImpact = 'Low',
        SupportsShouldProcess = $true,
        DefaultParameterSetName = "byObject"
    )]
    [OutputType([ConfluencePS.Space])]
    param (
        [Parameter( Mandatory = $true )]
        [uri]$ApiUri,

        [Parameter( Mandatory = $false )]
        [PSCredential]$Credential,

        [Parameter( Mandatory = $false )]
        [ValidateNotNull()]
        [System.Security.Cryptography.X509Certificates.X509Certificate]
        $Certificate,

        [Parameter(
            Mandatory = $true,
            ParameterSetName = "byObject",
            ValueFromPipeline = $true
        )]
        [ConfluencePS.Space]$InputObject,

        [Parameter(
            Mandatory = $true,
            ParameterSetName = "byProperties"
        )]
        [Alias('Key')]
        [string]$SpaceKey,

        [Parameter(
            Mandatory = $true,
            ParameterSetName = "byProperties"
        )]
        [string]$Name,

        [Parameter(
            ParameterSetName = "byProperties"
        )]
        [string]$Description
    )

    BEGIN {
        Write-Verbose "[$($MyInvocation.MyCommand.Name)] Function started"

        $resourceApi = "$ApiUri/space"
    }

    PROCESS {
        Write-Debug "[$($MyInvocation.MyCommand.Name)] ParameterSetName: $($PsCmdlet.ParameterSetName)"
        Write-Debug "[$($MyInvocation.MyCommand.Name)] PSBoundParameters: $($PSBoundParameters | Out-String)"

        if ($PsCmdlet.ParameterSetName -eq "byObject") {
            $SpaceKey = $InputObject.Key
            $Name = $InputObject.Name
            $Description = $InputObject.Description
        }

        $iwParameters = Copy-CommonParameter -InputObject $PSBoundParameters
        $iwParameters['Uri'] = $resourceApi
        $iwParameters['Method'] = 'Post'
        $iwParameters['OutputType'] = [ConfluencePS.Space]

        $Body = @{
            key         = $SpaceKey
            name        = $Name
            description = @{
                plain = @{
                    value          = $Description
                    representation = 'plain'
                }
            }
        }

        $iwParameters["Body"] = $Body | ConvertTo-Json

        Write-Debug "[$($MyInvocation.MyCommand.Name)] Content to be sent: $($Body | Out-String)"
        If ($PSCmdlet.ShouldProcess("$SpaceKey $Name")) {
            Invoke-Method @iwParameters
        }
    }

    END {
        Write-Verbose "[$($MyInvocation.MyCommand.Name)] Function ended"
    }
}

function Remove-Attachment {
    [CmdletBinding(
        ConfirmImpact = 'Medium',
        SupportsShouldProcess = $true
    )]
    [OutputType([Bool])]
    param (
        [Parameter( Mandatory = $true )]
        [uri]$ApiUri,

        [Parameter( Mandatory = $false )]
        [PSCredential]$Credential,

        [Parameter( Mandatory = $false )]
        [ValidateNotNull()]
        [System.Security.Cryptography.X509Certificates.X509Certificate]
        $Certificate,

        [Parameter(
            Position = 0,
            Mandatory = $true,
            ValueFromPipeline = $true
        )]
        [ConfluencePS.Attachment[]]$Attachment
    )

    BEGIN {
        Write-Verbose "[$($MyInvocation.MyCommand.Name)] Function started"

        $resourceApi = "$ApiUri/content/{0}"
    }

    PROCESS {
        Write-DebugMessage "[$($MyInvocation.MyCommand.Name)] ParameterSetName: $($PsCmdlet.ParameterSetName)"
        Write-DebugMessage "[$($MyInvocation.MyCommand.Name)] PSBoundParameters: $($PSBoundParameters | Out-String)"

        $iwParameters = Copy-CommonParameter -InputObject $PSBoundParameters
        $iwParameters['Method'] = 'Delete'

        foreach ($_attachment in $Attachment) {
            $iwParameters["Uri"] = $resourceApi -f $_attachment.ID

            if ($PSCmdlet.ShouldProcess("Attachment $($_attachment.ID), PageID $($_attachment.PageID)")) {
                Invoke-Method @iwParameters
            }
        }
    }

    END {
        Write-Verbose "[$($MyInvocation.MyCommand.Name)] Function ended"
    }
}

function Remove-Label {
    [CmdletBinding(
        ConfirmImpact = 'Low',
        SupportsShouldProcess = $true
    )]
    [OutputType([Bool])]
    param (
        [Parameter( Mandatory = $true )]
        [uri]$ApiUri,

        [Parameter( Mandatory = $false )]
        [PSCredential]$Credential,

        [Parameter( Mandatory = $false )]
        [ValidateNotNull()]
        [System.Security.Cryptography.X509Certificates.X509Certificate]
        $Certificate,

        [Parameter(
            Position = 0,
            Mandatory = $true,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true
        )]
        [ValidateRange(1, [uint64]::MaxValue)]
        [Alias('ID')]
        [uint64[]]$PageID,

        [Parameter()]
        [string[]]$Label
    )

    BEGIN {
        Write-Verbose "[$($MyInvocation.MyCommand.Name)] Function started"

        $resourceApi = "$ApiUri/content/{0}/label?name={1}"
    }

    PROCESS {
        Write-Debug "[$($MyInvocation.MyCommand.Name)] ParameterSetName: $($PsCmdlet.ParameterSetName)"
        Write-Debug "[$($MyInvocation.MyCommand.Name)] PSBoundParameters: $($PSBoundParameters | Out-String)"

        if (($_) -and -not($_ -is [ConfluencePS.Page] -or $_ -is [uint64])) {
            $message = "The Object in the pipe is not a Page."
            $exception = New-Object -TypeName System.ArgumentException -ArgumentList $message
            Throw $exception
        }

        $iwParameters = Copy-CommonParameter -InputObject $PSBoundParameters
        $iwParameters['Method'] = 'Delete'

        foreach ($_page in $PageID) {
            $_labels = $Label
            if (!$_labels) {
                Write-Verbose "[$($MyInvocation.MyCommand.Name)] Collecting all Labels for page $_page"
                $authAndApiUri = Copy-CommonParameter -InputObject $PSBoundParameters -AdditionalParameter "ApiUri"
                $allLabels = Get-Label -PageID $_page @authAndApiUri
                if ($allLabels.Labels) {
                    $_labels = $allLabels.Labels | Select-Object -ExpandProperty Name
                }
            }
            Write-Debug "[$($MyInvocation.MyCommand.Name)] Labels to remove: `$_labels"

            foreach ($_label in $_labels) {
                $iwParameters["Uri"] = $resourceApi -f $_page, $_label

                if ($PSCmdlet.ShouldProcess("Label $_label, PageID $_page")) {
                    Invoke-Method @iwParameters
                }
            }
        }
    }

    END {
        Write-Verbose "[$($MyInvocation.MyCommand.Name)] Function ended"
    }
}

function Remove-Page {
    [CmdletBinding(
        ConfirmImpact = 'Medium',
        SupportsShouldProcess = $true
    )]
    [OutputType([Bool])]
    param (
        [Parameter( Mandatory = $true )]
        [uri]$ApiUri,

        [Parameter( Mandatory = $false )]
        [PSCredential]$Credential,

        [Parameter( Mandatory = $false )]
        [ValidateNotNull()]
        [System.Security.Cryptography.X509Certificates.X509Certificate]
        $Certificate,

        [Parameter(
            Position = 0,
            Mandatory = $true,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true
        )]
        [ValidateRange(1, [uint64]::MaxValue)]
        [Alias('ID')]
        [uint64[]]$PageID
    )

    BEGIN {
        Write-Verbose "[$($MyInvocation.MyCommand.Name)] Function started"

        $resourceApi = "$ApiUri/content/{0}"
    }

    PROCESS {
        Write-Debug "[$($MyInvocation.MyCommand.Name)] ParameterSetName: $($PsCmdlet.ParameterSetName)"
        Write-Debug "[$($MyInvocation.MyCommand.Name)] PSBoundParameters: $($PSBoundParameters | Out-String)"

        if (($_) -and -not($_ -is [ConfluencePS.Page] -or $_ -is [uint64])) {
            $message = "The Object in the pipe is not a Page."
            $exception = New-Object -TypeName System.ArgumentException -ArgumentList $message
            Throw $exception
        }

        $iwParameters = Copy-CommonParameter -InputObject $PSBoundParameters
        $iwParameters['Method'] = 'Delete'

        foreach ($_page in $PageID) {
            $iwParameters["Uri"] = $resourceApi -f $_page

            If ($PSCmdlet.ShouldProcess("PageID $_page")) {
                Invoke-Method @iwParameters
            }
        }
    }

    END {
        Write-Verbose "[$($MyInvocation.MyCommand.Name)] Function ended"
    }
}

function Remove-Space {
    [CmdletBinding(
        ConfirmImpact = 'High',
        SupportsShouldProcess = $true
    )]
    [OutputType()]
    [System.Diagnostics.CodeAnalysis.SuppressMessage('PSUseDeclaredVarsMoreThanAssignments', '')]
    param (
        [Parameter( Mandatory = $true )]
        [uri]$ApiUri,

        [Parameter( Mandatory = $false )]
        [PSCredential]$Credential,

        [Parameter( Mandatory = $false )]
        [ValidateNotNull()]
        [System.Security.Cryptography.X509Certificates.X509Certificate]
        $Certificate,

        [Parameter(
            Position = 0,
            Mandatory = $true,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true
        )]
        [Alias('Key')]
        [string[]]$SpaceKey,

        [switch]$Force

        # TODO: Probably an extra param later to loop checking the status & wait for completion?
    )

    BEGIN {
        Write-Verbose "[$($MyInvocation.MyCommand.Name)] Function started"

        $resourceApi = "$ApiUri/space/{0}"

        if ($Force) {
            Write-Debug "[$($MyInvocation.MyCommand.Name)] -Force was passed. Backing up current ConfirmPreference [$ConfirmPreference] and setting to None"
            $oldConfirmPreference = $ConfirmPreference
            $ConfirmPreference = 'None'
        }
    }

    PROCESS {
        Write-Debug "[$($MyInvocation.MyCommand.Name)] ParameterSetName: $($PsCmdlet.ParameterSetName)"
        Write-Debug "[$($MyInvocation.MyCommand.Name)] PSBoundParameters: $($PSBoundParameters | Out-String)"

        if (($_) -and -not($_ -is [ConfluencePS.Space] -or $_ -is [string])) {
            $message = "The Object in the pipe is not a Space."
            $exception = New-Object -TypeName System.ArgumentException -ArgumentList $message
            Throw $exception
        }

        $iwParameters = Copy-CommonParameter -InputObject $PSBoundParameters
        $iwParameters['Method'] = 'Delete'

        foreach ($_space in $SpaceKey) {
            $iwParameters["Uri"] = $resourceApi -f $_space

            If ($PSCmdlet.ShouldProcess("Space key $_space")) {
                $response = Invoke-Method @iwParameters

                # Successful response provides a "longtask" status link
                # (add additional code here later to check and/or wait for the status)
            }
        }
    }

    END {
        if ($Force) {
            Write-Debug "[$($MyInvocation.MyCommand.Name)] Restoring ConfirmPreference to [$oldConfirmPreference]"
            $ConfirmPreference = $oldConfirmPreference
        }

        Write-Verbose "[$($MyInvocation.MyCommand.Name)] Function ended"
    }
}

function Set-Attachment {
    [CmdletBinding(
        ConfirmImpact = 'Low',
        SupportsShouldProcess = $true
    )]
    [OutputType([ConfluencePS.Attachment])]
    param (
        [Parameter( Mandatory = $true )]
        [uri]$ApiUri,

        [Parameter( Mandatory = $false )]
        [PSCredential]$Credential,

        [Parameter( Mandatory = $false )]
        [ValidateNotNull()]
        [System.Security.Cryptography.X509Certificates.X509Certificate]
        $Certificate,

        [Parameter(
            Position = 0,
            Mandatory = $true,
            ValueFromPipeline = $true
        )]
        [ConfluencePS.Attachment]$Attachment,

        # Path of the file to upload and attach
        [Parameter( Mandatory )]
        [ValidateScript(
            {
                if (-not (Test-Path $_ -PathType Leaf)) {
                    $errorItem = [System.Management.Automation.ErrorRecord]::new(
                        ([System.ArgumentException]"File not found"),
                        'ParameterValue.FileNotFound',
                        [System.Management.Automation.ErrorCategory]::ObjectNotFound,
                        $_
                    )
                    $errorItem.ErrorDetails = "No file could be found with the provided path '$_'."
                    $PSCmdlet.ThrowTerminatingError($errorItem)
                } else {
                    return $true
                }
            }
        )]
        [String]$FilePath
    )

    BEGIN {
        Write-Verbose "[$($MyInvocation.MyCommand.Name)] Function started"

        $resourceApi = "$ApiUri/content/{0}/child/attachment/{1}/data"
    }

    PROCESS {
        Write-DebugMessage "[$($MyInvocation.MyCommand.Name)] ParameterSetName: $($PsCmdlet.ParameterSetName)"
        Write-DebugMessage "[$($MyInvocation.MyCommand.Name)] PSBoundParameters: $($PSBoundParameters | Out-String)"

        $iwParameters = Copy-CommonParameter -InputObject $PSBoundParameters
        $iwParameters['Uri'] = $resourceApi -f $Attachment.PageID, $Attachment.ID
        $iwParameters['Method'] = 'Post'
        $iwParameters['InFile'] = $FilePath
        $iwParameters['OutputType'] = [ConfluencePS.Attachment]

        Write-Debug "[$($MyInvocation.MyCommand.Name)] Invoking Set Attachment Method with `$parameter"
        if ($PSCmdlet.ShouldProcess($Attachment.PageID, "Updating attachment '$($Attachment.Title)'.")) {
            Invoke-Method @iwParameters
        }
    }

    END {
        Write-Verbose "[$($MyInvocation.MyCommand.Name)] Function ended"
    }
}

function Set-Info {
    [CmdletBinding()]
    [System.Diagnostics.CodeAnalysis.SuppressMessage('PSUseShouldProcessForStateChangingFunctions', '')]
    param (
        [Parameter(
            HelpMessage = 'Example = https://brianbunke.atlassian.net/wiki (/wiki for Cloud instances)'
        )]
        [uri]$BaseURi,

        [PSCredential]$Credential,

        [uint64]$PageSize,

        [switch]$PromptCredentials
    )

    BEGIN {

        function Add-ConfluenceDefaultParameter {
            param(
                [Parameter(Mandatory = $true)]
                [string]$Command,

                [Parameter(Mandatory = $true)]
                [string]$Parameter,

                [Parameter(Mandatory = $true)]
                $Value
            )

            PROCESS {
                Write-Verbose "[$($MyInvocation.MyCommand.Name)] Setting [$command : $parameter] = $value"

                # Needs to set both global and module scope for the private functions:
                # http://stackoverflow.com/questions/30427110/set-psdefaultparametersvalues-for-use-within-module-scope
                $PSDefaultParameterValues["${command}:${parameter}"] = $Value
                $global:PSDefaultParameterValues["${command}:${parameter}"] = $Value
            }
        }

        $moduleCommands = Get-Command -Module ConfluencePS

        if ($PromptCredentials) {
            $Credential = (Get-Credential)
        }
    }

    PROCESS {
        foreach ($command in $moduleCommands) {

            $parameter = "ApiUri"
            if ($BaseURi -and ($command.Parameters.Keys -contains $parameter)) {
                Add-ConfluenceDefaultParameter -Command $command -Parameter $parameter -Value ($BaseURi.AbsoluteUri.TrimEnd('/') + '/rest/api')
            }

            $parameter = "Credential"
            if ($Credential -and ($command.Parameters.Keys -contains $parameter)) {
                Add-ConfluenceDefaultParameter -Command $command -Parameter $parameter -Value $Credential
            }

            $parameter = "PageSize"
            if ($PageSize -and ($command.Parameters.Keys -contains $parameter)) {
                Add-ConfluenceDefaultParameter -Command $command -Parameter $parameter -Value $PageSize
            }
        }
    }
}

function Set-Label {
    [CmdletBinding(
        ConfirmImpact = 'Low',
        SupportsShouldProcess = $true
    )]
    [OutputType([ConfluencePS.ContentLabelSet])]
    param (
        [Parameter( Mandatory = $true )]
        [uri]$ApiUri,

        [Parameter( Mandatory = $false )]
        [PSCredential]$Credential,

        [Parameter( Mandatory = $false )]
        [ValidateNotNull()]
        [System.Security.Cryptography.X509Certificates.X509Certificate]
        $Certificate,

        [Parameter(
            Position = 0,
            Mandatory = $true,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true
        )]
        [ValidateRange(1, [uint64]::MaxValue)]
        [Alias('ID')]
        [uint64[]]$PageID,

        [Parameter(Mandatory = $true)]
        [string[]]$Label
    )

    BEGIN {
        Write-Verbose "[$($MyInvocation.MyCommand.Name)] Function started"

        $resourceApi = "$ApiUri/content/{0}/label"
    }

    PROCESS {
        Write-Debug "[$($MyInvocation.MyCommand.Name)] ParameterSetName: $($PsCmdlet.ParameterSetName)"
        Write-Debug "[$($MyInvocation.MyCommand.Name)] PSBoundParameters: $($PSBoundParameters | Out-String)"

        if (($_) -and -not($_ -is [ConfluencePS.Page] -or $_ -is [uint64])) {
            $message = "The Object in the pipe is not a Page."
            $exception = New-Object -TypeName System.ArgumentException -ArgumentList $message
            Throw $exception
        }

        $iwParameters = Copy-CommonParameter -InputObject $PSBoundParameters
        $iwParameters['Method'] = 'Post'
        $iwParameters['OutputType'] = [ConfluencePS.Label]

        $authAndApiUri = Copy-CommonParameter -InputObject $PSBoundParameters -AdditionalParameter "ApiUri"
        foreach ($_page in $PageID) {
            if ($_ -is [ConfluencePS.Page]) {
                $InputObject = $_
            } else {
                $InputObject = Get-Page -PageID $_page @authAndApiUri
            }

            Write-Verbose "[$($MyInvocation.MyCommand.Name)] Removing all previous labels"
            Remove-Label -PageID $_page @authAndApiUri | Out-Null

            $iwParameters["Uri"] = $resourceApi -f $_page
            $iwParameters["Body"] = $Label | ForEach-Object { @{prefix = 'global'; name = $_ } } | ConvertTo-Json

            Write-Debug "[$($MyInvocation.MyCommand.Name)] Content to be sent: $($iwParameters["Body"] | Out-String)"
            if ($PSCmdlet.ShouldProcess("Label $Label, PageID $_page")) {
                $output = [ConfluencePS.ContentLabelSet]@{ Page = $InputObject }
                $output.Labels += (Invoke-Method @iwParameters)
                $output
            }
        }
    }

    END {
        Write-Verbose "[$($MyInvocation.MyCommand.Name)] Function ended"
    }
}

function Set-Page {
    [CmdletBinding(
        ConfirmImpact = 'Medium',
        SupportsShouldProcess = $true,
        DefaultParameterSetName = 'byParameters'
    )]
    [OutputType([ConfluencePS.Page])]
    param (
        [Parameter( Mandatory = $true )]
        [uri]$ApiUri,

        [Parameter( Mandatory = $false )]
        [PSCredential]$Credential,

        [Parameter( Mandatory = $false )]
        [ValidateNotNull()]
        [System.Security.Cryptography.X509Certificates.X509Certificate]
        $Certificate,

        [Parameter(
            Mandatory = $true,
            ValueFromPipeline = $true,
            ParameterSetName = 'byObject'
        )]
        [ConfluencePS.Page]$InputObject,

        [Parameter(
            Mandatory = $true,
            ValueFromPipeline = $true,
            ParameterSetName = 'byParameters'
        )]
        [ValidateRange(1, [uint64]::MaxValue)]
        [Alias('ID')]
        [uint64]$PageID,

        [Parameter(ParameterSetName = 'byParameters')]
        [ValidateNotNullOrEmpty()]
        [string]$Title,

        [Parameter(ParameterSetName = 'byParameters')]
        [string]$Body,

        [Parameter(ParameterSetName = 'byParameters')]
        [switch]$Convert,

        [Parameter(ParameterSetName = 'byParameters')]
        [ValidateRange(1, [uint64]::MaxValue)]
        [uint64]$ParentID,

        [Parameter(ParameterSetName = 'byParameters')]
        [ConfluencePS.Page]$Parent
    )

    BEGIN {
        Write-Verbose "[$($MyInvocation.MyCommand.Name)] Function started"

        $resourceApi = "$ApiUri/content/{0}"

        $authAndApiUri = Copy-CommonParameter -InputObject $PSBoundParameters -AdditionalParameter "ApiUri"
        # If -Convert is flagged, call ConvertTo-ConfluenceStorageFormat against the -Body
        if ($Convert) {
            Write-Verbose '[$($MyInvocation.MyCommand.Name)] -Convert flag active; converting content to Confluence storage format'
            $Body = ConvertTo-StorageFormat -Content $Body @authAndApiUri
        }
    }

    PROCESS {
        Write-Debug "[$($MyInvocation.MyCommand.Name)] ParameterSetName: $($PsCmdlet.ParameterSetName)"
        Write-Debug "[$($MyInvocation.MyCommand.Name)] PSBoundParameters: $($PSBoundParameters | Out-String)"

        $iwParameters = Copy-CommonParameter -InputObject $PSBoundParameters
        $iwParameters['Method'] = 'Put'
        $iwParameters['OutputType'] = [ConfluencePS.Page]

        $Content = [PSObject]@{
            type      = "page"
            title     = ""
            body      = [PSObject]@{
                storage = [PSObject]@{
                    value          = ""
                    representation = 'storage'
                }
            }
            version   = [PSObject]@{
                number = 0
            }
            ancestors = @()
        }

        switch ($PsCmdlet.ParameterSetName) {
            "byObject" {
                $iwParameters["Uri"] = $resourceApi -f $InputObject.ID
                $Content.version.number = ++$InputObject.Version.Number
                $Content.title = $InputObject.Title
                $Content.body.storage.value = $InputObject.Body
                # if ($InputObject.Ancestors) {
                # $Content["ancestors"] += @( $InputObject.Ancestors | Foreach-Object { @{ id = $_.ID } } )
                # }
            }
            "byParameters" {
                $iwParameters["Uri"] = $resourceApi -f $PageID
                $originalPage = Get-Page -PageID $PageID @authAndApiUri

                if (($Parent -is [ConfluencePS.Page]) -and ($Parent.ID)) {
                    $ParentID = $Parent.ID
                }

                $Content.version.number = ++$originalPage.Version.Number
                if ($Title) { $Content.title = $Title }
                else { $Content.title = $originalPage.Title }
                # $Body might be empty
                if ($PSBoundParameters.Keys -contains "Body") {
                    $Content.body.storage.value = $Body
                } else {
                    $Content.body.storage.value = $originalPage.Body
                }
                # Ancestors is undocumented! May break in the future
                # http://stackoverflow.com/questions/23523705/how-to-create-new-page-in-confluence-using-their-rest-api
                if ($ParentID) {
                    $Content.ancestors = @( @{ id = $ParentID } )
                }
            }
        }

        $iwParameters["Body"] = $Content | ConvertTo-Json

        Write-Debug "[$($MyInvocation.MyCommand.Name)] Content to be sent: $($Content | Out-String)"
        If ($PSCmdlet.ShouldProcess("Page $($Content.title)")) {
            Invoke-Method @iwParameters
        }
    }

    END {
        Write-Verbose "[$($MyInvocation.MyCommand.Name)] Function ended"
    }
}

function ConvertFrom-HTMLEncoded {
    <#
    .SYNOPSIS
    Decode a HTML encoded string
    #>
    [CmdletBinding()]
    [OutputType([String])]
    param (
        # String to decode
        [Parameter( Position = 0, Mandatory = $true, ValueFromPipeline = $true )]
        [string]$InputString
    )

    PROCESS {
        Write-Verbose "[$($MyInvocation.MyCommand.Name)] Decoding string from HTML"
        [System.Web.HttpUtility]::HtmlDecode($InputString)
    }
}

function ConvertFrom-URLEncoded {
    <#
    .SYNOPSIS
    Decode a URL encoded string
    #>
    [CmdletBinding()]
    [OutputType([String])]
    param (
        # String to decode
        [Parameter( Position = 0, Mandatory = $true, ValueFromPipeline = $true )]
        [string]$InputString
    )

    PROCESS {
        Write-Verbose "[$($MyInvocation.MyCommand.Name)] Decoding string from URL"
        [System.Web.HttpUtility]::UrlDecode($InputString)
    }
}

function ConvertTo-Attachment {
    <#
    .SYNOPSIS
    Extracted the conversion to private function in order to have a single place to
    select the properties to use when casting to custom object type
    #>
    [CmdletBinding()]
    [OutputType( [ConfluencePS.Attachment] )]
    param (
        # object to convert
        [Parameter( ValueFromPipeline = $true )]
        $InputObject
    )

    Process {
        foreach ($object in $InputObject) {
            Write-Verbose "[$($MyInvocation.MyCommand.Name)] Converting Object to Attachment"

            if ($_.container.id) {
                $PageId = $_.container.id
            } else {
                [UInt32]$PageID = $_._expandable.container -replace '^.*\/content\/', ''
            }

            [ConfluencePS.Attachment](ConvertTo-Hashtable -InputObject ($object | Select-Object `
                    @{Name = "id"; Expression = {
                            [UInt32]($_.id -replace 'att', '')
                        }
                    },
                    status,
                    title,
                    @{Name = "filename"; Expression = {
                            '{0}_{1}' -f $PageID, $_.title | Remove-InvalidFileCharacter
                        }
                    },
                    @{Name = "mediatype"; Expression = {
                            $_.extensions.mediaType
                        }
                    },
                    @{Name = "filesize"; Expression = {
                            [convert]::ToInt32($_.extensions.fileSize, 10)
                        }
                    },
                    @{Name = "comment"; Expression = {
                            $_.extensions.comment
                        }
                    },
                    @{Name = "spacekey"; Expression = {
                            $_._expandable.space -replace '^.*\/space\/', ''
                        }
                    },
                    @{Name = "pageid"; Expression = {
                            $PageID
                        }
                    },
                    @{Name = "version"; Expression = {
                            if ($_.version) {
                                ConvertTo-Version $_.version
                            } else { $null }
                        }
                    },
                    @{Name = "URL"; Expression = {
                            $base = $_._links.base
                            if (!($base)) { $base = $_._links.self -replace '\/rest.*', '' }
                            if ($_._links.download) {
                                "{0}{1}" -f $base, $_._links.download
                            } else { $null }
                        }
                    }
                ))
        }
    }
}

function ConvertTo-GetParameter {
    <#
    .SYNOPSIS
    Generate the GET parameter string for an URL from a hashtable
    #>
    [CmdletBinding()]
    param (
        [Parameter( Position = 0, Mandatory = $true, ValueFromPipeline = $true )]
        [hashtable]$InputObject
    )

    BEGIN {
        [string]$parameters = "?"
    }

    PROCESS {
        Write-Verbose "[$($MyInvocation.MyCommand.Name)] Making HTTP get parameter string out of a hashtable"
        foreach ($key in $InputObject.Keys) {
            $parameters += "$key=$($InputObject[$key])&"
        }
    }

    END {
        $parameters -replace ".$"
    }
}

function ConvertTo-HashTable {
    <#
    .SYNOPSIS
    Converts a PSCustomObject to Hashtable

    .DESCRIPTION
    PowerShell v4 on Windows 8.1 seems to have trouble casting [PSCustomObject] to custom classes.
    This function is a workaround, as casting from [Hashtable] is no problem.
    #>
    param(
        # Object to convert
        [Parameter(Mandatory = $true)]
        [PSCustomObject]$InputObject
    )

    begin {
        $hash = @{}
        $InputObject.PSObject.properties | ForEach-Object {
            $hash[$_.Name] = $_.Value
        }
        Write-Output $hash
    }
}

function ConvertTo-HTMLEncoded {
    <#
    .SYNOPSIS
    Encode a string into HTML (eg: &gt; instead of >)
    #>
    [CmdletBinding()]
    [OutputType([String])]
    param (
        # String to encode
        [Parameter( Position = $true, Mandatory = $true, ValueFromPipeline = $true )]
        [string]$InputString
    )

    PROCESS {
        Write-Verbose "[$($MyInvocation.MyCommand.Name)] Encoding string to HTML"
        [System.Web.HttpUtility]::HtmlEncode($InputString)
    }
}

function ConvertTo-Icon {
    <#
    .SYNOPSIS
    Extracted the conversion to private function in order to have a single place
    to select the properties to use when casting to custom object type
    #>
    [CmdletBinding()]
    [OutputType( [ConfluencePS.Icon] )]
    param (
        # object to convert
        [Parameter( Position = 0, ValueFromPipeline = $true )]
        $InputObject
    )

    Process {
        foreach ($object in $InputObject) {
            Write-Verbose "[$($MyInvocation.MyCommand.Name)] Converting Object to Icon"
            [ConfluencePS.Icon](ConvertTo-Hashtable -InputObject ($object | Select-Object `
                        Path,
                    Width,
                    Height,
                    IsDefault
                ))
        }
    }
}

function ConvertTo-Label {
    <#
    .SYNOPSIS
    Extracted the conversion to private function in order to have a single place to
    select the properties to use when casting to custom object type
    #>
    [CmdletBinding()]
    [OutputType( [ConfluencePS.Version] )]
    param (
        # object to convert
        [Parameter( Position = 0, ValueFromPipeline = $true )]
        $InputObject
    )

    Process {
        foreach ($object in $InputObject) {
            Write-Verbose "[$($MyInvocation.MyCommand.Name)] Converting Object to Label"
            [ConfluencePS.Label](ConvertTo-Hashtable -InputObject ($object | Select-Object `
                        id,
                    name,
                    prefix
                ))
        }
    }
}

function ConvertTo-Page {
    <#
    .SYNOPSIS
    Extracted the conversion to private function in order to have a single place to
    select the properties to use when casting to custom object type
    #>
    [CmdletBinding()]
    [OutputType( [ConfluencePS.Page] )]
    param (
        # object to convert
        [Parameter( Position = 0, ValueFromPipeline = $true )]
        $InputObject
    )

    Process {
        foreach ($object in $InputObject) {
            Write-Verbose "[$($MyInvocation.MyCommand.Name)] Converting Object to Page"
            [ConfluencePS.Page](ConvertTo-Hashtable -InputObject ($object | Select-Object `
                        id,
                    status,
                    title,
                    @{Name = "space"; Expression = {
                            if ($_.space) {
                                ConvertTo-Space $_.space
                            } else { $null }
                        }
                    },
                    @{Name = "version"; Expression = {
                            if ($_.version) {
                                ConvertTo-Version $_.version
                            } else { $null }
                        }
                    },
                    @{Name = "body"; Expression = { $_.body.storage.value } },
                    @{Name = "ancestors"; Expression = {
                            if ($_.ancestors) {
                                ConvertTo-PageAncestor $_.ancestors
                            } else { $null }
                        }
                    },
                    @{Name = "URL"; Expression = {
                            $base = $_._links.base
                            if (!($base)) { $base = $_._links.self -replace '\/rest.*', '' }
                            if ($_._links.webui) {
                                "{0}{1}" -f $base, $_._links.webui
                            } else { $null }
                        }
                    },
                    @{Name = "ShortURL"; Expression = {
                            $base = $_._links.base
                            if (!($base)) { $base = $_._links.self -replace '\/rest.*', '' }
                            if ($_._links.tinyui) {
                                "{0}{1}" -f $base, $_._links.tinyui
                            } else { $null }
                        }
                    }
                ))
        }
    }
}

function ConvertTo-PageAncestor {
    <#
    .SYNOPSIS
    Extracted the conversion to private function in order to have a single place to
    select the properties to use when casting to custom object type
    #>
    [CmdletBinding()]
    [OutputType( [ConfluencePS.Page] )]
    param (
        # object to convert
        [Parameter( Position = 0, ValueFromPipeline = $true )]
        $InputObject
    )

    Process {
        foreach ($object in $InputObject) {
            Write-Verbose "[$($MyInvocation.MyCommand.Name)] Converting Object to Page (Ancestor)"
            [ConfluencePS.Page](ConvertTo-Hashtable -InputObject ($object | Select-Object `
                        id,
                    status,
                    title
                ))
        }
    }
}

function ConvertTo-Space {
    <#
    .SYNOPSIS
    Extracted the conversion to private function in order to have a single place to
    select the properties to use when casting to custom object type
    #>
    [CmdletBinding()]
    [OutputType( [ConfluencePS.Space] )]
    param (
        # object to convert
        [Parameter( Position = 0, ValueFromPipeline = $true )]
        $InputObject
    )

    Process {
        foreach ($object in $InputObject) {
            Write-Verbose "[$($MyInvocation.MyCommand.Name)] Converting Object to Space"
            [ConfluencePS.Space](ConvertTo-Hashtable -InputObject ($object | Select-Object `
                        id,
                    key,
                    name,
                    @{Name = "description"; Expression = { $_.description.plain.value } },
                    @{Name = "Icon"; Expression = {
                            if ($_.icon) {
                                ConvertTo-Icon $_.icon
                            } else { $null }
                        }
                    },
                    type,
                    @{Name = "Homepage"; Expression = {
                            if ($_.homepage -is [PSCustomObject]) {
                                ConvertTo-Page $_.homepage
                            } else { $null } # homepage might be a string
                        }
                    }
                ))
        }
    }
}

function ConvertTo-URLEncoded {
    <#
    .SYNOPSIS
    Encode a string into URL (eg: %20 instead of " ")
    #>
    [CmdletBinding()]
    [OutputType([String])]
    param (
        # String to encode
        [Parameter( Position = 0, Mandatory = $true, ValueFromPipeline = $true )]
        [string]$InputString
    )

    PROCESS {
        Write-Verbose "[$($MyInvocation.MyCommand.Name)] Encoding string to URL"
        [System.Web.HttpUtility]::UrlEncode($InputString)
    }
}

function ConvertTo-User {
    <#
    .SYNOPSIS
    Extracted the conversion to private function in order to have a single place to
    select the properties to use when casting to custom object type
    #>
    [CmdletBinding()]
    [OutputType( [ConfluencePS.User] )]
    param (
        # object to convert
        [Parameter( Position = 0, ValueFromPipeline = $true )]
        $InputObject
    )

    Process {
        foreach ($object in $InputObject) {
            Write-Verbose "[$($MyInvocation.MyCommand.Name)] Converting Object to User"
            [ConfluencePS.User](ConvertTo-Hashtable -InputObject ($object | Select-Object `
                        username,
                    userKey,
                    @{Name = "profilePicture"; Expression = { ConvertTo-Icon $_.profilePicture } },
                    displayname
                ))
        }
    }
}

function ConvertTo-Version {
    <#
    .SYNOPSIS
    Extracted the conversion to private function in order to have a single place to
    select the properties to use when casting to custom object type
    #>
    [CmdletBinding()]
    [OutputType( [ConfluencePS.Version] )]
    param (
        # object to convert
        [Parameter( Position = 0, ValueFromPipeline = $true )]
        $InputObject
    )

    Process {
        foreach ($object in $InputObject) {
            Write-Verbose "[$($MyInvocation.MyCommand.Name)] Converting Object to Version"
            [ConfluencePS.Version](ConvertTo-Hashtable -InputObject ($object | Select-Object `
                    @{Name = "by"; Expression = { ConvertTo-User $_.by } },
                    when,
                    friendlyWhen,
                    number,
                    message,
                    minoredit
                ))
        }
    }
}

function Copy-CommonParameter {
    <#
    .SYNOPSIS
    This is a helper function to assist in creating a hashtable for splatting parameters to inner function calls.

    .DESCRIPTION
    This command copies all of the keys of a hashtable to a new hashtable if the key name matches the DefaultParameter
    or the AdditionalParameter values. This function is designed to help select only function parameters that have been
    set, so they can be passed to inner functions if and only if they have been set.

    .EXAMPLE
    PS C:\> Copy-CommonParameter -InputObject $PSBoundParameters

    Returns a hashtable that contains all of the bound default parameters.

    .EXAMPLE
    PS C:\> Copy-CommonParameter -InputObject $PSBoundParameters -AdditionalParameter "ApiUri"

    Returns a hashtable that contains all of the bound default parameters and the "ApiUri" parameter.
    #>
    [CmdletBinding( SupportsShouldProcess = $false )]
    [OutputType(
        [hashtable]
    )]
    param
    (
        [Parameter(Mandatory = $true)]
        [hashtable]$InputObject,

        [Parameter(Mandatory = $false)]
        [string[]]$AdditionalParameter,

        [Parameter(Mandatory = $false)]
        [string[]]$DefaultParameter = @("Credential", "Certificate")
    )

    [hashtable]$ht = @{}
    foreach ($key in $InputObject.Keys) {
        if ($key -in ($DefaultParameter + $AdditionalParameter)) {
            $ht[$key] = $InputObject[$key]
        }
    }

    return $ht
}

function Invoke-WebRequest {
    # For Version up to 5.1
    [CmdletBinding(HelpUri = 'https://go.microsoft.com/fwlink/?LinkID=217035')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        "PSAvoidUsingConvertToSecureStringWithPlainText",
        "",
        Justification = "Converting received plaintext token to SecureString"
    )]
    param(
        [switch]
        ${UseBasicParsing},

        [Parameter(Mandatory = $true, Position = 0)]
        [ValidateNotNullOrEmpty()]
        [uri]
        ${Uri},

        [Microsoft.PowerShell.Commands.WebRequestSession]
        ${WebSession},

        [Alias('SV')]
        [string]
        ${SessionVariable},

        [pscredential]
        [System.Management.Automation.CredentialAttribute()]
        ${Credential},

        [switch]
        ${UseDefaultCredentials},

        [ValidateNotNullOrEmpty()]
        [string]
        ${CertificateThumbprint},

        [ValidateNotNull()]
        [System.Security.Cryptography.X509Certificates.X509Certificate]
        ${Certificate},

        [string]
        ${UserAgent},

        [switch]
        ${DisableKeepAlive},

        [ValidateRange(0, 2147483647)]
        [uint64]
        ${TimeoutSec},

        [System.Collections.IDictionary]
        ${Headers},

        [ValidateRange(0, 2147483647)]
        [uint64]
        ${MaximumRedirection},

        [Microsoft.PowerShell.Commands.WebRequestMethod]
        ${Method},

        [uri]
        ${Proxy},

        [pscredential]
        [System.Management.Automation.CredentialAttribute()]
        ${ProxyCredential},

        [switch]
        ${ProxyUseDefaultCredentials},

        [Parameter(ValueFromPipeline = $true)]
        [System.Object]
        ${Body},

        [string]
        ${ContentType},

        [ValidateSet('chunked', 'compress', 'deflate', 'gzip', 'identity')]
        [string]
        ${TransferEncoding},

        [string]
        ${InFile},

        [string]
        ${OutFile},

        [switch]
        ${PassThru})

    begin {
        if ($Credential) {
            $SecureCreds = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes(
                    $('{0}:{1}' -f $Credential.UserName, $Credential.GetNetworkCredential().Password)
                ))
            $PSBoundParameters["Headers"]["Authorization"] = "Basic $($SecureCreds)"
            $null = $PSBoundParameters.Remove("Credential")
        }

        if ($InFile) {
            $boundary = [System.Guid]::NewGuid().ToString()
            $enc = [System.Text.Encoding]::GetEncoding("iso-8859-1")
            $fileName = Split-Path -Path $InFile -Leaf
            $readFile = Get-Content -Path $InFile -Encoding Byte
            $fileEnc = $enc.GetString($readFile)
            $PSBoundParameters["Body"] = @'
--{0}
Content-Disposition: form-data; name="file"; filename="{1}"
Content-Type: application/octet-stream

{2}
--{0}--

'@ -f $boundary, $fileName, $fileEnc

            $PSBoundParameters["Headers"]['X-Atlassian-Token'] = 'nocheck'
            $PSBoundParameters["ContentType"] = "multipart/form-data; boundary=`"$boundary`""
            $null = $PSBoundParameters.Remove("InFile")
        }

        try {
            $outBuffer = $null
            if ($PSBoundParameters.TryGetValue('OutBuffer', [ref]$outBuffer)) {
                $PSBoundParameters['OutBuffer'] = 1
            }
            $wrappedCmd = $ExecutionContext.InvokeCommand.GetCommand('Microsoft.PowerShell.Utility\Invoke-WebRequest', [System.Management.Automation.CommandTypes]::Cmdlet)
            $scriptCmd = { & $wrappedCmd @PSBoundParameters }
            $steppablePipeline = $scriptCmd.GetSteppablePipeline($myInvocation.CommandOrigin)
            $steppablePipeline.Begin($PSCmdlet)
        } catch {
            throw
        }
    }

    process {
        try {
            $steppablePipeline.Process($_)
        } catch {
            throw
        }
    }

    end {
        try {
            $steppablePipeline.End()
        } catch {
            throw
        }
    }
    <#

    .ForwardHelpTargetName Microsoft.PowerShell.Utility\Invoke-WebRequest
    .ForwardHelpCategory Cmdlet

    #>
}

if ($PSVersionTable.PSVersion.Major -ge 6) {
    function Invoke-WebRequest {
        #require -Version 6
        [CmdletBinding(DefaultParameterSetName = 'StandardMethod', HelpUri = 'https://go.microsoft.com/fwlink/?LinkID=217035')]
        param(
            [switch]
            ${UseBasicParsing},

            [Parameter(Mandatory = $true, Position = 0)]
            [ValidateNotNullOrEmpty()]
            [uri]
            ${Uri},

            [Microsoft.PowerShell.Commands.WebRequestSession]
            ${WebSession},

            [Alias('SV')]
            [string]
            ${SessionVariable},

            [switch]
            ${AllowUnencryptedAuthentication},

            [Microsoft.PowerShell.Commands.WebAuthenticationType]
            ${Authentication},

            [pscredential]
            [System.Management.Automation.CredentialAttribute()]
            ${Credential},

            [switch]
            ${UseDefaultCredentials},

            [ValidateNotNullOrEmpty()]
            [string]
            ${CertificateThumbprint},

            [ValidateNotNull()]
            [X509Certificate]
            ${Certificate},

            [switch]
            ${SkipCertificateCheck},

            [Microsoft.PowerShell.Commands.WebSslProtocol]
            ${SslProtocol},

            [securestring]
            ${Token},

            [string]
            ${UserAgent},

            [switch]
            ${DisableKeepAlive},

            [ValidateRange(0, 2147483647)]
            [uint64]
            ${TimeoutSec},

            [System.Collections.IDictionary]
            ${Headers},

            [ValidateRange(0, 2147483647)]
            [uint64]
            ${MaximumRedirection},

            [Parameter(ParameterSetName = 'StandardMethod')]
            [Parameter(ParameterSetName = 'StandardMethodNoProxy')]
            [Microsoft.PowerShell.Commands.WebRequestMethod]
            ${Method},

            [Parameter(ParameterSetName = 'CustomMethod', Mandatory = $true)]
            [Parameter(ParameterSetName = 'CustomMethodNoProxy', Mandatory = $true)]
            [Alias('CM')]
            [ValidateNotNullOrEmpty()]
            [string]
            ${CustomMethod},

            [Parameter(ParameterSetName = 'CustomMethodNoProxy', Mandatory = $true)]
            [Parameter(ParameterSetName = 'StandardMethodNoProxy', Mandatory = $true)]
            [switch]
            ${NoProxy},

            [Parameter(ParameterSetName = 'StandardMethod')]
            [Parameter(ParameterSetName = 'CustomMethod')]
            [uri]
            ${Proxy},

            [Parameter(ParameterSetName = 'StandardMethod')]
            [Parameter(ParameterSetName = 'CustomMethod')]
            [pscredential]
            [System.Management.Automation.CredentialAttribute()]
            ${ProxyCredential},

            [Parameter(ParameterSetName = 'StandardMethod')]
            [Parameter(ParameterSetName = 'CustomMethod')]
            [switch]
            ${ProxyUseDefaultCredentials},

            [Parameter(ValueFromPipeline = $true)]
            [System.Object]
            ${Body},

            [string]
            ${ContentType},

            [ValidateSet('chunked', 'compress', 'deflate', 'gzip', 'identity')]
            [string]
            ${TransferEncoding},

            [string]
            ${InFile},

            [string]
            ${OutFile},

            [switch]
            ${PassThru},

            [switch]
            ${PreserveAuthorizationOnRedirect},

            [switch]
            ${SkipHeaderValidation})

        begin {
            if ($Credential -and (-not ($Authentication))) {
                $PSBoundParameters["Authentication"] = "Basic"
            }
            if ($InFile) {
                $multipartContent = [System.Net.Http.MultipartFormDataContent]::new()
                $FileStream = [System.IO.FileStream]::new($InFile, [System.IO.FileMode]::Open)
                $fileHeader = [System.Net.Http.Headers.ContentDispositionHeaderValue]::new("form-data")
                $fileHeader.Name = "file"
                $fileHeader.FileName = ([System.io.FileInfo]$InFile).name
                $fileContent = [System.Net.Http.StreamContent]::new($FileStream)
                $fileContent.Headers.ContentDisposition = $fileHeader
                $fileContent.Headers.ContentType = [System.Net.Http.Headers.MediaTypeHeaderValue]::Parse("application/octet-stream")
                $multipartContent.Add($fileContent)
                $PSBoundParameters["Headers"]['X-Atlassian-Token'] = 'nocheck'
                $PSBoundParameters["Body"] = $multipartContent
                $null = $PSBoundParameters.Remove("InFile")
            }
            try {
                $outBuffer = $null
                if ($PSBoundParameters.TryGetValue('OutBuffer', [ref]$outBuffer)) {
                    $PSBoundParameters['OutBuffer'] = 1
                }
                $wrappedCmd = $ExecutionContext.InvokeCommand.GetCommand('Microsoft.PowerShell.Utility\Invoke-WebRequest', [System.Management.Automation.CommandTypes]::Cmdlet)
                $scriptCmd = { & $wrappedCmd @PSBoundParameters }
                $steppablePipeline = $scriptCmd.GetSteppablePipeline($myInvocation.CommandOrigin)
                $steppablePipeline.Begin($PSCmdlet)
            } catch {
                throw
            }
        }

        process {
            try {
                $steppablePipeline.Process($_)
            } catch {
                throw
            }
        }

        end {
            try {
                $steppablePipeline.End()
            } catch {
                throw
            }
        }
        <#

    .ForwardHelpTargetName Microsoft.PowerShell.Utility\Invoke-WebRequest
    .ForwardHelpCategory Cmdlet

    #>
    }
}

function Remove-InvalidFileCharacter {
    <#
    .SYNOPSIS
        Replace any invalid filename characters from a string with underscores
    #>
    [CmdletBinding(
        ConfirmImpact = 'Low',
        SupportsShouldProcess = $false
    )]
    [OutputType( [String] )]
    [System.Diagnostics.CodeAnalysis.SuppressMessage('PSUseShouldProcessForStateChangingFunctions', '')]
    param (
        # string to process
        [Parameter( ValueFromPipeline = $true )]
        [String]$InputString
    )

    BEGIN {
        Write-Verbose "[$($MyInvocation.MyCommand.Name)] Function started"
        $InvalidChars = [IO.Path]::GetInvalidFileNameChars() -join ''
        $RegExInvalid = "[{0}]" -f [RegEx]::Escape($InvalidChars)
    }
    Process {
        foreach ($_string in $InputString) {
            Write-Verbose "[$($MyInvocation.MyCommand.Name)] Removing invalid characters"
            $_string -replace $RegExInvalid, '_'
        }
    }
}

function Set-TlsLevel {
    [CmdletBinding( SupportsShouldProcess = $false )]
    [System.Diagnostics.CodeAnalysis.SuppressMessage('PSUseShouldProcessForStateChangingFunctions', '')]
    param (
        [Parameter(Mandatory, ParameterSetName = 'Set')]
        [Switch]$Tls12,

        [Parameter(Mandatory, ParameterSetName = 'Revert')]
        [Switch]$Revert
    )

    begin {
        switch ($PSCmdlet.ParameterSetName) {
            "Set" {
                $Script:OriginalTlsSettings = [Net.ServicePointManager]::SecurityProtocol

                [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
            }
            "Revert" {
                if ($Script:OriginalTlsSettings) {
                    [Net.ServicePointManager]::SecurityProtocol = $Script:OriginalTlsSettings
                }
            }
        }
    }
}

function Test-Captcha {
    [CmdletBinding()]
    param(
        # Response of Invoke-WebRequest
        [Parameter(
            ValueFromPipeline = $true
        )]
        [PSObject]$InputObject
    )

    begin {
        $tokenRequiresCaptcha = "AUTHENTICATION_DENIED"
        $headerRequiresCaptcha = "X-Seraph-LoginReason"
    }

    process {
        if ($InputObject.Headers -and $InputObject.Headers[$headerRequiresCaptcha]) {
            if ( ($InputObject.Headers[$headerRequiresCaptcha] -split ",") -contains $tokenRequiresCaptcha ) {
                Write-Warning "Confluence requires you to log on to the website before continuing for security reasons."
            }
        }
    }

    end {
    }
}

function Write-DebugMessage {
    [CmdletBinding()]
    param(
        [Parameter(
            ValueFromPipeline = $true
        )]
        $Message
    )

    begin {
        $oldDebugPreference = $DebugPreference
        if (!($DebugPreference -eq "SilentlyContinue")) {
            $DebugPreference = 'Continue'
        }
    }

    process {
        Write-Debug $Message
    }

    end {
        $DebugPreference = $oldDebugPreference
    }
}
