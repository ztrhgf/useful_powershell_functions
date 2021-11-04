function ConvertFrom-XML {
    <#
    .SYNOPSIS
    Function for converting XML object (XmlNode) to PSObject.

    .DESCRIPTION
    Function for converting XML object (XmlNode) to PSObject.

    .PARAMETER node
    XmlNode object (retrieved like: [xml]$xmlObject = (Get-Content C:\temp\file.xml -Raw))

    .EXAMPLE
    [xml]$xmlObject = (Get-Content C:\temp\file.xml -Raw)
    ConvertFrom-XML $xmlObject

    .NOTES
    Based on https://stackoverflow.com/questions/3242995/convert-xml-to-psobject
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true, ValueFromPipeline)]
        [System.Xml.XmlNode] $node
    )

    #region helper functions

    function ConvertTo-PsCustomObjectFromHashtable {
        param (
            [Parameter(
                Position = 0,
                Mandatory = $true,
                ValueFromPipeline = $true,
                ValueFromPipelineByPropertyName = $true
            )] [object[]]$hashtable
        );

        begin { $i = 0; }

        process {
            foreach ($myHashtable in $hashtable) {
                if ($myHashtable.GetType().Name -eq 'hashtable') {
                    $output = New-Object -TypeName PsObject;
                    Add-Member -InputObject $output -MemberType ScriptMethod -Name AddNote -Value {
                        Add-Member -InputObject $this -MemberType NoteProperty -Name $args[0] -Value $args[1];
                    };
                    $myHashtable.Keys | Sort-Object | % {
                        $output.AddNote($_, $myHashtable.$_);
                    }
                    $output
                } else {
                    Write-Warning "Index $i is not of type [hashtable]";
                }
                $i += 1;
            }
        }
    }
    #endregion helper functions

    $hash = @{}

    foreach ($attribute in $node.attributes) {
        $hash.$($attribute.name) = $attribute.Value
    }

    $childNodesList = ($node.childnodes | ? { $_ -ne $null }).LocalName

    foreach ($childnode in ($node.childnodes | ? { $_ -ne $null })) {
        if (($childNodesList.where( { $_ -eq $childnode.LocalName })).count -gt 1) {
            if (!($hash.$($childnode.LocalName))) {
                Write-Verbose "ChildNode '$($childnode.LocalName)' isn't in hash. Creating empty array and storing in hash.$($childnode.LocalName)"
                $hash.$($childnode.LocalName) += @()
            }
            if ($childnode.'#text') {
                Write-Verbose "Into hash.$($childnode.LocalName) adding '$($childnode.'#text')'"
                $hash.$($childnode.LocalName) += $childnode.'#text'
            } else {
                Write-Verbose "Into hash.$($childnode.LocalName) adding result of ConvertFrom-XML called upon '$($childnode.Name)' node object"
                $hash.$($childnode.LocalName) += ConvertFrom-XML($childnode)
            }
        } else {
            Write-Verbose "In ChildNode list ($($childNodesList -join ', ')) is only one node '$($childnode.LocalName)'"

            if ($childnode.'#text') {
                Write-Verbose "Into hash.$($childnode.LocalName) set '$($childnode.'#text')'"
                $hash.$($childnode.LocalName) = $childnode.'#text'
            } else {
                Write-Verbose "Into hash.$($childnode.LocalName) set result of ConvertFrom-XML called upon '$($childnode.Name)' $($childnode.Value) object"
                $hash.$($childnode.LocalName) = ConvertFrom-XML($childnode)
            }
        }
    }

    Write-Verbose "Returning hash ($($hash.Values -join ', '))"
    return $hash | ConvertTo-PsCustomObjectFromHashtable
}