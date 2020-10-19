# Functions for emulating OneDrive native client

# Gets the ID of default document library
# Nov 26th 2019
function Get-ODDefaultDocLibId
{
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$True)]
        $OneDriveSettings
    )
    Process
    {
        $command+="/_api/web/DefaultDocumentLibrary/ID"
        
        $response = Invoke-ODCommand -Command $command -OneDriveSettings $OneDriveSettings

        # Return
        $response.D.id

    }
}


# Gets the Site ID of user's OneDrive
# Nov 26th 2019
function Get-ODDefaultSiteId
{
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$True)]
        $OneDriveSettings
    )
    Process
    {
        $command+="/_api/Site/Id"

        $response = Invoke-ODCommand -Command $command -OneDriveSettings $OneDriveSettings

        # Return
        $response.d.id

    }
}

# Gets the user's OneDrive sync policy
# Nov 26th 2019
function Get-ODSyncPolicy
{
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$True)]
        $OneDriveSettings
    )
    Process
    {
        $command+="/_api/SPFileSync/sync/$($OneDriveSettings.DefaultDocumentLibraryId)/policy/"

        $response = Invoke-ODCommand -Command $command -OneDriveSettings $OneDriveSettings -Accept "Application/xml"

        # Return
        $rules=$response.PolicyDocument.Rule

        $attributes = @{}
        foreach($rule in $rules)
        {
            $attributes[$rule.name] = $rule.value
        }

        $policy = New-Object PSObject -Property $attributes

        # return
        $policy
    }
}

# Gets the list of user's OneDrive sync files
# Nov 26th 2019
function Get-ODSyncFiles
{
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$True)]
        $OneDriveSettings,
        [Parameter(Mandatory=$False)]
        [ValidateRange(1,1000)]
        [int]$MaxItems=1000,
        [Parameter(Mandatory=$False)]
        [guid]$DomainGuid,
        [Parameter(Mandatory=$False)]
        [boolean]$Mac=$false,
        [Parameter(Mandatory=$False)]
        [guid]$MachineGuid
    )
    Process
    {
        # Set the special headers
        $headers=@{"X-MachineId" = "$($MachineGuid.toString())"}

        if(!$MAC)
        {
            $headers["X-MachineDomainInfo"] = "{$($DomainGuid.toString())}"
        }

        # Paging..
        $syncToken = $null
        $continue = $true

        # Return value
        $retVal = @()

        while($continue)
        {
            $command="/_api/SPFileSync/sync/$($OneDriveSettings.DefaultDocumentLibraryId)/RootFolder?Filter=changes&InlineBlobs=false&MaxItemCount=$MaxItems&View=SkyDriveSync"
            if(![string]::IsNullOrEmpty($syncToken))
            {
                $command += "&SyncToken=$syncToken"
            }

            # We need the response headers to know whether we've done or is there more data to get
            $responseHeaders = @{}

            # Get the response using StreamReader, otherwise the response is not properly decoded (using ISO-8859-1 instead of UTF-8)
            $response = Invoke-ODCommand -Command $command -OneDriveSettings $OneDriveSettings -Accept "Application/xml" -headers $headers -UseStreamReader -ResponseHeaders ([ref]$responseHeaders) -Mac $Mac

            if($response -eq $null -or [String]::IsNullOrEmpty($responseHeaders["Value"]["X-HasMoreData"]) -or $responseHeaders["Value"]["X-HasMoreData"] -ne "True")
            {
                $continue = $false
            }
            else
            {
                $syncToken = $responseHeaders["Value"]["X-SyncToken"]
            }
            
            # Add to return array
            [xml]$xmlResponse = $response
            $retVal += $xmlResponse
            
        }
        
        # Return
        $retVal
    }
}


# Downloads the user's OneDrive files
# Nov 26th 2019
function Get-OneDriveFiles
{
    <#
        .SYNOPSIS
        Downloads user's OneDrive 

        .DESCRIPTION
        Downloads the user's OneDrive root folder and files recursively

        .Parameter OneDriveSettings
        OneDrive settings of the user

        .Parameter PrintOnly
        Doesn't download the files

        .Parameter FoldersOnly
        Doesn't handle files but only folders

        .Parameter Mac
        Pretend to be a macOS client
    
        .Example
        $os = New-AADIntOneDriveSettings
        Get-AADIntOneDriveFiles -OneDriveSettings $os | Format-Table

        Path                              Size  Created            Modified           ResourceID                   
        ----                              ----  -------            --------           ----------                   
        \RootFolder\Document1.docx        11032 2.12.2019 20.47.23 2.12.2019 20.48.46 5e7acf393a2e45f18c1ce6caa7...
        \RootFolder\Book.xlsx             8388  2.12.2019 20.49.14 2.12.2019 20.50.14 b26c0a38d4d14b23b785576e29...
        \RootFolder\Docs\Document1.docx   84567 9.12.2019 11.24.40 9.12.2019 12.17.50 d9d51e47b66c4805aff3a08763...
        \RootFolder\Docs\Document2.docx   31145 7.12.2019 17.28.37 7.12.2019 17.28.37 972f9c317e1e468fb2b6080ac2...

        .Example
        $os = New-AADIntOneDriveSettings
        Get-AADIntOneDriveFiles -OneDriveSettings $os -PrintOnly | Format-Table

        Path                              Size  Created            Modified           ResourceID                   
        ----                              ----  -------            --------           ----------                   
        \RootFolder\Document1.docx        11032 2.12.2019 20.47.23 2.12.2019 20.48.46 5e7acf393a2e45f18c1ce6caa7...
        \RootFolder\Book.xlsx             8388  2.12.2019 20.49.14 2.12.2019 20.50.14 b26c0a38d4d14b23b785576e29...
        \RootFolder\Docs\Document1.docx   84567 9.12.2019 11.24.40 9.12.2019 12.17.50 d9d51e47b66c4805aff3a08763...
        \RootFolder\Docs\Document2.docx   31145 7.12.2019 17.28.37 7.12.2019 17.28.37 972f9c317e1e468fb2b6080ac2...

        .Example
        $os = New-AADIntOneDriveSettings
        Get-AADIntOneDriveFiles -OneDriveSettings $os -DomainGuid "ff909322-6b19-4a86-b9e9-e01ebb9432fe" | Format-Table

        Path                              Size  Created            Modified           ResourceID                   
        ----                              ----  -------            --------           ----------                   
        \RootFolder\Document1.docx        11032 2.12.2019 20.47.23 2.12.2019 20.48.46 5e7acf393a2e45f18c1ce6caa7...
        \RootFolder\Book.xlsx             8388  2.12.2019 20.49.14 2.12.2019 20.50.14 b26c0a38d4d14b23b785576e29...
        \RootFolder\Docs\Document1.docx   84567 9.12.2019 11.24.40 9.12.2019 12.17.50 d9d51e47b66c4805aff3a08763...
        \RootFolder\Docs\Document2.docx   31145 7.12.2019 17.28.37 7.12.2019 17.28.37 972f9c317e1e468fb2b6080ac2...
    #>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$True)]
        $OneDriveSettings,
        [Parameter(Mandatory=$False)]
        [int]$MaxItems=500,
        [Parameter(Mandatory=$False)]
        [guid]$DomainGuid = (New-Guid),
        [switch]$Mac,
        [switch]$PrintOnly,
        [switch]$FoldersOnly
    )
    Process
    {
        # Get the list of sync files
        $allSyncFiles = Get-ODSyncFiles -OneDriveSettings $OneDriveSettings -MaxItems $MaxItems -DomainGuid $DomainGuid -MachineGuid (New-Guid) -Mac $Mac
        foreach($syncFiles in $allSyncFiles)
        {
            # Dowload the OneDrive root folder
            Get-ODFolder -OneDriveSettings $OneDriveSettings -Folder $syncFiles.Folder -PrintOnly $PrintOnly -FoldersOnly $FoldersOnly
        }
    }
}

# Downloads the user's OneDrive files
# Dec 9th 2019
function Send-OneDriveFile
{
    <#
        .SYNOPSIS
        Sends a file to user's OneDrive 

        .DESCRIPTION
        Sends a file to user's OneDrive

        .Parameter OneDriveSettings
        OneDrive settings of the user

        .Parameter FileName
        File name of the file to be sent OneDrive

        .Parameter ETag
        Contains Resource ID and version information of the file. If provided, tries to update the file

        .Parameter FolderId
        Contains Resource ID of folder where file will be uploaded.

        .Parameter DomainGuid
        Guid of the domain of user's computer.

        .Parameter Mac
        Pretend to be a macOS client
    
        .Example
        $os = New-AADIntOneDriveSettings
        Send-AADIntOneDriveFile -FileName "Document1.docx" -OneDriveSettings $os -FolderId 3936bbea74b54f52b4c0ec6f362d6df9rea

        ResourceID                            : 68c71b7f4be8414b9752266ef4d715b3
        ETag                                  : "{68C71B7F-4BE8-414B-9752-266EF4D715B3},2"
        DateModified                          : 2019-12-09T10:57:36.0000000Z
        RelationshipName                      : Document1.docx
        ParentResourceID                      : 3936bbea74b54f52b4c0ec6f362d6df9
        fsshttpstate.xschema.storage.live.com : fsshttpstate.xschema.storage.live.com
        DocumentStreams                       : DocumentStreams
        WriteStatus                           : Success

        .Example
        $os = New-AADIntOneDriveSettings
        Send-AADIntOneDriveFile -FileName "Document1.docx" -OneDriveSettings $os -ETag "{68c71b7f-4be8-414b-9752-266ef4d715b3},2" -FolderId 3936bbea74b54f52b4c0ec6f362d6df9

        ResourceID                            : 68c71b7f4be8414b9752266ef4d715b3
        ETag                                  : "{68C71B7F-4BE8-414B-9752-266EF4D715B3},3"
        DateModified                          : 2019-12-09T10:57:36.0000000Z
        RelationshipName                      : Document1.docx
        ParentResourceID                      : 3936bbea74b54f52b4c0ec6f362d6df9
        fsshttpstate.xschema.storage.live.com : fsshttpstate.xschema.storage.live.com
        DocumentStreams                       : DocumentStreams
        WriteStatus                           : Success
    #>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [String]$FileName,
        [Parameter(Mandatory=$True)]
        $OneDriveSettings,
        [Parameter(Mandatory=$True)]
        [String]$FolderId,
        [Parameter(Mandatory=$False)]
        [guid]$DomainGuid=(New-Guid),
        [Parameter(Mandatory=$False)]
        [switch]$Mac,
        [Parameter(Mandatory=$False)]
        [String]$ETag
    )
    Process
    {
        # Check that the file exists..
        if(!(Test-Path $FileName))
        {
            Write-Error "The file $FileName does not exist!"
            return 
        }
        
        # Get the file and information
        $file = Get-Item $FileName
        [byte[]]$fileBytes=Get-Content $FileName -Encoding byte
        $created=$file.CreationTimeUtc.toString("yyyy-MM-ddTHH:mm:ss.0000000Z").Replace(".",":")
        $modified=$file.LastWriteTimeUtc.toString("yyyy-MM-ddTHH:mm:ss.0000000Z").Replace(".",":")

        # Create hash and IDs
        $hash = Get-XorHash $FileName
        $multipartUUID = (New-Guid).ToString()
        $fileUUID = (New-Guid).ToString()
        $parentId = $OneDriveSettings.DefaultDocumentLibraryId

        $command+="/_api/SPFileSync/sync/$($parentId.Replace('-',''))/RootFolder?View=SkyDriveSync"

        # Set the write mode
        $WriteMode="Create"
        if(![string]::IsNullOrEmpty($ETag))
        {
            $resourceId=($ETag.Substring(1,($ETag.LastIndexOf("}")-1))).Replace("-","")
            $etagXml = "<ResourceID>$resourceId</ResourceID><ETag>`"$ETag`"</ETag>"
            $WriteMode="Update"
        }

        $bodyStart=@"
--uuid:$multipartUUID
Content-ID: <LiveFolders>
Content-Type: application/web3s+xml

<?xml version="1.0" encoding="utf-8"?><Items><Document><ParentResourceID>$($FolderId.Replace('-',''))</ParentResourceID><WriteMode>$WriteMode</WriteMode>$etagXml<RelationshipName>$($file.Name)</RelationshipName><DateCreatedOnClient>$created</DateCreatedOnClient><DateModifiedOnClient>$modified</DateModifiedOnClient><DocumentStreams><DocumentStream><DocumentStreamName>Default</DocumentStreamName><MimeType>application/octet-stream</MimeType><XORHash>$hash</XORHash><FragmentSessionId>$fileUUID</FragmentSessionId><DataSize>$($fileBytes.Length)</DataSize></DocumentStream></DocumentStreams></Document></Items>

--uuid:$multipartUUID
Content-Transfer-Encoding: binary
Content-Type: application/octet-stream
Content-ID:<"$fileUUID":Default>


"@
        $bodyEnd = @"

--uuid:$multipartUUID--

"@

        $body=@()
        $body+=[System.Text.Encoding]::ASCII.GetBytes($bodyStart)
        $body+=$fileBytes
        $body+=[System.Text.Encoding]::ASCII.GetBytes($bodyEnd)


        $headers=@{
            "Scenario" = "StorageInlineUploadsScenario"
            "Content-Type" = "multipart/related; boundary=`"uuid:$multipartUUID`""
            "Application" = "OneDriveSync"
            #"X-TransactionId" = "$((New-Guid).ToString())StorageInlineUploadsScenario"
            "X-RestrictedWriteCapabilities" = "Irm, LabelIrm"
            "X-SyncFeatures" = "40"
            "X-SynchronousMetadata" = "false"
            "X-UpdateGroupId" = "60"
            "X-UpdateRing" = "Prod"
            #"X-SubscriptionIdToNotNotify" = (New-Guid).ToString()
            #"X-MachineDomainInfo" = "{$($DomainGuid.toString())}"
            #"X-MachineId" = "$((New-Guid).toString())"
            #"X-RequestStats" ="btuc=6;did=$((New-Guid).toString());ftuc=1"
            "X-CustomIdentity" = "SkyDriveSync=$((New-Guid).toString())"
            "X-GeoMoveOptions" = "HttpRedirection"
        }

        if(!$MAC)
        {
            $headers["X-MachineDomainInfo"] = "{$($DomainGuid.toString())}"
        }

        $responseHeaders = @{}

        # First get the X-RequestDigest
        Invoke-ODCommand -OneDriveSettings $OneDriveSettings -Command $command -Body ([byte[]]$body) -Scenario "" -UseStreamReader -ResponseHeaders ([ref]$responseHeaders) -headers $headers -Accept "Application/Web3s+xml" -Mac $Mac
        if(![String]::IsNullOrEmpty($responseHeaders["Value"]["X-RequestDigest"]))
        {
            $headers+=@{
                "X-RequestDigest" = $responseHeaders["Value"]["X-RequestDigest"]
            }
            # The try to send again
            [xml]$response = Invoke-ODCommand -OneDriveSettings $OneDriveSettings -Command $command -Body ([byte[]]$body) -Scenario "" -UseStreamReader -headers $headers -Accept "Application/Web3s+xml" -Mac $Mac
        }

        # Return
        $response.Items.Document
    }
}

# Downloads a folder from user's OneDrive
# Nov 26th
function Get-ODFolder
{
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$True)]
        $OneDriveSettings,
        [Parameter(Mandatory=$True)]
        $Folder,
        [Parameter(Mandatory=$False)]
        [bool]$PrintOnly,
        [Parameter(Mandatory=$False)]
        [bool]$FoldersOnly
    )
    Process
    {
        if(!$PrintOnly)
        {
            Write-Verbose "Folder: $($Folder.Path)"
            New-Item -ItemType Directory -Path ".$($Folder.Path)" -Force | Out-Null
        }

        # Set the attributes
        $attributes=[ordered]@{
            "Path" = $Folder.Path.replace("/","\")
            "Size" = ""
            "ETag" = ""
            "Created" = [DateTime]$Folder.DateCreated
            "Modified" = [DateTime]$Folder.DateModified
            "ResourceID" = $Folder.ResourceID
            "MimeType" = ""
            "Url" = ""
            "XORHash" = ""
        }
        $FolderFile = New-Object PSObject -Property $attributes

        $FolderFile
        
        if(!$FoldersOnly)
        {
            # Download the files
            foreach($document in $Folder.Items.Document)
            {
                Get-ODDocument -OneDriveSettings $OneDriveSettings -Document $document -PrintOnly $PrintOnly
            }
        }

        # Download the folders
        foreach($subFolder in $Folder.Items.Folder)
        {
            Get-ODFolder -OneDriveSettings $OneDriveSettings -Folder $subFolder -PrintOnly $PrintOnly
        }
        
    }
}

# Downloads a file from user's OneDrive
# Nov 26th
function Get-ODDocument
{
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$True)]
        $OneDriveSettings,
        [Parameter(Mandatory=$True)]
        $Document,
        [Parameter(Mandatory=$False)]
        [bool]$PrintOnly
    )
    Process
    {
        
        # Set the attributes
        $attributes=[ordered]@{
            "Path" = $Document.Path.replace("/","\")
            "Size" = $Document.DocumentStreams.DocumentStream.DataSize
            "ETag" = $Document.ETag
            "Created" = [DateTime]$Document.DateCreated
            "Modified" = [DateTime]$Document.DateModified
            "ResourceID" = $Document.ResourceID
            "MimeType" = $Document.DocumentStreams.DocumentStream.MimeType
            "Url" = $Document.DocumentStreams.DocumentStream.PreAuthURL
            "XORHash" = $Document.DocumentStreams.DocumentStream.XORHash
        }
        $DocFile = New-Object PSObject -Property $attributes

        if(!$PrintOnly)
        {
            # Create a web session for the authentication cookie
            $session = New-Object Microsoft.PowerShell.Commands.WebRequestSession
            $webCookie = New-Object System.Net.Cookie
            $webCookie.Name = ($OneDriveSettings.AuthenticationCookie.Split("="))[0]
            $webCookie.Value = $OneDriveSettings.AuthenticationCookie.Substring($webCookie.Name.Length + 1)
            $webCookie.Domain = ($OneDriveSettings.Url.Split("/"))[2]
            $session.Cookies.Add($webCookie)

            # Download the file
            Invoke-WebRequest -Method Get -Uri $DocFile.Url -OutFile ".$($DocFile.Path)" -WebSession $session

            # Set the date attributes
            $FileItem = Get-Item ".$($DocFile.Path)"
            $FileItem.CreationTime=$DocFile.Created
            $FileItem.LastWriteTime=$DocFile.Modified
            
        }
        return $DocFile
    }
}