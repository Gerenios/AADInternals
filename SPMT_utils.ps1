# This file contains utility functions to implement protocol used by
# SharePoint Migration Tool (SPMT) and Migration Manager agent

# Calculates SPO SPMT Guid for the given file
# Ref: Microsoft.SharePoint.Migration.Common.GuidGenerator
# Nov 23rd 2022
Function Get-SPMTFileGuid
{
    [cmdletbinding()]

    param(
        [parameter(Mandatory=$true,ValueFromPipeline)]
        [String]$FilePath
    )
    Process
    {
        # Byte order swapping function
        function Swap-ByteOrder
        {
            [cmdletbinding()]

            param(
                [parameter(Mandatory=$true,ValueFromPipeline)]
                [byte[]]$Guid
            )
            Process
            {
                $Guid = Swap-Bytes -Guid $Guid -Left 0 -Right 3
                $Guid = Swap-Bytes -Guid $Guid -Left 1 -Right 2
                $Guid = Swap-Bytes -Guid $Guid -Left 4 -Right 5
                $Guid = Swap-Bytes -Guid $Guid -Left 6 -Right 7
                return $Guid
            }
        }

        # Byte swapping function
        function Swap-Bytes
        {
            [cmdletbinding()]

            param(
                [parameter(Mandatory=$true,ValueFromPipeline)]
                [byte[]]$Guid,
                [parameter(Mandatory=$true)]
                [int]$Left = 0,
                [parameter(Mandatory=$true)]
                [int]$Right = 0
            )
            Process
            {
                $b = $Guid[$Left]
                $Guid[$Left] = $Guid[$Right]
                $Guid[$Right] = $b
                return $Guid
            }
        }

        $bytes = [text.encoding]::UTF8.GetBytes($FilePath)

        $nameSpaceId = [byte[]](Swap-ByteOrder -Guid ([guid]"6ba7b811-9dad-11d1-80b4-00c04fd430c8").ToByteArray())
        
        $alg = 0x05 # SHA1
       
        $sha1 = [System.Security.Cryptography.SHA1]::Create()
        $sha1.TransformBlock($nameSpaceId, 0, $nameSpaceId.Length, $null, 0) | Out-Null
        $sha1.TransformFinalBlock($bytes, 0, $bytes.Length) | Out-Null
        $hash = $sha1.Hash

        $retVal = New-Object byte[] 16
        [Array]::Copy($hash,$retVal,16)

        $retVal[6] = $retVal[6] -band 15 -bor ($alg -shl 4)
        $retVal[8] = $retVal[8] -band 63 -bor 128

        return [guid][byte[]](Swap-ByteOrder -Guid $retVal)
    }
}

# Encrypt the given content for migration
# Nov 23rd 2022
function Encrypt-SPMTFile
{
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [byte[]]$Key,
        [Parameter(ParameterSetName='String',Mandatory=$True)]
        [string]$StringContent,
        [Parameter(ParameterSetName='Binary',Mandatory=$True)]
        [byte[]]$BinaryContent,
        [Parameter(ParameterSetName='File',Mandatory=$True)]
        [string]$FilePath
    )
    Process
    {
        # Create encryptor and use the given key
        $aes = [System.Security.Cryptography.AesCryptoServiceProvider]::new()
        $aes.Key = $key
        $encryptor = $aes.CreateEncryptor()
        $iv = Convert-ByteArrayToB64 -Bytes $aes.IV

        if(![string]::IsNullOrEmpty($StringContent))
        {
            Write-Verbose $StringContent
            $BinaryContent = [text.encoding]::UTF8.GetBytes($StringContent)
        }
        
        # Encrypt content
        if(![string]::IsNullOrEmpty($FilePath))
        {
            # Open the file
            $infs = [System.IO.FileStream]::new($filePath,[System.IO.FileMode]::Open,[System.IO.FileAccess]::Read)

            # Create a temporary file
            $tempFile = (New-TemporaryFile).FullName
            $outfs = [System.IO.FileStream]::new($tempFile,[System.IO.FileMode]::OpenOrCreate,[System.IO.FileAccess]::Write)

            # Read and encrypt the file in 1kb chunks
            $cs = [System.Security.Cryptography.CryptoStream]::new($outfs,$encryptor,[System.Security.Cryptography.CryptoStreamMode]::Write)
            $buffer = New-Object byte[] 1024
            while($infs.Position -lt $infs.Length)
            {
                $read = $infs.Read($buffer,0,1024)
                $cs.Write($buffer,0,$read)
            }
            $cs.FlushFinalBlock()

            # Clean up
            $infs.Close()
            $infs.Dispose()
            $outfs.Close()
            $outfs.Dispose()
            $cs.Close()
            $cs.Dispose()
            $aes.Dispose()

            # Calculate MD5
            $md5 = Convert-ByteArrayToB64 (Convert-HexToByteArray (Get-FileHash -Path $tempFile -Algorithm MD5).Hash)
        }
        else
        {
            # Encrypt in memory
            $ms = [System.IO.MemoryStream]::new()
            $cs = [System.Security.Cryptography.CryptoStream]::new($ms,$encryptor,[System.Security.Cryptography.CryptoStreamMode]::Write)
            $cs.Write($BinaryContent,0,$BinaryContent.Count)
            $cs.FlushFinalBlock()
            $encData = $ms.ToArray()

            # Clean up
            $cs.Close()
            $cs.Dispose()
            $ms.Close()
            $ms.Dispose()
            $aes.Dispose()

            # Calculate MD5
            $md5hash = [System.Security.Cryptography.MD5]::Create()
            $md5 = Convert-ByteArrayToB64 -Bytes $md5hash.ComputeHash($encData)
            $md5hash.Dispose()
        }
          
        # Return
        return [PSCustomObject]@{
            "Data"     = $encData
            "IV"       = $iv
            "MD5"      = $MD5
            "DataFile" = $tempFile
        }
    }
}

# Generate metadatafiles for migration
# Nov 24th 2022
function Generate-SPMTMetadata
{
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [PSObject]$ContainerInfo,
        [Parameter(Mandatory=$True)]
        [PSObject]$FolderInfo,
        [Parameter(Mandatory=$True)]
        [guid]$WebId,
        [Parameter(Mandatory=$True)]
        [PSObject]$UserInformation,
        [Parameter(Mandatory=$True)]
        [Hashtable]$Files,
        [Parameter(Mandatory=$True)]
        [string]$Site
    )
    Process
    {
        $metadataFiles = @{}

        $key = Convert-B64ToByteArray -B64 $ContainerInfo.EncryptionKey

        # Create ExportSettings.xml
        Write-Verbose "Generating ExportSettings.xml"
        $content = @"
<?xml version="1.0" encoding="utf-8"?>
<ExportSettings xmlns="urn:deployment-exportsettings-schema" SiteUrl="http://fileshare/sites/user" FileLocation="C:\" IncludeSecurity="All" SourceType="FileShare">
  <ExportObjects/>
</ExportSettings>
"@ 

        $metadataFiles["ExportSettings.xml"] = Encrypt-SPMTFile -Key $key -StringContent $content

        # Create SystemData.xml
        Write-Verbose "Generating SystemData.xml"
        $content = @"
<?xml version="1.0" encoding="utf-8"?>
<SystemData xmlns="urn:deployment-systemdata-schema">
  <SchemaVersion Version="15.0.0.0" Build="16.0.3111.1200" DatabaseVersion="11552" SiteVersion="15" ObjectsProcessed="7" />
  <ManifestFiles>
    <ManifestFile Name="Manifest.xml" />
  </ManifestFiles>
  <SystemObjects/>
</SystemData>
"@ 

        $metadataFiles["SystemData.xml"] = Encrypt-SPMTFile -Key $key -StringContent $content

        # Create UserGroup.xml
        Write-Verbose "Generating UserGroup.xml"
        $content = @"
<?xml version="1.0" encoding="utf-8"?>
<UserGroupMap xmlns="urn:deployment-usergroupmap-schema">
  <Users>
    <User Id="1" Name="$($UserInformation.Title)" Login="$($UserInformation.LoginName)" IsSiteAdmin="false" SystemId="$(Convert-ByteArrayToB64 ([text.encoding]::UTF8.GetBytes($UserInformation.NameId)))" IsDeleted="false" IsDomainGroup="false" />
  </Users>
  <Groups />
</UserGroupMap>
"@ 
        $metadataFiles["UserGroup.xml"] = Encrypt-SPMTFile -Key $key -StringContent $content

        # Create Requirements.xml
        Write-Verbose "Generating Requirements.xml"
        $content = @"
<?xml version="1.0" encoding="utf-8"?>
<Requirements xmlns="urn:deployment-requirements-schema" />
"@ 
        $metadataFiles["Requirements.xml"] = Encrypt-SPMTFile -Key $key -StringContent $content

        # Create Manifest.xml
        Write-Verbose "Generating Manifest.xml"
        
        $content = @"
<?xml version="1.0" encoding="utf-8"?>
<SPObjects xmlns="urn:deployment-manifest-schema">
  
"@ 
        $id = 1
        foreach($fileName in $Files.Keys)
        {
            $fileInfo = $Files[$fileName]
            
            $content += @"
  <SPObject Id="$($fileInfo.Guid)" ObjectType="SPFile">
    <File Url="$($FolderInfo.Name)/$fileName" Id="$($fileInfo.Guid)" ParentWebId="$WebId" Name="$fileName" ParentId="$($FolderInfo.Id)" TimeCreated="$($fileInfo.TimeCreated)" TimeLastModified="$($fileInfo.TimeLastModified)" Version="1.0" FileValue="$($fileInfo.Guid).dat" Author="1" ModifiedBy="1" MD5Hash="$($fileInfo.MD5)" InitializationVector="$($fileInfo.IV)" />
  </SPObject>
"@
        } 

        $content += @"
</SPObjects>
"@
        $metadataFiles["Manifest.xml"] = Encrypt-SPMTFile -Key $key -StringContent $content

        return $metadataFiles
    }
}

# Generate metadatafiles for migration
# Nov 24th 2022
function Generate-SPMTFiledata
{
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$False)]
        [string]$Cookie,
        [Parameter(Mandatory=$False)]
        [string]$AccessToken,
        [Parameter(Mandatory=$True)]
        [string]$Site,
        [Parameter(Mandatory=$True)]
        [PSObject]$FolderInfo,
        [Parameter(Mandatory=$True)]
        [PSObject]$ContainerInfo,
        [Parameter(Mandatory=$True)]
        [string[]]$Files,
        [Parameter(Mandatory=$False)]
        [string]$LocalFile,
        [Parameter(Mandatory=$False)]
        [PSObject]$TimeCreated,
        [Parameter(Mandatory=$False)]
        [PSObject]$TimeLastModified,
        [Parameter(Mandatory=$False)]
        [PSObject]$Id,
        [Parameter(Mandatory=$False)]
        [String]$RelativePath
    )
    Process
    {
        $fileData = @{}

        $key = Convert-B64ToByteArray -B64 $ContainerInfo.EncryptionKey

        foreach($file in $Files)
        {
            if((Test-Path $file) -or (Test-Path $LocalFile))
            {
                if($LocalFile)
                {
                    # Get local file if provided (may have different name than the target one when replacing)
                    $fileItem = Get-Item $LocalFile
                    $fileName = $file
                }
                else
                {
                    # Get file item 
                    $fileItem = Get-Item $file
                    $fileName = $fileItem.Name
                }


                Write-Verbose "Processing file $($fileItem.FullName)"

                # Encrypt
                $fileInfo = Encrypt-SPMTFile -Key $key -FilePath $fileItem.FullName

                # Add created and modified time
                if($TimeCreated -eq $null)
                {
                    $TimeCreated = $fileItem.CreationTimeUtc
                }
                if($TimeLastModified -eq $null)
                {
                    $TimeLastModified = $fileItem.LastWriteTimeUtc
                }

                

                # We are replacing an existing file so use that guid
                if($Id)
                {
                    $guid = $Id
                }
                else
                {
                    # Form the filepath for calculating guid
                    $filePath = $Site + $FolderInfo.Name + $FolderInfo.ListName + $fileName
                    $guid = Get-SPMTFileGuid -FilePath $FilePath
                }
                
                $fileInfo | Add-Member -NotePropertyName "TimeCreated"      -NotePropertyValue $TimeCreated.ToString("o").Split(".")[0]
                $fileInfo | Add-Member -NotePropertyName "TimeLastModified" -NotePropertyValue $TimeLastModified.ToString("o").Split(".")[0]
                $fileInfo | Add-Member -NotePropertyName "Guid"             -NotePropertyValue $guid

                $fileData[$fileName] = $fileInfo
            }
            else
            {
                Write-Warning "File does not exist, skipping: $file"
            }
        }

        return $fileData
    }
}

# Send files
# Nov 24th 2022
function Send-SPMTFiles
{
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [Hashtable]$Files,
        [Parameter(Mandatory=$True)]
        [Hashtable]$Metadata,
        [Parameter(Mandatory=$True)]
        [PSObject]$ContainerInfo
    )
    Process
    {
        if($Files.Count -lt 1)
        {
            throw "No files to be sent"
        }
        Write-Verbose "Sending $($Files.Count) file(s) and $($Metadata.Count) metadata file(s) to SPO"

        # Send metadata
        foreach($fileName in $Metadata.Keys)
        {
            $metadataInfo = $Metadata[$fileName]
            Write-Verbose "Sending metadata: $($metadataInfo.Guid) $fileName "

            # Create the url
            $url = $ContainerInfo.MetadataContainerUri.Replace("?","/$fileName`?")
            $url += "&api-version=2018-03-28"
            
            # Create headers
            $headers=@{
                "x-ms-client-request-id" = (New-Guid).ToString()
                "Content-MD5"            = $metadataInfo.MD5
                "x-ms-blob-type"         = "BlockBlob"
                "x-ms-version"           = "2018-03-28"
            }

            # Send the file
            $response = Invoke-RestMethod -UseBasicParsing -Method Put -Uri "$url&timeout=300" -Headers $headers -Body $metadataInfo.Data

            # Create headers for IV
            $headers=@{
                "x-ms-client-request-id" = (New-Guid).ToString()
                "x-ms-meta-IV"           = $metadataInfo.IV
                "x-ms-version"           = "2018-03-28"
            }

            # Send the IV
            $response = Invoke-RestMethod -UseBasicParsing -Method Put -Uri "$url&comp=metadata" -Headers $headers

            # Create headers for snapshot
            $headers=@{
                "x-ms-client-request-id" = (New-Guid).ToString()
                "x-ms-version"           = "2018-03-28"
            }

            # Create a snapshot
            $response = Invoke-RestMethod -UseBasicParsing -Method Put -Uri "$url&comp=snapshot" -Headers $headers
        }

        # Send files
        foreach($fileName in $Files.Keys)
        {
            Write-Verbose "Sending file: $fileName"
            $fileInfo = $Files[$fileName]

            # Create the url
            $url = $ContainerInfo.DataContainerUri.Replace("?","/$($fileInfo.Guid).dat?")
            $url += "&api-version=2018-03-28"
            
            # Create headers
            $headers=@{
                "x-ms-client-request-id" = (New-Guid).ToString()
                "Content-MD5"            = $fileInfo.MD5
                "x-ms-blob-type"         = "BlockBlob"
                "x-ms-version"           = "2018-03-28"
            }

            # Send the file and delete temporary file
            $response = Invoke-RestMethod -UseBasicParsing -Method Put -Uri "$url&timeout=300" -Headers $headers -InFile $fileInfo.DataFile
            Remove-Item -Path $fileInfo.DataFile -Force -ErrorAction SilentlyContinue

            # Create headers for IV
            $headers=@{
                "x-ms-client-request-id" = (New-Guid).ToString()
                "x-ms-meta-IV"           = $fileInfo.IV
                "x-ms-version"           = "2018-03-28"
            }

            # Send the IV
            $response = Invoke-RestMethod -UseBasicParsing -Method Put -Uri "$url&comp=metadata" -Headers $headers

            # Create headers for snapshot
            $headers=@{
                "x-ms-client-request-id" = (New-Guid).ToString()
                "x-ms-version"           = "2018-03-28"
            }

            # Create a snapshot
            $response = Invoke-RestMethod -UseBasicParsing -Method Put -Uri "$url&comp=snapshot" -Headers $headers
        }

    }
}

# Poll messages
# Nov 24th 2022
function Start-SPMTPoll
{
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [PSObject]$ContainerInfo,
        [Parameter(Mandatory=$True)]
        [guid]$JobId
    )
    Process
    {
        # Decode the key
        $key = Convert-B64ToByteArray -B64 $ContainerInfo.EncryptionKey

        # Start polling for messages from migration queue
        $jobQueueUri = $ContainerInfo.JobQueueUri
        $continue = $true
        Write-Verbose "Polling messages.."
        while($continue)
        {
            # Create the url
            $url = $jobQueueUri.Replace("?","/messages?")
            $createUrl = $url + "&api-version=2018-03-28&numofmessages=30&timeout=5"
            
            # Create headers
            $headers=@{
                "x-ms-client-request-id" = (New-Guid).ToString()
                "x-ms-version"           = "2018-03-28"
            }

            # Get message
            $response = Invoke-WebRequest -UseBasicParsing -Method Get -Uri $createUrl -Headers $headers
            
            $responseBytes = New-Object byte[] $response.RawContentLength
            $response.RawContentStream.Read($responseBytes,0,$response.RawContentLength) | Out-Null

            # Strip the BOM
            [xml]$queueResponse = [text.encoding]::UTF8.getString([byte[]](Remove-BOM -ByteArray $responseBytes))

            # Parse messages
            foreach($queueMessage in $queueResponse.QueueMessagesList.ChildNodes)
            {
                $messageText = ConvertFrom-Json (Convert-B64ToText -B64 $queueMessage.MessageText)

                Write-Verbose "Received message $($queueMessage.MessageId)"
                # Check the JobId
                if([guid]$messageText.JobId -ne $JobId)
                {
                    Write-Warning "Message $($queueMessage.MessageId) is for wrong job ($($messageText.JobId)). Was expecting $JobId"
                }

                # Decrypt the message
                if($messageText.Label -eq "Encrypted")
                {
                    $iv = Convert-B64ToByteArray -B64 $messageText.IV
                    $encData = Convert-B64ToByteArray -B64 $messageText.Content
                    $aes = [System.Security.Cryptography.AesCryptoServiceProvider]::new()
                    $aes.Key = $key
                    $aes.IV = $iv
                    $ms = [System.IO.MemoryStream]::new()
                    $decryptor = $aes.CreateDecryptor()
                    $cs = [System.Security.Cryptography.CryptoStream]::new($ms,$decryptor,[System.Security.Cryptography.CryptoStreamMode]::Write)
                    $cs.Write($encData,0,$encData.Count)
                    $cs.FlushFinalBlock()
                    $decData = $ms.ToArray()

                    $ms.Close()
                    $cs.Close()
                    $decryptor.Dispose()

                    $messageText.Content = [text.encoding]::UTF8.GetString($decData)
                }

                $content = $messageText.Content | ConvertFrom-Json
                Write-Verbose $content

                # Delete the message from the server
                $deleteUrl = $url.Replace("?","/$($queueMessage.MessageId)?")
                $deleteUrl += "&api-version=2018-03-28&popreceipt=$([System.Web.HttpUtility]::UrlEncode($queueMessage.PopReceipt))"
                $response = Invoke-WebRequest -UseBasicParsing -Method Delete -Uri $deleteUrl -Headers $headers

                Write-Host "$($content.Time) $($content.Event)"
                
                switch($content.Event)
                {
                    "JobEnd" {
                        $continue = $false
                        Write-Host "$($content.FilesCreated) files ($('{0:N0}' -f $content.BytesProcessed) bytes) sent."
                        break
                    }
                }
                if($content.Message)
                {
                    Write-Host $content.Message -ForegroundColor DarkYellow
                }                
            }
            if($continue)
            {
                Start-Sleep -Seconds 5
            }
        }
    }
}

# Create migration job
# Nov 24th 2022
function New-SPMTMigrationJob
{
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$False)]
        [string]$Cookie,
        [Parameter(Mandatory=$False)]
        [string]$AccessToken,
        [Parameter(Mandatory=$True)]
        [string]$Site,
        [Parameter(Mandatory=$True)]
        [PSObject]$ContainerInfo
    )
    Process
    {
        # Get digest
        $digest = Get-SPODigest -Cookie $cookie -AccessToken $AccessToken -Site $site

        # body for site id
        $Body=@"
<Request AddExpandoFieldTypeSuffix="true" SchemaVersion="15.0.0.0" LibraryVersion="16.0.0.0" ApplicationName=".NET Library" xmlns="http://schemas.microsoft.com/sharepoint/clientquery/2009">
	<Actions>
		<ObjectPath Id="2" ObjectPathId="1"/>
		<ObjectPath Id="4" ObjectPathId="3"/>
		<ObjectPath Id="6" ObjectPathId="5"/>
		<Query Id="7" ObjectPathId="3">
			<Query SelectAllProperties="false">
				<Properties>
					<Property Name="RootWeb">
						<Query SelectAllProperties="false">
							<Properties>
								<Property Name="Id" ScalarProperty="true"/>
							</Properties>
						</Query>
					</Property>
				</Properties>
			</Query>
		</Query>
		<Query Id="9" ObjectPathId="5">
			<Query SelectAllProperties="false">
				<Properties>
					<Property Name="Id" ScalarProperty="true"/>
				</Properties>
			</Query>
		</Query>
	</Actions>
	<ObjectPaths>
		<StaticProperty Id="1" TypeId="{3747adcd-a3c3-41b9-bfab-4a64dd2f1e0a}" Name="Current"/>
		<Property Id="3" ParentId="1" Name="Site"/>
		<Property Id="5" ParentId="1" Name="Web"/>
	</ObjectPaths>
</Request>
"@
        
        # Invoke ProcessQuery to get site id
        $response = Invoke-ProcessQuery -Cookie $Cookie -AccessToken $AccessToken -Site $site -Body $Body -Digest $digest

        $content = ($response.content | ConvertFrom-Json)
        
        $SPWebIdentity = $content[$content.Count -1]._ObjectIdentity_
        $SPSiteIdentity = $SPWebIdentity.Substring(0,$SPWebIdentity.IndexOf(":web:"))

        # Body for starting the job (must be linearised...)
        $Body=@"
<Request AddExpandoFieldTypeSuffix="true" SchemaVersion="15.0.0.0" LibraryVersion="16.0.0.0" ApplicationName=".NET Library" xmlns="http://schemas.microsoft.com/sharepoint/clientquery/2009"><Actions><Method Name="CreateMigrationJobEncrypted" Id="14" ObjectPathId="3"><Parameters><Parameter Type="Guid">{5ac5b4f2-8830-4b68-8811-276e29e0595d}</Parameter><Parameter Type="String">$($ContainerInfo.DataContainerUri.Replace("&","&amp;").Replace("0:0","0%3A0"))</Parameter><Parameter Type="String">$($ContainerInfo.MetadataContainerUri.Replace("&","&amp;").Replace("0:0","0%3A0"))</Parameter><Parameter Type="String">$($ContainerInfo.JobQueueUri.Replace("&","&amp;").Replace("0:0","0%3A0"))</Parameter><Parameter TypeId="{85614ad4-7a40-49e0-b272-6d1807dbfcc6}"><Property Name="AES256CBCKey" Type="Base64Binary">$($ContainerInfo.EncryptionKey)</Property></Parameter></Parameters></Method></Actions><ObjectPaths><Identity Id="3" Name="$SPSiteIdentity"/></ObjectPaths></Request>
"@
        
        # Invoke ProcessQuery
        $response = Invoke-ProcessQuery -Cookie $Cookie -AccessToken $AccessToken -Site $site -Body $Body -Digest $digest

        $content = ($response.content | ConvertFrom-Json)

        [guid]$guid = $content[$content.Count -1].Split("(")[1].Split(")")[0]

        return $guid
    }
}

# Send given file(s) to given SPO site
# Nov 23rd 2022
function Send-SPOFiles
{
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [string]$Site,
        [Parameter(Mandatory=$True)]
        [string]$FolderName,
        [Parameter(Mandatory=$True)]
        [string[]]$Files,
        [Parameter(Mandatory=$False)]
        [string]$LocalFile,
        [Parameter(Mandatory=$True)]
        [string]$UserName,
        [Parameter(Mandatory=$False)]
        [DateTime]$TimeCreated,
        [Parameter(Mandatory=$False)]
        [DateTime]$TimeLastModified,
        [Parameter(Mandatory=$False)]
        [Guid]$Id
    )
    Process
    {
        # Get user information
        Write-Verbose "Getting user information"
        try
        {
            $userInformation = Get-SPOMigrationUser -Site $Site -UserName $UserName
        }
        catch
        {
            Write-Error $_.Exception.Message
            return
        }

        # Get the container information
        Write-Verbose "Getting migration container information"
        $containerInfo = Get-SPOMigrationContainersInfo -Site $Site

        # Get folder information
        Write-Verbose "Getting information for folder '$FolderName'"
        $folderInformation = Get-SPOSiteFolder -Site $Site -RelativePath $FolderName

        # Get WebId
        $webId = Get-SPOWebId -Site $Site

        # Process the data files (encrypt & get information)
        $fileData = Generate-SPMTFileData -ContainerInfo $containerInfo -FolderInfo $folderInformation -Files $Files -TimeCreated $TimeCreated -TimeLastModified $TimeLastModified -Id $Id -Site $Site -LocalFile $LocalFile

        Write-Host "Sending $($fileData.Count) file(s) as `"$($userInformation.LoginName)`" to `"$($Site)/$($folderInformation.Name)`""

        # Generate metadata files
        $metadata = Generate-SPMTMetadata -ContainerInfo $containerInfo -FolderInfo $folderInformation -UserInformation $userInformation -Files $fileData -WebId $webId -Site $Site 
        
        # Send the files
        Send-SPMTFiles -Files $fileData -Metadata $metadata -ContainerInfo $containerInfo

        # Create a new migration job
        $jobId = New-SPMTMigrationJob -Cookie $Cookie -AccessToken $AccessToken -Site $site -ContainerInfo $containerInfo

        # Start polling messages
        Start-SPMTPoll -ContainerInfo $containerInfo -JobId $jobId
    }
}