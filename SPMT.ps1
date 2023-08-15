# This file contains functions to implement protocol used by
# SharePoint Migration Tool (SPMT) and Migration Manager agent
# Ref: https://learn.microsoft.com/en-us/sharepointmigration/introducing-the-sharepoint-migration-tool
# Ref: https://learn.microsoft.com/en-us/sharepointmigration/mm-how-to-use

# Send given file(s) to given SPO site
# Nov 23rd 2022
function Add-SPOSiteFiles
{
<#
    .SYNOPSIS
    Send given file(s) to given SPO site.

    .DESCRIPTION
    Send given file(s) to given SPO site using SharePoint Migration Tool protocol.

    .Parameter Site
    Url of the SharePoint site

    .Parameter FolderName
    Name of the folder where to send the files. Relative to site, e.g., "Shared Documents/General"

    .Parameter Files
    The name(s) of file(s) to be sent to SPO.

    .Parameter UserName
    The username to be used as an author of the file(s). Defaults to "SHAREPOINT\System".

    .Parameter TimeCreated
    Creation time of the file(s). Defaults to creation time of the file(s) to be sent.

    .Parameter TimeLastModified
    Last modified time of the file(s). Defaults to modification time of the file(s) to be sent.
    
    .Example
    PS C:\>Get-AADIntAccessTokenForSPO -SaveToCache
    PS C:\>Add-AADIntSPOSiteFiles -Site "https://company.sharepoint.com/sales" -Folder "Shared Documents" -Files "C:\share\Document1.docx","C:\share\Document2.docx"

    Sending 2 files as "SHAREPOINT\system" to site "https://company.sharepoint.com/sales/Shared Documents"
    11/28/2022 08:59:35.042 JobQueued
    11/28/2022 09:01:55.986 JobLogFileCreate
    11/28/2022 09:01:56.018 JobStart
    11/28/2022 09:01:57.580 JobEnd
    2 files (2,322,536 bytes) created.

    .Example
    PS C:\>Get-AADIntAccessTokenForSPO -SaveToCache
    PS C:\>Add-AADIntSPOSiteFiles -Site "https://company.sharepoint.com/sales" -Folder "Shared Documents" -Files "C:\share\Document1.docx","C:\share\Document2.docx" -UserName "user2@company.com" -TimeCreated "1.1.1970 01:00" -TimeLastModified "1.1.1970 02:00"

    Sending 2 files as "i:0#.f|membership|user2@company.com" to site "https://company.sharepoint.com/sales/Shared Documents"
    11/28/2022 08:59:35.042 JobQueued
    11/28/2022 09:01:55.986 JobLogFileCreate
    11/28/2022 09:01:56.018 JobStart
    11/28/2022 09:01:57.580 JobEnd
    2 files (2,322,536 bytes) created.
#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [string]$Site,
        [Parameter(Mandatory=$True)]
        [string]$FolderName,
        [Parameter(Mandatory=$True)]
        [string[]]$Files,
        [Parameter(Mandatory=$False)]
        [string]$UserName="SHAREPOINT\System",
        [Parameter(Mandatory=$False)]
        [DateTime]$TimeCreated=(Get-Date),
        [Parameter(Mandatory=$False)]
        [DateTime]$TimeLastModified=$TimeCreated
    )
    Process
    {
        # Add files to SPO
        Send-SPOFiles -Site $Site -FolderName $FolderName -Files $Files -UserName $UserName -TimeCreated $TimeCreated -TimeLastModified $TimeLastModified 
    }
}

# Replace a given file on SPO site - including design files
# Mar 9th 2023
function Update-SPOSiteFile
{
<#
    .SYNOPSIS
    Replaces an existing file in SPO site with the given file.

    .DESCRIPTION
    Replaces an existing file in SPO site with the given file using SharePoint Migration Tool protocol.

    .Parameter Site
    Url of the SharePoint site

    .Parameter File
    The name of the file to be sent to SPO.

    .Parameter UserName
    The username to be used as an author of the replaced file. Defaults to current author of the file.

    .Parameter TimeCreated
    Creation time of the file. Defaults to current creation time of the existing SPO file.

    .Parameter TimeLastModified
    Last modified time of the file. Defaults to current last modification time of the existing SPO file.
    
    .Parameter RelativePath
    Path of the file to be replaced relative to site, e.g., "Shared Documents/Document.docx"

    .Example
    PS C:\>Get-AADIntAccessTokenForSPO -SaveToCache
    PS C:\>Update-AADIntSPOSiteFile -Site "https://company.sharepoint.com/sales" -RelativePath "Shared Documents/Document1.docx" -File "UpdatedDocument.docx"

    Sending 1 files as "i:0#.f|membership|user1@company.com" to site "https://company.sharepoint.com/sales/Shared Documents"
    11/28/2022 08:59:35.042 JobQueued
    11/28/2022 09:01:55.986 JobLogFileCreate
    11/28/2022 09:01:56.018 JobStart
    11/28/2022 09:01:57.580 JobEnd
    1 files (322,536 bytes) created.

    .Example
    PS C:\>Get-AADIntAccessTokenForSPO -SaveToCache
    PS C:\>Update-AADIntSPOSiteFile -Site "https://company.sharepoint.com/sales" -RelativePath "Shared Documents/Document1.docx" -File "UpdatedDocument.docx" -UserName "user2@company.com" -TimeCreated "1.1.1970 01:00" -TimeLastModified "1.1.1970 02:00"

    Sending 1 files as "i:0#.f|membership|user2@company.com" to site "https://company.sharepoint.com/sales/Shared Documents"
    11/28/2022 08:59:35.042 JobQueued
    11/28/2022 09:01:55.986 JobLogFileCreate
    11/28/2022 09:01:56.018 JobStart
    11/28/2022 09:01:57.580 JobEnd
    1 files (322,536 bytes) created.
#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [string]$Site,
        [Parameter(Mandatory=$True)]
        [string]$File,
        [Parameter(ParameterSetName="Id",Mandatory=$True)]
        [Guid]$Id,
        [Parameter(ParameterSetName="RelativePath",Mandatory=$True)]
        [string]$RelativePath,
        [Parameter(Mandatory=$False)]
        [string]$UserName,
        [Parameter(Mandatory=$False)]
        [DateTime]$TimeCreated,
        [Parameter(Mandatory=$False)]
        [DateTime]$TimeLastModified
    )
    Process
    {
        $Site=$Site.TrimEnd("/")
        
        # Get the file information
        $fileInformation = Get-SPOSiteFile -Site $Site -Id $Id -RelativePath $RelativePath

        # Set to default values if not provided
        if([string]::IsNullOrEmpty($UserName))
        {
            $UserName = $fileInformation.Author
        }

        if(-Not $TimeCreated)
        {
            $TimeCreated = $fileInformation.TimeCreated
        }

        if(-Not $TimeLastModified)
        {
            $TimeLastModified = $fileInformation.TimeLastModified
        }

        # Get folder information
        $folderInformation = Get-SPOSiteFolder -Site $Site -Id $fileInformation.ParentId
        $FolderName = $folderInformation.Name

        # Replace the target file
        Send-SPOFiles -Site $Site -FolderName $FolderName -Files @($fileInformation.Name) -UserName $UserName -TimeCreated $TimeCreated -TimeLastModified $TimeLastModified -Id $fileInformation.Id -LocalFile $File
        
    }
}
