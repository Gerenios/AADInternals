# Functions for SharePoint Online


# Jul 17th 2019
function Get-SPOSiteGroups
{
<#
    .SYNOPSIS
    Gets list of groups of SharePoint Online site

    .DESCRIPTION
    Gets list of groups of SharePoint Online site the user has access to.

    .Parameter Site
    Url of the SharePoint site

    .Parameter AuthHeader
    SharePoint Online authentication header
    
    .Example
    PS C:\>$auth=Get-AADIntSPOAuthenticationHeader -Site https://company.sharepoint.com
    PS C:\>Get-AADIntSPOSiteGroups -Site https://company.sharepoint.com/sales -AuthHeader $auth
#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [String]$Site,
        [Parameter(Mandatory=$False)]
        [String]$AuthHeader,
        [Parameter(Mandatory=$False)]
        [String]$AccessToken
    )
    Process
    {
        # Check the site url
        if($Site.EndsWith("/"))
        {
            $Site=$Site.Substring(0,$Site.Length-1)
        }

        $siteDomain=$Site.Split("/")[2]

        if(![string]::IsNullOrEmpty($AuthHeader))
        {
            # Create a WebSession object
            $siteSession = Create-WebSession -SetCookieHeader $AuthHeader -Domain $siteDomain
        }
        else
        {
            # Get from cache if not provided
            $AccessToken = Get-AccessTokenFromCache -AccessToken $AccessToken -Resource $site -ClientId "d3590ed6-52b3-4102-aeff-aad2292ab01c"
            $headers=@{
                "Authorization" = "Bearer $AccessToken"
            }
        }

        # Invoke the request
        $response=Invoke-WebRequest -UseBasicParsing -Uri "$Site/_api/web/sitegroups" -Method Get -WebSession $siteSession -ErrorAction SilentlyContinue -Headers $headers

        if($response.StatusCode -eq 200)
        {
            [xml]$response=$response.Content


            $users=New-Object System.Collections.ArrayList

            # Loop through the entries
            foreach($entry in $response.feed.entry)
            {
                $attributes = @{}
                $attributes["Id"] = $entry.content.properties.Id.'#Text'
                $attributes["IsHiddenInUI"] = $entry.content.properties.IsHiddenInUI.'#Text' -eq "true"
                $attributes["LoginName"] = $entry.content.properties.LoginName
                $attributes["Title"] = $entry.content.properties.Title
                $attributes["PrincipalType"] = $entry.content.properties.PrincipalType.'#Text'
                $attributes["OwnerTitle"] = $entry.content.properties.OwnerTitle
                $attributes["Description"] = $entry.content.properties.Description.'#Text'
                
                $attributes["AllowMembersEditMembership"] = $entry.content.properties.AllowMembersEditMembership.'#Text' -eq "true"
                $attributes["AllowRequestToJoinLeave"] = $entry.content.properties.AllowRequestToJoinLeave.'#Text' -eq "true"
                $attributes["AutoAcceptRequestToJoinLeave"] = $entry.content.properties.AutoAcceptRequestToJoinLeave.'#Text' -eq "true"
                $attributes["OnlyAllowMembersViewMembership"] = $entry.content.properties.OnlyAllowMembersViewMembership.'#Text' -eq "true"
           
                $users+=New-Object PSObject -Property $attributes
            }

            # Return
            return $users
        }
    }
}

# Jul 17th 2019
function Get-SPOSiteUsers
{
<#
    .SYNOPSIS
    Gets list of users of SharePoint Online site

    .DESCRIPTION
    Gets list of users of SharePoint Online site the user has access to.

    .Parameter Site
    Url of the SharePoint site

    .Parameter AuthHeader
    SharePoint Online authentication header
    
    .Example
    PS C:\>$auth=Get-AADIntSPOAuthenticationHeader -Site https://company.sharepoint.com
    PS C:\>Get-AADIntSPOSiteUsers -Site https://company.sharepoint.com/sales -AuthHeader $auth
#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [String]$Site,
        [Parameter(Mandatory=$False)]
        [String]$AuthHeader,
        [Parameter(Mandatory=$False)]
        [String]$AccessToken
    )
    Process
    {
        $Site=$Site.TrimEnd("/")
        
        $tenant=$Site.Split("/")[2]

        if(![string]::IsNullOrEmpty($AuthHeader))
        {
            # Create a WebSession object
            $siteSession = Create-WebSession -SetCookieHeader $AuthHeader -Domain $siteDomain
        }
        else
        {
            # Get from cache if not provided
            $AccessToken = Get-AccessTokenFromCache -AccessToken $AccessToken -Resource "https://$Tenant" -ClientId "d3590ed6-52b3-4102-aeff-aad2292ab01c"
            $headers=@{
                "Authorization" = "Bearer $AccessToken"
            }
        }

        # Invoke the request
        $response=Invoke-WebRequest -UseBasicParsing -Uri "$Site/_api/web/siteusers" -Method Get -WebSession $siteSession -Headers $headers -ErrorAction SilentlyContinue

        if($response.StatusCode -eq 200)
        {
            [xml]$response=$response.Content


            $users=New-Object System.Collections.ArrayList

            # Loop through the entries
            foreach($entry in $response.feed.entry)
            {
                $attributes = @{}
                $attributes["Id"] = $entry.content.properties.Id.'#Text'
                $attributes["IsHiddenInUI"] = $entry.content.properties.IsHiddenInUI.'#Text' -eq "true"
                $attributes["LoginName"] = $entry.content.properties.LoginName
                $attributes["Title"] = $entry.content.properties.Title
                $attributes["PrincipalType"] = $entry.content.properties.PrincipalType.'#Text'
                $attributes["Email"] = $entry.content.properties.Email
                $attributes["IsEmailAuthenticationGuestUser"] = $entry.content.properties.IsEmailAuthenticationGuestUser.'#Text' -eq "true"
                $attributes["IsShareByEmailGuestUser"] = $entry.content.properties.IsShareByEmailGuestUser.'#Text' -eq "true"
                $attributes["IsSiteAdmin"] = $entry.content.properties.IsSiteAdmin.'#Text' -eq "true"
                $attributes["NameId"] = $entry.content.properties.UserId.NameId
                $attributes["NameIdIssuer"] = $entry.content.properties.UserId.NameIdIssuer
            

                if($entry.content.properties.UserPrincipalName.GetType().Name  -eq "String")
                {
                    $attributes["UserPrincipalName"] = $entry.content.properties.UserPrincipalName
                }
                else
                {
                    $attributes["UserPrincipalName"] = ""
                }
            
                $users+=New-Object PSObject -Property $attributes
            }

            # Return
            return $users
        }
    }
}

# Jul 18th 2019
function Get-SPOUserProperties
{
<#
    .SYNOPSIS
    Gets properties of SharePoint Online user

    .DESCRIPTION
    Gets properties of SharePoint Online user using PeopleManager API

    .Parameter Site
    Url of the SharePoint site

    .Parameter User
    SharePoint Online authentication header

    .Parameter AuthHeader
    LoginName of the user in format "i:0i.t|00000003-0000-0ff1-ce00-000000000000|app@sharepoint"
    
    .Example
    PS C:\>$auth=Get-AADIntSPOAuthenticationHeader -Site https://company.sharepoint.com
    PS C:\>Get-AADIntSPOUserProperties -Site https://company.sharepoint.com/sales -AuthHeader $auth -User "i:0i.t|00000003-0000-0ff1-ce00-000000000000|app@sharepoint"
#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [String]$Site,
        [Parameter(Mandatory=$True)]
        [String]$UserName,
        [Parameter(Mandatory=$False)]
        [String]$AuthHeader,
        [Parameter(Mandatory=$False)]
        [String]$AccessToken
    )
    Process
    {
        # Check the site url
        $Site=$Site.Trim("/")

        $UserName=$UserName.Replace("#","%23")

        $siteDomain=$Site.Split("/")[2]

        $tenant = $siteDomain.Split(".")[0]

        # Check the username format
        if(!$UserName.StartsWith("i"))
        {
            $UserName="i:0%23.f|membership|$UserName"
        }

        if(![string]::IsNullOrEmpty($AuthHeader))
        {
            # Create a WebSession object
            $siteSession = Create-WebSession -SetCookieHeader $AuthHeader -Domain $siteDomain
        }
        else
        {
            # Get from cache if not provided
            $AccessToken = Get-AccessTokenFromCache -AccessToken $AccessToken -Resource "https://$Tenant.sharepoint.com/" -ClientId "d3590ed6-52b3-4102-aeff-aad2292ab01c"
            $headers=@{
                "Authorization" = "Bearer $AccessToken"
            }
        }

        # Invoke the request
        $response=Invoke-WebRequest2 -Uri "$Site/_api/sp.userprofiles.peoplemanager/getpropertiesfor(@v)?@v='$UserName'" -Method Get -WebSession $siteSession -Headers $headers -ErrorAction SilentlyContinue 

        if($response.StatusCode -eq 200)
        {
            [xml]$response=$response.Content
            $entry=$response.entry

            $attributes = [ordered]@{}

            $attributes["Updated"] = $response.entry.Updated
            $attributes["Author"] = $response.entry.Author.Name

            $properties = $response.entry.content.properties
            $attributes["AccountName"] = $properties.AccountName
            $attributes["DirectReports"] = Create-ListFromCollection $properties.DirectReports
            $attributes["DisplayName"] = $properties.DisplayName
            $attributes["Email"] = $properties.Email
            $attributes["ExtendedManagers"] = Create-ListFromCollection $properties.ExtendedManagers
            $attributes["ExtendedReports"] = Create-ListFromCollection $properties.ExtendedReports
            $attributes["IsFollowed"] = $properties.IsFollowed -eq "true"
            #$attributes["LatestPost"] = $properties.LatestPost
            $attributes["Peers"] = Create-ListFromCollection $properties.Peers
            #$attributes["PersonalSiteHostUrl"] = $properties.PersonalSiteHostUrl
            $attributes["PersonalUrl"] = [System.Net.WebUtility]::UrlDecode($properties.PersonalUrl)
            $attributes["PictureUrl"] = [System.Net.WebUtility]::UrlDecode($properties.PictureUrl)
            $attributes["UserUrl"] = [System.Net.WebUtility]::UrlDecode($properties.UserUrl)
            $attributes["Title"] = $properties.Title

            # Loop through the userprofile fields
            foreach($up in $properties.UserProfileProperties.Element)
            {
                $name = $up.Key
                $value = $up.Value
                $attributes[$name] = $value
            }

            # Return            
            New-Object PSObject -Property $attributes
        }
    }
}

# Jun 10th 2020
function Get-SPOSiteUserProperties
{
<#
    .SYNOPSIS
    Gets the SPO user properties

    .DESCRIPTION
    Gets the SPO user properties

    .Parameter Site
    Url of the SharePoint site

    .Parameter AuthHeader
    SharePoint Online authentication header

    .Parameter AccessToken
    SharePoint Online Access Token
    
    .Example
    PS C:\>$auth=Get-AADIntSPOAuthenticationHeader -Site https://company.sharepoint.com
    PS C:\>Get-AADIntSPOSiteGroups -Site https://company.sharepoint.com/sales -AuthHeader $auth

    .Example
    PS C:\>$at=Get-AADIntAccessTokenForSPO
    PS C:\>Get-AADIntSPOSiteGroups -Site https://company.sharepoint.com/sales -AccessToken $at
#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [String]$Site,
        [Parameter(Mandatory=$True)]
        [String]$UserName,
        [Parameter(Mandatory=$False)]
        [String]$AuthHeader,
        [Parameter(Mandatory=$False)]
        [String]$AccessToken
    )
    Process
    {
        # Check the site url
        if($Site.EndsWith("/"))
        {
            $Site=$Site.Substring(0,$Site.Length-1)
        }

        $siteDomain=$Site.Split("/")[2]

        # Check the username format
        if(!$UserName.StartsWith("i"))
        {
            $UserName="i:0%23.f|membership|$UserName"
        }

        if(![string]::IsNullOrEmpty($AuthHeader))
        {
            # Create a WebSession object
            $siteSession = Create-WebSession -SetCookieHeader $AuthHeader -Domain $siteDomain
        }
        else
        {
            # Get from cache if not provided
            $AccessToken = Get-AccessTokenFromCache -AccessToken $AccessToken -Resource "https://$Tenant.sharepoint.com/" -ClientId "d3590ed6-52b3-4102-aeff-aad2292ab01c"
            $headers=@{
                "Authorization" = "Bearer $AccessToken"
            }
        }

        # Invoke the request
        $response=Invoke-WebRequest -UseBasicParsing -Uri "$Site/_api/SP.UserProfiles.PeopleManager/GetPropertiesFor(accountName=@v)?@v='$UserName'" -Method Get -WebSession $siteSession -ErrorAction SilentlyContinue -Headers $headers

        if($response.StatusCode -eq 200)
        {
            # Get the response
            [xml]$response=$response.Content

            # Create the attributes varialbe
            $attributes=@{}

            # Loop through the elements
            foreach($element in $response.entry.content.properties.UserProfileProperties.element)
            {
                $key=$element.Key
                $value=$element.Value

                $attributes[$key] = $value
            }

            # Sort by the key
            $attributes_sorted=[ordered]@{}
            $entries = $attributes.GetEnumerator() | Sort-Object Key
            foreach($entry in $entries)
            {
                $attributes_sorted[$entry.Name]=$entry.Value
            }

            # Return
            return New-Object psobject -Property $attributes_sorted
        }
    }
}

# Jun 10th 2020
function Set-SPOSiteUserProperty
{
<#
    .SYNOPSIS
    Sets the SPO user property

    .DESCRIPTION
    Sets the SPO user property

    .Parameter Site
    Url of the SharePoint site

    .Parameter AuthHeader
    SharePoint Online authentication header

    .Parameter AccessToken
    SharePoint Online Access Token

    .Parameter Property
    Property name
    
    .Parameter Value
    Property value

    .Example
    PS C:\>$auth=Get-AADIntSPOAuthenticationHeader -Site https://company.sharepoint.com
    PS C:\>Set-AADIntSPOUserProperty -Site https://company.sharepoint.com/sales -AuthHeader $auth -UserName user@company.com -Property "AboutMe" -Value "I'm a happy SPO user!"

    .Example
    PS C:\>$at=Get-AADIntAccessTokenForSPO
    PS C:\>Set-AADIntSPOUserProperty -Site https://company.sharepoint.com/sales -AccessToken $at -UserName user@company.com -Property "AboutMe" -Value "I'm a happy SPO user!"
#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [String]$Site,
        [Parameter(Mandatory=$True)]
        [String]$UserName,
        [Parameter(Mandatory=$False)]
        [String]$AuthHeader,
        [Parameter(Mandatory=$False)]
        [String]$AccessToken,
        [Parameter(Mandatory=$True)]
        [String]$Property,
        [Parameter(Mandatory=$False)]
        [String]$Value
    )
    Process
    {
        # Get the digest
        #$digest = Get-SPODigest -AccessToken $AccessToken -Cookie $Cookie -Site $Site
        # Set the headers
        $headers=@{
        #    "X-RequestDigest" = $digest
        }

        # Check the site url
        if($Site.EndsWith("/"))
        {
            $Site=$Site.Substring(0,$Site.Length-1)
        }

        $siteDomain=$Site.Split("/")[2]

        # Check the username format
        if(!$UserName.StartsWith("i"))
        {
            $UserName="i:0#.f|membership|$UserName"
        }

        if(![string]::IsNullOrEmpty($AuthHeader))
        {
            # Create a WebSession object
            $siteSession = Create-WebSession -SetCookieHeader $AuthHeader -Domain $siteDomain
        }
        else
        {
            # Get from cache if not provided
            $AccessToken = Get-AccessTokenFromCache -AccessToken $AccessToken -Resource "https://$Tenant.sharepoint.com/" -ClientId "d3590ed6-52b3-4102-aeff-aad2292ab01c"
            $headers["Authorization"] = "Bearer $AccessToken"
        }

        # Create the body
        $body=@{
            "accountName" =   "$UserName"
            "propertyName" =  $Property
            "propertyValue" = $Value
        }

        # Invoke the request
        $response=Invoke-WebRequest2 -Uri "$Site/_api/SP.UserProfiles.PeopleManager/SetSingleValueProfileProperty" -Method Post -WebSession $siteSession -ErrorAction SilentlyContinue -Headers $headers -ContentType "application/json" -Body ($body | ConvertTo-Json)

        if($response.StatusCode -eq 200)
        {
            # All good, nothing to return :)
        }
    }
}

function Get-SPOSettings
{
<#
    .SYNOPSIS
    Gets SharePoint Online settings

    .DESCRIPTION
    Gets SharePoint Online settings

    .Parameter AccessToken
    SharePoint Online Access Token

    .Parameter Tenant
    The tenant name of the organization, ie. company.onmicrosoft.com -> "company"

    .Example
    PS C:\>Get-AADIntAccessTokenForSPO -Admin -SaveToCache -Tenant company
    PS C:\>Get-AADIntSPOSettings -Tenant Company

    _ObjectType_                                          : Microsoft.Online.SharePoint.TenantAdministration.Tenant
    _ObjectIdentity_                                      : 4b09819f-80c3-b000-9cfe-8c850fbea6d5|908bed80-a04a-4433-b4a0-883d9847d110:908c17b8-5ebe-450c-9073-15e52aa1739b
                                                            Tenant
    AIBuilderEnabled                                      : False
    AIBuilderSiteInfoList                                 : {}
    AIBuilderSiteList                                     : {}
    AIBuilderSiteListFileName                             : 
    AllowCommentsTextOnEmailEnabled                       : True
    AllowDownloadingNonWebViewableFiles                   : True
    AllowedDomainListForSyncClient                        : {}
    AllowEditing                                          : True
    AllowGuestUserShareToUsersNotInSiteCollection         : False
    AllowLimitedAccessOnUnmanagedDevices                  : False
    AllowSelectSGsInODBListInTenant                       : 
    AnyoneLinkTrackUsers                                  : False
    ApplyAppEnforcedRestrictionsToAdHocRecipients         : True
    BccExternalSharingInvitations                         : False
    ...

#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$False)]
        [String]$AccessToken,
        [Parameter(Mandatory=$True)]
        [String]$Tenant
    )
    Process
    {
        # Get from cache if not provided
        $AccessToken = Get-AccessTokenFromCache -AccessToken $AccessToken -Resource "https://$Tenant-admin.sharepoint.com/" -ClientId "d3590ed6-52b3-4102-aeff-aad2292ab01c"

        $body=@"
<Request xmlns="http://schemas.microsoft.com/sharepoint/clientquery/2009" SchemaVersion="15.0.0.0" LibraryVersion="16.0.0.0" ApplicationName="Javascript Library">
	<Actions>
		<ObjectPath Id="1" ObjectPathId="0" />
		<Query Id="2" ObjectPathId="0">
			<Query SelectAllProperties="true">
				<Properties />
			</Query>
		</Query>
	</Actions>
	<ObjectPaths>
		<Constructor Id="0" TypeId="{268004ae-ef6b-4e9b-8425-127220d84719}" />
	</ObjectPaths>
</Request>
"@
        $headers=@{
            "Authorization" = "Bearer $AccessToken"
        }

        
        # Invoke the request
        $response=Invoke-RestMethod -UseBasicParsing -Uri "https://$Tenant-admin.sharepoint.com/_vti_bin/client.svc/ProcessQuery" -Method Post -Body $body -Headers $headers

        if($response.count -gt 4)
        {
            $response[4]
        }

    }
}

# Oct 1st 2022 by Sapir Fed
function Set-SPOSiteMembers
{
    <#
        .SYNOPSIS
        Add a member into a site (also adding the member to the correlated Azure AD group)

        .DESCRIPTION
        Add a member into a site (also adding the member to the correlated AzureAD group)
    
        .Parameter Site
        Url of the SharePoint site
    
        .Parameter AuthHeader
        SharePoint Online authentication header

        .Parameter SiteName
        Name of the specific site on SharePoint

        .Parameter UserPrincipalName
        UserPrincipalName of the AzureAD user you wish to add to the site
        
        .Example
        PS C:\>$auth=Get-AADIntSPOAuthenticationHeader -Site https://company.sharepoint.com
        PS C:\>Set-AADIntSPOSiteMembers -Site https://company.sharepoint.com -AuthHeader $auth -SiteName CompanyWiki -UserPrincipalName user@company.com

        User user@company.com was added to group CompanyWiki!
    #>
        [cmdletbinding()]
        Param(
            [Parameter(Mandatory=$True)]
            [String]$Site,
            [Parameter(Mandatory=$True)]
            [String]$AuthHeader,
            [Parameter(Mandatory=$True)]
            [String]$SiteName,
            [Parameter(Mandatory=$True)]
            [String]$UserPrincipalName
        )
        Process
        {
            # Check the site url
            if($Site.EndsWith("/"))
            {
                $Site=$Site.Substring(0,$Site.Length-1)
            }            
            $siteDomain=$Site.Split("/")[2]

            # Create a WebSession object
            $siteSession = Create-WebSession -SetCookieHeader $AuthHeader -Domain $siteDomain
            
            # Invoke the request tp get groupId and digest
            $response=Invoke-WebRequest2 -Uri "$($Site)/sites/$($siteName)?sw=auth" -Method GET -WebSession $siteSession -ErrorAction SilentlyContinue -Headers $headers
            
            # Validate response
            $baseContent = $response.BaseResponse
            if($baseContent.StatusCode -eq "OK" -and $baseContent.ResponseUri -eq "$($Site)/sites/$($siteName)?sw=auth")
            {
                $requestContent = $response.Content
                
                # Parse digest
                $tempValue = $requestContent -match 'formDigestValue":"(.*?")'
                $digestTemp = $Matches[1]
                $digest = $digestTemp.Split('"')[0]
                $newheaders=@{
                        "X-RequestDigest" = $digest
                    }

                # Parse groupId
                $tempValue = $requestContent -match 'groupId":"(.*?")'
                $groupidTemp = $Matches[1]
                $groupid = $groupidTemp.Split('"')[0]

                # Invoke the request to add a member to the SharePoint site
                $newresponse=Invoke-WebRequest2 -Uri "$($Site)/sites/$($siteName)/_api/SP.Directory.DirectorySession/Group('$($groupid)')/Members/Add(objectId='00000000-0000-0000-0000-000000000000', principalName='$($UserPrincipalName)')" -Method POST -WebSession $siteSession -ErrorAction SilentlyContinue -Headers $newheaders -ContentType "application/json"
                
                # Validate response
                if($newresponse.StatusCode -eq 201 -and $newresponse.StatusDescription -eq "Created")
                {
                    Write-Host "User $($UserPrincipalName) was added to group $($siteName)!"
                }
                else
                {
                    Write-Error "Cannot Add user to the group."
                }
            }
            else
            {
                Write-Error "An error occurred while executing the request to the site."
            }
        }
    }


# Gets information of the given file from the given site
# Nov 28th 2022
function Get-SPOSiteFile
{
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [String]$Site,
        [Parameter(Mandatory=$False)]
        [PSObject]$Id,
        [Parameter(Mandatory=$False)]
        [String]$RelativePath,
        [Parameter(Mandatory=$False)]
        [String]$AuthHeader,
        [Parameter(Mandatory=$False)]
        [String]$AccessToken,
        [Parameter(Mandatory=$False)]
        [Switch]$Download
    )
    Process
    {
        if($Id -eq $null -and [string]::IsNullOrEmpty($RelativePath))
        {
            Throw "Either file Id or RelativePath must be provided"
        }
        $Site=$Site.TrimEnd("/")
        
        $tenant=$Site.Split("/")[2]

        $webUrl = "https://$tenant"

        if(![string]::IsNullOrEmpty($AuthHeader))
        {
            # Create a WebSession object
            $siteSession = Create-WebSession -SetCookieHeader $AuthHeader -Domain $siteDomain
        }
        else
        {
            # Get from cache if not provided
            $AccessToken = Get-AccessTokenFromCache -AccessToken $AccessToken -Resource "https://$Tenant" -ClientId "d3590ed6-52b3-4102-aeff-aad2292ab01c"
            $headers=@{
                "Authorization" = "Bearer $AccessToken"
            }
        }

        # Invoke the initial requests
        try
        {
            if($Id)
            {
                $response = Invoke-WebRequest2 -Uri "$Site/_api/web/GetFileById('$Id')" -Method Get -WebSession $siteSession -Headers $headers -ErrorAction SilentlyContinue
            }
            else
            {
                $siteUrl = $Site.Substring($webUrl.Length)
                $response = Invoke-WebRequest2 -Uri "$Site/_api/web/GetFileByServerRelativePath(decodedurl='$([System.Net.WebUtility]::HtmlEncode("$siteUrl/$RelativePath"))')" -Method Get -WebSession $siteSession -Headers $headers -ErrorAction SilentlyContinue
            }
        }
        catch
        {
            Throw $_.Exception.Message
        }

        if($response.StatusCode -eq 200)
        {
            [xml]$response = $response.Content

            $fileInformation = [PSCustomObject]@{
                "IsPage"           = $response.entry.content.properties.CustomizedPageStatus.'#text' -ne "0"
                "Name"             = $response.entry.content.properties.Name
                "RelativeUrl"      = $response.entry.content.properties.ServerRelativeUrl
                "Id"               = [Guid]$response.entry.content.properties.UniqueId.'#text'
                "TimeCreated"      = [System.DateTime]$response.entry.content.properties.TimeCreated.'#text'
                "TimeLastModified" = [System.DateTime]$response.entry.content.properties.TimeLastModified.'#text'
            }
        }
        Remove-Variable -Name "response"

        # Download the file
        if($Download)
        {
            Invoke-WebRequest2 -Uri "$Site/_api/web/GetFileById('$($fileInformation.Id)')/OpenBinaryStream" -Method Get -WebSession $siteSession -Headers $headers -ErrorAction SilentlyContinue -OutFile $fileInformation.Name

            # Set the timestamps
            (Get-Item -Path $fileInformation.Name).LastWriteTime = $fileInformation.TimeLastModified
            (Get-Item -Path $fileInformation.Name).CreationTime  = $fileInformation.TimeCreated
            Write-Host "File saved to $($fileInformation.Name)"
        }
        else
        {
            # Get ParentId
        
            $response = Invoke-WebRequest2 -Uri "$Site/_api/web/GetFileById('$($fileInformation.Id)')/Properties" -Method Get -WebSession $siteSession -Headers $headers -ErrorAction SilentlyContinue

            if($response.StatusCode -eq 200)
            {
                [xml]$response = $response.Content

                $fileInformation | Add-Member -NotePropertyName "ParentId"   -NotePropertyValue ([Guid]$response.entry.content.properties.vti_x005f_parentid)
                $fileInformation | Add-Member -NotePropertyName "Author"     -NotePropertyValue $response.entry.content.properties.vti_x005f_author
                $fileInformation | Add-Member -NotePropertyName "ModifiedBy" -NotePropertyValue $response.entry.content.properties.vti_x005f_modifiedby
            }

            return $fileInformation
        }

    }
}

# Gets WebId of SPOSite
# Mar 9th 2023
function Get-SPOWebId
{
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [String]$Site,
        [Parameter(Mandatory=$False)]
        [String]$AuthHeader,
        [Parameter(Mandatory=$False)]
        [String]$AccessToken
    )
    Process
    {
        $Site=$Site.TrimEnd("/")
        
        $tenant=$Site.Split("/")[2]

        if(![string]::IsNullOrEmpty($AuthHeader))
        {
            # Create a WebSession object
            $siteSession = Create-WebSession -SetCookieHeader $AuthHeader -Domain $siteDomain
        }
        else
        {
            # Get from cache if not provided
            $AccessToken = Get-AccessTokenFromCache -AccessToken $AccessToken -Resource "https://$Tenant" -ClientId "d3590ed6-52b3-4102-aeff-aad2292ab01c"
            $headers=@{
                "Authorization" = "Bearer $AccessToken"
            }
        }

        # Get WebId 
        $response = Invoke-WebRequest2 -Uri "$Site/_api/web/id" -Method Get -WebSession $siteSession -Headers $headers -ErrorAction SilentlyContinue

        if($response.StatusCode -eq 200)
        {
            [xml]$response = $response.Content

            $retVal = [Guid]$response.id.'#text'
        }

        return $retVal
    }
}

# Gets information of the given folder from the given site
# Mar 9th 2023
function Get-SPOSiteFolder
{
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [String]$Site,
        [Parameter(Mandatory=$False)]
        [PSObject]$Id,
        [Parameter(Mandatory=$False)]
        [String]$RelativePath,
        [Parameter(Mandatory=$False)]
        [String]$AuthHeader,
        [Parameter(Mandatory=$False)]
        [String]$AccessToken
    )
    Process
    {
        if($Id -eq $null -and [string]::IsNullOrEmpty($RelativePath))
        {
            Throw "Either file Id or RelativePath must be provided"
        }
        $Site=$Site.TrimEnd("/")
        
        $tenant=$Site.Split("/")[2]

        if(![string]::IsNullOrEmpty($AuthHeader))
        {
            # Create a WebSession object
            $siteSession = Create-WebSession -SetCookieHeader $AuthHeader -Domain $siteDomain
        }
        else
        {
            # Get from cache if not provided
            $AccessToken = Get-AccessTokenFromCache -AccessToken $AccessToken -Resource "https://$Tenant" -ClientId "d3590ed6-52b3-4102-aeff-aad2292ab01c"
            $headers=@{
                "Authorization" = "Bearer $AccessToken"
            }
        }

        # Invoke the initial requests
        try
        {
            if($Id)
            {
                $response = Invoke-WebRequest2 -Uri "$Site/_api/web/GetFolderById('$Id')" -Method Get -WebSession $siteSession -Headers $headers -ErrorAction SilentlyContinue
            }
            else
            {
                $response = Invoke-WebRequest2 -Uri "$Site/_api/web/GetFolderByServerRelativePath(decodedurl='$([System.Net.WebUtility]::HtmlEncode($RelativePath))')" -Method Get -WebSession $siteSession -Headers $headers -ErrorAction SilentlyContinue
            }
        }
        catch
        {
            throw $_.Exception.Message
        }

        if($response.StatusCode -eq 200)
        {
            [xml]$response = $response.Content

            $folderInformation = [PSCustomObject]@{
                "RelativeUrl"      = $response.entry.content.properties.ServerRelativeUrl
                "Id"               = [Guid]$response.entry.content.properties.UniqueId.'#text'
                "TimeCreated"      = [System.DateTime]$response.entry.content.properties.TimeCreated.'#text'
                "TimeLastModified" = [System.DateTime]$response.entry.content.properties.TimeLastModified.'#text'
            }

            # Parse the full folder name
            $webUrl = "https://$tenant"
            $siteUrl = $Site.Substring($webUrl.Length)
            $folderInformation | Add-Member -NotePropertyName "Name" -NotePropertyValue $folderInformation.RelativeUrl.Substring($siteUrl.Length+1)
        }

        # Get ParentId
        Remove-Variable -Name "response"
        $response = Invoke-WebRequest2 -Uri "$Site/_api/web/GetFolderById('$($folderInformation.Id)')/Properties" -Method Get -WebSession $siteSession -Headers $headers -ErrorAction SilentlyContinue

        if($response.StatusCode -eq 200)
        {
            [xml]$response = $response.Content
            if($response.entry.content.properties.vti_x005f_parentid)
            {
                $folderInformation | Add-Member -NotePropertyName "ParentId" -NotePropertyValue ([Guid]$response.entry.content.properties.vti_x005f_parentid)
            }
            # listid seems to be same as listname, but doesn't exist for all folders
            #if($response.entry.content.properties.vti_x005f_listid)
            #{
            #    $folderInformation | Add-Member -NotePropertyName "ListId"   -NotePropertyValue ([Guid]$response.entry.content.properties.vti_x005f_listid)
            #}
            if($response.entry.content.properties.vti_x005f_listname)
            {
                $folderInformation | Add-Member -NotePropertyName "ListId"   -NotePropertyValue ([Guid]$response.entry.content.properties.vti_x005f_listname)
            }
            if($response.entry.content.properties.vti_x005f_modifiedby)
            {
                $folderInformation | Add-Member -NotePropertyName "ModifiedBy" -NotePropertyValue $response.entry.content.properties.vti_x005f_modifiedby
            }
        }

        return $folderInformation
    }
}

# Downloads the given file from SPO
# Mar 10th 2023
<#
    .SYNOPSIS
    Downloads the given file from SPO

    .DESCRIPTION
    Downloads the given file from SPO

    .Parameter AccessToken
    SharePoint Online Access Token

    .Parameter Site
    The site name

    .Parameter RelativePath
    Path of the file to be exported

    .Example
    PS C:\>Get-AADIntAccessTokenForSPO -SaveToCache
    PS C:\>Export-AADIntSPOSiteFile -Site "https://company.sharepoint.com/sites/Sales" -RelativePath "Shared Documents/General/sales.xlsx"

    File saved to sales.xlsx
#>
function Export-SPOSiteFile
{
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [String]$Site,
        [String]$RelativePath,
        [Parameter(Mandatory=$False)]
        [String]$AuthHeader,
        [Parameter(Mandatory=$False)]
        [String]$AccessToken
    )
    Process
    {
        # Download the file
        Get-SPOSiteFile -AccessToken $AccessToken -AuthHeader $AuthHeader -Site $site -RelativePath $RelativePath -Download
    }
}