﻿# This file contains functions for Teams

# Gets a skype token using Teams accesstoken
# Oct 3rd 2020
function Get-SkypeToken
{
<#
    .SYNOPSIS
    Gets SkypeToken.

    .DESCRIPTION
    Gets SkypeToken.

    .Parameter AccessToken
    The access token used to get the token

    .EXAMPLE
    PS\:>Get-AADIntAccessTokenForTeams -SaveToCache
    PS\:>$skypeToken = Get-AADIntSkypeToken
#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$False)]
        [String]$AccessToken
    )
    Process
    {
        # Get from cache if not provided
        $AccessToken = Get-AccessTokenFromCache -AccessToken $AccessToken -Resource "https://api.spaces.skype.com" -ClientId "1fec8e78-bce4-4aaf-ab1b-5451cc387264" 

        $response = Get-TeamsInformation -AccessToken $AccessToken

        $response.tokens.SkypeToken
    }
}

# Sets user's availability status
# Oct 3rd 2020
function Set-TeamsAvailability
{
<#
    .SYNOPSIS
    Sets the availability status of the user.

    .DESCRIPTION
    Sets the availability status of the user.

    .Parameter AccessToken
    The access token used to set the availability

    .Parameter Status
    The status, one of Available, Busy, DoNotDisturb, BeRightBack, or Away

    .EXAMPLE
    Get-AADIntAccessTokenForTeams -SaveToCache
    PS\:>Set-AADIntTeamsAvailability -Status Busy
#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$False)]
        [String]$AccessToken,
        [Parameter(Mandatory=$False)]
        [ValidateSet("Available","Busy","DoNotDisturb","BeRightBack","Away")]
        [String]$Status="Available"
    )
    Process
    {
        # Get from cache if not provided
        $AccessToken = Get-AccessTokenFromCache -AccessToken $AccessToken -Resource "https://api.spaces.skype.com" -ClientId "1fec8e78-bce4-4aaf-ab1b-5451cc387264" 

        $body="{""availability"":""$Status""}"

        $headers = @{
            "Authorization" = "Bearer $AccessToken"
            "User-Agent" =    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Teams/1.3.00.24755 Chrome/69.0.3497.128 Electron/4.2.12 Safari/537.36"
        }

        Invoke-RestMethod -Method Put -Uri "https://presence.teams.microsoft.com/v1/me/forceavailability/" -Headers $headers -Body $body -ContentType "application/json"

    }
}

# Sets user's Teams statusmessage
# Oct 3rd 2020
function Set-TeamsStatusMessage
{
<#
    .SYNOPSIS
    Sets the Teams status message status of the user.

    .DESCRIPTION
    Sets the Teams status message status of the user.

    .Parameter AccessToken
    The access token used to set the availability

    .Parameter Message
    The status message

    .Parameter Expires
    Expiration time of the message

    .EXAMPLE
    Get-AADIntAccessTokenForTeams -SaveToCache
    PS\:>Set-AADIntTeamsStatusMessage -Message "Out of office til noon"
#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$False)]
        [String]$AccessToken,
        [Parameter(Mandatory=$False)]
        [String]$Message,
        [Parameter(Mandatory=$False)]
        [DateTime]$Expires
    )
    Process
    {
        # Get from cache if not provided
        $AccessToken = Get-AccessTokenFromCache -AccessToken $AccessToken -Resource "https://api.spaces.skype.com" -ClientId "1fec8e78-bce4-4aaf-ab1b-5451cc387264" 

        if($Expires)
        {
            $expiry = $Expires.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ").Replace(".",":")
        }
        else
        {
            $expiry = "9999-12-31T08:00:00.000Z"
        } 

        $body=[ordered]@{
            "message" = $Message
            "expiry" =  $expiry
        }

        $headers = @{
            "Authorization" = "Bearer $AccessToken"
            "User-Agent" =    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Teams/1.3.00.24755 Chrome/69.0.3497.128 Electron/4.2.12 Safari/537.36"
        }

        Invoke-RestMethod -Method Put -Uri "https://presence.teams.microsoft.com/v1/me/publishnote" -Headers $headers -Body ($body | ConvertTo-Json -Compress) -ContentType "application/json;charset=utf-8"

    }
}

# Searches a teams user
# Oct 3rd 2020
function Search-TeamsUser
{
<#
    .SYNOPSIS
    Searhes users with the given searchstring.

    .DESCRIPTION
    Searhes users with the given searchstring.

    .Parameter AccessToken
    The access token used to perform the search

    .Parameter SearchString
    Search string.

    .EXAMPLE
    Get-AADIntAccessTokenForTeams -Resource https://outlook.com -SaveToCache 
    PS C:\>Search-AADIntTeamsUser -SearchString "user" | Format-Table UserPrincipalName,DisplayName

    UserPrincipalName       DisplayName
    -----------------       -----------
    first.user@company.com  First User 
    second.user@company.com Second User
#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$False)]
        [String]$AccessToken,
        [Parameter(Mandatory=$False)]
        [String]$SearchString
    )
    Process
    {
        # Get from cache if not provided
        $AccessToken = Get-AccessTokenFromCache -AccessToken $AccessToken -Resource "https://outlook.com" -ClientId "1fec8e78-bce4-4aaf-ab1b-5451cc387264" 

        $body=@"
         {
	"EntityRequests": [{
			"Query": {
				"QueryString": "$SearchString",
				"DisplayQueryString": ""
			},
			"EntityType": "People",
			"Provenances": ["Mailbox", "Directory"],
			"From": 0,
			"Size": 500,
			
			"Fields": ["Id", "DisplayName", "EmailAddresses", "CompanyName", "JobTitle", "ImAddress", "UserPrincipalName", "ExternalDirectoryObjectId", "PeopleType", "PeopleSubtype", "ConcatenatedId", "Phones", "MRI"],

		}
	],
	"Cvid": "$((New-Guid).ToString())",
	"AppName": "Microsoft Teams",
	"Scenario": {
		"Name": "staticbrowse"
	}
}
"@

        $headers = @{
            "Authorization" = "Bearer $AccessToken"
            "User-Agent" =    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Teams/1.3.00.24755 Chrome/69.0.3497.128 Electron/4.2.12 Safari/537.36"
        }

        $response=Invoke-RestMethod -Method Post -Uri "https://substrate.office.com/search/api/v1/suggestions" -Headers $headers -Body $body -ContentType "application/json"

        $response.Groups.Suggestions 

    }
}

# Sends a message using teams
# Oct 16th 2020
function Send-TeamsMessage
{
<#
    .SYNOPSIS
    Sends a Teams message to given recipients..

    .DESCRIPTION
    Sends a Teams message to given recipients.

    .Parameter AccessToken
    The access token used to send the message.

    .Parameter Recipients
    Email addresses of the recipients

    .Parameter Message
    Message to be sent. If in html, use -Html switch

    .Parameter MessageId
    The client message id of the message. If exists, the content is replaced with the given message.

    .EXAMPLE
    Get-AADIntAccessTokenForTeams -SaveToCache 
    PS C:\>Send-AADIntTeamsMessage -Recipients user@company.com -Message "Hi user!"

    Sent                MessageID         
    ----                ---------         
    16/10/2020 14.40.23 132473328207053858
#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$False)]
        [String]$AccessToken,
        [Parameter(Mandatory=$True)]
        [String[]]$Recipients,
        [Parameter(Mandatory=$True)]
        [String]$Message,
        [switch]$Html,
        [Parameter(Mandatory=$False)]
        [String]$MessageId=(Get-Date).ToFileTimeUtc()
    )
    Process
    {
        # Get from cache if not provided
        $AccessToken = Get-AccessTokenFromCache -AccessToken $AccessToken -Resource "https://api.spaces.skype.com" -ClientId "1fec8e78-bce4-4aaf-ab1b-5451cc387264"

        if($Html)
        {
            $messagetype = "RichText/Html"
            $contenttype = "text"
        }
        else
        {
            $messagetype = "Text"
            $contenttype = "text"
        }

        # Get the settings
        $teamsSettings = Get-TeamsInformation -AccessToken $AccessToken
        $chatService =   $teamsSettings.regionGtms.chatService
        $apiUrl =        $teamsSettings.regionGtms.middleTier
        $skypeToken =    $teamsSettings.tokens.SkypeToken

        # Construct the headers
        $headers = @{
            "Authorization" =  "Bearer $AccessToken"
            "User-Agent" =     "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Teams/1.3.00.24755 Chrome/69.0.3497.128 Electron/4.2.12 Safari/537.36"
            "Authentication" = "skypetoken=$skypeToken"
        }

        # Parse AccessToken to get sender details
        $parsedToken = Read-Accesstoken $AccessToken

        # Get information for the recipient (add empty string to make sure its an array)
        $Recipients += ""
        $recipientInfo = Invoke-RestMethod -Method Post -Uri "$apiUrl/beta/users/fetch?isMailAddress=true&canBeSmtpAddress=false&enableGuest=true&includeIBBarredUsers=true&skypeTeamsInfo=true" -Headers $headers -Body ([String[]]$Recipients|ConvertTo-Json) -ContentType "application/json"

        if($recipientInfo.Value.Count -lt 1)
        {
            Write-Verbose $recipientInfo
            Throw "Recipient not found"
        }

        # Get a new thread for the conversation
        $members=@(
            @{
                "id" =   "8:orgid:$($parsedToken.oid)"
                "role" = "Admin"
            }
        )
        foreach($recipient in $recipientInfo.Value)
        {
            $members += @{
                "id" =   $recipient.mri
                "role" = "Admin"
            }
        }

        $threadBody = @{
            "members" =    $members
            "properties" = @{
                 "threadType" =        "chat"
		        "chatFilesIndexId" =   "2"
		        "uniquerosterthread" = ($members.Count -eq 2).ToString().ToLower()
		        "fixedRoster" =        "true"
            }
        }
        
        $threadResponse = Invoke-WebRequest -Method Post -Uri "$chatService/v1/threads" -Headers $headers -Body ($threadBody | ConvertTo-Json) -ContentType "application/json" -MaximumRedirection 0
        $threadUrl =      $threadResponse.Headers["location"]
        $thread =         $threadUrl.Substring($threadUrl.LastIndexOf("/")+1)

        # Links
        $links=@()
        # Check if we have any links
        if($Html -and $Message.IndexOf("href") -gt -1)
        {
            # Try to convert to xml for parsing..
            try
            {
                [xml]$xmlHtml = $Message
                $messageLinks = Select-Xml -Xml $xmlHtml -XPath "//a"

                for($a = 0; $a -lt $messageLinks.Count ; $a++)
                {
                    $linkUrl = $messageLinks[$a].Node.href
                    $links += @{
                        "@type" =          "http://schema.skype.com/HyperLink"
                        "itemid"=          $a
                        "url"=             $linkUrl
                        "previewenabled" = "false"
                        "preview" = @{
	                        "previewurl" =   ""
	                        "previewmeta" =  ""
	                        "title" =        ""
	                        "description" =  ""
	                        "isLinkUnsafe" = "false"
                        }
                    }
                }
            }
            catch
            {
                Write-Warning "The message contains link(s), but it was not well-formed html. Check the syntax of the message!"
            }
        }

        # Send the message
        $messageBody=@{
	        "content" =         $Message
	        "messagetype"=      $messagetype
	        "contenttype"=      $contenttype
	        "amsreferences" =   @()
	        "clientmessageid" = $MessageId
	        "imdisplayname" =   $parsedToken.name
	        "properties" =      @{"importance" = ""; "subject"= $null; "links" = $links}
        }

        $response=Invoke-RestMethod -Method Post -Uri "$chatService/v1/users/ME/conversations/$thread/messages" -Headers $headers -Body ($messageBody | ConvertTo-Json -Depth 5) -ContentType "application/json; charset=utf-8"
        
        $posted=$epoch.AddMilliseconds($response.OriginalArrivalTime)

        return New-Object psobject -Property @{"MessageID" = $MessageId; "Sent" = $posted}

    }
}


# Get the latest Teams messages
# Oct 16th 2020
function Get-TeamsMessages
{
<#
    .SYNOPSIS
    Gets user's latest Teams messages.

    .DESCRIPTION
    Gets user's latest Teams messages.

    .Parameter AccessToken
    The access token used to get the messages

    .EXAMPLE
    Get-AADIntAccessTokenForTeams -SaveToCache 
    PS C:\>Get-AADIntTeamsMessages | Format-Table id,content,deletiontime,*type*,DisplayName

    Id            Content                         DeletionTime  MessageType   Type          DisplayName 
    --            -------                         ------------  -----------   ----          ----------- 
    1602842299338                                 1602846853687 RichText/Html MessageUpdate Bad User
    1602844861358                                 1602858789696 RichText/Html MessageUpdate Bad User
    1602846167606                                 1602858792943 Text          MessageUpdate Bad User
    1602846853687                                 1602858795517 Text          MessageUpdate Bad User
    1602833251951                                 1602833251951 Text          MessageUpdate Bad User
    1602833198442                                 1602833198442 Text          MessageUpdate Bad User
    1602859223294 Hola User!                                    Text          NewMessage    Bad User
    1602859423019 Hi User!                                      Text          NewMessage    Bad User
    1602859423019 Hi User!                                      Text          MessageUpdate Bad User
    1602859473083 <div><div>Hi User!</div></div>                RichText/Html NewMessage    Bad User
    1602859484420 Hey User!                                     Text          NewMessage    Bad User
    1602859528028 Hy User!                                      Text          NewMessage    Bad User
    1602859484420 Hey User!                                     Text          MessageUpdate Bad User
    1602859590916 Hi User!                                      Text          NewMessage    Bad User

#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$False)]
        [String]$AccessToken
    )
    Process
    {
        # Get from cache if not provided
        $AccessToken = Get-AccessTokenFromCache -AccessToken $AccessToken -Resource "https://api.spaces.skype.com" -ClientId "1fec8e78-bce4-4aaf-ab1b-5451cc387264"

        # Endpoint
        $endPoint = (New-Guid).ToString()

        # Get the settings
        $teamsSettings = Get-TeamsInformation -AccessToken $AccessToken
        $chatService =   $teamsSettings.regionGtms.chatService
        $skypeToken =    $teamsSettings.tokens.SkypeToken

        # Construct the headers
        $headers = @{
            "Authorization" =  "Bearer $AccessToken"
            "User-Agent" =     "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Teams/1.3.00.24755 Chrome/69.0.3497.128 Electron/4.2.12 Safari/537.36"
            "Authentication" = "skypetoken=$skypeToken"
        }

        $body=@"
        {
	        "startingTimeSpan": 0,
	        "endpointFeatures": "Agent,Presence2015,MessageProperties,CustomUserProperties,NotificationStream,SupportsSkipRosterFromThreads",
	        "subscriptions": [{
			        "channelType": "HttpLongPoll",
			        "interestedResources": ["/v1/users/ME/conversations/ALL/properties", "/v1/users/ME/conversations/ALL/messages", "/v1/threads/ALL"]
		        }
	        ]
        }
"@
        $response = Invoke-RestMethod -Method Put -Uri "$chatService/v2/users/ME/endpoints/$endPoint" -Headers $headers -Body $body -ContentType "application/json; charset=utf-8"
        
        $pollUrl = $response.subscriptions[0].longPollUrl
        if($pollUrl.contains("?"))
        {
            $pollUrl = $pollUrl.Split("?")[0]
        }
        
        $pollResponse = Invoke-RestMethod -Method Get -Uri "$pollUrl" -Headers $headers

        foreach($message in $pollResponse.eventMessages)
        {
            if($message.resourceType -like "*Message*" -and $message.resource.contenttype -eq "text")
            {
                $attributes = [ordered]@{
                    "ClientMessageId" = $message.resource.clientmessageid
                    "Id" =              $message.resource.id
                    "MessageType" =     $message.resource.messageType
                    "DisplayName" =     $message.resource.imdisplayname
                    "ArrivalTime" =     $message.resource.originalarrivaltime
                    "DeletionTime" =    $message.resource.properties.deletetime
                    "Link" =            $message.resource.conversationLink.Substring($message.resource.conversationLink.LastIndexOf("/")+1)
                    "Content" =         $message.resource.content
                    "Type" =            $message.resourceType
                }

                New-Object psobject -Property $attributes
            }
        }
        
    }
}


# Deletes Teams messages
# Oct 16th 2020
function Remove-TeamsMessages
{
<#
    .SYNOPSIS
    Deletes given Teams messages.

    .DESCRIPTION
    Deletes given Teams messages.

    .Parameter AccessToken
    The access token used to get the messages

    .Parameter MessageIDs
    List of IDs of the messages to be deleted

    .Parameter DeleteType
    Deletion type, can be either SoftDelete or HardDelete. Defaults to HardDelete. Soft deleted messages can be restored from the UI.

    .EXAMPLE
    Get-AADIntAccessTokenForTeams -SaveToCache 
    PS C:\>Get-AADIntTeamsMessages | Format-Table id,content,deletiontime,*type*,DisplayName

    Id            Content                         DeletionTime  MessageType   Type          DisplayName 
    --            -------                         ------------  -----------   ----          ----------- 
    1602842299338                                 1602846853687 RichText/Html MessageUpdate Bad User
    1602844861358                                 1602858789696 RichText/Html MessageUpdate Bad User
    1602846167606                                 1602858792943 Text          MessageUpdate Bad User
    1602846853687                                 1602858795517 Text          MessageUpdate Bad User
    1602833251951                                 1602833251951 Text          MessageUpdate Bad User
    1602833198442                                 1602833198442 Text          MessageUpdate Bad User
    1602859223294 Hola User!                                    Text          NewMessage    Bad User
    1602859423019 Hi User!                                      Text          NewMessage    Bad User
    1602859423019 Hi User!                                      Text          MessageUpdate Bad User
    1602859473083 <div><div>Hi User!</div></div>                RichText/Html NewMessage    Bad User
    1602859484420 Hey User!                                     Text          NewMessage    Bad User
    1602859528028 Hy User!                                      Text          NewMessage    Bad User
    1602859484420 Hey User!                                     Text          MessageUpdate Bad User
    1602859590916 Hi User!                                      Text          NewMessage    Bad User

    PS C:\>Remove-AADIntTeamsMessages -MessageIDs 1602859590916,1602859484420

#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$False)]
        [String]$AccessToken,
        [Parameter(Mandatory=$True)]
        [String[]]$MessageIDs,
        [Parameter(Mandatory=$False)]
        [ValidateSet("HardDelete","SoftDelete")]
        [String]$DeleteType="HardDelete"
    )
    Process
    {
        # Get from cache if not provided
        $AccessToken = Get-AccessTokenFromCache -AccessToken $AccessToken -Resource "https://api.spaces.skype.com" -ClientId "1fec8e78-bce4-4aaf-ab1b-5451cc387264"

        # Get the settings
        $teamsSettings = Get-TeamsInformation -AccessToken $AccessToken
        $chatService =   $teamsSettings.regionGtms.chatService
        $skypeToken =    $teamsSettings.tokens.SkypeToken

        # Construct the headers
        $headers = @{
            "Authorization" =  "Bearer $AccessToken"
            "User-Agent" =     "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Teams/1.3.00.24755 Chrome/69.0.3497.128 Electron/4.2.12 Safari/537.36"
            "Authentication" = "skypetoken=$skypeToken"
        }

        # Get the latest messages
        $messages = Get-TeamsMessages -AccessToken $AccessToken

        # Loop through the messages and delete when the correct ones if found
        foreach($message in $messages)
        {
            if($MessageIDs -contains $message.Id)
            {
                try
                {
                    $response = Invoke-RestMethod -Method Delete -Uri "$chatService/v1/users/ME/conversations/$($message.Link)/messages/$($message.Id)`?behavior=$DeleteType" -Headers $headers -ErrorAction SilentlyContinue
                }
                catch{
                    Write-Warning "MessageId $($message.Id):`n$(($_.ErrorDetails.Message | ConvertFrom-Json).message)"
                }
               
            }
        }
   
    }
}