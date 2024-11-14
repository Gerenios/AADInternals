# This file contains functions for Teams

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

        $response = Get-TeamsUserSettings -AccessToken $AccessToken

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

        Invoke-RestMethod -UseBasicParsing -Method Put -Uri "https://presence.teams.microsoft.com/v1/me/forceavailability/" -Headers $headers -Body $body -ContentType "application/json"

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
    The access token used to set the status message

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
            $expiry = $Expires.ToUniversalTime().ToString("s", [cultureinfo]::InvariantCulture)+"Z"
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

        Invoke-RestMethod -UseBasicParsing -Method Put -Uri "https://presence.teams.microsoft.com/v1/me/publishnote" -Headers $headers -Body ($body | ConvertTo-Json -Compress) -ContentType "application/json;charset=utf-8"

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

        $response=Invoke-RestMethod -UseBasicParsing -Method Post -Uri "https://substrate.office.com/search/api/v1/suggestions" -Headers $headers -Body $body -ContentType "application/json"

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

    .Parameter ClientMessageId
    The client message id of the message. If exists, the content is replaced with the given message.

    .Parameter Thread
    The conversation thread of existing chat or channel.

    .EXAMPLE
    Get-AADIntAccessTokenForTeams -SaveToCache 
    PS C:\>Send-AADIntTeamsMessage -Recipients user@company.com -Message "Hi user!"

    Sent                ClientMessageID         
    ----                ---------         
    16/10/2020 14.40.23 132473328207053858

    .EXAMPLE
    Get-AADIntAccessTokenForTeams -SaveToCache 
    PS C:\>Get-AADIntTeamsMessages | Select Link

    Link                                                                                       
    ----                                                                                       
    19:a84fdc0c-519c-4467-b2e6-323a48ce09af_4d40755a-020b-422b-b9cf-2f1f50602377@unq.gbl.spaces
    19:a84fdc0c-519c-4467-b2e6-323a48ce09af_4d40755a-020b-422b-b9cf-2f1f50602377@unq.gbl.spaces
    19:292f1d53677d45ff9d61d333cb0b4853@thread.tacv2                                           
    19:292f1d53677d45ff9d61d333cb0b4853@thread.tacv2                                           
    19:292f1d53677d45ff9d61d333cb0b4853@thread.tacv2                                           

    PS C:\>Send-AADIntTeamsMessage -Thread 19:292f1d53677d45ff9d61d333cb0b4853@thread.tacv2 -Message "Hi there!"

    Sent                ClientMessageID         
    ----                ---------         
    16/10/2020 14.40.23 132473328207053858
#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$False)]
        [String]$AccessToken,
        [Parameter(ParameterSetName = "New", Mandatory=$True)]
        [String[]]$Recipients,
        [Parameter(Mandatory=$True)]
        [String]$Message,
        [switch]$Html,
        [Parameter(ParameterSetName = "Existing", Mandatory=$True)]
        [String]$ClientMessageId,
        [Parameter(ParameterSetName = "Thread", Mandatory=$True)]
        [String]$Thread,
        [bool]$External = $false,
        [bool]$FakeInternal = $false
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
        $teamsSettings = Get-TeamsUserSettings -AccessToken $AccessToken
        $chatService =   $teamsSettings.regionGtms.chatService
        $apiUrl =        $teamsSettings.regionGtms.middleTier
        $skypeToken =    $teamsSettings.tokens.SkypeToken

        # Construct the headers
        $headers = @{
            "Authorization" =       "Bearer $AccessToken"
            "User-Agent" =          "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Teams/1.3.00.24755 Chrome/69.0.3497.128 Electron/4.2.12 Safari/537.36"
            "Authentication" =      "skypetoken=$skypeToken"
            "x-ms-client-version" = "27/1.0.0.2020101241"
        }

        # Parse AccessToken to get sender details
        $parsedToken = Read-Accesstoken $AccessToken

        # If the client message is given, find the message and corresponding id
        if($ClientMessageId)
        {
            $response = Get-TeamsMessage -AccessToken $AccessToken -ClientMessageId $ClientMessageId
            if(!$response)
            {
                throw "Message ($ClientMessageId) not found! Check the ClientMessageId and try again."
            }

            $thread = $response.Link
        }
        elseif($Thread) # Thread is given, so post message to there
        {
            $ClientMessageId=(Get-Date).ToFileTimeUtc()
        }
        else # A new message
        {
            $ClientMessageId=(Get-Date).ToFileTimeUtc()

            $msgRecipients = @()

            if($External)
            {
                foreach($recipient in $Recipients)
                {
                    try
                    {
                        if(![string]::IsNullOrEmpty($recipient))
                        {
                            $msgRecipients += Invoke-RestMethod -UseBasicParsing -Method Get -Uri "https://teams.microsoft.com/api/mt/part/emea-02/beta/users/$recipient/externalsearchv3" -Headers $headers                }
                        }
                    catch
                    {
                        # Okay, federation doesn't exists etc.
                    }
                }
            }
            else
            {
                $msgRecipients = Get-TeamsRecipients -AccessToken $AccessToken -Recipients $Recipients
            }

            if(!$msgRecipients.Count)
            {
                # Just one found so create an array
                $newRecipients = @($msgRecipients)
                Remove-Variable "msgRecipients"
                $msgRecipients = $newRecipients
            }
            elseif($msgRecipients.Count -lt 1)
            {
                Throw "Recipient not found"
            }

            # Get a new thread for the conversation
            $members=@(
                @{
                    "id" =   "8:orgid:$($parsedToken.oid)"
                    "role" = "Admin"
                }
            )
            foreach($recipient in $msgRecipients)
            {
                $members += @{
                    "id" =   $recipient.mri
                    "role" = "Admin"
                }
            }

            if($External -and !$FakeInternal)
            {
                $threadBody = @{
                    "members" =    $members
                    "properties" = @{
                        "threadType" =         "sfbinteropchat"
		                "chatFilesIndexId" =   "2"
                        "isFederated" =        "true"
		                "uniquerosterthread" = ($members.Count -eq 2).ToString().ToLower()
		                "fixedRoster" =        "true"
                    }
                }
            }
            else
            {
                $threadBody = @{
                    "members" =    $members
                    "properties" = @{
                         "threadType" =        "chat"
		                "chatFilesIndexId" =   "2"
		                "uniquerosterthread" = ($members.Count -eq 2).ToString().ToLower()
		                "fixedRoster" =        "true"
                    }
                }
            }
        
            $threadResponse = Invoke-WebRequest2 -Method Post -Uri "$chatService/v1/threads" -Headers $headers -Body ($threadBody | ConvertTo-Json) -ContentType "application/json" -MaximumRedirection 0
            $threadUrl =      $threadResponse.Headers["location"]
            $thread =         $threadUrl.Substring($threadUrl.LastIndexOf("/")+1)
        }

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
	        "clientmessageid" = $ClientMessageId
	        "imdisplayname" =   $parsedToken.name
	        "properties" =      @{
                    "importance" = ""; 
                    "subject"= $null; 
                    "links" = $links
                    }
        }
        if($External -and !$FakeInternal)
        {
            $messageBody["properties"]["interopType"]="receiverSfB"
            $messageBody["fromSipUri"] = $parsedToken.upn
            $messageBody["toSipUri"] =   $msgRecipients | Select-Object -ExpandProperty email
        }

        if($FakeInternal)
        {
            # Fake internal by removing the "fed." from the thread
            # This allows sending rich text to external users too.
            $Thread = $Thread.Replace("@fed.","@")
        }

        $response=Invoke-RestMethod -UseBasicParsing -Method Post -Uri "$chatService/v1/users/ME/conversations/$thread/messages" -Headers $headers -Body ($messageBody | ConvertTo-Json -Depth 5) -ContentType "application/json; charset=utf-8"
        
        $posted=$epoch.AddMilliseconds($response.OriginalArrivalTime)

        return New-Object psobject -Property @{"ClientMessageID" = $ClientMessageId; "Sent" = $posted}

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
        $teamsSettings = Get-TeamsUserSettings -AccessToken $AccessToken
        $chatService =   $teamsSettings.regionGtms.chatService
        $skypeToken =    $teamsSettings.tokens.SkypeToken

        # Construct the headers
        $headers = @{
            "Authorization" =  "Bearer $AccessToken"
            "User-Agent" =     "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Teams/1.3.00.24755 Chrome/69.0.3497.128 Electron/4.2.12 Safari/537.36"
            "Authentication" = "skypetoken=$skypeToken"
        }

        $conversations = Invoke-RestMethod -UseBasicParsing -Method Get -Uri "$chatService/v1/users/ME/conversations" -Headers $headers
        
        foreach($conversation in $conversations.conversations)
        {
            $id = $conversation.id

            
            try
            {
                if($id.startsWith("19:"))
                {
                    $chatMessages = Invoke-RestMethod -UseBasicParsing -Method Get -Uri "$chatService/v1/users/ME/conversations/$id/messages?startTime=0&view=msnp24Equivalent" -Headers $headers
                }

                foreach($message in $chatMessages.messages)
                {
                    if($message.type -like "*Message*" -and $message.contenttype -eq "text")
                    {
                        $attributes = [ordered]@{
                            "ClientMessageId" = $message.clientmessageid
                            "Id" =              $message.id
                            "MessageType" =     $message.messageType
                            "DisplayName" =     $message.imdisplayname
                            "ArrivalTime" =     $message.originalarrivaltime
                            "DeletionTime" =    $message.properties.deletetime
                            "Link" =            $message.conversationid
                            "Content" =         $message.content
                            "Type" =            $message.type
                        }

                        New-Object psobject -Property $attributes
                    }
                }
            }
            catch
            {
                Write-Verbose "$(($_.ErrorDetails.Message | ConvertFrom-Json).message)"
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
        $teamsSettings = Get-TeamsUserSettings -AccessToken $AccessToken
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
                    $response = Invoke-RestMethod -UseBasicParsing -Method Delete -Uri "$chatService/v1/users/ME/conversations/$($message.Link)/messages/$($message.Id)`?behavior=$DeleteType" -Headers $headers -ErrorAction SilentlyContinue
                }
                catch{
                    Write-Warning "MessageId $($message.Id):`n$(($_.ErrorDetails.Message | ConvertFrom-Json).message)"
                }
               
            }
        }
   
    }
}

# Sets the emotion for the given message
# Oct 26th 2020
function Set-TeamsMessageEmotion
{
<#
    .SYNOPSIS
    Sets emotion for the given Teams message.

    .DESCRIPTION
    Sets emotion for the given Teams message.

    .Parameter AccessToken
    The access token used to get the messages

    .Parameter MessageID
    The id of the message

    .Parameter ConversationID
    The id of the message conversation

    .Parameter Clear
    Clear the given emotion.

    .Parameter Emotion
    The emotion to be added. One of like, heart, laugh, surprised, sad, or angry

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

    PS C:\>Set-AADIntTeamsMessageEmotion -MessageID 1602859223294 -Emotion like

#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$False)]
        [String]$AccessToken,
        [Parameter(Mandatory=$True)]
        [String]$MessageID,
        [Parameter(Mandatory=$False)]
        [String]$ConversationID,
        [Parameter(Mandatory=$False)]
        [psobject]$TeamsSettings,
        [Parameter(Mandatory=$True)]
        [ValidateSet("like","heart","laugh","surprised","sad","angry")]
        [String]$Emotion,
        [switch]$Clear
    )
    Process
    {
        # Get from cache if not provided
        $AccessToken = Get-AccessTokenFromCache -AccessToken $AccessToken -Resource "https://api.spaces.skype.com" -ClientId "1fec8e78-bce4-4aaf-ab1b-5451cc387264"

        # Get the settings
        if(!$TeamsSettings)
        {
            $TeamsSettings = Get-TeamsUserSettings -AccessToken $AccessToken
        }
        $chatService =   $TeamsSettings.regionGtms.chatService
        $skypeToken =    $TeamsSettings.tokens.SkypeToken

        # Construct the headers
        $headers = @{
            "Authorization" =  "Bearer $AccessToken"
            "User-Agent" =     "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Teams/1.3.00.24755 Chrome/69.0.3497.128 Electron/4.2.12 Safari/537.36"
            "Authentication" = "skypetoken=$skypeToken"
        }

        # If conversation id not given, try to find one
        if([String]::IsNullOrEmpty($ConversationID))
        {
            $conversations = Invoke-RestMethod -Method Get -Uri "$chatService/v1/users/ME/conversations" -Headers $headers
            foreach($conversation in $conversations.conversations)
            {
                try
                {
                    $response = Invoke-RestMethod -UseBasicParsing -Method Get -Uri "$chatService/v1/users/ME/conversations/$($conversation.id)/messages/$MessageID" -Headers $headers -ErrorAction SilentlyContinue
                    $ConversationID = $conversation.id
                    break
                }
                catch{
                    # Okay, not a correct conversation
                }
            }
        }

        try
        {
            if($Clear)
            {
                $headers["x-ms-client-caller"] = "updateMessageReactionRemove"
                $body = "{""emotions"":""{\""key\"":\""$Emotion\""}""}"
                $method = "Delete"
            }
            else
            {
                $headers["x-ms-client-caller"] = "updateMessageReactionAdd"
                $body = "{""emotions"":""{\""key\"":\""$Emotion\"",\""value\"":$([long]((Get-Date)-$epoch).TotalMilliseconds)}""}"
                $method = "Put"
            }

            $continue = $true
            while($continue)
            {
                try
                {
                    $response = Invoke-RestMethod -UseBasicParsing -Method $method -Uri "$chatService/v1/users/ME/conversations/$ConversationID/messages/$MessageID/properties?name=emotions" -Headers $headers -Body $body
                    $continue = $false
                }
                catch
                {
                    if($_.Exception.Response.StatusCode -eq 429)
                    {
                        if($_.Exception.Response.Headers["Retry-After"])
                        {
                            $retryAfter = ([datetime]$_.Exception.Response.Headers["Retry-After"]).Second
                            Write-Warning "Retrying after $($retryAfter)s"
                            Start-Sleep -Seconds $retryAfter
                        }
                        else
                        {
                            throw $_
                        }
                    }
                    else
                    {
                        throw $_
                    }
                }
            }

        }
        catch{
            Throw $_
        }
 
    }
}


# Get a teams message with clientmessageid
# Oct 26th 2020
function Get-TeamsMessage
{

    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [String]$AccessToken,
        [Parameter(Mandatory=$True)]
        [String]$ClientMessageId
    )
    Process
    {
        $messages = Get-TeamsMessages -AccessToken $AccessToken

        foreach($message in $messages)
        {
            if($message.clientmessageid -eq $ClientMessageId)
            {
                return $message
            }
        }
    }
}

# Get user's Teams memberships (Teams' and chats)
# May 11th 2021
function Get-TeamsMemberships
{

   [cmdletbinding()]
    Param()
    Process
    {
        # Get access token from cache
        $AccessToken = Get-AccessTokenFromCache -AccessToken $AccessToken -Resource "https://api.spaces.skype.com" -ClientId "1fec8e78-bce4-4aaf-ab1b-5451cc387264"

        # Try to get a new access token for chat service using cached refreshtoken
		$refreshToken = Get-RefreshTokenFromCache -ClientID "1fec8e78-bce4-4aaf-ab1b-5451cc387264" -Resource "https://api.spaces.skype.com"
        if(!$refreshToken)
        {
            Throw "No refresh token found!"
        }
        $AccessToken2 = Get-AccessTokenWithRefreshToken -Resource "https://chatsvcagg.teams.microsoft.com" -ClientId "1fec8e78-bce4-4aaf-ab1b-5451cc387264" -RefreshToken $refreshToken -TenantId (Read-Accesstoken $AccessToken).tid

        # Get the settings
        $teamsSettings = Get-TeamsUserSettings -AccessToken $AccessToken
        $skypeToken =    $teamsSettings.tokens.SkypeToken

        # Construct the headers
        $headers = @{
            "Authorization" = "Bearer $AccessToken2"
            "User-Agent" =    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Teams/1.3.00.24755 Chrome/69.0.3497.128 Electron/4.2.12 Safari/537.36"
            "x-skypetoken" =  "$skypeToken"
        }

        $membershipInfo = Invoke-RestMethod -UseBasicParsing -Method Get -Uri "https://teams.microsoft.com/api/csa/api/v1/teams/users/me?isPrefetch=false&enableMembershipSummary=true" -Headers $headers
        
        return $membershipInfo
  
    }
}

# Removes a teams member from a given thread
# May 11th 2021
function Remove-TeamsMember
{
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$False)]
        [String]$AccessToken,
        [Parameter(Mandatory=$True)]
        [String]$User,
        [Parameter(Mandatory=$True)]
        [String]$Thread
    )
    Process
    {
        # Get from cache if not provided
        $AccessToken = Get-AccessTokenFromCache -AccessToken $AccessToken -Resource "https://api.spaces.skype.com" -ClientId "1fec8e78-bce4-4aaf-ab1b-5451cc387264"

        # Get the settings
        $teamsSettings =            Get-TeamsUserSettings -AccessToken $AccessToken
        $teamsAndChannelsService =  $teamsSettings.regionGtms.teamsAndChannelsService
        $skypeToken =               $teamsSettings.tokens.SkypeToken

        # Construct the headers
        $headers = @{
            "Authorization" = "Bearer $AccessToken"
            "User-Agent" =    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Teams/1.3.00.24755 Chrome/69.0.3497.128 Electron/4.2.12 Safari/537.36"
            "X-Skypetoken" =  $skypeToken
            "Accept" =        "application/json"
        }

        # Get the recipient info
        $recipient = Get-TeamsRecipients -AccessToken $AccessToken -Recipients $User

        $body = @{
            "teamMri" =    $Thread
            "userMri" =    $recipient.Mri
            "updateType" = "Left"
        }
       
        $response = Invoke-RestMethod -UseBasicParsing -Method Put -Uri "$teamsAndChannelsService/beta/teams/$Thread/members?allowBotsInChannel=true" -Headers $headers -Body ($body|ConvertTo-Json) -ContentType "application/json"
    }
}

# Adds a new teams member to the given thread
# May 11th 2021
function Add-TeamsMember
{
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$False)]
        [String]$AccessToken,
        [Parameter(Mandatory=$True)]
        [String]$User,
        [Parameter(Mandatory=$True)]
        [String]$Thread
    )
    Process
    {
        # Get from cache if not provided
        $AccessToken = Get-AccessTokenFromCache -AccessToken $AccessToken -Resource "https://api.spaces.skype.com" -ClientId "1fec8e78-bce4-4aaf-ab1b-5451cc387264"

        # Get the settings
        $teamsSettings =            Get-TeamsUserSettings -AccessToken $AccessToken
        $teamsAndChannelsService =  $teamsSettings.regionGtms.teamsAndChannelsService
        $skypeToken =               $teamsSettings.tokens.SkypeToken

        # Construct the headers
        $headers = @{
            "Authorization" = "Bearer $AccessToken"
            "User-Agent" =    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Teams/1.3.00.24755 Chrome/69.0.3497.128 Electron/4.2.12 Safari/537.36"
            "X-Skypetoken" =  $skypeToken
            "Accept" =        "application/json"
        }

        # Get the recipient info
        $recipient = Get-TeamsRecipients -AccessToken $AccessToken -Recipients $User

        $body = @{ "users" = @(@{
                                "mri" =  $recipient.mri
                                "role" = 2
                             })}

        $response = Invoke-RestMethod -UseBasicParsing -Method Put -Uri "$teamsAndChannelsService/beta/teams/$Thread/bulkUpdateRoledMembers?allowBotsInChannel=true" -Headers $headers -Body ($body|ConvertTo-Json) -ContentType "application/json"

        if($response.value.updatedUsers[0].errorType)
        {
            Write-Error $response.value.updatedUsers[0].errorType
        }
        
    }
}


# Finds the external Teams user
# Feb 2nd 2022
function Find-TeamsExternalUser
{
<#
    .SYNOPSIS
    Finds the given external Teams user.

    .DESCRIPTION
    Finds the given external Teams user.


    .Parameter AccessToken
    The access token used to get user information

    .EXAMPLE
    PS\:>Get-AADIntAccessTokenForTeams -SaveToCache
    PS\:>Find-AADIntTeamsExternalUser -UserPrincipalName JohnD@company.com

    tenantId          : dcc7d7bf-e3f5-4778-b6e0-aa7207bdb033
    isShortProfile    : False
    accountEnabled    : True
    featureSettings   : @{coExistenceMode=TeamsOnly}
    userPrincipalName : johnd@company.com
    givenName         : JohnD@company.com
    surname           : 
    email             : JohnD@company.com
    displayName       : John Doe
    type              : Federated
    mri               : 8:orgid:84bdccdb-eaba-4545-9729-4eff71b76841
    objectId          : fe401a12-879c-4e5b-8b51-03e1985fa62f
#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$False)]
        [String]$AccessToken,
        [Parameter(Mandatory=$True)]
        [String]$UserPrincipalName
    )
    Process
    {
        # Get from cache if not provided
        $AccessToken = Get-AccessTokenFromCache -AccessToken $AccessToken -Resource "https://api.spaces.skype.com" -ClientId "1fec8e78-bce4-4aaf-ab1b-5451cc387264" 

        # Get the API url
        $url=(Get-TeamsUserSettings -AccessToken $AccessToken).regionGtms.appService

        $headers = @{
            "Authorization" = "Bearer $AccessToken"
            "User-Agent" =    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Teams/1.3.00.24755 Chrome/69.0.3497.128 Electron/4.2.12 Safari/537.36"
            "x-ms-client-version" = 666
        }

        try
        {
            Invoke-RestMethod -UseBasicParsing -Method Get -Uri "$url/beta/users/$UserPrincipalName/externalsearchv3?includeTFLUsers=true" -Headers $headers -ContentType "application/json"
        }
        catch
        {
            Write-Error $_.Exception.Message
        }

    }
}


# Get the availability of the user
# Feb 2nd 2022
function Get-TeamsAvailability
{
<#
    .SYNOPSIS
    Shows the availability of the given user.

    .DESCRIPTION
    Shows the availability of the given user.


    .Parameter AccessToken
    The access token used to get the availability
    
    .Parameter ObjectId
    The Azure AD Object ID of the target user.

    .EXAMPLE
    PS\:>Get-AADIntAccessTokenForTeams -SaveToCache

    .EXAMPLE
    PS\:>Get-AADIntAccessTokenForTeams -SaveToCache
    PS\:>Find-AADIntTeamsExternalUser -UserPrincipalName JohnD@company.com

    tenantId          : dcc7d7bf-e3f5-4778-b6e0-aa7207bdb033
    isShortProfile    : False
    accountEnabled    : True
    featureSettings   : @{coExistenceMode=TeamsOnly}
    userPrincipalName : johnd@company.com
    givenName         : JohnD@company.com
    surname           : 
    email             : JohnD@company.com
    displayName       : John Doe
    type              : Federated
    mri               : 8:orgid:84bdccdb-eaba-4545-9729-4eff71b76841
    objectId          : fe401a12-879c-4e5b-8b51-03e1985fa62f

    PS\:>Get-AADIntTeamsAvailability -ObjectId "fe401a12-879c-4e5b-8b51-03e1985fa62f"

    sourceNetwork : Federated
    capabilities  : {Audio, Video}
    availability  : Away
    activity      : Away
    deviceType    : Desktop
#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$False)]
        [String]$AccessToken,
        [Parameter(ParameterSetName='ObjectId',Mandatory=$True)]
        [Guid]$ObjectId,
        [Parameter(ParameterSetName='UserPrincipalName',Mandatory=$True)]
        [String]$UserPrincipalName
    )
    Process
    {
        # Get from cache if not provided
        $AccessToken = Get-AccessTokenFromCache -AccessToken $AccessToken -Resource "https://api.spaces.skype.com" -ClientId "1fec8e78-bce4-4aaf-ab1b-5451cc387264" 

        if($UserPrincipalName)
        {
            try
            {
                $extUserResponse = Find-TeamsExternalUser -AccessToken $AccessToken -UserPrincipalName $UserPrincipalName
                if($extUserResponse -is [System.Array])
                {
                    $ObjectId = $extUserResponse[0].objectId
                }
                else
                {
                    $ObjectId = $extUserResponse.objectId
                }
            }
            catch
            {
                return $null
            }
        }

        $headers = @{
            "Authorization" = "Bearer $AccessToken"
        }

        $body = "[{""mri"":""8:orgid:$ObjectId""}]"

        try
        {
            $response = Invoke-RestMethod -UseBasicParsing -Method Post -Uri "https://presence.teams.microsoft.com/v1/presence/getpresence" -Headers $headers -ContentType "application/json" -Body $body
        }
        catch
        {
            Write-Error $_.Exception.Message
        }

        $response.presence
    }
}



# Translate the given text to given language
# Mar 21st 2022
function Get-Translation
{
<#
    .SYNOPSIS
    Translate the given text to the given language.

    .DESCRIPTION
    Translate the given text to the given language using Teams internal API.


    .Parameter AccessToken
    The access token used to get the availability
    
    .Parameter Language
    The language code. Defaults to "en-US"

    .EXAMPLE
    PS\:>Get-AADIntAccessTokenForTeams -SaveToCache
    PS\:>Get-AADIntTranslation -Text "Terve Maailma!" -Language "en-US"
    Hello World!

#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$False)]
        [String]$AccessToken,
        [Parameter(Mandatory=$True)]
        [String]$Text,
        [Parameter(Mandatory=$False)]
        [String]$Language = "en-US"
    )
    Process
    {
        # Get from cache if not provided
        $AccessToken = Get-AccessTokenFromCache -AccessToken $AccessToken -Resource "https://api.spaces.skype.com" -ClientId "1fec8e78-bce4-4aaf-ab1b-5451cc387264" 

        # Get the settings
        try
        {
            $teamsSettings = Get-TeamsUserSettings -AccessToken $AccessToken
            $apiUrl =        $teamsSettings.regionGtms.middleTier
        }
        catch
        {
            $apiUrl = "https://teams.microsoft.com/api/mt/part/amer-01"
        }

        $body = @{
            "texts" = @($Text)
            "toLanguage" = $Language
        }

        $headers = @{
            "Authorization" = "Bearer $AccessToken"
        }
        
        try
        {
            $response = Invoke-RestMethod -UseBasicParsing -Method Post -Uri "$apiUrl/beta/translate" -Headers $headers -ContentType "application/json; charset=utf-8" -Body ($body | ConvertTo-Json -Compress)

            $lang = $response[0].detectedLanguage.language
            $score = [int](([double]$response[0].detectedLanguage.score)*100)

            Write-Verbose "Detected language: $lang ($score %)"

            $response[0].text
        }
        catch
        {
            Throw $_.Exception.Message
        }
    }
}

# Gets list of current user's Teams
# Aug 15 2023
function Get-MyTeams
{
<#
    .SYNOPSIS
    Returns all teams the user is member of.

    .DESCRIPTION
    Returns all teams the user is member of.
    
    .Parameter AccessToken
    The access token used to get teams
    
    .Parameter Owner
    Return only Teams where the user is owner.

    .EXAMPLE
    PS\:>Get-AADIntAccessTokenForTeams -SaveToCache
    PS\:>Get-AADIntMyTeams
    
    id                                   displayName site                                                 
    --                                   ----------- ----                                                 
    afa3b2d4-79d8-4a00-bfb2-070b58af26fc Sales       https://company.sharepoint.com/sites/Sales
    eb780ae6-9f80-4ad3-9219-0deee278fb2a Marketing   https://company.sharepoint.com/sites/Marketing
    0ab1c9ec-629a-4412-8e65-348bd1ed4fe8 All Hands   https://company.sharepoint.com/sites/AllHAnds
    5521cd57-f814-4564-85ae-0e8c644a2a96 London      https://company.sharepoint.com/sites/London
    0bf31a81-4833-4421-a1ff-5d4efb669d4b Test        https://company.sharepoint.com/sites/Test

    .EXAMPLE
    PS\:>Get-AADIntAccessTokenForTeams 
    PS\:>Get-AADIntMyTeams -Owner
    
    id                                   displayName site                                                 
    --                                   ----------- ----                                                 
    afa3b2d4-79d8-4a00-bfb2-070b58af26fc Sales       https://company.sharepoint.com/sites/Sales
    0bf31a81-4833-4421-a1ff-5d4efb669d4b Test        https://company.sharepoint.com/sites/Test

#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$False)]
        [String]$AccessToken,
        [Parameter(Mandatory=$False)]
        [Switch]$Owner,
        [Parameter(Mandatory=$False)]
        [Switch]$Channels
    )
    Process
    {
        # Get from cache if not provided
        $AccessToken = Get-AccessTokenFromCache -AccessToken $AccessToken -Resource "https://graph.microsoft.com" -ClientId "d3590ed6-52b3-4102-aeff-aad2292ab01c" 

        $userName = (Read-Accesstoken -AccessToken $AccessToken).upn

        $response = Call-MSGraphAPI -AccessToken $AccessToken -API "me/joinedTeams" -QueryString '$select=id,displayName'

        $teams = @()

        # Include only those where the user is owner
        if($Owner)
        {
            foreach($team in $response)
            {
                $response = Call-MSGraphAPI -AccessToken $AccessToken -API "groups/$($team.id)/owners" -QueryString '$top=999&$select=userPrincipalName'
                $owners = $response.userPrincipalName
                if($owners.Contains($userNAme))
                {
                    $teams += $team
                }
            }
        }
        else
        {
            $teams = $response
        }
        

        foreach($team in $teams)
        {
            $site = Call-MSGraphAPI -AccessToken $AccessToken -API "groups/$($team.id)/sites/root" -QueryString '$select=webUrl'
            $team | Add-Member -NotePropertyName "site" -NotePropertyValue $site.webUrl
            
            # Include channels
            if($Channels)
            {
                $response = Call-MSGraphAPI -AccessToken $AccessToken -ApiVersion "beta" -API "teams/$($team.id)/channels" -QueryString '$select=displayName,filesFolderWebUrl'
                $teamsChannels = @()
                foreach($channel in $response)
                {
                    $teamsChannels += $channel.filesFolderWebUrl.Substring($team.site.Length+1)
                    #[pscustomobject]@{
                        #"name" = $channel.displayName
                        #"folderName" = $channel.filesFolderWebUrl.Substring($team.site.Length+1)
                     #   $channel.filesFolderWebUrl.Substring($team.site.Length+1)
                    #}
                }

                $team | Add-Member -NotePropertyName "channels" -NotePropertyValue $teamsChannels
            }

            $team
        }
    }
}

# Get the external user information
# May 22nd 2024
function Get-TeamsExternalUserInformation
{
<#
    .SYNOPSIS
    Returns the external user information.

    .DESCRIPTION
    Returns the external user information using Teams API.


    .Parameter AccessToken
    The access token used to get the information.
    
    .Parameter ObjectId
    The Entra ID Object ID of the target user.

    .Parameter UserPrincipalName
    The user principal name of the target user.

    .EXAMPLE
    PS\:>Get-AADIntAccessTokenForTeams -SaveToCache

    PS\:>Get-AADIntTeamsExternalUserInformation -ObjectId "fe401a12-879c-4e5b-8b51-03e1985fa62f"

    tenantId          : dcc7d7bf-e3f5-4778-b6e0-aa7207bdb033
    isShortProfile    : False
    accountEnabled    : True
    featureSettings   : @{coExistenceMode=TeamsOnly}
    userPrincipalName : johnd@company.com
    givenName         : JohnD@company.com
    surname           : 
    email             : JohnD@company.com
    displayName       : John Doe
    type              : Federated
    mri               : 8:orgid:84bdccdb-eaba-4545-9729-4eff71b76841
    objectId          : fe401a12-879c-4e5b-8b51-03e1985fa62f

    PS\:>Get-AADIntAccessTokenForTeams -SaveToCache

    PS\:>Get-AADIntTeamsExternalUserInformation -UserPrincipalname = "johnd@company.com"

    tenantId          : dcc7d7bf-e3f5-4778-b6e0-aa7207bdb033
    isShortProfile    : False
    accountEnabled    : True
    featureSettings   : @{coExistenceMode=TeamsOnly}
    userPrincipalName : johnd@company.com
    givenName         : JohnD@company.com
    surname           : 
    email             : JohnD@company.com
    displayName       : John Doe
    type              : Federated
    mri               : 8:orgid:84bdccdb-eaba-4545-9729-4eff71b76841
    objectId          : fe401a12-879c-4e5b-8b51-03e1985fa62f

    .EXAMPLE
    PS\:>Get-AADIntAccessTokenForTeams -SaveToCache

    PS\:>Get-AADIntTeamsExternalUserInformation -ObjectId "fe401a12-879c-4e5b-8b51-03e1985fa62f"

    tenantId          : dcc7d7bf-e3f5-4778-b6e0-aa7207bdb033
    isShortProfile    : False
    accountEnabled    : True
    featureSettings   : @{coExistenceMode=TeamsOnly}
    userPrincipalName : johnd@company.com
    givenName         : JohnD@company.com
    surname           : 
    email             : JohnD@company.com
    displayName       : John Doe
    type              : Federated
    mri               : 8:orgid:84bdccdb-eaba-4545-9729-4eff71b76841
    objectId          : fe401a12-879c-4e5b-8b51-03e1985fa62f

    PS\:>Get-AADIntAccessTokenForTeams -SaveToCache

    PS\:>Get-AADIntTeamsExternalUserInformation -MRI "8:orgid:84bdccdb-eaba-4545-9729-4eff71b76841"

    tenantId          : dcc7d7bf-e3f5-4778-b6e0-aa7207bdb033
    isShortProfile    : False
    accountEnabled    : True
    featureSettings   : @{coExistenceMode=TeamsOnly}
    userPrincipalName : johnd@company.com
    givenName         : JohnD@company.com
    surname           : 
    email             : JohnD@company.com
    displayName       : John Doe
    type              : Federated
    mri               : 8:orgid:84bdccdb-eaba-4545-9729-4eff71b76841
    objectId          : fe401a12-879c-4e5b-8b51-03e1985fa62f
#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$False)]
        [String]$AccessToken,
        [Parameter(ParameterSetName='ObjectId',Mandatory=$True)]
        [Guid]$ObjectId,
        [Parameter(ParameterSetName='UserPrincipalName',Mandatory=$True)]
        [String]$UserPrincipalName,
        [Parameter(ParameterSetName='MRI',Mandatory=$True)]
        [String]$MRI
    )
    Process
    {
        # Get from cache if not provided
        $AccessToken = Get-AccessTokenFromCache -AccessToken $AccessToken -Resource "https://api.spaces.skype.com" -ClientId "1fec8e78-bce4-4aaf-ab1b-5451cc387264" 

        # Get the settings
        try
        {
            $teamsSettings = Get-TeamsUserSettings -AccessToken $AccessToken
            $apiUrl =        $teamsSettings.regionGtms.middleTier
        }
        catch
        {
            $apiUrl = "https://teams.microsoft.com/api/mt/part/amer-01"
        }

        if([string]::IsNullOrEmpty($MRI))
        {
            if($UserPrincipalName)
            {
                try
                {
                    $extUserResponse = Find-TeamsExternalUser -AccessToken $AccessToken -UserPrincipalName $UserPrincipalName
                    if($extUserResponse -is [System.Array])
                    {
                        $MRI = $extUserResponse[0].mri
                    }
                    else
                    {
                        $MRI = $extUserResponse.mri
                    }
                }
                catch
                {} # Okay(ish)

                if([string]::IsNullOrEmpty($MRI))
                {
                    throw "User $UserPrincipalName not found"
                }
            }
            else
            {
                $MRI = "8:orgid:$ObjectId"
            }
        }

        $body = "[""$MRI""]"

        $headers = @{
            "Authorization" = "Bearer $AccessToken"
        }

        try
        {
            $response = Invoke-RestMethod -UseBasicParsing -Method Post -Uri "$apiurl/beta/users/fetchFederated?edEnabled=true " -Headers $headers -ContentType "application/json" -Body $body
        }
        catch
        {
            Write-Error $_.Exception.Message
        }

        $response.value
    }
}