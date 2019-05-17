# Utilities for ActiveSync

# Checks whether the mail is Base64 encoded
function Get-MessageAsBase64
{
    Param(
        [Parameter(Mandatory=$True)]
        [String]$Message
        )
    Process
    {
        # Let's assume message is Base64 encoded
        $retVal = $Message
        try
        {
            [System.Convert]::FromBase64String($Message)
        }
        catch
        {
            # Was not, so let's convert
            Write-Warning "Message was not Base64 encoded, converting.."
            $retVal = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($Message))
        }

        return $retVal
    }

}

# Function to create token objects
function Token
{
    Param(
        [Parameter(Mandatory=$True)]
        [Int]$Code,

        [Parameter(Mandatory=$True)]
        [String]$Name

    )
    Process
    {
    
        $Token=[PSCustomObject]@{
            PSTypeName = "Token"
            Code = $Code
            Name = $Name
        }

        return $Token
    }
}

# Function to create CodePage objects
function CodePage
{
    Param(
        [Parameter(Mandatory=$True)]
        [Int]$Code,

        [Parameter(Mandatory=$True)]
        [String]$Namespace,

        [Parameter(Mandatory=$True)]
        [Array][PSTypeName("Token")]$Tokens

    )
    Process
        {
        $Token=[PSCustomObject]@{
            PSTypeName = "CodePage"
            Code = $Code
            NameSpace = $Namespace
            Tokens = $Tokens
        }

        return $Token
    }
}

# Returns codepage for the given name or number
function Get-CodePage
{
    Param(
        [Parameter(ParameterSetName='Name',Mandatory=$True)]
        [String]$Name,
        [Parameter(ParameterSetName='Code',Mandatory=$True)]
        [Int]$Code
    )
    
    Process
    {
        if([String]::IsNullOrEmpty($Name))
        {
            $CodePages | Where Code -EQ $Code
        }
        else
        {
            $CodePages | Where NameSpace -EQ $Name
        }
    }
}

# Returns token for the given namespace or codepage
function Get-Token
{
    Param(
        [Parameter(ParameterSetName='NameSpace',Mandatory=$True)]
        [String]$NameSpace,

        [Parameter(ParameterSetName='CodePage',Mandatory=$True)]
        [Int]$CodePage,

        [Parameter(Mandatory=$False)]
        [String]$Tag,

        [Parameter(Mandatory=$False)]
        [Int]$Code
    )

    Process
        {

        $CP=$null

        if([String]::IsNullOrEmpty($NameSpace))
        {
            $CP = Get-CodePage -Code $CodePage
        }
        else
        {
            $CP = Get-CodePage -Name $NameSpace
        }

        if([String]::IsNullOrEmpty($Tag))
        {
            $retVal=$CP.Tokens | Where Code -EQ $Code | Select -ExpandProperty Name
            if([String]::IsNullOrEmpty($retVal))
            {
                Throw "XML2WBXML: Tag with code $Code was not found!"
            }

            # Some tags share the same code
            # e.g. DeviceEncryptionEnabled and RequireStorageCardEncryption
            if($retVal.Count -gt 1)
            {
                $retVal=$retVal[0]
            }
        }
        else
        {
            $retVal=$CP.Tokens | Where Name -EQ $Tag | Select -ExpandProperty Code
            if([String]::IsNullOrEmpty($retVal))
            {
                Throw "XML2WBXML: Tag $Tag was not found!"
            }
        }
        
        $retVal

    }
} 

# Converts XML to WBXML
# The current codepage
$CurrentCodePage = 0

function XML2WBXML
{
    Param(
        [Parameter(Mandatory=$True)]
        [xml]$Xml
    )

    Process
        {
        # Some fixed variables
        $Header = @(0x03, 0x01, 0x6A, 0x00)
        $StringStart = 0x03
        $StringEnd = 0x00
        $TagClose = 0x01
        $TokenWithContent = 0x40
        $CodePageChange = 0x00
        $Script:CurrentCodePage = 0
    

        # Parses the given XMLElement
        function Parse{
        Param(
                [Parameter(Mandatory=$True)]
                [System.Xml.XmlElement]$Element
            )
            $retVal = @()
            $retVal += $Header
            $retVal += Get-Element $Element

            return $retVal
        
        }

        # Parses the given XMLElement
        function Get-Element{
        Param(
                [Parameter(Mandatory=$True)]
                [System.Xml.XmlElement]$Element
            )
            $retVal = @()
            $retVal += Get-CodePageBytes (Get-CodePage -Name $Element.NamespaceURI).Code
            $retVal += Get-Content $Element
            #$retVal += $TagClose

            return $retVal
        }

        function Get-Content{
        Param(
                [Parameter(Mandatory=$True)]
                [System.Xml.XmlElement]$Element
            )
            $retVal = @()

            if($Element.HasChildNodes)
            {
                $byte=((Get-Token -CodePage $CurrentCodePage -Tag $Element.LocalName) + $TokenWithContent)
                

                $retVal += $byte

                foreach($child in $Element.ChildNodes)
                {
                    if(($child.GetType()).Name -eq "XmlText")
                    {
                        $retVal += Get-String $child.Value
                    }
                    elseif(($child.GetType()).Name -eq "XmlCDataSection")
                    {
                        $retVal += Get-CData $child
                    }
                    else
                    {
                        $retVal += Get-Element $child
                    }
                }

                $retVal += $TagClose
            }
            else
            {
                $retVal += Get-Token -CodePage $CurrentCodePage -Tag $Element.LocalName
            }

            return $retVal
        }

        function Get-String{
        Param(
                [Parameter(Mandatory=$True)]
                [String]$Text
            )
            $retVal = @()
            $retVal += 0x03
            $retVal += [system.Text.Encoding]::UTF8.GetBytes($Text)
            $retVal += 0x00

            return $retVal
        }

        # Returns CData
        function Get-CData{
        Param(
                [Parameter(Mandatory=$True)]
                [System.Xml.XmlCDataSection]$CData
            )
            $retVal = @()
            $retVal += 0xC3
            $UTFBytes = [system.Text.Encoding]::UTF8.GetBytes($CData.Data)
            #$UTFBytes = LF2CRLF -bytes $UTFBytes
            $retVal += EncodeMultiByteInteger -Value $UTFBytes.Count
            $retVal += $UTFBytes

            return $retVal
        }

        # Converts 0x0A to 0x0D 0x0A
        function LF2CRLF
        {
        Param(
                [Parameter(Mandatory=$True)]
                [byte[]]$bytes
            )
            $retVal = @()
        
            foreach($byte in $bytes)
            {
                if($byte -eq 0x0A)
                {
                    $retVal += [byte]0x0D
                    $retVal += [byte]0x0A
                }
                else
                {
                    $retVal += [byte]$byte
                }
            }

            return $retVal
        }

        # Returns code page bytes
        function Get-CodePageBytes{
        Param(
                [Parameter(Mandatory=$True)]
                [Int]$CodePage
            )
            $retVal = @()
            if($Script:CurrentCodePage -ne $CodePage)
            {
                $Script:CurrentCodePage = $CodePage
                $retVal += $CodePageChange
                $retVal += $CodePage
            }

            return $retVal
        }

        Parse $Xml.DocumentElement
    }
}

# Converts WBXML to XML
$WBXML_currentPage = 0
$WBXML_position = 0
function WBXML2XML
{
    Param(
        [Parameter(Mandatory=$True)]
        [byte[]]$wbxml
    )

    Process
        {

        # Some variables
        $Script:WBXML_currentPage = 0
        $Script:WBXML_position = 4 # Skip the header

        function Get-CurrentToken{
        Param(
                [Parameter(Mandatory=$True)]
                [byte[]]$wbxml
            )
            return $wbxml[$Script:WBXML_position++]
        }

        # Parses the XML element
        function Parse-Element{
        Param(
                [Parameter(Mandatory=$True)]
                [byte[]]$wbxml,
                [Parameter(Mandatory=$True)]
                [byte]$next
            )
            $codePageChanged=$false
        
            if($next -eq 0) # The first token, 0 = change the codepage
            {
                $Script:WBXML_currentPage = Get-CurrentToken $wbxml
                $codePageChanged=$true
                $next = Get-CurrentToken $wbxml
            }

            $codePage = Get-CodePage -Code $Script:WBXML_currentPage | Select -ExpandProperty NameSpace
            $hasContent = ($next -band 0x40) -eq 0x40
            $currentToken = $next -band 0x3f
            $tag = Get-Token -CodePage $Script:WBXML_currentPage -Code $currentToken
        
            if($codePageChanged)
            {
                $retval = "<$tag xmlns=`"$codePage`">"
            }
            else
            {
                $retval = "<$tag>"
            }

            if($hasContent)
            {
                while(($next = Get-CurrentToken -wbxml $wbxml) -ne 0x01)
                {
                    if($next -eq 0x03) # Start of string
                    {
                        $retVal += Get-String -wbxml $wbxml
                    }
                    elseif($next -eq 0xC3) # Start of blob
                    {
                        $retVal += Get-CData -wbxml $wbxml
                    }
                    else
                    {
                        $retVal += Parse-Element -wbxml $wbxml -next $next
                    }
                }
            }


            $retval += "</$tag>"

            return $retVal
        }

        function Get-String{
        Param(
                [Parameter(Mandatory=$True)]
                [byte[]]$wbxml
            )
            $next = 0
            $bytes = @()
            while(($next = Get-CurrentToken -wbxml $wbxml) -ne 0x00)
            {
                $bytes+=[byte]$next
            }

            return [System.Text.Encoding]::UTF8.GetString($bytes)
        }

        function Get-CData{
        Param(
                [Parameter(Mandatory=$True)]
                [byte[]]$wbxml
            )
            $next = 0
            $bytes = @()
        
            #$next=Get-CurrentToken -wbxml $wbxml
            $length = Get-CDATALength -wbxml $wbxml
            for($i=0; $i -lt $length ; $i++)
            {
                $next = Get-CurrentToken -wbxml $wbxml
                $bytes += [byte]$next
            }
        
            $retVal = "<![CDATA["
            $retVal +=  [System.Text.Encoding]::UTF8.GetString($bytes)
            $retVal += "]]>"

            return $retVal
       
        }

        function Get-CDATALength()
        {
            Param(
                [Parameter(Mandatory=$True)]
                [byte[]]$wbxml
            )

            [int] $length = 0;
            [byte] $singleByte = 0xFF;

            do
            {
                $length = $length -shl 7
                $singleByte = Get-CurrentToken -wbxml $wbxml
              
                $length += [int]($singleByte -band 0x7f)
            }
            while (CheckContinuationBit($singleByte))
                
            return $length
        }

        function CheckContinuationBit
        {
            Param(
                [Parameter(Mandatory=$True)]
                [byte]$byteVal
            )

            [byte] $continuationBitmask = 0x80;
            return ($continuationBitmask -band $byteval) -ne 0
        }

        Parse-Element -wbxml $wbxml -next (Get-CurrentToken -wbxml $wbxml)
    }
}





function EncodeMultiByteInteger
{
    param(
        [parameter(Mandatory=$true)]
        [Int]$value
    )
    Process
    {
        $byteList = @()

        $shiftedValue = $value;

        while ($value -gt 0)
        {
            $addByte = [byte]($value -band 0x7F)

            if ($byteList.Count -gt 0)
            {
                    $addByte = $addByte -bor 0x80
            }
            $newList = @()
            $newList += $addByte
            $newList += $byteList
            $byteList = $newList
       

            $value = $value -shr 7;
        }

        return $byteList
    }
}

# Calls Exchange ActiveSync API
function Call-EAS
{
    Param(
        [Parameter(Mandatory=$True)]
        [String]$Authorization,
        [Parameter(Mandatory=$True)]
        [xml]$Request,
        [Parameter(Mandatory=$True)]
        [String]$DeviceId,
        [Parameter(Mandatory=$False)]
        [String]$DeviceType="Android",
        [Parameter(Mandatory=$True)]
        [ValidateSet('Sync','SendMail','SmartForward','SmartReply','GetAttachment','GetHierarchy','CreateCollection','DeleteCollection','MoveCollection','FolderSync','FolderCreate','FolderDelete','FolderUpdate','MoveItems','GetItemEstimate','MeetingResponse','Search','Settings','Ping','ItemOperations','Provision','ResolveRecipients','ValidateCert','Find')]
        [String]$Command,
        [Parameter(Mandatory=$False)]
        [ValidateSet("2.0","2.1","2.5","12.0","12.1","14.0","14.1","16.0","16.1")]
        [String]$Version="16.1",
        [Parameter(Mandatory=$False)]
        [String]$UserAgent="Outlook-Android/2.0",
        [Parameter(Mandatory=$False)]
        [String]$PolicyKey,
        [Parameter(Mandatory=$False)]
        [Switch]$ReturnHeaders
    )

    Process
        {
    
        $url="https://outlook.office365.com/Microsoft-Server-ActiveSync?Cmd=$Command&User=$(Get-UserNameFromAuthHeader($Authorization))&DeviceId=$DeviceId&DeviceType=$DeviceType"    

        $headers = @{
            "Authorization" = Create-AuthorizationHeader -Credentials $Credentials -AccessToken $AccessToken
            "User-Agent" = $UserAgent
            "Content-Type" = "application/vnd.ms-sync.WBXML"
            "MS-ASProtocolVersion" = $Version
        }
        if(![String]::IsNullOrEmpty($PolicyKey))
        {
            $headers["X-MS-Policykey"]=$PolicyKey
        }

        # MUST be convert to bytes
        [byte[]]$body=XML2WBXML $Request
    
        $response=Invoke-WebRequest -Uri $Url -Method Post -Headers $headers -Body $body -TimeoutSec 30
    
        $wbxml = $response.Content
        if(![String]::IsNullOrEmpty($wbxml))
        {
            # Got response
            $xmlVal = [xml](WBXML2XML -wbxml $wbxml)
            $status = Select-Xml -Xml $xmlVal -XPath "//*[local-name()='Status']"
            if([string]::IsNullOrEmpty($status)) 
            {
                # All good
                return $xmlVal
            }
            else
            {
                if($status.Count -ge 1)
                {
                    $code = $status[0].Node.'#text'
                }
                else
                {
                    $code = $status.Node.'#text'
                }

                if([int]($code) -lt 2) # codes below 2 are not errors
                {
                    # All good
                    if($ReturnHeaders)
                    {
                        return $response.Headers
                    }
                    else
                    {
                        return $xmlVal
                    }
                }
                else
                {
                    # Got error, so throw an exception
                    throw "Error: $code $($EASErrors[$code])"
                }
            }
        
        }
        else
        {
            # All good - nothing to return
        }
    }
}

# Adds tag if value is not null
function InsertTag
{
    Param(
        [Parameter(Mandatory=$True)]
        [String]$Key,
        [Parameter()]
        [String]$Value
        )
    Process
    {
        if(![String]::IsNullOrEmpty($key) -or [String]::IsNullOrEmpty($value))
        {
            return "<$key>$value</$key>"
        }

        return ""
    }
}


# ActiveSync error codes
# https://docs.microsoft.com/en-us/openspecs/exchange_server_protocols/ms-ascmd/95cb9d7c-d33d-4b94-9366-d59911c7a060
$EASErrors=@{
"2" = "ActiveSync Error"
"3" = "ActiveSync Error"
"4" = "ActiveSync Error"
"5" = "ActiveSync Error"
"6" = "ActiveSync Error"
"7" = "ActiveSync Error"
"8" = "ActiveSync Error"
"9" = "ActiveSync Error"
    "101" = "InvalidContent"
    "102" = "InvalidWBXML"
    "103" = "InvalidXML"
    "104" = "InvalidDateTime"
    "105" = "InvalidCombinationOfIDs"
    "106" = "InvalidIDs"
    "107" = "InvalidMIME"
    "108" = "DeviceIdMissingOrInvalid"
    "109" = "DeviceTypeMissingOrInvalid"
    "110" = "ServerError"
    "111" = "ServerErrorRetryLater"
    "112" = "ActiveDirectoryAccessDenied"
    "113" = "MailboxQuotaExceeded"
    "114" = "MailboxServerOffline"
    "115" = "SendQuotaExceeded"
    "116" = "MessageRecipientUnresolved"
    "117" = "MessageReplyNotAllowed"
    "118" = "Message PreviouslySent"
    "119" = "MessageHasNoRecipient"
    "120" = "MailSubmissionFailed"
    "121" = "MessageReplyFailed"
    "122" = "AttachmentIsTooLarge"
    "123" = "UserHasNoMailbox"
    "124" = "UserCannotBeAnonymous"
    "125" = "UserPrincipalCouldNotBeFound"
    "126" = "UserDisabledForSync"
    "127" = "UserOnNewMailboxCannotSync"
    "128" = "UserOnLegacyMailboxCannotSync"
    "129" = "DeviceIsBlockedForThisUser"
    "130" = "AccessDenied"
    "131" = "AccountDisabled"
    "132" = "SyncStateNotFound"
    "133" = "SyncStateLocked"
    "134" = "SyncStateCorrupt"
    "135" = "SyncStateAlreadyExists"
    "136" = "SyncStateVersionInvalid"
    "137" = "CommandNotSupported"
    "138" = "VersionNotSupported"
    "139" = "DeviceNotFullyProvisionable"
    "140" = "RemoteWipeRequested"
    "141" = "LegacyDeviceOnStrictPolicy"
    "142" = "DeviceNotProvisioned"
    "143" = "PolicyRefresh"
    "144" = "InvalidPolicyKey"
    "145" = "ExternallyManagedDevicesNotAllowed"
    "146" = "NoRecurrenceInCalendar"
    "147" = "UnexpectedItemClass"
    "148" = "RemoteServerHasNoSSL"
    "149" = "InvalidStoredRequest"
    "150" = "ItemNotFound"
    "151" = "TooManyFolders"
    "152" = "NoFoldersFound"
    "153" = "ItemsLostAfterMove"
    "154" = "FailureInMoveOperation"
    "155" = "MoveCommandDisallowedForNonPersistentMoveAction"
    "156" = "MoveCommandInvalidDestinationFolder"
    "160" = "AvailabilityTooManyRecipients"
    "161" = "AvailabilityDLLimitReached"
    "162" = "AvailabilityTransientFailure"
    "163" = "AvailabilityFailure"
    "164" = "BodyPartPreferenceTypeNotSupported"
    "165" = "DeviceInformationRequired"
    "166" = "InvalidAccountId"
    "167" = "AccountSendDisabled"
    "168" = "IRM_FeatureDisabled"
    "169" = "IRM_TransientError"
    "170" = "IRM_PermanentError"
    "171" = "IRM_InvalidTemplateID"
    "172" = "IRM_OperationNotPermitted"
    "173" = "NoPicture"
    "174" = "PictureTooLarge"
    "175" = "PictureLimitReached"
    "176" = "BodyPart_ConversationTooLarge"
    "177" = "MaximumDevicesReached"
    "178" = "InvalidMimeBodyCombination"
    "179" = "InvalidSmartForwardParameters"
    "183" = "InvalidRecipients"
    "184" = "OneOrMoreExceptionsFailed"

}

# ActiveSync WBXML CodePages and tokens
$CodePages = @(
        	(CodePage 0 "AirSync" @(
			(Token 0x05 "Sync"),
			(Token 0x06 "Responses"),
			(Token 0x07 "Add"),
			(Token 0x08 "Change"),
			(Token 0x09 "Delete"),
			(Token 0x0A "Fetch"),
			(Token 0x0B "SyncKey"),
			(Token 0x0C "ClientId"),
			(Token 0x0D "ServerId"),
			(Token 0x0E "Status"),
			(Token 0x0F "Collection"),
			(Token 0x10 "Class"),
			(Token 0x12 "CollectionId"),
			(Token 0x13 "GetChanges"),
			(Token 0x14 "MoreAvailable"),
			(Token 0x15 "WindowSize"),
			(Token 0x16 "Commands"),
			(Token 0x17 "Options"),
			(Token 0x18 "FilterType"),
			(Token 0x1B "Conflict"),
			(Token 0x1C "Collections"),
			(Token 0x1D "ApplicationData"),
			(Token 0x1E "DeletesAsMoves"),
			(Token 0x20 "Supported"),
			(Token 0x21 "SoftDelete"),
			(Token 0x22 "MIMESupport"),
			(Token 0x23 "MIMETruncation"),
			(Token 0x24 "Wait"),
			(Token 0x25 "Limit"),
			(Token 0x26 "Partial"),
			(Token 0x27 "ConversationMode"),
			(Token 0x28 "MaxItems"),
			(Token 0x29 "HeartbeatInterval"))
	),
	(CodePage 1 "Contacts" @(
			(Token 0x05 "Anniversary"),
			(Token 0x06 "AssistantName"),
			(Token 0x07 "AssistantTelephoneNumber"),
			(Token 0x08 "Birthday"),
			(Token 0x0C "Business2PhoneNumber"),
			(Token 0x0D "BusinessCity"),
			(Token 0x0E "BusinessCountry"),
			(Token 0x0F "BusinessPostalCode"),
			(Token 0x10 "BusinessState"),
			(Token 0x11 "BusinessStreet"),
			(Token 0x12 "BusinessFaxNumber"),
			(Token 0x13 "BusinessPhoneNumber"),
			(Token 0x14 "CarPhoneNumber"),
			(Token 0x15 "Categories"),
			(Token 0x16 "Category"),
			(Token 0x17 "Children"),
			(Token 0x18 "Child"),
			(Token 0x19 "CompanyName"),
			(Token 0x1A "Department"),
			(Token 0x1B "Email1Address"),
			(Token 0x1C "Email2Address"),
			(Token 0x1D "Email3Address"),
			(Token 0x1E "FileAs"),
			(Token 0x1F "FirstName"),
			(Token 0x20 "Home2PhoneNumber"),
			(Token 0x21 "HomeCity"),
			(Token 0x22 "HomeCountry"),
			(Token 0x23 "HomePostalCode"),
			(Token 0x24 "HomeState"),
			(Token 0x25 "HomeStreet"),
			(Token 0x26 "HomeFaxNumber"),
			(Token 0x27 "HomePhoneNumber"),
			(Token 0x28 "JobTitle"),
			(Token 0x29 "LastName"),
			(Token 0x2A "MiddleName"),
			(Token 0x2B "MobilePhoneNumber"),
			(Token 0x2C "OfficeLocation"),
			(Token 0x2D "OtherCity"),
			(Token 0x2E "OtherCountry"),
			(Token 0x2F "OtherPostalCode"),
			(Token 0x30 "OtherState"),
			(Token 0x31 "OtherStreet"),
			(Token 0x32 "PagerNumber"),
			(Token 0x33 "RadioPhoneNumber"),
			(Token 0x34 "Spouse"),
			(Token 0x35 "Suffix"),
			(Token 0x36 "Title"),
			(Token 0x37 "Webpage"),
			(Token 0x38 "YomiCompanyName"),
			(Token 0x39 "YomiFirstName"),
			(Token 0x3A "YomiLastName"),
			(Token 0x3C "Picture"),
			(Token 0x3D "Alias"),
			(Token 0x3E "WeightedRank"))
	),		
	(CodePage 2 "Email" @(
			(Token 0x0F "DateReceived"),
			(Token 0x11 "DisplayTo"),
			(Token 0x12 "Importance"),
			(Token 0x13 "MessageClass"),
			(Token 0x14 "Subject"),
			(Token 0x15 "Read"),
			(Token 0x16 "To"),
			(Token 0x17 "Cc"),
			(Token 0x18 "From"),
			(Token 0x19 "ReplyTo"),
			(Token 0x1A "AllDayEvent"),
			(Token 0x1B "Categories"),
			(Token 0x1C "Category"),
			(Token 0x1D "DTStamp"),
			(Token 0x1E "EndTime"),
			(Token 0x1F "InstanceType"),
			(Token 0x20 "BusyStatus"),
			(Token 0x21 "Location"),
			(Token 0x22 "MeetingRequest"),
			(Token 0x23 "Organizer"),
			(Token 0x24 "RecurrenceId"),
			(Token 0x25 "Reminder"),
			(Token 0x26 "ResponseRequested"),
			(Token 0x27 "Recurrences"),
			(Token 0x28 "Recurrence"),
			(Token 0x29 "Recurrence_Type"),
			(Token 0x2A "Recurrence_Until"),
			(Token 0x2B "Recurrence_Occurrences"),
			(Token 0x2C "Recurrence_Interval"),
			(Token 0x2D "Recurrence_DayOfWeek"),
			(Token 0x2E "Recurrence_DayOfMonth"),
			(Token 0x2F "Recurrence_WeekOfMonth"),
			(Token 0x30 "Recurrence_MonthOfYear"),
			(Token 0x31 "StartTime"),
			(Token 0x32 "Sensitivity"),
			(Token 0x33 "TimeZone"),
			(Token 0x34 "GlobalObjId"),
			(Token 0x35 "ThreadTopic"),
			(Token 0x39 "InternetCPID"),
			(Token 0x3A "Flag"),
			(Token 0x3B "FlagStatus"),
			(Token 0x3C "ContentClass"),
			(Token 0x3D "FlagType"),
			(Token 0x3E "CompleteTime"),
			(Token 0x3F "DisallowNewTimeProposal"))
	),
	(CodePage 3 "AirNotify" @(Token 0xFF "none")),
	(CodePage 4 "Calendar" @(
			(Token 0x05 "TimeZone"),
			(Token 0x06 "AllDayEvent"),
			(Token 0x07 "Attendees"),
			(Token 0x08 "Attendee"),
			(Token 0x09 "Attendee_Email"),
			(Token 0x0A "Attendee_Name"),
			(Token 0x0D "BusyStatus"),
			(Token 0x0E "Categories"),
			(Token 0x0F "Category"),
			(Token 0x11 "DTStamp"),
			(Token 0x12 "EndTime"),
			(Token 0x13 "Exception"),
			(Token 0x14 "Exceptions"),
			(Token 0x15 "Exception_Deleted"),
			(Token 0x16 "Exception_StartTime"),
			(Token 0x17 "Location"),
			(Token 0x18 "MeetingStatus"),
			(Token 0x19 "Organizer_Email"),
			(Token 0x1A "Organizer_Name"),
			(Token 0x1B "Recurrence"),
			(Token 0x1C "Recurrence_Type"),
			(Token 0x1D "Recurrence_Until"),
			(Token 0x1E "Recurrence_Occurrences"),
			(Token 0x1F "Recurrence_Interval"),
			(Token 0x20 "Recurrence_DayOfWeek"),
			(Token 0x21 "Recurrence_DayOfMonth"),
			(Token 0x22 "Recurrence_WeekOfMonth"),
			(Token 0x23 "Recurrence_MonthOfYear"),
			(Token 0x24 "Reminder"),
			(Token 0x25 "Sensitivity"),
			(Token 0x26 "Subject"),
			(Token 0x27 "StartTime"),
			(Token 0x28 "UID"),
			(Token 0x29 "Attendee_Status"),
			(Token 0x2A "Attendee_Type"),
			(Token 0x33 "DisallowNewTimeProposal"),
			(Token 0x34 "ResponseRequested"),
			(Token 0x35 "AppointmentReplyTime"),
			(Token 0x36 "ResponseType"),
			(Token 0x37 "CalendarType"),
			(Token 0x38 "IsLeapMonth"),
			(Token 0x39 "FirstDayOfWeek"),
			(Token 0x3A "OnlineMeetingConfLink"),
			(Token 0x3B "OnlineMeetingExternalLink"))
	),		
	(CodePage 5 "Move" @(
			(Token 0x05 "MoveItems"),
			(Token 0x06 "Move"),
			(Token 0x07 "SrcMsgId"),
			(Token 0x08 "SrcFldId"),
			(Token 0x09 "DstFldId"),
			(Token 0x0A "Response"),
			(Token 0x0B "Status"),
			(Token 0x0C "DstMsgId"))
	),		
	(CodePage 6 "ItemEstimate" @(
			(Token 0x05 "GetItemEstimate"),
			(Token 0x06 "Version"),
			(Token 0x07 "Collections"),
			(Token 0x08 "Collection"),
			(Token 0x09 "Class"),
			(Token 0x0A "CollectionId"),
			(Token 0x0B "DateTime"),
			(Token 0x0C "Estimate"),
			(Token 0x0D "Response"),
			(Token 0x0E "Status"))
	),		
	(CodePage 7 "FolderHierarchy" @(
			(Token 0x07 "DisplayName"),
			(Token 0x08 "ServerId"),
			(Token 0x09 "ParentId"),
			(Token 0x0A "Type"),
			(Token 0x0C "Status"),
			(Token 0x0E "Changes"),
			(Token 0x0F "Add"),
			(Token 0x10 "Delete"),
			(Token 0x11 "Update"),
			(Token 0x12 "SyncKey"),
			(Token 0x13 "FolderCreate"),
			(Token 0x14 "FolderDelete"),
			(Token 0x15 "FolderUpdate"),
			(Token 0x16 "FolderSync"),
			(Token 0x17 "Count"))
	),		
	(CodePage 8 "MeetingResponse" @(
			(Token 0x05 "CalendarId"),
			(Token 0x06 "CollectionId"),
			(Token 0x07 "MeetingResponse"),
			(Token 0x08 "RequestId"),
			(Token 0x09 "Request"),
			(Token 0x0A "Result"),
			(Token 0x0B "Status"),
			(Token 0x0C "UserResponse"),
			(Token 0x0E "InstanceId"))
	),		
	(CodePage 9 "Tasks" @(
			(Token 0x08 "Categories"),
			(Token 0x09 "Category"),
			(Token 0x0A "Complete"),
			(Token 0x0B "DateCompleted"),
			(Token 0x0C "DueDate"),
			(Token 0x0D "UTCDueDate"),
			(Token 0x0E "Importance"),
			(Token 0x0F "Recurrence"),
			(Token 0x10 "Recurrence_Type"),
			(Token 0x11 "Recurrence_Start"),
			(Token 0x12 "Recurrence_Until"),
			(Token 0x13 "Recurrence_Occurrences"),
			(Token 0x14 "Recurrence_Interval"),
			(Token 0x15 "Recurrence_DayOfMonth"),
			(Token 0x16 "Recurrence_DayOfWeek"),
			(Token 0x17 "Recurrence_WeekOfMonth"),
			(Token 0x18 "Recurrence_MonthOfYear"),
			(Token 0x19 "Recurrence_Regenerate"),
			(Token 0x1A "Recurrence_DeadOccur"),
			(Token 0x1B "ReminderSet"),
			(Token 0x1C "ReminderTime"),
			(Token 0x1D "Sensitivity"),
			(Token 0x1E "StartDate"),
			(Token 0x1F "UTCStartDate"),
			(Token 0x20 "Subject"),
			(Token 0x22 "OrdinalDate"),
			(Token 0x23 "SubOrdinalDate"),
			(Token 0x24 "CalendarType"),
			(Token 0x25 "IsLeapMonth"),
			(Token 0x26 "FirstDayOfWeek"))
	)		
	(CodePage 10 "ResolveRecipients" @(
			(Token 0x05 "ResolveRecipients"),
			(Token 0x06 "Response"),
			(Token 0x07 "Status"),
			(Token 0x08 "Type"),
			(Token 0x09 "Recipient"),
			(Token 0x0A "DisplayName"),
			(Token 0x0B "EmailAddress"),
			(Token 0x0C "Certificates"),
			(Token 0x0D "Certificate"),
			(Token 0x0E "MiniCertificate"),
			(Token 0x0F "Options"),
			(Token 0x10 "To"),
			(Token 0x11 "CertificateRetrieval"),
			(Token 0x12 "RecipientCount"),
			(Token 0x13 "MaxCertificates"),
			(Token 0x14 "MaxAmbiguousRecipients"),
			(Token 0x15 "CertificateCount"),
			(Token 0x16 "Availability"),
			(Token 0x17 "StartTime"),
			(Token 0x18 "EndTime"),
			(Token 0x19 "MergedFreeBusy"),
			(Token 0x1A "Picture"),
			(Token 0x1B "MaxSize"),
			(Token 0x1C "Data"),
			(Token 0x1D "MaxPictures"))
	),		
	(CodePage 11 "ValidateCert" @(
			(Token 0x05 "ValidateCert"),
			(Token 0x06 "Certificates"),
			(Token 0x07 "Certificate"),
			(Token 0x08 "CertificateChain"),
			(Token 0x09 "CheckCRL"),
			(Token 0x0A "Status"))
	),		
	(CodePage 12 "Contacts2" @(
			(Token 0x05 "CustomerId"),
			(Token 0x06 "GovernmentId"),
			(Token 0x07 "IMAddress"),
			(Token 0x08 "IMAddress2"),
			(Token 0x09 "IMAddress3"),
			(Token 0x0A "ManagerName"),
			(Token 0x0B "CompanyMainPhone"),
			(Token 0x0C "AccountName"),
			(Token 0x0D "NickName"),
			(Token 0x0E "MMS"))
	),		
	(CodePage 13 "Ping" @(
			(Token 0x05 "Ping"),
			(Token 0x06 "AutdState"),
			(Token 0x07 "Status"),
			(Token 0x08 "HeartbeatInterval"),
			(Token 0x09 "Folders"),
			(Token 0x0A "Folder"),
			(Token 0x0B "Id"),
			(Token 0x0C "Class"),
			(Token 0x0D "MaxFolders"))
	),		
	(CodePage 14 "Provision" @(
			(Token 0x05 "Provision"),
			(Token 0x06 "Policies"),
			(Token 0x07 "Policy"),
			(Token 0x08 "PolicyType"),
			(Token 0x09 "PolicyKey"),
			(Token 0x0A "Data"),
			(Token 0x0B "Status"),
			(Token 0x0C "RemoteWipe"),
			(Token 0x0D "EASProvisionDoc"),
			(Token 0x0E "DevicePasswordEnabled"),
			(Token 0x0F "AlphanumericDevicePasswordRequired"),
			(Token 0x10 "DeviceEncryptionEnabled"),
			(Token 0x10 "RequireStorageCardEncryption"),
			(Token 0x11 "PasswordRecoveryEnabled"),
            (Token 0x12 "DocumentBrowseEnabled"),
			(Token 0x13 "AttachmentsEnabled"),
			(Token 0x14 "MinDevicePasswordLength"),
			(Token 0x15 "MaxInactivityTimeDeviceLock"),
			(Token 0x16 "MaxDevicePasswordFailedAttempts"),
			(Token 0x17 "MaxAttachmentSize"),
			(Token 0x18 "AllowSimpleDevicePassword"),
			(Token 0x19 "DevicePasswordExpiration"),
			(Token 0x1A "DevicePasswordHistory"),
			(Token 0x1B "AllowStorageCard"),
			(Token 0x1C "AllowCamera"),
			(Token 0x1D "RequireDeviceEncryption"),
			(Token 0x1E "AllowUnsignedApplications"),
			(Token 0x1F "AllowUnsignedInstallationPackages"),
			(Token 0x20 "MinDevicePasswordComplexCharacters"),
			(Token 0x21 "AllowWiFi"),
			(Token 0x22 "AllowTextMessaging"),
			(Token 0x23 "AllowPOPIMAPEmail"),
			(Token 0x24 "AllowBluetooth"),
			(Token 0x25 "AllowIrDA"),
			(Token 0x26 "RequireManualSyncWhenRoaming"),
			(Token 0x27 "AllowDesktopSync"),
			(Token 0x28 "MaxCalendarAgeFilter"),
			(Token 0x29 "AllowHTMLEmail"),
			(Token 0x2A "MaxEmailAgeFilter"),
			(Token 0x2B "MaxEmailBodyTruncationSize"),
			(Token 0x2C "MaxEmailHTMLBodyTruncationSize"),
			(Token 0x2D "RequireSignedSMIMEMessages"),
			(Token 0x2E "RequireEncryptedSMIMEMessages"),
			(Token 0x2F "RequireSignedSMIMEAlgorithm"),
			(Token 0x30 "RequireEncryptionSMIMEAlgorithm"),
			(Token 0x31 "AllowSMIMEEncryptionAlgorithmNegotiation"),
			(Token 0x32 "AllowSMIMESoftCerts"),
			(Token 0x33 "AllowBrowser"),
			(Token 0x34 "AllowConsumerEmail"),
			(Token 0x35 "AllowRemoteDesktop"),
			(Token 0x36 "AllowInternetSharing"),
			(Token 0x37 "UnapprovedInROMApplicationList"),
			(Token 0x38 "ApplicationName"),
			(Token 0x39 "ApprovedApplicationList"),
			(Token 0x3A "Hash"))
	),		
	(CodePage 15 "Search" @(
			(Token 0x05 "Search"),
			(Token 0x07 "Store"),
			(Token 0x08 "Name"),
			(Token 0x09 "Query"),
			(Token 0x0A "Options"),
			(Token 0x0B "Range"),
			(Token 0x0C "Status"),
			(Token 0x0D "Response"),
			(Token 0x0E "Result"),
			(Token 0x0F "Properties"),
			(Token 0x10 "Total"),
			(Token 0x11 "EqualTo"),
			(Token 0x12 "Value"),
			(Token 0x13 "And"),
			(Token 0x14 "Or"),
			(Token 0x15 "FreeText"),
			(Token 0x17 "DeepTraversal"),
			(Token 0x18 "LongId"),
			(Token 0x19 "RebuildResults"),
			(Token 0x1A "LessThan"),
			(Token 0x1B "GreaterThan"),
			(Token 0x1E "UserName"),
			(Token 0x1F "Password"),
			(Token 0x20 "ConversationId"),
			(Token 0x21 "Picture"),
			(Token 0x22 "MaxSize"),
			(Token 0x23 "MaxPictures"))
	),		
	(CodePage 16 "GAL" @(
			(Token 0x05 "DisplayName"),
			(Token 0x06 "Phone"),
			(Token 0x07 "Office"),
			(Token 0x08 "Title"),
			(Token 0x09 "Company"),
			(Token 0x0A "Alias"),
			(Token 0x0B "FirstName"),
			(Token 0x0C "LastName"),
			(Token 0x0D "HomePhone"),
			(Token 0x0E "MobilePhone"),
			(Token 0x0F "EmailAddress"),
			(Token 0x10 "Picture"),
			(Token 0x11 "Status"),
			(Token 0x12 "Data"))
	),		
	(CodePage 17 "AirSyncBase" @(
			(Token 0x05 "BodyPreference"),
			(Token 0x06 "Type"),
			(Token 0x07 "TruncationSize"),
			(Token 0x08 "AllOrNone"),
			(Token 0x0A "Body"),
			(Token 0x0B "Data"),
			(Token 0x0C "EstimatedDataSize"),
			(Token 0x0D "Truncated"),
			(Token 0x0E "Attachments"),
			(Token 0x0F "Attachment"),
			(Token 0x10 "DisplayName"),
			(Token 0x11 "FileReference"),
			(Token 0x12 "Method"),
			(Token 0x13 "ContentId"),
			(Token 0x14 "ContentLocation"),
			(Token 0x15 "IsInline"),
			(Token 0x16 "NativeBodyType"),
			(Token 0x17 "ContentType"),
			(Token 0x18 "Preview"),
			(Token 0x19 "BodyPartPreference"),
			(Token 0x1A "BodyPart"),
			(Token 0x1B "Status"))
	),		
	(CodePage 18 "Settings" @(
			(Token 0x05 "Settings"),
			(Token 0x06 "Status"),
			(Token 0x07 "Get"),
			(Token 0x08 "Set"),
			(Token 0x09 "Oof"),
			(Token 0x0A "OofState"),
			(Token 0x0B "StartTime"),
			(Token 0x0C "EndTime"),
			(Token 0x0D "OofMessage"),
			(Token 0x0E "AppliesToInternal"),
			(Token 0x0F "AppliesToExternalKnown"),
			(Token 0x10 "AppliesToExternalUnknown"),
			(Token 0x11 "Enabled"),
			(Token 0x12 "ReplyMessage"),
			(Token 0x13 "BodyType"),
			(Token 0x14 "DevicePassword"),
			(Token 0x15 "Password"),
			(Token 0x16 "DeviceInformation"),
			(Token 0x17 "Model"),
			(Token 0x18 "IMEI"),
			(Token 0x19 "FriendlyName"),
			(Token 0x1A "OS"),
			(Token 0x1B "OSLanguage"),
			(Token 0x1C "PhoneNumber"),
			(Token 0x1D "UserInformation"),
			(Token 0x1E "EmailAddresses"),
			(Token 0x1F "SmtpAddress"),
			(Token 0x20 "UserAgent"),
			(Token 0x21 "EnableOutboundSMS"),
			(Token 0x22 "MobileOperator"),
			(Token 0x23 "PrimarySmtpAddress"),
			(Token 0x24 "Accounts"),
			(Token 0x25 "Account"),
			(Token 0x26 "AccountId"),
			(Token 0x27 "AccountName"),
			(Token 0x28 "UserDisplayName"),
			(Token 0x29 "SendDisabled"),
			(Token 0x2B "RightsManagementInformation"))
	),		
	(CodePage 19 "DocumentLibrary" @(
			(Token 0x05 "LinkId"),
			(Token 0x06 "DisplayName"),
			(Token 0x07 "IsFolder"),
			(Token 0x08 "CreationDate"),
			(Token 0x09 "LastModifiedDate"),
			(Token 0x0A "IsHidden"),
			(Token 0x0B "ContentLength"),
			(Token 0x0C "ContentType"))
	),		
	(CodePage 20 "ItemOperations" @(
			(Token 0x05 "ItemOperations"),
			(Token 0x06 "Fetch"),
			(Token 0x07 "Store"),
			(Token 0x08 "Options"),
			(Token 0x09 "Range"),
			(Token 0x0A "Total"),
			(Token 0x0B "Properties"),
			(Token 0x0C "Data"),
			(Token 0x0D "Status"),
			(Token 0x0E "Response"),
			(Token 0x0F "Version"),
			(Token 0x10 "Schema"),
			(Token 0x11 "Part"),
			(Token 0x12 "EmptyFolderContents"),
			(Token 0x13 "DeleteSubFolders"),
			(Token 0x14 "UserName"),
			(Token 0x15 "Password"),
			(Token 0x16 "Move"),
			(Token 0x17 "DstFldId"),
			(Token 0x18 "ConversationId"),
			(Token 0x19 "MoveAlways"))
	),		
	(CodePage 21 "ComposeMail" @(
			(Token 0x05 "SendMail"),
			(Token 0x06 "SmartForward"),
			(Token 0x07 "SmartReply"),
			(Token 0x08 "SaveInSentItems"),
			(Token 0x09 "ReplaceMime"),
			(Token 0x0B "Source"),
			(Token 0x0C "FolderId"),
			(Token 0x0D "ItemId"),
			(Token 0x0E "LongId"),
			(Token 0x0F "InstanceId"),
			(Token 0x10 "MIME"),
			(Token 0x11 "ClientId"),
			(Token 0x12 "Status"),
			(Token 0x13 "AccountId"))
	),		
	(CodePage 22 "Email2" @(
			(Token 0x05 "UmCallerID"),
			(Token 0x06 "UmUserNotes"),
			(Token 0x07 "UmAttDuration"),
			(Token 0x08 "UmAttOrder"),
			(Token 0x09 "ConversationId"),
			(Token 0x0A "ConversationIndex"),
			(Token 0x0B "LastVerbExecuted"),
			(Token 0x0C "LastVerbExecutionTime"),
			(Token 0x0D "ReceivedAsBcc"),
			(Token 0x0E "Sender"),
			(Token 0x0F "CalendarType"),
			(Token 0x10 "IsLeapMonth"),
			(Token 0x11 "AccountId"),
			(Token 0x12 "FirstDayOfWeek"),
			(Token 0x13 "MeetingMessageType"))
	),		
	(CodePage 23 "Notes" @(
			(Token 0x05 "Subject"),
			(Token 0x06 "MessageClass"),
			(Token 0x07 "LastModifiedDate"),
			(Token 0x08 "Categories"),
			(Token 0x09 "Category"))
	),		
	(CodePage 24 "RightsManagement" @(
			(Token 0x05 "RightsManagementSupport"),
			(Token 0x06 "RightsManagementTemplates"),
			(Token 0x07 "RightsManagementTemplate"),
			(Token 0x08 "RightsManagementLicense"),
			(Token 0x09 "EditAllowed"),
			(Token 0x0A "ReplyAllowed"),
			(Token 0x0B "ReplyAllAllowed"),
			(Token 0x0C "ForwardAllowed"),
			(Token 0x0D "ModifyRecipientsAllowed"),
			(Token 0x0E "ExtractAllowed"),
			(Token 0x0F "PrintAllowed"),
			(Token 0x10 "ExportAllowed"),
			(Token 0x11 "ProgrammaticAccessAllowed"),
			(Token 0x12 "RMOwner"),
			(Token 0x13 "ContentExpiryDate"),
			(Token 0x14 "TemplateID"),
			(Token 0x15 "TemplateName"),
			(Token 0x16 "TemplateDescription"),
			(Token 0x17 "ContentOwner"),
			(Token 0x18 "RemoveRightsManagementDistribution"))
	)
)
