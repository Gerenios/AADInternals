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
        [Int]$Code,
        [Parameter(Mandatory=$True)]
        [boolean]$O365,
        [Parameter(Mandatory=$True)]
        [boolean]$SyncML
    )
    
    Process
    {
        if($O365)
        {
            $cps=$O365CodePages
        }
        elseif($SyncML)
        {
            $cps=$SyncMLCodePage
        }
        else
        {
            $cps=$CodePages
        }

        if([String]::IsNullOrEmpty($Name))
        {
            $cps| Where Code -EQ $Code
        }
        else
        {
            $cps | Where NameSpace -EQ $Name
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
        [Int]$Code,

        [Parameter(Mandatory=$True)]
        [boolean]$O365,
        [Parameter(Mandatory=$True)]
        [boolean]$SyncML
    )

    Process
        {

        $CP=$null

        if([String]::IsNullOrEmpty($NameSpace))
        {
            $CP = Get-CodePage -Code $CodePage -O365 $O365 -SyncML $SyncML
        }
        else
        {
            $CP = Get-CodePage -Name $NameSpace -O365 $O365 -SyncML $SyncML
        }

        if([String]::IsNullOrEmpty($Tag))
        {
            $retVal=$CP.Tokens | Where Code -EQ $Code | Select -ExpandProperty Name

            if([String]::IsNullOrEmpty($retVal))
            {
                $hexCode = "0x{0:X}" -f $Code
                Write-Host "(Token $hexCode `"$($Code)_$($hexCode.Substring(2))`")"
                Throw "XML2WBXML: Tag with code $Code ($hexCode) was not found from namespace $($CodePage):$($cp.NameSpace)"
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
                Throw "XML2WBXML: Tag with code $Tag was not found from namespace $($cp.Code):$($cp.NameSpace)"
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
        [xml]$Xml,
        [switch]$O365,
        [switch]$SyncML
    )
    Begin
    {
        # Some fixed variables
        $Header = @(
                0x03, # WBXML version 1.3
                0x01, # Unknown public identifier
                0x6A, # Charset = UTF8
                0x00  # String table length
            )
        $SyncMlHeader = @(
                0x02, # ??
                0xA4, # ??
                0x01, # Unknown public identifier
                0x6A, # Charset = UTF8
                0x00  # String table length
            )
        $StringTable =      0x04
        $StringStart =      0x03
        $StringEnd =        0x00
        $TagClose =         0x01
        $TokenWithContent = 0x40
        $CodePageChange =   0x00
        $EXT_1 =            0xC1
        $EXT_2 =            0xC2
    }
    Process
    {
        
        $Script:CurrentCodePage = 0
    

        # Parses the given XMLElement
        function Parse{
        Param(
                [Parameter(Mandatory=$True)]
                [System.Xml.XmlElement]$Element
            )
            $retVal = @()
            if($SyncML)
            {
                $retVal += $SyncMlHeader
            }
            else
            {
                $retVal += $Header
            }
            $retVal += Get-Element $Element -O365 $O365 -SyncML $SyncML

            return $retVal
        
        }

        # Parses the given XMLElement
        function Get-Element{
        Param(
                [Parameter(Mandatory=$True)]
                [System.Xml.XmlElement]$Element,
                [Parameter(Mandatory=$True)]
                [boolean]$O365,
                [Parameter(Mandatory=$True)]
                [boolean]$SyncML
                
            )
            $retVal = @()
            if($O365)
            {
                $retVal += Get-CodePageBytes ([int]"0x$($Element.NamespaceURI.Substring(1))")
            }
            else
            {
                $retVal += Get-CodePageBytes (Get-CodePage -Name $Element.NamespaceURI -O365 $O365 -SyncML $SyncML).Code 
            }
            
            $retVal += Get-Content $Element -O365 $O365 -SyncML $SyncML
            #$retVal += $TagClose

            return $retVal
        }

        function Get-Content{
        Param(
                [Parameter(Mandatory=$True)]
                [System.Xml.XmlElement]$Element,
                [Parameter(Mandatory=$True)]
                [boolean]$O365,
                [Parameter(Mandatory=$True)]
                [boolean]$SyncML
            )
            $retVal = @()

            if($Element.LocalName -eq "EXT_1")
            {
                # EXT_1 is used as a string
                $retVal += 0xC1 # EXT_1
                # After token, add the length of the string
                $stringBytes = [system.Text.Encoding]::UTF8.GetBytes($Element.InnerText)
                # 0D 0A -> 0D
                $stringBytes = LF2CRLF -bytes $stringBytes
                $retVal += EncodeMultiByteInteger -value  $stringBytes.Length
                $retVal += $stringBytes
                $retVal += 0x00 # End of the string
            }
            elseif($Element.LocalName -eq "EXT_2")
            {
                # EXT_2 is used as an integer (normally). But here the integers can be veeeery long (more than 64bits), so this is not working properly.
                $retVal += 0xC2 # EXT_2
                $retVal += Encode-EXT2 -Bytes (Convert-HexToByteArray -HexString $Element.InnerText)
                #$retVal += EncodeMultiByteInteger -value $Element.InnerText
            }
            elseif($Element.HasChildNodes)
            {
                if($O365)
                {
                    $byte = [byte]"0x$($Element.LocalName.Substring(4))" + $TokenWithContent
                }
                else
                {
                    $byte=((Get-Token -CodePage $CurrentCodePage -Tag $Element.LocalName -O365 $O365 -SyncML $SyncML) + $TokenWithContent)
                }

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
                        $retVal += Get-Element $child -O365 $O365 -SyncML $SyncML
                    }
                }

                $retVal += $TagClose
            }
            else
            {
                if($O365)
                {
                    $retVal += [byte]"0x$($Element.LocalName.Substring(4))"
                }
                else
                {
                    $retVal += Get-Token -CodePage $CurrentCodePage -Tag $Element.LocalName -O365 $O365 -SyncML $SyncML
                }
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
            $UTFBytes = [text.encoding]::UTF8.GetBytes($CData.Data)
            #$UTFBytes = [convert]::FromBase64String($CData.Data)
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
        [byte[]]$wbxml,
        [Parameter(Mandatory=$False)]
        [int]$Skip=4, # Skip the header by default
        [switch]$O365,
        [switch]$SyncML
    )

    Process
        {

        # Some variables
        $EXT_1 = 0xC1
        $EXT_2 = 0xC2
        $Script:WBXML_currentPage = 0
        $Script:WBXML_position = $Skip

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
                [byte]$next,
                [Parameter(Mandatory=$True)]
                [boolean]$O365,
                [Parameter(Mandatory=$True)]
                [boolean]$SyncML
            )

            $codePageChanged=$false
        
            if($next -eq 0) # The first token, 0 = change the codepage
            {
                $Script:WBXML_currentPage = Get-CurrentToken $wbxml
                $codePageChanged=$true
                $next = Get-CurrentToken $wbxml
            }

            if($next -eq $EXT_1) # Special handling for EXT_1
            {
                # After the token, the length of the string as multi-byte value
                $byteValue = $wbxml[$Script:WBXML_position]

                if(CheckContinuationBit -byteVal $byteValue)
                {
                    $intValue = Get-CDATALength -wbxml $wbxml
                }
                else
                {
                    $intValue = $byteValue
                    $Script:WBXML_position+=1
                }

                # Get the string
                $stringBytes = $wbxml[$Script:WBXML_position..$($Script:WBXML_position + $intValue -1)]
                $stringValue = [system.text.encoding]::UTF8.GetString($stringBytes)
                #$stringValue = Get-String -wbxml $wbxml

                $Script:WBXML_position+=$intValue+1

                $retval = "<EXT_1>$([System.Net.WebUtility]::HtmlEncode($stringValue))</EXT_1>"

                
            }
            elseif($next -eq $EXT_2) # Special handling for EXT_2
            {
                #$byteValue = $wbxml[$Script:WBXML_position]

                # EXT_2 is used as an integer (normally). But here the integers can be veeeery long (more than 64bits), so we only support hex values.
                $hexString = Convert-ByteArrayToHex -Bytes (Decode-EXT2 -wbxml $wbxml)

                <#
                if(CheckContinuationBit -byteVal $byteValue)
                {
                    # EXT_2 is used as an integer (normally). But here the integers can be veeeery long (more than 64bits), so this is not working properly.
                    $intValue = Get-CDATALength -wbxml $wbxml
                }
                else
                {
                    $intValue = $byteValue
                    $Script:WBXML_position+=1
                }#>
                $retval = "<EXT_2>$hexString</EXT_2>"
                
            }
            else
            {

                $hasContent = ($next -band 0x40) -eq 0x40
                $currentToken = $next -band 0x3f

                if($O365)
                {
                    $codePage = "_$([System.BitConverter]::ToString($Script:WBXML_currentPage))"
                    $tag = $codePage
                    $tag += "_"
                    $tag += [System.BitConverter]::ToString($currentToken)
                }
                else
                {
                    $codePage = Get-CodePage -Code $Script:WBXML_currentPage -O365 $O365 -SyncML $SyncML | Select -ExpandProperty NameSpace
                    $tag = Get-Token -CodePage $Script:WBXML_currentPage -Code $currentToken -O365 $O365 -SyncML $SyncML
                }
        
                if($codePageChanged)
                {
                    $retval = "<$tag xmlns=`"$codePage`">"
                }
                else
                {
                    $retval = "<$tag>"
                    #$retval = "<$tag xmlns=`"$codePage`">"
                }

                if($hasContent) 
                {
                    while($Script:WBXML_position -le $wbxml.Length -and (($next = Get-CurrentToken -wbxml $wbxml) -ne 0x01) )
                    {
                        if($next -eq 0x03) # Start of string
                        {
                            $retVal += Get-String -wbxml $wbxml
                        }
                        elseif($next -eq 0x04) # Start of string table string
                        {
                            # The next byte is the index number of the text from string table
                            $index = Get-CurrentToken -wbxml $wbxml
                            # TODO: Implement string table handling
                        }
                        elseif($next -eq 0xC3) # Start of blob
                        {
                            $retVal += Get-CData -wbxml $wbxml
                        }
                        else
                        {
                            $retVal += Parse-Element -wbxml $wbxml -next $next -O365 $O365 -SyncML $SyncML
                        }
                    }
                }

                $retval += "</$tag>"
            }

            # Verbose
            Write-Verbose $retval

            return $retVal
        }

        function Get-String{
        Param(
                [Parameter(Mandatory=$True)]
                [byte[]]$wbxml
            )
            $next = 0
            $bytes = @()
            while(($next = Get-CurrentToken -wbxml $wbxml) -ne 0x00 -and $next -ne 0x01)
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
            $retVal +=  [convert]::ToBase64String($bytes)#[System.Text.Encoding]::UTF8.GetString($bytes)
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

        $retVal = Parse-Element -wbxml $wbxml -next (Get-CurrentToken -wbxml $wbxml) -O365 $O365 -SyncML $SyncML

        #return ([xml]$retVal).InnerXml
        return $retVal
    }
}

# Checks whether the multi-byte integer has more bytes
function CheckContinuationBit
{
    Param(
        [Parameter(Mandatory=$True)]
        [byte]$byteVal
    )

    [byte] $continuationBitmask = 0x80;
    return ($continuationBitmask -band $byteval) -ne 0
}

# Encodes integer as multi-byte integer
function EncodeMultiByteInteger
{
    param(
        [parameter(Mandatory=$true)]
        [int]$value
    )
    Process
    {
        # If integer is 0, just return that
        if($value -eq 0)
        {
            return 0
        }

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
        [Parameter(Mandatory=$False)]
        [String]$DeviceOS,
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
    
        $url="https://outlook.office365.com/Microsoft-Server-ActiveSync?Cmd=$Command&User=$(Get-UserNameFromAuthHeader($Authorization))&DeviceId=$DeviceId&DeviceType=$DeviceType&DeviceOS=$DeviceOS"    

        $headers = @{
            "Authorization" = Create-AuthorizationHeader -Credentials $Credentials -AccessToken $AccessToken -Resource "https://outlook.office365.com" -ClientId "d3590ed6-52b3-4102-aeff-aad2292ab01c"
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
    
        $response=Invoke-WebRequest -UseBasicParsing -Uri $Url -Method Post -Headers $headers -Body $body -TimeoutSec 30
    
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

# Jan 2nd 2020
# Converts Office 365 WBXML (Outlook for Android) to XML
function O365WBXML2XML
{
    Param(
        [Parameter(Mandatory=$True)]
        [byte[]]$wbxml
    )

    Process
    {
        # First, strip the ~StartOutlookFrame~ and ~EndOutlookFrame~

        # 13 7E 53 74 61 72 74 4F 75 74 6C 6F 6F 6B 46 72 61 6D 65 7E
        #     ~  S  t  a  r  t  O  u  t  l  o  o  k  F  r  a  m  e  ~

        # 11 7E 45 6E 64 4F 75 74 6C 6F 6F 6B 46 72 61 6D 65 7E
        #    ~  E  n  d  O  u  t  l  o  o  k  F  r  a  m  e  ~

        #
        
        # Set the position to 0 and initialize the return variable
        $pos=0

        $retVal="<frames>"

        # Loop through all the frames
        while($pos -lt $wbxml.Length)
        {
            $retVal+="<frame>"

            # First, get the length bytes
            $int_1 = [bitconverter]::toint32($wbxml[$($pos+20)..$($pos+23)],0) # The length of the first wbxml block
            $int_2 = [bitconverter]::toint32($wbxml[$($pos+24)..$($pos+27)],0) # The length of the second wbxml block
            $int_3 = [bitconverter]::toint32($wbxml[$($pos+28)..$($pos+31)],0) # The total length of the data

            Write-Verbose "First wbxml block $int_1 bytes"
            Write-Verbose "Second wbxml block $int_2 bytes"
            Write-Verbose "Total wbxml block $int_3 bytes"
            Write-Verbose "True wbxml block $($wbxml.length) bytes"

            # Extract the frame and strip ~StartOutlookFrame~ and ~EndOutlookFrame~
            $frame = $wbxml[$($pos+20+12)..$($pos+20+12+$int_3-1)] 

            # Set the position to the next frame position + ~StartOutlookFrame~ + length bytes + current frame size + ~EndlOutlookFrame~
            $pos=$pos+20+12+$int_3+18
            
            # Get the two wbxml blocks
            $wbxml1 = $frame[0..$($int_1-1)]
            $wbxml2 = $frame[$int_1..$($frame.Length)]

            $retVal +="<block>"
            $retVal += WBXML2XML -wbxml $wbxml1 -O365
            $retVal +="</block>"

            # The second block might not be available
            if($int_2 -gt 0)
            {
                $retVal +="<block>"
                $retVal += WBXML2XML -wbxml $wbxml2 -O365
                $retVal +="</block>"
            }
            $retVal+="</frame>"
        }

        $retVal+="</frames>"
        
        
        # Return
        $retVal
    }
}

# Jan 2nd 2020
# Converts XML to Office 365 WBXML (Outlook for Android)
function XML2O365WBXML
{
    Param(
        [Parameter(Mandatory=$True)]
        [xml]$xml
    )

    Process
    {
        # ~StartOutlookFrame~ and ~EndOutlookFrame~
        $startFrame = @(0x13, 0x7E, 0x53, 0x74, 0x61, 0x72, 0x74, 0x4F, 0x75, 0x74, 0x6C, 0x6F, 0x6F, 0x6B, 0x46, 0x72, 0x61, 0x6D, 0x65, 0x7E)
        $endFrame = @(0x11, 0x7E, 0x45, 0x6E, 0x64, 0x4F, 0x75, 0x74, 0x6C, 0x6F, 0x6F, 0x6B, 0x46, 0x72, 0x61, 0x6D, 0x65, 0x7E)
        
        $wbxml=@()

        # Loop through the frames
        foreach($frame in $xml.DocumentElement.frame)
        {
            # The second xml block is empty on response messages
            $int_2=0

            # Convert xml to wbxml
            if($frame.block[0] -eq $null)
            {
                $wbxml1 = XML2WBXML -Xml $frame.block.innerXml -O365
            }
            else
            {
                $wbxml1 = XML2WBXML -Xml $frame.block[0].innerXml -O365
            }
            
            if($frame.block[1] -ne $null)
            {
                $wbxml2 = XML2WBXML -Xml $frame.block[1].innerXml -O365
                $int_2 = $wbxml2.length # The length of the second wbxml block
            }

            # Get the lengths
            $int_1 = $wbxml1.length # The length of the first wbxml block
            $int_3 = $int_1+$int_2  # The total length of the data

            # Construct the frame
            $wbxml += $startFrame
            $wbxml += [bitconverter]::GetBytes([int32]$int_1)
            $wbxml += [bitconverter]::GetBytes([int32]$int_2)
            $wbxml += [bitconverter]::GetBytes([int32]$int_3)
            $wbxml += $wbxml1

            Write-Verbose "First wbxml block $int_1 bytes"
            Write-Verbose "Second wbxml block $int_2 bytes"
            Write-Verbose "Total wbxml block $int_3 bytes"
            Write-Verbose "True wbxml block $($wbxml.length) bytes"
            
            if($wbxml2 -ne $null)
            {
                $wbxml += $wbxml2
            }
            $wbxml += $endFrame
        }

        # Return
        return $wbxml
    }
}

function ByteArrayToBinary
{
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [byte[]]$Bytes
    )
    Process
    {
        $retVal = ""
        for($i = 0; $i -lt $Bytes.Length ; $i++)
        {
            $binTxt = [convert]::ToString($Bytes[$i],2)
            while($binTxt.length -lt 8)
            {
                $binTxt = "0$binTxt"
            }
            $retVal += $binTxt
            #$retVal += " "
        }

        return $retVal
    }
}

# Decodes EXT_2 from O365WBXML
function Decode-EXT2
{
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [byte[]]$wbxml

    )
    Process
    {
        [byte[]]$retVal = @(0,0,0,0,0,0,0,0,0)
        $pos = 0
        [byte] $singleByte = 0xFF

        do
        {
            # Save the last bit to be added to the value later
            $firstBit = $retVal[8] -shl 7

            # Shift the bits to the left (at the beginning it's empty anyway)
            Shift-ByteArrayLeft $retVal

            # Get the byte
            $singleByte = $wbxml[$Script:WBXML_position++]
            
            # Add it to the last byte of the array saving the first bit
            $retVal[8] = ($singleByte -band 0x7f) -bor $firstBit

            $pos++

            Write-Verbose (ByteArrayToBinary -Bytes $retVal)
        }
        while (CheckContinuationBit($singleByte))

        if($pos -gt 8)
        {
            $pos--
        }

        $retVal = $retVal[(9-$pos)..9]

        return $retVal
    }
}

function Encode-EXT2
{
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [byte[]]$Bytes

    )
    Process
    {
        $retVal = @()

        [byte] $singleByte = 0xFF

        # Needed in a halfway
        $byteShift=0

        # Set the length
        $length = $Bytes.Length
        if($length -gt 7)
        {
            $length++
        }

        for($i=0; $i -lt $length ; $i++)
        {
            # Get the last byte
            $singleByte = $Bytes[$Bytes.Length-1]

            # Add to the retval
            $retVal += $singleByte
            
            
            Write-Verbose (ByteArrayToBinary -Bytes $Bytes)

            # Shift to right
            Shift-ByteArrayRight $Bytes
            
            if($i -gt 0)
            {
                $byteShift = 1
            }
            elseif($i -gt 7)
            {
                $byteShift = 2
            }

            $Bytes[$i-$byteShift] = 0x00
            
        }

        [array]::Reverse($retVal)

        # Set or remove the continuation bits
        for($i=0; $i -lt $retVal.Length-1 ; $i++)
        {
            $retVal[$i] = $retVal[$i] -bor 0x80
        }
        $retVal[$retVal.Length-1] = $retVal[$retVal.Length-1] -band 0x7F
                
        
        
        $retVal
    }
}

# Shifts bits in the given byte array to left by seven bits
function Shift-ByteArrayLeft
{
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [byte[]]$Bytes
    )
    Process
    {
        for($i = 0 ; $i -lt $Bytes.length-1 ; $i++)
        {
            # Get the current byte
            $this = $Bytes[$i]
            # Save the last bit and shift it to left
            $lastBit = $this -shl 7

            # Get the next byte
            $next = $Bytes[$i+1]

            # Set the seven first bits to current byte with the saved bit
            $Bytes[$i] = ($next -shr 1) -bor $lastBit
        }

        
    }
}

function Shift-ByteArrayRight
{
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [byte[]]$Bytes
    )
    Process
    {
        for($i = $Bytes.length-1 ; $i -gt 0 ; $i--)
        {
            # Get the current byte
            $this = $Bytes[$i]
            # Save the first bit and shift it to right
            $firstBit = $this -shr 7

            # Get the previous byte
            $previous = $Bytes[$i-1]

            # Set the seven first bits to current byte with the saved bit
            $Bytes[$i] = ($previous -shl 1) + $firstBit
        }

        
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
            (Token 0x02 "tag2"), # O365WBXML

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

# Office 365 undocumented WBXML CodePage and tokens
$O365CodePages = @(
    (CodePage 0xFF "Sync" @(
            (Token 0x01 "A1_01"),
            (Token 0x04 "A4_04"),
            (Token 0x05 "Sync"),
            (Token 0x06 "Setting1"),
			(Token 0x07 "Setting2"),
            (Token 0x08 "Setting3"),
            (Token 0x09 "DeviceId"), 
            (Token 0x0A "A10_0A"), 
            (Token 0x0B "A11_0B"),
            (Token 0x0C "A12_0C"),
            (Token 0x0D "Setting4"),
            (Token 0x0E "Setting5"),
            (Token 0x0F "Setting6"),
            (Token 0x10 "A16_16"),
            (Token 0x11 "A17_11"),
            (Token 0x12 "ClientAccessServerName"),
            (Token 0x13 "ServerName"),
            (Token 0x14 "A20_14"),
            (Token 0x15 "A21_15"),
            (Token 0x16 "A22_16"),
            (Token 0x17 "A23_17"),
            (Token 0x18 "A24_18"),
            (Token 0x19 "A25_19"),
            (Token 0x1A "A26_1A"),
            (Token 0x1B "A27_1B"),
            (Token 0x1C "A28_1C"),
            (Token 0x1D "A29_1D"),
            (Token 0x1E "A30_1E"),
            (Token 0x1F "A31_1F"),
            (Token 0x20 "A32_20"),
            (Token 0x21 "A33_21"),
            (Token 0x22 "A34_22"),
            (Token 0x23 "A35_23"),
            (Token 0x25 "A37_25"),
            (Token 0x26 "A38_26"),
            (Token 0x27 "A39_27"),
            (Token 0x28 "A40_28"),
            (Token 0x29 "A41_29"),
            (Token 0x2A "A42_2A"),
            (Token 0x2B "A43_2B"),
            (Token 0x2E "A46_2E"),
            (Token 0x33 "A51_33"),
            (Token 0x39 "A57_39"))
    ),
	(CodePage 0xE0 "Outlook" @(
        (Token 0x20 "B32_20"),
        (Token 0x23 "B35_23"),
        (Token 0x37 "B55_37"),
        (Token 0x3B "B59_3B"),
        (Token 0x3C "B60_3C"),
        (Token 0x3D "B61_3D"),
        (Token 0x3E "B62_3E"))
	),
    (CodePage 0xE1 "Settings" @(
        (Token 0x19 "C25_19"),
        (Token 0x1A "C26_1A")
        (Token 0x1B "C27_1B"),
        (Token 0x1C "C28_1C"),
        (Token 0x1D "C29_1D"),
        (Token 0x1E "C30_1E"),
        (Token 0x1F "C31_1F"),
        (Token 0x24 "C36_24"),
        (Token 0x29 "C41_29"))
	),
    (CodePage 0x10 "O365WBXML4" @(
        (Token 0x11 "D17_11"),
        (Token 0x12 "D18_12"),
        (Token 0x13 "D19_13"),
        (Token 0x14 "D20_14"),
        (Token 0x15 "D21_15"),
        (Token 0x16 "D22_16"),
        (Token 0x17 "D23_17"),
        (Token 0x18 "D24_18"))
	),
    (CodePage 0x1B "O365WBXML5" @(
        (Token 0x17 "E23_17"),
        (Token 0x22 "E34_22"))
	),
    (CodePage 0x0E "O365WBXML6" @(
        (Token 0x37 "F55_37"),
        (Token 0x38 "F56_38"),
        (Token 0x3B "F59_3B"),
        (Token 0x3C "F60_3C"),
        (Token 0x3D "F61_3D"),
        (Token 0x3E "F62_3E"),
        (Token 0x3F "F63_3F"))
	),
    (CodePage 0x00 "O365WBXML7" @(
        (Token 0x06 "G6_06"),
        (Token 0x08 "G8_08"),
        (Token 0x09 "G9_09"),
        (Token 0x0B "G11_0B"),
        (Token 0x24 "G36_24"),
        (Token 0x2C "G44_2C"),
        (Token 0x2D "G45_2D"),
        (Token 0x31 "G49_31"),
        (Token 0x32 "G50_32"),
        (Token 0x33 "G51_33"),
        (Token 0x34 "G52_34"),
        (Token 0x35 "G53_35"),
        (Token 0x36 "G54_36"),
        (Token 0x37 "G55_37"),
        (Token 0x38 "G56_38"),
        (Token 0x39 "G57_39"),
        (Token 0x3A "G58_3A"),
        (Token 0x3B "G59_3B"),
        (Token 0x3C "G60_3C"),
        (Token 0x3D "G61_3D"),
        (Token 0x3E "G62_3E"),
        (Token 0x3F "G63_3F"))
	),
    (CodePage 0x11 "O365WBXML8" @(
        (Token 0x06 "H6_06"),
        (Token 0x1A "h26_1A"),
        (Token 0x1E "H30_1E"),
        (Token 0x1F "H31_1F"),
        (Token 0x24 "H36_24"),
        (Token 0x31 "H49_31"),
        (Token 0x32 "H50_32"),
        (Token 0x33 "H51_33"),
        (Token 0x34 "H52_34"),
        (Token 0x35 "H53_35"),
        (Token 0x36 "H54_36"),
        (Token 0x3A "H58_3A"),
        (Token 0x3B "H59_3B")
        (Token 0x3C "H60_3C")
        (Token 0x3D "H61_3D")
        (Token 0x3E "H62_3E")
        (Token 0x3F "H63_3F"))
	),
    (CodePage 0x14 "O365WBXML9" @(
        (Token 0x08 "I8_09"),
        (Token 0x12 "I18_12"),
        (Token 0x29 "I41_29"),
        (Token 0x38 "I56_38"))
	),
    (CodePage 0x01 "O365WBXML10" @(
        (Token 0x06 "J6_06"),
        (Token 0x07 "J7_07"),
        (Token 0x08 "J8_08"),
        (Token 0x09 "J9_09"),
        (Token 0x0A "J10_0A"),
        (Token 0x0B "J11_0B"),
        (Token 0x0C "J12_0C"),
        (Token 0x0D "J13_0D"),
        (Token 0x0E "J14_0E"),
        (Token 0x0F "J15_0F"),
        (Token 0x10 "J16_10"),
        (Token 0x11 "J17_11"),
        (Token 0x12 "J18_12"),
        (Token 0X13 "J19_13"),
        (Token 0x14 "J20_14"),
        (Token 0x15 "J21_15"),
        (Token 0x16 "J22_16"),
        (Token 0x17 "J23_17"),
        (Token 0x18 "J24_18"))
	),
    (CodePage 0x08 "O365WBXML11" @(
        (Token 0x3E "K62_3E"))
	),
    (CodePage 0x13 "O365WBXML12" @(
        (Token 0x07 "L7_07"),
        (Token 0x0A "L10_0A"),
        (Token 0x0B "L11_0B"),
        (Token 0x26 "L38_26"),
        (Token 0x3B "L59_3B"),
        (Token 0x3C "L60_3C"),
        (Token 0x3D "L61_3D"))
	),
    (CodePage 0x16 "O365WBXML13" @(
        (Token 0x1A "M26_1A"),
        (Token 0x1B "M27_1B"),
        (Token 0x2D "M45_2D"),
        (Token 0x2E "M46_2E"),
        (Token 0x2F "M47_2F"),
        (Token 0x34 "M52_34"))
	),
    (CodePage 0x04 "O365WBXML14" @(
        (Token 0x39 "N57_39"))
	),
    (CodePage 0x15 "O365WBXML15" @(
        (Token 0x1B "O27_1B"),
        (Token 0x28 "O40_28"),
        (Token 0x27 "O39_27"),
        (Token 0x38 "O56_38"),
        (Token 0x3E "O62_3E"),
        (Token 0x3D "O63_3D")
        (Token 0x3E "O64_3E")
        (Token 0x3F "O65_3F"))
	),
    (CodePage 0x17 "O365WBXML16" @(
        (Token 0x1C "P28_1C"),
        (Token 0x1D "P29_1D"),
        (Token 0x1E "P30_1E"))
	),
    (CodePage 0x0D "O365WBXML17" @(
        (Token 0x28 "Q40_28"),
        (Token 0x39 "Q57_39"))
	),
    (CodePage 0x02 "O365WBXML18" @(
        (Token 0x35 "R53_35"))
	),
    (CodePage 0x1A "O365WBXML19" @(
        (Token 0x0D "S13_0D"),
        (Token 0x31 "S49_31"),
        (Token 0x39 "S57_39"),
        (Token 0x3A "S58_3A"))
	),
    (CodePage 0x1D "O365WBXML20" @(
        (Token 0x2E "T46_2E"))
	),
    (CodePage 0x09 "O365WBXML21" @(
        (Token 0x05 "U5_05"),
        (Token 0x06 "U6_06"),
        (Token 0x07 "U7_07"),
        (Token 0x08 "U8_08"),
        (Token 0x09 "U9_09"),
        (Token 0x0A "U10_0A"),
        (Token 0x0B "U11_0B")
        (Token 0x0C "U12_0C")
        (Token 0x0D "U13_0D")
        (Token 0x0E "U14_0E")
        (Token 0x0F "U15_0F")
        (Token 0x10 "U16_10"))
	),
    (CodePage 0x12 "O365WBXML22" @(
        (Token 0x2D "V45_2D"),
        (Token 0x31 "V49_31"),
        (Token 0x37 "V55_37"))
	),
    (CodePage 0x18 "O365WBXML23" @(
        (Token 0x2E "W46_2E"))
	),
    (CodePage 0x1C "O365WBXML24" @(
        (Token 0x28 "X40_28"),
        (Token 0x29 "X41_29"),
        (Token 0x35 "X53_35"))
	),
    (CodePage 0x0F "O365WBXML25" @(
        (Token 0x05 "Y5_05"),
        (Token 0x06 "Y6_06"),
        (Token 0x07 "Y7_07"),
        (Token 0x08 "Y8_08"),
        (Token 0x09 "Y9_09"),
        (Token 0x0A "Y10_0A"),
        (Token 0x0B "Y11_0B"),
        (Token 0x0C "Y12_0C"),
        (Token 0x0D "Y13_0D"),
        (Token 0x0E "Y14_0E"),
        (Token 0x0F "Y15_0F"),
        (Token 0x10 "Y16_10"),
        (Token 0x11 "Y17_11"),
        (Token 0x12 "Y18_12"),
        (Token 0x13 "Y19_13"),
        (Token 0x14 "Y20_14"),
        (Token 0x1A "Y26_1A"),
        (Token 0x1B "Y27_1B"),
        (Token 0x1C "Y28_1C"),
        (Token 0x1D "Y29_1D"),
        (Token 0x1E "Y30_1E"),
        (Token 0x1F "Y31_1F"),
        (Token 0x24 "Y36_24"),
        (Token 0x25 "Y37_25"),
        (Token 0x26 "Y38_26"),
        (Token 0x27 "Y39_27"),
        (Token 0x28 "Y40_28"),
        (Token 0x29 "Y41_29"),
        (Token 0x2A "Y42_2A"),
        (Token 0x2B "Y43_2B"),
        (Token 0x2C "Y44_2C"),
        (Token 0x2D "Y45_2D"),
        (Token 0x2E "Y46_2E"),
        (Token 0x2F "Y47_2F"),
        (Token 0x30 "Y48_30"),
        (Token 0x31 "Y49_31"),
        (Token 0x32 "Y50_32"),
        (Token 0x33 "Y51_33"),
        (Token 0x34 "Y52_34"),
        (Token 0x35 "Y53_35"))
	)
)

# SyncML WBXML CodePages and tokens
$SyncMLCodePage = @(
        (CodePage 0 "SYNCML:SYNCML1.2" @(
			(Token 0x05 "Add"),
			(Token 0x06 "Alert"),
			(Token 0x07 "Archive"),
			(Token 0x08 "Atomic"),
			(Token 0x09 "Chal"),
			(Token 0x0A "Cmd"),
			(Token 0x0B "CmdID"),
			(Token 0x0C "CmdRef"),
			(Token 0x0D "Copy"),
			(Token 0x0E "Cred"),
			(Token 0x0F "Data"),
			(Token 0x10 "Delete"),
            (Token 0x11 "Exec"),
			(Token 0x12 "Final"),
			(Token 0x13 "Get"),
			(Token 0x14 "Item"),
			(Token 0x15 "Lang"),
			(Token 0x16 "LocName"),
			(Token 0x17 "LocURI"),
			(Token 0x18 "Map"),
            (Token 0x19 "MapItem"),
            (Token 0x1A "Meta"),
			(Token 0x1B "MsgID"),
			(Token 0x1C "MsgRef"),
			(Token 0x1D "NoResp"),
			(Token 0x1E "NoResults"),
            (Token 0x1F "Put"),
			(Token 0x20 "Replace"),
			(Token 0x21 "RespURI"),
			(Token 0x22 "Results"),
			(Token 0x23 "Search"),
			(Token 0x24 "Sequence"),
			(Token 0x25 "SessionID"),
			(Token 0x26 "SftDel"),
			(Token 0x27 "Source"),
			(Token 0x28 "SourceRef"),
			(Token 0x29 "Status"),
            (Token 0x2A "Sync"),
			(Token 0x2B "SyncBody"),
			(Token 0x2C "SyncHdr"),
			(Token 0x2D "SyncML"),
			(Token 0x2E "Target"),
			(Token 0x2F "TargetRef"),
            (Token 0x30 "RESERVED"), # Reserved for future use.
			(Token 0x31 "VerDTD"),
			(Token 0x32 "VerProto"),
			(Token 0x33 "NumberOfChanges"),
			(Token 0x34 "MoreData"),
			(Token 0x35 "Field"),
			(Token 0x36 "Filter"),
			(Token 0x37 "Record"),
			(Token 0x38 "FilterType"),
			(Token 0x39 "SourceParent"),
            (Token 0x3A "TargetParent"),
			(Token 0x3B "Move"),
			(Token 0x3C "Correlator"))
        ),
    
        (CodePage 1 "syncml:metinf" @(
			(Token 0x05 "Anchor"),
			(Token 0x06 "EMI"),
			(Token 0x07 "Format"),
			(Token 0x08 "FreeID"),
			(Token 0x09 "FreeMem"),
			(Token 0x0A "Last"),
			(Token 0x0B "Mark"),
			(Token 0x0C "MaxMsgSize"),
			(Token 0x0D "Mem"),
			(Token 0x0E "MetInf"),
			(Token 0x0F "Next"),
			(Token 0x10 "NextNonce"),
            (Token 0x11 "SharedMem"),
			(Token 0x12 "Size"),
			(Token 0x13 "Type"),
			(Token 0x14 "Version"),
			(Token 0x15 "MaxObjSize"))
	    )
)