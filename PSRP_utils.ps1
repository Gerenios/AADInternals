# PowerShell Remoting Protocol utils


# Constants
$const_bom = [byte[]]@(0xEF,0xBB,0xBF)

# Fragments
$const_fragment_start =     0x01
$const_fragment_end =       0x02 
$const_fragment_start_end = 0x03
$const_fragment_middle =    0x00
$PSRM_message_fragment=@{
    $const_fragment_start =     "Start"
    $const_fragment_end =       "End"
    $const_fragment_start_end = "Single"
    $const_fragment_middle =    "Middle"
}

# Destinations
$const_destination_client = 0x01
$const_destination_server = 0x02
$PSRM_message_destination=@{
    $const_destination_client = "Client"
    $const_destination_server = "Server"
}

# Message types
$const_SESSION_CAPABILITY =       0x00010002
$const_INIT_RUNSPACEPOOL =        0x00010004
$const_PUBLIC_KEY =               0x00010005
$const_ENCRYPTED_SESSION_KEY =    0x00010006
$const_PUBLIC_KEY_REQUEST =       0x00010007
$const_CONNECT_RUNSPACEPOOL =     0x00010008
$const_SET_MAX_RUNSPACES =        0x00021002
$const_SET_MIN_RUNSPACES =        0x00021003
$const_RUNSPACE_AVAILABILITY =    0x00021004
$const_RUNSPACEPOOL_STATE =       0x00021005
$const_CREATE_PIPELINE =          0x00021006
$const_GET_AVAILABLE_RUNSPACES =  0x00021007
$const_USER_EVENT =               0x00021008
$const_APPLICATION_PRIVATE_DATA = 0x00021009
$const_GET_COMMAND_METADATA =     0x0002100A
$const_RUNSPACEPOOL_INIT_DATA =   0x0002100B
$const_RESET_RUNSPACE_STATE =     0x0002100C
$const_RUNSPACEPOOL_HOST_CALL =   0x00021100
$const_RUNSPACEPOOL_HOST_RESPONSE=0x00021101
$const_PIPELINE_INPUT =           0x00041002
$const_END_OF_PIPELINE_INPUT =    0x00041003
$const_PIPELINE_OUTPUT =          0x00041004
$const_ERROR_RECORD =             0x00041005
$const_PIPELINE_STATE =           0x00041006
$const_DEBUG_RECORD =             0x00041007
$const_VERBOSE_RECORD =           0x00041008
$const_WARNING_RECORD =           0x00041009
$const_PROGRESS_RECORD =          0x00041010
$const_INFORMATION_RECORD =       0x00041011
$const_PIPELINE_HOST_CALL =       0x00041100
$const_PIPELINE_HOST_RESPONSE =   0x00041101

$PSRM_message_types=@{
    $const_SESSION_CAPABILITY =       "Session capability"      
    $const_INIT_RUNSPACEPOOL =        "Init runspacepool"
    $const_PUBLIC_KEY =               "Public key"
    $const_ENCRYPTED_SESSION_KEY =    "Encrypted session key"
    $const_PUBLIC_KEY_REQUEST =       "Public key request"
    $const_SET_MAX_RUNSPACES =        "Set max runspaces"
    $const_SET_MIN_RUNSPACES =        "Set min runspaces"
    $const_RUNSPACE_AVAILABILITY =    "Runspace availability"
    $const_APPLICATION_PRIVATE_DATA = "Application private data"
    $const_GET_COMMAND_METADATA =     "Get command metadata"
    $const_RUNSPACEPOOL_STATE =       "Runspool state"
    $const_CREATE_PIPELINE =          "Create pipeline"
    $const_GET_AVAILABLE_RUNSPACES =  "Get available runspaces"
    $const_USER_EVENT =               "User event"
    $const_RUNSPACEPOOL_HOST_CALL =   "Runspacepool host call"
    $const_RUNSPACEPOOL_HOST_RESPONSE = "Runspacepool host response"
    $const_PIPELINE_STATE =           "Pipeline state"
    $const_PIPELINE_INPUT =           "Pipeline input" 
    $const_END_OF_PIPELINE_INPUT =    "End of pipeline input"
    $const_PIPELINE_OUTPUT =          "Pipeline output"
    $const_PIPELINE_HOST_CALL =       "Pipeline host call"
    $const_PIPELINE_HOST_RESPONSE =   "Pipeline host response"
    $const_ERROR_RECORD =             "Error record"
    $const_DEBUG_RECORD =             "Debug record"
    $const_VERBOSE_RECORD =           "Verbose record"
    $const_WARNING_RECORD =           "Warning record"
    $const_PROGRESS_RECORD =          "Progress record"
    $const_INFORMATION_RECORD =       "Informaition record"
    $const_CONNECT_RUNSPACEPOOL =     "Connect runspacepool"
    $const_RUNSPACEPOOL_INIT_DATA =   "Runspacepool init data"
    $const_RESET_RUNSPACE_STATE =     "Reset runspace state"
}

# Runspace status
$const_beforeopen =           0x00
$const_opening =              0x01
$const_opened =               0x02
$const_closed =               0x03
$const_closing =              0x04
$const_broken =               0x05
$const_negotiationsent =      0x06
$const_negotiationsucceeded = 0x07
$const_connecting =           0x08
$const_disconnected =         0x09

# Invocation state
$const_Notstarted =   0x00
$const_Running =      0x01
$const_Stopping =     0x02
$const_Stopped =      0x03
$const_Completed =    0x04
$const_Failed =       0x05
$const_Disconnected = 0x06

# Waiting messages
$waiting_messages=@(
"Your PC is almost ready..."
"We're getting everything ready for you..."
"Almost there..."
"Back in a moment..."
"This might take several minutes..."
"It's taking a bit longer than expected, but we'll get there as fast as we can..."
"Don't turn off your PC..."
"This might take a while..."
"This might take a while, I'll tell you when we're ready.."

)

# Function returning a random waiting message
function Get-WaitingMessage
{
    [int]$msg=Get-Random -Minimum 0 -Maximum ($waiting_messages.Count-1)
    return $waiting_messages[$msg]
}

# Remove bom bytes from the byte array
function Remove-Bom
{
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [Byte[]]$ByteArray
    )
    Process
    {
        Remove-Bytes -ByteArray $ByteArray -BytesToRemove $const_bom
    }
}

# removes the given bytes from the given bytearray
function Remove-Bytes
{
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [Byte[]]$ByteArray,
        [Parameter(Mandatory=$True)]
        [Byte[]]$BytesToRemove
    )
    Process
    {
        $retVal = @()

        for($i = 0; $i -le $ByteArray.Count; $i++)
        {
            $AddByte=$true

            for($b = 0; $b -le $BytesToRemove.Count; $b++)
            {
                $ByteToRemove = $BytesToRemove[$b]
                if($ByteArray[$i] -eq $ByteToRemove)
                {
                    $AddByte=$false
                }
            }
            if($AddByte)
            {
                $retVal+=$ByteArray[$i]
            }
        }

        $retVal
    }
}


# Parse the PowerShell Remoting Protocol Message
function Parse-PSRPMessage
{
    [cmdletbinding()]
    Param(
        [Parameter(ParameterSetName='Base64',Mandatory=$True)]
        [String]$Base64Value,

        [Parameter(ParameterSetName='Byte',Mandatory=$True)]
        [Byte[]]$ByteArray,

        [Parameter(Mandatory=$False)]
        [int]$Skip=0

    )
    Process
    {
        # If Base64, decode to byte[]
        if(![String]::IsNullOrEmpty($Base64Value))
        {
            Write-Verbose "Decoding message to bytes ($Base64Value)"
            [byte[]]$ByteArray = [System.Convert]::FromBase64String($Base64Value)
        }

        $messageLength = $ByteArray.Count
        
        # Check the length
        if($messageLength -le 4)
        {
            Throw "Message too short"
        }

        $position = $skip

        $messages=@()

        # There might be more than one message..
        while($position -lt $messageLength)
        {
            # Message attributes
            $attributes = [ordered]@{}

            $ps_object_id=[byte[]]$ByteArray[($position)..($position+7)]
            $ps_fragment_id=[byte[]]$ByteArray[($position+8)..($position+15)]
            $ps_fragment=[int]$ByteArray[($position+16)]
            $ps_blobLength=[int][System.BitConverter]::ToUInt32([byte[]]$ByteArray[($position+20)..($position+17)],0)
            $ps_destination = [int]$ByteArray[($position+21)]
            $ps_messagetype=[int][System.BitConverter]::ToUInt32([byte[]]$ByteArray[($position+25)..($position+28)],0)
            $ps_rpid=[byte[]]$ByteArray[($position+29)..($position+44)]
            $ps_pid=[byte[]]$ByteArray[($position+45)..($position+60)]

            $attributes["Object Id"] = [System.BitConverter]::ToString($ps_object_id)
            $attributes["Fragment Id"] = [System.BitConverter]::ToString($ps_fragment_id)
            $attributes["Fragment"] = $PSRM_message_fragment[$ps_fragment]
            $attributes["Data length"] = $ps_blobLength
            $attributes["Destination"] = $PSRM_message_destination[$ps_destination]
            $attributes["Message type"] = $PSRM_message_types[$ps_messagetype]
            $attributes["RPID"] = ([guid]$ps_rpid).ToString()
            $attributes["PID"] = ([guid]$ps_pid).ToString()
        
            # Header length is 64 bytes so the actual data is after that
            $xmlBytes = $ByteArray[($position+64)..($position+$ps_blobLength+20)]
            $position += $xmlBytes.Count + 64

            # The data is UTF8 text
            [xml]$xml=[System.Text.Encoding]::UTF8.GetString($xmlBytes)
            $attributes["Data"]=$xml.OuterXml
            
            $message = New-Object PSObject -Property $attributes

            Write-Verbose "Found message:"
            Write-Verbose $message

            $messages +=  $message
        }
        

        return $messages
     }
}

# Creates the PowerShell Remoting Protocol Message
function Create-PSRPMessage
{
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [String]$Data,
        [Parameter(Mandatory=$False)]
        [guid]$MSG_RPID = (New-Guid),
        [Parameter(Mandatory=$False)]
        [guid]$MSG_PID = (New-Guid),
        [Parameter(Mandatory=$False)]
        [ValidateSet('Server','Client')]
        [String]$Destination = "Server",
        [Parameter(Mandatory=$False)]
        [ValidateSet("Session_capability","Init_runspacepool","Public_key","Encrypted_session_key","Public_key_request","Set_max_runspaces","Set_min_runspaces","Runspace_availability","Application_private_data","Get_command_metadata","Runspool_state","Create_pipeline","Get_available_runspaces","User_event","Runspacepool_host_call","Runspacepool_host_response","Pipeline_state","Pipeline_input","End_of_pipeline_input","Pipeline_output","Pipeline_host_call","Pipeline_host_response","Error_record","Debug_record","Verbose_record","Warning_record","Progress_record","Informaition_record","Connect_runspacepool","Runspacepool_init_data","Reset_runspace_state")]
        [String]$Type = "Create_pipeline",
        [Parameter(Mandatory=$False)]
        [Int]$ObjectId=3
     
    )
    Process
    {
        Write-Verbose "Creating PowerShell Remote Protocol message: $Destination, $Type"

        $ByteArray = [System.Text.Encoding]::UTF8.getBytes($Data)

        $messageLength = $ByteArray.Count+43 # Add the message header size
                
        # Init the message
        $message=@()
 
        $ps_object_id=[byte[]]@(0,0,0,0,0,0,0,$ObjectId)
        $ps_fragment_id=[byte[]]@(0,0,0,0,0,0,0,0)
        $ps_fragment=[byte]$const_fragment_start_end

        $ps_blobLength=[System.BitConverter]::GetBytes([uint32]$messageLength)
        if($Destination -eq "Server")
        {
            $ps_destination = [byte] $const_destination_server
        }
        else
        {
            $ps_destination = [byte] $const_destination_client
        }
        
        $ps_messagetype=$PSRM_message_types.Keys |? { $PSRM_message_types[$_] -eq $Type.Replace("_"," ") }
        $ps_messagetype=[System.BitConverter]::GetBytes([uint32]$ps_messagetype)
        
        $ps_rpid=[byte[]]$MSG_RPID.ToByteArray()
        $ps_pid=[byte[]]$MSG_PID.ToByteArray()

        # Construct the message
        $message += $ps_object_id        # 01-08
        $message += $ps_fragment_id      # 09-16
        $message += $ps_fragment         #    17
        $message += $ps_blobLength[3..0] # 18-21
        $message += $ps_destination      # 22-25 (continues on the next line)
        $message += @(0x00, 0x00, 0x00)  # 
        $message += $ps_messagetype      # 26-29
        $message += $ps_rpid             # 30-45
        $message += $ps_pid              # 46-61
        $message += $const_bom           # 62-64
 
        $message += $ByteArray  

        $b64Message = [System.Convert]::ToBase64String([byte[]]$message)

        Write-Verbose "Message created: $b64Message"
         
        return $b64Message
     }   
}

# Creates a PSRP Envelope
function Create-PSRPEnvelope
{
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$False)]
        [String]$SessionId=(New-Guid).ToString(),
        [Parameter(Mandatory=$True)]
        [String]$Body,
        [Parameter(Mandatory=$False)]
        [String[]]$Option,
        [Parameter(Mandatory=$True)]
        [ValidateSet('Create','Receive','Delete','Command')]
        [String]$Action,
        [Parameter(Mandatory=$False)]
        [String]$Shell_Id

    )
    Process
    {
        Write-Verbose "Creating PowerShell Remote Protocol envelope: $action, $body"
        switch ( $Action )
        {
            "Command"  { $action_url = 'http://schemas.microsoft.com/wbem/wsman/1/windows/shell/Command'}
            "Create"   { $action_url = 'http://schemas.xmlsoap.org/ws/2004/09/transfer/Create'}
            "Receive"  { $action_url = 'http://schemas.microsoft.com/wbem/wsman/1/windows/shell/Receive'}
            "Delete"   { $action_url = 'http://schemas.xmlsoap.org/ws/2004/09/transfer/Delete'}
        }
        
        $MessageId = (New-Guid).ToString().ToUpper()
        $OperationId = (New-Guid).ToString().ToUpper()

        $SequenceId="1"

        #$To = "https://ps.outlook.com:443/powershell?PSVersion=5.1.17134.590"
        $To = "https://outlook.office365.com:443/PowerShell-LiveID?BasicAuthToOAuthConversion=true&amp;PSVersion=5.1.17763.1490"
        $Envelope=@"
        <s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:a="http://schemas.xmlsoap.org/ws/2004/08/addressing" xmlns:w="http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd" xmlns:p="http://schemas.microsoft.com/wbem/wsman/1/wsman.xsd">
	        <s:Header>
		        <a:To>$To</a:To>
		        <a:ReplyTo>
			        <a:Address s:mustUnderstand="true">http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous</a:Address>
		        </a:ReplyTo>
		        <a:Action s:mustUnderstand="true">$action_url</a:Action>
		        <w:MaxEnvelopeSize s:mustUnderstand="true">512000</w:MaxEnvelopeSize>
		        <a:MessageID>uuid:$MessageId</a:MessageID>
		        <w:Locale xml:lang="en-US" s:mustUnderstand="false" />
		        <p:DataLocale xml:lang="en-US" s:mustUnderstand="false" />
		        <p:SessionId s:mustUnderstand="false">uuid:$SessionId</p:SessionId>
		        <p:OperationID s:mustUnderstand="false">uuid:$OperationId</p:OperationID>
		        <p:SequenceId s:mustUnderstand="false">$SequenceId</p:SequenceId>
                <w:ResourceURI xmlns:w="http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd">http://schemas.microsoft.com/powershell/Microsoft.Exchange</w:ResourceURI>
                $(
                    if(![String]::IsNullOrEmpty($Shell_Id))
                    {
		           @"
                	<w:SelectorSet xmlns:w="http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd" xmlns="http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd">
			            <w:Selector Name="ShellId">$Shell_Id</w:Selector>
		            </w:SelectorSet>
"@
                    }
                )
                $(
                    if(![String]::IsNullOrEmpty($Option))
                    {
		           @"
                <w:OptionSet xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" s:mustUnderstand="true">
			        <w:Option Name="$($Option[0])">$($Option[1])</w:Option>
		        </w:OptionSet>
"@
                    }
                )<w:OperationTimeout>PT180.000S</w:OperationTimeout>
	        </s:Header>
	        <s:Body>
		        $Body
	        </s:Body>
        </s:Envelope>
"@
        # This can be used to compress the data (which we don't want to)
        # <rsp:CompressionType s:mustUnderstand="true" xmlns:rsp="http://schemas.microsoft.com/wbem/wsman/1/windows/shell">xpress</rsp:CompressionType>

        Write-Verbose "ENVELOPE: $Envelope"
        return $Envelope
    }
        
}


# Creates a PSRP Envelope
function Call-PSRP
{
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [String]$Envelope,
        [Parameter(Mandatory=$True)]
        [System.Management.Automation.PSCredential]$Credentials,
        [Parameter(Mandatory=$False)]
        [Bool]$Oauth=$false
    )
    Process
    {
        Write-Verbose "Calling the Remote PowerShell: $Envelope"

        $headers = @{
            "Authorization" = Create-AuthorizationHeader -Credentials $Credentials
            "Content-Type" = "application/soap+xml;charset=UTF-8"
            "User-Agent" = "Microsoft WinRM Client"
        }

        $url="https://outlook.office365.com:443/PowerShell-LiveID?"

        # EXO Remote PS uses basic authentication header to provide the Oauth token..
        if($Oauth)
        {
            $url+="BasicAuthToOauthConversion=true;"
        }
        $url += "PSVersion=5.1.17134.590"


        $response = Invoke-WebRequest -UseBasicParsing -Method Post -Uri $url -Headers $headers -Body $Envelope -TimeoutSec 190 
                
        
        Write-Verbose "RESPONSE: $response.Content"

        return $response.Content
    }
        
}

# Reads the response(s)
function Receive-PSRP
{
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [System.Management.Automation.PSCredential]$Credentials,
        [Parameter()]
        [Bool]$Oauth=$false,
        [Parameter(Mandatory=$True)]
        [String]$SessionId,
        [Parameter(Mandatory=$True)]
        [String]$Shell_Id,
        [Parameter(Mandatory=$False)]
        [String]$CommandId
    )
    Process
    {
        Write-Verbose "Retrieving PowerShell Remote Protocol response" 

        $AuthHeader = Create-AuthorizationHeader -Credentials $Credentials
        
        $CommandIdString =""
        if(![String]::IsNullOrEmpty($CommandId))
        {
            $CommandIdString = " CommandId=`"$CommandId`""
        }
                
        $Body = @"
        <rsp:Receive xmlns:rsp="http://schemas.microsoft.com/wbem/wsman/1/windows/shell" SequenceId="0">
			<rsp:DesiredStream$CommandIdString>stdout</rsp:DesiredStream>
		</rsp:Receive>
"@
        $SessionId = (New-Guid).ToString().ToUpper()
        $Envelope = Create-PSRPEnvelope -SessionId $SessionId -Body $Body -Action Receive -Shell_Id $Shell_Id  -Option @("WSMAN_CMDSHELL_OPTION_KEEPALIVE","TRUE")
        
        $response = Call-PSRP -Envelope $Envelope -Credentials $Credentials -Oauth $Oauth
        
        Write-Verbose "RESPONSE: $response"

        return $response
    }
        
}


# Reads the response(s) and returns an array of objects
function Receive-PSRPObjects
{
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [System.Management.Automation.PSCredential]$Credentials,
        [Parameter()]
        [Bool]$Oauth=$false,
        [Parameter(Mandatory=$True)]
        [String]$Envelope,
        [Parameter(Mandatory=$True)]
        [String]$SessionId,
        [Parameter(Mandatory=$True)]
        [String]$Shell_Id,
        [Parameter(Mandatory=$False)]
        [String]$CommandId
    )
    Process
    {
        $return_array = @()
        try
        {
            # Make the command call
            $response = Call-PSRP -Envelope $Envelope -Credentials $Credentials -Oauth $Oauth
 
            $get_output = $true

            # Get the output
            while($get_output)
            {
                try
                {
                    [xml]$response = Receive-PSRP -Credentials $Credentials -SessionId $SessionId -Shell_Id $Shell_Id -CommandId $commandId -Oauth $Oauth

                    # Loop through streams
                    foreach($message in $response.Envelope.Body.ReceiveResponse.Stream)
                    {
                        $parsed_message = Parse-PSRPMessage -Base64Value $message.'#text'
                        [xml]$xmlData = $parsed_message.Data

                        if($parsed_message.'Message type' -eq "Pipeline output")
                        {
                            # Loop thru the attributes
                            $attributes = [ordered]@{}
                            foreach($node in $xmlData.Obj.Props.ChildNodes)
                            {
                                $name = $node.N
                                $value = $node.InnerText
                                if($name -eq "ObjectClass")
                                {
                                    # Special attribute..
                                    $value=$node.LST.s[1]
                                }
                                $attributes[$name]=$value
                            }
                            $return_array+=(New-Object psobject -Property $attributes)
                        }
                        elseif($parsed_message.'Message type' -eq "Pipeline state")
                        {
                            $errorRecord = (Select-Xml -Xml $xmlData -XPath "//*[@N='ErrorRecord']").Node.'#text'
                            if(![string]::IsNullOrEmpty($errorRecord))
                            {
                                # Something went wrong, probably not an admin user
                                Write-Error "Got an error! May be not an admin user?"
                                Write-Verbose "ERROR: $errorRecord"
                            }
                        }
                        elseif($parsed_message.'Message type' -eq "Warning record")
                        {
                            $warningRecord = (Select-Xml -Xml $xmlData -XPath "//*[@N='InformationalRecord_Message']").Node.'#text'
                            if(![string]::IsNullOrEmpty($warningRecord))
                            {
                                Write-Warning $warningRecord
                            }
                        }
                    }

                    # Loop thru the CommandStates
                    foreach($state in $response.Envelope.Body.ReceiveResponse.CommandState)
                    {
                        # Okay, we're done!
                        $exitCode = $state.ExitCode
                        if(![string]::IsNullOrEmpty($exitCode))
                        {
                            Write-Progress -Activity "Retrieving objects" -Completed
                            $get_output = $false
                        }
                    }
                }
                catch
                {
                    # Something wen't wrong so exit the loop
                    break
                }
            
            }
        }
        catch
        {
            # Do nothing
        }

        return $return_array
    }
        
}


