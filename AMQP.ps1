# This file contains functions for AMQP and relay messaging

# Parses Bus message from the given byte array
function Parse-BusMessage
{
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [byte[]]$Bytes
    )
    Process
    {
        

        # Check the message type
        if($Bytes[0] -eq 0x41 -and $Bytes[1] -eq 0x4D -and $Bytes[2] -eq 0x51 -and $Bytes[3] -eq 0x50)
        {
            # This is version negotiation message
            # Construct the message object
            $message = New-Object PSObject
            switch($Bytes[4])
            {
                0 { $type = "AMQP"}
                1 { $type = "AMQP"}
                2 { $type = "TLS"}
                3 { $type = "SASL"}
            }
            $message | Add-Member -NotePropertyName "Type" -NotePropertyValue "Protocol $type"
            $message | Add-Member -NotePropertyName "Protocol" -NotePropertyValue $Bytes[4]
            $message | Add-Member -NotePropertyName "Major" -NotePropertyValue $Bytes[5]
            $message | Add-Member -NotePropertyName "Minor" -NotePropertyValue $Bytes[6]
            $message | Add-Member -NotePropertyName "Revision" -NotePropertyValue $Bytes[7]
        }
        elseif($Bytes[0] -eq 0x00 -and $Bytes[1] -eq 0x53 -and $Bytes[2] -eq 0x75 -and $Bytes[3] -eq 0xb0)
        {
            # This is a OnewaySend message
            $message = Parse-RelayMessage -Bytes $Bytes
        }
        else
        {
            # This is an AMQP frame
            $message = Parse-AMQPFrame -Bytes $Bytes
        }
        return $message
    }
}

# Parses AMQP Frame error
# Mar 12th 2020
function Parse-AMQPError
{
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$False)]
        [PSObject]$Error
    )
    Process
    {
        $retVal = $Error
        # If the error is not $null, let's try to get the actual error message
        if($Error -ne $null)
        {
            $enum = $Error.getEnumerator()

            if($enum.MoveNext())
            {
                $retVal = $enum.Value[1]
            }
        }
        return $retVal
    }
}


# Parses AMQP Frame from the given byte array
# Mar 10th 2020
function Parse-AMQPFrame
{
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [byte[]]$Bytes
    )
    Process
    {
        # Parse the header
        $Size = ([BitConverter]::ToUInt32($Bytes[3..0],0))
        $DOff = $Bytes[4]
        $ExtendedHeader = $Bytes[8..$($DOff * 4)]

        # Construct the message
        $message = New-Object PSObject
        $message | Add-Member -NotePropertyName "Size" -NotePropertyValue $Size
        $message | Add-Member -NotePropertyName "DOFF" -NotePropertyValue $DOff
        $message | Add-Member -NotePropertyName "Extended Header" -NotePropertyValue $ExtendedHeader

        # Data position
        $pos = $DOff * 4 + 2
        
        if($Bytes[5] -eq 0x00) # Parse AQMP Frame
        {
            $message | Add-Member -NotePropertyName "Type" -NotePropertyValue "AQMP"

            # Channel
            $channel = ([BitConverter]::ToUInt16($Bytes[7..6],0))
            $message | Add-Member -NotePropertyName "Channel" -NotePropertyValue $channel

            switch($Bytes[$pos++])
            {
                0x10 {
                        $message.Type = "AQMP Open"
                        $content = Parse-AMQPItem -Bytes $Bytes -Pos ([ref]$pos)
                        $message | Add-Member -NotePropertyName "ContainerId" -NotePropertyValue $content[0]
                        $message | Add-Member -NotePropertyName "HostName" -NotePropertyValue $content[1]
                        $message | Add-Member -NotePropertyName "MaxFrameSize" -NotePropertyValue $content[2]
                        $message | Add-Member -NotePropertyName "ChannelMax" -NotePropertyValue $content[3]
                        $message | Add-Member -NotePropertyName "IdleTimeOut" -NotePropertyValue $content[4]
                        $message | Add-Member -NotePropertyName "OutgoingLocales" -NotePropertyValue $content[5]
                        $message | Add-Member -NotePropertyName "IncomingLocales" -NotePropertyValue $content[6]
                        $message | Add-Member -NotePropertyName "OfferedCapabilities" -NotePropertyValue $content[7]
                        $message | Add-Member -NotePropertyName "DesiredCapabilities" -NotePropertyValue $content[8]
                        $message | Add-Member -NotePropertyName "Properties" -NotePropertyValue $content[9]

                     }
                0x11 {
                        $message.Type = "AQMP Begin"
                        $content = Parse-AMQPItem -Bytes $Bytes -Pos ([ref]$pos)
                        $message | Add-Member -NotePropertyName "RemoteChannel" -NotePropertyValue $content[0]
                        $message | Add-Member -NotePropertyName "NextOutgoingId" -NotePropertyValue $content[1]
                        $message | Add-Member -NotePropertyName "IncomingWindow" -NotePropertyValue $content[2]
                        $message | Add-Member -NotePropertyName "OutgoingWindow" -NotePropertyValue $content[3]
                        $message | Add-Member -NotePropertyName "HandleMax" -NotePropertyValue $content[4]
                        $message | Add-Member -NotePropertyName "OfferedCapabilities" -NotePropertyValue $content[5]
                        $message | Add-Member -NotePropertyName "DesiredCapabilities" -NotePropertyValue $content[6]
                        $message | Add-Member -NotePropertyName "Properties" -NotePropertyValue $content[7]

                     }
                0x12 {
                        $message.Type = "AQMP Attach"
                        $content = Parse-AMQPItem -Bytes $Bytes -Pos ([ref]$pos)
                        $message | Add-Member -NotePropertyName "Name" -NotePropertyValue $content[0]
                        $message | Add-Member -NotePropertyName "Handle" -NotePropertyValue $content[1]

                        $message | Add-Member -NotePropertyName "Direction" -NotePropertyValue "out"
                        if($content[2] -eq "True"){ $message.Direction = "in"; $targetPos=-1}

                        # Target
                        $enum=$content[(6+$targetPos)].Values.GetEnumerator()
                        if($enum.MoveNext())
                        { 
                            $message | Add-Member -NotePropertyName "Target" -NotePropertyValue ($enum.Value[0])
                        }

                        # Tracking id
                        $enum=$content[13].Values.GetEnumerator()
                        if($enum.MoveNext())
                        { 
                            $message | Add-Member -NotePropertyName "TrackingId" -NotePropertyValue ($enum.Value)
                        }

                     }
                0x13 {
                        $message.Type = "AQMP Flow"
                        $content = Parse-AMQPItem -Bytes $Bytes -Pos ([ref]$pos)
                        $message | Add-Member -NotePropertyName "NextIncomingId" -NotePropertyValue $content[0]
                        $message | Add-Member -NotePropertyName "IncomingWindow" -NotePropertyValue $content[1]
                        $message | Add-Member -NotePropertyName "NextOutgoingId" -NotePropertyValue $content[2]
                        $message | Add-Member -NotePropertyName "OutgoingWindow" -NotePropertyValue $content[3]
                        $message | Add-Member -NotePropertyName "Handle" -NotePropertyValue $content[4]
                        $message | Add-Member -NotePropertyName "DeliveryCount" -NotePropertyValue $content[5]
                        $message | Add-Member -NotePropertyName "LinkCredit" -NotePropertyValue $content[6]
                        $message | Add-Member -NotePropertyName "Available" -NotePropertyValue $content[7]
                        $message | Add-Member -NotePropertyName "Drain" -NotePropertyValue $content[8]
                        $message | Add-Member -NotePropertyName "Echo" -NotePropertyValue $content[9]
                        $message | Add-Member -NotePropertyName "Properties" -NotePropertyValue $content[10]
                     }
                0x14 {
                        $message.Type = "AQMP Transfer"
                        $content = Parse-AMQPItem -Bytes $Bytes -Pos ([ref]$pos)
                        $message | Add-Member -NotePropertyName "Handle" -NotePropertyValue $content[0]
                        $message | Add-Member -NotePropertyName "DeliveryId" -NotePropertyValue $content[1]
                        $message | Add-Member -NotePropertyName "DeliveryTag" -NotePropertyValue $content[2]
                        $message | Add-Member -NotePropertyName "MessageFormat" -NotePropertyValue $content[3]
                        $message | Add-Member -NotePropertyName "Settled" -NotePropertyValue $content[4]
                        $message | Add-Member -NotePropertyName "More" -NotePropertyValue $content[5]
                        $message | Add-Member -NotePropertyName "RcvSettleMode" -NotePropertyValue $content[6]
                        $message | Add-Member -NotePropertyName "State" -NotePropertyValue $content[7]
                        $message | Add-Member -NotePropertyName "Resume" -NotePropertyValue $content[8]
                        $message | Add-Member -NotePropertyName "Aborted" -NotePropertyValue $content[9]
                        $message | Add-Member -NotePropertyName "Batchable" -NotePropertyValue $content[10]
                        
                     }
                0x16 {
                        $message.Type = "AQMP Detach"
                        $content = Parse-AMQPItem -Bytes $Bytes -Pos ([ref]$pos)
                        $message | Add-Member -NotePropertyName "Handle" -NotePropertyValue $content[0]
                        $message | Add-Member -NotePropertyName "Closed" -NotePropertyValue $content[1]
                        $message | Add-Member -NotePropertyName "Error" -NotePropertyValue (Parse-AMQPError -Error $content[2])
 
                     }
                0x17 {
                        $message.Type = "AQMP End"

                        $content = Parse-AMQPItem -Bytes $Bytes -Pos ([ref]$pos)
                        if($content -ne $null)
                        {
                            $message | Add-Member -NotePropertyName "Error" -NotePropertyValue (Parse-AMQPError -Error $content[0])
                        }
                        else
                        {
                            $message | Add-Member -NotePropertyName "Error" -NotePropertyValue $null
                        }
                     }
                0x18 {
                        $message.Type = "AQMP Close"
                        if($content -ne $null)
                        {
                            $message | Add-Member -NotePropertyName "Error" -NotePropertyValue (Parse-AMQPError -Error $content[0])
                        }
                     }
            }

        }
        else # Parse SASL Frame
        {
            switch($Bytes[$pos++])
            {
                0x40 { # sasl-server-mechanisms = list
                        $message | Add-Member -NotePropertyName "Type" -NotePropertyValue "SASL Mechanisms"
                        $content = Parse-AMQPList -Bytes $Bytes -Pos ([ref]$pos)
                        $message | Add-Member -NotePropertyName "Content" -NotePropertyValue $content
                        }
                0x44 { # sasl-outcome = list
                        $message | Add-Member -NotePropertyName "Type" -NotePropertyValue "SASL Outcome"
                        $content = Parse-AMQPList -Bytes $Bytes -Pos ([ref]$pos)

                        # Status
                        $statusCodes = @("ok","auth","sys","sys-perm","sys-temp")
                        $status = $statusCodes[$content[0]]

                        # Message
                        $text = [text.encoding]::ASCII.GetString( [convert]::FromBase64String($content[1]))

                        $message | Add-Member -NotePropertyName "Status" -NotePropertyValue $status
                        $message | Add-Member -NotePropertyName "Message" -NotePropertyValue $text
                    }
            }
            
        }
        
        return $message

    }
}

# Parses an AMQP item from the given byte array
# Mar 10th 2020
function Parse-AMQPItem
{
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [byte[]]$Bytes,
        [Parameter(Mandatory=$True)]
        [ref]$Pos
    )
    Process
    {
        $p=$Pos.Value

        $retVal = $null
        # Check the item type
        switch($Bytes[$p++])
        {   
            # descriptor constructor
            0x00 {  
                    $descriptor = Parse-AMQPItem -Bytes $Bytes -Pos([ref]$p)
                    $value = Parse-AMQPItem -Bytes $Bytes -Pos([ref]$p)

                    $retVal = @{ $descriptor = $value }
            }
            # null
            0x40 { 
                    $pos.Value = $p
                    return $null
                 } 
            # true
            0x41 {  $retVal = $True } 
            # false
            0x42 {  $retVal = $False }
            # uint 0
            0x43 {  $retVal = 0 }
            # ulong 0
            0x44 {  $retVal = 0 }
            # empty list
            0x45 {  $retVal = @() }  
            # boolean
            0x56 {  
                    $boolean = $Bytes[$p++]
                    $retVal = $boolean -eq 0x01 # 0x01 = true
                 }
            # ubyte
            0x50 { 
                    $retVal = [byte]$Bytes[$p++]
                 }
            # byte
            0x51 { 
                    $retVal = [byte]$Bytes[$p++]
                 }
            # smalluint
            0x52 { 
                    $retVal = [byte]$Bytes[$p++]
                 }
            # smallulong
            0x53 { 
                    $retVal = [byte]$Bytes[$p++]
                 }
            # smallint
            0x54 { 
                    $retVal = [int]$Bytes[$p++]
                 }
            # smalllong
            0x55 { 
                    $retVal = [long]$Bytes[$p++]
                 }
            # ushort
            0x60 { 
                    $retVal = [BitConverter]::ToUInt16($Bytes[$($p+1)..$($p)],0)
                    $p+=2
                 }
            # short
            0x61 { 
                    $retVal = [BitConverter]::ToInt16($Bytes[$($p+1)..$($p)],0)
                    $p+=2
                 }
            # uint
            0x70 { 
                    $retVal = [BitConverter]::ToUInt32($Bytes[$($p+3)..$($p)],0)
                    $p+=4
                 }
            # int
            0x71 { 
                    $retVal = [BitConverter]::ToUInt32($Bytes[$($p+3)..$($p)],0)
                    $p+=4
                 }
            # float
            0x72 { 
                    $retVal = [float][BitConverter]::ToInt32($Bytes[$($p+3)..$($p)],0)
                    $p+=4
                 }
            # char
            0x73 { 
                    $retVal = [text.encoding]::UTF32.GetChars($Bytes[$($p+3)..$($p)])
                    $p+=4
                 }
            # decimal32
            0x74 { 
                    # Do nothing
                    $p+=4
                 }
            # ulong
            0x80 { 
                    $retVal = [BitConverter]::ToUInt64($Bytes[$($p+7)..$($p)],0)
                    $p+=8
                 }
            # long
            0x81 { 
                    $retVal = [BitConverter]::ToInt64($Bytes[$($p+7)..$($p)],0)
                    $p+=8
                 }
            # double
            0x82 { 
                    $retVal = [BitConverter]::ToDouble($Bytes[$($p+7)..$($p)],0)
                    $p+=8
                 }
            # timestamp
            0x82 { 
                    $timeStamp = [BitConverter]::ToUint($Bytes[$($p+7)..$($p)],0)
                    $retVal = $epoch.AddSeconds($timeStamp)
                    $p+=8
                 }
            # decimal64
            0x84 { 
                    # Do nothing
                    $p+=8
                 }
            # decimal128
            0x94 { 
                    # Do nothing
                    $p+=16
                 }
            # UUID
            0x98 { 
                    $retVal = [guid][BitConverter]::ToUint($Bytes[$($p+15)..$($p)],0)
                    $p+=16
                 }
            # Binary
            0xa0 { 
                    $size = $Bytes[$p++]
                    $retVal = [convert]::ToBase64String($Bytes[$p..$($p+$size)])
                    $p += $size
                 }
            # String
            0xa1 { 
                    $size = $Bytes[$p++]
                    $retVal = [text.encoding]::UTF8.GetString($Bytes[$p..$($p+$size-1)])
                    $p += $size
                 }
            # symbol
            0xa3 { 
                    $size = $Bytes[$p++]
                    $retVal = [text.encoding]::ASCII.GetString($Bytes[$p..$($p+$size-1)])
                    $p += $size
                 }
            # Binary
            0xb0 { 
                    $size = [BitConverter]::ToUInt32($Bytes[$($p+3)..$($p)],0)
                    $p+=4
                    $retVal = [convert]::ToBase64String($Bytes[$p..$($p+$size)])
                    $p += $size
                 }
            
            # String
            0xb1 { 
                    $size = [BitConverter]::ToUInt32($Bytes[$($p+3)..$($p)],0)
                    $p+=4
                    $retVal = [text.encoding]::UTF8.GetString($Bytes[$p..$($p+$size)])
                    $p += $size
                 }
            # Symbol
            0xb3 { 
                    $size = [BitConverter]::ToUInt32($Bytes[$($p+3)..$($p)],0)
                    $p+=4
                    $retVal = [text.encoding]::ASCII.GetString($Bytes[$p..$($p+$size)])
                    $p += $size
                 }
            # List
            0xC0 {  
                    #$p--
                    $retVal = Parse-AMQPList -Bytes $Bytes -Pos ([ref]$p) }
            # List
            0xD0 {  
                    #$p--
                    $retVal = Parse-AMQPList -Bytes $Bytes -Pos ([ref]$p) }
            # Map
            0xC1 {  
                    #$p--
                    $retVal = Parse-AMQPMap -Bytes $Bytes -Pos ([ref]$p) }
            # Map
            0xD1 {  
                    #$p--
                    $retVal = Parse-AMQPMap -Bytes $Bytes -Pos ([ref]$p) }
            # Array
            0xE0 {  
                    $retVal = Parse-AMQPArray -Bytes $Bytes -Pos ([ref]$p) }
            # Array
            0xF0 {  
                    $retVal = Parse-AMQPArray -Bytes $Bytes -Pos ([ref]$p) }
        }
        $Pos.Value = $p

        #if($retVal -ne $null)
        #{
            return $retVal
        #}

    }
}

# Parses a AMQP list from the given byte array
# Mar 10th 2020
function Parse-AMQPList
{
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [byte[]]$Bytes,
        [Parameter(Mandatory=$True)]
        [ref]$Pos
    )
    Process
    {
        $p=$Pos.Value
        $p--
        # Check the list type
        switch($Bytes[$p++])
        {
            0x45 { # The empty list
                    $size = 0
                 }
            0xC0 {  
                    $size = $Bytes[$p++] 
                    $intSize = 1
                 }
            0xD0 { 
                    $size = [BitConverter]::ToUInt16($bytes[$($p+3)..$($p)],0)
                    $p += 4
                    $intSize = 4
                 }
        }
        
        $max = $p + $size

        # Next int indicates the number of the items so increase position by the size of the int
        $p += $intSize
        
        $retVal = @()

        # Loop through the items

        while($p -lt $max)
        {
            $retVal += Parse-AMQPItem -Bytes $Bytes -Pos ([ref]$p)
        }
        $Pos.Value=$p
        return $retVal
    }
}

# Parses a AMQP list from the given byte array
# Mar 10th 2020
function Parse-AMQPArray
{
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [byte[]]$Bytes,
        [Parameter(Mandatory=$True)]
        [ref]$Pos
    )
    Process
    {
        $p=$Pos.Value
        $retVal = @()

        # Size
        $size = $Bytes[$p++]
        # Number of elements
        $elements = $Bytes[$p++]
        # Type
        $type = $Bytes[$p++]

        for($a = 0 ; $a -lt $elements ; $a++)
        {
            # Array elements does not have type (except for the first one)
            $p--
            $Bytes[$p]=$type
            $retVal += Parse-AMQPItem -Bytes $Bytes -Pos ([ref]$p)
        }
        $Pos.Value = $p
        return $retVal
    }
}

# Parses a AMQP list from the given byte array
# Mar 12th 2020
function Parse-AMQPMap
{
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [byte[]]$Bytes,
        [Parameter(Mandatory=$True)]
        [ref]$Pos
    )
    Process
    {
        $p=$Pos.Value
        $p--
        # Check the list type
        switch($Bytes[$p++])
        {
            0xC1 {  
                    $size = $Bytes[$p++] 
                    $intSize = 1
                 }
            0xD1 { 
                    $size = [BitConverter]::ToUInt16($bytes[$($p+3)..$($p)],0)
                    $p += 4
                    $intSize = 4
                 }
        }
        
        $max = $p + $size

        # Next int indicates the number of the items so increase position by the size of the int
        $p += $intSize
        
        $retVal = @()

        # Loop through the items

        while($p -lt $max)
        {
            $key = Parse-AMQPItem -Bytes $Bytes -Pos ([ref]$p)
            $value = Parse-AMQPItem -Bytes $Bytes -Pos ([ref]$p)

            $retVal = @{ $key = $value }
        }
        $Pos.Value=$p
        return $retVal
    }
}

# Returns a SASL Init message
# Mar 10th 2020
function New-SASLInit
{
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$False)]
        [ValidateSet('EXTERNAL','MSSBCBS','PLAIN','ANONYMOUS')]
        [String]$Mechanics="EXTERNAL"
    )
    Process
    {
        # Get the ascii bytes of the selected mechanics
        $mechBytes = [text.encoding]::ASCII.getBytes($Mechanics)
        
        $array =  @(
                    0xC0,                    # Array 
                    [byte]($mechBytes.length + 5), # Length of the Array
                    0x03,                    # Number of elements
                    0xA3,                    # Symbol
                    [byte]$mechBytes.length) # Length of the mechanics string
        $array +=   $mechBytes               # The mechanics string
        $array += @(
                    0x40,                    # The initial response ($null)
                    0x40)                    # The hostname ($null)

        # Construct the message
        $message = @(
                    # The length of the whole message
                    [BitConverter]::GetBytes([Uint32]($mechBytes.length+18))[3..0])
        $message += @(
                    0x02,   # DOFF = 2
                    0x01,   # Message type = SASL
                    0x00,   #
                    0x00,   #
                    0x00,   #
                    0x53,   # SmallULong
                    0x41)   # SASL Init
        $message += $array # The array
                    
        return $message
    }
}

# Returns an AMQP Open message
# Mar 10th 2020
function New-AMQPOpen
{
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [String]$ContainerId,
        [Parameter(Mandatory=$True)]
        [String]$HostName
    )
    Process
    {
        # Get the ascii bytes of the strings
        $idByt = [text.encoding]::ASCII.getBytes($ContainerId)
        $idS=$idByt.Length
        $hostByt = [text.encoding]::ASCII.getBytes($HostName)
        $hostS=$hostByt.Length
        
        $array =  @(
                    0xC0,                    # Array 
                    [byte]($ids+$hostS + 19), # Length of the Array
                    0x0A,                    # Number of elements
                    0xA1,                    # UTF-8
                    [byte]$ids)              # Length of the ContainerId string
        $array +=   $idByt                   # The ContainerId string
        $array +=  @(
                    0xA1,                    # UTF-8
                    [byte]$hostS)            # Length of the ContainerId string
        $array +=   $hostByt                 # The ContainerId string
        $array += @(
                    0x70,                    # UINT 32 bit
                    0x00,0x01,0x00, 0x00,    # Max Frame Size = 65536
                    0x60,                    # UShort 16 bit
                    0x1F, 0xFF,              # Channel Max = 8191
                    0x40,                    # Idle timeout in millis. ($null)
                    0x40,                    # Outgoing locales ($null)
                    0x40,                    # Incoming locales ($null)
                    0x40,                    # Offered capabilities ($null)
                    0x40,                    # Desired capabilities ($null)
                    0x40)                    # Properties ($null)
        
        # Construct the message
        $message = @(
                    # The length of the whole message
                    [BitConverter]::GetBytes([Uint32]($array[1]+13))[3..0])
        $message += @(
                    0x02,   # DOFF = 2
                    0x00,   # Message type = AMQP
                    0x00,   #
                    0x00,   #
                    0x00,   #
                    0x53,   # SmallULong
                    0x10)   # AMQP Open
        $message += $array # The array
                    
        return $message
    }
}

# Returns an AMQP Open message
# Mar 10th 2020
function New-AMQPBegin
{
    [cmdletbinding()]
    Param()
    Process
    {
        
        # Construct the message
        $message = [byte[]]@(
                    0x00, 0x00, 0x00, 0x23, # Length of the message
                    0x02,   # DOFF = 2
                    0x00,   # Message type = AMQP
                    0x00,   #
                    0x00,   #
                    0x00,   #
                    0x53,   # SmallULong
                    0x11,   # AMQP Begin

                    0xC0,   # Array
                    0x16,   # Array length
                    0x08,   # Array items
                    0x40,   # Remote Channel ($null)
                    0x52,   # Small Uint
                    0x01,   # Next outgoing Id
                    0x70,   # UInt 32
                    0x00, 0x00, 0x13, 0x88,   # Incoming Window = 5000
                    0x70,   # UInt 32
                    0x00, 0x00, 0x13, 0x88,   # Outgoing Window = 5000
                    0x70,   # UInt 32
                    0x00, 0x03, 0xFF, 0xFF,   # Handle max = 262143
                    0x40,   # Offered capabilities ($null)
                    0x40,   # Desired capabilities ($null)
                    0x40)   # Properties ($null)
                    
        
                    
        return $message
    }
}

# Returns an AMQP Attach message
# Mar 11th 2020
function New-AMQPAttach
{
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [byte]$Handle,
        [Parameter(Mandatory=$True)]
        [PSObject]$BootStrap,
        [Parameter(Mandatory=$True)]
        [String]$RelayLinkGuid,
        [Parameter(Mandatory=$True)]        [ValidateSet('in','out')]
        [String]$Direction,
        [Parameter(Mandatory=$True)]        [String]$TrackingID
    )
    Process
    {
        # Define variables
        $name = "RelayLink_$($RelayLinkGuid):$($Direction)"
        $url = "://$($BootStrap.Namespace).servicebus.windows.net/$($BootStrap.ServicePath)/"
        $target = "sb$url"

        # Calculate SAS Token
        $sasUrl = "http$url"
        $SASToken = Get-SASToken -Url $sasUrl -Key $BootStrap.SharedAccessKey -KeyName $BootStrap.SharedAccessKeyName

        # Get the bytes of the strings 
        $bName=              [text.encoding]::UTF8.GetBytes($name)
        $bTarget=            [text.encoding]::UTF8.GetBytes($target)
        $bSwt=               [text.encoding]::ASCII.GetBytes("com.microsoft:swt")
        $bSAS=               [text.encoding]::UTF8.GetBytes($SASToken)
        $bClientAgent=       [text.encoding]::ASCII.GetBytes("com.microsoft:client-agent")
        $bClientAgentString= [text.encoding]::UTF8.GetBytes("ServiceBus/3.0.51093.14;")
        $bDynamicRelay=      [text.encoding]::ASCII.GetBytes("com.microsoft:dynamic-relay")
        $bListenerType=      [text.encoding]::ASCII.GetBytes("com.microsoft:listener-type")
        $bRelayedConnection= [text.encoding]::UTF8.GetBytes("RelayedConnection")
        $bTrackingId=        [text.encoding]::ASCII.GetBytes("com.microsoft:tracking-id")
        $bTrackingIdString = [text.encoding]::UTF8.GetBytes($TrackingId.ToString())
        
        # Calculate the combined length
        $strLen =   $bName.length + $bTarget.length + $bSwt.length + $bSAS.length + $bClientAgent.length + `
                    $bClientAgentString.length + $bDynamicRelay.length +  $bListenerType.length + `
                    $bRelayedConnection.length + $bTrackingId.length + $bTrackingIdString.length

        # Set the handle
        if($Handle -gt 0)
        {
            $bHandle=(0x52,  # smallUint
                    $Handle) # handle value
        }
        else
        {
            $bHandle+=@(0x43)    # Handle = 0, UInt 8 
        }
        # Set the role
        if($Direction -eq "in")
        {
            $bRole=0x41
        }
        else
        {
            $bRole=0x42
        }

        # Construct the message
        $message = [byte[]]@(([BitConverter]::GetBytes([uint32]($strLen + 91 +($bHandle.Length - 1))))[3..0]) # Length of the frame
        $message+=@(0x02,   # DOFF = 2
                    0x00,   # Message type = AMQP
                    0x00,   #
                    0x00,   #
                    0x00,   #
                    0x53,   # SmallULong
                    0x12,   # AMQP Attach

                    0xD0)    # List
        $message+=@(([BitConverter]::GetBytes([uint32]($strLen + 75 +($bHandle.Length - 1))))[3..0]
                    0x00, 0x00, 0x00, 0x0E, # Number of elements 
                    0xA1,   # String
                    $bName.length)   # String length
        $message+=@($bName) # Name
        $message+=@($bHandle) # Handle
        $message+=@($bRole,   # Role (False) = Sender
                    0x40,   # snd-settle-mode ($null)
                    0x40,   # rcv-settle-mode ($null)

                    0x00,   # Source (0x00)
                    0x53,   # SmallULong
                    0x28)   #  (0x28 = 40)
        if($Direction -eq "in")
        {
            $message+=@(0xC0,   # List
                        ($bTarget.length + 13),   # Array Length 
                        0x0B,   # ?
                        0xA1,    # String 
                        $bTarget.length) # Length
            $message+=@($bTarget) # Target
            $message+=@(0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40) # ? (belongs to the array)
            
            $message+=@(0x00,   # ?
                        0x53,   # SmallULong
                        0x29,   #  (0x29 = 41)
                        0xC0,   # List
                        0x08,   # List Length 
                        0x07,   # List items
                        0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40)   # ?
        }
        else
        {
            $message+=@(0xC0,   # List
                        0x0C,   # List Length (0x0c = 12)
                        0x0b,   # List elements
                        0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40,

                        0x00,   # 
                        0x53,   # SmallULong
                        0x29,   #  (0x29 = 41)

                        0xC0,   # Array
                        ($bTarget.length + 9),   # Array Length 
                        0x07,    # ?
                        0xA1,    # String 
                        $bTarget.length) # Length
            $message+=@($bTarget) # Target
            $message+=@(0x40, 0x40, 0x40, 0x40, 0x40, 0x40) # ? (belongs to the array)
        }
        $message+=@(0x40, 0x40, 0x40, 0x40, 0x40, 0x40, # ?
                    0xD1)   # Map (unsettled)
                            # Length of the map:
        $message+=@(([BitConverter]::GetBytes([uint32]($strLen - $bName.length - $bTarget.length + 23)))[3..0])
        $message+=@(0x00, 0x00, 0x00, 0x0A # ?
                    0xA3,   # Symbol
                    $bSwt.length) # Length
        $message+=@($bSwt)  # com.microsoft:swt
        $message+=@(0xA1,   # String
                    $bSAS.length) # Length
        $message+=@($bSAS)  # SASToken

        $message+=@(0xA3,   # Symbol
                    $bClientAgent.length) # Length
        $message+=@($bClientAgent)  # com.microsoft:client-agent
        $message+=@(0xA1,   # String
                    $bClientAgentString.length) # Length
        $message+=@($bClientAgentString)  # ServiceBus/3.0.51093.14

        $message+=@(0xA3,   # Symbol
                    $bDynamicRelay.length) # Length
        $message+=@($bDynamicRelay)  # com.microsoft:dynamic-relay
        $message+=@(0x42)   # False

        $message+=@(0xA3,   # Symbol
                    $bListenerType.length) # Length
        $message+=@($bListenerType)  # com.microsoft:client-agent
        $message+=@(0xA1,   # String
                    $bRelayedConnection.length) # Length
        $message+=@($bRelayedConnection)  # RelayedConnection

        $message+=@(0xA3,   # Symbol
                    $bTrackingId.length) # Length
        $message+=@($bTrackingId)  # com.microsoft:tracking-id
        $message+=@(0xA1,   # String
                    $bTrackingIdString.length) # Length
        $message+=@($bTrackingIdString)  # GUID
        
                    
        return [byte[]]$message
    }
}

# Returns an AMQP Open message
# Mar 11th 2020
function New-AMQPFlow
{
    [cmdletbinding()]
    Param()
    Process
    {
        
        # Construct the message
        $message = [byte[]]@(
                    0x00, 0x00, 0x00, 0x28, # Length of the message
                    0x02,   # DOFF = 2
                    0x00,   # Message type = AMQP
                    0x00,   #
                    0x00,   #
                    0x00,   #
                    0x53,   # SmallULong
                    0x13,   # AMQP Flow

                    0xC0,   # Array
                    0x1B,   # Array length
                    0x0B,   # Array items
                    0x52,   # Small Uint
                    0x01,   # Next incoming Id
                    0x70,   # UInt 32
                    0x00, 0x00, 0x13, 0x88,   # Incoming Window = 5000
                    0x52,   # Small Uint
                    0x01,   # Next outgoing Id
                    0x70,   # UInt 32
                    0x00, 0x00, 0x13, 0x88,   # Outgoing Window = 5000
                    0x52,   # Small Uint
                    0x01,   # Handle (=1)
                    0x43,   # UInt Delivery count = 0
                    0x70,   # UInt 32
                    0x00, 0x00, 0x03, 0xE8,   # Link credit = 1000
                    0x43,   # UInt Available count = 0
                    0x40,   # Drain ($null)
                    0x42,   # Echo ($false)
                    0x40)   # Properties ($null)
                    
        
                    
        return $message
    }
}

# Returns an AMQP Detach message
# Mar 11th 2020
function New-AMQPDetach
{
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [byte]$Handle
        
    )
    Process
    {
        # Set the handle
        if($Handle -gt 0)
        {
            $bHandle=(0x52,  # smallUint
                    $Handle) # handle value
        }
        else
        {
            $bHandle+=@(0x43)    # Handle = 0, UInt 8 
        }
        
        # Construct the message
        $message= @(0x00, 0x00, 0x00, (17+($bHandle.Length - 1)), # Length of the frame (will be set later)
                    0x02,   # DOFF = 2
                    0x00,   # Message type = AMQP
                    0x00,   #
                    0x00,   #
                    0x00,   #
                    0x53,   # SmallULong
                    0x16,   # AMQP Detach

                    0xC0,   # List
                    (0x04+($bHandle.Length - 1)),# Size
                    0x03)   # Elements
        $message+=@($bHandle)
        $message+=@(0x41,   # Closed ($true)
                    0x40)   # Error ($null)
        
                    
        return [byte[]]$message
    }
}

# Returns an AMQP End message
# Mar 11th 2020
function New-AMQPEnd
{
    [cmdletbinding()]
    Param()
    Process
    {
       
        # Construct the message
        $message= @(0x00, 0x00, 0x00, 0x0F, # Length of the frame (will be set later)
                    0x02,   # DOFF = 2
                    0x00,   # Message type = AMQP
                    0x00,   #
                    0x00,   #
                    0x00,   #
                    0x53,   # SmallULong
                    0x17,   # AMQP End

                    0xC0,   # List
                    0x02,   # Size
                    0x01,   # Elements
                    0x40)   # Error ($null)
                    
        return [byte[]]$message
    }
}

# Returns an AMQP Close message
# Mar 11th 2020
function New-AMQPClose
{
    [cmdletbinding()]
    Param()
    Process
    {
       
        # Construct the message
        $message= @(0x00, 0x00, 0x00, 0x0F, # Length of the frame
                    0x02,   # DOFF = 2
                    0x00,   # Message type = AMQP
                    0x00,   #
                    0x00,   #
                    0x00,   #
                    0x53,   # SmallULong
                    0x18,   # AMQP Close

                    0xC0,   # List
                    0x02,   # Size
                    0x01,   # Elements
                    0x40)   # Error ($null)
                    
        return [byte[]]$message
    }
}

# Returns an AMQP Disposition message
# Mar 11th 2020
function New-AMQPDisposition
{
    [cmdletbinding()]
    Param()
    Process
    {
       
        # Construct the message
        $message= @(0x00, 0x00, 0x00, 0x17, # Length of the frame
                    0x02,   # DOFF = 2
                    0x00,   # Message type = AMQP
                    0x00,   #
                    0x00,   #
                    0x00,   #
                    0x53,   # SmallULong
                    0x15,   # AMQP Disposition

                    0xC0,   # List
                    0x0A,   # Size
                    0x06,   # Elements
                    0x41,   # Role ($true = Receiver)
                    0x43,   # First (0)
                    0x40,   # Last ($null),
                    0x41,   # Settled ($true),
                    0x00, 0x53, 0x24, # State (0x24)
                    0x45,   # State value (empty list)
                    0x40)   # Batchable ($null)
                    
        return [byte[]]$message
    }
}

# "Parses" the relay messages
# Mar 16th 2020
function Parse-RelayMessage
{
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [byte[]]$Bytes
        #[Parameter(Mandatory=$True)]
        #[ref]$Pos
    )
    Process
    {
        $p=0
        $content = @()

        # First parse the strings and guids
        while($p -lt $Bytes.Length)
        {
            $curByte=$Bytes[$p++]

            # Something
            #if($curByte -eq 0x56)
            #{
            #    $length=$Bytes[$p]
            #    $p+=$length
            #}
            # Strings
            if(($curByte -eq 0x99 -and $bytes[$p] -lt 0xC8) -or $curByte -eq 0x3F -or ($curByte -eq 0x40 -and $bytes[$p] -lt 0x80) -or ($curByte -eq 0x02 -and $bytes[$p] -eq 0x02))# -or ($curByte -eq 0x42 -and ($bytes[$p]+$p -lt $bytes.Length -and $bytes[$p] -gt 20)))
            {
                # If 0x02, move to next one
                if($Bytes[$($p-1)] -eq 0x02 -and $curByte -eq 0x02){$p++}

                # Get the string length and bytes
                $strLen = $Bytes[$p++]
                $stringBytes = $Bytes[$p..$($p+$strLen-1)]

                # Convert to string
                $str=[text.encoding]::UTF8.GetString($stringBytes)
                $content+=$str

                $p+=$strLen

                # OnewaySend message hack: Get the relay ip address
                if($str -eq "HttpsAddress")
                {
                    $ip="$($Bytes[$p+1]).$($Bytes[$p+2]).$($Bytes[$p+3]).$($Bytes[$p+4])"
                    $content += $ip
                }
            }
            # Guid
            elseif($curByte -eq 0xAD)
            {
                [byte[]]$bGuid = $Bytes[$p..$($p+15)]
                $content += ([guid]$bGuid).ToString()
                $p+=16
            }
        }
       

        # Construct the message
        $message = New-Object PSObject
        $message | Add-Member -NotePropertyName "Size" -NotePropertyValue $Bytes.Length
        $message | Add-Member -NotePropertyName "Type" -NotePropertyValue "Relay"

        if($content.Count -gt 16 -and $content[0] -eq "OnewaySend")
        {
            # This is a OnewaySend message
            $message.Type="OnewaySend"

            $message | Add-Member -NotePropertyName "RelayName" -NotePropertyValue $content[2]
            $message | Add-Member -NotePropertyName "Container" -NotePropertyValue $content[3]
            $message | Add-Member -NotePropertyName "RelayId" -NotePropertyValue $content[8]
            $message | Add-Member -NotePropertyName "RelayIp" -NotePropertyValue $content[14]
            $message | Add-Member -NotePropertyName "RelayAddress" -NotePropertyValue $content[17]
            if($message.RelayAddress -eq $null)
            {
                $message.RelayAddress = $content[16]
            }
        }
        elseif($Bytes.Length -eq 4 -and $Bytes[0] -eq 0x98)
        {
            $message.type="Relay ConnectReply"
        }
        elseif($content.Count -eq 1)
        {
            if($content[0] -eq "RelayedAcceptReply")
            {
                $message.type="Relay AcceptReply"
            }
            elseif($content[0].StartsWith("sb://"))
            {
                $message.type="Relay Name"
                $message | Add-Member -NotePropertyName "Relay" -NotePropertyValue $content[0]
            }
        }
        elseif($content.Count -eq 2)
        {
            if($content[0] -eq "Ping")
            {
                $message.type="Relay Ping"
            }
            else
            {
                $message.type="Relay NetRemoteReply"
                $message | Add-Member -NotePropertyName "Id" -NotePropertyValue $content[0]
            }
        }
        elseif($content.Count -eq 3)
        {
            $message.type="Relay Ids"
            $message | Add-Member -NotePropertyName "SequenceId" -NotePropertyValue $content[2]
            $message | Add-Member -NotePropertyName "Relay" -NotePropertyValue $content[1]
            $message | Add-Member -NotePropertyName "SomeId" -NotePropertyValue $content[0]
        }
        elseif($content.Count -gt 10)
        {
            $message.type="Relay ProxyConnect"
            $message | Add-Member -NotePropertyName "ProxyUrl" -NotePropertyValue $content[8]
            $message | Add-Member -NotePropertyName "ProxyId" -NotePropertyValue $content[10]
            $message | Add-Member -NotePropertyName "SomeId2" -NotePropertyValue $content[1]
            $message | Add-Member -NotePropertyName "ConId" -NotePropertyValue $content[0]
            $message | Add-Member -NotePropertyName "ConnectionId" -NotePropertyValue $content[12]
        }

        return $message
    }
}

# Returns a Relay Connect message
# Mar 17th 2020
function New-RelayConnect
{
    [cmdletbinding()]
    Param()
    Process
    {
       
        # Construct the message
        $message= @(0x1E, 0x01, 0x00, 0x00)
                    
        return [byte[]]$message
    }
}

# Returns a Relay Accept message
# Mar 17th 2020
function New-RelayAccept
{
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [String]$Id
        
    )
    Process
    {
       
        # Construct the message
        $message = @(0x56, 0x02, 0x0B, 0x01, 0x73, 0x04, 0x0B, 0x01, 0x61, 0x06, 0x56, 0x08, 0x44, 0x0A, 0x1E, 0x00, 0x82, 0x99, 0x0D, 0x52, 0x65, 0x6C, 0x61, 0x79, 0x65, 0x64, 0x41, 0x63, 0x63, 0x65, 0x70, 0x74, 0x44, 0x0C, 0x1E, 0x00, 0x82, 0x99, 0x46, 0x68, 0x74, 0x74, 0x70, 0x3A, 0x2F, 0x2F, 0x73, 0x63, 0x68, 0x65, 0x6D, 0x61, 0x73, 0x2E, 0x6D, 0x69, 0x63, 0x72, 0x6F, 0x73, 0x6F, 0x66, 0x74, 0x2E, 0x63, 0x6F, 0x6D, 0x2F, 0x32, 0x30, 0x30, 0x35, 0x2F, 0x31, 0x32, 0x2F, 0x53, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x4D, 0x6F, 0x64, 0x65, 0x6C, 0x2F, 0x41, 0x64, 0x64, 0x72, 0x65, 0x73, 0x73, 0x69, 0x6E, 0x67, 0x2F, 0x41, 0x6E, 0x6F, 0x6E, 0x79, 0x6D, 0x6F, 0x75, 0x73, 0x01, 0x56, 0x0E, 0x40, 0x0D, 0x52, 0x65, 0x6C, 0x61, 0x79, 0x65, 0x64, 0x41, 0x63, 0x63, 0x65, 0x70, 0x74, 0x08, 0x43, 0x68, 0x74, 0x74, 0x70, 0x3A, 0x2F, 0x2F, 0x73, 0x63, 0x68, 0x65, 0x6D, 0x61, 0x73, 0x2E, 0x6D, 0x69, 0x63, 0x72, 0x6F, 0x73, 0x6F, 0x66, 0x74, 0x2E, 0x63, 0x6F, 0x6D, 0x2F, 0x6E, 0x65, 0x74, 0x73, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x73, 0x2F, 0x32, 0x30, 0x30, 0x39, 0x2F, 0x30, 0x35, 0x2F, 0x73, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x62, 0x75, 0x73, 0x2F, 0x63, 0x6F, 0x6E, 0x6E, 0x65, 0x63, 0x74, 0x09, 0x01, 0x69, 0x29, 0x68, 0x74, 0x74, 0x70, 0x3A, 0x2F, 0x2F, 0x77, 0x77, 0x77, 0x2E, 0x77, 0x33, 0x2E, 0x6F, 0x72, 0x67, 0x2F, 0x32, 0x30, 0x30, 0x31, 0x2F, 0x58, 0x4D, 0x4C, 0x53, 0x63, 0x68, 0x65, 0x6D, 0x61, 0x2D, 0x69, 0x6E, 0x73, 0x74, 0x61, 0x6E, 0x63, 0x65, 0x40, 0x02, 0x49, 0x64, 0x99, 0x24)
        $message += [text.encoding]::UTF8.getBytes($id)
        $message += @(0x01, 0x01, 0x01)
                    
        return [byte[]]$message
    }
}

# Returns a Relay Ids Reply message
# Mar 17th 2020
function New-RelayNameReply
{
    [cmdletbinding()]
    Param()
    Process
    {
       
        # Construct the message
        $message = @(0x0B)
                  
        return [byte[]]$message
    }
}

# Returns an Relay Name reply message
# Mar 17th 2020
function New-RelayIdsReply
{
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [guid]$SomeId,
        [Parameter(Mandatory=$True)]
        [guid]$ConnectionId,
        [Parameter(Mandatory=$True)]
        [String]$Relay
        
    )
    Process
    {
        
        $bRelay = [text.encoding]::UTF8.GetBytes($Relay)

        # Construct the message
        $message = @(0x06,($bRelay.length + 89))
        $message+=@(0x01, 0x00, 0x56, 0x02, 0x0B, 0x01, 0x73, 0x04, 0x0B, 0x01, 0x61, 0x06, 0x56, 0x08, 0x44, 0x0A, 0x1E, 0x00, 0x82, 0xAB, 0xA0, 0x05, 0x44, 0x12, 0xAD)
        $message+=$someId.ToByteArray()
        $message+=@(0x44, 0x0C, 0x1E, 0x00, 0x82, 0xAB, 0x14, 0x01, 0x56, 0x0E, 0x42, 0x9E, 0x05, 0x0A, 0x20, 0x42, 0x1E, 0xAD)
        $message+=$ConnectionId.ToByteArray()
        $message+=@(0x42, 0x96, 0x05, 0x42, 0x94, 0x05, 0x44, 0x2A, 0x99)
        $message+=$bRelay.length
        $message+=$bRelay
        $message+=@(0x01, 0x01, 0x01, 0x01, 0x01)
       
                   
        return [byte[]]$message
    }
}

# Returns an Relay Net Remote message
# Mar 17th 2020
function New-RelayNetRemote
{
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [guid]$ConnectionId 
    )
    Process
    {
        # Construct the message
        $message = @(0x06, 0x55, 0x00, 0x56, 0x02, 0x0B, 0x01, 0x73, 0x04, 0x0B, 0x01, 0x72, 0x20, 0x0B, 0x01, 0x61, 0x06, 0x56, 0x08, 0x55, 0x2E, 0x55, 0x1E, 0xAD)
        $message += $ConnectionId.ToByteArray()
        $message += @(0x55, 0x30, 0x06, 0x34, 0x82, 0x06, 0x32, 0x82, 0x01, 0x43, 0x05, 0x6E, 0x65, 0x74, 0x72, 0x6D, 0x36, 0x0B, 0x05, 0x6E, 0x65, 0x74, 0x72, 0x6D, 0x38, 0x89, 0x08, 0x01, 0x44, 0x0A, 0x1E, 0x00, 0x82, 0xAB, 0x3A, 0x44, 0x0C, 0x1E, 0x00, 0x82, 0xAB, 0x14, 0x01, 0x56, 0x0E, 0x01, 0x01)
                    
        return [byte[]]$message
    }
}

# Returns an Relay Proxy Connect Reply message
# Mar 17th 2020
function New-RelayProxyConnectReply
{
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [guid]$SequenceId, 
        [Parameter(Mandatory=$True)]
        [guid]$SomeId2,
        [Parameter(Mandatory=$False)]
        [guid]$ConnectionId = (New-Guid)
    )
    Process
    {
        # Construct the message
        [byte[]]$message = @(0x06, 0xCC, 0x03, 0xA6, 0x02, 0x45, 0x68, 0x74, 0x74, 0x70, 0x3A, 0x2F, 0x2F, 0x74, 0x65, 0x6D, 0x70, 0x75, 0x72, 0x69, 0x2E, 0x6F, 0x72, 0x67, 0x2F, 0x49, 0x43, 0x6F, 0x6E, 0x6E, 0x65, 0x63, 0x74, 0x6F, 0x72, 0x53, 0x69, 0x67, 0x6E, 0x61, 0x6C, 0x69, 0x6E, 0x67, 0x53, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x2F, 0x53, 0x69, 0x67, 0x6E, 0x61, 0x6C, 0x43, 0x6F, 0x6E, 0x6E, 0x65, 0x63, 0x74, 0x6F, 0x72, 0x52, 0x65, 0x73, 0x70, 0x6F, 0x6E, 0x73, 0x65, 0x17, 0x53, 0x69, 0x67, 0x6E, 0x61, 0x6C, 0x43, 0x6F, 0x6E, 0x6E, 0x65, 0x63, 0x74, 0x6F, 0x72, 0x52, 0x65, 0x73, 0x70, 0x6F, 0x6E, 0x73, 0x65, 0x13, 0x68, 0x74, 0x74, 0x70, 0x3A, 0x2F, 0x2F, 0x74, 0x65, 0x6D, 0x70, 0x75, 0x72, 0x69, 0x2E, 0x6F, 0x72, 0x67, 0x2F, 0x15, 0x53, 0x69, 0x67, 0x6E, 0x61, 0x6C, 0x43, 0x6F, 0x6E, 0x6E, 0x65, 0x63, 0x74, 0x6F, 0x72, 0x52, 0x65, 0x73, 0x75, 0x6C, 0x74, 0x5C, 0x68, 0x74, 0x74, 0x70, 0x3A, 0x2F, 0x2F, 0x73, 0x63, 0x68, 0x65, 0x6D, 0x61, 0x73, 0x2E, 0x64, 0x61, 0x74, 0x61, 0x63, 0x6F, 0x6E, 0x74, 0x72, 0x61, 0x63, 0x74, 0x2E, 0x6F, 0x72, 0x67, 0x2F, 0x32, 0x30, 0x30, 0x34, 0x2F, 0x30, 0x37, 0x2F, 0x4D, 0x69, 0x63, 0x72, 0x6F, 0x73, 0x6F, 0x66, 0x74, 0x2E, 0x41, 0x70, 0x70, 0x6C, 0x69, 0x63, 0x61, 0x74, 0x69, 0x6F, 0x6E, 0x50, 0x72, 0x6F, 0x78, 0x79, 0x2E, 0x43, 0x6F, 0x6D, 0x6D, 0x6F, 0x6E, 0x2E, 0x53, 0x69, 0x67, 0x6E, 0x61, 0x6C, 0x69, 0x6E, 0x67, 0x44, 0x61, 0x74, 0x61, 0x4D, 0x6F, 0x64, 0x65, 0x6C, 0x29, 0x68, 0x74, 0x74, 0x70, 0x3A, 0x2F, 0x2F, 0x77, 0x77, 0x77, 0x2E, 0x77, 0x33, 0x2E, 0x6F, 0x72, 0x67, 0x2F, 0x32, 0x30, 0x30, 0x31, 0x2F, 0x58, 0x4D, 0x4C, 0x53, 0x63, 0x68, 0x65, 0x6D, 0x61, 0x2D, 0x69, 0x6E, 0x73, 0x74, 0x61, 0x6E, 0x63, 0x65, 0x0A, 0x41, 0x63, 0x6B, 0x4C, 0x61, 0x74, 0x65, 0x6E, 0x63, 0x79, 0x0B, 0x43, 0x6F, 0x6E, 0x6E, 0x65, 0x63, 0x74, 0x6F, 0x72, 0x49, 0x64, 0x56, 0x02, 0x0B, 0x01, 0x73, 0x04, 0x0B, 0x01, 0x72, 0x20, 0x0B, 0x01, 0x61, 0x06, 0x56, 0x08, 0x55, 0x90, 0x05, 0x55, 0x1E, 0xAD)
        $message += $SequenceId.ToByteArray()
        $message += @(0x01, 0x55, 0x3E, 0x1E, 0x00, 0x82, 0x55, 0x1E, 0xAD)
        $message += $SequenceId.ToByteArray()
        $message += @(0x55, 0x40, 0x83, 0x01, 0x44, 0x0A, 0x1E, 0x00, 0x82, 0xAB, 0x01, 0x44, 0x12, 0xAD)
        $message += $SomeId2.ToByteArray()
        $message += @(0x44, 0x0C, 0x1E, 0x00, 0x82, 0xAB, 0x14, 0x01, 0x56, 0x0E, 0x42, 0x03, 0x0A, 0x05, 0x42, 0x07, 0x0B, 0x01, 0x62, 0x09, 0x0B, 0x01, 0x69, 0x0B, 0x45, 0x0D, 0x81, 0x45, 0x0F, 0x99, 0x24)
        $message += [text.encoding]::UTF8.GetBytes($ConnectionId.ToString())
        $message += @(0x01, 0x01, 0x01, 0x01)
                    
        return [byte[]]$message
    }
}
