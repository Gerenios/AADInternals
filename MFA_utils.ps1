# Creates an Oath counter
# Jun 26th 2020
function Get-OathCounter
{
[cmdletbinding()]
    Param()
    Process
    {
        $OathCounter = [int](((Get-Date).ToUniversalTime() - $epoch).TotalSeconds / 30)

        return $OathCounter
    }
}



# Generates a new time-based OTP for MFA
# Jun 26th 2020
function Generate-tOTP
{
[cmdletbinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [String]$SecretKey,
        [Parameter(Mandatory=$False)]
        [int]$Seconds=0,
        [Parameter(Mandatory=$False)]
        [int]$TimeShift=0,
        [Parameter(Mandatory=$False)]
        [int]$TimeStep=30,
        [Parameter(Mandatory=$False)]
        [int]$Digits=6
    )
    Process
    {
        if ($Digits -le 0)
        {
            $Digits = 6 # Can't be zero so default to six
        }
        
        if($Seconds -le 0) 
        {
            # Can't be zero so default to current time
            $Seconds = [int]((Get-Date).ToUniversalTime() -$epoch).TotalSeconds
        }
        
        if($TimeStep -le 0)
        {
            $TimeStep = 30 # Can't be zero, so default to 30 seconds
        }
        
        $Seconds = ($Seconds + $TimeShift) / $TimeStep
        

        [byte[]]$timeBytes = @( 0,0,0,0, # Integer has only 4 bytes so the first four are zeros
                            [byte](([int]$Seconds -shr 24) -band 255),
                            [byte](([int]$Seconds -shr 16) -band 255),
                            [byte](([int]$Seconds -shr  8) -band 255), 
                            [byte]( [int]$Seconds          -band 255)
                        )
        return Generate-hOTP -SecretKey $SecretKey -timeBytes $timeBytes -Digits $Digits
    }
}

# Generates a new HMAC based OTP for MFA
# Jun 26th 2020
function Generate-hOTP
{
[cmdletbinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [String]$SecretKey,
        [Parameter(Mandatory=$True)]
        [byte[]]$TimeBytes,
        [Parameter(Mandatory=$True)]
        [int]$Digits,
        [Parameter(Mandatory=$False)]
        [int]$Position = 0
    )
    Begin
    {
        $hOtpFullResult = 1073741840
    }
    Process
    {
        $divider=0
        if ($Digits -ge 1 -and $Digits -le 9)
        {
            $divider = [Math]::Pow(10, $Digits)
        }
        elseif ($Digits -eq $hOtpFullResult)
        {
            $divider = 0
        }
        else
        {
            throw "Only 1-9 digits are accepted!"
        }

        # Calculate the hash using the secret as a key
        [byte[]]$decodedSecret = From-Base32String -Secret $SecretKey
        $HmacSHA1 = [Security.Cryptography.HMACSHA1]::new($decodedSecret)
        $hmacSize = 20
        $hash=$HmacSHA1.ComputeHash($TimeBytes)
        

        if ($divider -gt 0) 
        {
            if ($Position -le 0 -or  $Position -ge ($hmacSize - 4))
            {
                $Position = $hash[$hmacSize- 1] -band 15
            }

            # Generate the OTP from the hash
            $retVal =              ($hash[$Position]     -band 127) -shl 24
            $retVal = $retVal -bor ($hash[$Position + 1] -band 255) -shl 16
            $retVal = $retVal -bor ($hash[$Position + 2] -band 255) -shl  8
            $retVal = $retVal -bor ($hash[$Position + 3] -band 255)
            $retVal = $retVal % $divider
         
            return $retVal
  
        }
        else
        {
            return Convert-ByteArrayToHex -Bytes $hash
        }
    }
}

# Generates a validation code
# Jun 27th 2020
function Generate-ValidationCode
{
[cmdletbinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [String]$SecretKey,
        [Parameter(Mandatory=$False)]
        [int]$OathCounter=0
    )
    Process
    {
        if ($OathCounter -le 0)
        {
            $OathCounter = Get-OathCounter
        }
        
        $validationCode = Generate-tOTP -SecretKey $SecretKey -Digits 1073741840 -Seconds ($OathCounter*30)
        return $validationCode.toLower()
    }
}

# Converts Base32 string to bytes
# Jun 26th 2020
# Credits: HumanEquivalentUnit
function From-Base32String
{
[cmdletbinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [String]$Secret
    )
    Process
    {
        $bigInteger = [Numerics.BigInteger]::Zero
    
        foreach ($char in ($secret.ToUpper() -replace '[^A-Z2-7]').GetEnumerator()) {
            $bigInteger = ($bigInteger -shl 5) -bor ('ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'.IndexOf($char))
        }

        [byte[]]$secretAsBytes = $bigInteger.ToByteArray()
    

        # BigInteger sometimes adds a 0 byte to the end,
        # if the positive number could be mistaken as a two's complement negative number.
        # If it happens, we need to remove it.
        if ($secretAsBytes[-1] -eq 0) {
            $secretAsBytes = $secretAsBytes[0..($secretAsBytes.Count - 2)]
        }


        # BigInteger stores bytes in Little-Endian order, 
        # but we need them in Big-Endian order.
        [array]::Reverse($secretAsBytes)

        return [byte[]]$secretAsBytes

    }
}

# Converts Base32 string to bytes
# Jun 26th 2020
# Credits: HumanEquivalentUnit
function To-Base32String
{
[cmdletbinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [byte[]]$Secret
    )
    Process
    {
        $byteArrayAsBinaryString = -join $Secret.ForEach{
            [Convert]::ToString($_, 2).PadLeft(8, '0')
        }

        $Base32Secret = [regex]::Replace($byteArrayAsBinaryString, '.{5}', {
        param($Match)
        'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'[[Convert]::ToInt32($Match.Value, 2)]
        })

        return $Base32Secret

    }
}


# Parses authentication apps data
# Jun 27th 2020
function Parse-AuthApps
{
[cmdletbinding()]
    Param(
        [Parameter(Mandatory=$True)]
        $appDetails
    )
    Process
    {
       
        $apps=@()
        foreach($app in $appDetails)
        {
            $appAtributes = [ordered]@{
                "AuthenticationType"=$app.AuthenticationType
                "DeviceName"=        $app.DeviceName
                "DeviceTag"=         $app.DeviceTag
                "DeviceToken"=       $app.DeviceToken
                "Id"=                $app.Id
                "NotificationType"=  $app.NotificationType
                "OathTokenTimeDrift"=$app.OathTokenTimeDrift
                "OathSecretKey"=     $app.OathTokenSecretKey
                "PhoneAppVersion"=   $app.PhoneAppVersion
                "TimeInterval"=      $app.TimeInterval
                "LastAuthTime" =     [DateTime]$app.lastAuthenticatedTimestamp
            }

            $apps+=New-Object psobject -Property $appAtributes
        }

        return $apps

    }
}


# Gets MFA App Registration information (i.e. url, activation code, and session context)
# Jul 1st 2020
function Get-MFAAppRegistrationInfo
{

    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [String]$AccessToken
    )
    Process
    {
        # Create the headers
        $headers=@{
            "Authorization" = "Bearer $AccessToken"
            "Content-Type" =  "application/json"
            "User-Agent" =    ""
        }

        # Get the authorization information
        $response = Invoke-RestMethod -Uri "https://account.activedirectory.windowsazure.com/securityinfo/Authorize" -Method POST -Headers $headers 

        # Strip the carbage from the start and convert to psobject
        $response=$response.Substring($response.IndexOf("{")-1) | ConvertFrom-Json

        # Extract the session context and update headers
        $sessionCtx = $response.sessionCtx
        $headers["SessionCtx"] = $sessionCtx

        # Get the needed codes
        $response = Invoke-RestMethod -Uri "https://account.activedirectory.windowsazure.com/securityinfo/InitializeMobileAppRegistration" -Method POST -Headers $headers -Body '{"securityInfoType":2}'

        # Strip the carbage from the start and convert to psobject
        $response=$response.Substring($response.IndexOf("{")-1) | ConvertFrom-Json

        # Add the session context to return value
        $response | Add-Member -NotePropertyName "SessionCtx" -NotePropertyValue $sessionCtx

        Write-Verbose "Registration info:`n$response"

        # Return
        return $response
        
    }
}

# Sends a new MFA App activation
# Jul 2nd 2020
function Send-MFAAppNewActivation
{

    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [String]$AccessToken,
        [Parameter(Mandatory=$True)]
        $RegistrationInfo,
        [Parameter(Mandatory=$True)]
        [String]$DeviceToken,
        [Parameter(Mandatory=$False)]
        [String]$DeviceName="AADInternals"
    )
    Process
    {
        $url = $RegistrationInfo.Url
        # Append the PfPaWs.asmx if not included
        if(!$Url.EndsWith($PfPaWs))
        {
            if(!$Url.EndsWith("/"))
            {
                $Url+="/";
            }
            $Url+=$PfPaWs;
        }


        # Create the headers
        $headers=@{
            "SOAPAction" =   "http://www.phonefactor.com/PfPaWs/ActivateNew"
            "Content-Type" = "text/xml; charset=utf-8"
            "User-Agent" =   "Dalvik/2.1.0 (Linux; U; Android 8.1.0; AADInternals)"
        }

        $body=@"
<soap:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/" xmlns:ns4="http://www.phonefactor.com/PfPaWs">
	<soap:Header/>
	<soap:Body>
		<ns4:ActivateNew>
			<ns4:activationParams>
				<ns4:ActivationCode>$($RegInfo.ActivationCode)</ns4:ActivationCode>
				<ns4:DeviceToken>$DeviceToken</ns4:DeviceToken>
				<ns4:DeviceName>$DeviceName</ns4:DeviceName>
				<ns4:OathCounter>$(Get-OathCounter)</ns4:OathCounter>
				<ns4:Version>$Version</ns4:Version>
			</ns4:activationParams>
		</ns4:ActivateNew>
	</soap:Body>
</soap:Envelope>
"@
        # Send the activation request
        $response = Invoke-RestMethod -Uri $Url -Method POST -Headers $headers -Body $body

        # Extract the activation information
        $activationInformation=$response.Envelope.Body.ActivateNewResponse.activationInfo

        Write-Verbose "Activation info:`n$activationInformation"

        # Return
        return $activationInformation
        
    }
}

# Sends a new MFA App activation confirmation
# Jul 2nd 2020
function Send-MFAAppNewActivationConfirmation
{

    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [String]$AccessToken,
        [Parameter(Mandatory=$True)]
        $RegistrationInfo,
        [Parameter(Mandatory=$True)]
        $ActivationInfo

    )
    Process
    {
        $url = $RegistrationInfo.Url
        # Append the PfPaWs.asmx if not included
        if(!$Url.EndsWith($PfPaWs))
        {
            if(!$Url.EndsWith("/"))
            {
                $Url+="/";
            }
            $Url+=$PfPaWs;
        }


        # Create the headers
        $headers=@{
            "SOAPAction" =   "http://www.phonefactor.com/PfPaWs/ConfirmActivation"
            "Content-Type" = "text/xml; charset=utf-8"
            "User-Agent" =   "Dalvik/2.1.0 (Linux; U; Android 8.1.0; AADInternals)"
        }

        # Create the body
        $body=@"
<soap:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/" xmlns:ns4="http://www.phonefactor.com/PfPaWs">
<soap:Header/>
<soap:Body>
	<ns4:ConfirmActivation>
		<ns4:confirmationCode>$($ActivationInfo.ConfirmationCode)</ns4:confirmationCode>
	</ns4:ConfirmActivation>
</soap:Body>
</soap:Envelope>
"@
            
        # Send the activation confirmation
        $response = Invoke-RestMethod -Uri $Url -Method POST -Headers $headers -Body $body

        Write-Verbose "Confirmation Activation: $($response.Envelope.Body.ConfirmActivationResponse.ConfirmActivationResult)"

        # Return
        return $response.Envelope.Body.ConfirmActivationResponse.ConfirmActivationResult -eq "true"
        
    }
}

# Adds the new device
# Jul 2nd 2020
function Add-MFAAppAddDevice
{

    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [String]$AccessToken,
        [Parameter(Mandatory=$True)]
        $RegistrationInfo

    )
    Process
    {
        # Set the headers
        $headers=@{
            "Authorization" = "Bearer $AccessToken"
            "SessionCtx" =     $RegistrationInfo.SessionCtx
            #"Access-Control-Request-Method" = "POST"
            #"Access-Control-Request-Headers" ="ajaxrequest,authorization,content-type,sessionctx"
            "Origin" = "https://mysignins.microsoft.com"
            "Sec-Fetch-Site" = "cross-site"
            "Sec-Fetch-Mode" = "cors"
            "Sec-Fetch-Dest" = "empty"
            "Content-Type" =   "application/json"

        }

        $body="{""Type"":2,""Data"":""{\""secretKey\"":\""$($RegistrationInfo.ActivationCode)\"",\""affinityRegion\"":\""$($RegistrationInfo.AffinityRegion)\""}""}"

        $state=0
        $counter=0

        # Loop until we get the context or fail for 10 times
        while($state -ne 1 -and ($counter++) -lt 11)
        {
            # Wait
            Start-Sleep -Seconds 2

            Write-Verbose "Adding MFA application #$counter"

            # Send the AddSecurityInfo request
            $response = Invoke-RestMethod -Method Post -Uri "https://account.activedirectory.windowsazure.com/securityinfo/AddSecurityInfo" -Headers $headers -Body $body

            # Strip the carbage from the start and convert to psobject
            $response=$response.Substring($response.IndexOf("{")-1) | ConvertFrom-Json

            # Get the verification state
            $state = $response.VerificationState
        }

        Write-Verbose "Verification context: $($response.VerificationContext)"
        
        # Return
        return $response.VerificationContext
        
    }
}

# Sends MFA App verification request
# Jul 2nd 2020
function Verify-MFAAppAddDevice
{

    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [String]$AccessToken,
        [Parameter(Mandatory=$True)]
        $RegistrationInfo,
        [Parameter(Mandatory=$True)]
        [String]$VerificationContext
    )
    Process
    {
        # Set the headers
        $headers=@{
            "Authorization" = "Bearer $AccessToken"
            "SessionCtx" =     $RegistrationInfo.SessionCtx
            #"Access-Control-Request-Method" = "POST"
            #"Access-Control-Request-Headers" ="ajaxrequest,authorization,content-type,sessionctx"
            "Origin" = "https://mysignins.microsoft.com"
            "Sec-Fetch-Site" = "cross-site"
            "Sec-Fetch-Mode" = "cors"
            "Sec-Fetch-Dest" = "empty"
            "Content-Type" =   "application/json"

        }

        # Create the body
        $body = "{""Type"":2,""VerificationContext"":""$VerificationContext"",""VerificationData"":null}"

        $state=0
        $counter=0
        $dataUpdates=""

        # Loop until we get the data or fail for 10 times
        while([string]::IsNullOrEmpty($dataUpdates) -and ($counter++) -lt 11)
        {
            # Wait
            Start-Sleep -Seconds 2

            Write-Verbose "Sending VerifySecurityInfo message #$counter"

            # Send the VerifySecurityInfo message
            $response = Invoke-RestMethod -Method Post -Uri "https://account.activedirectory.windowsazure.com/securityinfo/VerifySecurityInfo" -Headers $headers -Body $body

            # Strip the carbage from the start and convert to psobject
            $responseBody=$response.Substring($response.IndexOf("{")-1) | ConvertFrom-Json

            # Get the verification state
            $dataUpdates = $responseBody.Dataupdates
        }

        Write-Verbose "Data Updates: $dataUpdates"

        # Return
        return $dataUpdates
        
    }
}