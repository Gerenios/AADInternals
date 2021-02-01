## MFA functions utilizing provisioning API

# Mar 3rd 2020
function Set-UserMFA
{
    <#
        .SYNOPSIS
        Sets user's MFA settings

        .DESCRIPTION
        Sets user's MFA settings using Provisioning API
    
        .Parameter AccessToken
        Access Token of the user accessing Azure Active Directory to find the given user to get the SID

        .Parameter UserPrincipalName
        User's principal name.

        .Parameter State
        State of user's MFA: Disabled, Enabled, or Enforced.

        .Parameter StartTime
        Remembers devices issued after the given time. Note! Applied only if State equals Enabled or Enfoced.

        .Parameter PhoneNumber
        User's phone number used for MFA. Must in the following format "+CCC NNNNN" where CCC is country code and NNNN the phone number without leading zero.

        .Parameter AlternativePhoneNumber
        User's alternative phone number used for MFA. Must in the following format "+CCC NNNNN" where CCC is country code and NNNN the phone number without leading zero.

        .Parameter Email
        User's phone number used for MFA. Should be correct email address.

        .Parameter DefaultMethod
        User's default MFA method: PhoneAppNotification, PhoneAppOTP, or OneWaySMS. TwoWayVoiceOffice and TwoWayVoiceMobile won't work in TRIAL tenants.
        In audit log: PhoneAppNotification=0, PhoneAppOTP=6, OneWaySMS=7, TwoWayVoiceOffice=5, TwoWayVoiceMobile=2

        .Example
        PS C:\>$at=Get-AADIntAccessTokenForAADGraph
        PS C:\>Set-AADIntUserMFA -AccessToken $at -UserPrincipalName user@company.com -PhoneNumber "+1 123456789" -DefaultMethod PhoneAppNotification
    #>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$False)]
        [String]$AccessToken,
        [Parameter(Mandatory=$False)]
        $UserPrincipalName,
        [Parameter(Mandatory=$False)]
        [ValidateSet('Disabled','Enabled','Enforced')]
        $State,
        [Parameter(Mandatory=$False)]
        [ValidateSet('PhoneAppOTP','PhoneAppNotification','OneWaySMS','TwoWayVoiceOffice','TwoWayVoiceMobile')]
        $DefaultMethod,
        [Parameter(Mandatory=$False)]
        [DateTime]$StartTime=(Get-Date),
        [Parameter(Mandatory=$False)]
        [String]$PhoneNumber,
        [Parameter(Mandatory=$False)]
        [String]$AlternativePhoneNumber,
        [Parameter(Mandatory=$False)]
        [String]$Email
    )
    Process
    {
        # Validation for phone numbers
        function valPho
        {
            Param([String]$PhoneNumber)
            if(![String]::IsNullOrEmpty($PhoneNumber))
            {
                $regex="^[+]\d{1,3} [1-9]\d{1,11}$" #  1-3 digits (country code), space, non-zero digit, and 1 to 11 digits.
                return [regex]::Match($PhoneNumber,$regex).success
            }
            else
            {
                return $true
            }
        }

        # Check the phone numbers
        if(!((valPho $PhoneNumber) -and (valPho $AlternativePhoneNumber)))
        {
            Write-Error 'Invalid phone number format! Use the following format: "+CCC NNNNNNN" where CCC is the country code and NNNN the phonenumber without the leading zero.'
            return
        }
        
        
        $command="SetUser"

        # Get from cache if not provided
        $AccessToken = Get-AccessTokenFromCache -AccessToken $AccessToken -ClientID "1b730954-1685-4b74-9bfd-dac224a7b894" -Resource "https://graph.windows.net"

        # Get user name from access token if empty
        if([string]::IsNullOrEmpty($UserPrincipalName))
        {
            $UserPrincipalName = (Read-Accesstoken -AccessToken $AccessToken).unique_name
        }

        # Convert time to text
        $startText = $StartTime.ToUniversalTime().toString("yyyy-MM-ddTHH:mm:ss+00:00").Replace(".",":")

        # Set StrongAuthenticationRequirements
        $StrongAuthenticationRequirements="<c:StrongAuthenticationRequirements/>"
        if([string]::IsNullOrEmpty($State))
        {
            $StrongAuthenticationRequirements='<c:StrongAuthenticationRequirements i:nil="true"/>'
        }
        elseif($State -ne "Disabled")
        {
            $StrongAuthenticationRequirements=@"
                <c:StrongAuthenticationRequirements>
	                <c:StrongAuthenticationRequirement>
                        $(Add-CElement -Parameter "RelyingParty" -Value "*")
                        $(Add-CElement -Parameter "RememberDevicesNotIssuedBefore" -Value "$startText")
                        $(Add-CElement -Parameter "State" -Value "$State")
	                </c:StrongAuthenticationRequirement>
                </c:StrongAuthenticationRequirements> 
"@
        }

        # Set the default method
        $StrongAuthenticationMethods='<c:StrongAuthenticationMethods i:nil="true"/>'
        if(![String]::IsNullOrEmpty($DefaultMethod))
        {
            $StrongAuthenticationMethods=@"
            <c:StrongAuthenticationMethods>
				<c:StrongAuthenticationMethod>
					<c:IsDefault>$($DefaultMethod.Equals("PhoneAppOTP").ToString().ToLower())</c:IsDefault>
					<c:MethodType>PhoneAppOTP</c:MethodType>
				</c:StrongAuthenticationMethod>
				<c:StrongAuthenticationMethod>
					<c:IsDefault>$($DefaultMethod.Equals("PhoneAppNotification").ToString().ToLower())</c:IsDefault>
					<c:MethodType>PhoneAppNotification</c:MethodType>
				</c:StrongAuthenticationMethod>
				<c:StrongAuthenticationMethod>
					<c:IsDefault>$($DefaultMethod.Equals("OneWaySMS").ToString().ToLower())</c:IsDefault>
					<c:MethodType>OneWaySMS</c:MethodType>
				</c:StrongAuthenticationMethod>
                <c:StrongAuthenticationMethod>
					<c:IsDefault>$($DefaultMethod.Equals("TwoWayVoiceOffice").ToString().ToLower())</c:IsDefault>
					<c:MethodType>TwoWayVoiceOffice</c:MethodType>
				</c:StrongAuthenticationMethod>
				<c:StrongAuthenticationMethod>
					<c:IsDefault>$($DefaultMethod.Equals("TwoWayVoiceMobile").ToString().ToLower())</c:IsDefault>
					<c:MethodType>TwoWayVoiceMobile</c:MethodType>
				</c:StrongAuthenticationMethod>
			</c:StrongAuthenticationMethods>
"@
        }
        
        # Create the body for setting MFA
        $request_elements=@"
		    <b:User xmlns:c="http://schemas.datacontract.org/2004/07/Microsoft.Online.Administration">
                $StrongAuthenticationMethods
			    <c:StrongAuthenticationPhoneAppDetails i:nil="true"/>
			    <c:StrongAuthenticationProofupTime i:nil="true"/>
			    $StrongAuthenticationRequirements
                <c:StrongAuthenticationUserDetails>
                    $(Add-CElement -Parameter "AlternativePhoneNumber" -Value "$AlternativePhoneNumber")
                    $(Add-CElement -Parameter "Email" -Value "$Email")
                    <c:OldPin i:nil="true"/>
                    $(Add-CElement -Parameter "PhoneNumber" -Value "$PhoneNumber")
                    <c:Pin i:nil="true"/>
                </c:StrongAuthenticationUserDetails>
                $(Add-CElement -Parameter "UserPrincipalName" -Value "$UserPrincipalName")
		    </b:User>
"@

        # Create the envelope and call the API
        $response=Call-ProvisioningAPI(Create-Envelope $AccessToken $command $request_elements)

        # Get the results
        $results = Parse-SOAPResponse($Response)

        # Return
        $results
    }
}

# Sets user's MFA app details
# Jun 29th 2020
function Set-UserMFAApps
{
    <#
        .SYNOPSIS
        Sets user's MFA Apps settings

        .DESCRIPTION
        Sets user's MFA Apps settings using Azure AD Graph
    
        .Parameter AccessToken
        Access Token of the user accessing Azure Active Directory to find the given user to get the SID

        .Parameter UserPrincipalName
        User's principal name.

        .Parameter Id
        Id of the device.

        .Parameter AuthenticationType
        Comma separated list of authentication types of the device. For example, "Notification, OTP" or just "OTP". 
        In audit log: OTP=1, Notification=2.

        .Parameter DeviceName
        Name of the device

        .Parameter DeviceTag
        Tag. Usually "SoftwareTokenActivated".

        .Parameter DeviceToken
        Device token of MFA Authenticator App.

        .Parameter NotificationType
        Notification type of the app. Can be GCM (notification through app) or Invalid (just OTP).
        In audit log: OTP=1, GCM=4

        .Parameter OathTokenTimeDrift
        Time drift of Oath token in seconds. Should be 0 or close to it.

        .Parameter OathSecretKey
        Secret key for calculating OTPs.

        .Parameter PhoneAppVersion
        Version of the app.

        .Parameter TimeInterval
        Time interval.

        .Example
        PS C:\>$at=Get-AADIntAccessTokenForAADGraph
        PS C:\>Get-AADIntUserMFAApps -AccessToken $at -UserPrincipalName user@company.com

        AuthenticationType : Notification, OTP
        DeviceName         : SM-R2D2
        DeviceTag          : SoftwareTokenActivated
        DeviceToken        : APA91...
        Id                 : 454b8d53-d97e-4ead-a69c-724166394334
        NotificationType   : GCM
        OathTokenTimeDrift : 0
        OathSecretKey      : 
        PhoneAppVersion    : 6.2001.0140
        TimeInterval       : 

        AuthenticationType : OTP
        DeviceName         : NO_DEVICE
        DeviceTag          : SoftwareTokenActivated
        DeviceToken        : NO_DEVICE_TOKEN
        Id                 : aba89d77-0a69-43fa-9e5d-6f41c7b9bb16
        NotificationType   : Invalid
        OathTokenTimeDrift : 0
        OathSecretKey      : 
        PhoneAppVersion    : NO_PHONE_APP_VERSION
        TimeInterval       :  

        PS C:\>Set-AADIntUserMFAApps -AccessToken $at -Id 454b8d53-d97e-4ead-a69c-724166394334 -DeviceName "SM-3CPO"
    #>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$False)]
        [String]$AccessToken,
        [Parameter(Mandatory=$False)]
        [String]$UserPrincipalName,
        [Parameter(Mandatory=$True)]
        [guid]$Id,
        [Parameter(Mandatory=$False)]
        [String]$AuthenticationType,
        [Parameter(Mandatory=$False)]
        [String]$DeviceName,
        [Parameter(Mandatory=$False)]
        [String]$DeviceTag,
        [Parameter(Mandatory=$False)]
        [String]$DeviceToken,
        [Parameter(Mandatory=$False)]
        [ValidateSet('Invalid','GCM')]
        [String]$NotificationType,
        [Parameter(Mandatory=$False)]
        [int]$OathTokenTimeDrift,
        [Parameter(Mandatory=$False)]
        [String]$OathSecretKey,
        [Parameter(Mandatory=$False)]
        [String]$PhoneAppVersion,
        [Parameter(Mandatory=$False)]
        [String]$TimeInterval
        
    )
    Process
    {
        # Get from cache if not provided
        $AccessToken = Get-AccessTokenFromCache -AccessToken $AccessToken -ClientID "1b730954-1685-4b74-9bfd-dac224a7b894" -Resource "https://graph.windows.net"

        # Get user name from access token if empty
        if([string]::IsNullOrEmpty($UserPrincipalName))
        {
            $UserPrincipalName = (Read-Accesstoken -AccessToken $AccessToken).unique_name
        }

        # Get user's current configuration and get the app details
        $MFAApps = Get-UserMFAApps -UserPrincipalName $UserPrincipalName -AccessToken $AccessToken

        # If only one element, add it to array
        if(!$MFAApps.Count -gt 0)
        {
            $MFAApp = $MFAApps
            Remove-Variable MFAApps
            $MFAApps = @($MFAApp)
        }

        $found = $false
        $pos=0
        foreach($app in $MFAApps)
        {
            if($app.id -eq ($id.ToString()))
            {
                $found = $true
                break
            }
            $pos++
        }
        
        if(!$found)
        {
            Throw "Authentication app $id not found from user $UserPrincipalName"
        }

        # Apply the new information
        if($AuthenticationType)
        {
            $MFAApps[$pos].AuthenticationType=$AuthenticationType
        }
        if($DeviceName)
        {
            $MFAApps[$pos].DeviceName=$DeviceName
        }
        if($DeviceTag)
        {
            $MFAApps[$pos].DeviceTag=$DeviceTag
        }
        if($DeviceToken)
        {
            $MFAApps[$pos].DeviceToken=$DeviceToken
        }
        if($NotificationType)
        {
            $MFAApps[$pos].NotificationType=$NotificationType
        }
        if($OathTokenTimeDrift -ne $MFAApps[$pos].OathTokenTimeDrift)
        {
            $MFAApps[$pos].OathTokenTimeDrift=$OathTokenTimeDrift
        }
        if($OathSecretKey)
        {
            $MFAApps[$pos].OathSecretKey=$OathSecretKey
        }
        if($PhoneAppVersion)
        {
            $MFAApps[$pos].PhoneAppVersion=$PhoneAppVersion
        }
        if($TimeInterval)
        {
            $MFAApps[$pos].TimeInterval=$TimeInterval
        }

        # Create the body
        $body = '{ "strongAuthenticationDetail": {"phoneAppDetails": ['

        # We need to reverse so that it doesn't look weird in audit log.
        for($a=$MFAApps.count-1; $a -ge 0; $a--)
        {
            $app=$MFAApps[$a]
            $body+="{"
            $body += """authenticationType"": ""$($app.AuthenticationType)"","
            $body += """deviceName"": ""$($app.DeviceName)"","
            $body += """deviceTag"": ""$($app.DeviceTag)"","
            $body += """deviceToken"": ""$($app.DeviceToken)"","
            $body += """id"": ""$($app.Id)"","
            $body += """notificationType"": ""$($app.NotificationType)"","
            $body += """oathTokenTimeDrift"": $($app.OathTokenTimeDrift),"
            if([string]::IsNullOrEmpty($app.OathSecretKey))
            {
                $body += """oathSecretKey"": null,"
            }
            else
            {
                $body += """oathSecretKey"": ""$($app.oathSecretKey)"","
            }
            $body += """phoneAppVersion"": ""$($app.PhoneAppVersion)"","
            $body += """timeInterval"": $(if([string]::IsNullOrEmpty($app.TimeInterval)){'null'}else{$app.TimeInterval})"
            $body += "},"
        }
        # Strip the last comma
        $body=$body.Substring(0,$body.Length-1)
        $body += "]}}";

        # Set the user agent
        $headers=@{
            "User-Agent" = ""
        }
        
        try
        {
            # Set app details
            $results=Call-GraphAPI -AccessToken $AccessToken -Command "users/$UserPrincipalName" -Method PATCH -Body $body -Headers $headers
        }
        catch
        {
            # Get the error
            $err =      $_.ErrorDetails.Message | ConvertFrom-Json

            # Insufficient privileges etc.
            if($err.'odata.error'.message.value)
            {
                Write-Error $err.'odata.error'.message.value
            }
            else # Other errors
            {
                $property = $err.'odata.error'.values[0].value
                $error =    $err.'odata.error'.values[1].value

                Write-Error "$($property): $error"
            }

        }

    }
}

# Mar 3rd 2020
# Deprecated old version
function Get-UserMFA2
{
    <#
        .SYNOPSIS
        Gets user's MFA settings

        .DESCRIPTION
        Gets user's MFA settings using Provisioning API
    
        .Parameter AccessToken
        Access Token of the user accessing Azure Active Directory to find the given user to get the SID

        .Parameter UserPrincipalName
        User's principal name.

        .Example
        PS C:\>$at=Get-AADIntAccessTokenForAADGraph
        PS C:\>Get-AADIntUserMFA -AccessToken $at  -UserPrincipalName user@company.com

        UserPrincipalName      : user@company.com
        State                  : Enforced
        PhoneNumber            : +1 123456789
        AlternativePhoneNumber : +358 123456789
        Email                  : someone@hotmail.com
        DefaultMethod          : OneWaySMS
        Pin                    : 
        OldPin                 : 
        StartTime              : 
    #>

    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$False)]
        [String]$AccessToken,
        [Parameter(Mandatory=$False)]
        $UserPrincipalName
    )
    Process
    {
        # Get the user
        $user = Get-UserByUpn -AccessToken $AccessToken -UserPrincipalName $UserPrincipalName

        # Get user name from access token if empty
        if([string]::IsNullOrEmpty($UserPrincipalName))
        {
            $UserPrincipalName = (Read-Accesstoken -AccessToken $AccessToken).unique_name
        }

        # Get the details and requirements
        $details = $user.StrongAuthenticationUserDetails
        $requirements = $user.StrongAuthenticationRequirements
        $appDetails = $user.StrongAuthenticationPhoneAppDetails
        
        # Construct the attributes hashtable
        $attributes = [ordered]@{
            "UserPrincipalName" = $UserPrincipalName
            "State" = "Disabled"
            "PhoneNumber" = $details.PhoneNumber
            "AlternativePhoneNumber" = $details.AlternativePhoneNumber
            "Email" = $details.Email
            "DefaultMethod" =""
            "Pin" = $details.Pin
            "OldPin" = $details.OldPin
            "StartTime" = $null
        }
        if(![string]::IsNullOrEmpty($requirements))
        {
            $attributes["State"]=$requirements.StrongAuthenticationRequirement.State
            $attributes["StartTime"]=[DateTime]$requirements.StrongAuthenticationRequirement.RememberDevicesNotIssuedBefore
        }

        $count=0
        foreach($app in $appDetails.StrongAuthenticationPhoneAppDetail)
        {
            $count++
            #$app=$appDetails.StrongAuthenticationPhoneAppDetail
            $attributes["App$count-AppAuthenticationType"]=$app.AuthenticationType
            $attributes["App$count-AppDeviceId"]=$app.DeviceId
            $attributes["App$count-AppDeviceName"]=$app.DeviceName
            $attributes["App$count-AppDeviceTag"]=$app.DeviceTag
            $attributes["App$count-AppDeviceToken"]=$app.DeviceToken
            $attributes["App$count-AppId"]=$app.Id
            $attributes["App$count-AppNotificationType"]=$app.NotificationType
            $attributes["App$count-AppOathTokenTimeDrift"]=$app.OathTokenTimeDrift
            $attributes["App$count-AppPhoneAppVersion"]=$app.PhoneAppVersion
            $attributes["App$count-AppTimeInterval"]=$app.TimeInterval

        }

            

        # Get the default method
        foreach($method in $user.StrongAuthenticationMethods.StrongAuthenticationMethod)
        {
            if($method.IsDefault.equals("true"))
            {
                $attributes["DefaultMethod"]=$method.Methodtype
            }
        }

        # Return
        New-Object PSObject -Property $attributes
    }
}


# Jun 24th 2020
function Get-UserMFA
{
    <#
        .SYNOPSIS
        Gets user's MFA settings

        .DESCRIPTION
        Gets user's MFA settings using Provisioning API
    
        .Parameter AccessToken
        Access Token of the user accessing Azure Active Directory to find the given user to get the SID

        .Parameter UserPrincipalName
        User's principal name.

        .Example
        PS C:\>$at=Get-AADIntAccessTokenForAADGraph
        PS C:\>Get-AADIntUserMFA -AccessToken $at  -UserPrincipalName user@company.com

        UserPrincipalName      : user@company.com
        State                  : Enforced
        PhoneNumber            : +1 123456789
        AlternativePhoneNumber : +358 123456789
        Email                  : someone@hotmail.com
        DefaultMethod          : OneWaySMS
        Pin                    : 
        OldPin                 : 
        StartTime              : 
    #>

    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$False)]
        [String]$AccessToken,
        [Parameter(Mandatory=$False)]
        $UserPrincipalName
    )
    Process
    {
        # Get from cache if not provided
        $AccessToken = Get-AccessTokenFromCache -AccessToken $AccessToken -ClientID "1b730954-1685-4b74-9bfd-dac224a7b894" -Resource "https://graph.windows.net"

        # Get user name from access token if empty
        if([string]::IsNullOrEmpty($UserPrincipalName))
        {
            $UserPrincipalName = (Read-Accesstoken -AccessToken $AccessToken).unique_name
        }

        # Get the user information
        $user=Call-GraphAPI -AccessToken $AccessToken -Command "users/$UserPrincipalName" -QueryString "`$select=strongAuthenticationDetail"

        # Get the details and requirements
        $details =      $user.strongAuthenticationDetail.verificationDetail
        $requirements = $user.strongAuthenticationDetail.Requirements
        $appDetails =   $user.strongAuthenticationDetail.PhoneAppDetails
        
        # Construct the attributes hashtable
        $attributes = [ordered]@{
            "UserPrincipalName" =      $UserPrincipalName
            "State" =  $null
            "PhoneNumber" =            $details.PhoneNumber
            "AlternativePhoneNumber" = $details.AlternativePhoneNumber
            "Email" =                  $details.Email
            "DefaultMethod" =""
            "Pin" =                    $details.Pin
            "OldPin" =                 $details.OldPin
            "StartTime" = $null
            "RelyingParty" = $null
        }
        # Check if we got details. If so, default the State to Disabled
        if($details)
        {
            $attributes["State"]="Disabled"
        }
        # Check if we got requirements and update.
        if($requirements)
        {
            $attributes["State"]=$requirements.state
            $attributes["StartTime"]=[DateTime]$requirements.rememberDevicesNotIssuedBefore
            $attributes["RelyingParty"]=$requirements.relyingParty
        }

        $attributes["AppDetails"]=Parse-AuthApps -appDetails $appDetails

            

        # Get the default method
        foreach($method in $user.strongAuthenticationDetail.methods)
        {
            if($method.IsDefault -eq "True")
            {
                $attributes["DefaultMethod"]=$method.Methodtype
            }
        }

        # Return
        New-Object PSObject -Property $attributes
    }
}

# Jun 30th 2020
function Get-UserMFAApps
{
    <#
        .SYNOPSIS
        Gets user's MFA Authentication App settings

        .DESCRIPTION
        Gets user's MFA Authentication App settings using Azure AD Graph
    
        .Parameter AccessToken
        Access Token of the user accessing Azure Active Directory to find the given user to get the SID

        .Parameter UserPrincipalName
        User's principal name.

        .Example
        PS C:\>$at=Get-AADIntAccessTokenForAADGraph
        PS C:\>Get-AADIntUserMFAApps -AccessToken $at -UserPrincipalName user@company.com

        AuthenticationType : Notification, OTP
        DeviceName         : SM-R2D2
        DeviceTag          : SoftwareTokenActivated
        DeviceToken        : APA91...
        Id                 : 454b8d53-d97e-4ead-a69c-724166394334
        NotificationType   : GCM
        OathTokenTimeDrift : 0
        OathSecretKey      : 
        PhoneAppVersion    : 6.2001.0140
        TimeInterval       : 
        LastAuthTime       : 16/08/2020 10.12.17

        AuthenticationType : OTP
        DeviceName         : NO_DEVICE
        DeviceTag          : SoftwareTokenActivated
        DeviceToken        : NO_DEVICE_TOKEN
        Id                 : aba89d77-0a69-43fa-9e5d-6f41c7b9bb16
        NotificationType   : Invalid
        OathTokenTimeDrift : 0
        OathSecretKey      : 
        PhoneAppVersion    : NO_PHONE_APP_VERSION
        TimeInterval       :  
        LastAuthTime       : 06/08/2019 11.07.05
    #>

    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$False)]
        [String]$AccessToken,
        [Parameter(Mandatory=$False)]
        $UserPrincipalName
    )
    Process
    {
        # Get from cache if not provided
        $AccessToken = Get-AccessTokenFromCache -AccessToken $AccessToken -ClientID "1b730954-1685-4b74-9bfd-dac224a7b894" -Resource "https://graph.windows.net"

        # Get user name from access token if empty
        if([string]::IsNullOrEmpty($UserPrincipalName))
        {
            $UserPrincipalName = (Read-Accesstoken -AccessToken $AccessToken).unique_name
        }

        # Get the user information
        $MFAinfo=Get-UserMFA -AccessToken $AccessToken -UserPrincipalName $UserPrincipalName

        # Return
        return $MFAinfo.AppDetails
    }
}


# Generates a new One-Time-Password for MFA with the given secret
# Jun 26th 2020
function New-OTP
{
<#
    .SYNOPSIS
    Generates a one-time-password (OTP) using the given secret.

    .DESCRIPTION
    Generates a one-time-password (OTP) using the given secret. Can be used for MFA if the user's secret is known.

    .Example
    New-AADIntOTP -SecretKey "rrc2 wntz dkbu iikb"
                             
    OTP     Valid
    ---     -----
    502 109 26s 

    .Example
    New-AADIntOTP -SecretKey "rrc2 wntz dkbu iikb" -Clipboard
                             
    OTP copied to clipboard, valid for 28s 
#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [String]$SecretKey,
        [switch]$Clipboard
    )
    Process
    {
        # Strip the spaces
        $SecretKey=$SecretKey.Replace(" ","")

        # Get the current time in seconds from 1.1.1970
        $now = [int]((Get-Date).ToUniversalTime() -$epoch).TotalSeconds

        # Generate the OTP
        $OTP = Generate-tOTP -SecretKey $SecretKey -Seconds $now -TimeShift -15

        # Copy to clipboard
        if($Clipboard)
        {
            "{0:000000}" -f $OTP | Set-Clipboard
            Write-Host "OTP copied to clipboard, valid for $(30-($now % 30))s"
            return
        }

        # Return
        $otpFormatted = "{0:000 000}" -f $OTP

        return New-Object psobject -Property ([ordered]@{"OTP" = $otpFormatted; "Valid" = "$(30-($now % 30))s"})
        
    }
}

# Generates a new One-Time-Password secret
# Jun 27th 2020
function New-OTPSecret
{
<#
    .SYNOPSIS
    Generates a one-time-password (OTP) secret.

    .DESCRIPTION
    Generates a one-time-password (OTP) secret.

    .Example
    New-AADIntOTPSecret
                             
    njny7gdb6tnfihy3 

    .Example
    New-AADIntOTPSecret -Clipboard
                             
    OTP secret copied to clipboard.
#>
    [cmdletbinding()]
    Param(
        [switch]$Clipboard
    )
    Process
    {
        $RNG = [Security.Cryptography.RNGCryptoServiceProvider]::Create()
        [Byte[]]$x=1

        for($secret=''; $secret.length -lt 16)
        {
            $RNG.GetBytes($x); 
            if([char]$x[0] -clike '[2-7a-z]')
            {
                $secret+=[char]$x[0]
            }
        }


        # Copy to clipboard
        if($Clipboard)
        {
            $secret | Set-Clipboard
            Write-Host "OTP secret copied to clipboard"
            return
        }

        # Return
        return $secret

    }
}

# Registers an authenticator app
# Jul 1st 2020
function Register-MFAApp
{
<#
    .SYNOPSIS
    Registers AADInternals Authenticator App for the user. 

    .DESCRIPTION
    Registers AADInternals Authenticator App for the user. 
    
    Requirements:
    * AADInternals Authentication app is installed.
    * Device Token is copied from the app.
    * The user have registered at least one MFA method, e.g. SMS. This is because Access Token creation performs MFA.
    * Registration is done through https://mysignins.microsoft.com so "Users can use the combined security information registration experience" MUST be activated for the tenant.
    
    .Example
    $deviceToken = "APA91bEGIvk1CCg1VIj_YQ_L8fn59UD6...mvXYxlWM6s90_Ct_fpo7iE3uF8hTb"
    PS C:\>Get-AADIntAccessTokenForMySignins -SaveToCache

    Tenant                               User             Resource                             Client                              
    ------                               ----             --------                             ------                              
    9a79b12c-f563-4bdc-9d18-6e6d0d52f73b user@company.com 0000000c-0000-0000-c000-000000000000 19db86c3-b2b9-44cc-b339-36da233a3be2

    PS C:\>Register-AADIntMFAApp -DeviceToken -$deviceToken -DeviceName "My MFA App"

    DefaultMethodOptions : 1
    DefaultMethod        : 0
    Username             : user@company.com
    TenantId             : 9a79b12c-f563-4bdc-9d18-6e6d0d52f73b
    AzureObjectId        : dce60ee2-d907-4478-9f36-de3d74708381
    ConfirmationCode     : 1481770594613653
    OathTokenSecretKey   : dzv5osvdx6dhtly4av2apcts32eqh4bg
    OathTokenEnabled     : true

#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$False)]
        [String]$AccessToken,
        [Parameter(Mandatory=$True)]
        [String]$DeviceToken,
        [Parameter(Mandatory=$False)]
        [String]$DeviceName="AADInternals"
    )
    Begin
    {
        # Define some variables
        $PfPaWs =  "PfPaWs.asmx"
        $Version = "6.2001.0140" # Don't change this or Android version number. It should match the auth app version.
    }
    Process
    {
        try
        {
            # Get from cache if not provided
            $AccessToken = Get-AccessTokenFromCache -AccessToken $AccessToken -Resource "0000000c-0000-0000-c000-000000000000" -ClientId "19db86c3-b2b9-44cc-b339-36da233a3be2"
        }
        catch
        {
            Throw "Access token not found! Call Get-AADIntAccessTokenForMySignins with SaveToCache switch."
        }

        # Phase 1: Get the registration info (url, activation code, session context)
        $regInfo = Get-MFAAppRegistrationInfo -AccessToken $AccessToken
        if(!$regInfo)  {
            Throw "Registration failed (phase 1)"
        }
        
        # Phase 2: Send a new activation request
        $actInfo = Send-MFAAppNewActivation -AccessToken $AccessToken -RegistrationInfo $regInfo -DeviceToken $DeviceToken -DeviceName $DeviceName
        if(!$actInfo) {
            Throw "Registration failed (phase 2)"
        }

        # Phase 3: Send confirmation
        $confResult = Send-MFAAppNewActivationConfirmation -AccessToken $AccessToken -ActivationInfo $actInfo -RegistrationInfo $regInfo
        if(!$confResult) {
            Throw "Registration failed (phase 3)"
        }

        # Phase 4: Add the device to the user
        $verContext = Add-MFAAppAddDevice -AccessToken $AccessToken -RegistrationInfo $regInfo
        if(!$verContext) {
            Throw "Registration failed (phase 4)"
        }

        # Phase 5: Get data updates (not needed)
        $updates = Verify-MFAAppAddDevice -AccessToken $AccessToken -RegistrationInfo $regInfo -VerificationContext $verContext
        if(!$updates) {
            Write-Warning "Couldn't get data updates."
        }

        # Insert data update info to return value
        $actInfo | Add-Member -NotePropertyName "DefaultMethodOptions" -NotePropertyValue $updates.DefaultMethodOptions
        $actInfo | Add-Member -NotePropertyName "DefaultMethod"        -NotePropertyValue $updates.DefaultMethod

        # Return
        return $actInfo

        
    }
}