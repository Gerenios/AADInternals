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
        User's default MFA method: PhoneAppNotification, PhoneAppOTP, or OneWaySMS. TwoWayVoiceOffice and TwoWayVoiceMobile can be set but won't work anymore.

        .Example
        PS C:\>$at=Get-AADIntAccessTokenForAADGraph
        PS C:\>Set-AADIntUserMFA -AccessToken $at  -UserPrincipalName user@company.com -PhoneNumber "+1 123456789" -DefaultMethod PhoneAppNotification
    #>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$False)]
        [String]$AccessToken,
        [Parameter(Mandatory=$True)]
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
        $AccessToken = Get-AccessTokenFromCache($AccessToken)

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

# Mar 3rd 2020
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
        [Parameter(Mandatory=$True)]
        $UserPrincipalName
    )
    Process
    {
        # Get the user
        $user = Get-UserByUpn -AccessToken $AccessToken -UserPrincipalName $UserPrincipalName

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
            "AppAuthenticationType" = $null
            "AppDeviceId" = $null
            "AppDeviceName" = $null
            "AppDeviceTag" = $null
            "AppDeviceToken" = $null
            "AppId" = $null
            "AppNotificationType" = $null
            "AppOathSecretKey" = $null
            "AppOathTokenTimeDrift" = $null
            "AppPhoneAppVersion" = $null
            "AppTimeInterval" = $null
        }
        if(![string]::IsNullOrEmpty($requirements))
        {
            $attributes["State"]=$requirements.StrongAuthenticationRequirement.State
            $attributes["StartTime"]=[DateTime]$requirements.StrongAuthenticationRequirement.RememberDevicesNotIssuedBefore
        }

        if(![string]::IsNullOrEmpty($appDetails))
        {
            $app=$appDetails.StrongAuthenticationPhoneAppDetail
            $attributes["AppAuthenticationType"]=$app.AuthenticationType
            $attributes["AppDeviceId"]=$app.DeviceId
            $attributes["AppDeviceName"]=$app.DeviceName
            $attributes["AppDeviceTag"]=$app.DeviceTag
            $attributes["AppDeviceToken"]=$app.DeviceToken
            $attributes["AppId"]=$app.Id
            $attributes["AppNotificationType"]=$app.NotificationType
            $attributes["AppOathTokenTimeDrift"]=$app.OathTokenTimeDrift
            $attributes["AppPhoneAppVersion"]=$app.PhoneAppVersion
            $attributes["AppTimeInterval"]=$app.TimeInterval

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