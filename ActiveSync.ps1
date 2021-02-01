<#
    .SYNOPSIS
    Performs autodiscover for the given user and protocol

    .DESCRIPTION
    Performs autodiscover for the given user using AutoDiscover V2. Returns the url of the requested protocol, defaults to ActiveSync

    .Example
    Get-AADIntEASAutoDiscover -Email user@company.com

    Protocol   Url                                                      
    --------   ---                                                      
    ActiveSync https://outlook.office365.com/Microsoft-Server-ActiveSync


    .Example
    Get-AADIntEASAutoDiscover -Email user@company.com -Protocol All

    Protocol                     Url                                                        
    --------                     ---                                                        
    Rest                         https://outlook.office.com/api                             
    ActiveSync                   https://outlook.office365.com/Microsoft-Server-ActiveSync  
    Ews                          https://outlook.office365.com/EWS/Exchange.asmx            
    Substrate                    https://substrate.office.com                               
    Substratesearchservice       https://outlook.office365.com/search                       
    AutodiscoverV1               https://outlook.office365.com/autodiscover/autodiscover.xml
    substratesearchservice       https://outlook.office365.com/search                       
    substratenotificationservice https://substrate.office.com/insights                      
    outlookmeetingscheduler      https://outlook.office.com/scheduling/api                  
    outlookpay                   https://outlook.office.com/opay
    
#>
function Get-EASAutoDiscover
{
    Param(
            
            [Parameter(Mandatory=$True)]
            [String]$Email,
            [ValidateSet('All','Rest','ActiveSync','Ews','Substrate','SubstrateSearchService','AutodiscoverV1','SubstrateNotificationService','OutlookMeetingScheduler','OutlookPay','Actions','Connectors','ConnectorsProcessors','ConnectorsWebhook','NotesClient','OwaPoweredExperience','ToDo','Weve','OutlookLocationsService','OutlookCloudSettingsService','OutlookTailoredExperiences','OwaPoweredExperienceV2')]
            [String]$Protocol="All"
        )
    Process
    {
        if($Protocol -eq "All")
        {
            $Protocols = @('Rest','ActiveSync','Ews','Substrate','SubstrateSearchService','AutodiscoverV1','SubstrateNotificationService','OutlookMeetingScheduler','OutlookPay','Actions','Connectors','ConnectorsProcessors','ConnectorsWebhook','NotesClient','OwaPoweredExperience','ToDo','Weve','OutlookLocationsService','OutlookCloudSettingsService','OutlookTailoredExperiences','OwaPoweredExperienceV2')
            $Response = @()
            foreach($p in $Protocols)
            {
                $url = "https://outlook.office365.com/Autodiscover/Autodiscover.json?Email=$Email&Protocol=$p"

                $response+=Invoke-RestMethod -Uri $url -Method Get
            }
        }
        else
        {
            $url = "https://outlook.office365.com/Autodiscover/Autodiscover.json?Email=$Email&Protocol=$Protocol"

            $response=Invoke-RestMethod -Uri $url -Method Get
        }
        $response
    }
}

<#
    .SYNOPSIS
    Performs autodiscover for the given user

    .DESCRIPTION
    Performs autodiscover for the given user. Returns the url of ActiveSync service

    .Example
    Get-AADIntEASAutoDiscoverV1 -Credentials $Cred

    https://outlook.office365.com/Microsoft-Server-ActiveSync
    
#>
function Get-EASAutoDiscoverV1
{
    Param(
            [Parameter(Mandatory=$False)]
            [System.Management.Automation.PSCredential]$Credentials,
            [Parameter(Mandatory=$False)]
            [String]$AccessToken
        )
    Process
    {
        $auth = Create-AuthorizationHeader -Credentials $Credentials -AccessToken $AccessToken -Resource "https://outlook.office365.com" -ClientId "d3590ed6-52b3-4102-aeff-aad2292ab01c"
        $headers = @{
            "Authorization" = $auth
            "Content-Type" = "text/xml"
        }

        $user=Get-UserNameFromAuthHeader -Auth $auth
        $domain=$user.Split("@")[1]

        # Default host for Office 365
        $hostname = "autodiscover-s.outlook.com"
        
        $url = "https://$hostname/Autodiscover/Autodiscover.xml"

        $body=@"
            <Autodiscover xmlns="http://schemas.microsoft.com/exchange/autodiscover/mobilesync/requestschema/2006">
            <Request>
                <EMailAddress>$user</EMailAddress>
                <AcceptableResponseSchema>http://schemas.microsoft.com/exchange/autodiscover/mobilesync/responseschema/2006</AcceptableResponseSchema>
            </Request>
            </Autodiscover>
"@
        
        $response=Invoke-RestMethod -Uri $url -Method Post -Headers $headers -Body $body -TimeoutSec 60
        $response.Autodiscover.Response.Action.Settings.Server.Url
    }
}


function Get-EASOptions
{
    Param(
            [Parameter(Mandatory=$False)]
            [System.Management.Automation.PSCredential]$Credentials,
            [Parameter(Mandatory=$False)]
            [String]$AccessToken
        )
    Process
    {

        $headers = @{
            "Authorization" = Create-AuthorizationHeader -Credentials $Credentials -AccessToken $AccessToken -Resource "https://outlook.office365.com" -ClientId "d3590ed6-52b3-4102-aeff-aad2292ab01c"
        }
        
        $response=Invoke-WebRequest -UseBasicParsing -Uri "https://outlook.office365.com/Microsoft-Server-ActiveSync" -Method Options -Headers $headers -TimeoutSec 10
        $response.headers
    }
}


# Get folders to sync
function Get-EASFolderSync
{
<#
    .SYNOPSIS
    Gets user's ActiveSync options

    .DESCRIPTION
    Gets user's ActiveSync options. Shows for instance Front and Backend server names. 
    The first two characters indicates the city: HE=Helsinki, VI=Vienna, DB=Dublin, AM=Amsterdam, etc.

    .Example
    Get-AADIntEASOptions -Credentials $Cred

    Key                   Value                                                                                                              
    ---                   -----                                                                                                              
    Allow                 OPTIONS,POST                                                                                                       
    request-id            61e62c8d-f689-4d08-b0d7-4ffa1e42e1ea                                                                               
    X-CalculatedBETarget  HE1PR0802MB2202.eurprd08.prod.outlook.com                                                                          
    X-BackEndHttpStatus   200                                                                                                                
    X-RUM-Validated       1                                                                                                                  
    MS-Server-ActiveSync  15.20                                                                                                              
    MS-ASProtocolVersions 2.0,2.1,2.5,12.0,12.1,14.0,14.1,16.0,16.1                                                                          
    MS-ASProtocolCommands Sync,SendMail,SmartForward,SmartReply,GetAttachment,GetHierarchy,CreateCollection,DeleteCollection,MoveCollectio...
    Public                OPTIONS,POST                                                                                                       
    X-MS-BackOffDuration  L/-469                                                                                                             
    X-DiagInfo            HE1PR0802MB2202                                                                                                    
    X-BEServer            HE1PR0802MB2202                                                                                                    
    X-FEServer            HE1PR1001CA0019                                                                                                    
    Content-Length        0                                                                                                                  
    Cache-Control         private                                                                                                            
    Content-Type          application/vnd.ms-sync.wbxml                                                                                      
    Date                  Wed, 03 Apr 2019 17:40:18 GMT                                                                                      
    Server                Microsoft-IIS/10.0                                                                                                 
    X-AspNet-Version      4.0.30319                                                                                                          
    X-Powered-By          ASP.NET 
#>
    Param(
            [Parameter(Mandatory=$False)]
            [System.Management.Automation.PSCredential]$Credentials,
            [Parameter(Mandatory=$False)]
            [String]$AccessToken,
            [Parameter(Mandatory=$True)]
            [String]$DeviceId,
            [Parameter(Mandatory=$False)]
            [String]$DeviceType="Android"
        )
    Process
    {
        [xml]$request=@"
        <FolderSync xmlns="FolderHierarchy">
            <SyncKey>0</SyncKey>
        </FolderSync>
"@

        $response = Call-EAS -Request $request -Command FolderSync -Authorization (Create-AuthorizationHeader -Credentials $Credentials -AccessToken $AccessToken -Resource "https://outlook.office365.com" -ClientId "d3590ed6-52b3-4102-aeff-aad2292ab01c") -DeviceId $DeviceId -DeviceType $DeviceType

        return $response
    }
}


function Send-EASMessage
{
<#
    .SYNOPSIS
    Sends mail message using ActiveSync

    .DESCRIPTION
    Sends mail using ActiveSync using the account of given credentials. 
    Supports both Basic and Modern Authentication.
    Message MUST be html (or plaintext) and SHOULD be Base64 encoded (if not, it's automatically converted).

    .Example
    PS C:\>$Cred=Get-Credential
    PS C:\>Send-AADIntEASMessage -Credentials $Cred -DeviceId androidc481040056 -DeviceType Android -Recipient someone@company.com -Subject "An email" -Message "This is a message!"

    .Example
    PS C:\>$At=Get-AADIntAccessTokenForEXO
    PS C:\>Send-AADIntEASMessage -AccessToken $At -DeviceId androidc481040056 -DeviceType Android -Recipient someone@company.com -Subject "An email" -Message "This is a message!"
   
#>
    Param(
            [Parameter(Mandatory=$False)]
            [System.Management.Automation.PSCredential]$Credentials,
            [Parameter(Mandatory=$False)]
            [String]$AccessToken,
            [Parameter(Mandatory=$True)]
            [String]$Recipient,
            [Parameter(Mandatory=$True)]
            [String]$Subject,
            [Parameter(Mandatory=$True)]
            [String]$Message,
            [Parameter(Mandatory=$True)]
            [String]$DeviceId,
            [Parameter(Mandatory=$False)]
            [String]$DeviceType="Android",
            [Parameter(Mandatory=$False)]
            [String]$DeviceOS
        )
    Process
    {
        $messageId = (New-Guid).ToString()
        [xml]$request=@"
<SendMail xmlns="ComposeMail"><ClientId>$messageId</ClientId><SaveInSentItems></SaveInSentItems><MIME><![CDATA[Date: Wed, 03 Apr 2019 08:51:41 +0300
Subject: $Subject
Message-ID: <$messageId>
From: rudolf@santaclaus.org
To: $recipient
Importance: Normal
X-Priority: 3
X-MSMail-Priority: Normal
MIME-Version: 1.0
Content-Type: text/html; charset=utf-8
Content-Transfer-Encoding: base64

$(Get-MessageAsBase64 -Message $Message)
]]></MIME></SendMail>
"@

        $response = Call-EAS -Request $request -Command SendMail -Authorization (Create-AuthorizationHeader -Credentials $Credentials -AccessToken $AccessToken -Resource "https://outlook.office365.com" -ClientId "d3590ed6-52b3-4102-aeff-aad2292ab01c") -DeviceId $DeviceId -DeviceType $DeviceType -DeviceOS $DeviceOS

        return $response
    }
}

<#
    .SYNOPSIS
    Sets users device settings using ActiveSync

    .DESCRIPTION
    Sets users device settings using ActiveSync. You can change device's Model, IMEI, FriendlyName, OS, OSLanguage, PhoneNumber, MobileOperator, and User-Agent.
    All empty properties are cleared from the device settings. I.e., if IMEI is not given, it will be cleared.

    .Example
    PS C:\>$Cred=Get-Credential
    PS C:\>Set-AADIntEASSettings -Credentials $Cred -DeviceId androidc481040056 -DeviceType Android -Model "Samsung S10" -PhoneNumber "+1234567890"   
#>
function Set-EASSettings
{
    Param(
            [Parameter(Mandatory=$False)]
            [System.Management.Automation.PSCredential]$Credentials,
            [Parameter(Mandatory=$False)]
            [String]$AccessToken,
            [Parameter(Mandatory=$True)]
            [String]$DeviceId,
            [Parameter(Mandatory=$False)]
            [String]$DeviceType="Android",
            [Parameter(Mandatory=$False)]
            [String]$Model,
            [Parameter(Mandatory=$False)]
            [String]$IMEI,
            [Parameter(Mandatory=$False)]
            [String]$FriendlyName,
            [Parameter(Mandatory=$False)]
            [String]$OS,
            [Parameter(Mandatory=$False)]
            [String]$OSLanguage,
            [Parameter(Mandatory=$False)]
            [String]$PhoneNumber,
            [Parameter(Mandatory=$False)]
            [String]$MobileOperator,
            [Parameter(Mandatory=$False)]
            [String]$UserAgent
        )
    Process
    {
        [xml]$request=@"
<Settings xmlns="Settings">
     <DeviceInformation>
         <Set>
             <Model>$Model</Model>
             <IMEI>$IMEI</IMEI>
             <FriendlyName>$FriendlyName</FriendlyName>
             <OS>$OS</OS>
             <OSLanguage>$OSLanguage</OSLanguage>
             <PhoneNumber>$PhoneNumber</PhoneNumber>
             <MobileOperator>$MobileOperator</MobileOperator>
             <UserAgent>$UserAgent</UserAgent>
         </Set>
     </DeviceInformation>
 </Settings>
"@

        $response = Call-EAS -Request $request -Command Settings -Authorization (Create-AuthorizationHeader -Credentials $Credentials -AccessToken $AccessToken -Resource "https://outlook.office365.com" -ClientId "d3590ed6-52b3-4102-aeff-aad2292ab01c") -DeviceId $DeviceId -DeviceType $DeviceType -UserAgent $UserAgent

        return $response.OuterXml
    }
}

<#
    .SYNOPSIS
    Adds a new ActiveSync device to user

    .DESCRIPTION
    Adds a new ActiveSync device to the user, and accepts security policies. All device information settings are required (Model, IMEI, FriendlyName, OS, OSLanguage, PhoneNumber, MobileOperator, and User-Agent).
    Returns a policy key that could be used in subsequent ActiveSync calls
    
    .Example
    PS C:\>$Cred=Get-Credential
    PS C:\>Add-AADIntEASDevice -Credentials $Cred -DeviceId androidc481040056 -DeviceType Android -Model "Samsung S10" -PhoneNumber "+1234567890" -IMEI "1234" -FriendlyName "My Phone" -OS "Android" -OSLanguage "EN" -MobileOperator "BT" -UserAgent "Android/8.0"

    3382976401
#>
function Add-EASDevice
{
    Param(
            [Parameter(Mandatory=$False)]
            [System.Management.Automation.PSCredential]$Credentials,
            [Parameter(Mandatory=$False)]
            [String]$AccessToken,
            [Parameter(Mandatory=$True)]
            [String]$DeviceId,
            [Parameter(Mandatory=$False)]
            [String]$DeviceType="Android",
            [Parameter(Mandatory=$False)]
            [String]$Model,
            [Parameter(Mandatory=$False)]
            [String]$IMEI,
            [Parameter(Mandatory=$False)]
            [String]$FriendlyName,
            [Parameter(Mandatory=$False)]
            [String]$OS,
            [Parameter(Mandatory=$False)]
            [String]$OSLanguage,
            [Parameter(Mandatory=$False)]
            [String]$PhoneNumber,
            [Parameter(Mandatory=$False)]
            [String]$MobileOperator,
            [Parameter(Mandatory=$False)]
            [String]$UserAgent
        )
    Process
    {
        [xml]$request=@"
<Provision xmlns="Provision" >
     <DeviceInformation xmlns="Settings">
         <Set>
             <Model>$Model</Model>
             <IMEI>$IMEI</IMEI>
             <FriendlyName>$FriendlyName</FriendlyName>
             <OS>$OS</OS>
             <OSLanguage>$OSLanguage</OSLanguage>
             <PhoneNumber>$PhoneNumber</PhoneNumber>
             <MobileOperator>$MobileOperator</MobileOperator>
             <UserAgent>$UserAgent</UserAgent>
         </Set>
     </DeviceInformation>
      <Policies>
           <Policy>
                <PolicyType>MS-EAS-Provisioning-WBXML</PolicyType> 
           </Policy>
      </Policies>
 </Provision>

"@

        # The first request (must be done twice for some reason)
        $response = Call-EAS -Request $request -Command Provision -Authorization (Create-AuthorizationHeader -Credentials $Credentials -AccessToken $AccessToken -Resource "https://outlook.office365.com" -ClientId "d3590ed6-52b3-4102-aeff-aad2292ab01c") -DeviceId $DeviceId -DeviceType $DeviceType -UserAgent $UserAgent -PolicyKey 0 
        $response = Call-EAS -Request $request -Command Provision -Authorization (Create-AuthorizationHeader -Credentials $Credentials -AccessToken $AccessToken -Resource "https://outlook.office365.com" -ClientId "d3590ed6-52b3-4102-aeff-aad2292ab01c") -DeviceId $DeviceId -DeviceType $DeviceType -UserAgent $UserAgent -PolicyKey 0 

        # Save the temporary policy key
        $policyKey = $response.Provision.Policies.Policy.PolicyKey

        # Create a request to acknowledge the policy
[xml]$request=@"
<Provision xmlns="Provision" >
      <Policies>
           <Policy>
                <PolicyType>MS-EAS-Provisioning-WBXML</PolicyType> 
                <PolicyKey>$policyKey</PolicyKey>
                <Status>1</Status>
           </Policy>
      </Policies>
 </Provision>
"@

        # The second request
        $response = Call-EAS -Request $request -Command Provision -Authorization (Create-AuthorizationHeader -Credentials $Credentials -AccessToken $AccessToken -Resource "https://outlook.office365.com" -ClientId "d3590ed6-52b3-4102-aeff-aad2292ab01c") -DeviceId $DeviceId -DeviceType $DeviceType -UserAgent $UserAgent -PolicyKey $policyKey

        # Save the final policy key
        $policyKey = $response.Provision.Policies.Policy.PolicyKey
        
        $policyKey
    }
}


# Jan 2nd 2020
function Get-MobileOutlookSettings
{
    Param(
            [Parameter(Mandatory=$False)]
            [System.Management.Automation.PSCredential]$Credentials,
            [Parameter(Mandatory=$False)]
            [String]$AccessToken
        )
    Process
    {

        $headers = @{
            "Authorization" = Create-AuthorizationHeader -Credentials $Credentials -AccessToken $AccessToken -Resource "https://outlook.office365.com" -ClientId "d3590ed6-52b3-4102-aeff-aad2292ab01c"
            "Accept"="application/json"
        }

        $response=Invoke-RestMethod "https://outlook.office365.com/outlookservice/ishxscapable" -Headers $headers

        # Return
        $response
    }
}

# Gets the settings for Exchange Active Sync (Outlook mobile)
function Get-EASSettings
{
    Param(
            [Parameter(Mandatory=$False)]
            [System.Management.Automation.PSCredential]$Credentials,
            [Parameter(Mandatory=$False)]
            [String]$AccessToken
        )
    Process
    {

        $headers = @{
            "Authorization" = Create-AuthorizationHeader -Credentials $Credentials -AccessToken $AccessToken -Resource "https://outlook.office365.com" -ClientId "d3590ed6-52b3-4102-aeff-aad2292ab01c"
            "Accept"="application/json"
        }

        $response=Invoke-RestMethod "https://outlook.office365.com/outlookservice/ishxscapable" -Headers $headers

        # Return
        $response
    }
}

# Gets the sync status for Exchange Active Sync (Outlook mobile)
function Get-EASSyncStatus
{
    Param(
            [Parameter(Mandatory=$False)]
            [System.Management.Automation.PSCredential]$Credentials,
            [Parameter(Mandatory=$False)]
            [String]$AccessToken,
            [Parameter(Mandatory=$True)]
            [String]$AnchorMailBox,
            [Parameter(Mandatory=$True)]
            [byte[]]$OutlookFrame
        )
    Process
    {

        $headers = @{
            "Authorization" = Create-AuthorizationHeader -Credentials $Credentials -AccessToken $AccessToken -Resource "https://outlook.office365.com" -ClientId "d3590ed6-52b3-4102-aeff-aad2292ab01c"
            "Accept"="application/http.wbxml"
            "X-AnchorMailbox" = $AnchorMailBox
            "Content-Type" = "application/http.wbxml"
            "X-OSApi-Protocol" = "HttpSockets:1.1"
            #"X-CommandId" = "6" # 6
            "User-Agent" = "Outlook-Android/2.0"
            "connect" = "GET"
        }

        $response=Invoke-WebRequest -UseBasicParsing "https://outlook.office365.com/outlookservice/servicechannel.hxs" -Headers $headers -Body $OutlookFrame -Method Post -TimeOutSec 300

        $responseBytes = [byte[]]$response.Content

        [xml]$responseXml = O365WBXML2XML -wbxml $responseBytes

        # Return
        $responseXml.InnerXml
        
    }
}

function Get-EASMails
{
    Param(
            [Parameter(Mandatory=$False)]
            [System.Management.Automation.PSCredential]$Credentials,
            [Parameter(Mandatory=$False)]
            [String]$AccessToken,
            [Parameter(Mandatory=$True)]
            [guid]$DeviceId,
            [Parameter(Mandatory=$False)]
            [String]$DeviceType="Android",
            [Parameter(Mandatory=$False)]
            [String]$OSVersion="5.0.2",
            [Parameter(Mandatory=$False)]
            [String]$ClientVersion="4.0.90 (379) prod",
            [Parameter(Mandatory=$False)]
            [String]$OutlookVersion="16.0.12317.33832",
            [Parameter(Mandatory=$False)]
            [String]$OutlookTitle="Outlook for iOS and Android"
        )
    Process
    {

        $settings = Get-EASSettings -Credentials $Credentials -AccessToken $AccessToken
        $anchorMailBox = $settings.AnchorMailBox

        $request=@"
            <frames>
	            <frame>
		            <block>
			            <_FF_05 xmlns="_FF">
				            <_FF_07 xmlns="_FF">
					            <EXT_2>01</EXT_2>
				            </_FF_07>
				            <_FF_06 xmlns="_FF">
					            <EXT_2>01</EXT_2>
				            </_FF_06>
				            <_FF_08 xmlns="_FF">sync</_FF_08>
				            <_FF_09 xmlns="_FF">$((New-Guid).ToString())</_FF_09>
				            <_FF_0D xmlns="_FF">
					            <EXT_2>04</EXT_2>
				            </_FF_0D>
				            <_FF_0E xmlns="_FF">
					            <EXT_2>0B</EXT_2>
				            </_FF_0E>
				            <_FF_0F xmlns="_FF">
					            <EXT_2>1C03</EXT_2>
				            </_FF_0F>
				            <_FF_19 xmlns="_FF">$($DeviceId.ToString())</_FF_19>
				            <_FF_16 xmlns="_FF"/>
				            <_FF_2B xmlns="_FF">$ClientVersion</_FF_2B>
				            <_FF_18 xmlns="_FF">$OutlookVersion</_FF_18>
				            <_FF_1A xmlns="_FF">$OSVersion</_FF_1A>
				            <_FF_1B xmlns="_FF">$DeviceType</_FF_1B>
				            <_FF_1F xmlns="_FF"/>
				            <_FF_2A xmlns="_FF"/>
				            <_FF_20 xmlns="_FF">
					            <_FF_21 xmlns="_FF">
						            <_FF_22 xmlns="_FF">
							            <EXT_2>01</EXT_2>
						            </_FF_22>
						            <_FF_23 xmlns="_FF">$((New-Guid).ToString())</_FF_23>
					            </_FF_21>
					            <_FF_21 xmlns="_FF">
						            <_FF_22 xmlns="_FF">
							            <EXT_2>02</EXT_2>
						            </_FF_22>
						            <_FF_23 xmlns="_FF">true</_FF_23>
					            </_FF_21>
					            <_FF_21 xmlns="_FF">
						            <_FF_22 xmlns="_FF">
							            <EXT_2>03</EXT_2>
						            </_FF_22>
						            <_FF_23 xmlns="_FF">0</_FF_23>
					            </_FF_21>
					            <_FF_21 xmlns="_FF">
						            <_FF_22 xmlns="_FF">
							            <EXT_2>04</EXT_2>
						            </_FF_22>
						            <_FF_23 xmlns="_FF">true</_FF_23>
					            </_FF_21>
					            <_FF_21 xmlns="_FF">
						            <_FF_22 xmlns="_FF">
							            <EXT_2>06</EXT_2>
						            </_FF_22>
						            <_FF_23 xmlns="_FF">true</_FF_23>
					            </_FF_21>
					            <_FF_21 xmlns="_FF">
						            <_FF_22 xmlns="_FF">
							            <EXT_2>08</EXT_2>
						            </_FF_22>
						            <_FF_23 xmlns="_FF">true</_FF_23>
					            </_FF_21>
					            <_FF_21 xmlns="_FF">
						            <_FF_22 xmlns="_FF">
							            <EXT_2>0B</EXT_2>
						            </_FF_22>
						            <_FF_23 xmlns="_FF">true</_FF_23>
					            </_FF_21>
					            <_FF_21 xmlns="_FF">
						            <_FF_22 xmlns="_FF">
							            <EXT_2>09</EXT_2>
						            </_FF_22>
						            <_FF_23 xmlns="_FF">true</_FF_23>
					            </_FF_21>
					            <_FF_21 xmlns="_FF">
						            <_FF_22 xmlns="_FF">
							            <EXT_2>0E</EXT_2>
						            </_FF_22>
						            <_FF_23 xmlns="_FF">true</_FF_23>
					            </_FF_21>
					            <_FF_21 xmlns="_FF">
						            <_FF_22 xmlns="_FF">
							            <EXT_2>07</EXT_2>
						            </_FF_22>
						            <_FF_23 xmlns="_FF">2</_FF_23>
					            </_FF_21>
					            <_FF_21 xmlns="_FF">
						            <_FF_22 xmlns="_FF">
							            <EXT_2>0A</EXT_2>
						            </_FF_22>
						            <_FF_23 xmlns="_FF">true</_FF_23>
					            </_FF_21>
					            <_FF_21 xmlns="_FF">
						            <_FF_22 xmlns="_FF">
							            <EXT_2>0F</EXT_2>
						            </_FF_22>
						            <_FF_23 xmlns="_FF">true</_FF_23>
					            </_FF_21>
				            </_FF_20>
				            <_FF_26 xmlns="_FF">
					            <EXT_2>02</EXT_2>
				            </_FF_26>
				            <_FF_25 xmlns="_FF">
					            <EXT_2>00</EXT_2>
				            </_FF_25>
			            </_FF_05>
		            </block>
		            <block>
			            <_E0_3B xmlns="_E0">
				            <_E0_3C xmlns="_E0">$OutlookVersion</_E0_3C>
				            <_E0_3D xmlns="_E0"/>
				            <_E1_1B xmlns="_E1"/>
				            <_E1_1C xmlns="_E1"/>
				            <_E1_1D xmlns="_E1">$OutlookTitle</_E1_1D>
				            <_E1_1E xmlns="_E1"/>
				            <_E1_1F xmlns="_E1"/>
				            <_E0_3E xmlns="_E0">
					            <EXT_2>01</EXT_2>
				            </_E0_3E>
				            <_10_11 xmlns="_10">
					            <EXT_2>01</EXT_2>
				            </_10_11>
				            <_1B_22 xmlns="_1B">
					            <EXT_2>01</EXT_2>
				            </_1B_22>
			            </_E0_3B>
		            </block>
	            </frame>
            </frames>
"@

        $response=Get-EASSyncStatus -Credentials $Credentials -AccessToken $AccessToken -AnchorMailBox $anchorMailBox -OutlookFrame ([byte[]](XML2O365WBXML -xml $request))

        $response
    }
}