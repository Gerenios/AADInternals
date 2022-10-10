+++
title = "How to create over 256 character long passwords for cloud-only users"
date = "2019-05-10"
lastmod = "2019-05-10"
categories =["blog"]
tags = ["Office 365","AzureAD","Identity","Security","Password"]
thumbnail = "/images/posts/long passwords.jpg"
+++

Microsoft (finally!) announced in April 2019 the support for 8-256 character passwords in Azure AD/Office 365. 
This limit does not apply to users whose passwords are synced from the on-prem Active Directory (or for federated users).
In this blog, I tell how to set insanely long passwords (64K+) also for cloud-only users!


<!--more-->


# Background

Since the beginning of times, Azure AD and Office 365 has supported only 8-16 long passwords. In April 2019 Microsoft <a href="https://techcommunity.microsoft.com/t5/Microsoft-365-Blog/What-s-new-in-Microsoft-365-user-management-for-April-2019/ba-p/542153" target="_blank">announced</a>
the support for 8-256 long passwords. Passwords also needs to complex, i.e., it has to be a combination of at least three of the following: uppercase letters, lowercase letters, numbers, and symbols (!#, etc.)

This password policy does not apply for passwords synced from on-premises Active Directory. The simple reason for this is that Azure AD does not know what the passwords are.
When password hash sync (PHS) updates user's password, it simply sends AADHash as explained by <a href="https://www.dsinternals.com/en/how-azure-active-directory-connect-syncs-passwords/" target="_blank">Michael Grafnetter</a>.
AADHash is similar to this:
```
v1;PPH1_MD4,181a3024085fcee2f70e,1000,b39525c3bc72a1136fcf7c8a338e0c14313d0450d1a4c98ef0a6ddada3bc5b0a;
```

As the only thing saved to Azure AD is the AADHash of the password, there is no TECHNICAL reason for using longer than 256 character passwords.

# How to set insanely long passwords

To set longer than officially supported passwords, we need to pretend to be Azure AD Connect. And, of course, this is not supported by Microsoft 😬

## AADInternals 

The first thing needed is the latest version <a href="/aadinternals/" target="_blank">AADInternals</a> PowerShell module made by me 😉

{{< highlight powershell >}}
# Install the module if needed
Install-Module AADInternals

# Import the module
Import-Module AADInternals

# Get the access token (and save it to cache)
$token=Get-AADIntAccessTokenForAADGraph
{{< /highlight>}}

## Password hash sync (PHS)

Second, you need PHS to enabled in your tenant. You can check the status using the following command:

{{< highlight powershell >}}
# Check the sync status
Get-AADIntCompanyInformation | fl *sync*
{{< /highlight>}}

Output should be similar to this:
```
DirSyncAnchorAttribute          : mS-DS-ConsistencyGuid
DirSyncApplicationType          : 1651564e-7ce4-4d99-88be-0a65050d8dc3
DirSyncClientMachineName        : 
DirSyncClientVersion            : 1.3.20.0
DirSyncServiceAccount           : 
DirectorySynchronizationEnabled : true
DirectorySynchronizationStatus  : Enabled
LastDirSyncTime                 : 
LastPasswordSyncTime            : 2019-05-09T17:53:25Z
PasswordSynchronizationEnabled  : false
```
If the **PasswordSynchronizationEnabled** is **true**, you are good to go. 

If it is **false**, you need to turn it on.
Normally PHS and the directory synchronization is turned on when Azure AD Connect is installed. 
PHS (and sync if needed) can be turned on using the following command:
{{< highlight powershell >}}
# Turn PHS (and sync) on
Set-AADIntPasswordHashSyncEnabled -Enabled $true
{{< /highlight>}}

Enabling the PHS will take at least a few seconds, so check the status with **Get-AADIntCompanyInformation** before continuing.

**Note:** The **Set-AADIntPasswordHashSyncEnabled** only tells to your Azure AD tenant that PHS is enabled, it doesn't change any settings of the Azure AD Connect (if exist). 
Thus, there should not be any side-effects. Plus, after setting the password, you can disable PHS.

## Setting the cloud anchor (ImmutableId)

Directory synchronization uses cloud anchor to identify users in the Azure AD. The actual user property is **ImmutableId** which is set by Azure AD Connect when the user is synced to Azure AD.
ImmutableID is a Base64 encoded GUID of the user's on-prem AD user object. Currently, this value typically comes from **mS-DS-ConsistencyGuid** attribute which is set by Azure AD Connect (more details <a href="https://docs.microsoft.com/en-gb/azure/active-directory/hybrid/plan-connect-design-concepts#using-msds-consistencyguid-as-sourceanchor" target="_blank">here</a>).

So, in order to set the user's password by "emulating" Azure AD Connect PHS, the third thing is to set the user's ImmutableId attribute.
To check the user's ImmutableId, use the following command:
{{< highlight powershell >}}
# Check user's ImmutableId
Get-AADIntUser -UserPrincipalName "long.password@company.com" | select UserPrincipalName,ImmutableId
{{< /highlight>}}
This user does not have the ImmutableId set:
```
UserPrincipalName          ImmutableId                    
-----------------          -----------                    
long.password@company.com 
```

The ImmutableId can be any string, as long as it is **unique** in your tenant.
To set the ImmutableId with UserPrincipalName of the user, use the following command:
{{< highlight powershell >}}
# Set user's ImmutableId
Set-AADIntUser -UserPrincipalName "long.password@company.com" -ImmutableId long.password@company.com
{{< /highlight>}}

Double-check the ImmutableId using **Get-AADIntUser** as above, should be similar to this:
```
UserPrincipalName          ImmutableId                    
-----------------          -----------                    
long.password@company.com  long.password@company.com
```

## Setting the loooong password

The final step is to set a password for the user.

One of my favorite places to create long passwords is **baconipsum.com**. This <a href="https://baconipsum.com/api/?type=all-meat&paras=1&sentences=10&start-with-lorem=1&format=text" target="_blank">link</a> creates a paragraph of text which can be used as a long password.
Copy the text and save it (or any other password you like) to a variable and set it to the user:
{{< highlight powershell >}}
# Save the password to a variable
$InsanelyLongPassword = "Bacon ipsum dolor amet leberkas doner prosciutto turducken, ham strip steak spare ribs capicola sausage. Beef ribs beef jowl, picanha frankfurter andouille ball tip chicken pig porchetta pork corned beef turkey buffalo ham. Pancetta fatback ball tip pork belly pork chop rump flank. Pork belly prosciutto turkey, sirloin ball tip short ribs strip steak capicola turducken drumstick salami. Ham hock tail tenderloin prosciutto boudin drumstick doner tongue short loin. Short loin boudin pork andouille ham sausage turkey flank hamburger spare ribs meatball jerky bresaola alcatra. Pork loin shank tenderloin drumstick. Alcatra pastrami hamburger buffalo. Strip steak boudin kielbasa picanha. Tenderloin ground round doner, biltong rump chicken capicola meatloaf sausage turducken pork beef ribs cupim."

# Set the password
Set-AADIntUserPassword -AccessToken $token -SourceAnchor "long.password@company.com" -Password $InsanelyLongPassword
{{< /highlight>}}
If succesfull, the output should be similar to this:
```
CloudAnchor Result SourceAnchor                   
----------- ------ ------------                   
CloudAnchor 0      long.password@company.com
```

Now you can login to Office 365 or Azure AD with your insanely long password.

**But how long passwords can be used?** To be honest, I don't know. I've successfully used a 64K long password, which should be enough for any security-freak out there!

## Setting the shrt password
You can also set ridiculously short passwords for test accounts etc.:
{{< highlight powershell >}}
# Set a short password
Set-AADIntUserPassword -AccessToken $token -SourceAnchor "long.password@company.com" -Password "1"
{{< /highlight>}}
