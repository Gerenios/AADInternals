+++
title = "Hunt for the gMSA secrets"
date = "2022-08-29"
lastmod = "2022-08-29"
categories =["blog"]
tags = ["Azure Active Directory","Azure","security","PRT","device","join","hybrid join"]
thumbnail = "/images/posts/gmsa.png"
draft = false
+++
 
Group Managed Service Accounts (gMSA's) can be used to run Windows services over multiple servers within the Windows domain.
<br>
<br>
Since the launch of Windows Server 2012 R2, gMSA has been the recommended service account option for AD FS. 
As abusing AD FS is one of my favourite hobbies, I wanted to learn how gMSAs work.

<!--more-->

# Introduction

## What is gMSA?

According to Microsoft's <a href="https://docs.microsoft.com/en-us/windows-server/security/group-managed-service-accounts/getting-started-with-group-managed-service-accounts" target="_blank">documentation</a>, there are multiple options for running services:

Principals										|Services supported								| Password management
---												| ---											| ---
Computer Account of Windows system				| Limited to one domain joined server			| Computer manages
Computer Account without Windows system			| Any domain joined server						| None
Virtual Account									| Limited to one server							| Computer manages
Windows 7 standalone Managed Service Account	| Limited to one domain joined server			| Computer manages
User Account									| Any domain joined server						| None
Group Managed Service Account					| Any Windows Server 2012 domain-joined server	| The domain controller manages, and the host retrieves

If we want to run Windows service on multiple servers using the same **managed** account, we need to use <a href="https://docs.microsoft.com/en-us/windows-server/security/group-managed-service-accounts/group-managed-service-accounts-overview" target="_blank">gMSA</a>.
One of these kind of services is <a href="https://docs.microsoft.com/en-us/windows-server/identity/active-directory-federation-services" target="_blank">Active Directory Federation Services</a> (AD FS).

## Sample AD FS configuration

As I'm using AD FS here as an example, I configured AD FS to use gMSA account. I named the account to **AADINTERNALS\gmsaADFS$**

![ad fs](/images/posts/gmsa_01.png)

The account can be located in AD under **Managed Service Accounts**

![gmsa in ad](/images/posts/gmsa_02.png)

To run the service using gMSA means that the computer running the service needs to know it's password. So how could one access that password?

# Getting gMSA password from AD

While googling around, I ended up to **The Hacker Recipes**'s <a href="https://www.thehacker.recipes/ad/movement/dacl/readgmsapassword" target="_blank">ReadGMSAPassword</a> site.

It turned out that the password blob is stored in **msDS-ManagedPassword** attribute of the gMSA account.
However, running the command as a Domain Admin didn't return the password:
{{< highlight powershell >}}
# Get gmsaADFS account:
Get-ADServiceAccount -Identity gmsaADFS -Properties "msDS-ManagedPassword"
{{< /highlight>}}

```
DistinguishedName    : CN=gmsaADFS,CN=Managed Service Accounts,DC=aadinternals,DC=com
Enabled              : True
Name                 : gmsaADFS
ObjectClass          : msDS-GroupManagedServiceAccount
ObjectGUID           : b3a4f131-bb4f-4bf4-9e54-3d54b285620b
SamAccountName       : gmsaADFS$
SID                  : S-1-5-21-2918793985-2280761178-2512057791-2103
UserPrincipalName    : 
```

Googling around took me to **Sean Metcalf**'s blog <a href="https://adsecurity.org/?p=4367" target="_blank">Attacking Active Directory Group Managed Service Accounts (GMSAs)</a>.

It turned out that only those principals who are listed in **PrincipalsAllowedToRetrieveManagedPassword** property of the gMSA can retrieve the password.
So the next step was to find out who those principals are:

{{< highlight powershell >}}
# Get principals allowed to get gmsaADFS account password:
Get-ADServiceAccount -Identity gmsaADFS -Properties "PrincipalsAllowedToRetrieveManagedPassword" | Select PrincipalsAllowedToRetrieveManagedPassword
{{< /highlight>}}

```
PrincipalsAllowedToRetrieveManagedPassword   
------------------------------------------   
{CN=ADFS,CN=Computers,DC=aadinternals,DC=com}
```
Quick query to AD showed that the principal in question is the computer account of AD FS server:
{{< highlight powershell >}}
# Get AD object for the ADFS principal
Get-ADObject -Identity "CN=ADFS,CN=Computers,DC=aadinternals,DC=com"
{{< /highlight>}}

```
DistinguishedName                           Name ObjectClass ObjectGUID        
-----------------                           ---- ----------- ----------        
CN=ADFS,CN=Computers,DC=aadinternals,DC=com ADFS computer    bb5a6e8a-2956-4...
```

To get the system permissions, I launched the PowerShell as a system using **Sysinternals**' <a href="https://docs.microsoft.com/en-us/sysinternals/downloads/psexec" target="_blank">PsExec</a>:
```
psexec -sid powershell.exe
```

Now I was able to access the password blob!

{{< highlight powershell >}}
# Get gmsaADFS account password:
Get-ADServiceAccount -Identity gmsaADFS -Properties "msDS-ManagedPassword"
{{< /highlight>}}

{{< highlight text "hl_lines=3" >}}
DistinguishedName    : CN=gmsaADFS,CN=Managed Service Accounts,DC=aadinternals,DC=com
Enabled              : True
msDS-ManagedPassword : {1, 0, 0, 0...}
Name                 : gmsaADFS
ObjectClass          : msDS-GroupManagedServiceAccount
ObjectGUID           : b3a4f131-bb4f-4bf4-9e54-3d54b285620b
SamAccountName       : gmsaADFS$
SID                  : S-1-5-21-2918793985-2280761178-2512057791-2103
UserPrincipalName    : 
{{< /highlight>}}

Next step was to figure out what to do with the password blob. 
Both blogs I mentioned earlier used **Michael Grafnetter**'s excellent <a href="https://github.com/MichaelGrafnetter/DSInternals" target="_blank">DSInternals</a> tool for this.

DSInternals includes a command <a href="https://github.com/MichaelGrafnetter/DSInternals/blob/master/Documentation/PowerShell/ConvertFrom-ADManagedPasswordBlob.md" target="_blank">ConvertFrom-ADManagedPasswordBlob</a>
which is able to parse the password blob.

{{< highlight powershell >}}
# Get gmsaADFS account:
$gmsa = Get-ADServiceAccount -Identity "gmsaADFS" -Properties "msDS-ManagedPassword"

# Parse blob
ConvertFrom-ADManagedPasswordBlob -Blob $gmsa.'msDS-ManagedPassword'
{{< /highlight>}}

```
Version                   : 1
CurrentPassword           : 逻ᄚꃙ﬚銒樶ﯮꖘﶴᓑ㾁驭屓ᨨ鍛뢍웾䨻汪ᇑ㜽ⱱ띵ꗯ멮큢㽓碖橔△䌙赧ᴣꆂⲃ욌᎟ℼ呺숒蓠⭉ﶎ胭軇...
SecureCurrentPassword     : System.Security.SecureString
PreviousPassword          : 
SecurePreviousPassword    : 
QueryPasswordInterval     : 19.16:27:51.4782824
UnchangedPasswordInterval : 19.16:22:51.4782824
```

# Getting gMSA password from local computer

As I mentioned earlier, if a computer needs to run a service as gMSA, it needs the password. 
The computer can fetch the password from AD, but what if the AD is unavailable?

The service must be able to start without contacting the domain controller, so the password must be stored locally somewhere..

## Password location
In one of my previous blogs on <a href="/post/adsync/" target="_blank">ADSync passwords</a>, I noticed that 
service account passwords were stored in registry at:
```
HKLM:\SECURITY\Policy\Secrets
```

Quick visit to registry reveleaded that LSASS stores also gMSA account passwords in the registry.

![gmsa in registry](/images/posts/gmsa_03.png)

As such, I was able dump the passwords with <a href="/aadinternals/" target="_blank">AADInternals</a> (requires local admin rights):

{{< highlight powershell >}}
# Get LSA secrets:
Get-AADIntLSASecrets | Where Name -Like "_SC_GMSA_{*"
{{< /highlight>}}

```
Name        : _SC_GMSA_{84A78B8C-56EE-465b-8496-FFB35A1B52A7}_cda3685b92675ebbe3d56f9bc852aef55f6bee660447c19f4864486b112a50ad
Password    : {1, 0, 0, 0...}
PasswordHex : 01000000220100001000000012011a013b901a11d9a01[redacted]
PasswordTxt :  Ģ  ĒĚ逻ᄚꃙ﬚銒樶ﯮꖘﶴᓑ㾁驭屓ᨨ鍛뢍웾䨻汪ᇑ㜽ⱱ띵ꗯ멮큢㽓[redacted]
MD4         : {249, 119, 202, 116...}
SHA1        : {247, 92, 241, 94...}
MD4Txt      : f977ca74a5e7640ae65[redacted]
SHA1Txt     : f75cf15efd029b7bfb7[redacted]
```

Could this password actually be the same blob that is stored to AD? Let's find out!

{{< highlight powershell >}}
# Get gmsaADFS account password:
$gmsa2 = Get-AADIntLSASecrets | Where Name -Like "_SC_GMSA_{*")

# Parse blob
ConvertFrom-ADManagedPasswordBlob -Blob $gmsa2.Password
{{< /highlight>}}

Unfortunately, I got an error message related to blob length.

```
ConvertFrom-ADManagedPasswordBlob : The length of the input is unexpected.
Parameter name: blob
Actual value was 304.
At line:1 char:1
+ ConvertFrom-ADManagedPasswordBlob -Blob $gmsa2.Password
+ ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    + CategoryInfo          : NotSpecified: (:) [ConvertFrom-ADManagedPasswordBlob], ArgumentOutOfRangeException
    + FullyQualifiedErrorId : System.ArgumentOutOfRangeException,DSInternals.PowerShell.Commands.ConvertFromADManagedPasswordBlobCommand
```

Luckily, comparison of the blobs revealed that the LSASS blob had the same content but also zero padding at the end 😊

![gmsa comparison](/images/posts/gmsa_04.png)

Another try with the truncated blob confirmed that the content of the blobs are indeed identical:

{{< highlight powershell >}}
# Parse blob
ConvertFrom-ADManagedPasswordBlob -Blob $gmsa2.Password[0..289]
{{< /highlight>}}

```
Version                   : 1
CurrentPassword           : 逻ᄚꃙ﬚銒樶ﯮꖘﶴᓑ㾁驭屓[redacted]
SecureCurrentPassword     : System.Security.SecureString
PreviousPassword          : 
SecurePreviousPassword    : 
QueryPasswordInterval     : 21.11:39:16.0895943
UnchangedPasswordInterval : 21.11:34:16.0895943
```

## Locating the correct password

If you're running just one service using gMSA, locating the password is easy. 
But what about if you have multiple services using gMSAs, which of the secrets is correct?

![which gmsa](/images/posts/gmsa_05.png)

Cracking this secret took a while, so bear with me 🙏

First, it seems that the all gMSA account names start with the same prefix:
```
_SC_GMSA_{84A78B8C-56EE-465b-8496-FFB35A1B52A7}_
```
Googling the **84A78B8C-56EE-465b-8496-FFB35A1B52A7** GUID brought me to another great blog post: <a href="https://www.1e.com/news-insights/blogs/accounts-part-2/" target="_blank">Accounts Everywhere, part 2: Managed Service Accounts and Group Managed Service Accounts</a> by **Andrew Mayo**.

Unfortunately, he stated the same than I had already noticed:

> Note, however, that the NAME of the gMSA (unlike the MSA) doesn’t appear to be stored in plaintext in the secret. It is, presumably, recoverable – however, I don’t have information on how to do so currently. This – in theory – makes it a little more difficult for an attacker, since unlike an MSA, where the account name is clearly part of the local secret key, you don’t have that information here.

But now that we know the gMSA account prefix is constant, I had something to start with.

I decided to find out how Windows locates the correct gMSA password when starting the service.

I started this journey by running Sysinternals' <a href="https://docs.microsoft.com/en-us/sysinternals/downloads/strings" target="_blank">Strings</a> against all dll files under **System32**:
```
strings -n 20  c:\windows\system32\*.dll > strings.txt
```
Only hit was in **netlogon.dll**. There was also an interesting function named **NetpGetSecretName** which I decided to study further!

![which gmsa](/images/posts/gmsa_06.png)

### Studying NetpGetSecretName

So, time to open <a href="https://ghidra-sre.org/" target="_blank">Ghidra</a> and start to work! First, I located the function in question by searching the gMSA prefix and started to rename parameters and functions
as I learned how the function worked.

![NetpGetServiceSecretName](/images/posts/gmsa_07.png)

The function takes three parameters:

Type 		| Name 			| Description
---  		| ---  			| ---
int  		| type 			| The type of the secret. <br>0: GMSA DPAPI <br>1: GMSA
wchar_t * 	| AccountName 	| The name of the service account.
wchar_t * 	| DomainName 	| The domain of the service account.
wchar_t ** 	| NameOutput 	| The target buffer containing the service secret name.

1: The prefix is chosen based on the type:
![NetpGetServiceSecretName](/images/posts/gmsa_08.png)

2: The domain name and account name are concatenated without any delimiters.

3: The concatenated name is made upper case.

![NetpGetServiceSecretName](/images/posts/gmsa_09.png)

Then to the beef! 

4: A new SHA256 has object is created.

5: The upper case concatenated account name **pbInput** is send to the hash object. (Ghidra did not decompile the file correctly, so some variable assignments etc. seem to be missing.)

6: The hash is finalized and saved the **pbOutput**.

![NetpGetServiceSecretName](/images/posts/gmsa_10.png)

7: There is an interesting do-while loop that seems to creating a hex string from the hash. 
However, high and low bits of each byte are switched..

Normal bytes to hex:
```
dc3a86b52976e5bb3e5df6b98c25ea5ff5b6ee6640741cf9844684b611a205da
```
NetpGetServiceSecretName's bytes to hex:
```
cda3685b92675ebbe3d56f9bc852aef55f6bee660447c19f4864486b112a50ad
```

8: The SHA256 has is appended to the prefix

![NetpGetServiceSecretName](/images/posts/gmsa_11.png)

### Implementing NetpGetSecretName

Now that I knew how the gMSA name was derived, I was ready to implement it in PowerShell!

{{< highlight powershell >}}
# Create the SHA256 object
$sha256 = [System.Security.Cryptography.SHA256]::Create()

# Convert to upper case and calculate the hash
$hash = $sha256.ComputeHash([text.encoding]::unicode.GetBytes("AADINTERNALSgmsaADFS".ToUpper()))

# Create the hex string
$hexLetters = "0123456789abcdef"
$strHash=""
$pos = 0
do{
    
    $strHash += $hexLetters[($hash[$pos] -band 0xf)]
    $strHash += $hexLetters[($hash[$pos] -shr 4)]
    $pos+=1
}while($pos -lt 0x20)

# Print the result
$strHash
{{< /highlight>}}

Unfortunately, the output was what I was expecting:

```
6c070a1a97baba5ae7e20e1c3911b560bd9f2813c1b49ad7e2188ba33c648b62
```

I assumed that there was something different with the implementation of SHA256 between PowerShell and BCrypt.dll that the netlogon.dll was using.

So, I implement a C# console program that used native BCrypt.dll methods directly.

{{< highlight csharp >}}
static void Main(string[] args)
{
	byte[] data = System.Text.Encoding.Unicode.GetBytes("AADINTERNALSgmsaADFS".ToUpper());
	IntPtr phAlgorithm = IntPtr.Zero;
	IntPtr phHash = IntPtr.Zero;
	byte[] hash = new byte[0x20];
	uint status;
	if ((status = BCryptOpenAlgorithmProvider(out phAlgorithm, "SHA256", null, 0)) == 0)
	{
		Console.WriteLine("Algorithm 0x{0:X8}", phAlgorithm.ToInt64());
		byte[] pbHashObject = new byte[0x20];

		if ((status = BCryptCreateHash(phAlgorithm, out phHash, null, 0, null, 0, 0)) == 0)
		{
			Console.WriteLine("Hash 0x{0:X8}", phHash.ToInt64());
			if ((status = BCryptHashData(phHash,data,(uint)data.Length,0)) == 0)
			{
				if((status = BCryptFinishHash(phHash, hash, 0x20,0)) == 0)
				{
					Console.WriteLine("{0}", BitConverter.ToString(hash).Replace("-", "").ToLower());
				}
			}
			BCryptDestroyHash(phHash);
		}
		BCryptCloseAlgorithmProvider(phAlgorithm, 0);
	}
	Console.WriteLine("Last error 0x{0:X8}, status 0x{0:X8}", Marshal.GetLastWin32Error(), status);
	Console.ReadKey();
}
{{< /highlight>}}

Still no luck (output bytes are not reversed, but we can see the hash is incorrect):

![NetpGetServiceSecretName](/images/posts/gmsa_12.png)

### Studying NetpGetSecretName - part 2

I spent a lot of time trying to figure out what was wrong.
I even installed <a href="https://github.com/x64dbg/x64dbg" target="_blank">x64dbg</a> for the first time of my life 😬

So, I attached the debugger to **lsass.exe**, searched the correct call to **BCryptFinishHash**, and set the breakpoint.

Running the following PowerShell command will hit the **NetpGetSecretName** function.
{{< highlight powershell >}}
Install-ADServiceAccount gmsaADFS
{{< /highlight>}}

The (non reversed) output hash was correct! 

![NetpGetServiceSecretName](/images/posts/gmsa_13.png)

At this point, it took a lot of time to make sure the hashing was implemented correctly - as it was.

If the implementation was correct, then the problem had to be somewhere else. 

While reviewing the code once again, I noticed that the **SHA256** hash algorithm was not initialized in **NetpGetSecretName** function. 
So, it must have been initialized somewhere else.

![NetpGetServiceSecretName](/images/posts/gmsa_14.png)

With Ghidra, it was quite easy to find the correct function where the **SHA256** was initialized: **NlInitializeCNG**

![NetpGetServiceSecretName](/images/posts/gmsa_15.png)

After reviewing the code time after time after time, I finally spotted the only difference! 

The **NlInitializeCNG** function provided a flag (8 = **BCRYPT_ALG_HANDLE_HMAC_FLAG**) to **BCryptOpenAlgorithmProvider** function which my code did not.
According to the <a href="https://docs.microsoft.com/en-us/windows/win32/api/bcrypt/nf-bcrypt-bcryptopenalgorithmprovider" target="_blank">documentation</a>:

Value 						| Meaning
--- 						| ---
BCRYPT_ALG_HANDLE_HMAC_FLAG | The provider will perform the Hash-Based Message Authentication Code (HMAC) algorithm with the specified hash algorithm. This flag is only used by hash algorithm providers.

I included the BCRYPT_ALG_HANDLE_HMAC_FLAG flag to the **BCryptOpenAlgorithmProvider** call: 

![NetpGetServiceSecretName](/images/posts/gmsa_17.png)

And now the (non-reversed) output hash was correct!

![NetpGetServiceSecretName](/images/posts/gmsa_16.png)

So, Microsoft initializes the SHA256 as HMAC, but does not provide HMAC key (i.e. password) when calling **BCryptCreateHash** function 🤷‍♂️

# AADInternals

Based on what I learned about gMSAs, I was able to implement new and update existing gMSA related functionality of **AADInternals**. 

Here's a sneak peek what to expect:

![AADInternals](/images/posts/gmsa_18.png)

The new gMSA functionality will be included in the next version. I'll update the blog with details after it's released (hopefully soon)!

# Summary

* The password of gMSA account can be retrieved from AD by principals listed in **PrincipalsAllowedToRetrieveManagedPassword** property of the gMSA.
* The password is also stored in the registry at **HKLM:\SECURITY\Policy\Secrets**
* Microsoft is using **HMAC** with **SHA256** hash function (incorrectly without password?) to derive the gMSA secret name from the gMSA account name.
* Local Administrator can extract plaintext passwords of gMSA accounts.

# References / credits
* Microsoft: <a href="https://docs.microsoft.com/en-us/windows-server/security/group-managed-service-accounts/group-managed-service-accounts-overview" target="_blank">Group Managed Service Accounts Overview</a>
* Microsoft: <a href="https://docs.microsoft.com/en-us/windows-server/security/group-managed-service-accounts/getting-started-with-group-managed-service-accounts" target="_blank">Getting Started with Group Managed Service Accounts</a>
* Microsoft: <a href="https://docs.microsoft.com/en-us/windows-server/identity/active-directory-federation-services" target="_blank">Active Directory Federation Services</a>
* The Hacker Recipes: <a href="https://www.thehacker.recipes/ad/movement/dacl/readgmsapassword" target="_blank">ReadGMSAPassword</a>
* Sean Metcalf: <a href="https://adsecurity.org/?p=4367" target="_blank">Attacking Active Directory Group Managed Service Accounts (GMSAs)</a>.
* Sysinternals: <a href="https://docs.microsoft.com/en-us/sysinternals/downloads/psexec" target="_blank">PsExec</a>
* Michael Grafnetter: DSInternals <a href="https://github.com/MichaelGrafnetter/DSInternals/blob/master/Documentation/PowerShell/ConvertFrom-ADManagedPasswordBlob.md" target="_blank">ConvertFrom-ADManagedPasswordBlob</a>.
* Andrew Mayo: <a href="https://www.1e.com/news-insights/blogs/accounts-part-2/" target="_blank">Accounts Everywhere, part 2: Managed Service Accounts and Group Managed Service Accounts</a>.
* Sysinternals: <a href="https://docs.microsoft.com/en-us/sysinternals/downloads/strings" target="_blank">Strings</a>
* NSA: <a href="https://ghidra-sre.org/" target="_blank">Ghidra</a>
* Microsoft: <a href="https://docs.microsoft.com/en-us/windows/win32/api/bcrypt/nf-bcrypt-bcryptopenalgorithmprovider" target="_blank">BCryptOpenAlgorithmProvider function (bcrypt.h)</a>