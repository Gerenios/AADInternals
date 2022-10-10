+++
title = "Chasing the Unicorn: PowerShell module for 'The Secret Office 365 Forensics Tool'"
date = "2018-07-02"
lastmod = "2018-07-13"
categories =["blog"]
tags = ["Office 365","Security","Exchange","Forensics","Logs"]
thumbnail = "/images/posts/EXOMailActivity.png"
+++

In June 2018 the existence of secret Office 365 forensics tool was confirmed.
The tool refers to Microsoft's undocumented Exchange Online Activities API. 
The API provides access to a granular mail activity events for up to six months old data!

To provide administrators with easy access to the API, I created a PowerShell module (EXOMailActivity). 
In this blog, I'll show you how to use the module to get access to mail activity data.

<!--more-->

# What is this "secret forensics tool"?

Apparently there have been rumours of the tool for some time now. In June 2018 the Anonymous revealed the existence of the 
tool as reported by <a href="http://lmgsecurity.com/exposing-the-secret-office-365-forensics-tool/" target="_blank">Sherri Davidoff from LMG security</a>.

In practice, the "tool" is an undocumented Exchange Online Activity API. For clarification: it is **NOT an Office 365 forensics tool**, but an Exchange Online forensics tool.

Anyways, the revealed Activity API provides access to granular mail activity data for up to six months old data!

<span style="color:red">**EDIT: In July 3rd the API seems to be banned by Microsoft. Calling the API will return a HTTP error: 403 Forbidden.**</span>

# EXOMailActivity PowerShell module
Immediately after discovering the news about the Activity API I researched it carefully. Thanks to research done by 
<a href="https://www.crowdstrike.com/blog/hiding-in-plain-sight-using-the-office-365-activities-api-to-investigate-business-email-compromises/" target="_blank">CrowdStrike</a>, 
it was easy to pull up a proof-of-concept using PowerShell. 

To make the API easily accessible for administrators, I decided to create a PowerShell module called EXOMailActivity

## Installing EXOMailActivity

The module is available at <a href="https://github.com/Gerenios/EXOMailActivity" target="_blank">GitHub</a>.

The easiest way to use the module is to add it to a directory from where PowerShell can find it.
{{< highlight powershell >}}
# List PowerShell module paths
$env:PSModulePath -split ";"
{{< /highlight>}}
This returns a list of PowerShell module directories:
```
C:\Users\MyUser\Documents\WindowsPowerShell\Modules
C:\Program Files\WindowsPowerShell\Modules
C:\WINDOWS\system32\WindowsPowerShell\v1.0\Modules
C:\Program Files\SharePoint Online Management Shell\
C:\Program Files\WindowsPowerShell\Modules\
```
Change the current directory to one those directories and get the module from GitHub
{{< highlight powershell >}}
git clone https://github.com/Gerenios/EXOMailActivity
{{< /highlight>}}

## Using EXOMailActivity

There are two cmdlets in the module; **Get-MailActivity** and **Get-MailActivityDetails**

**Note!** To get the activity data, you need credentials having FullAccess to target user's mailbox.

In the following, we get the first 500 mail activities of the user from the previous 30 days.
{{< highlight powershell >}}
# Save credentials to a variable
$cred=Get-Credential

# Get activity data
Get-MailActivity -Credential $cred -User "user@example.com"
{{< /highlight>}}
The output contains activity data entries similar to this:
```
@odata.id            : https://outlook.office365.com/api/v1.0/Users('user@example.com')/Activities('AAMkAGRmZTg4NTMwLWFkMzUtNDIwZC1iY2JkLTliZTc1N2ZiNDJlOABGAAAAAADMs1bsdkG3Spbrf-DOuHSKBwC4zq7ZZymRR
                       oql8uBEAL0JAAAAAAEfAAC4zq7ZZymRRoql8uBEAL0JAAADdDKuAAA=')
@odata.etag          : W/"CQAAAA=="
Id                   : AAMkAGRmZTg4NTMwLWFkMzUtNDIwZC1iY2JkLTliZTc1N2ZiNDJlOABGAAAAAADMs1bsdkG3Spbrf-DOuHSKBwC4zq7ZZymRRoql8uBEAL0JAAAAAAEfAAC4zq7ZZymRRoql8uBEAL0JAAADdDKuAAA=
ActivityCreationTime : 2018-07-02T12:14:13.816Z
ActivityIdType       : Logon
AppIdType            : Web
ClientSessionId      : 1c6c6a80-b98b-45ef-8a4e-b874f3fe375f
ActivityItemId       : 
TimeStamp            : 2018-07-02T12:14:13.019Z
CustomProperties     : {@{Name=Layout; Value=Mouse}, @{Name=Timezone; Value=FLE Standard Time}, @{Name=IPAddress; Value=104.40.211.35}, @{Name=Browser; Value=Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleW
                       ebKit/537.36 (KHTML, like Gecko) Chrome/67.0.3396.99 Safari/537.36+Preload+Preload}...}
```

By default, the command returns 500 entries of data for previous month (~30 days). 
The timeframe can be changed using StartTime and EndTime parameters. The number of returned entries can be set using MaxResults parameter.
For "pagination", a StartFrom parameter can be used. Activity and application types can be specified using ActivityType and ApplicationType parameters, respectively.

Note! Credentials and user parameters are not required for subsequent queries.
{{< highlight powershell >}}
# Get the first 200 login activities from the beginning of 2018
Get-MailActivity -StartTime "2018-01-01" -ActivityType ServerLogon -MaxResults 200

# Get the next 200 login activities from the beginning of 2018
Get-MailActivity -StartTime "2018-01-01" -ActivityType ServerLogon -MaxResults 200 -StartFrom 200
{{< /highlight>}} 


Activity details can be queried only for email messages. Other activity types will return an error.
In the following, all delivered messages are saved to a variable and details will be queried for the first one.
{{< highlight powershell >}}
# Save mail delivery activities to a variable
$activities=Get-MailActivity -ActivityType MessageDelivered

# Get details of the delivered message
Get-MailActivityDetails -ActivityItemId $activities[0].ActivityItemId
{{< /highlight>}} 
The output contains activity detailed data similar to this:
```
@odata.context             : https://outlook.office365.com/api/v1.0/$metadata#Users('user%40example.com')/Messages(BccRecipients,BodyPreview,Categories,CcRecipients,ChangeKey,ConversationId,DateTim
                             eCreated,DateTimeLastModified,DateTimeReceived,DateTimeSent,From,HasAttachments,Id,Importance,IsDeliveryReceiptRequested,IsDraft,IsRead,IsReadReceiptRequested,ParentFolderId,Re
                             plyTo,Sender,Subject,ToRecipients,WebLink)/$entity
@odata.id                  : https://outlook.office365.com/api/v1.0/Users('user@example.com')/Messages('AQMkAGRmZTg4ADUzMC1hZDM1LTQyMGQtYmNiZC05YmU3NTdmYjQyZTgARgAAA8yzVux2QbdKlut-8M64dIoHALjOrtlnK
                             ZFGiqXy4EQAvQkAAAIBDAAAALjOrtlnKZFGiqXy4EQAvQkAAAIheQAAAA==')
@odata.etag                : W/"CQAAABYAAAC4zq7ZZymRRoql8uBEAL0JAAAAAAuz"
Id                         : AQMkAGRmZTg4ADUzMC1hZDM1LTQyMGQtYmNiZC05YmU3NTdmYjQyZTgARgAAA8yzVux2QbdKlut-8M64dIoHALjOrtlnKZFGiqXy4EQAvQkAAAIBDAAAALjOrtlnKZFGiqXy4EQAvQkAAAIheQAAAA==
DateTimeCreated            : 2018-06-26T11:19:50Z
DateTimeLastModified       : 2018-06-27T19:38:27Z
ChangeKey                  : CQAAABYAAAC4zq7ZZymRRoql8uBEAL0JAAAAAAuz
Categories                 : {}
DateTimeReceived           : 2018-06-26T11:19:50Z
DateTimeSent               : 2018-06-26T11:19:43Z
HasAttachments             : False
Subject                    : This is an email
BodyPreview                : admin demo (admin.demo@example.com) has sent you a protected message.
                             Lorem ipsum dolor
Importance                 : Normal
ParentFolderId             : AQMkAGRmZTg4ADUzMC1hZDM1LTQyMGQtYmNiZC05YmU3NTdmYjQyZTgALgAAA8yzVux2QbdKlut-8M64dIoBALjOrtlnKZFGiqXy4EQAvQkAAAIBDAAAAA==
ConversationId             : AAQkAGRmZTg4NTMwLWFkMzUtNDIwZC1iY2JkLTliZTc1N2ZiNDJlOAAQAERP2prSYs1LojG5LfI2HvA=
IsDeliveryReceiptRequested : 
IsReadReceiptRequested     : False
IsRead                     : True
IsDraft                    : False
WebLink                    : https://outlook.office365.com/owa/?ItemID=AQMkAGRmZTg4ADUzMC1hZDM1LTQyMGQtYmNiZC05YmU3NTdmYjQyZTgARgAAA8yzVux2QbdKlut%2F8M64dIoHALjOrtlnKZFGiqXy4EQAvQkAAAIBDAAAALjOrtlnKZFGiqXy
                             4EQAvQkAAAIheQAAAA%3D%3D&exvsurl=1&viewmodel=ReadMessageItem
Sender                     : @{EmailAddress=}
From                       : @{EmailAddress=}
ToRecipients               : {@{EmailAddress=}}
CcRecipients               : {}
BccRecipients              : {}
ReplyTo                    : {}
```
The message body can be included using -IncludeBody switch.