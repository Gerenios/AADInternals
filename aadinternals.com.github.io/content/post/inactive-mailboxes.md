+++
title = "How to preserve user's mailbox during the long leave"
date = "2018-05-29"
lastmod = "2018-05-29"
categories =["blog"]
tags = ["Office 365","Email","Inactive","Mailbox"]
thumbnail = "/images/posts/inactive-mailbox.png"
+++

Have you ever faced a situation, where a user takes a longer than 30-day leave, and you would like to 
save money spent on Office 365 licenses but still preserve user's mailbox?

In this blog, I tell you how!

<!--more-->

# What happens when you delete the user or remove user's license?

After deleting the user or removing user's license, user's mailbox will be soft-deleted. After 30 days, it will be completely removed, or hard-deleted.
If the user's license is reassigned during that 30 day period (or the user is restored), the context of the mailbox will be retained.

# How to preserve mailbox longer than 30 days?

You have two options to preserve mailbox after its deletion. You can either use <a href="https://support.office.com/fi-fi/article/overview-of-retention-policies-5e377752-700d-4870-9b6d-12bfc12d2423?ui=fi-FI&rs=fi-FI&ad=FI" target="_blank">retention policies</a>, or you can put the mailbox on a <a href="https://technet.microsoft.com/library/dn743673(v=exchg.150).aspx" target="_blank">Litigation Hold</a>.
Placing the mailbox on hold, makes it **inactive mailbox** after soft-deletion. 
Inactive mailboxes are mailboxes that are not linked to any user, and thus **not need a license**!

To place the mailbox on a hold, use the <a href="https://outlook.office365.com/ecp/" target="_blank">Exchange Online Admin Center</a> or the following Exchange Online PowerShell command:

{{< highlight powershell >}}
# Place the mailbox on a hold
Set-Mailbox "jane.doe@example.com" -LitigationHoldEnabled $true
{{< /highlight>}}

# How to restore the user's mailbox after the long leave?

Let's imagine a scenario when the user returns from a two-year leave. Let's also assume that you are syncing your users from the on-prem AD.
When user object is re-created in AD (or moved to a synced scope), it is synchronized to Office 365 AAD. You give the user a license and a new mailbox is created.

First, let's save the user's email address to a variable. For this example, we assume that his or hers email address hasn't changed.

{{< highlight powershell >}}
# Save the user's email address to a variable for later use
$email = "jane.doe@example.com"
{{< /highlight>}}

Next, you need to fetch the Exchange guid of both the old (inactive) and new mailboxes and save them in variables.

{{< highlight powershell >}}
# Fetch the Exchange guid of the inactive mailbox
$oldMailBox=(Get-Mailbox $email -InactiveMailboxOnly).ExchangeGuid.ToString()

# Fetch the Exchange guid of the active mailbox
$newMailBox=(Get-Mailbox $email).ExchangeGuid.ToString()
{{< /highlight>}}

Now you are ready to restore user's mailbox!

{{< highlight powershell >}}
# Restore the mailbox
New-MailboxRestoreRequest -SourceMailbox $oldMailBox -TargetMailbox $newMailBox -AllowLegacyDNMismatch
{{< /highlight>}}


If you have a warning about an existing archive mailbox, it can also be restored (provided that the new mailbox has the archive enabled):
{{< highlight powershell >}}
# Restore the archive
New-MailboxRestoreRequest -SourceMailbox $oldMailBox -TargetMailbox $newMailBox -TargetIsArchive -SourceIsArchive -AllowLegacyDNMismatch
{{< /highlight>}}

**Note!** Depending on the size of the mailbox, this may take a looong time...

After the restore is completed (or failed), you'll have a notification in Office 365 portal. 

You may also manually check the status of the restore process for both mailbox and archive:
{{< highlight powershell >}}
# Check the restoration status
Get-MailboxRestoreRequest -TargetMailbox $newMailBox
{{< /highlight>}}

And that's it: the mailbox is restored! 

Finally, you may take the old mailbox under the hold, and it will get hard-deleted.

{{< highlight powershell >}}
# Remove the inactive mailbox under hold
Set-Mailbox $oldMailBox -InactiveMailbox -LitigationHoldEnabled $false
{{< /highlight>}}
