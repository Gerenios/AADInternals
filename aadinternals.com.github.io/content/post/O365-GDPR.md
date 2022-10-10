+++
title = "Is my Office 365 GDPR compliant?"
date = "2018-04-25"
lastmod = "2021-09-10"
categories =["blog"]
tags = ["Office 365","GDPR","Security"]
thumbnail = "/images/posts/O365-GDPR.png"
+++

In short, no it's not. In this blog, I’ll tell you three reasons why.

<!--more-->

First, I would like to clarify that I do believe that the <a href="https://www.microsoft.com/en-us/TrustCenter/CloudServices/office365/GDPR" target="_blank">Office 365 and Azure Active Directory platforms are GDPR compliant</a>.
However, your Office 365 tenant is not.


# PowerShell
Previously, Microsoft has stated that the MsOnline and AzureAD PowerShell modules require administrative rights. Currently, they <a href="https://docs.microsoft.com/en-us/office365/enterprise/powershell/connect-to-office-365-powershell" target="_blank">state</a> that they are **intended for admins**, which is more truthful. However, what is not told is that **any Office 365 user can connect to AAD with PowerShell**. 

So, what’s the big deal? Well, accessing AAD with PowerShell gives you read-only access to AAD. This means that you can for instance export all users to an XML file or list all administrators:

{{< highlight powershell >}}
# Connect to Azure Ad
Connect-MsolService

# Export all AAD users to xml file
Get-MsolUser | Export-Clixml -Path users.xml

# Get the role id of Global Administrators
$roleid=Get-MsolRole -RoleName "Company Administrator"

# List all Global Administrators
Get-MsolRoleMember -RoleObjectId $roleid.ObjectId
{{< /highlight>}}
(to install MsOnline module, see <a href="../ps-module" target="_blank">this</a>)

<strike>Currently, there is no way to prevent regular users to use PowerShell to access AAD.</strike></br>
**EDIT:** To blog regular users access to PowerShell, see my <a href="/post/limit-user-access/" target="_blank">blog post</a>.

# Delegated Administration
Besides the normal admin rights, Microsoft partners can give their users <a href="https://support.office.com/en-us/article/about-office-365-admin-roles-da585eea-f576-4f55-a1e0-87090b6aaa9d" target="_blank">delegated admin</a> role. There are two admin roles: full administration and limited administrations. These are, respectively, equivalent to global admin and password admin roles. 

So, when a delegated partner offer is accepted by customer’s global admin, partner organisation’s users having delegated admin roles have access to customer's tenant. The problem is that customer organisation can see that there is a delegated admin contract, but they do not know who actually has those delegated admin roles. Thus, customers have no way to know who has the global admin level rights to their tenant.

Therefore I **strongly** suggest removing any delegated admin partner contracts immediately. It is more secure to create separate admin accounts for partners to your tenant.

# Identity federation

As I announced last year in my <a href="../federation-vulnerability" target="_blank">blog post</a>, there is a serious implementation flaw in AAD identity federation. In short, the flaw allows rogue administrators to impersonate any user in their Office 365. This includes external users and users having the initial **onmicrosoft.com** domain name.

Currently, there is no way to prevent this either. However, I strongly suggest removing any unnecessary global admin rights to minimize the risk of exploitation.

# Summary

GDPR sets many requirements for organisations regarding handling personal data. For instance, organisations need to be aware of WHO is processing personal data and HOW it is processed.
Regular users' PowerShell access, delegated administration, and the identity federation prevents organisations to be GDPR compliant. And, unfortunately, only the delegated administration can be mitigated.

# Acknowledgements

This blog is based on a research paper I co-authored with <a href="https://www.linkedin.com/in/t3554v/" target="_blank">Tessa Viitanen</a>. Original research paper available <a href="http://www.scitepress.org/PublicationsDetail.aspx?ID=ei1ohESemLk=" target="_blank">here</a> (requires registration).

All the mentioned issues have been reported to Microsoft in November 2017.