+++
title = "AAD & M365 kill chain"
date = "2020-06-14"
lastmod = "2021-02-08"
menu = "main"
categories =["article"]
tags = ["Azure Active Directory","Azure","outsider","user","guest","admin","recon","compromise","persistence"]
description = "Azure AD and Microsoft 365 kill chain"
+++

<img src="/images/posts/killchain.png" width="1920" height="1080" alt="Azure AD Kill Chain" usemap="#killchain">
<map name="killchain">
  <area coords="0,160,1920,346"  title="Outsider"      alt="Outsider"      href="/post/just-looking/">
  <area coords="0,347,1920,533"  title="Guest"         alt="Guest"         href="/post/quest_for_guest/">
  <area coords="0,534,1920,718"  title="User"          alt="User"          href="/post/insider/">
  <area coords="0,719,1920,893"  title="Admin"         alt="Admin"         href="/post/admin/">
  <area coords="0,894,1920,1080" title="On-prem admin" alt="On-prem admin" href="/post/on-prem_admin/">
</map>


<script type="text/javascript" src="/js/imageMapResizer.min.js"></script>
<script type="text/javascript">
	imageMapResize();
</script>


# Introduction
According to Verizon's <a href="http://enterprise.verizon.com/resources/reports/2020/2020-data-breach-investigations-report.pdf" target="_blank">Data Breach Investigations Report 2020</a>, externals attackers are considerable more common than internal attackers.
In the cloud era, attacking the organisation from the outside is much more difficult, if not impossible. Therefore, to be able to access organisation's data, one must gain some level of legitimate access to the organisation.

The Azure AD and Microsoft 365 kill chain is a collection of recon techniques and hacking tools I've discovered and built during the last 10+ years while working with Microsoft cloud services.

# Kill chain roles

The kill chain consists of five different roles: **outsider**, **guest**, **insider**, **admin**, and **on-prem admin**. 
Typically, outsiders are aiming for guest, insider, or admin roles. Similarly, guests are aiming for insider or admin roles. 
Insiders can already do much harm, but to get "keys to the kingdom" they often are aiming for (cloud) admin role. This is same for the on-prem admin.

<img src="/images/posts/killchain2.png" alt="Azure AD Kill Chain roles">


**Figure 1:** Azure AD Kill Chain roles and target

Attackers' ultimate goal is to get access to target tenant. The kill chain provides tools for recon to improve targeting the organisation. 
After gaining the preferred role (out-of-scope of kill chain), the kill chain provides tools for hacking the organisation.

## Outsider
Outsider refers to an user who has no access to the tenant of the target organisation.

Outsiders can exract information from any tenant using publicly available APIs and DNS queries. See the <a href="/post/just-looking/" target="_blank">blog post</a> for more details.

The ultimate goal of an outsider is to gain guest, user, or admin role.

## Guest
Guest refers to an user who has guest access (external user) to the target tenant. These users have a restricted access to Azure AD, but they can gather a lot of information from tenant using 
various APIs provided by Microsoft. For instance, guests can easily read the whole Azure Active Directory (AAD) using <a href="https://docs.microsoft.com/en-us/graph/use-the-api" target="_blank">MS Graph API</a>.

See the <a href="/post/quest_for_guest/" target="_blank">blog post</a> for more details.

## User (insider)
User refers to "normal" users of the tenant. They have read-only access to practically all information in AAD. However, users are also able to invoke Denial-of-Service (DoS) attacks against their own tenant by filling
the Azure AD with user or device objects, making it practically unusable.

See the <a href="/post/insider/" target="_blank">blog post</a> for more details.

## Admin
Admin refers to a <a href="https://docs.microsoft.com/en-us/azure/active-directory/users-groups-roles/directory-assign-admin-roles#global-administrator--company-administrator" target="_blank">Global Administrator</a> role.
Global admin has an unlimited access to all settings in the tenant. As such, they can change security settings, access any data, and create back doors.

See the <a href="/post/admin/" target="_blank">blog post</a> for more details.

## On-prem admin
On-prem admin refers to an administrator who is administering on-prem servers running <a href="https://docs.microsoft.com/en-us/azure/active-directory/hybrid/whatis-azure-ad-connect" target="_blank">Azure AD Connect</a>,
<a href="https://docs.microsoft.com/en-us/windows-server/identity/active-directory-federation-services" target="_blank">Active Directory Federation Services</a> (AD FS), or Active Directory. 

On-prem admins doesn't have direct access to the cloud, but they can dump Azure AD Connect credentials and gain admin rights to cloud. 

If organisation is using Desktop SSO (also known as <a href="https://docs.microsoft.com/en-us/azure/active-directory/hybrid/how-to-connect-sso" target="_blank">Seamless SSO</a>), on-prem admin
can dump the MD4 hash of AZUREADSSO computer account password and create Kerberos tickets to login as any user of the tenant. 

Similarly, If organisation is using identity federation, on-prem admin can export the token signing certificates and sign in as any user of the tenant and bypass MFA!

See the <a href="/post/on-prem_admin/" target="_blank">blog post</a> for more details.

# References
* 2020 Verizon <a href="http://enterprise.verizon.com/resources/reports/2020/2020-data-breach-investigations-report.pdf" target="_blank">Data Breach Investigations Report</a>
* <a href="https://docs.microsoft.com/en-us/azure/active-directory/users-groups-roles/directory-assign-admin-roles" target="_blank">Administrator role permissions in Azure Active Directory</a>
