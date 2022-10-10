+++
title = "Abusing Teams client protocol to bypass Teams security policies"
date = "2020-10-27"
lastmod = "2020-10-29"
categories =["blog"]
tags = ["security","Teams"]
thumbnail = "/images/posts/teams-policies.png"
+++

Administrators can use teams policies for controlling what users can do in Microsoft Teams. 

In this blog, I'll show that these policies are applied only in client and thus can be easily bypassed. 


<!--more-->

# What are Teams policies?

Policies are used in Microsoft Office 365 and Azure AD for securing access to services and data. Besides the <a href="https://docs.microsoft.com/en-us/microsoft-365/security/office-365-security/identity-access-policies?view=o365-worldwide" target="_blank">common identity and device access policies</a>,
Microsoft has provided a set of <a href="https://docs.microsoft.com/en-us/microsoft-365/security/office-365-security/teams-access-policies?view=o365-worldwide" target="_blank">Teams specific policies</a>:

* Teams and channel policies
* Messaging policies
* Meeting policies
* App permission policies

For example, administrators can configure Teams so that external users are not able to edit or delete any messages they've sent. Or, an owner of a Teams site can disable message editing for members of a certain channel.

# Bypassing Teams policies

## Initial discovery

While I was working with the previous version (v0.4.4) of <a href="/aadinternals" target="_blank">AADInternals</a> Teams functions I noticed an interesting thing: I was able to edit and delete chat messages using AADInternals as a guest
even when it was not allowed. 

This led to a question that **what if the policies are applied only at the client end?** In practice this would mean that the Teams service tells to your Teams client that "Though shall not edit messages!" but the client
could still do so.

## Observing Teams client behaviour

I started by watching what was going on between the client and cloud when the Teams client started. The first observation was that the client made about 120 http requests to the cloud.
While browsing through those requests, I spotted one that caught my interest (headers stripped):
```
POST https://teams.microsoft.com/api/mt/part/emea-02/beta/users/useraggregatesettings HTTP/1.1

{
    "tenantSettingsV2": true,
    "userResourcesSettings": true,
    "messagingPolicy": true,
    "clientSettings": true,
    "targetingPolicy": true,
    "tenantSiteUrl": true,
    "userPropertiesSettings": true,
    "callingPolicy": true,
    "meetingPolicy": true,
    "educationAssignmentsAppPolicy": true
}
```
The response contained all the settings and policies the Teams client is allowed to do as the logged in user. Below can be seen the **messagingPolicy** section:
{{< highlight json >}}

"messagingPolicy": {
	"value": {
		"allowUserEditMessage": true,
		"allowUserDeleteMessage": true,
		"allowUserChat": true,
		"allowGiphy": true,
		"giphyRatingType": "Moderate",
		"allowGiphyDisplay": true,
		"allowPasteInternetImage": true,
		"allowMemes": true,
		"allowStickers": true,
		"allowUserTranslation": true,
		"allowUrlPreviews": true,
		"readReceiptsEnabledType": "UserPreference",
		"allowImmersiveReader": true,
		"allowPriorityMessages": true,
		"audioMessageEnabledType": "ChatsAndChannels",
		"channelsInChatListEnabledType": "DisabledUserOverride",
		"allowRemoveUser": true,
		"allowSmartReply": true
	}
}
{{< /highlight>}}

What we can learn here is that the Teams client asks from the cloud what the current user is allowed to do, which was the expected behaviour.

## Testing in action

Next I decided to try whether I could lie to Teams client:

1. I saved the response from above to be used as a baseline.

2. I created a new Messaging policy to disable editing and deleting of sent messages.<br><br>
I applied the policy to a single demo user:<br><br>
![Custom policy](/images/posts/teams-policies1.png)
<br><br>Now I had two policies, the default organisation wide and the restricted one for demo user:<br><br>
![Policies](/images/posts/teams-policies2.png)

3. I restarted the Teams client and noticed that the editing and deleting were correctly disabled (didn't exists).

4. I compared the returned policies from the **useraggregatesettings** requests<br>
and as we can see, the request was missing two lines:<br><br>
![Policy comparison](/images/posts/teams-policies3.png)

5. I closed the client and configured Fiddler to do an autoresponse using the saved http response from above:<br><br>
![Fiddler autoresponse](/images/posts/teams-policies4.png)
<br><br>
Now, when the client is requesting the settings file, it will be served the one that allows editing and deleting.

6. I started the Teams client and **the editing and deleting were again allowed** and I was able to edit and delete (my own) messages!


What we can lean here is that **we can lie to Teams client** and change its behaviour :joy: <br>
Moreover, we learnt that **Teams policies are applied only on the client** :man_facepalming:

Here is the video demonstrating this with **AADInternals** and **Fiddler** (sorry for the bad audio after 03:20):

<iframe width="560" height="315" src="https://www.youtube.com/embed/Zcqig-OyUMY" frameborder="0" allow="accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture" allowfullscreen></iframe>
<br><br>

Below is a video that shows in action that this works also with **cloud file storage restrictions**:<br>

<iframe width="560" height="315" src="https://www.youtube.com/embed/a32TkLIBwS4" frameborder="0" allow="accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture" allowfullscreen></iframe>
<br>**Note:** Although not seen on the video, I was able to add my Google Drive account to Teams so this is not just a UI thing.

# Detecting and protecting

As far as I know, the "uncompliant" Teams client behaviour can not be detected. 

Same verdict with protecting. Well, one could try to use Conditional Access (CA) with device ownership and compliance restrictions, but that doesn't cover all scenarios.

# Summary

Our little test here proves that **Teams policies are applied ONLY on the client!**. 
 
If the user (or guest) is utilising Teams APIs directly, using for instance AADInternals <a href="/aadinternals/#teams-functions" target="_blank">Teams functionality</a>, he or she can bypass the restrictions set by the policies.
However, this is not a bug or vulnerability as such, but a (very very bad) design choice by Microsoft.

Users can do at least the following:

* Bypass messaging policies
* Bypass cloud file storage restrictions
* Bypass meetings policies

:warning: **Teams policies are NOT a security measure and organisations should not rely on them!** :warning: 

# References:

* Microsoft: <a href="https://docs.microsoft.com/en-us/microsoft-365/security/office-365-security/identity-access-policies?view=o365-worldwide" target="_blank">Common identity and device access policies</a>
* Microsoft: <a href="https://docs.microsoft.com/en-us/microsoft-365/security/office-365-security/teams-access-policies?view=o365-worldwide" target="_blank">Policy recommendations for securing Teams chats, groups, and files</a>

