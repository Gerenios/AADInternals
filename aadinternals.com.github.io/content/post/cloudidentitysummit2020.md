+++
title = "AADInternals Cloud Identity Summit 2020 edition"
date = "2020-10-19"
lastmod = "2020-10-19"
categories =["blog"]
tags = ["Azure","security","phishing"]
thumbnail = "/images/posts/AADInt_CloudIdentitySummit2020.png"
+++

The new AADInternals release v0.4.4 **AADInternals Cloud Identity Summit 2020 edition** is now released! Read on to see the list of updates and new features.


<!--more-->

# AADInternals Cloud Identity Summit 2020 edition

AADInternals v0.4.4 has some updates as well as new features. Some of the new features will be introduced at <a href="https://www.identitysummit.cloud/" target="_blank">Cloud Identity Summit 2020</a>.

![Cloud Identity Summit 020](/images/posts/CloudIdentitySummit2020.png)

## Updates

* Added device code authentication support for <a href="/aadinternals/#playing-with-access-tokens" target="_blank">Get-AccessTokenFor*</a> functions.
* Added **-GetNonce** switch to <a href="/aadinternals/#new-aadintuserprttoken" target="_blank">New-AADIntUserPRTToken</a> function.

## New features

* Added <a href="/aadinternals/#invoke-aadintphishing" target="_blank">Invoke-AADIntPhishing</a> function for sending phishing messages (email/teams) utilising device code authentication token.
* Added <a href="/aadinternals/#teams-functions" target="_blank">Teams functionality</a> for setting Teams status and message, and for sending, listing, editing, and deleting Teams messages.
