+++
title = "Tools"
date = "2017-11-08"
lastmod = "2021-02-09"
menu = "main"
tags = ["Office365"]
categories = ""
description = "Office 365 tools"
+++

This page has some tools to make your life as an Office 365 administrator easier
 <!--more-->



# Converters
   
## GUID to ImmutableID 

 Enter the GUID below and hit the button to convert it to ImmutableID
 <input type="text" name="guid" id="fldGuid" placeholder="12345678-9abc-4def-0123-456789abcdef"><input type="button" onClick="guidToB64()" Value="Convert to ImmutableID">
 
 <div>
 Base 64<br>
 <input type="text" name="base64" id="resBase64" readonly>
 </div>
 
 <div id="guidToB64Error" style="display:none;margin: 10px 0px; padding:12px;color: #D8000C; background-color: #FFD2D2;">
 This is hidden
  </div>
  
## ImmutableID to GUID

 Enter the ImmutableID below and hit the button to convert it to GUID
 <input type="text" name="guid" id="fldImmutableId" placeholder="eFY0Erya700BI0VniavN7w=="><input type="button" onClick="b64ToGuid()" Value="Convert to GUID">
 
 <div>
 GUID<br>
 <input type="text" name="GUID" id="resGuid" readonly>
 </div>
 
 <div id="b64ToGuidError" style="display:none;margin: 10px 0px; padding:12px;color: #D8000C; background-color: #FFD2D2;">
 This is hidden
  </div>
  
# AADInternals backdoor token creator
https://<a href="https://aadinternalsbackdoor.azurewebsites.net" target="_blank">aadinternalsbackdoor.azurewebsites.net</a>
