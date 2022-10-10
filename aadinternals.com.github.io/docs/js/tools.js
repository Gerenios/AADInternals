// Copyright (c) Nestori Syynimaa 2017
function showMessage(field, value){
	var fldError = document.getElementById(field);
	fldError.style.display="inline";
	fldError.innerText=value;
}
function hideMessage(field){
	var fldError = document.getElementById(field);
	fldError.style.display="none";
	fldError.innerText="";
}
function getRealm(loginName){
	// Save the AzureAD GetUserRealm REST API url
	var searchUrl="https://login.microsoftonline.com/GetUserRealm.srf?login=" + encodeURI(loginName);
	var xhr = new XMLHttpRequest();
	xhr.onreadystatechange  = function(e){
		if (xhr.readyState == 4){
			if (xhr.status == 200) {
				showMessage("smartLinkError", "Got it!");
			} else {
				showMessage("smartLinkError", "Cannot resolve user's authentication realm from Office 365.");
			}
		}
	}
	xhr.open("GET", searchUrl, true);
	xhr.send();
}
function createSmartLink()
{
	var domain=document.getElementById("fldDomain").value;
	var smartLinkField=document.getElementById("fldSmartlink");
	getRealm("nn@"+domain);
	//smartLinkField.value=domain; 
}
function byteArrayToBase64( buffer ) {
    var binary = '';
    var bytes = new Uint8Array( buffer );
    var len = bytes.byteLength;
    for (var i = 0; i < len; i++) {
        binary += String.fromCharCode( bytes[ i ] );
    }
    return btoa( binary );
}
function parseByte(str, start)
{
	var strByte=str.substring(start,start+2);
	var byte=parseInt(strByte,16);
	return byte;
}
function parseGuid(guid){
	var bytes = [];
	// Bytes 1-4
	bytes.push(parseByte(guid,6));
	bytes.push(parseByte(guid,4));
	bytes.push(parseByte(guid,2));
	bytes.push(parseByte(guid,0));
		
	// Bytes 5-6
	bytes.push(parseByte(guid,10+1));
	bytes.push(parseByte(guid,8+1));
	
	// Bytes 7-8
	bytes.push(parseByte(guid,14+2));
	bytes.push(parseByte(guid,12+2));
		
	// Bytes 9-10 
	bytes.push(parseByte(guid,16+3));
	bytes.push(parseByte(guid,18+3));
			
	// Bytes 12-16
	for(var i = 20+4; i < 32+4 ; i+=2)
		bytes.push(parseByte(guid,i));
	return byteArrayToBase64(bytes);
}
function Base64ToByteArray( base64 ) {
	var rawData = atob( base64 );
	var bytes = [];
	for (var i = 0; i < rawData.length; i++) {
        bytes.push(rawData.charCodeAt(i));
    }
    
    return bytes; 
}
function parseHex(bytes,pos)
{
	var retVal = bytes[pos].toString(16);
	if(retVal.length==1)
		retVal="0"+retVal;
	return retVal;
}
function parseBase64(base64){
	var bytes = Base64ToByteArray(base64);
	if(bytes.length != 16)
		throw "Size != 16 bytes";
	var retVal = new String();
	
	// Bytes 1-4
	retVal+=parseHex(bytes,3);
	retVal+=parseHex(bytes,2);
	retVal+=parseHex(bytes,1);
	retVal+=parseHex(bytes,0);
	
	retVal+="-"
		
	// Bytes 5-6
	retVal+=parseHex(bytes,5);
	retVal+=parseHex(bytes,4);
	
	retVal+="-"
	
	// Bytes 7-8
	retVal+=parseHex(bytes,7);
	retVal+=parseHex(bytes,6);

	retVal+="-"	
			
	// Bytes 9-10 
	retVal+=parseHex(bytes,8);
	retVal+=parseHex(bytes,9);
	
	retVal+="-"
			
	// Bytes 12-16
	for(var i = 10; i < 16 ; i++)
		retVal+=parseHex(bytes,i);
	
	return retVal;
}
function guidToB64()
{
	// GUID regexp
	var re = new RegExp("^(([0-9]|[a-f]){8}-([0-9]|[a-f]){4}-4([0-9]|[a-f]){3}-([0-9]|[a-f]){4}-([0-9]|[a-f]){12})$");
	var guid = document.getElementById("fldGuid").value.toLowerCase();
	var returnFld = document.getElementById("resBase64");
	
	var isGuid = re.test(guid);
	if(isGuid) {
		hideMessage("guidToB64Error");
		var result=parseGuid(guid);
		returnFld.value=result;
	}
	else {
		returnFld.value="";
		showMessage("guidToB64Error","Not a GUID");
	}
}
function b64ToGuid()
{
	// Base64 regexp
	var re = new RegExp("^[a-zA-Z0-9/+]+={0,2}$");
	var base64 = document.getElementById("fldImmutableId").value;
	var returnFld = document.getElementById("resGuid");
	
	var isGuid = re.test(base64);
	if(isGuid) {
		try{
			hideMessage("b64ToGuidError");
			var result=parseBase64(base64);
			returnFld.value=result;
		}catch(err){
			returnFld.value="";
			showMessage("b64ToGuidError","Not an ImmutableID");
		}
	}
	else {
		returnFld.value="";
		showMessage("b64ToGuidError","Not an ImmutableID");
	}
}

