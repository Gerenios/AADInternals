# This module contains functions to extract and update AADConnect sync credentials

# Oct 29th 2019
function Check-Server
{
    [cmdletbinding()]
    Param(
            [Parameter(Mandatory=$true)]
            [bool]$AsADSync,
            [Parameter(Mandatory=$true)]
            [bool]$force
    )
    process
    {
        # Check that we are on AADConnect server and that the service is running
        if($force -ne $true -and (($adSyncService = Get-Service ADSync -ErrorAction SilentlyContinue) -eq $null -or $adSyncService.Status -ne "Running"))
        {
            Write-Error "This command needs to be run on a computer with ADSync running!"
            return $false
        }

        # Add the encryption reference (should always be there)
        $ADSyncLocation = Get-ItemPropertyValue -Path "HKLM:SOFTWARE\Microsoft\AD Sync" -Name Location
        Add-Type -path "$ADSyncLocation\Bin\mcrypt.dll"

        $ADSyncUser=""
        $CurrentUser = "{0}\{1}" -f $env:USERDOMAIN,$env:USERNAME

        # Check the version number: since 1.4.xx.xx uses DPAPI instead of registry to store the keyset
        try
        {
            $serviceWMI = Get-WmiObject Win32_Service -Filter "Name='ADSync'" -ErrorAction SilentlyContinue
            $ADSyncUser=  $serviceWMI.StartName
            $ver=         ($serviceWMI.PathName.Split('"')[1] | Get-Item).VersionInfo.FileVersion
            $ver2=$ver.split('.')
            if($force -ne $true -and $ver2[0] -eq 1 -and $ver2[1] -ge 4 -and !$AsADSync)
            {
                Write-Warning "ADSync passwords can be read or modified as local administrator only for ADSync version 1.3.xx.xx!"
                Write-Warning "The current version is $ver and access to passwords requires running as ADSync ($ADSyncUser)."
                Write-Warning "Use the -AsADSync $true parameter to try again!"
                return $false
            }
        }
        catch
        {
            Write-Verbose "Could not get WMI info, probably already running as ADSync so skipping the ""elevation"""
            $AsADSync = $false
        }

        # Elevate the current thread by copying the token from ADSync service
        if($AsADSync)
        {
            # First we need to get connection once to the DB to get token. 
            # If done after "elevating" to ADSync, all SQL connections to configuration database will fail.
            $SQLclient = new-object System.Data.SqlClient.SqlConnection -ArgumentList (Get-AADConfigDbConnection)
            $SQLclient.Open()
            $SQLclient.Close()
            try
            {
                # Copy the tokens from lsass and miiserver (ADSync) processes
                Write-Verbose "Trying to ""elevate"" by copying token from lsass and then miiserver (ADSync) processes"
                $elevation = [AADInternals.Native]::copyLsassToken() -and [AADInternals.Native]::copyADSyncToken()
            }
            catch
            {
                $elevation = $false
            }

            if($elevation)
            {
                Write-Verbose """Elevation"" to ADSync succeeded!"
                Write-Warning "Running as ADSync ($ADSyncUser). You MUST restart PowerShell to restore $CurrentUser rights."
            }
            else
            {
                Write-Error "Could not change to $ADSyncUser. MUST be run as administrator!"
            }
        }
    }
}

# May 15th 2019
function Get-SyncCredentials
{
<#
    .SYNOPSIS
    Gets Azure AD Connect synchronization credentials

    .Description
    Extracts Azure Active Directory Connect crecentials from WID configuration database. MUST be run on AADConnect server
    as local administrator
  
    .Example
    Get-AADIntSyncCredentials

    Name                           Value
    ----                           -----
    ADDomain                       company.com  
    ADUser                         MSOL_4bc4a34e95fa
    ADUserPassword                 Q9@p(poz{#:kF_G)(s/Iy@8c*9(t;...
    AADUser                        Sync_SRV01_4bc4a34e95fa@company.onmicrosoft.com                                                      
    AADUserPassword                $.1%(lxZ&/kNZz[r

    .Example
    Get-AADIntSyncCredentials -AsCredentials

    UserName                                                            Password
    --------                                                            --------
    MSOL_4bc4a34e95fa                               System.Security.SecureString
    Sync_SRV01_4bc4a34e95fa@company.onmicrosoft.com System.Security.SecureString

    .Example
    $syncCreds=Get-AADIntSyncCredentials -AsCredentials
    PS C:\>$at=Get-AADIntAccessTokenForAADGraph -Credentials $syncCreds[1]
    PS C:\>Get-AADIntSyncConfiguration -AccessToken $at

    AllowedFeatures                         : {ObjectWriteback,  , PasswordWriteback}
    AnchorAttribute                         : mS-DS-ConsistencyGuid
    ApplicationVersion                      : 1651564e-7ce4-4d99-88be-0a65050d8dc3
    ClientVersion                           : 1.4.38.0
    DirSyncClientMachine                    : SERVER1
    DirSyncFeatures                         : 41016
    DisplayName                             : Company Ltd
    IsDirSyncing                            : true
    IsPasswordSyncing                       : false
    IsTrackingChanges                       : false
    MaxLinksSupportedAcrossBatchInProvision : 15000
    PreventAccidentalDeletion               : EnabledForCount
    SynchronizationInterval                 : PT30M
    TenantId                                : 57cf9f28-1ad7-40f4-bee8-d3ab9877f0a8
    TotalConnectorSpaceObjects              : 1
    TresholdCount                           : 500
    TresholdPercentage                      : 0
    UnifiedGroupContainer                   : 
    UserContainer                           : 
    DirSyncAnchorAttribute                  : mS-DS-ConsistencyGuid
    DirSyncServiceAccount                   : Sync_SERVER1_xxxxxxxxxxx@company.onmicrosoft.com
    DirectorySynchronizationStatus          : Enabled
    InitialDomain                           : company.onmicrosoft.com
    LastDirSyncTime                         : 2020-03-03T10:23:09Z
    LastPasswordSyncTime                    : 2020-03-04T10:23:43Z
#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$false)]
        [bool]$AsADSync=$true,
        [Parameter(Mandatory=$false)]
        [switch]$AsCredentials,
        [Parameter(Mandatory=$false)]
        [switch]$force
    )
    Process
    {
        # Do the checks
        if((Check-Server -AsADSync $AsADSync -force $force) -eq $false)
        {
           return
        }

        # Read the encrypt/decrypt key settings
        $SQLclient = new-object System.Data.SqlClient.SqlConnection -ArgumentList (Get-AADConfigDbConnection)
        $SQLclient.Open()
        $SQLcmd = $SQLclient.CreateCommand()
        $SQLcmd.CommandText = "SELECT keyset_id, instance_id, entropy FROM mms_server_configuration"
        $SQLreader = $SQLcmd.ExecuteReader()
        $SQLreader.Read() | Out-Null
        $key_id = $SQLreader.GetInt32(0)
        $instance_id = $SQLreader.GetGuid(1)
        $entropy = $SQLreader.GetGuid(2)
        $SQLreader.Close()

        # Read the AD configuration data
        $SQLcmd = $SQLclient.CreateCommand()
        $SQLcmd.CommandText = "SELECT private_configuration_xml, encrypted_configuration FROM mms_management_agent WHERE ma_type = 'AD'"
        $SQLreader = $SQLcmd.ExecuteReader()
        $SQLreader.Read() | Out-Null
        $ADConfig = $SQLreader.GetString(0)
        $ADCryptedConfig = $SQLreader.GetString(1)
        $SQLreader.Close()

        # Read the AAD configuration data
        $SQLcmd = $SQLclient.CreateCommand()
        $SQLcmd.CommandText = "SELECT private_configuration_xml, encrypted_configuration FROM mms_management_agent WHERE subtype = 'Windows Azure Active Directory (Microsoft)'"
        $SQLreader = $SQLcmd.ExecuteReader()
        $SQLreader.Read() | Out-Null
        $AADConfig = $SQLreader.GetString(0)
        $AADCryptedConfig = $SQLreader.GetString(1)
        $SQLreader.Close()
        $SQLclient.Close()

        # Extract the data
        $attributes=@{}
        $attributes["ADUser"]=([xml]$ADConfig).'adma-configuration'.'forest-login-user'
        $attributes["ADDomain"]=([xml]$ADConfig).'adma-configuration'.'forest-login-domain'
        $attributes["AADUser"]=([xml]$AADConfig).MAConfig.'parameter-values'.parameter[0].'#text'

        try
        {
            # Decrypt config data
            $KeyMgr = New-Object -TypeName Microsoft.DirectoryServices.MetadirectoryServices.Cryptography.KeyManager

            $KeyMgr.LoadKeySet($entropy, $instance_id, $key_id)
            $key = $null
            $KeyMgr.GetActiveCredentialKey([ref]$key)
            $key2 = $null
            $KeyMgr.GetKey(1, [ref]$key2)
            $ADDecryptedConfig = $null
            $AADDecryptedConfig = $null
            $key2.DecryptBase64ToString($ADCryptedConfig, [ref]$ADDecryptedConfig)
            $key2.DecryptBase64ToString($AADCryptedConfig, [ref]$AADDecryptedConfig)

            # Extract the ecrypted data
            $attributes["ADUserPassword"]=([xml]$ADDecryptedConfig).'encrypted-attributes'.attribute.'#text'
            $attributes["AADUserPassword"]=([xml]$AADDecryptedConfig).'encrypted-attributes'.attribute.'#text'
        }
        catch
        {
            Write-Error "Could not load key set!"
        }

        # Return
        if($AsCredentials)
        {
            $adCreds =  New-Object System.Management.Automation.PSCredential($attributes["ADUser"],  (ConvertTo-SecureString $attributes["ADUserPassword"] -AsPlainText -Force))
            $aadCreds = New-Object System.Management.Automation.PSCredential($attributes["AADUser"], (ConvertTo-SecureString $attributes["AADUserPassword"] -AsPlainText -Force))

            return @($adCreds, $aadCreds)
        }
        else
        {
            return New-Object -TypeName PSObject -Property $attributes
        }
        
    }
}

# May 16th 2019
function Update-SyncCredentials
{
<#
    .SYNOPSIS
    Updates Azure AD Connect synchronization credentials

    .Description
    Updates Azure Active Directory Connect user's password to Azure AD and WID configuration database. MUST be run on AADConnect server
    as local administrator with Global Admin credentials to Azure AD
  
    .Example
    Update-AADIntSyncCredentials
    Password successfully updated to Azure AD and configuration database!
    Remember to restart the sync service: Restart-Service ADSync

    Name                           Value
    ----                           -----
    ADDomain                       company.com  
    ADUser                         MSOL_4bc4a34e95fa
    ADUserPassword                 Q9@p(poz{#:kF_G)(s/Iy@8c*9(t;...
    AADUser                        Sync_SRV01_4bc4a34e95fa@company.onmicrosoft.com
    AADUserPassword                $.1%(lxZ&/kNZz[r

    .Example
    Update-AADIntSyncCredentials -RestartADSyncService
    Password successfully updated to Azure AD and configuration database!
    
    Name                           Value
    ----                           -----
    ADDomain                       company.com  
    ADUser                         MSOL_4bc4a34e95fa
    ADUserPassword                 Q9@p(poz{#:kF_G)(s/Iy@8c*9(t;...
    AADUser                        Sync_SRV01_4bc4a34e95fa@company.onmicrosoft.com
    AADUserPassword                $.1%(lxZ&/kNZz[r

    WARNING: Waiting for service 'Microsoft Azure AD Sync (ADSync)' to stop...
    WARNING: Waiting for service 'Microsoft Azure AD Sync (ADSync)' to start...
#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$False)]
        [String]$AccessToken,
        [Switch]$RestartADSyncService,
        [Parameter(Mandatory=$false)]
        [bool]$AsADSync=$true,
        [Parameter(Mandatory=$false)]
        [switch]$force
     )
    Process
    {
        # Do the checks
        if((Check-Server -AsADSync $AsADSync -force $force) -eq $false)
        {
           return
        }

        # Get from cache if not provided
        $AccessToken = Get-AccessTokenFromCache -AccessToken $AccessToken -ClientID "1b730954-1685-4b74-9bfd-dac224a7b894" -Resource "https://graph.windows.net"

        if([String]::IsNullOrEmpty($AccessToken))
        {
            Write-Error "No AccessToken provided!"
            return
        }
        # Admin user
        $AdminUser = (Read-Accesstoken -AccessToken $at).upn

        # Get the current configuration
        $SyncCreds = Get-SyncCredentials -force
        $SyncUser = ($SyncCreds.AADUser.Split("@")[0])

        Write-Verbose "Updating password for $SyncUser as $AdminUser"

        # Reset the account password in AzureAD
        $NewPassword = (Reset-ServiceAccount -AccessToken $AccessToken -ServiceAccount $SyncUser).Password

        # Escaping password for xml
        $NewPassword = [System.Security.SecurityElement]::Escape($NewPassword)

        if([String]::IsNullOrEmpty($NewPassword))
        {
            Write-Error "Password for user $SyncCreds could not be reset to Azure AD"
            return
        }

        # Create a new config
        $ADDecryptedConfig=@"
<encrypted-attributes>
 <attribute name="Password">$NewPassword</attribute>
</encrypted-attributes>
"@
        # Read the encrypt/decrypt key settings
        $SQLclient = new-object System.Data.SqlClient.SqlConnection -ArgumentList -ArgumentList (Get-AADConfigDbConnection)
        $SQLclient.Open()
        $SQLcmd = $SQLclient.CreateCommand()
        $SQLcmd.CommandText = "SELECT keyset_id, instance_id, entropy FROM mms_server_configuration"
        $SQLreader = $SQLcmd.ExecuteReader()
        $SQLreader.Read() | Out-Null
        $key_id = $SQLreader.GetInt32(0)
        $instance_id = $SQLreader.GetGuid(1)
        $entropy = $SQLreader.GetGuid(2)
        $SQLreader.Close()

        # Load keys
        $KeyMgr = New-Object -TypeName Microsoft.DirectoryServices.MetadirectoryServices.Cryptography.KeyManager
        $KeyMgr.LoadKeySet($entropy, $instance_id, $key_id)
        $key = $null
        $KeyMgr.GetActiveCredentialKey([ref]$key)
        $key2 = $null
        $KeyMgr.GetKey(1, [ref]$key2)

        # Encrypt
        $AADCryptedConfig = $null
        $key2.EncryptStringToBase64($ADDecryptedConfig,[ref]$AADCryptedConfig)

        # Write the updated AAD password
        $SQLcmd = $SQLclient.CreateCommand()
        $SQLcmd.CommandText = "UPDATE mms_management_agent SET encrypted_configuration=@pwd WHERE subtype = 'Windows Azure Active Directory (Microsoft)'"
        $SQLcmd.Parameters.AddWithValue("@pwd",$AADCryptedConfig) | Out-Null
        $UpdatedRows = $SQLcmd.ExecuteNonQuery() 
        $SQLclient.Close()
        
        if($UpdatedRows -ne 1)
        {
            Write-Error "Updated $UpdatedRows while should update 1. Could be error"
            return
        }

        Write-Host "Password successfully updated to Azure AD and configuration database!"

        # Return        
        Get-SyncCredentials -force

        # Restart the ADSync service if requested
        if($RestartADSyncService)
        {
            Restart-Service ADSync
        }
        else
        {
            Write-Host "Remember to restart the sync service: Restart-Service ADSync" -ForegroundColor Yellow
        }
    }
}

# May 17th 2019
function Set-ADSyncAccountPassword
{
<#
    .SYNOPSIS
    Sets the password of ADSync service account

    .Description
    Sets the password of ADSync service account to AD and WID configuration database. MUST be run on AADConnect server
    as domain administrator.
  
    .Example
    Set-AADIntADSyncAccountPassword -NewPassword 'Pa$$w0rd'
    Password successfully updated to AD and configuration database!
    Remember to restart the sync service: Restart-Service ADSync

    Name                           Value
    ----                           -----
    ADDomain                       company.com  
    ADUser                         MSOL_4bc4a34e95fa
    ADUserPassword                 Pa$$w0rd
    AADUser                        Sync_SRV01_4bc4a34e95fa@company.onmicrosoft.com
    AADUserPassword                $.1%(lxZ&/kNZz[r

    .Example
    Set-AADIntADSyncAccountPassword -NewPassword 'Pa$$w0rd' -RestartADSyncService
    Password successfully updated to AD and configuration database!
    
    Name                           Value
    ----                           -----
    ADDomain                       company.com  
    ADUser                         MSOL_4bc4a34e95fa
    ADUserPassword                 Pa$$w0rd
    AADUser                        Sync_SRV01_4bc4a34e95fa@company.onmicrosoft.com
    AADUserPassword                $.1%(lxZ&/kNZz[r

    WARNING: Waiting for service 'Microsoft Azure AD Sync (ADSync)' to stop...
    WARNING: Waiting for service 'Microsoft Azure AD Sync (ADSync)' to start...
#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [String]$NewPassword,
        [Switch]$RestartADSyncService,
        [Parameter(Mandatory=$false)]
        [bool]$AsADSync=$true,
        [Parameter(Mandatory=$false)]
        [switch]$force
     )
    Process
    {
        # Do the checks
        if((Check-Server -AsADSync $AsADSync -force $force) -eq $false)
        {
           return
        }

        # Add the encryption reference (should always be there)
        Add-Type -path 'C:\Program Files\Microsoft Azure AD Sync\Bin\mcrypt.dll’

        # Get the current configuration
        $SyncCreds = Get-SyncCredentials -force
        $SyncUser = $SyncCreds.ADUser

        Write-Verbose "Updating password for $SyncUser"

        # Reset the account password in AD
        try
        {
            Set-ADAccountPassword -Identity $SyncUser -Reset -NewPassword (ConvertTo-SecureString -AsPlainText $NewPassword -Force)
        }
        catch
        {
            # There might be complexity etc. requirements
            throw $_
            return
        }

        # Escaping password for xml
        $NewPassword = [System.Security.SecurityElement]::Escape($NewPassword)

        # Create a new config
        $ADDecryptedConfig=@"
<encrypted-attributes>
 <attribute name="Password">$NewPassword</attribute>
</encrypted-attributes>
"@
        # Read the encrypt/decrypt key settings
        $SQLclient = new-object System.Data.SqlClient.SqlConnection -ArgumentList (Get-AADConfigDbConnection)
        $SQLclient.Open()
        $SQLcmd = $SQLclient.CreateCommand()
        $SQLcmd.CommandText = "SELECT keyset_id, instance_id, entropy FROM mms_server_configuration"
        $SQLreader = $SQLcmd.ExecuteReader()
        $SQLreader.Read() | Out-Null
        $key_id = $SQLreader.GetInt32(0)
        $instance_id = $SQLreader.GetGuid(1)
        $entropy = $SQLreader.GetGuid(2)
        $SQLreader.Close()

        # Load keys
        $KeyMgr = New-Object -TypeName Microsoft.DirectoryServices.MetadirectoryServices.Cryptography.KeyManager
        $KeyMgr.LoadKeySet($entropy, $instance_id, $key_id)
        $key = $null
        $KeyMgr.GetActiveCredentialKey([ref]$key)
        $key2 = $null
        $KeyMgr.GetKey(1, [ref]$key2)

        # Encrypt
        $ADCryptedConfig = $null
        $key2.EncryptStringToBase64($ADDecryptedConfig,[ref]$ADCryptedConfig)

        # Write the updated AA password
        $SQLcmd = $SQLclient.CreateCommand()
        $SQLcmd.CommandText = "UPDATE mms_management_agent SET encrypted_configuration=@pwd WHERE ma_type = 'AD'"
        $SQLcmd.Parameters.AddWithValue("@pwd",$ADCryptedConfig) | Out-Null
        $UpdatedRows = $SQLcmd.ExecuteNonQuery() 
        $SQLclient.Close()
        
        if($UpdatedRows -ne 1)
        {
            Write-Error "Updated $UpdatedRows while should update 1. Could be error"
            return
        }

        Write-Host "Password successfully updated to AD and configuration database!"

        # Return        
        Get-SyncCredentials -force

        # Restart the ADSync service if requested
        if($RestartADSyncService)
        {
            Restart-Service ADSync
        }
        else
        {
            Write-Host "Remember to restart the sync service: Restart-Service ADSync" -ForegroundColor Yellow
        }
    }
}


# Decrypts AD and AAD passwords with the given key and IV
# May 3rd 2020
function Get-DecryptedConfigPassword
{
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$true)]
        [byte[]]$Data,
        [Parameter(Mandatory=$true)]
        [byte[]]$Key,
        [Parameter(Mandatory=$true)]
        [guid]$InitialVector
    )
    Process
    {
        # Create the AES decryptor        
        $aes=New-Object -TypeName System.Security.Cryptography.AesCryptoServiceProvider
        $aes.Mode = "CBC"
        $aes.Key =  $Key
        $aes.IV =   $iv.ToByteArray()
        $dc=$aes.CreateDecryptor()
        
        # Decrypt the data    
        $decData = $dc.TransformFinalBlock($Data,0,$Data.Length)

        # Convert to xml and get the password
        [xml]$decDataXml = ([text.encoding]::Unicode.GetString($decData)).trimEnd(@(0x00,0x0a,0x0d))
        $decPassword = $decDataXml.'encrypted-attributes'.attribute.'#text'

        Write-Verbose "DecryptedConfigPassword: $($decDataXml.OuterXml)"

        # Return
        return $decPassword

    }
}

# Encrypts AD or AAD password with the given key and IV
# May 3rd 2020
function New-DecryptedConfigPassword
{
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$true)]
        [string]$Password,
        [Parameter(Mandatory=$true)]
        [byte[]]$Key,
        [Parameter(Mandatory=$true)]
        [guid]$InitialVector
    )
    Process
    {
        # Escaping password for xml
        $NewPassword = [System.Security.SecurityElement]::Escape($Password)

        # Create the AES encryptor        
        $aes=New-Object -TypeName System.Security.Cryptography.AesCryptoServiceProvider
        $aes.Mode = "CBC"
        $aes.Key =  $Key
        $aes.IV =   $iv.ToByteArray()
        $de=$aes.CreateEncryptor()
        
        # Encrypt the data    
        $data = "<encrypted-attributes><attribute name=""password"">$NewPassword</attribute></encrypted-attributes>"
        $binData = [text.encoding]::Unicode.GetBytes($data)
        $decData = $de.TransformFinalBlock($binData,0,$binData.Length)

        Write-Verbose "DecryptedConfigPassword: $data"

        # Return
        return $decData

    }
}

# Retrieves ADSync encryption key used to encrypt and decrypt configuration data
# May 3rd 2020
function Get-SyncEncryptionKey
{
<#
    .SYNOPSIS
    Gets ADSync encryption key using the given entropy and instance id

    .DESCRIPTION
    Gets the ADSync encryption key used to encrypt and decrypt passwords for service users of Azure AD and local AD

    .Example
    Get-AADIntSyncEncryptionKey -Entropy a1c80460-6fe9-4c6f-bf31-d7a34c878dca -InstanceId 299b1d83-9dc6-479a-92f1-2357fc5abfed

    Id     Guid                                 CryptAlg Key
    --     ----                                 -------- ---
    100000 299b1d83-9dc6-479a-92f1-2357fc5abfed    26128 {4, 220, 54, 13...}

    .Example
    $key_info = Get-AADIntSyncEncryptionKeyInfo

    PS C:\>Get-AADIntSyncEncryptionKey -Entropy $key_info.Entropy -InstanceId $key_info.InstanceId

    Id     Guid                                 CryptAlg Key                   
    --     ----                                 -------- ---                   
    100000 299b1d83-9dc6-479a-92f1-2357fc5abfed    26128 {4, 220, 54, 13...}
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [guid]$Entropy,
        [Parameter(Mandatory=$true)]
        [guid]$InstanceId
    )

    # Define the return variable
    $retVal = $null
   
    # Fetch the full name of the ADSync user. Should be in the format DOMAIN\AAD_xxxxxxxxxxxx
    $FullName=(Get-WmiObject Win32_Service -Filter "Name='ADSync'").StartName
    $userName = $FullName.split("\")[1]

    # Get user's SID
    $userSID=(Get-WmiObject win32_useraccount -Filter "Name='$userName'").SID

    
    # Get the stored password for the ADSync service -> this is the password of DOMAIN\AAD_xxxxxxxxxxxx user!
    $LSAUserName = "_SC_ADSync"
    $LSASecret=Get-LSASecrets -Users "_SC_ADSync"
    $password=$LSASecret.PasswordTxt

    Write-Verbose "UserName: $FullName"
    Write-Verbose "SID:      $userSID"
    Write-Verbose "Password: $password`n`n"

    # As we now know the password of the user, we can get user masterkeys without system masterkey
    # Get user's masterkeys and decode them with username and password
    #$masterKeys=Get-UserMasterkeys -UserName $userName -SID $userSID -Password $password

    # Get the system key
    $systemKey = Get-LSABackupKeys | Where-Object name -eq "RSA"
    
    # Get the system masterkeys
    $masterKeys = Get-SystemMasterkeys -SystemKey $systemKey.Key

    # Get the user's masterkeys
    $usrMasterKeys = Get-UserMasterkeys -UserName $userName -SystemKey $systemKey.Key -SID $userSID

    # Merge the keys
    foreach($key in $usrMasterKeys.Keys)
    {
        $masterKeys[$key]=$usrMasterKeys[$key]
    }

    # Get user's credentials with the masterkeys
    $credentials = Get-LocalUserCredentials -UserName $userName -MasterKeys $masterKeys

    # Try to find the correct credential entry
    foreach($cred in $credentials)
    {
        $target = $cred.Target
        # Check the target, we are looking for:
        # LegacyGeneric:target=Microsoft_AzureADConnect_KeySet_{00000000-0000-0000-0000-0000000000}_100000
        if($target.toLower().Contains(([guid]$instanceid).ToString()))
        {
            $keySetId = [int]$target.Split("_")[4]
            # The keyset is actually a DPAPIBlob, so decrypt it using a native DPAPI method in LOCAL MACHINE context
            $keySet = [AADInternals.Native]::getDecryptedData($cred.Secret,$entropy.toByteArray())
            
            Write-Verbose "KeySet ($keySetId): $(Convert-ByteArrayToHex -Bytes $keySet)"

            # Parse the keyset
            $key = Parse-KeySetBlob -Data $keySet

            # Check whether the id and guid matches
            if($key.Id -eq $keySetId -and $key.Guid -eq $instanceId)
            {
                $retVal = $key
            }
            
        }
    }

    return $retVal
}

# Parses the MMSK key set blob
# May 3rd 2020
function Parse-KeySetBlob
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true)]
        [byte[]]$Data
    )
    Process
    {
        # Parse the KeySet
        $p=4 # Skip the MMSK string at the beginning
        $version =       [System.BitConverter]::ToInt32($Data,$p);$p+=4
        $id =            [System.BitConverter]::ToInt32($Data,$p);$p+=4
        $guid =          [guid][byte[]]$Data[$p..$($p+15)]; $p+=16
        $unk0 =          [System.BitConverter]::ToInt32($Data,$p);$p+=4
        $unk1 =          [System.BitConverter]::ToInt32($Data,$p);$p+=4
        $unk2 =          [System.BitConverter]::ToInt32($Data,$p);$p+=4
        $unk3 =          [System.BitConverter]::ToInt32($Data,$p);$p+=4
        $unk4 =          [System.BitConverter]::ToInt32($Data,$p);$p+=4
        $keyBlockSize =  [System.BitConverter]::ToInt32($Data,$p);$p+=4
        $secondKeySize = [System.BitConverter]::ToInt32($Data,$p);$p+=4
        $unk7 =          [System.BitConverter]::ToInt32($Data,$p);$p+=4
        $unk8 =          [System.BitConverter]::ToInt32($Data,$p);$p+=4
        $unk9 =          [System.BitConverter]::ToInt32($Data,$p);$p+=4
        $unk10 =         [System.BitConverter]::ToInt32($Data,$p);$p+=4
        $unk11 =         [System.BitConverter]::ToInt32($Data,$p);$p+=4
        $unk12 =         [System.BitConverter]::ToInt32($Data,$p);$p+=4
        $enAlg =         [System.BitConverter]::ToInt32($Data,$p);$p+=4
        $keyLength =     [System.BitConverter]::ToInt32($Data,$p);$p+=4
        $key =           $Data[$p..$($p+$keyLength-1)]; $p+=$keyLength
        #$unk15 =         [System.BitConverter]::ToInt32($Data,$p);$p+=4
        #$enAlg2 =        [System.BitConverter]::ToInt32($Data,$p);$p+=4
        #$keyLength2 =    [System.BitConverter]::ToInt32($Data,$p);$p+=4
        #$key2 =          $Data[$p..$($p+$keyLength2-1)]; $p+=$keyLength2

        Write-Verbose "*** KEYSET ***"
        Write-Verbose "Id:       $id"
        Write-Verbose "Guid:     $guid"
        Write-Verbose "CryptAlg: $enAlg $($ALGS[$enAlg])"
        Write-Verbose "Key:      $(Convert-ByteArrayToHex -Bytes $key)`n`n"

        $attributes=[ordered]@{
            "Id" =       $id
            "Guid" =     $guid
            "CryptAlg" = $enAlg
            "Key" =      $key
        }
        

        return New-Object PSObject -Property $attributes
        
    }
}

# Gets entropy and instanceid from the local configuration database
# May 6th 2020
function Get-SyncEncryptionKeyInfo
{
<#
    .SYNOPSIS
    Gets ADSync encryption key info from the local configuration database

    .DESCRIPTION
    Gets ADSync encryption key info from the local configuration database

    .Example
    Get-AADIntSyncEncryptionKeyInfo

    Name                           Value 
    ----                           ----- 
    InstanceId                     299b1d83-9dc6-479a-92f1-2357fc5abfed
    Entropy                        a1c80460-6fe9-4c6f-bf31-d7a34c878dca
#>
    [CmdletBinding()]
    param()

    # Read the encrypt/decrypt key settings
    $SQLclient = new-object System.Data.SqlClient.SqlConnection -ArgumentList (Get-AADConfigDbConnection)
    $SQLclient.Open()
    $SQLcmd = $SQLclient.CreateCommand()
    $SQLcmd.CommandText = "SELECT keyset_id, instance_id, entropy FROM mms_server_configuration"
    $SQLreader = $SQLcmd.ExecuteReader()
    $SQLreader.Read() | Out-Null
    $key_id = $SQLreader.GetInt32(0)
    $instance_id = $SQLreader.GetGuid(1)
    $entropy = $SQLreader.GetGuid(2)
    $SQLreader.Close()
    $SQLClient.Close()

    return New-Object PSObject @{Entropy = $entropy; InstanceId = $instance_id}
}

# Gets the db connection string from the registry
# May 11th
function Get-AADConfigDbConnection
{
    [cmdletbinding()]
    Param()
    Begin
    {
        # Create the connection string for the configuration database
        $parametersPath =    "HKLM:\SYSTEM\CurrentControlSet\Services\ADSync\Parameters"
        $dBServer =          Get-ItemPropertyValue -Path $parametersPath -Name "Server"
        $dBName =            Get-ItemPropertyValue -Path $parametersPath -Name "DBName"
        $dBInstance =        Get-ItemPropertyValue -Path $parametersPath -Name "SQLInstance"
        $connectionString  = "Data Source=$dbServer\$dBInstance;Initial Catalog=$dBName"
    }
    Process
    {
        Write-Verbose "ConnectionString=$connectionString"

        return $connectionString
    }
}
