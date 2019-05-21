# This module contains functions to extract and update AADConnect sync credentials

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
#>
    [cmdletbinding()]
    Param()
    Process
    {
        # Check that we are on AADConnect server
        if((Get-Service ADSync -ErrorAction SilentlyContinue) -eq $null)
        {
            Write-Error "This command needs to be run on a computer with AADConnect"
            return
        }

        # Add the encryption reference (should always be there)
        Add-Type -path 'C:\Program Files\Microsoft Azure AD Sync\Bin\mcrypt.dll’

        # Read the encrypt/decrypt key settings
        $SQLclient = new-object System.Data.SqlClient.SqlConnection -ArgumentList "Data Source=(localdb)\.\ADSync;Initial Catalog=ADSync"
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

        # Extract the data
        $attributes=@{}
        $attributes["ADUser"]=([xml]$ADConfig).'adma-configuration'.'forest-login-user'
        $attributes["ADDomain"]=([xml]$ADConfig).'adma-configuration'.'forest-login-domain'
        $attributes["ADUserPassword"]=([xml]$ADDecryptedConfig).'encrypted-attributes'.attribute.'#text'
        $attributes["AADUser"]=([xml]$AADConfig).MAConfig.'parameter-values'.parameter[0].'#text'
        $attributes["AADUserPassword"]=([xml]$AADDecryptedConfig).'encrypted-attributes'.attribute.'#text'

        # Return
        return New-Object -TypeName PSObject -Property $attributes
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
        [Switch]$RestartADSyncService
     )
    Process
    {
        # Check that we are on AADConnect server
        if((Get-Service ADSync -ErrorAction SilentlyContinue) -eq $null)
        {
            Write-Error "This command needs to be run on a computer with AADConnect"
            return
        }

        # Get from cache if not provided
        $AccessToken = Get-AccessTokenFromCache($AccessToken)

        if([String]::IsNullOrEmpty($AccessToken))
        {
            Write-Error "No AccessToken provided!"
            return
        }
        # Admin user
        $AdminUser = (Read-Accesstoken -AccessToken $at).upn

        # Add the encryption reference (should always be there)
        Add-Type -path 'C:\Program Files\Microsoft Azure AD Sync\Bin\mcrypt.dll’

        # Get the current configuration
        $SyncCreds = Get-SyncCredentials
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
        $SQLclient = new-object System.Data.SqlClient.SqlConnection -ArgumentList "Data Source=(localdb)\.\ADSync;Initial Catalog=ADSync"
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
        Get-SyncCredentials

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
    as company administrator.
  
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
        [Switch]$RestartADSyncService
     )
    Process
    {
        # Check that we are on AADConnect server
        if((Get-Service ADSync -ErrorAction SilentlyContinue) -eq $null)
        {
            Write-Error "This command needs to be run on a computer with AADConnect"
            return
        }

        # Add the encryption reference (should always be there)
        Add-Type -path 'C:\Program Files\Microsoft Azure AD Sync\Bin\mcrypt.dll’

        # Get the current configuration
        $SyncCreds = Get-SyncCredentials
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
        $SQLclient = new-object System.Data.SqlClient.SqlConnection -ArgumentList "Data Source=(localdb)\.\ADSync;Initial Catalog=ADSync"
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
        Get-SyncCredentials

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