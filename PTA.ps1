# This script contains utility functions for PTA

# Error codes
$ERROR_ACCESS_DENIED = 5
$ERROR_ACCOUNT_DISABLED = 1331
$ERROR_ACCOUNT_EXPIRED = 1793
$ERROR_ACCOUNT_LOCKED_OUT = 1909
$ERROR_ACCOUNT_RESTRICTION = 1327
$ERROR_AUTHENTICATION_FIREWALL_FAILED = 1935
$ERROR_BAD_ARGUMENTS = 160
$ERROR_DOMAIN_CONTROLLER_NOT_FOUND = 1908
$ERROR_DOMAIN_TRUST_INCONSISTENT = 1810
$ERROR_FILENAME_EXCED_RANGE = 206
$ERROR_INTERNAL_ERROR = 1359
$ERROR_INVALID_ACCESS = 12
$ERROR_INVALID_LOGON_HOURS = 1328
$ERROR_INVALID_SERVER_STATE = 1352
$ERROR_INVALID_WORKSTATION = 1329
$ERROR_LDAP_FILTER_ERROR = 87
$ERROR_LDAP_OPERATIONS_ERROR = 1
$ERROR_LOGON_FAILURE = 1326
$ERROR_LOGON_TYPE_NOT_GRANTED = 1385
$ERROR_NETLOGON_NOT_STARTED = 1792
$ERROR_NOT_ENOUGH_MEMORY = 8
$ERROR_NOT_ENOUGH_SERVER_MEMORY = 1130
$ERROR_NO_LOGON_SERVERS = 1311
$ERROR_NO_SUCH_DOMAIN = 1355
$ERROR_NO_SUCH_PACKAGE = 1364
$ERROR_NO_SUCH_USER = 1317
$ERROR_NO_SYSTEM_RESOURCES = 1450
$ERROR_NO_TRUST_SAM_ACCOUNT = 1787
$ERROR_OUTOFMEMORY = 14
$ERROR_PASSWORD_EXPIRED = 1330
$ERROR_PASSWORD_MUST_CHANGE = 1907
$ERROR_PASSWORD_RESTRICTION = 1325
$ERROR_REQUEST_NOT_SUPPORTED = 50
$ERROR_RPC_S_CALL_FAILED = 1726
$ERROR_RPC_S_SERVER_UNAVAILABLE = 1722
$ERROR_TIME_SKEW = 1398
$ERROR_TOO_MANY_CONTEXT_IDS = 1384
$ERROR_TRUSTED_DOMAIN_FAILURE = 1788
$ERROR_TRUSTED_RELATIONSHIP_FAILURE = 1789
$ERROR_WRONG_PASSWORD = 1323
$SEC_E_SMARTCARD_LOGON_REQUIRED = -2146892994

# Registers PTAAgent to the Azure AD
# Nov 10th 2019
# Sep 7th 2022: Added UpdateTrust
function Register-PTAAgent
{
<#
    .SYNOPSIS
    Registers the PTA agent to Azure AD and creates a client certificate or renews existing certificate.

    .DESCRIPTION
    Registers the PTA agent to Azure AD with given machine name and creates a client certificate or renews existing certificate.

    The filename of the certificate is <server FQDN>_<tenant id>_<agent id>_<cert thumbprint>.pfx

    .Example
    Get-AADIntAccessTokenForPTA -SaveToCache
    Register-AADIntPTAAgent -MachineName "server1.company.com"

    PTA Agent (005b136f-db3e-4b54-9d8b-8994f7717de6) registered as server1.company.com
    Certificate saved to server1.company.com_513d8d3d-7498-4d8c-85ed-b485ed5c39a9_005b136f-db3e-4b54-9d8b-8994f7717de6_6464A8C05194B416B347D65F01F89FCCE66292FB.pfx

    .Example
    $pt=Get-AADIntAccessTokenForPTA
    PS C:\>Register-AADIntPTAAgent -AccessToken $pt -MachineName "server1.company.com" 

    PTA Agent (005b136f-db3e-4b54-9d8b-8994f7717de6) registered as server1.company.com
    Certificate saved to server1.company.com_513d8d3d-7498-4d8c-85ed-b485ed5c39a9_005b136f-db3e-4b54-9d8b-8994f7717de6_6464A8C05194B416B347D65F01F89FCCE66292FB.pfx

    .Example
    PS C:\>Register-AADIntPTAAgent -MachineName "server1.company.com" -UpdateTrust -PfxFileName .\server1.company.com_513d8d3d-7498-4d8c-85ed-b485ed5c39a9_005b136f-db3e-4b54-9d8b-8994f7717de6_6464A8C05194B416B347D65F01F89FCCE66292FB.pfx

    PTA Agent (005b136f-db3e-4b54-9d8b-8994f7717de6) certificate renewed for server1.company.com
    Certificate saved to server1.company.com_513d8d3d-7498-4d8c-85ed-b485ed5c39a9_005b136f-db3e-4b54-9d8b-8994f7717de6_449D42C1BA32B23A621EBE62329AE460FE68924B.pfx
   
#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$False)]
        [String]$AccessToken,
        [Parameter(Mandatory=$True)]
        [String]$MachineName,
        [Parameter(Mandatory=$False)]
        [String]$FileName,
        [Parameter(ParameterSetName='normal',Mandatory=$False)]
        [Parameter(ParameterSetName='update',Mandatory=$True)]
        [switch]$UpdateTrust,
        [Parameter(Mandatory=$False)]
        [String]$Bootstrap,
        [Parameter(ParameterSetName='update',Mandatory=$True)]
        [String]$PfxFileName,
        [Parameter(ParameterSetName='update',Mandatory=$False)]
        [String]$PfxPassword
    )
    Process
    {
        return Register-ProxyAgent -AccessToken $AccessToken -MachineName $MachineName -FileName $FileName -AgentType PTA -UpdateTrust $UpdateTrust -PfxFileName $PfxFileName -PfxPassword $PfxPassword -Bootstrap $Bootstrap
    }
}



# Sets the certificate used by Azure AD Authentication Agent
# Mar 3rd 2020
# May 18th 2022: Fixed
function Set-PTACertificate
{
<#
    .SYNOPSIS
    Sets the certificate used by Azure AD Authentication Agent

    .DESCRIPTION
    Sets the certificate used by Azure AD Authentication Agent. 
    The certificate must be created with Register-AADIntPTAAgent function or exported with Export-AADIntProxyAgentCertificates.

    .Example
    Set-AADIntPTACertificate -PfxFileName server1.pfx -PfxPassword "password"
#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$False)]
        [String]$PfxFileName="PTA_client_certificate.pfx",
        [Parameter(Mandatory=$False)]
        [String]$PfxPassword
    )
    Process
    {
        # Check if the file exists
        if(-not (Test-Path $PfxFileName))
        {
            Write-Error "The file $PfxFileName does not exist!"
            return
        }

        # Import the certificate twice, otherwise PTAAgent has issues to access private keys
        $cert = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new((Get-Item $PfxFileName).FullName, $PfxPassword, [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::MachineKeySet -bor [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::PersistKeySet -bor [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::Exportable)
        $cert.Import((Get-Item $PfxFileName).FullName, $PfxPassword, [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::MachineKeySet -bor [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::PersistKeySet -bor [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::Exportable)

        # Add certificate to Local Computer Personal store
        $myStore = Get-Item -Path "Cert:\LocalMachine\My"
        $myStore.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)
        $myStore.Add($cert)
        $myStore.Close()

        # Get the Tenant Id and Instance Id
        $TenantId = $cert.Subject.Split("=")[1]
        
        foreach($extension in $cert.Extensions)
        {
            if($extension.Oid.Value -eq "1.3.6.1.4.1.311.82.1")
            {
                $InstanceID = [guid]$extension.RawData
                break
            }
        }

        # Set the registry value (the registy entry should already exists)
        Write-Verbose "Setting HKLM:\SOFTWARE\Microsoft\Azure AD Connect Agents\Azure AD Connect Authentication Agent\InstanceID to $InstanceID"
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Azure AD Connect Agents\Azure AD Connect Authentication Agent" -Name "InstanceID" -Value $InstanceID

        if(![string]::IsNullOrEmpty($TenantId))
        {
            Write-Verbose "Setting HKLM:\SOFTWARE\Microsoft\Azure AD Connect Agents\Azure AD Connect Authentication Agent\TenantID to $TenantId"
            Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Azure AD Connect Agents\Azure AD Connect Authentication Agent" -Name "TenantID" -Value $TenantId
        }

        # Set the certificate thumbprint to config file
        $configFile = "$env:ProgramData\Microsoft\Azure AD Connect Authentication Agent\Config\TrustSettings.xml"
        
        Write-Verbose "Setting the certificate thumbprint $($cert.Thumbprint) to $configFile"
        
        [xml]$TrustConfig = Get-Content $configFile
        $TrustConfig.ConnectorTrustSettingsFile.CloudProxyTrust.Thumbprint = $cert.Thumbprint
        $TrustConfig.ConnectorTrustSettingsFile.CloudProxyTrust.IsInUserStore = "false"
        $TrustConfig.OuterXml | Set-Content $configFile

        # Set the read access to private key
        $ServiceUser="NT SERVICE\AzureADConnectAuthenticationAgent"

        # Create an accessrule for private key
        $AccessRule = New-Object Security.AccessControl.FileSystemAccessrule $ServiceUser, "read", allow
        
        # Give read permissions to the private key
        $keyName = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($cert).Key.UniqueName
        Write-Verbose "Private key: $keyName"

        $paths = @(
            "$env:ALLUSERSPROFILE\Microsoft\Crypto\RSA\MachineKeys\$keyName"
            "$env:ALLUSERSPROFILE\Microsoft\Crypto\Keys\$keyName"
        )
        foreach($path in $paths)
        {
            if(Test-Path $path)
            {       
                Write-Verbose "Setting read access for ($ServiceUser) to the private key ($path)"
        
                try
                {
                    $permissions = Get-Acl -Path $path -ErrorAction SilentlyContinue
                    $permissions.AddAccessRule($AccessRule)
                    Set-Acl -Path $path -AclObject $permissions -ErrorAction SilentlyContinue
                }
                catch
                {
                    Write-Error "Could not give read access for ($ServiceUser) to the private key ($path)!"
                }
                break
            }
        }

        Write-Host "`nCertification information set, remember to (re)start the service."
    }
}