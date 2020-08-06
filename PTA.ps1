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
function Register-PTAAgent
{
<#
    .SYNOPSIS
    Registers the PTA agent to Azure AD and creates a client certificate

    .DESCRIPTION
    Registers the PTA agent to Azure AD with given machine name and creates a client certificate

    .Example
    Register-AADIntPTAAgent -MachineName "server1.company.com"

    PTA Agent (005b136f-db3e-4b54-9d8b-8994f7717de6) registered as server1.company.com
    Certificate saved to PTA_client_certificate.pfx

    .Example
    $pt=Get-AADIntAccessTokenForPTA
    PS C:\>Register-AADIntPTAAgent -AccessToken $pt -MachineName "server1.company.com" -FileName server1.pfx

    PTA Agent (005b136f-db3e-4b54-9d8b-8994f7717de6) registered as server1.company.com
    Certificate saved to server1.pfx
   
#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$False)]
        [String]$AccessToken,
        [Parameter(Mandatory=$True)]
        [String]$MachineName,
        [Parameter(Mandatory=$False)]
        [String]$FileName="PTA_client_certificate.pfx"
    )
    Process
    {
        # Get access token from cache
        $AccessToken = Get-AccessTokenFromCache -AccessToken $AccessToken -Resource "https://proxy.cloudwebappproxy.net/registerapp" -ClientId "cb1056e2-e479-49de-ae31-7812af012ed8"

        return Register-ProxyAgent -AccessToken $AccessToken -MachineName $MachineName -FileName $FileName -AgentType PTA
    }
}



# Sets the certificate used by Azure AD Authentication Agent
# Mar 3rd 2020
function Set-PTACertificate
{
<#
    .SYNOPSIS
    Sets the certificate used by Azure AD Authentication Agent

    .DESCRIPTION
    Sets the certificate used by Azure AD Authentication Agent. The certificate must be created with Register-AADIntPTAAgent function.

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
        if(($PfxFile=Get-Item $PfxFileName -ErrorAction SilentlyContinue) -eq $null)
        {
            Write-Error "The file ($PfxFile.FullName) does not exist!"
            return
        }

        # Load the certificate
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$cert = [System.Security.Cryptography.X509Certificates.X509Certificate2]::CreateFromCertFile($PfxFile)

        # Get the Tenant Id and Instance Id
        $TenantId = $cert.Subject.Split("=")[1]
        $InstanceID = [guid]$cert.GetSerialNumberString()

        # Actually, it is not the serial number but this oid for Private Enterprise Number. Microsoft = 1.3.6.1.4.1.311
        foreach($extension in $cert.Extensions)
        {
            if($extension.Oid.Value -eq "1.3.6.1.4.1.311.82.1")
            {
                $InstanceID = [guid]$extension.RawData
            }
        }

        # Import the certificate to Local Machine\My
        $store = [System.Security.Cryptography.X509Certificates.X509Store]::new([System.Security.Cryptography.X509Certificates.StoreName]::My, [System.Security.Cryptography.X509Certificates.StoreLocation]::LocalMachine)
        $store.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)
        $store.Add($cert)
        $store.Close()

        # Set the registry value (the registy entry should already exists)
        Write-Verbose "Setting HKLM:\SOFTWARE\Microsoft\Azure AD Connect Agents\Azure AD Connect Authentication Agent\InstanceID to $InstanceID"
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Azure AD Connect Agents\Azure AD Connect Authentication Agent" -Name "InstanceID" -Value $InstanceID

        if(![string]::IsNullOrEmpty($TenantId))
        {
            Write-Verbose "Setting HKLM:\SOFTWARE\Microsoft\Azure AD Connect Agents\Azure AD Connect Authentication Agent\TenantID to $TenantId"
            Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Azure AD Connect Agents\Azure AD Connect Authentication Agent" -Name "TenantID" -Value $TenantId
        }

        # Set the certificate thumb print to config file
        $configFile = "$env:ProgramData\Microsoft\Azure AD Connect Authentication Agent\Config\TrustSettings.xml"
        Write-Verbose "Setting the certificate thumb print to $configFile"
        [xml]$TrustConfig = Get-Content $configFile
        $TrustConfig.ConnectorTrustSettingsFile.CloudProxyTrust.Thumbprint = $cert.Thumbprint
        $TrustConfig.OuterXml | Set-Content $configFile

        # Set the read access to private key
        # Get the service information
        $Service=Get-WMIObject -namespace "root\cimv2" -class Win32_Service -Filter 'Name="AzureADConnectAuthenticationAgent"'

        # Create an accessrule for private key
        $AccessRule = New-Object Security.AccessControl.FileSystemAccessrule $service.StartName, "read", allow
        $Root = "C:\ProgramData\Microsoft\Crypto\RSA\MachineKeys"

        # Give read permissions to the private key
        $rsaCert = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($cert)
        $fileName = $rsaCert.key.UniqueName
        $path="$Root\$fileName"
        Write-Verbose "Setting read access for ($($service.StartName)) to the private key ($path)"
        
        try
        {
            $permissions = Get-Acl -Path $path -ErrorAction SilentlyContinue
            $permissions.AddAccessRule($AccessRule)
            Set-Acl -Path $path -AclObject $permissions -ErrorAction SilentlyContinue
        }
        catch
        {
            Write-Warning "Could not give read access for ($($service.StartName)) to the private key ($path) but this is propably okay."
        }

        Write-Host "`nCertification information set, remember to (re)start the service."
    }
}