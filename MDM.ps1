# This file contains functions for Intune MDM

# Enroll device to Intune MDM
# Aug 29th
function Join-DeviceToIntune
{
<#
    .SYNOPSIS
    Registers (enrolls) the given device to Azure AD.

    .DESCRIPTION
    Enrolls the given device to Azure AD and generates a corresponding certificate.

    After enrollment, the device is in compliant state, which allows bypassing conditional access (CA) restrictions based on the compliance.

    The certificate has no password.

    .Parameter AccessToken
    The access token used to enroll the device. Must have deviceid claim!
    If not given, will be prompted.

    .Parameter DeviceName
    The name of the device to be registered.

    .EXAMPLE
    Get-AADIntAccessTokenForIntuneMDM -PfxFileName .\d03994c9-24f8-41ba-a156-1805998d6dc7.pfx -SaveToCache
    PS\:>Join-AADIntDeviceToIntune -DeviceName "My computer"

    Intune client certificate successfully created:
      Subject:         "CN=5ede6e7a-7b77-41bd-bfe0-ef29ca70a3fb"
      Issuer:          "CN=Microsoft Intune MDM Device CA"
      Cert thumbprint: A1D407FF66EF05D153B67129B8541058A1C395B1
      Cert file name:  "226fb636-a2e3-4235-976a-040a8cb28fde-MDM.pfx"
      CA file name :   "226fb636-a2e3-4235-976a-040a8cb28fde-MDM-CA.der"
      IntMedCA file :  "226fb636-a2e3-4235-976a-040a8cb28fde-MDM-INTMED-CA.der"

#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$False)]
        [String]$AccessToken,
        [Parameter(Mandatory=$True)]
        [String]$DeviceName
    )
    Process
    {
        # Get from cache if not provided
        $AccessToken = Get-AccessTokenFromCache -AccessToken $AccessToken -ClientID "29d9ed98-a469-4536-ade2-f981bc1d605e" -Resource "https://enrollment.manage.microsoft.com/"

        # Get the claims
        $claims = Read-Accesstoken -AccessToken $AccessToken
        
        if(!$claims.deviceid)
        {
            throw "No device id included in access token! Use Get-AADIntAccessTokenForIntuneMDM with the device certificate and try again."
        }

        $joinInfo = Enroll-DeviceToMDM -AccessToken $AccessToken -DeviceName $DeviceName

        # Get the certificates
        $CA =                $joinInfo[0]
        $IntMedCA =          $joinInfo[1]
        $clientCertificate = $joinInfo[2]
        
        $clientCertificate.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Pfx) | Set-Content "$($claims.deviceid)-MDM.pfx" -Encoding Byte
        
        $CA       | Set-Content "$($claims.deviceid)-MDM-CA.der"
        $IntMedCA | Set-Content "$($claims.deviceid)-MDM-INTMED-CA.der"

        # Unload the private key
        Unload-PrivateKey -PrivateKey $clientCertificate.privateKey

        # Print out information
        Write-Host "Intune client certificate successfully created:"
        Write-Host "  Subject:         ""$($clientCertificate.Subject)"""
        Write-Host "  Issuer:          ""$($clientCertificate.Issuer)"""
        Write-Host "  Cert thumbprint: $($clientCertificate.Thumbprint)"
        Write-host "  Cert file name:  ""$($claims.deviceid)-MDM.pfx"""
        Write-host "  CA file name :   ""$($claims.deviceid)-MDM-CA.der"""
        Write-host "  IntMedCA file :  ""$($claims.deviceid)-MDM-INTMED-CA.der"""
            
    }
}