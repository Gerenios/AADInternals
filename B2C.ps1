# Creates a new B2CToken
# Sep 12th 2023
Function New-B2CToken
{
    [cmdletbinding()]

    param(
        [Parameter(Mandatory=$True)]
        [string]$Tenant,
        [Parameter(Mandatory=$True)]
        [string]$Policy,
        [Parameter(Mandatory=$True)]
        [guid]$ClientId,
        [Parameter(Mandatory=$True)]
        [guid]$UserId,

        [Parameter(Mandatory=$False)]
        [ValidateSet("authorization_code","refresh_token")]
        [string]$Type = "refresh_token",

        [Parameter(Mandatory=$False)]
        [System.Security.Cryptography.RSA]$PublicKey,

        [Parameter(Mandatory=$False)]
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate,

        [Parameter(Mandatory=$False)]
        [string]$PfxFileName,
        [Parameter(Mandatory=$False)]
        [string]$PfxPassword,
        [Parameter(Mandatory=$False)]
        [string]$KeyId,
        [Parameter(Mandatory=$False)]
        [System.Collections.Hashtable]$Claims,

        [Parameter(Mandatory=$True)]
        [DateTime]$NotBefore,
        [Parameter(Mandatory=$True)]
        [DateTime]$ExpiresOn
    )
    process
    {
        # Get the public key from certificate if not provided
        if(!$PublicKey)
        {
            # Load certificate if not provided
            if(!$Certificate)
            {
                $Certificate = Load-Certificate -FileName $PfxFileName -Password $PfxPassword -Exportable
            }

            $PublicKey = $Certificate.PublicKey.Key
        }

        # Get the tenant name
        if(($parts = $Tenant.Split(".")).Count -gt 1)
        {
            $Tenant = $parts[0]
        }

        # Type
        # 1 = authorization_code
        # 2 = refresh_token
        $t = 1
        if($Type -eq "refresh_token")
        {
            $t = 2
        }

        # Create the claims block
        $claimValues = @()
        if($Claims)
        {
            foreach($key in $Claims.Keys)
            {
                $claimValues += @{
                    "claimTypeId" = $key
                    "value"       = $Claims[$key] 
                }
            }
        }

        # Create the token (minimal working)
        $B2Ctoken = [ordered]@{
	        "tid"   = "$Tenant.onmicrosoft.com"
	        "pid"   = $Policy
	        "t"     = $t
            "cls"   = @{
		        "`$id" = "1"
		        "`$values" = $claimValues
	            }
	        "o_aud" = $ClientId.ToString()
	        "o_iat" = [int]($NotBefore-$epoch).TotalSeconds
	        "iat"   = [int]($NotBefore-$epoch).TotalSeconds
	        "exp"   = [int]($ExpiresOn-$epoch).TotalSeconds
	        "avm"   = "V2.0"
	        "rcc"   = $true
	        "uid"   = $UserId
        }

        # Create the payload: convert to unicode and deflate
        $payload = Get-DeflatedByteArray -byteArray ([text.encoding]::Unicode.getBytes( ($B2Ctoken | ConvertTo-Json -Depth 10 -Compress ))) 

        # Create the header
        $header = [ordered]@{
            "kid"="$KeyId"
            "ver"="1.0"
            "zip"= "Deflate"
            "ser" ="1.0"
        }

        # Create the JWE
        New-JWE -PublicKey $publicKey -Payload $payload -Header ($header | ConvertTo-Json -Depth 10 -Compress)
    }
}


# Creates a new B2C refresh token
# Sep 12th 2023
Function New-B2CRefreshToken
{
<#
    .SYNOPSIS
    Creates a new B2C refresh token using the provided public key.

    .DESCRIPTION
    Creates a new B2C refresh token using the provided public key.
    
    .Parameter Certificate
    A certificate which public key is used to encrypt the refresh token.

    .PARAMETER Claims
    A hashtable of claims (key & value) to be added to the refresh token.

    .PARAMETER ClientId
    Client id of the application

    .PARAMETER ExpiresOn
    Date time when the refresh token expires

    .PARAMETER KeyId
    Id of the public key.

    .PARAMETER NotBefore
    Date time after when the refresh token is active

    .PARAMETER PfxFileName
    File name of the certificate .pfx file

    .PARAMETER PfxPassword
    Password of the certificate .pfx file

    .PARAMETER Policy
    Policy id of the Identity Experience Framework policy.

    .PARAMETER Tenant
    Name of the B2C (without .b2clogin.com)

    .PARAMETER UserId
    User's Entra ID object ID

    .Example
    $keys = Get-AADIntB2CEncryptionKeys
    PS C:\>$refresh_token = New-AADIntB2CRefreshToken -Tenant "companyb2c" -ClientId "00364d2a-695e-49e6-b5ef-377276103dc2" -UserId "910e4c2f-1396-434c-aa8e-1bcf8883376a" -Policy "B2C_1A_signup_signin" -PublicKey $keys[1].Key -KeyId $keys[1].Id
#>
    [cmdletbinding()]

    param(
        [Parameter(Mandatory=$True)]
        [string]$Tenant,
        [Parameter(Mandatory=$True)]
        [string]$Policy,
        [Parameter(Mandatory=$True)]
        [guid]$ClientId,
        [Parameter(Mandatory=$True)]
        [guid]$UserId,

        [Parameter(ParameterSetName='PublicKey',Mandatory=$True)]
        [System.Security.Cryptography.RSA]$PublicKey,

        [Parameter(ParameterSetName='Certificate',Mandatory=$True)]
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate,

        [Parameter(ParameterSetName='FileAndPassword',Mandatory=$True)]
        [string]$PfxFileName,
        [Parameter(ParameterSetName='FileAndPassword',Mandatory=$False)]
        [string]$PfxPassword,
        [Parameter(Mandatory=$False)]
        [string]$KeyId,
        [Parameter(Mandatory=$False)]
        [System.Collections.Hashtable]$Claims,

        [Parameter(Mandatory=$False)]
        [DateTime]$NotBefore = ((Get-Date).ToUniversalTime()),
        [Parameter(Mandatory=$False)]
        [DateTime]$ExpiresOn = ($NotBefore.AddDays(14))
    )
    process
    {
        $arguments = @{ 
            "Tenant"      = $Tenant
            "ClientId"    = $ClientId
            "UserId"      = $UserId
            "Policy"      = $Policy
            "Certificate" = $Certificate
            "PfxFileName" = $PfxFileName
            "PfxPassword" = $PfxPassword
            "KeyId"       = $KeyId
            "Type"        = "refresh_token"
            "Claims"      = $Claims
            "NotBefore"   = $NotBefore
            "ExpiresOn"   = $ExpiresOn
            "PublicKey"   = $PublicKey
        }

        New-B2CToken @arguments
    }
}

# Creates a new B2C refresh token
# Sep 12th 2023
Function New-B2CAuthorizationCode
{
<#
    .SYNOPSIS
    Creates a new B2C authorization code using the provided public key.

    .DESCRIPTION
    Creates a new B2C authorization code using the provided public key.
    
    .Parameter Certificate
    A certificate which public key is used to encrypt the authorization code.

    .PARAMETER Claims
    A hashtable of claims (key & value) to be added to the authorization code.

    .PARAMETER ClientId
    Client id of the application

    .PARAMETER ExpiresOn
    Date time when the authorization code expires

    .PARAMETER KeyId
    Id of the public key.

    .PARAMETER NotBefore
    Date time after when the authorization code is active

    .PARAMETER PfxFileName
    File name of the certificate .pfx file

    .PARAMETER PfxPassword
    Password of the certificate .pfx file

    .PARAMETER Policy
    Policy id of the Identity Experience Framework policy.

    .PARAMETER Tenant
    Name of the B2C (without .b2clogin.com)

    .PARAMETER UserId
    User's Entra ID object ID

    .Example
    $keys = Get-AADIntB2CEncryptionKeys
    PS C:\>$authorization_code = New-AADIntB2CAuthorizationCode -Tenant "companyb2c" -ClientId "00364d2a-695e-49e6-b5ef-377276103dc2" -UserId "910e4c2f-1396-434c-aa8e-1bcf8883376a" -Policy "B2C_1A_signup_signin" -PublicKey $keys[1].Key -KeyId $keys[1].Id
#>
    [cmdletbinding()]

    param(
        [Parameter(Mandatory=$True)]
        [string]$Tenant,
        [Parameter(Mandatory=$True)]
        [string]$Policy,
        [Parameter(Mandatory=$True)]
        [guid]$ClientId,
        [Parameter(Mandatory=$True)]
        [guid]$UserId,

        [Parameter(ParameterSetName='PublicKey',Mandatory=$True)]
        [System.Security.Cryptography.RSA]$PublicKey,

        [Parameter(ParameterSetName='Certificate',Mandatory=$True)]
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate,

        [Parameter(ParameterSetName='FileAndPassword',Mandatory=$True)]
        [string]$PfxFileName,
        [Parameter(ParameterSetName='FileAndPassword',Mandatory=$False)]
        [string]$PfxPassword,
        [Parameter(Mandatory=$False)]
        [string]$KeyId,
        [Parameter(Mandatory=$False)]
        [System.Collections.Hashtable]$Claims,

        [Parameter(Mandatory=$False)]
        [DateTime]$NotBefore = ((Get-Date).ToUniversalTime()),
        [Parameter(Mandatory=$False)]
        [DateTime]$ExpiresOn = ($NotBefore.AddDays(14))
    )
    process
    {
        $arguments = @{ 
            "Tenant"      = $Tenant
            "ClientId"    = $ClientId
            "UserId"      = $UserId
            "Policy"      = $Policy
            "Certificate" = $Certificate
            "PfxFileName" = $PfxFileName
            "PfxPassword" = $PfxPassword
            "KeyId"       = $KeyId
            "Type"        = "authorization_code"
            "Claims"      = $Claims
            "NotBefore"   = $NotBefore
            "ExpiresOn"   = $ExpiresOn
            "PublicKey"   = $PublicKey
        }

        New-B2CToken @arguments
    }
}