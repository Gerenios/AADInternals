# Utility functions for OneDrive native client

# OneDrive settings class
class OneDriveSettings {
    [string]$Url
    [string]$AuthenticationCookie
    [string]$DefaultDocumentLibraryId
    [string]$DownloadUrlTemplate
    [int]$ItemCount
}

# Gets the authentication cookie for OneDrive native client
# Nov 26th 2019
function Get-ODAuthenticationCookie
{
<#
    .SYNOPSIS
    Gets authentication cookie for OneDrive

    .DESCRIPTION
    Gets authentication cookie for OneDrive native client

    .Parameter AccessToken
    AccessToken for OneDrive
    
    .Example
    Get-AADIntODAuthenticationCookie
#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [String]$AccessToken
    )
    Process
    {
        # Get the tenant url
        $tenant = ((Read-Accesstoken $AccessToken).aud.Split("/"))[2]

        $url = "https://$tenant/_api/SP.OAuth.NativeClient/Authenticate?client-request-id=$((New-Guid).toString())"
        
        
        $headers=@{
                "Authorization" = "Bearer $AccessToken"
                "Accept"= "application/json;odata=verbose"
                "User-Agent"="Microsoft SkyDriveSync 19.192.0926.0012 ship; Windows NT 10.0 (17763)"
                "X-GeoMoveOptions" = "HttpRedirection"
                "X-IDCRL_ACCEPTED" ="t"
                "X-UserScenario"= "AUO,SignIn"
                

        }

        # Call the authentication API
        $response = Invoke-WebRequest -uri $url -MaximumRedirection 0 -ErrorAction SilentlyContinue -Method Post -ContentType "application/x-www-form-urlencoded" -Headers $headers
        
        # Return the SPOIDCRL cookie
        ($response.headers["Set-Cookie"].split(";"))[0]

    }
}

# Invokes the OD API commands
# Nov 26th
function Invoke-ODCommand
{
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$True)]
        $OneDriveSettings,
        [Parameter(Mandatory=$True)]
        [String]$Command,
        [Parameter(Mandatory=$False)]
        [String]$Accept="application/json;odata=verbose",
        [Parameter(Mandatory=$False)]
        [String]$Scenario="AUO,SignIn",
        [Parameter(Mandatory=$False)]
        [byte[]]$Body,
        [Parameter(Mandatory=$False)]
        $headers=@{},
        [Parameter(Mandatory=$False)]
        [Switch]$UseStreamReader,
        [Parameter(Mandatory=$False)]
        [PSObject][ref]$ResponseHeaders,
        [Parameter(Mandatory=$False)]
        [boolean]$Mac=$False

    )
    Process
    {
        # Set the headers
        $headers["Accept"] = $Accept

        if($MAC)
        {
            $headers["User-Agent"] = "Microsoft SkyDriveSync 20.169.0823.0006 ship; Mac OS X 10.15.7"
        }
        else
        {
            $headers["User-Agent"] = "Microsoft SkyDriveSync 19.192.0926.0012 ship; Windows NT 10.0 (17763)"
        }

        if(![string]::IsNullOrEmpty($Scenario))
        {
            $headers["X-UserScenario"] = $Scenario 
        }

        # Create a web session for the authentication cookie
        $session = New-Object Microsoft.PowerShell.Commands.WebRequestSession
        $webCookie = New-Object System.Net.Cookie
        $webCookie.Name = ($OneDriveSettings.AuthenticationCookie.Split("="))[0]
        $webCookie.Value = $OneDriveSettings.AuthenticationCookie.Substring($webCookie.Name.Length + 1)
        $webCookie.Domain = ($OneDriveSettings.Url.Split("/"))[2]
        $session.Cookies.Add($webCookie)

        # Create the url
        $url = $OneDriveSettings.Url
        $url += $Command

        # Call the  API
        try
        {
            if($UseStreamReader)
            {
                if($Body -ne $null)
                {
                    $fullResponse = Invoke-WebRequest -uri $url -Method Post -Headers $headers -WebSession $session -Body $Body
                }
                else
                {
                    $fullResponse = Invoke-WebRequest -uri $url -Method Get -Headers $headers -WebSession $session
                }

                $response = [System.IO.StreamReader]::new($fullResponse.RawContentStream, [System.Text.Encoding]::UTF8).ReadToEnd()
                if($ResponseHeaders -ne $null)
                {
                    $ResponseHeaders.Value = $fullResponse.headers
                }
            }
            else
            {
                $response = Invoke-RestMethod -uri $url -Method Get -Headers $headers -WebSession $session
            }
        }
        catch
        {
            if($_.Exception -like "*(501)*")
            {
                Write-Error "Got 501 - try using a -Mac switch or proper domain guid"
            }
            elseif($Body -ne $null -and $_.Exception -like "*(403)*" -and $ResponseHeaders -ne $null)
            {
                # This is part of the normal file upload flow
                $ResponseHeaders.Value = $_.Exception.Response.Headers
            }
            else
            {
                Write-Error $_.Exception
            }

            return
        }

        # Return
        $response 
    }
}


# Creates an OneDrive settings object to be used in OneDrive functions
function New-OneDriveSettings
{
<#
    .SYNOPSIS
    Creates a new OneDriveSettings object

    .DESCRIPTION
    Creates a new OneDriveSettings object used with OneDrive functions

    .Example
    $os = New-AADIntOneDriveSettings
    PS C:\> Get-AADIntOneDriveFiles -OneDriveSettings $os | Format-Table

    Path                              Size  Created            Modified           ResourceID                   
    ----                              ----  -------            --------           ----------                   
    \RootFolder\Document1.docx        11032 2.12.2019 20.47.23 2.12.2019 20.48.46 5e7acf393a2e45f18c1ce6caa7...
    \RootFolder\Book.xlsx             8388  2.12.2019 20.49.14 2.12.2019 20.50.14 b26c0a38d4d14b23b785576e29...
    \RootFolder\Docs\Document1.docx   84567 9.12.2019 11.24.40 9.12.2019 12.17.50 d9d51e47b66c4805aff3a08763...
    \RootFolder\Docs\Document2.docx   31145 7.12.2019 17.28.37 7.12.2019 17.28.37 972f9c317e1e468fb2b6080ac2...
#>
    [cmdletbinding()]
    Param(
        [Parameter(ParameterSetName='Credentials',Mandatory=$False)]
        [System.Management.Automation.PSCredential]$Credentials,
        [Parameter(ParameterSetName='SAML',Mandatory=$True)]
        [String]$SAMLToken,
        [Parameter(ParameterSetName='Kerberos',Mandatory=$True)]
        [String]$KerberosTicket,
        [Parameter(ParameterSetName='Kerberos',Mandatory=$True)]
        [String]$Domain
    )
    Process
    {
        # Create a new settings object
        $ODSettings=[OneDriveSettings]::new()

        # Get AccessToken for OfficeApps
        $OAtoken=Get-AccessToken -Resource "https://officeapps.live.com" -ClientId "ab9b8c07-8f02-4f72-87fa-80105867a763" -KerberosTicket $KerberosTicket -Domain $Domain -SAMLToken $SAMLToken -Credentials $Credentials -IncludeRefreshToken $true

        # Get the connection details
        $connections = Get-UserConnections -AccessToken $OAtoken[0]

        # Get the url
        foreach($connection in $connections)
        {
            if($connection.EnabledCapabilities -eq 2051) # Should be OneDrive
            {
                $url = $connection.ConnectionUrl
                # Strip the "/Documents" from the end of the url
                $ODSettings.Url = $url.Substring(0,$url.LastIndexOf("/"))
                break
            }
        }

        if([string]::IsNullOrEmpty($ODSettings.Url))
        {
            # The user doesn't have onedrive :(
            $upn = (Read-Accesstoken $OAtoken[0]).upn
            Write-Error "The user $upn doesn't have OneDrive :("
            return
        }

        # Get AccessToken for OneDrive
        $ODtoken=Get-AccessTokenWithRefreshToken -Resource "https://$(($ODSettings.Url.Split("/"))[2])" -ClientId "ab9b8c07-8f02-4f72-87fa-80105867a763" -RefreshToken $OAtoken[1] -TenantId ((Read-Accesstoken -AccessToken $OAtoken[0]).tid)

        # Get the authentication cookie
        $ODSettings.AuthenticationCookie = Get-ODAuthenticationCookie -AccessToken $ODtoken

        # Get the document library id
        $ODSettings.DefaultDocumentLibraryId = Get-ODDefaultDocLibId -OneDriveSettings $ODSettings

        # Get the sync policy
        $syncPolicy = Get-ODSyncPolicy -OneDriveSettings $ODSettings

        # Set the download url template
        $dlUrl = $syncPolicy.DownloadUrlTemplate
        $ODSettings.DownloadUrlTemplate = $dlUrl.Substring(0,$dlUrl.IndexOf("{"))

        # Set the ItemCount
        $ODSettings.ItemCount = [int]$syncPolicy.ItemCount

        # return
        $ODSettings
    }
}

# QuickXorHash by Microsoft https://docs.microsoft.com/en-us/onedrive/developer/code-snippets/quickxorhash
# Dec 9th 2019
$xorhash_code = @"
using System;

public class QuickXorHash : System.Security.Cryptography.HashAlgorithm
{
    private const int BitsInLastCell = 32;
    private const byte Shift = 11;
    private const int Threshold = 600;
    private const byte WidthInBits = 160;

    private UInt64[] _data;
    private Int64 _lengthSoFar;
    private int _shiftSoFar;

    public QuickXorHash()
    {
        this.Initialize();
    }

    protected override void HashCore(byte[] array, int ibStart, int cbSize)
    {
        unchecked
        {
            int currentShift = this._shiftSoFar;

            // The bitvector where we'll start xoring
            int vectorArrayIndex = currentShift / 64;

            // The position within the bit vector at which we begin xoring
            int vectorOffset = currentShift % 64;
            int iterations = Math.Min(cbSize, QuickXorHash.WidthInBits);

            for (int i = 0; i < iterations; i++)
            {
                bool isLastCell = vectorArrayIndex == this._data.Length - 1;
                int bitsInVectorCell = isLastCell ? QuickXorHash.BitsInLastCell : 64;

                // There's at least 2 bitvectors before we reach the end of the array
                if (vectorOffset <= bitsInVectorCell - 8)
                {
                    for (int j = ibStart + i; j < cbSize + ibStart; j += QuickXorHash.WidthInBits)
                    {
                        this._data[vectorArrayIndex] ^= (ulong)array[j] << vectorOffset;
                    }
                }
                else
                {
                    int index1 = vectorArrayIndex;
                    int index2 = isLastCell ? 0 : (vectorArrayIndex + 1);
                    byte low = (byte)(bitsInVectorCell - vectorOffset);

                    byte xoredByte = 0;
                    for (int j = ibStart + i; j < cbSize + ibStart; j += QuickXorHash.WidthInBits)
                    {
                        xoredByte ^= array[j];
                    }
                    this._data[index1] ^= (ulong)xoredByte << vectorOffset;
                    this._data[index2] ^= (ulong)xoredByte >> low;
                }
                vectorOffset += QuickXorHash.Shift;
                while (vectorOffset >= bitsInVectorCell)
                {
                    vectorArrayIndex = isLastCell ? 0 : vectorArrayIndex + 1;
                    vectorOffset -= bitsInVectorCell;
                }
            }

            // Update the starting position in a circular shift pattern
            this._shiftSoFar = (this._shiftSoFar + QuickXorHash.Shift * (cbSize % QuickXorHash.WidthInBits)) % QuickXorHash.WidthInBits;
        }

        this._lengthSoFar += cbSize;
    }

    protected override byte[] HashFinal()
    {
        // Create a byte array big enough to hold all our data
        byte[] rgb = new byte[(QuickXorHash.WidthInBits - 1) / 8 + 1];

        // Block copy all our bitvectors to this byte array
        for (Int32 i = 0; i < this._data.Length - 1; i++)
        {
            Buffer.BlockCopy(
                BitConverter.GetBytes(this._data[i]), 0,
                rgb, i * 8,
                8);
        }

        Buffer.BlockCopy(
            BitConverter.GetBytes(this._data[this._data.Length - 1]), 0,
            rgb, (this._data.Length - 1) * 8,
            rgb.Length - (this._data.Length - 1) * 8);

        // XOR the file length with the least significant bits
        // Note that GetBytes is architecture-dependent, so care should
        // be taken with porting. The expected value is 8-bytes in length in little-endian format
        var lengthBytes = BitConverter.GetBytes(this._lengthSoFar);
        System.Diagnostics.Debug.Assert(lengthBytes.Length == 8);
        for (int i = 0; i < lengthBytes.Length; i++)
        {
            rgb[(QuickXorHash.WidthInBits / 8) - lengthBytes.Length + i] ^= lengthBytes[i];
        }

        return rgb;
    }

    public override sealed void Initialize()
    {
        this._data = new ulong[(QuickXorHash.WidthInBits - 1) / 64 + 1];
        this._shiftSoFar = 0;
        this._lengthSoFar = 0;
    }

    public override int HashSize
    {
        get
        {
            return QuickXorHash.WidthInBits;
        }
    }
}
"@
Add-Type -TypeDefinition $xorhash_code -Language CSharp	
Remove-Variable $xorhash_code


# Calculates XorHash for OneDrive files
# Dec 9th 2019
function Get-XorHash
{
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [string]$FileName
    )
    Process
    {
        # Get the full path..
        $fullpath = (Get-Item $FileName).FullName

        # Create a stream to read bytes
        $stream = [System.IO.FileStream]::new($fullpath,[System.IO.FileMode]::Open,[System.IO.FileAccess]::Read)

        # Create the hash object and do the magic
        $xorhash = [quickxorhash]::new()
        $hash = $xorhash.ComputeHash($stream)
        $b64Hash = [convert]::ToBase64String($hash)   

        # Return
        $b64Hash
    }
}