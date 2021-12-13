# This file contains utility functions for MS Partner operations.

# Invoke parter api
# Aug 27th 2021
function Invoke-MSPartnerAPI
{
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [String]$AccessToken,
        [Parameter(Mandatory=$False)]
        $Body,
        [Parameter(Mandatory=$True)]
        [String]$Url,
        [Parameter(Mandatory=$True)]
        [ValidateSet('Get','Post','Patch','Put')]
        [String]$Method
    )
    Process
    {
        # Get from cache if not provided
        $AccessToken = Get-AccessTokenFromCache -AccessToken $AccessToken -Resource "fa3d9a0c-3fb0-42cc-9193-47c7ecd2edbd" -ClientId "d3590ed6-52b3-4102-aeff-aad2292ab01c"

        # Set the headers
        $headers=@{
            "Authorization"             = "Bearer $AccessToken"
            "ocp-apim-subscription-key" = "c306f5dd740f4946920822865932a356"
            "MS-PartnerCenter-Client"   = "Partner Center Web"
        }

        # Invoke the command with Invoke-WebRequest so we can remove BOM
        $response = Invoke-WebRequest -UseBasicParsing -Method $Method -Uri "https://api.partnercenter.microsoft.com/$Url" -Headers $headers -Body $body

        $responseBytes = New-Object byte[] $response.RawContentLength
        $response.RawContentStream.Read($responseBytes,0,$response.RawContentLength) | Out-Null

        # Strip the BOM and convert to json
        [text.encoding]::UTF8.getString([byte[]](Remove-BOM -ByteArray $responseBytes)) | ConvertFrom-Json


    }
}
