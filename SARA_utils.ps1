
# Jul 8th 2019
function Call-AnalysisAPI
{
    [cmdletbinding()]
    Param(
        [ValidateSet('userInfo','tenantInfo','cloudCheck')]
        [String]$Command,
        [Parameter(Mandatory=$True)]
        [String]$AccessToken,
        [Parameter(Mandatory=$True)]
        [String]$Body,
        [Parameter(Mandatory=$False)]
        [String]$Url="https://api.diagnostics.office.com/v1/analysis"
    )
    Process
    {
        
        $headers =@{
                "Content-Type" = "application/json;odata=verbose"
                "Accept" = "application/json; charset=utf-8"
                "Authorization" = $(Create-AuthorizationHeader -AccessToken $AccessToken -ClientId "d3590ed6-52b3-4102-aeff-aad2292ab01c" -Resource "https://api.diagnostics.office.com")
                "x-ms-sara-api-version" = "schema-v1"
                "User-Agent" = "saraclient"

        }
        
        try
        {
            $response = Invoke-RestMethod -UseBasicParsing -Uri $url -Method Post -Body $body -Headers $headers
        
        }
        catch
        {
            # Okay, something went wrong
            return $null
        }

        if($url.EndsWith("/analysis"))
        {
            $sessionId = $response.SessionId
        }
        else
        {
            $sessionId = $response.RequestId
        }

        while($response.RequestStatus -ne "Completed" -and $response.RequestStatus -ne "Failed")
        {
            Write-Verbose "Retrieving information.."
            if($response.ProcessingStatus -eq "Queued")
            {
                Start-Sleep -Seconds "2"
            }
            $response = Invoke-RestMethod -UseBasicParsing -Uri "$url/?id=$sessionId" -Method Get -Headers $headers
        }

        # Return
        $response
    }
}




			