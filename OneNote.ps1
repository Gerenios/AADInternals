# Speaks out the given text.
# Feb 22nd 2022
function Start-Speech
{
<#
    .SYNOPSIS
    Gets mp3 stream of the given text and plays it with Media player.

    .DESCRIPTION
    Gets mp3 stream of the given text using learning tools API and plays it with Media player.

    .Parameter AccessToken
    The access token used to get the speech.

    .Parameter Language
    The language code. Defaults to "en-US"

    .Parameter PreferredVoice
    Male or Female voice, defaults to Female.

    .Parameter Text
    The text to speak.

    .Example
    PS C:\>Get-AADIntAccessTokenForOneNote -SaveToCache
    PS C:\>Start-AADIntSpeech -Text "Three Swedish switched witches watch three Swiss Swatch watch switches. Which Swedish switched witch watch which Swiss Swatch watch switch?" -Language "en-GB" -PreferredVoice Male

    .Example
    PS C:\>Get-AADIntAccessTokenForOneNote -SaveToCache
    PS C:\>Start-AADIntSpeech -Text "Mustan kissan paksut posket" -PreferredVoice Female -Language fi-FI

#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$False)]
        [String]$AccessToken,
        [Parameter(Mandatory=$True)]
        [String]$Text,
        [Parameter(Mandatory=$False)]
        [String]$Language = "en-US",
        [Parameter(Mandatory=$False)]
        [ValidateSet("Female","Male")]
        [String]$PreferredVoice = "Female"
    )
    Process
    {
        # Get from cache if not provided
        $AccessToken = Get-AccessTokenFromCache -AccessToken $AccessToken -Resource "https://onenote.com" -ClientId "1fec8e78-bce4-4aaf-ab1b-5451cc387264"

        # Construct the body
        $body = @{
            "data" = [ordered]@{
                "title" = "The King's Speech"
                "chunks" = @(
                    [ordered]@{
                        "content"  = $Text
                        "mimeType" = "text/plain"
                    }
                )
                "startingChunkIndex" = 0
		        "startingCharIndex"  = 0
            }
        }

        # Set the headers
        $headers=@{
            "Authorization" = "Bearer $AccessToken"
            "Accept-Language" = $Language
            "MS-Int-AppId" = "Teams"
        }

        # Invoke the command 
        $contentModel = Invoke-RestMethod -UseBasicParsing -Method Post -Uri "https://learningtools.onenote.com/learningtoolsapi/v2.0/getcontentmodelforreader" -Headers $headers -Body ($body | ConvertTo-Json -Depth 5) -ContentType "application/json; charset=utf-8"

        # Construct the body
        $body = [ordered]@{
            "data" = [ordered]@{
                "sentenceModels" = @(
                    [ordered]@{
                        "t"  = $Text
                        "lang" = $Language
                        "se" = $contentModel.data[0].formatting.b.r[0].i[0]
                        "wo" = @()
                    }
                )
            }
            "options" = [ordered]@{
                "preferredVoice" = $PreferredVoice
                "extractWordMarkers" = $True
		        "encoding" = "Wav"
		        "clientLabel" = "ReadAloudFirstPrefetch"
		        "useBrowserSpecifiedDialect" = $True
            }
        }

        # Set the headers
        $headers=@{
            "Authorization" = "MS-SessionToken $($contentModel.meta.sessionToken)"
            "X-UserSessionId" = $contentModel.meta.sessionId
            "Accept-Language" = $Language
            "MS-Int-AppId" = "Teams"
        }

        # Invoke the command  
        $response = Invoke-RestMethod -UseBasicParsing -Method Post -Uri "https://learningtools.onenote.com/learningtoolsapi/v2.0/GetSpeech" -Headers $headers -Body ($body | ConvertTo-Json -Depth 5) -ContentType "application/json"

        $mp3B64 = $response.data.sb[0].ad.Split(",")[1]

        # Create a temporary file
        $tmp = New-TemporaryFile
        Rename-Item -Path $tmp.FullName -NewName ($tmp.Name+".mp3")
        $mp3 = ($tmp.FullName+".mp3")
        
        try
        {
            Set-BinaryContent -Path $mp3 -Value (Convert-B64ToByteArray -B64 $mp3B64)

            $player = [System.Windows.Media.MediaPlayer]::new()
            $player.Open($mp3)
            # Pause for a while to populate the duration
            Start-Sleep -Milliseconds 100
            $player.Play()

            # Wait till completed
            while($player.Position -lt $player.NaturalDuration.TimeSpan)
            {
                Start-Sleep -Milliseconds 10
            }
            $player.Close()
        }
        catch
        {
        }
        finally
        {
            # Remove the temp file
            Remove-Item $mp3
        }
    }
}
