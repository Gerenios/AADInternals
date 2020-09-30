# Starts Azure Cloud Shell session
# Sep 8th 2020
function Start-CloudShell
{
<#
    .SYNOPSIS
    Starts an Azure Cloud Shell session.

    .DESCRIPTION
    Starts an Azure Cloud Shell session for the given user.
    Note: Does not work with VSCode or ISE.

    .Parameter AccessToken
    The access token used to start the session.

    .EXAMPLE
    Get-AADIntAccessTokenForCloudShell -SaveToCache
    PS\:>Start-AADIntCloudShell
#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$False)]
        [String]$AccessToken,
        [ValidateSet('PowerShell','Bash')]
        [String]$Shell="PowerShell"
    )
    Process
    {
        # Get from cache if not provided
        $AccessToken = Get-AccessTokenFromCache -AccessToken $AccessToken -Resource "https://management.core.windows.net/" -ClientId "0c1307d4-29d6-4389-a11c-5cbe7f65d7fa"

        if(!$host.UI.SupportsVirtualTerminal)
        {
            Write-Error "PowerShell ISE or VSCode not supported!"
            return
        }

        try
        {
            # Get the shell info
            $shellInfo = New-CloudShell -AccessToken $AccessToken
            Write-Verbose "Created shell $($shellInfo.uri)"

            # Get the authorization code
            $authToken = Get-CloudShellAuthToken -AccessToken $AccessToken -Url $shellInfo.uri
            Write-Verbose "Received auth-token $authToken"

            # Get the settings
            $settings = Get-CloudShellSettings -AccessToken $AccessToken -Url $shellInfo.uri -Shell $Shell
            Write-Verbose "Received cloud shell settings"
        }
        catch
        {
            Write-Error "Failed to connect to Cloud Shell $($_.Message)"
            return
        }

        # Save the current setting for Ctrl+C 
        $CtrlC = [console]::TreatControlCAsInput

        Try
        {
            $url = $settings.socketUri
           
            # Create the socket and keep alive
            $socket = New-Object System.Net.WebSockets.ClientWebSocket

            # Set the cookies
            $cookiec = [System.Net.CookieContainer]::new(1)
            $cookie =  [System.Net.Cookie]::new("auth-token", $authToken)
            $cookie.Domain = ".console.azure.com"
            $cookiec.Add($cookie)
            $socket.Options.Cookies = $cookiec

            # Create the token and open the connection
            $token = New-Object System.Threading.CancellationToken                                                   
            $connection = $socket.ConnectAsync($url, $token)

            Write-Verbose "Connecting to socket $($settings.socketUri)"

            # Wait 'till the connection is completed
            While (!$connection.IsCompleted) { Start-Sleep -Milliseconds 100 }

            if($connection.IsFaulted -eq "True")
            {
                Write-Error $connection.Exception
                return
            }

            Write-Verbose "Connected to socket."

            # Buffer for the content
            $buffer = New-Object Byte[] 1024
            $socket_in = $Socket.ReceiveAsync($buffer, $Token)

            # Clear the console and set the Ctlr+C to be used as an input (so that we can stop things running in cloud)
            [console]::TreatControlCAsInput = $true
            [console]::Clear()

                
            # The main loop
            do
            {
                # If the read is completed, print it to console and start another read
                if($socket_in.IsCompleted)
                {
                    $retVal = $buffer[0..$($socket_in.Result.Count-1)]

                    $text = [text.encoding]::UTF8.GetString($retVal)

                    [console]::Write($text)
                    
                    $socket_in = $Socket.ReceiveAsync($buffer, $Token)
                }

                # Read the key if available 
                if([console]::KeyAvailable)
                {
                    $key = [console]::ReadKey($True)

                    # https://docs.microsoft.com/en-us/windows/console/console-virtual-terminal-sequences
                    switch($key.Key)
                    {
                        "Insert"     { $keyBytes = [byte[]]@(27,91,50,126) }
                        "Delete"     { $keyBytes = [byte[]]@(27,91,51,126) }
                        "PageUp"     { $keyBytes = [byte[]]@(27,91,53,126) }
                        "PageDown"   { $keyBytes = [byte[]]@(27,91,54,126) }

                        "UpArrow"    { $keyBytes = [byte[]]@(27,79,65) }
                        "DownArrow"  { $keyBytes = [byte[]]@(27,79,66) }
                        "RightArrow" { $keyBytes = [byte[]]@(27,79,67) }
                        "LeftArrow"  { $keyBytes = [byte[]]@(27,79,68) }
                        "Home"       { $keyBytes = [byte[]]@(27,79,72) }
                        "End"        { $keyBytes = [byte[]]@(27,79,70) }
                        default      { $keyBytes = [text.encoding]::UTF8.GetBytes($key.KeyChar) }
                    }

                    SendToSocket -Socket $socket -Token $token -Bytes $keyBytes
                }

            } Until (!$connection -or $socket_in.IsFaulted -eq "True")
           
        }
        Catch
        {
            Write-Error $_
        }
        Finally
        {

            # Return the original Ctrl+C
            [console]::TreatControlCAsInput = $CtrlC

            If ($socket) { 
                Write-Verbose "Closing websocket"
                $socket.Dispose()
            }

        }

        

    }
}