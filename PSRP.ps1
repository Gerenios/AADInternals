# PowerShell Remoting Protocol functions

# Creates a PowerShell remote shell
function Create-PSRPShell
{
    [cmdletbinding()]
    Param(
        [Parameter()]
        [System.Management.Automation.PSCredential]$Credentials,
        [Parameter()]
        [Bool]$Oauth=$false,
        [Parameter(Mandatory=$False)]
        [String]$SessionId=((New-Guid).ToString())
    )
    Process
    {

        $Body = @"
        <rsp:Shell xmlns:rsp="http://schemas.microsoft.com/wbem/wsman/1/windows/shell" Name="WinRM$(Get-Random -Maximum 1000)" ShellId="$((New-Guid).ToString().ToUpper())">
			<rsp:InputStreams>stdin pr</rsp:InputStreams>
			<rsp:OutputStreams>stdout</rsp:OutputStreams>
			<creationXml xmlns="http://schemas.microsoft.com/powershell">AAAAAAAAAAcAAAAAAAAAAAMAAALwAgAAAAIAAQAGWlblyniqQabvSrnLG9XKAAAAAAAAAAAAAAAAAAAAAO+7vzxPYmogUmVmSWQ9IjAiPjxNUz48VmVyc2lvbiBOPSJwcm90b2NvbHZlcnNpb24iPjIuMzwvVmVyc2lvbj48VmVyc2lvbiBOPSJQU1ZlcnNpb24iPjIuMDwvVmVyc2lvbj48VmVyc2lvbiBOPSJTZXJpYWxpemF0aW9uVmVyc2lvbiI+MS4xLjAuMTwvVmVyc2lvbj48QkEgTj0iVGltZVpvbmUiPkFBRUFBQUQvLy8vL0FRQUFBQUFBQUFBRUFRQUFBQnhUZVhOMFpXMHVRM1Z5Y21WdWRGTjVjM1JsYlZScGJXVmFiMjVsQkFBQUFCZHRYME5oWTJobFpFUmhlV3hwWjJoMFEyaGhibWRsY3cxdFgzUnBZMnR6VDJabWMyVjBEbTFmYzNSaGJtUmhjbVJPWVcxbERtMWZaR0Y1YkdsbmFIUk9ZVzFsQXdBQkFSeFRlWE4wWlcwdVEyOXNiR1ZqZEdsdmJuTXVTR0Z6YUhSaFlteGxDUWtDQUFBQUFOQ0l3eEFBQUFBS0NnUUNBQUFBSEZONWMzUmxiUzVEYjJ4c1pXTjBhVzl1Y3k1SVlYTm9kR0ZpYkdVSEFBQUFDa3h2WVdSR1lXTjBiM0lIVm1WeWMybHZiZ2hEYjIxd1lYSmxjaEJJWVhOb1EyOWtaVkJ5YjNacFpHVnlDRWhoYzJoVGFYcGxCRXRsZVhNR1ZtRnNkV1Z6QUFBREF3QUZCUXNJSEZONWMzUmxiUzVEYjJ4c1pXTjBhVzl1Y3k1SlEyOXRjR0Z5WlhJa1UzbHpkR1Z0TGtOdmJHeGxZM1JwYjI1ekxrbElZWE5vUTI5a1pWQnliM1pwWkdWeUNPeFJPRDhBQUFBQUNnb0RBQUFBQ1FNQUFBQUpCQUFBQUJBREFBQUFBQUFBQUJBRUFBQUFBQUFBQUFzPTwvQkE+PC9NUz48L09iaj4AAAAAAAAACAAAAAAAAAAAAwAACtwCAAAABAABAAZaVuXKeKpBpu9Kucsb1coAAAAAAAAAAAAAAAAAAAAA77u/PE9iaiBSZWZJZD0iMCI+PE1TPjxJMzIgTj0iTWluUnVuc3BhY2VzIj4xPC9JMzI+PEkzMiBOPSJNYXhSdW5zcGFjZXMiPjE8L0kzMj48T2JqIE49IlBTVGhyZWFkT3B0aW9ucyIgUmVmSWQ9IjEiPjxUTiBSZWZJZD0iMCI+PFQ+U3lzdGVtLk1hbmFnZW1lbnQuQXV0b21hdGlvbi5SdW5zcGFjZXMuUFNUaHJlYWRPcHRpb25zPC9UPjxUPlN5c3RlbS5FbnVtPC9UPjxUPlN5c3RlbS5WYWx1ZVR5cGU8L1Q+PFQ+U3lzdGVtLk9iamVjdDwvVD48L1ROPjxUb1N0cmluZz5EZWZhdWx0PC9Ub1N0cmluZz48STMyPjA8L0kzMj48L09iaj48T2JqIE49IkFwYXJ0bWVudFN0YXRlIiBSZWZJZD0iMiI+PFROIFJlZklkPSIxIj48VD5TeXN0ZW0uVGhyZWFkaW5nLkFwYXJ0bWVudFN0YXRlPC9UPjxUPlN5c3RlbS5FbnVtPC9UPjxUPlN5c3RlbS5WYWx1ZVR5cGU8L1Q+PFQ+U3lzdGVtLk9iamVjdDwvVD48L1ROPjxUb1N0cmluZz5Vbmtub3duPC9Ub1N0cmluZz48STMyPjI8L0kzMj48L09iaj48T2JqIE49IkFwcGxpY2F0aW9uQXJndW1lbnRzIiBSZWZJZD0iMyI+PFROIFJlZklkPSIyIj48VD5TeXN0ZW0uTWFuYWdlbWVudC5BdXRvbWF0aW9uLlBTUHJpbWl0aXZlRGljdGlvbmFyeTwvVD48VD5TeXN0ZW0uQ29sbGVjdGlvbnMuSGFzaHRhYmxlPC9UPjxUPlN5c3RlbS5PYmplY3Q8L1Q+PC9UTj48RENUPjxFbj48UyBOPSJLZXkiPlBTVmVyc2lvblRhYmxlPC9TPjxPYmogTj0iVmFsdWUiIFJlZklkPSI0Ij48VE5SZWYgUmVmSWQ9IjIiIC8+PERDVD48RW4+PFMgTj0iS2V5Ij5QU1ZlcnNpb248L1M+PFZlcnNpb24gTj0iVmFsdWUiPjUuMS4xNzEzNC41OTA8L1ZlcnNpb24+PC9Fbj48RW4+PFMgTj0iS2V5Ij5QU0VkaXRpb248L1M+PFMgTj0iVmFsdWUiPkRlc2t0b3A8L1M+PC9Fbj48RW4+PFMgTj0iS2V5Ij5QU0NvbXBhdGlibGVWZXJzaW9uczwvUz48T2JqIE49IlZhbHVlIiBSZWZJZD0iNSI+PFROIFJlZklkPSIzIj48VD5TeXN0ZW0uVmVyc2lvbltdPC9UPjxUPlN5c3RlbS5BcnJheTwvVD48VD5TeXN0ZW0uT2JqZWN0PC9UPjwvVE4+PExTVD48VmVyc2lvbj4xLjA8L1ZlcnNpb24+PFZlcnNpb24+Mi4wPC9WZXJzaW9uPjxWZXJzaW9uPjMuMDwvVmVyc2lvbj48VmVyc2lvbj40LjA8L1ZlcnNpb24+PFZlcnNpb24+NS4wPC9WZXJzaW9uPjxWZXJzaW9uPjUuMS4xNzEzNC41OTA8L1ZlcnNpb24+PC9MU1Q+PC9PYmo+PC9Fbj48RW4+PFMgTj0iS2V5Ij5DTFJWZXJzaW9uPC9TPjxWZXJzaW9uIE49IlZhbHVlIj40LjAuMzAzMTkuNDIwMDA8L1ZlcnNpb24+PC9Fbj48RW4+PFMgTj0iS2V5Ij5CdWlsZFZlcnNpb248L1M+PFZlcnNpb24gTj0iVmFsdWUiPjEwLjAuMTcxMzQuNTkwPC9WZXJzaW9uPjwvRW4+PEVuPjxTIE49IktleSI+V1NNYW5TdGFja1ZlcnNpb248L1M+PFZlcnNpb24gTj0iVmFsdWUiPjMuMDwvVmVyc2lvbj48L0VuPjxFbj48UyBOPSJLZXkiPlBTUmVtb3RpbmdQcm90b2NvbFZlcnNpb248L1M+PFZlcnNpb24gTj0iVmFsdWUiPjIuMzwvVmVyc2lvbj48L0VuPjxFbj48UyBOPSJLZXkiPlNlcmlhbGl6YXRpb25WZXJzaW9uPC9TPjxWZXJzaW9uIE49IlZhbHVlIj4xLjEuMC4xPC9WZXJzaW9uPjwvRW4+PC9EQ1Q+PC9PYmo+PC9Fbj48L0RDVD48L09iaj48T2JqIE49Ikhvc3RJbmZvIiBSZWZJZD0iNiI+PE1TPjxPYmogTj0iX2hvc3REZWZhdWx0RGF0YSIgUmVmSWQ9IjciPjxNUz48T2JqIE49ImRhdGEiIFJlZklkPSI4Ij48VE4gUmVmSWQ9IjQiPjxUPlN5c3RlbS5Db2xsZWN0aW9ucy5IYXNodGFibGU8L1Q+PFQ+U3lzdGVtLk9iamVjdDwvVD48L1ROPjxEQ1Q+PEVuPjxJMzIgTj0iS2V5Ij45PC9JMzI+PE9iaiBOPSJWYWx1ZSIgUmVmSWQ9IjkiPjxNUz48UyBOPSJUIj5TeXN0ZW0uU3RyaW5nPC9TPjxTIE49IlYiPldpbmRvd3MgUG93ZXJTaGVsbCBJU0U8L1M+PC9NUz48L09iaj48L0VuPjxFbj48STMyIE49IktleSI+NTwvSTMyPjxPYmogTj0iVmFsdWUiIFJlZklkPSIxMCI+PE1TPjxTIE49IlQiPlN5c3RlbS5NYW5hZ2VtZW50LkF1dG9tYXRpb24uSG9zdC5TaXplPC9TPjxPYmogTj0iViIgUmVmSWQ9IjExIj48TVM+PEkzMiBOPSJ3aWR0aCI+ODg8L0kzMj48STMyIE49ImhlaWdodCI+MDwvSTMyPjwvTVM+PC9PYmo+PC9NUz48L09iaj48L0VuPjxFbj48STMyIE49IktleSI+MjwvSTMyPjxPYmogTj0iVmFsdWUiIFJlZklkPSIxMiI+PE1TPjxTIE49IlQiPlN5c3RlbS5NYW5hZ2VtZW50LkF1dG9tYXRpb24uSG9zdC5Db29yZGluYXRlczwvUz48T2JqIE49IlYiIFJlZklkPSIxMyI+PE1TPjxJMzIgTj0ieCI+MDwvSTMyPjxJMzIgTj0ieSI+MDwvSTMyPjwvTVM+PC9PYmo+PC9NUz48L09iaj48L0VuPjxFbj48STMyIE49IktleSI+MTwvSTMyPjxPYmogTj0iVmFsdWUiIFJlZklkPSIxNCI+PE1TPjxTIE49IlQiPlN5c3RlbS5Db25zb2xlQ29sb3I8L1M+PEkzMiBOPSJWIj4tMTwvSTMyPjwvTVM+PC9PYmo+PC9Fbj48RW4+PEkzMiBOPSJLZXkiPjA8L0kzMj48T2JqIE49IlZhbHVlIiBSZWZJZD0iMTUiPjxNUz48UyBOPSJUIj5TeXN0ZW0uQ29uc29sZUNvbG9yPC9TPjxJMzIgTj0iViI+LTE8L0kzMj48L01TPjwvT2JqPjwvRW4+PC9EQ1Q+PC9PYmo+PC9NUz48L09iaj48QiBOPSJfaXNIb3N0TnVsbCI+ZmFsc2U8L0I+PEIgTj0iX2lzSG9zdFVJTnVsbCI+ZmFsc2U8L0I+PEIgTj0iX2lzSG9zdFJhd1VJTnVsbCI+ZmFsc2U8L0I+PEIgTj0iX3VzZVJ1bnNwYWNlSG9zdCI+ZmFsc2U8L0I+PC9NUz48L09iaj48L01TPjwvT2JqPg==</creationXml>
		</rsp:Shell>
"@

        Write-Verbose "Session Id: $SessionId"
        $Envelope = Create-PSRPEnvelope -SessionId $SessionId -Body $Body -Action Create -Option @("protocolversion","2.3")
        
        # Create the Shell
        try
        {
            $shell_response = Call-PSRP -Envelope $Envelope -Credentials $Credentials -Oauth $Oauth
        }
        catch
        {
            # Probably wrong credentials or access token
            Write-error $_.ToString().split("]")[1].trim()
            return
        }

        [xml]$response = $shell_response
        
        # Save the shell id for the later use
        $Shell_Id = $response.Envelope.Body.Shell.ShellId
        Write-Verbose "ShellId: $Shell_Id"

        # Get the output to read session capabilities etc.
        $response = Receive-PSRP -Credentials $Credentials -SessionId $SessionId -Shell_Id $Shell_Id -Oauth $Oauth
        foreach($message in $response.Envelope.Body.ReceiveResponse.Stream)
        {
            $parsed_message = Parse-PSRPMessage -Base64Value $message.'#text'
        }
        
        # Read the rest of the output
        while($parsed_message.'Message type' -ne "Runspool state")
        {
            try
            {
                $response = Receive-PSRP -Credentials $Credentials -SessionId $SessionId -Shell_Id $Shell_Id -Oauth $Oauth
                $message = $response.Envelope.Body.ReceiveResponse.Stream.'#text'
                $parsed_message = Parse-PSRPMessage -Base64Value $message
            }
            catch
            {
                break
            }
            
        }

        return $Shell_Id
       
    }
        
}

# Gets other domains of the given tenant
function Get-TenantDomains
{
<#
    .SYNOPSIS
    Gets other domains from the tenant of the given domain

    .DESCRIPTION
    Uses Exchange Online "feature" that allows Get-FederationInformation cmdlet to retrive other 
    domains from the tenant of the given domain. The tenant used to retrieve information can
    be any tenant having Exchange Online, including trial tenants. 
    The given user MUST have GlobalAdmin / CompanyAdministrator role in the tenant running the function,
    but no rights to the target tenant are needed.

    Due to Exchange Online, this function is extremely slow, can take 10 seconds or more per domain.

    The given domain SHOULD be Managed, federated domains are not always found for some reason.

    .Example
    Get-AADIntTenantDomains -Credentials $Cred -Domain company.com

    company.com
    company.fi
    company.co.uk
    company.onmicrosoft.com
    company.mail.onmicrosoft.com

    .Example
    $at = Get-AADIntAccessTokenForEXOPS
    PS C:\>Get-AADIntTenantDomains -AccessToken $at -Domain company.com

    company.com
    company.fi
    company.co.uk
    company.onmicrosoft.com
    company.mail.onmicrosoft.com
#>
    [cmdletbinding()]
    Param(
        [Parameter(ParameterSetName='Credentials',Mandatory=$True)]
        [System.Management.Automation.PSCredential]$Credentials,
        [Parameter(ParameterSetName='AccessToken',Mandatory=$True)]
        [String]$AccessToken,
        [Parameter(Mandatory=$True)]
        [String]$Domain
    )
    Process
    {
        # A fixed runspacel pool ID, used in PSRP messages
        $runspacePoolId = [guid]"e5565a06-78ca-41aa-a6ef-4ab9cb1bd5ca"

        # Counter for Object IDs
        $ObjectId=10


        $Oauth=$false
        # If Access Token is given, create the credentials object manually
        if(![string]::IsNullOrEmpty($AccessToken))
        {
            $upn = (Read-Accesstoken $AccessToken).upn
            $password = ConvertTo-SecureString -String "Bearer $AccessToken" -AsPlainText -Force
            $Credentials = [System.Management.Automation.PSCredential]::new($upn,$password)
            $Oauth=$True
        }

        # Create a shell
        $SessionId = (New-Guid).ToString().ToUpper()
        
        $Shell_Id = Create-PSRPShell -Credentials $Credentials -SessionId $SessionId -Oauth $Oauth
        if([string]::IsNullOrEmpty($Shell_Id))
        {
            # Something went wrong, exit
            return
        }

        # Create an arguments message (uses the fixed runspace pool ID)
        $arguments = @"
<Obj RefId="0"><MS><Obj N="PowerShell" RefId="1"><MS><Obj N="Cmds" RefId="2"><TN RefId="0"><T>System.Collections.Generic.List``1[[System.Management.Automation.PSObject, System.Management.Automation, Version=3.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35]]</T><T>System.Object</T></TN><LST><Obj RefId="3"><MS><S N="Cmd">Get-FederationInformation</S><B N="IsScript">false</B><Nil N="UseLocalScope" /><Obj N="MergeMyResult" RefId="4"><TN RefId="1"><T>System.Management.Automation.Runspaces.PipelineResultTypes</T><T>System.Enum</T><T>System.ValueType</T><T>System.Object</T></TN><ToString>None</ToString><I32>0</I32></Obj><Obj N="MergeToResult" RefId="5"><TNRef RefId="1" /><ToString>None</ToString><I32>0</I32></Obj><Obj N="MergePreviousResults" RefId="6"><TNRef RefId="1" /><ToString>None</ToString><I32>0</I32></Obj><Obj N="MergeError" RefId="7"><TNRef RefId="1" /><ToString>None</ToString><I32>0</I32></Obj><Obj N="MergeWarning" RefId="8"><TNRef RefId="1" /><ToString>None</ToString><I32>0</I32></Obj><Obj N="MergeVerbose" RefId="9"><TNRef RefId="1" /><ToString>None</ToString><I32>0</I32></Obj><Obj N="MergeDebug" RefId="10"><TNRef RefId="1" /><ToString>None</ToString><I32>0</I32></Obj><Obj N="MergeInformation" RefId="11"><TNRef RefId="1" /><ToString>None</ToString><I32>0</I32></Obj><Obj N="Args" RefId="12"><TNRef RefId="0" /><LST><Obj RefId="13"><MS><S N="N">-DomainName:</S><S N="V">$Domain</S></MS></Obj></LST></Obj></MS></Obj></LST></Obj><B N="IsNested">false</B><Nil N="History" /><B N="RedirectShellErrorOutputPipe">true</B></MS></Obj><B N="NoInput">true</B><Obj N="ApartmentState" RefId="14"><TN RefId="2"><T>System.Threading.ApartmentState</T><T>System.Enum</T><T>System.ValueType</T><T>System.Object</T></TN><ToString>Unknown</ToString><I32>2</I32></Obj><Obj N="RemoteStreamOptions" RefId="15"><TN RefId="3"><T>System.Management.Automation.RemoteStreamOptions</T><T>System.Enum</T><T>System.ValueType</T><T>System.Object</T></TN><ToString>0</ToString><I32>0</I32></Obj><B N="AddToHistory">true</B><Obj N="HostInfo" RefId="16"><MS><B N="_isHostNull">true</B><B N="_isHostUINull">true</B><B N="_isHostRawUINull">true</B><B N="_useRunspaceHost">true</B></MS></Obj><B N="IsNested">false</B></MS></Obj>
"@
        $message = Create-PSRPMessage -Data $arguments -Type Create_pipeline -ObjectId ($ObjectId++) -MSG_RPID $runspacePoolId
            
        $commandId = (New-Guid).ToString().ToUpper()
        
        $Body = @"
        <rsp:CommandLine xmlns:rsp="http://schemas.microsoft.com/wbem/wsman/1/windows/shell" CommandId="$commandId">
			<rsp:Command>Get-FederationInformation</rsp:Command>
			<rsp:Arguments>$message</rsp:Arguments>
		</rsp:CommandLine>
"@
        # Create the envelope for Get-FederationInfo -cmdlet
        $Envelope = Create-PSRPEnvelope -Shell_Id $Shell_Id -SessionId $SessionId -Body $Body -Action Command
        
        $Domains = @()
        
        try
        {
            # Make the command call
            $response = Call-PSRP -Envelope $Envelope -Credentials $Credentials -Oauth $Oauth
 
            $get_output = $true

            # Get the output
            while($get_output)
            {
                try
                {
                    [xml]$response = Receive-PSRP -Credentials $Credentials -SessionId $SessionId -Shell_Id $Shell_Id -CommandId $commandId -Oauth $Oauth

                    # Loop through streams
                    foreach($message in $response.Envelope.Body.ReceiveResponse.Stream)
                    {
                        $parsed_message = Parse-PSRPMessage -Base64Value $message.'#text'
                        [xml]$xmlData = $parsed_message.Data

                        if($parsed_message.'Message type' -eq "Progress record")
                        {
                            # Extract the StatusDescription and PercentComlete from the message
                            $StatusDescription = (Select-Xml -Xml $xmlData -XPath "//*[@N='StatusDescription']").Node.'#text'
                            [int]$PercentComlete = (Select-Xml -Xml $xmlData -XPath "//*[@N='PercentComplete']").Node.'#text'
                            
                            # Extract the domain name
                            $s=$StatusDescription.IndexOf("'")+1
                            $e=$StatusDescription.Length-$s-2
                            $DomainName = $StatusDescription.Substring($s,$e)

                            # There might some text like "Finish" and "Complete" in the status which we don't need..
                            if($DomainName.IndexOf(".") -gt 1)
                            {
                                $Domains += $DomainName
                            }

                            # Update the progress so we know what is going on..
                            Write-Progress -Activity "Retrieving domains from tenant ($Domain)" -Status "Found $DomainName" -PercentComplete $PercentComlete
                        }
                        elseif($parsed_message.'Message type' -eq "Pipeline state")
                        {
                            $errorRecord = (Select-Xml -Xml $xmlData -XPath "//*[@N='ErrorRecord']").Node.'#text'
                            if(![string]::IsNullOrEmpty($errorRecord))
                            {
                                # Something went wrong, probably not an admin user
                                Write-Error "Got an error! May be not an admin user?"
                                Write-Verbose "ERROR: $errorRecord"
                            }
                        }
                    }

                    # Loop thru the CommandStates
                    foreach($state in $response.Envelope.Body.ReceiveResponse.CommandState)
                    {
                        # Okay, we're done!
                        $exitCode = $state.ExitCode
                        if(![string]::IsNullOrEmpty($exitCode))
                        {
                            Write-Progress -Activity "Retrieving domains" -Completed
                            $get_output = $false
                        }
                    }
                }
                catch
                {
                    # Something wen't wrong so exit the loop
                    break
                }
            
            }
        }
        catch
        {
            # Do nothing
        }

        
        # Finally remove the shell
        Remove-PSRPShell -Credentials $Credentials -Shell_Id $Shell_Id -SessionId $SessionId -Oauth $Oauth
       
        # Same domain may be added more than once so do the Select -Unique
        return $Domains | select -Unique | sort

    }
        
}


# Removes the shell, a.k.a. disconnects from the ps host
function Remove-PSRPShell
{
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [System.Management.Automation.PSCredential]$Credentials,
        [Parameter()]
        [Bool]$Oauth=$False,
        [Parameter(Mandatory=$True)]
        [String]$Shell_Id,
        [Parameter(Mandatory=$True)]
        [String]$SessionId
    )
    Process
    {
               
        $Envelope = Create-PSRPEnvelope -SessionId $SessionId -Body " " -Action Delete -Shell_Id $Shell_Id
        
        $response = Call-PSRP -Envelope $Envelope -Credentials $Credentials -Oauth $Oauth

        # Nothing to return..
    }
        
}



