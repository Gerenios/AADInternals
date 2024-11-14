# This script contains utility functions for PTA

# Registers PTAAgent to the Azure AD
# Nov 10th 2019
# Sep 7th 2022: Added UpdateTrust
function Register-PTAAgent
{
<#
    .SYNOPSIS
    Registers the PTA agent to Azure AD and creates a client certificate or renews existing certificate.

    .DESCRIPTION
    Registers the PTA agent to Azure AD with given machine name and creates a client certificate or renews existing certificate.

    The filename of the certificate is <server FQDN>_<tenant id>_<agent id>_<cert thumbprint>.pfx

    .Example
    Get-AADIntAccessTokenForPTA -SaveToCache
    Register-AADIntPTAAgent -MachineName "server1.company.com"

    PTA Agent (005b136f-db3e-4b54-9d8b-8994f7717de6) registered as server1.company.com
    Certificate saved to server1.company.com_513d8d3d-7498-4d8c-85ed-b485ed5c39a9_005b136f-db3e-4b54-9d8b-8994f7717de6_6464A8C05194B416B347D65F01F89FCCE66292FB.pfx

    .Example
    $pt=Get-AADIntAccessTokenForPTA
    PS C:\>Register-AADIntPTAAgent -AccessToken $pt -MachineName "server1.company.com" 

    PTA Agent (005b136f-db3e-4b54-9d8b-8994f7717de6) registered as server1.company.com
    Certificate saved to server1.company.com_513d8d3d-7498-4d8c-85ed-b485ed5c39a9_005b136f-db3e-4b54-9d8b-8994f7717de6_6464A8C05194B416B347D65F01F89FCCE66292FB.pfx

    .Example
    PS C:\>Register-AADIntPTAAgent -MachineName "server1.company.com" -UpdateTrust -PfxFileName .\server1.company.com_513d8d3d-7498-4d8c-85ed-b485ed5c39a9_005b136f-db3e-4b54-9d8b-8994f7717de6_6464A8C05194B416B347D65F01F89FCCE66292FB.pfx

    PTA Agent (005b136f-db3e-4b54-9d8b-8994f7717de6) certificate renewed for server1.company.com
    Certificate saved to server1.company.com_513d8d3d-7498-4d8c-85ed-b485ed5c39a9_005b136f-db3e-4b54-9d8b-8994f7717de6_449D42C1BA32B23A621EBE62329AE460FE68924B.pfx
   
#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$False)]
        [String]$AccessToken,
        [Parameter(Mandatory=$True)]
        [String]$MachineName,
        [Parameter(Mandatory=$False)]
        [String]$FileName,
        [Parameter(ParameterSetName='normal',Mandatory=$False)]
        [Parameter(ParameterSetName='update',Mandatory=$True)]
        [switch]$UpdateTrust,
        [Parameter(Mandatory=$False)]
        [String]$Bootstrap,
        [Parameter(ParameterSetName='update',Mandatory=$True)]
        [String]$PfxFileName,
        [Parameter(ParameterSetName='update',Mandatory=$False)]
        [String]$PfxPassword
    )
    Process
    {
        return Register-ProxyAgent -AccessToken $AccessToken -MachineName $MachineName -FileName $FileName -AgentType PTA -UpdateTrust $UpdateTrust -PfxFileName $PfxFileName -PfxPassword $PfxPassword -Bootstrap $Bootstrap
    }
}

