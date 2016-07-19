
add-type @"
    using System.Net;
    using System.Security.Cryptography.X509Certificates;
    public class TrustAllCertsPolicy : ICertificatePolicy {
        public bool CheckValidationResult(
            ServicePoint srvPoint, X509Certificate certificate,
            WebRequest request, int certificateProblem) {
            return true;
        }
    }
"@
[System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy

<#
    .SYNOPSIS
        Connects to the PRTG server, this must be called before any other function can be invoked.
    .DESCRIPTION
        Establishes a connection to the PRTG server. This must be called before any other function is invoked.
        
        Throws an exception in case of an error
    .PARAMETER Credential 
        A PSCredential object with the credentials with which to connect to PRTG
    .PARAMETER Server
        The name of IP address of the server to connect to. By default, this will connect to localhost
    .PARAMETER Port
        The port to use to connect to PRTG
    .EXAMPLE
        Connect-PRTG -Credential (Get-Credential) -Server PRTGServer
#>
function Connect-PRTG 
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true, Position = 0)]
        [PSCredential]
        $Credential,

        [Parameter(Position = 1)]
        [string]
        $Server = $env:COMPUTERNAME,

        [Parameter(Position = 2)]
        [int]
        $Port = 12123
    )
    End
    {
        # URL Encoding username
        $encodedUsername = [System.Net.WebUtility]::UrlEncode($Credential.UserName)
        $encodedPassword = [System.Net.WebUtility]::UrlEncode($Credential.GetNetworkCredential().Password)

        try 
        {
            $result = Invoke-WebRequest -Uri "https://$($Server):$Port/api/getpasshash.htm?username=$encodedUsername&password=$encodedPassword" -UseBasicParsing

            $Script:Server = $Server
            $Script:Username = $encodedUsername
            $Script:Password = $result.Content
        }
        catch 
        {
            $PSCmdlet.ThrowTerminatingError((New-ErrorRecord $_.Exception))
        }
        
    }
}

# <
function Get-prtgSensorInGroup([string]$StartingID=0)
{
    $url = "http://$PRTGHost/api/table.xml?content=sensors&output=csvtable&columns=objid,probe,group,device,sensor,status,message,lastvalue,priority,favorite,tags&id=$StartingID&count=2500&$auth"
    $request = Invoke-WebRequest -Uri $url -MaximumRedirection 0 -ErrorAction Ignore

    convertFrom-csv $request -WarningAction SilentlyContinue
} # end function

















function New-ErrorRecord
{
    [CmdletBinding(DefaultParameterSetName = 'ErrorMessageSet')]
    param
    (
        [Parameter(ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true, Position = 0, ParameterSetName = 'ErrorMessageSet')]
        [String]$ErrorMessage,

        [Parameter(ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true, Position = 0, ParameterSetName = 'ExceptionSet')]
        [System.Exception]$Exception,

        [Parameter(ValueFromPipelineByPropertyName = $true, Position = 1)]
        [System.Management.Automation.ErrorCategory]$ErrorCategory = [System.Management.Automation.ErrorCategory]::NotSpecified,

        [Parameter(ValueFromPipelineByPropertyName = $true, Position = 2)]
        [String]$ErrorId,

        [Parameter(ValueFromPipelineByPropertyName = $true, Position = 3)]
        [Object]$TargetObject
    )
    
    Process
    {
        if (!$Exception)
        {
            $Exception = New-Object System.Exception $ErrorMessage
        }
    
        New-Object System.Management.Automation.ErrorRecord $Exception, $ErrorId, $ErrorCategory, $TargetObject
    }
}