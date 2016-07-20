
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

function Connect-PRTG 
{
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
    [CmdletBinding()]
    param
    (
        [Parameter(Position = 0)]
        [string]
        $Server = $env:COMPUTERNAME,

        [Parameter(Position = 1)]
        [int]
        $Port,

        [Parameter(Position = 2)]
        [ValidateSet('HTTP', 'HTTPS')]
        [string]
        $Protocol = 'HTTPS',

        [Parameter(Mandatory = $true, Position = 3, ParameterSetName = 'Credential')]
        [PSCredential]
        $Credential,

        [Parameter(Mandatory = $true, Position = 3, ParameterSetName = 'PasswordHash')]
        [string]
        $Username,

        [Parameter(Mandatory = $true, Position = 4, ParameterSetName = 'PasswordHash')]
        [string]
        $PasswordHash
    )
    End
    {
        try 
        {
            if (!$Port)
            {
                if ($Protocol -eq 'HTTPS')
                {
                    $Port = 443
                }
                else 
                {
                    $Port = 80
                }
            }
            
            $Script:Protocol = $Protocol
            $Script:Server = $Server
            $Script:Port = $Port
            $Script:Username = if ($Username) {$Username} else {$Credential.UserName}
            $Script:PasswordHash = if ($PasswordHash) {$PasswordHash} else {Get-PRTGPasswordHash -Credential $Credential}
        }
        catch 
        {
            $PSCmdlet.ThrowTerminatingError((New-ErrorRecord $_.Exception))
        }
        
    }
}

function Get-PRTGServerSettings
{
    [CmdletBinding()]
    param
    (
    )
    Process
    {
        try
        {
            $xmlStatus = ([XML] (Invoke-PRTGCommand -CommandPath "api\getstatus.xml").Content).Status
            $result = @{}
            $result.Server = $Script:Server
            $result.Port = $Script:Port
            $result.Protocol = $Script:Protocol
            $result.Username = $Script:Username
            $result.AcknowledgedAlarms = $xmlStatus.AckAlarms
            $result.ActivationStatusMessage = $xmlStatus.ActivationStatusMessage
            $result.Alarms = $xmlStatus.Alarms
            $result.AutoDiscoveryTasks = $xmlStatus.AutoDiscoTasks
            $result.BackgroundTasks = $xmlStatus.BackgroundTasks
            $result.CorrelationTasks = $xmlStatus.CorrelationTasks            
            $result.IsCluster = $xmlStatus.IsCluster -eq 'true'
            $result.IsReadOnlyUser = $xmlStatus.ReadOnlyUser -eq 'true'
            $result.IsUserAdmin = $xmlStatus.IsAdminUser -eq 'true'
            $result.NewAlarms = $xmlStatus.NewAlarms
            $result.NewMessages = $xmlStatus.NewMessages
            $result.NewToDos = $xmlStatus.AckAlarms
            $result.ReadOnlyAllowAcknowledge = $xmlStatus.ReadONlyAllowAcknowledge -eq 'true'
            $result.ReadOnlyPwChange = $xmlStatus.ReadOnlyPwChange -eq 'true'
            $result.Time = $xmlStatus.Clock
            $result.UpdateAvailable = $xmlStatus.PRTGUpdateAvailable -eq 'yes'
            $result.Version = $xmlStatus.Version

            New-Object -TypeName PSObject -Property $result
        }
        catch
        {
            $PSCmdlet.ThrowTerminatingError((New-ErrorRecord $_.Exception))
        }
    }
}

function Get-PRTGSensor
{
    [CmdletBinding(DefaultParameterSetName = 'All')]
    param
    (
        [Parameter(ParameterSetName = 'StartAndCount')]
        [int]
        $Count,

        [Parameter(ParameterSetName = 'StartAndCount')]
        [int]
        $Start,

        [Parameter(ParameterSetName = 'Id')]
        [int]
        $Id,

        [Parameter()]
        [ValidateSet('objid', 'type', 'name', 'tags', 'active', 'downtime', 'downtimetime', 'downtimesince', 'uptime', 'uptimetime', 'uptimesince', 'knowntime', 'cumsince', 'sensor', 'interval', 'lastcheck', 'lastup', 'lastdown', 'device', 'group', 'probe', 'grpdev', 'notifiesx', 'intervalx', 'access', 'dependency', 'probegroupdevice', 'status', 'message', 'priority', 'lastvalue', 'upsens', 'downsens', 'downacksens', 'partialdownsens', 'warnsens', 'pausedsens', 'unusualsens', 'undefinedsens', 'totalsens', 'favorite', 'schedule', 'period', 'minigraph', 'comments', 'basetype', 'baselink', 'parentid')]
        [string[]]
        $Columns
    )
    Process
    {
        if (!$PSBoundParameters.ContainsKey('Columns'))
        {
            $PSBoundParameters.Add('Columns', @('objid', 'type', 'name', 'tags', 'active', 'downtime', 'downtimetime', 'downtimesince', 'uptime', 'uptimetime', 'uptimesince', 'knowntime', 'cumsince', 'sensor', 'interval', 'lastcheck', 'lastup', 'lastdown', 'device', 'group', 'probe', 'grpdev', 'notifiesx', 'intervalx', 'access', 'dependency', 'probegroupdevice', 'status', 'message', 'priority', 'lastvalue', 'upsens', 'downsens', 'downacksens', 'partialdownsens', 'warnsens', 'pausedsens', 'unusualsens', 'undefinedsens', 'totalsens', 'favorite', 'schedule', 'period', 'minigraph', 'comments', 'basetype', 'baselink', 'parentid'))
        }

        $Sensors = ([xml] (Invoke-PRTGCommand -Content sensors @PSBoundParameters).Content).Sensors
        
        if ($Sensors.Item.Count -gt 0)
        {
            $Sensors.Item
        }
    }
}

function Get-PRTGDevice
{
    [CmdletBinding(DefaultParameterSetName = 'All')]
    param
    (
        [Parameter(ParameterSetName = 'StartAndCount')]
        [int]
        $Count,

        [Parameter(ParameterSetName = 'StartAndCount')]
        [int]
        $Start,

        [Parameter(ParameterSetName = 'Id')]
        [int]
        $Id,

        [Parameter()]
        [ValidateSet('objid', 'type', 'name', 'tags', 'active', 'device', 'group', 'probe', 'grpdev', 'notifiesx', 'intervalx', 'access', 'dependency', 'probegroupdevice', 'status', 'message', 'priority', 'upsens', 'downsens', 'downacksens', 'partialdownsens', 'warnsens', 'pausedsens', 'unusualsens', 'undefinedsens', 'totalsens', 'favorite', 'schedule', 'deviceicon', 'comments', 'host', 'basetype', 'baselink', 'icon', 'parentid', 'location')]
        [string[]]
        $Columns
    )
    Process
    {
        if (!$PSBoundParameters.ContainsKey('Columns'))
        {
            $PSBoundParameters.Add('Columns', @('objid', 'type', 'name', 'tags', 'active', 'device', 'group', 'probe', 'grpdev', 'notifiesx', 'intervalx', 'access', 'dependency', 'probegroupdevice', 'status', 'message', 'priority', 'upsens', 'downsens', 'downacksens', 'partialdownsens', 'warnsens', 'pausedsens', 'unusualsens', 'undefinedsens', 'totalsens', 'favorite', 'schedule', 'deviceicon', 'comments', 'host', 'basetype', 'baselink', 'icon', 'parentid', 'location'))
        }

        $Devices = ([xml] (Invoke-PRTGCommand -Content devices @PSBoundParameters).Content).Devices

        if ($Devices.Item.Count -gt 0)
        {
            $Devices.Item
        }
    }
}

function Set-PRTGObject
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [Alias('objid')]
        [int]
        $Id,

        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
        [string]
        $PropertyName,

        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
        [string]
        $Value
    )
    Process
    {
        Invoke-PRTGCommand -CommandPath api/setobjectproperty.htm -Id $Id -OtherParameters "name=$PropertyName&value=$Value"
    }
}

function Get-PRTGGroup
{
    [CmdletBinding()]
    param
    (
        [Parameter(ParameterSetName = 'StartAndCount')]
        [int]
        $Count,

        [Parameter(ParameterSetName = 'StartAndCount')]
        [int]
        $Start,

        [Parameter(ParameterSetName = 'Id')]
        [int]
        $Id,

        [Parameter()]
        [ValidateSet('objid', 'type', 'name', 'tags', 'active', 'group', 'probe', 'notifiesx', 'intervalx', 'access', 'dependency', 'probegroupdevice', 'status', 'message', 'priority', 'upsens', 'downsens', 'downacksens', 'partialdownsens', 'warnsens', 'pausedsens', 'unusualsens', 'undefinedsens', 'totalsens', 'schedule', 'comments', 'condition', 'basetype', 'baselink', 'parentid', 'location', 'fold', 'groupnum,')]
        [string[]]
        $Columns
    )
    Process
    {
        if (!$PSBoundParameters.ContainsKey('Columns'))
        {
            $PSBoundParameters.Add('Columns', @('objid', 'type', 'name', 'tags', 'active', 'group', 'probe', 'notifiesx', 'intervalx', 'access', 'dependency', 'probegroupdevice', 'status', 'message', 'priority', 'upsens', 'downsens', 'downacksens', 'partialdownsens', 'warnsens', 'pausedsens', 'unusualsens', 'undefinedsens', 'totalsens', 'schedule', 'comments', 'condition', 'basetype', 'baselink', 'parentid', 'location', 'fold', 'groupnum,'))
        }

        $Groups = ([xml] (Invoke-PRTGCommand -Content group @PSBoundParameters).Content).Groups

        if ($Groups.Item.Count -gt 0)
        {
            $Groups.Item
        }
    }
}

function Suspend-PRTGObject
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory=$True, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [Alias('objid')]
        [int]
        $Id
    )

    Process
    {
        [null] (Invoke-PRTGCommand -CommandPath "api/pause.htm" -Id $Id -OtherParameters action=0)
    }
}

function Resume-PRTGObject
{
    [CmdletBinding()]
    param 
    (
        [Parameter(Mandatory=$True, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [Alias('objid')]
        [int]
        $Id
    )

    Process
    {
        [null] (Invoke-PRTGCommand -CommandPath "api/pause.htm" -Id $Id -OtherParameters action=1)
    }
}

function Get-PRTGPasswordHash
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true, Position = 0)]
        [PSCredential]
        $Credential
    )
    Process
    {
        try
        {
            $result = Invoke-PRTGCommand -Protocol $Script:Protocol -Server $Script:Server -Port $Script:Port -CommandPath 'api/getpasshash.htm' -Username $Credential.UserName -Password $Credential.GetNetworkCredential().Password
            $result.Content
        }
        catch
        {
            $PSCmdlet.ThrowTerminatingError((New-ErrorRecord $_.Exception))
        }
    }
}

function Invoke-PRTGCommand
{
    [CmdletBinding(DefaultParameterSetName = 'All')]
    param
    (
        [Parameter()]
        [ValidateSet('HTTP', 'HTTPS')]
        [string]
        $Protocol = $Script:Protocol,

        [Parameter()]
        [string]
        $Server = $Script:Server,

        [Parameter()]
        [int]
        $Port = $Script:Port,

        [Parameter()]
        [string]
        $CommandPath = 'api/table.xml',

        [Parameter()]
        [ValidateSet('sensortree', 'devices', 'sensors', 'tickets', 'ticketdata', 'messages', 'values', 'channels', 'reports', 'storedreports', 'toplists')]
        [string]
        $Content,

        [Parameter()]
        [ValidateSet('objid', 'type', 'name', 'tags', 'active', 'downtime', 'downtimetime', 'downtimesince', 'uptime', 'uptimetime', 'uptimesince', 'knowntime', 'cumsince', 'sensor', 'interval', 'lastcheck', 'lastup', 'lastdown', 'device', 'group', 'probe', 'grpdev', 'notifiesx', 'intervalx', 'access', 'dependency', 'probegroupdevice', 'status', 'message', 'priority', 'lastvalue', 'upsens', 'downsens', 'downacksens', 'partialdownsens', 'warnsens', 'pausedsens', 'unusualsens', 'undefinedsens', 'totalsens', 'value', 'coverage', 'favorite', 'user', 'parent', 'datetime', 'dateonly', 'timeonly', 'schedule', 'period', 'email', 'template', 'lastrun', 'nextrun', 'size', 'minigraph', 'deviceicon', 'comments', 'host', 'condition', 'basetype', 'baselink', 'icon', 'parentid', 'location', 'fold', 'groupnum,', 'tickettype', 'modifiedby', 'actions', 'content')]
        [string[]]
        $Columns,

        [Parameter()]
        [int]
        $Id,

        [Parameter()]
        [ValidateRange(1,50000)]
        [int]
        $Count,

        [Parameter()]
        [int]
        $Start,

        [Parameter()]
        [ValidateSet('xml', 'xmltable', 'csvtable', 'html')]
        [string]
        $OutputFormat,

        [Parameter()]
        [string]
        $Username = $Script:Username,

        [Parameter(ParameterSetName = 'PasswordHash')]
        [int]
        $PasswordHash = $Script:PasswordHash,

        [Parameter(ParameterSetName = 'Password')]
        [string]
        $Password,

        [Parameter()]
        [string]
        $OtherParameters
    )
    Process
    {
        # Normalize the command path, in case it starts with a /, remove that character
        if ($CommandPath.StartsWith('/'))
        {
            $CommandPath = $CommandPath.Remove(0, 1)
        }

        # If it ends with a ?, remove it
        if ($CommandPath.EndsWith('?'))
        {
            $CommandPath = $CommandPath.Remove($CommandPath.Length - 1, 1)
        }

        $urlString = "$($Protocol)://$($Server):$Port/$($CommandPath)?"
        
        if ($Content)
        {
            $urlString += "content=$Content&"
        }

        if ($Columns)
        {
            $urlString += "columns=$Columns&".Replace(' ', ',')
        }

        if ($Id)
        {
            $urlString += "id=$Id&"
        }

        if ($Count)
        {
            $urlString += "count=$Count&"
        }

        if ($Start)
        {
            $urlString += "start=$Start&"
        }

        if ($OutputFormat)
        {
            $urlString += "output=$OutputFormat&"
        }

        if ($Username)
        {
            $urlString += "username=$([System.Net.WebUtility]::UrlEncode($Username))&"
        }

        if ($Password)
        {
            $urlString += "password=$([System.Net.WebUtility]::UrlEncode($Password))&"
        }
        
        if ($PasswordHash -and -not $Password)
        {
            $urlString += "passhash=$PasswordHash&"
        }

        if ($OtherParameters)
        {
            $urlString += $OtherParameters
        }

        if ($urlString.EndsWith('&'))
        {
            $urlString = $urlString.Remove($urlString.Length - 1, 1)
        }

        try
        {
            Invoke-WebRequest -Uri $urlString -UseBasicParsing
        }
        catch
        {
            $PSCmdlet.ThrowTerminatingError((New-ErrorRecord $_.Exception))
        }
    }
}

function New-ErrorRecord
{
    [CmdletBinding(DefaultParameterSetName = 'All')]
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