
$Version = "v1.0"

Add-Type @"
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

        [Parameter(Mandatory, Position = 3, ParameterSetName = 'Credential')]
        [PSCredential]
        $Credential,

        [Parameter(Mandatory, Position = 3, ParameterSetName = 'PasswordHash')]
        [string]
        $Username,

        [Parameter(Mandatory, Position = 4, ParameterSetName = 'PasswordHash')]
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
            
            # Test Login
            if ($Username)
            {
                $url = "$($Protocol)://$($Server):$Port/api/public/testlogin.htm?username=$Username&passhash=$PasswordHash"
            }
            else 
            {
                $url = "$($Protocol)://$($Server):$Port/api/public/testlogin.htm?username=$($Credential.Username)&password=$($Credential.GetNetworkCredential().Password)"
            }

	        $result = Invoke-WebRequest -Uri $url -SessionVariable session -UseBasicParsing
            
            if ($result.Content -ne 'OK')
            {
                $PSCmdlet.ThrowTerminatingError((New-ErrorRecord "Failed to connect to PRTG"))
            }

            $Script:Protocol = $Protocol
            $Script:Server = $Server
            $Script:Port = $Port
            $Script:Session = $session           
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
    [CmdletBinding()]
    param
    (
        [Parameter()]
        [int]
        $Count,

        [Parameter()]
        [int]
        $Start,

        [Parameter()]
        [int]
        $Id,

        [Parameter()]
        [string]
        $Name,

        [Parameter()]
        [string]
        $Tag,

        [Parameter()]
        [string]
        $Device,

        [Parameter()]
        [string]
        $Group,

        [Parameter()]
        [string]
        $ParentId,

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

        $otherParameters = @()

        if ($Id)
        {
            $otherParameters += "filter_objid=$Id"
            [void] $PSBoundParameters.Remove('id')
        }
        
        if ($Name)
        {
            $otherParameters += "filter_name=$Name"
            [void] $PSBoundParameters.Remove('name')
        }

        if ($Tag)
        {
            $otherParameters += "filter_tags=$Tag"
            [void] $PSBoundParameters.Remove('tag')
        }

        if ($Device)
        {
            $otherParameters += "filter_device=$Device"
            [void] $PSBoundParameters.Remove('device')
        }

        if ($Group)
        {
            $otherParameters += "filter_group=$Group"
            [void] $PSBoundParameters.Remove('group')
        }

        if ($ParentId)
        {
            $otherParameters += "filter_parentid=$ParentId"
            [void] $PSBoundParameters.Remove('parentid')
        }

        if ($otherParameters.Count -gt 0)
        {
            $PSBoundParameters.Add('OtherParameters', $otherParameters)
        }

        $Sensors = ([xml] (Get-PRTGTable -Content sensors @PSBoundParameters).Content).Sensors
        
        if ($Sensors.TotalCount -gt 0)
        {
            $Sensors.Item
        }
    }
}

function Get-PRTGDevice
{
    [CmdletBinding()]
    param
    (
        [Parameter()]
        [int]
        $Count,

        [Parameter()]
        [int]
        $Start,

        [Parameter()]
        [int]
        $Id,

        [Parameter()]
        [string]
        $Name,

        [Parameter()]
        [string]
        $Tag,

        [Parameter()]
        [string]
        $Host,

        [Parameter()]
        [string]
        $Group,

	    [Parameter()]
        [string]
        $ParentId,

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

        $otherParameters = @()

        if ($Id)
        {
            $otherParameters += "filter_objid=$Id"
            [void] $PSBoundParameters.Remove('id')
        }
        
        if ($Name)
        {
            $otherParameters += "filter_name=$Name"
            [void] $PSBoundParameters.Remove('name')
        }

        if ($Tag)
        {
            $otherParameters += "filter_tags=$Tag"
            [void] $PSBoundParameters.Remove('tag')
        }

        if ($Host)
        {
            $otherParameters += "filter_device=$Host"
            [void] $PSBoundParameters.Remove('host')
        }

        if ($Group)
        {
            $otherParameters += "filter_group=$Group"
            [void] $PSBoundParameters.Remove('group')
        }

	    if ($ParentId)
        {
            $otherParameters += "filter_parentid=$ParentId"
            [void] $PSBoundParameters.Remove('parentid')
        }

        if ($otherParameters.Count -gt 0)
        {
            $PSBoundParameters.Add('OtherParameters', $otherParameters)
        }

        $Devices = ([xml] (Get-PRTGTable -Content devices @PSBoundParameters).Content).Devices

        if ($Devices.TotalCount -gt 0)
        {
            $Devices.Item
        }
    }
}

function Get-PRTGGroup
{
    [CmdletBinding()]
    param
    (
        [Parameter()]
        [int]
        $Count,

        [Parameter()]
        [int]
        $Start,

        [Parameter()]
        [int]
        $Id,

        [Parameter()]
        [string]
        $Name,

        [Parameter()]
        [string]
        $Tag,

	    [Parameter()]
        [string]
        $ParentId,

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

        $otherParameters = @()
        
	    if ($Id)
        {
            $otherParameters += "filter_objid=$Id"
            [void] $PSBoundParameters.Remove('id')
        }
        
        if ($Name)
        {
            $otherParameters += "filter_name=$Name"
            [void] $PSBoundParameters.Remove('name')
        }

        if ($Tag)
        {
            $otherParameters += "filter_tags=$Tag"
            [void] $PSBoundParameters.Remove('tag')
        }

	    if ($ParentId)
        {
            $otherParameters += "filter_parentid=$ParentId"
            [void] $PSBoundParameters.Remove('parentid')
        }

        $otherParameters += "filter_type=group"
        $PSBoundParameters.Add('OtherParameters', $otherParameters)
        
        $Groups = ([xml] (Get-PRTGTable -Content groups @PSBoundParameters).Content).Groups

        if ($Groups.TotalCount -gt 0)
        {
            $Groups.Item
        }
    }
}

function Set-PRTGObjectProperty
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [Alias('objid')]
        [int]
        $Id,

        [Parameter(Mandatory, ValueFromPipelineByPropertyName)]
        [string]
        $PropertyName,

        [Parameter(Mandatory, ValueFromPipelineByPropertyName)]
        [string]
        $Value
    )
    Process
    {
        [void] (Invoke-PRTGCommand -CommandPath api/setobjectproperty.htm -Id $Id -Parameters "name=$PropertyName", "value=$Value")
    }
}

function Get-PRTGObjectProperty
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [Alias('objid')]
        [int]
        $Id,

        [Parameter(Mandatory, ValueFromPipelineByPropertyName)]
        [string]
        $PropertyName
    )

    Process
    {
        ([xml] (Invoke-PRTGCommand -CommandPath api/getobjectproperty.htm -Id $Id -Parameters "name=$PropertyName").Content).PRTG.Result
    }
}

function Suspend-PRTGObject
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [Alias('objid')]
        [int]
        $Id
    )

    Process
    {
        [void] (Invoke-PRTGCommand -CommandPath "api/pause.htm" -Id $Id -Parameters action=0)
    }
}

function Resume-PRTGObject
{
    [CmdletBinding()]
    param 
    (
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [Alias('objid')]
        [int]
        $Id
    )

    Process
    {
        [void] (Invoke-PRTGCommand -CommandPath "api/pause.htm" -Id $Id -Parameters action=1)
        
        # This is invoked twice when doing through the GUI with a 2 second interval
        # It seems to speed things up as far as the console is concerned, so we're doing the same
        Start-PRTGScan -Id $Id
        Start-Sleep -Seconds 2
        Start-PRTGScan -Id $Id
    }
}

function Start-PRTGScan
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [Alias('objid')]
        [int]
        $Id
    )
    
    Process
    {
        [void] (Invoke-PRTGCommand -CommandPath "api/scannow.htm" -Id $Id)
    }
}

function Copy-PRTGObject
{
    [CmdletBinding(DefaultParameterSetName = 'Device')]
    param
    (
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName, ParameterSetName = 'Device')]
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName, ParameterSetName = 'Sensor')]
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName, ParameterSetName = 'Group')]
        [Alias('objid')]
        [int]
        $DeviceToCloneId,

        [Parameter(Mandatory, ValueFromPipelineByPropertyName, ParameterSetName = 'Device')]
        [Parameter(Mandatory, ValueFromPipelineByPropertyName, ParameterSetName = 'Sensor')]
        [Parameter(Mandatory, ValueFromPipelineByPropertyName, ParameterSetName = 'Group')]
        [string]
        $DisplayName,

        [Parameter(Mandatory, ValueFromPipelineByPropertyName, ParameterSetName = 'Device')]
        [Parameter(Mandatory, ValueFromPipelineByPropertyName, ParameterSetName = 'Sensor')]
        [Parameter(Mandatory, ValueFromPipelineByPropertyName, ParameterSetName = 'Group')]
        [string]
        $ParentGroupId,

        [Parameter(Mandatory, ValueFromPipelineByPropertyName, ParameterSetName = 'Device')]
        [string]
        $Hostname,

        [Parameter(ValueFromPipelineByPropertyName, ParameterSetName = 'Device')]
        [switch]
        $Device,

        [Parameter(ValueFromPipelineByPropertyName, ParameterSetName = 'Sensor')]
        [switch]
        $Sensor,

        [Parameter(ValueFromPipelineByPropertyName, ParameterSetName = 'Group')]
        [switch]
        $Group
    )

    Process
    {
        $otherParameters = "name=$DisplayName", "targetid=$ParentGroupId"

        if ($Hostname)
        {
            $otherParameters += "host=$Hostname"
        } 
        
        try 
        {
            $result = Invoke-PRTGCommand -CommandPath api/duplicateobject.htm -Id $DeviceToCloneId -Parameters $otherParameters
            
            # The result is the ID of the new object
            ($result.BaseResponse.responseuri.ToString() -split "ID=")[1].Split('&')[0]
        }
        catch 
        {
            $PSCmdlets.ThrowTerminatingError((New-ErrorRecord $_.Exception))
        }
    }
}

function New-PRTGSNMPTrafficSensor
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [Alias('Id')]
        [Int]
        $ParentId,

        [Parameter(Mandatory, ValueFromPipelineByPropertyName, ParameterSetName = 'InterfaceName')]
        [string]
        $Interface,

        [Parameter(ValueFromPipelineByPropertyName, ParameterSetName = 'InterfaceName')]
        [string]
        $Name = $Interface,

        [Parameter(ValueFromPipelineByPropertyName, ParameterSetName = 'InterfaceName')]
        [string]
        $Comments = $Interface,

        [Parameter(ValueFromPipelineByPropertyName, ParameterSetName = 'InterfaceName')]
        [Switch]
        $Is64Bit = $false,

        [Parameter(ValueFromPipelineByPropertyName, ParameterSetName = 'InterfaceName')]
        [int64]
        $LineSpeed = 0,

        [Parameter(Mandatory, ValueFromPipelineByPropertyName, ParameterSetName = 'InterfaceNumber__Check')]
        [string]
        $InterfaceNumber__Check,

        [Parameter(ValueFromPipelineByPropertyName)]
        [string[]]
        $Tags = @("PRTGFn_$Version", 'snmptrafficsensor', 'bandwidthsensor'),

        [Parameter(ValueFromPipelineByPropertyName)]
        [ValidateRange(1,5)]
        [int]
        $Priority = 3,

        [Parameter(ValueFromPipelineByPropertyName)]
        [string[]]
        [ValidateSet('errors', 'discards', 'unicast', 'nonunicast', 'multicast', 'broadcast', 'unknown')]
        $TrafficMode,

	    [Parameter(ValueFromPipelineByPropertyName)]
        [ValidateSet(0, 30, 60, 300, 600, 900, 1800, 3600, 14400, 21600, 43200, 86400)]
        [int]
        $RefreshInterval = 0
    )
    Process
    {
        $parameters = @()
        $parameters += "interfacenumber_=1"
        
        if ($Interface)
        {
            $parameters += "interfacenumber__check=$Interface|$Name|||$Comments|$([int][bool]$Is64Bit)||$LineSpeed"
        }
        else 
        {
            $parameters += "interfacenumber__check=$InterfaceNumber__Check"
        }

        foreach ($mode in $TrafficMode)
        {
            $parameters += "trafficmode_=$mode"
        }

        New-PRTGSensor -ParentId $ParentId -SensorType snmptraffic -Priority $Priority -Tags $Tags -RefreshInterval $RefreshInterval -OtherParameters $parameters
    }
}

function New-PRTGSNMPDiskFreeSensor
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [Alias('Id')]
        [Int]
        $ParentId,

        [Parameter(Mandatory, ValueFromPipelineByPropertyName, ParameterSetName = 'Disk')]
        [string]
        $Disk,

        [Parameter(Mandatory, ValueFromPipelineByPropertyName, ParameterSetName = 'Disk')]
        [int]
        $Index,

        [Parameter(Mandatory, ValueFromPipelineByPropertyName, ParameterSetName = 'Disk__Check')]
        [string]
        $Disk__Check,

        [Parameter(ValueFromPipelineByPropertyName)]
        [string[]]
        $Tags = @("PRTGFn_$Version", 'snmpdiskfreesensor', 'diskspacesensor', 'diskfree', 'snmp'),

        [Parameter(ValueFromPipelineByPropertyName)]
        [ValidateRange(1,5)]
        [int]
        $Priority = 3,

	    [Parameter(ValueFromPipelineByPropertyName)]
        [ValidateSet(0, 30, 60, 300, 600, 900, 1800, 3600, 14400, 21600, 43200, 86400)]
        [int]
        $RefreshInterval = 0
    )
    Process
    {
        $parameters = @()
	    $parameters += "disk_=1"
        
        if ($Disk)
        {
            $parameters += "disk__check=$Index|$Disk|Fixed Disk|"
        }
        else 
        {
            $parameters += "disk__check=$Disk__Check"
        }

        New-PRTGSensor -ParentId $ParentId -SensorType snmpdiskfree -Priority $Priority -Tags $Tags -RefreshInterval $RefreshInterval -OtherParameters $parameters
    }
}

function New-PRTGPingSensor
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [Alias('Id')]
        [int]
        $ParentId,

        [Parameter(ValueFromPipelineByPropertyName)]
        [string]
        $Name = 'Ping',

        [Parameter(ValueFromPipelineByPropertyName)]
        [string[]]
        $Tags = @("PRTG_$Version", "pingsensor"),

        [Parameter(ValueFromPipelineByPropertyName)]
        [ValidateRange(1,5)]
        [int]
        $Priority = 3,

        [Parameter(ValueFromPipelineByPropertyName)]
        [int]
        $Timeout = 5,

        [Parameter(ValueFromPipelineByPropertyName)]
        [int]
        $Size = 32,

        [Parameter(ValueFromPipelineByPropertyName)]
        [int]
        $Count = 5,

        [Parameter(ValueFromPipelineByPropertyName)]
        [int]
        $Delay = 5,

        [Parameter(ValueFromPipelineByPropertyName)]
        [ValidateSet(0, 30, 60, 300, 600, 900, 1800, 3600, 14400, 21600, 43200, 86400)]
        [int]
        $RefreshInterval = 0
    )

    Process
    {
        $parameters = @()
        $parameters += "timeout_=$Timeout"
        $parameters += "size_=$Size"
        $parameters += "count_=$Count"
        $parameters += "delay_=$Delay"

	    New-PRTGSensor -ParentId $ParentId -SensorType ping -Name $Name -Priority $Priority -Tags $Tags -RefreshInterval $RefreshInterval -OtherParameters $parameters
    }
}

function New-PRTGRDPSensor
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [Alias('Id')]
        [int]
        $ParentId,

        [Parameter(ValueFromPipelineByPropertyName)]
        [string]
        $Name = 'RDP',

        [Parameter(ValueFromPipelineByPropertyName)]
        [string[]]
        $Tags = @("PRTG_$Version", "rdpsensor"),

        [Parameter(ValueFromPipelineByPropertyName)]
        [ValidateRange(1,5)]
        [int]
        $Priority = 3,

        [Parameter(ValueFromPipelineByPropertyName)]
        [int]
        $Timeout = 60,

        [Parameter(ValueFromPipelineByPropertyName)]
        [int]
        $Port = 3389,

        [Parameter(ValueFromPipelineByPropertyName)]
        [ValidateSet(0, 30, 60, 300, 600, 900, 1800, 3600, 14400, 21600, 43200, 86400)]
        [int]
        $RefreshInterval = 0
    )

    Process
    {
        $parameters = @()
        $parameters += "timeout_=$Timeout"
        $parameters += "port_=$Port"

	    New-PRTGSensor -ParentId $ParentId -SensorType remotedesktop -Name $Name -Priority $Priority -Tags $Tags -RefreshInterval $RefreshInterval -OtherParameters $parameters
    }
}

function New-PRTGSNMPMemorySensor
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [Alias('Id')]
        [int]
        $ParentId,

        [Parameter(Mandatory, ValueFromPipelineByPropertyName, ParameterSetName = 'Memory')]
        [string]
        $Memory,

        [Parameter(Mandatory, ValueFromPipelineByPropertyName, ParameterSetName = 'Memory')]
        [string]
        $MemoryIndex,

        [Parameter(Mandatory, ValueFromPipelineByPropertyName, ParameterSetName = 'Memory__Check')]
        [string]
        $Memory__Check,

        [Parameter(ValueFromPipelineByPropertyName)]
        [string[]]
        $Tags = @("PRTG_$Version", "snmpmemorysensor", "memory", "memorysensor", "snmp"),

        [Parameter(ValueFromPipelineByPropertyName)]
        [ValidateRange(1,5)]
        [int]
        $Priority = 3,

        [Parameter(ValueFromPipelineByPropertyName)]
        [ValidateSet(0, 30, 60, 300, 600, 900, 1800, 3600, 14400, 21600, 43200, 86400)]
        [int]
        $RefreshInterval = 0
    )

    Process
    {
        $parameters = @()
        $parameters += "memory_=1"
        
        if ($Memory)
        {
            $parameters += "memory__check=$MemoryIndex|$Memory|"
        }
        else
        {
            $parameters += "memory__check=$Memory__Check"
        }

	    New-PRTGSensor -ParentId $ParentId -SensorType snmpmemory -Priority $Priority -Tags $Tags -RefreshInterval $RefreshInterval -OtherParameters $parameters
    }
}

function New-PRTGCPULoadSensor
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [Alias('Id')]
        [int]
        $ParentId,

        [Parameter(ValueFromPipelineByPropertyName)]
        [string]
        $Name = 'SNMP CPU Load',

        [Parameter(ValueFromPipelineByPropertyName)]
        [string[]]
        $Tags = @("PRTG_$Version", "snmp", "cpu", "cpuloadsensor"),

        [Parameter(ValueFromPipelineByPropertyName)]
        [ValidateRange(1,5)]
        [int]
        $Priority = 3,

        [Parameter(ValueFromPipelineByPropertyName)]
        [ValidateSet(0, 30, 60, 300, 600, 900, 1800, 3600, 14400, 21600, 43200, 86400)]
        [int]
        $RefreshInterval = 0

    )

    Process
    {
        New-PRTGSensor -ParentId $ParentId -SensorType snmpcpu -Name $Name -Priority $Priority -Tags $Tags -RefreshInterval $RefreshInterval
    }
}

function New-PRTGSystemUptimeSensor
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [Alias('Id')]
        [int]
        $ParentId,

        [Parameter(ValueFromPipelineByPropertyName)]
        [string]
        $Name = 'SNMP System Uptime',

        [Parameter(ValueFromPipelineByPropertyName)]
        [string[]]
        $Tags = @("PRTG_$Version", "snmp", "cpu", "cpuloadsensor"),

        [Parameter(ValueFromPipelineByPropertyName)]
        [ValidateRange(1,5)]
        [int]
        $Priority = 3,

        [Parameter(ValueFromPipelineByPropertyName)]
        [ValidateSet(0, 30, 60, 300, 600, 900, 1800, 3600, 14400, 21600, 43200, 86400)]
        [int]
        $RefreshInterval = 0

    )

    Process
    {
        New-PRTGSensor -ParentId $ParentId -SensorType snmpuptime -Name $Name -Priority $Priority -Tags $Tags -RefreshInterval $RefreshInterval
    }
}

function New-PRTGSensor
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [Alias('Id')]
        [int]
        $ParentId,

        [Parameter(Mandatory, ValueFromPipelineByPropertyName)]
        [string]
        $SensorType,

        [Parameter(ValueFromPipelineByPropertyName)]
        [string]
        $Name,

        [Parameter(ValueFromPipelineByPropertyName)]
        [ValidateRange(1,5)]
        [int]
        $Priority = 3,

        [Parameter(ValueFromPipelineByPropertyName)]
        [string[]]
        $Tags,

        [Parameter(ValueFromPipelineByPropertyName)]
        [ValidateSet(0, 30, 60, 300, 600, 900, 1800, 3600, 14400, 21600, 43200, 86400)]
        [int]
        $RefreshInterval,

        [Parameter(ValueFromPipelineByPropertyName)]
        [string[]]
        $OtherParameters
    )

    Process
    {
        $parameters = @()
        
        $parameters += "name_=$Name"
        $parameters += "id=$ParentId"
        $parameters += "tags_=$($Tags -join ' ')"
        $parameters += "priority_=$Priority"
        $parameters += "sensortype=$SensorType"
        $parameters += "accessrights_=1"

        if ($RefreshInterval -gt 0)
        {
            $parameters += "intervalgroup=0"
            $parameters += switch ($RefreshInterval)
            {
                30 {"interval_=30|30 seconds"}
                60 {"interval_=60|60 seconds"}
                300 {"interval_=300|5 minutes"}
                600 {"interval_=600|10 minutes"}
                900 {"interval_=900|15 minutes"}
                1800 {"interval_=1800|30 minutes"}
                3600 {"interval_=3600|1 hour"}
                14400 {"interval_=14400|4 hours"}
                21600 {"interval_=21600|6 hours"}
                43200 {"interval_=43200|12 hours"}
                86400 {"interval_=86400|24 hours"}
            }
        }

        $parameters = $parameters + $OtherParameters | Select -Unique

        $result = (Invoke-PRTGCommand -CommandPath addsensor5.htm -Parameters $parameters).Content

        [regex]::Match($result, "<title>.*</title>", "IgnoreCase").Value -notmatch "System Error"
    }
}

function New-PRTGDevice
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [Alias('Id')]
        [int]
        $ParentId,

        [Parameter(Mandatory, ValueFromPipelineByPropertyName)]
        [string]
        $Name,

        [Parameter(Mandatory, ValueFromPipelineByPropertyName)]
        [string]
        $Hostname,

        [Parameter(ValueFromPipelineByPropertyName)]
        [string]
        $DeviceIcon,

        [Parameter(ValueFromPipelineByPropertyName)]
        [ValidateSet('IPv4', 'IPv6')]
        [string]
        $IPVersion = 'IPv4',

        [Parameter(ValueFromPipelineByPropertyName)]
        [string[]]
        $Tags = @("PRTGFn_$Version")
    )

    Process
    {
	    $parameters = @()

        $parameters += "name_=$Name"
        $parameters += "id=$ParentId"
        $parameters += "ipversion_=$([int] ($IPVersion -eq 'IPv6'))"
        $parameters += "tags_=$($Tags -join ' ')"
        $parameters += "host$([regex]::Match($IPVersion, 'v6').Value)_=$Hostname"
        
        if ($DeviceIcon)
        {
            $parameters += "deviceicon_=$DeviceIcon"
        }

        # Might add parameters for these later on ...
        # Without these, the resulting XML will differ slightly in the sense that passwords do not have the <encrypted /> tag.
        # I haven't tested to see if that tag is added later on if the user decides not to inherit settings from parent, 
        # but at least with snmpcommv1_ and snmpcommv2_ if they are not added here the password will default to "public" but will be in clear text, so best to have it here
        $parameters += "accessrights_=1"
        $parameters += "awssk_="
        $parameters += "dbpassword_="
        $parameters += "elevationpass_="
        $parameters += "esxpassword_="
        $parameters += "linuxloginpassword_="
        $parameters += "privatekey_="
        $parameters += "snmpencpass_="
        $parameters += "snmpauthpass_="
        $parameters += "snmpcommv1_=public"
        $parameters += "snmpcommv2_=public"
        $parameters += "windowsloginpassword_="

        $result = (Invoke-PRTGCommand -CommandPath adddevice2.htm -Parameters $parameters).Content

        [regex]::Match($result, "<title>.*</title>", "IgnoreCase").Value -notmatch "System Error"
    }
}

function Get-PRTGSNMPSensorValues
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [Alias('Id')]
        [int]
        $DeviceId,

        [Parameter(Mandatory, ValueFromPipelineByPropertyName)]
        [ValidateSet('snmpmemory', 'snmptraffic', 'snmpdiskfree')]        
        [string]
        $SensorType
    )

    Process
    {
        $result = Invoke-PRTGCommand -CommandPath controls/addsensor2.htm -Id $DeviceId -Parameters "sensortype=$SensorType" -DoNotUseBasicParsing
        
        $tmpid = (($result.BaseResponse.ResponseUri.ToString() -split 'tmpid=')[1] -split '&')[0]
        
        do 
        {
            $progress = ((Invoke-PRTGCommand -CommandPath api/getaddsensorprogress.htm -Id $DeviceId -Parameters "tmpid=$tmpid").Content | ConvertFrom-Json).Progress
            Start-Sleep -Milliseconds 500
        } until ($progress -eq 100)
        
        $result = (Invoke-PRTGCommand -CommandPath addsensor4.htm -Id $DeviceId -Parameters "tmpid=$tmpid")
        
        $elementName = switch ($SensorType)
        {
            'snmpmemory' {'memory__check'}
            'snmptraffic' {'interfacenumber__check'}
            'snmpdiskfree' {'disk__check'}
        }

        $regex = ([regex]::Matches($result.Content, "<[^<]+$elementName[^>]*").Value | ForEach-Object {[xml] ($_ + "/>")}).Input.Value

        $regex | ForEach-Object {
            $value = $_
            $name = switch ($SensorType)
            {
                'snmpmemory' {$value.Split('|')[1]}
                'snmptraffic' {$value.Split('|')[6]}
                'snmpdiskfree' {$value.Split('|')[1]}
            }

            New-Object -TypeName PSOBject -Property @{'Name' = $name; $elementName = $value} | Select Name, $elementName
	    }
    }
}

function Get-PRTGTable
{
    [CmdletBinding()]
    param
    (
        [Parameter()]
        [ValidateSet('sensortree', 'devices', 'sensors', 'tickets', 'ticketdata', 'messages', 'values', 'channels', 'reports', 'storedreports', 'toplists', 'groups')]
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
        [string[]]
        $OtherParameters
    )
    Process
    {
        if ($Content)
        {
            $OtherParameters += "content=$Content"
        }

        if ($Columns)
        {
            $OtherParameters += "columns=$($Columns -join ',')"
        }

        if ($Id)
        {
            $OtherParameters += "id=$Id"
        }

        if ($Count)
        {
            $OtherParameters += "count=$Count"
        }

        if ($Start)
        {
            $OtherParameters += "start=$Start"
        }

        if ($OutputFormat)
        {
            $OtherParameters += "output=$OutputFormat"
        }

        Invoke-PRTGCommand -CommandPath api/table.xml -Parameters $OtherParameters
    }
}

function Invoke-PRTGCommand
{
    [CmdletBinding()]
    param
    (
        [Parameter()]
        [string]
        $CommandPath,

        [Parameter()]
        [int]
        $Id,

        [Parameter()]
        [string[]]
        $Parameters,

        [Parameter()]
        [int]
        $MaximumRedirection = 5,

        [Parameter()]
        [switch]
        $DoNotUseBasicParsing
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

        if ($Id)
        {
            $urlString += "id=$Id&"
        }

        if ($Parameters)
        {
            $urlString += $Parameters -join '&'
        }

        if ($urlString.EndsWith('&'))
        {
            $urlString = $urlString.Remove($urlString.Length - 1, 1)
        }

        try
        {
            Write-Debug $urlString
            Invoke-WebRequest -Uri $urlString -MaximumRedirection $MaximumRedirection -UseBasicParsing:(-not $DoNotUseBasicParsing) -ErrorAction Stop -WebSession $Script:Session
        }
        catch
        {
            if ($_.ErrorDetails.Message -eq 'The maximum redirection count has been exceeded. To increase the number of redirections allowed, supply a higher value to the -MaximumRedirection parameter.' )#-and $PSBoundParameters.ContainsKey('MaximumRedirection'))
            {
                return
            }
            
            $PSCmdlet.ThrowTerminatingError((New-ErrorRecord $_.Exception))
        }
    }
}

function New-ErrorRecord
{
    [CmdletBinding(DefaultParameterSetName = 'All')]
    param
    (
        [Parameter(ValueFromPipeline, ValueFromPipelineByPropertyName, Position = 0, ParameterSetName = 'ErrorMessageSet')]
        [String]$ErrorMessage,

        [Parameter(ValueFromPipeline, ValueFromPipelineByPropertyName, Position = 0, ParameterSetName = 'ExceptionSet')]
        [System.Exception]$Exception,

        [Parameter(ValueFromPipelineByPropertyName, Position = 1)]
        [System.Management.Automation.ErrorCategory]$ErrorCategory = [System.Management.Automation.ErrorCategory]::NotSpecified,

        [Parameter(ValueFromPipelineByPropertyName, Position = 2)]
        [String]$ErrorId,

        [Parameter(ValueFromPipelineByPropertyName, Position = 3)]
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