
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

function Connect-Prtg 
{
    <#
        .SYNOPSIS
            Connects to the Prtg server, this must be called before any other function can be invoked.
        .DESCRIPTION
            Establishes a connection to the Prtg server. This must be called before any other function is invoked.
            
            Throws an exception in case of an error
        .PARAMETER Credential 
            A PSCredential object with the credentials with which to connect to Prtg
        .PARAMETER Server
            The name of IP address of the server to connect to. By default, this will connect to localhost
        .PARAMETER Port
            The port to use to connect to Prtg
        .EXAMPLE
            Connect-Prtg -Credential (Get-Credential) -Server PrtgServer
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
                $PSCmdlet.ThrowTerminatingError((New-ErrorRecord "Failed to connect to Prtg"))
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

function Get-PrtgServerSettings
{
    [CmdletBinding()]
    param
    (
    )
    Process
    {
        try
        {
            $xmlStatus = ([XML] (Invoke-PrtgCommand -CommandPath "api\getstatus.xml").Content).Status
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
            $result.UpdateAvailable = $xmlStatus.PrtgUpdateAvailable -eq 'yes'
            $result.Version = $xmlStatus.Version

            [PSCustomObject] $result
        }
        catch
        {
            $PSCmdlet.ThrowTerminatingError((New-ErrorRecord $_.Exception))
        }
    }
}

function Get-PrtgSensor
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

        $Sensors = ([xml] (Get-PrtgTable -Content sensors @PSBoundParameters).Content).Sensors
        
        if ($Sensors.TotalCount -gt 0)
        {
            $Sensors.Item
        }
    }
}

function Get-PrtgDevice
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

        $Devices = ([xml] (Get-PrtgTable -Content devices @PSBoundParameters).Content).Devices

        if ($Devices.TotalCount -gt 0)
        {
            $Devices.Item
        }
    }
}

function Get-PrtgGroup
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
        
        $Groups = ([xml] (Get-PrtgTable -Content groups @PSBoundParameters).Content).Groups

        if ($Groups.TotalCount -gt 0)
        {
            $Groups.Item
        }
    }
}

function Set-PrtgObjectProperty
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
        [void] (Invoke-PrtgCommand -CommandPath api/setobjectproperty.htm -Id $Id -Parameters "name=$PropertyName", "value=$Value")
    }
}

function Get-PrtgObjectProperty
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
        ([xml] (Invoke-PrtgCommand -CommandPath api/getobjectproperty.htm -Id $Id -Parameters "name=$PropertyName").Content).Prtg.Result
    }
}

function Suspend-PrtgObject
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
        [void] (Invoke-PrtgCommand -CommandPath "api/pause.htm" -Id $Id -Parameters action=0)
    }
}

function Resume-PrtgObject
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
        [void] (Invoke-PrtgCommand -CommandPath "api/pause.htm" -Id $Id -Parameters action=1)
        
        # This is invoked twice when doing through the GUI with a 2 second interval
        # It seems to speed things up as far as the console is concerned, so we're doing the same
        Start-PrtgScan -Id $Id
        Start-Sleep -Seconds 2
        Start-PrtgScan -Id $Id
    }
}

function Start-PrtgScan
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
        [void] (Invoke-PrtgCommand -CommandPath "api/scannow.htm" -Id $Id)
    }
}

function Copy-PrtgObject
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
            $result = Invoke-PrtgCommand -CommandPath api/duplicateobject.htm -Id $DeviceToCloneId -Parameters $otherParameters
            
            # The result is the ID of the new object
            ($result.BaseResponse.responseuri.ToString() -split "ID=")[1].Split('&')[0]
        }
        catch 
        {
            $PSCmdlets.ThrowTerminatingError((New-ErrorRecord $_.Exception))
        }
    }
}

function New-PrtgSensorSnmpTraffic
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [Alias('Id')]
        [Int]
        $ParentId,

        [Parameter(Mandatory, ValueFromPipelineByPropertyName)]
        [Alias('InterfaceNumber__Check')]
        [string]
        $Interface,

        [Parameter(ValueFromPipelineByPropertyName)]
        [string[]]
        $Tags = @("PrtgFn_$Version", 'snmptrafficsensor', 'bandwidthsensor'),

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
        $RefreshInterval = 0,

        [Parameter(ValueFromPipelineByPropertyName)]
        [ValidateRange(0,5)]
        [int]
        $ErrorThreshold = 1,

        [Parameter(ValueFromPipelineByPropertyName)]
        [switch]
        $ValidateDoesNotExist
    )
    Process
    {
        $validationParameters = @()
        $validationParameters += "filter_parentid=$ParentId"
        $validationParameters += 'filter_type=snmptraffic'
        $validateName = $Interface.Split('|')[6]

        $otherParameters = @()
        $otherParameters += "interfacenumber_=1"
        $otherParameters += "interfacenumber__check=$Interface"

        foreach ($mode in $TrafficMode)
        {
            $otherParameters += "trafficmode_=$mode"
        }

        $parameters = @{}
        $parameters.ParentId = $ParentId
        $parameters.SensorType = 'snmptraffic'
        $parameters.Priority = $Priority
        $parameters.Tags = $Tags
        $parameters.RefreshInterval = $RefreshInterval
        $parameters.ErrorThreshold = $ErrorThreshold
        $parameters.ValidateDoesNotExist = $ValidateDoesNotExist
        $parameters.ValidationParameters = $validationParameters
        $parameters.ValidateName = $validateName
        $parameters.OtherParameters = $otherParameters
        
        New-PrtgSensor @parameters
    }
}

function New-PrtgSensorSnmpDiskFree
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [Alias('Id')]
        [Int]
        $ParentId,

        [Parameter(Mandatory, ValueFromPipelineByPropertyName)]
        [Alias('Disk__Check')]
        [string]
        $Disk,

        [Parameter(ValueFromPipelineByPropertyName)]
        [string[]]
        $Tags = @("PrtgFn_$Version", 'snmpdiskfreesensor', 'diskspacesensor', 'diskfree', 'snmp'),

        [Parameter(ValueFromPipelineByPropertyName)]
        [ValidateRange(1,5)]
        [int]
        $Priority = 3,

	    [Parameter(ValueFromPipelineByPropertyName)]
        [ValidateSet(0, 30, 60, 300, 600, 900, 1800, 3600, 14400, 21600, 43200, 86400)]
        [int]
        $RefreshInterval = 0,

        [Parameter(ValueFromPipelineByPropertyName)]
        [ValidateRange(0,5)]
        [int]
        $ErrorThreshold = 1,

        [Parameter(ValueFromPipelineByPropertyName)]
        [switch]
        $ValidateDoesNotExist
    )
    Process
    {
        $validationParameters = @()
        $validationParameters += "filter_parentid=$ParentId"
        $validationParameters += 'filter_type=snmpdiskfree'
        $validateName = $Disk.Split('|')[1]

        $otherParameters = @()
	    $otherParameters += "disk_=1"
        $otherParameters += "disk__check=$Disk"

        $parameters = @{}
        $parameters.ParentId = $ParentId
        $parameters.SensorType = 'snmpdiskfree'
        $parameters.Priority = $Priority
        $parameters.Tags = $Tags
        $parameters.RefreshInterval = $RefreshInterval
        $parameters.ErrorThreshold = $ErrorThreshold
        $parameters.ValidateDoesNotExist = $ValidateDoesNotExist
        $parameters.ValidationParameters = $validationParameters
        $parameters.ValidateName = $validateName
        $parameters.OtherParameters = $otherParameters
        
        New-PrtgSensor @parameters
    }
}

function New-PrtgSensorSnmpMemory
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [Alias('Id')]
        [int]
        $ParentId,

        [Parameter(Mandatory, ValueFromPipelineByPropertyName)]
        [Alias('Memory__Check')]
        [string]
        $Memory,

        [Parameter(ValueFromPipelineByPropertyName)]
        [string[]]
        $Tags = @("Prtg_$Version", "snmpmemorysensor", "memory", "memorysensor", "snmp"),

        [Parameter(ValueFromPipelineByPropertyName)]
        [ValidateRange(1,5)]
        [int]
        $Priority = 3,

        [Parameter(ValueFromPipelineByPropertyName)]
        [ValidateSet(0, 30, 60, 300, 600, 900, 1800, 3600, 14400, 21600, 43200, 86400)]
        [int]
        $RefreshInterval = 0,

        [Parameter(ValueFromPipelineByPropertyName)]
        [ValidateRange(0,5)]
        [int]
        $ErrorThreshold = 1,

        [Parameter(ValueFromPipelineByPropertyName)]
        [switch]
        $ValidateDoesNotExist
    )

    Process
    {
        $validationParameters = @()
        $validationParameters += "filter_parentid=$ParentId"
        $validationParameters += 'filter_type=snmpmemory'
        $validateName = $Memory.Split('|')[1]

        $otherParameters = @()
        $otherParameters += "memory_=1"
        $otherParameters += "memory__check=$Memory"

        $parameters = @{}
        $parameters.ParentId = $ParentId
        $parameters.SensorType = 'snmpmemory'
        $parameters.Priority = $Priority
        $parameters.Tags = $Tags
        $parameters.RefreshInterval = $RefreshInterval
        $parameters.ErrorThreshold = $ErrorThreshold
        $parameters.ValidateDoesNotExist = $ValidateDoesNotExist
        $parameters.ValidationParameters = $validationParameters
        $parameters.ValidateName = $validateName
        $parameters.OtherParameters = $otherParameters
        
        New-PrtgSensor @parameters
    }
}

function New-PrtgSensorSnmpNetAppEnclosure
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [Alias('Id')]
        [int]
        $ParentId,
        
        [Parameter(Mandatory, ValueFromPipelineByPropertyName)]
        [Alias('Enclosure__Check')]
        [string]
        $Enclosure,

        [Parameter(ValueFromPipelineByPropertyName)]
        [string[]]
        $Tags = @("Prtg_$Version", 'snmpnetappenclosuresensor', 'snmpnetapp', 'netapp'),

        [Parameter(ValueFromPipelineByPropertyName)]
        [ValidateRange(1,5)]
        [int]
        $Priority = 3,

        [Parameter(ValueFromPipelineByPropertyName)]
        [ValidateSet(0, 30, 60, 300, 600, 900, 1800, 3600, 14400, 21600, 43200, 86400)]
        [int]
        $RefreshInterval = 0,

        [Parameter(ValueFromPipelineByPropertyName)]
        [ValidateRange(0,5)]
        [int]
        $ErrorThreshold = 1,

        [Parameter(ValueFromPipelineByPropertyName)]
        [switch]
        $ValidateDoesNotExist
    )

    Process
    {
	    $validationParameters = @()
        $validationParameters += "filter_parentid=$ParentId"
        $validationParameters += 'filter_type=snmpnetappenclosurestatus'
        $validateName = $Enclosure.Split('|')[4]

        $otherParameters = @()
        $otherParameters += "enclosure_=1"
        $otherParameters += "enclosure__check=$Enclosure"

        $parameters = @{}
        $parameters.ParentId = $ParentId
        $parameters.SensorType = 'snmpnetappenclosurestatus'
        $parameters.Priority = $Priority
        $parameters.Tags = $Tags
        $parameters.RefreshInterval = $RefreshInterval
        $parameters.ErrorThreshold = $ErrorThreshold
        $parameters.ValidateDoesNotExist = $ValidateDoesNotExist
        $parameters.ValidationParameters = $validationParameters
        $parameters.ValidateName = $validateName
        $parameters.OtherParameters = $otherParameters
        
        New-PrtgSensor @parameters
    }
}

function New-PrtgSensorSnmpNetAppLogicalUnit
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [Alias('Id')]
        [int]
        $ParentId,
        
        [Parameter(Mandatory, ValueFromPipelineByPropertyName)]
        [Alias('Lun__Check')]
        [string]
        $LogicalUnit,

        [Parameter(ValueFromPipelineByPropertyName)]
        [string[]]
        $Tags = @("Prtg_$Version", 'snmpdiskfreesensor', 'snmpnetappdiskfreesensor', 'snmpnetapp', 'netapp'),

        [Parameter(ValueFromPipelineByPropertyName)]
        [ValidateRange(1,5)]
        [int]
        $Priority = 3,

        [Parameter(ValueFromPipelineByPropertyName)]
        [ValidateSet(0, 30, 60, 300, 600, 900, 1800, 3600, 14400, 21600, 43200, 86400)]
        [int]
        $RefreshInterval = 0,

        [Parameter(ValueFromPipelineByPropertyName)]
        [ValidateRange(0,5)]
        [int]
        $ErrorThreshold = 1,

        [Parameter(ValueFromPipelineByPropertyName)]
        [switch]
        $ValidateDoesNotExist
    )

    Process
    {
	    $validationParameters = @()
        $validationParameters += "filter_parentid=$ParentId"
        $validationParameters += 'filter_type=snmpnetapplun'
        $validateName = $LogicalUnit.Split('|')[0]

        $otherParameters = @()
        $otherParameters += "lun_=1"
        $otherParameters += "lun__check=$LogicalUnit"

        $parameters = @{}
        $parameters.ParentId = $ParentId
        $parameters.SensorType = 'snmpnetapplun'
        $parameters.Priority = $Priority
        $parameters.Tags = $Tags
        $parameters.RefreshInterval = $RefreshInterval
        $parameters.ErrorThreshold = $ErrorThreshold
        $parameters.ValidateDoesNotExist = $ValidateDoesNotExist
        $parameters.ValidationParameters = $validationParameters
        $parameters.ValidateName = $validateName
        $parameters.OtherParameters = $otherParameters
        
        New-PrtgSensor @parameters
    }
}

function New-PrtgSensorSnmpNetAppNetworkInterface
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [Alias('Id')]
        [int]
        $ParentId,
        
        [Parameter(Mandatory, ValueFromPipelineByPropertyName)]
        [Alias('Interface__Check')]
        [string]
        $Interface,

        [Parameter(ValueFromPipelineByPropertyName)]
        [string[]]
        $Tags = @("Prtg_$Version", 'snmpnetappnetworkinterfacesensor', 'snmpnetapp', 'netapp'),

        [Parameter(ValueFromPipelineByPropertyName)]
        [ValidateRange(1,5)]
        [int]
        $Priority = 3,

        [Parameter(ValueFromPipelineByPropertyName)]
        [ValidateSet(0, 30, 60, 300, 600, 900, 1800, 3600, 14400, 21600, 43200, 86400)]
        [int]
        $RefreshInterval = 0,

        [Parameter(ValueFromPipelineByPropertyName)]
        [ValidateRange(0,5)]
        [int]
        $ErrorThreshold = 1,

        [Parameter(ValueFromPipelineByPropertyName)]
        [switch]
        $ValidateDoesNotExist
    )

    Process
    {
	    $validationParameters = @()
        $validationParameters += "filter_parentid=$ParentId"
        $validationParameters += 'filter_type=snmpnetappnetworkinterface'
        $validateName = $Interface.Split('|')[0]

        $otherParameters = @()
        $otherParameters += "interface_=1"
        $otherParameters += "interface__check=$Interface"

        $parameters = @{}
        $parameters.ParentId = $ParentId
        $parameters.SensorType = 'snmpnetappnetworkinterface'
        $parameters.Priority = $Priority
        $parameters.Tags = $Tags
        $parameters.RefreshInterval = $RefreshInterval
        $parameters.ErrorThreshold = $ErrorThreshold
        $parameters.ValidateDoesNotExist = $ValidateDoesNotExist
        $parameters.ValidationParameters = $validationParameters
        $parameters.ValidateName = $validateName
        $parameters.OtherParameters = $otherParameters
        
        New-PrtgSensor @parameters
    }
}

function New-PrtgSensorSnmpNetAppDiskFree
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [Alias('Id')]
        [int]
        $ParentId,
        
        [Parameter(Mandatory, ValueFromPipelineByPropertyName)]
        [Alias('filesystem__check')]
        [string]
        $Disk,

        [Parameter(ValueFromPipelineByPropertyName)]
        [string[]]
        $Tags = @("Prtg_$Version", 'snmpdiskfreesensor', 'snmpnetappdiskfreesensor', 'snmpnetapp', 'netapp'),

        [Parameter(ValueFromPipelineByPropertyName)]
        [ValidateRange(1,5)]
        [int]
        $Priority = 3,

        [Parameter(ValueFromPipelineByPropertyName)]
        [ValidateSet(0, 30, 60, 300, 600, 900, 1800, 3600, 14400, 21600, 43200, 86400)]
        [int]
        $RefreshInterval = 0,

        [Parameter(ValueFromPipelineByPropertyName)]
        [ValidateRange(0,5)]
        [int]
        $ErrorThreshold = 1,

        [Parameter(ValueFromPipelineByPropertyName)]
        [switch]
        $ValidateDoesNotExist
    )

    Process
    {
	    $validationParameters = @()
        $validationParameters += "filter_parentid=$ParentId"
        $validationParameters += 'filter_type=snmpnetappdiskfree'
        $validateName = $Disk.Split('|')[0]

        $otherParameters = @()
        $otherParameters += "filesystem_=1"
        $otherParameters += "filesystem__check=$Disk"

        $parameters = @{}
        $parameters.ParentId = $ParentId
        $parameters.SensorType = 'snmpnetappdiskfree'
        $parameters.Priority = $Priority
        $parameters.Tags = $Tags
        $parameters.RefreshInterval = $RefreshInterval
        $parameters.ErrorThreshold = $ErrorThreshold
        $parameters.ValidateDoesNotExist = $ValidateDoesNotExist
        $parameters.ValidationParameters = $validationParameters
        $parameters.ValidateName = $validateName
        $parameters.OtherParameters = $otherParameters
        
        New-PrtgSensor @parameters
    }
}

function New-PrtgSensorSnmpNetAppIO
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
        $Name = 'SNMP NetApp I/O',

        [Parameter(ValueFromPipelineByPropertyName)]
        [string[]]
        $Tags = @("Prtg_$Version", 'snmpnetappiosensor', 'snmpnetapp', 'netapp'),

        [Parameter(ValueFromPipelineByPropertyName)]
        [ValidateRange(1,5)]
        [int]
        $Priority = 3,

        [Parameter(ValueFromPipelineByPropertyName)]
        [ValidateSet(0, 30, 60, 300, 600, 900, 1800, 3600, 14400, 21600, 43200, 86400)]
        [int]
        $RefreshInterval = 0,

        [Parameter(ValueFromPipelineByPropertyName)]
        [ValidateRange(0,5)]
        [int]
        $ErrorThreshold = 1,

        [Parameter(ValueFromPipelineByPropertyName)]
        [switch]
        $ValidateDoesNotExist
    )

    Process
    {
	    $validationParameters = @()
        $validationParameters += "filter_parentid=$ParentId"
        $validationParameters += 'filter_type=snmpnetappio'

        $parameters = @{}
        $parameters.ParentId = $ParentId
        $parameters.SensorType = 'snmpnetappio'
        $parameters.Name = $Name
        $parameters.Priority = $Priority
        $parameters.Tags = $Tags
        $parameters.RefreshInterval = $RefreshInterval
        $parameters.ErrorThreshold = $ErrorThreshold
        $parameters.ValidateDoesNotExist = $ValidateDoesNotExist
        $parameters.ValidationParameters = $validationParameters
        
        New-PrtgSensor @parameters
    }
}

function New-PrtgSensorSnmpNetAppSystemHealth
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
        $Name = 'SNMP NetApp System Health',

        [Parameter(ValueFromPipelineByPropertyName)]
        [string[]]
        $Tags = @("Prtg_$Version", 'snmpnetappsystemhealthsensor', 'snmpnetapp', 'netapp'),

        [Parameter(ValueFromPipelineByPropertyName)]
        [ValidateRange(1,5)]
        [int]
        $Priority = 3,

        [Parameter(ValueFromPipelineByPropertyName)]
        [ValidateSet(0, 30, 60, 300, 600, 900, 1800, 3600, 14400, 21600, 43200, 86400)]
        [int]
        $RefreshInterval = 0,

        [Parameter(ValueFromPipelineByPropertyName)]
        [ValidateRange(0,5)]
        [int]
        $ErrorThreshold = 1,

        [Parameter(ValueFromPipelineByPropertyName)]
        [switch]
        $ValidateDoesNotExist
    )

    Process
    {
	    $validationParameters = @()
        $validationParameters += "filter_parentid=$ParentId"
        $validationParameters += 'filter_type=snmpnetappsystemhealth'

        $parameters = @{}
        $parameters.ParentId = $ParentId
        $parameters.SensorType = 'snmpnetappsystemhealth'
        $parameters.Name = $Name
        $parameters.Priority = $Priority
        $parameters.Tags = $Tags
        $parameters.RefreshInterval = $RefreshInterval
        $parameters.ErrorThreshold = $ErrorThreshold
        $parameters.ValidateDoesNotExist = $ValidateDoesNotExist
        $parameters.ValidationParameters = $validationParameters
        
        New-PrtgSensor @parameters
    }
}

function New-PrtgSensorSnmpHpSystemHealth
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
        $Name = 'SNMP HP ProLiant System Health',

        [Parameter(ValueFromPipelineByPropertyName)]
        [string[]]
        $Tags = @("Prtg_$Version", 'snmphpsystemhealthsensor', 'systemhealth', 'snmphp', 'hp'),

        [Parameter(ValueFromPipelineByPropertyName)]
        [ValidateRange(1,5)]
        [int]
        $Priority = 3,

        [Parameter(ValueFromPipelineByPropertyName)]
        [ValidateSet(0, 30, 60, 300, 600, 900, 1800, 3600, 14400, 21600, 43200, 86400)]
        [int]
        $RefreshInterval = 0,

        [Parameter(ValueFromPipelineByPropertyName)]
        [ValidateRange(0,5)]
        [int]
        $ErrorThreshold = 1,

        [Parameter(ValueFromPipelineByPropertyName)]
        [switch]
        $ValidateDoesNotExist
    )

    Process
    {
	    $validationParameters = @()
        $validationParameters += "filter_parentid=$ParentId"
        $validationParameters += 'filter_type=snmphpsystemhealth'

        $parameters = @{}
        $parameters.ParentId = $ParentId
        $parameters.SensorType = 'snmphpsystemhealth'
        $parameters.Name = $Name
        $parameters.Priority = $Priority
        $parameters.Tags = $Tags
        $parameters.RefreshInterval = $RefreshInterval
        $parameters.ErrorThreshold = $ErrorThreshold
        $parameters.ValidateDoesNotExist = $ValidateDoesNotExist
        $parameters.ValidationParameters = $validationParameters
        
        New-PrtgSensor @parameters
    }
}

function New-PrtgSensorVmwareDatastore
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [Alias('Id')]
        [int]
        $ParentId,
        
        [Parameter(Mandatory, ValueFromPipelineByPropertyName)]
        [Alias('datafieldlist__check')]
        [string]
        $Datastore,

        [Parameter(ValueFromPipelineByPropertyName)]
        [string[]]
        $Tags = @("Prtg_$Version", 'vmwaredatastoreexternsensor'),

        [Parameter(ValueFromPipelineByPropertyName)]
        [ValidateRange(1,5)]
        [int]
        $Priority = 3,

        [Parameter(ValueFromPipelineByPropertyName)]
        [ValidateSet(0, 30, 60, 300, 600, 900, 1800, 3600, 14400, 21600, 43200, 86400)]
        [int]
        $RefreshInterval = 0,

        [Parameter(ValueFromPipelineByPropertyName)]
        [ValidateRange(0,5)]
        [int]
        $ErrorThreshold = 1,

        [Parameter(ValueFromPipelineByPropertyName)]
        [switch]
        $ValidateDoesNotExist
    )

    Process
    {
	    $validationParameters = @()
        $validationParameters += "filter_parentid=$ParentId"
        $validationParameters += 'filter_type=vmwaredatastoreextern'
        $validateName = $Datastore.Split('|')[1]

        $otherParameters = @()
        $otherParameters += "datafieldlist_=1"
        $otherParameters += "datafieldlist__check=$Datastore"

        $parameters = @{}
        $parameters.ParentId = $ParentId
        $parameters.SensorType = 'vmwaredatastoreextern'
        $parameters.Priority = $Priority
        $parameters.Tags = $Tags
        $parameters.RefreshInterval = $RefreshInterval
        $parameters.ErrorThreshold = $ErrorThreshold
        $parameters.ValidateDoesNotExist = $ValidateDoesNotExist
        $parameters.ValidationParameters = $validationParameters
        $parameters.ValidateName = $validateName
        $parameters.OtherParameters = $otherParameters
        
        New-PrtgSensor @parameters
    }
}

function New-PrtgSensorVmwareServerHostHealth
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [Alias('Id')]
        [int]
        $ParentId,
        
        [Parameter(Mandatory, ValueFromPipelineByPropertyName)]
        [Alias('datafieldlist__check')]
        [string]
        $Host,

        [Parameter(ValueFromPipelineByPropertyName)]
        [string]
        $Name = 'VMware Server Host Health',

        [Parameter(ValueFromPipelineByPropertyName)]
        [string[]]
        $Tags = @("Prtg_$Version", 'esxserverhosthealthsensor'),

        [Parameter(ValueFromPipelineByPropertyName)]
        [ValidateRange(1,5)]
        [int]
        $Priority = 3,

        [Parameter(ValueFromPipelineByPropertyName)]
        [ValidateSet(0, 30, 60, 300, 600, 900, 1800, 3600, 14400, 21600, 43200, 86400)]
        [int]
        $RefreshInterval = 0,

        [Parameter(ValueFromPipelineByPropertyName)]
        [ValidateRange(0,5)]
        [int]
        $ErrorThreshold = 1,

        [Parameter(ValueFromPipelineByPropertyName)]
        [switch]
        $ValidateDoesNotExist
    )

    Process
    {
	    $validationParameters = @()
        $validationParameters += "filter_parentid=$ParentId"
        $validationParameters += 'filter_type=esxserverhealthsensorextern'

        $otherParameters = @()
        $otherParameters += "datafieldlist_=1"
        $otherParameters += "datafieldlist__check=$Host"

        $parameters = @{}
        $parameters.ParentId = $ParentId
        $parameters.SensorType = 'esxserverhealthsensorextern'
        $parameters.Name = $Name
        $parameters.Priority = $Priority
        $parameters.Tags = $Tags
        $parameters.RefreshInterval = $RefreshInterval
        $parameters.ErrorThreshold = $ErrorThreshold
        $parameters.ValidateDoesNotExist = $ValidateDoesNotExist
        $parameters.ValidationParameters = $validationParameters
        $parameters.OtherParameters = $otherParameters
        
        New-PrtgSensor @parameters
    }
}

function New-PrtgSensorPerfCounterIISApplicationPool
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [Alias('Id')]
        [int]
        $ParentId,
        
        [Parameter(Mandatory, ValueFromPipelineByPropertyName)]
        [Alias('instance__check')]
        [string]
        $IISWebsite,

        [Parameter(ValueFromPipelineByPropertyName)]
        [string[]]
        $Tags = @("Prtg_$Version", 'pciisapppool', 'performancecounter'),

        [Parameter(ValueFromPipelineByPropertyName)]
        [ValidateRange(1,5)]
        [int]
        $Priority = 3,

        [Parameter(ValueFromPipelineByPropertyName)]
        [ValidateSet(0, 30, 60, 300, 600, 900, 1800, 3600, 14400, 21600, 43200, 86400)]
        [int]
        $RefreshInterval = 0,

        [Parameter(ValueFromPipelineByPropertyName)]
        [ValidateRange(0,5)]
        [int]
        $ErrorThreshold = 1,

        [Parameter(ValueFromPipelineByPropertyName)]
        [switch]
        $ValidateDoesNotExist
    )

    Process
    {
	    $validationParameters = @()
        $validationParameters += "filter_parentid=$ParentId"
        $validationParameters += 'filter_type=pciisapppool'
        $validateName = $IISWebsite.Split('|')[1]

        $otherParameters = @()
        $otherParameters += "instance_=1"
        $otherParameters += "instance__check=$IISWebsite"

        $parameters = @{}
        $parameters.ParentId = $ParentId
        $parameters.SensorType = 'pciisapppool'
        $parameters.Priority = $Priority
        $parameters.Tags = $Tags
        $parameters.RefreshInterval = $RefreshInterval
        $parameters.ErrorThreshold = $ErrorThreshold
        $parameters.ValidateDoesNotExist = $ValidateDoesNotExist
        $parameters.ValidationParameters = $validationParameters
        $parameters.ValidateName = $validateName
        $parameters.OtherParameters = $otherParameters

        New-PrtgSensor @parameters
    }
}

function New-PrtgSensorOracleSql
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
        $SqlQueryFile,

        [Parameter(ValueFromPipelineByPropertyName)]
        [string]
        $Name = "Oracle SQL - $SqlQueryFile",

        [Parameter(ValueFromPipelineByPropertyName)]
        [string]
        $Identifier,

        [Parameter(ValueFromPipelineByPropertyName)]
        [ValidateSet('SID', 'Service_Name')]
        [string]
        $IdentifierType = 'SID',

        [Parameter(ValueFromPipelineByPropertyName)]
        [ValidateSet('NoTransaction', 'Rollback', 'Commit')]
        [string]
        $Transaction = 'NoTransaction',

        [Parameter(ValueFromPipelineByPropertyName)]
        [ValidateSet('ChangeDB', 'CountRows', 'ReadData')]
        [string]
        $ExecutionMode = 'ChangeDB',

        [Parameter(ValueFromPipelineByPropertyName)]
        [string[]]
        $Tags = @("Prtg_$Version", 'sqlsensor'),

        [Parameter(ValueFromPipelineByPropertyName)]
        [ValidateRange(1,5)]
        [int]
        $Priority = 3,

        [Parameter(ValueFromPipelineByPropertyName)]
        [ValidateSet(0, 30, 60, 300, 600, 900, 1800, 3600, 14400, 21600, 43200, 86400)]
        [int]
        $RefreshInterval = 0,

        [Parameter(ValueFromPipelineByPropertyName)]
        [ValidateRange(0,5)]
        [int]
        $ErrorThreshold = 1,

        [Parameter(ValueFromPipelineByPropertyName)]
        [switch]
        $ValidateDoesNotExist
    )

    Process
    {
	    $validationParameters = @()
        $validationParameters += "filter_parentid=$ParentId"
        $validationParameters += 'filter_type=oraclev2'
        $validationParameters += "filter_name=$Name"

        $otherParameters = @()
        $otherParameters += "sqlquery_=$SqlQueryFile|$SqlQueryFile||"
        $otherParameters += "database_=$Identifier"
        $otherParameters += "sid_type_=$([int]($IdentifierType -ne 'SID'))"
        $otherParameters += "transaction_=$Transaction"
        $otherParameters += "executionmode_=$ExecutionMode"
        $otherParameters += "channel1valuelookup_=|None"
        $otherParameters += "channel2valuelookup_=|None"
        $otherParameters += "channel3valuelookup_=|None"
        $otherParameters += "channel4valuelookup_=|None"
        $otherParameters += "channel5valuelookup_=|None"
        $otherParameters += "channel6valuelookup_=|None"
        $otherParameters += "channel7valuelookup_=|None"
        $otherParameters += "channel8valuelookup_=|None"
        $otherParameters += "channel9valuelookup_=|None"
        $otherParameters += "channel10valuelookup_=|None"

        $parameters = @{}
        $parameters.ParentId = $ParentId
        $parameters.SensorType = 'oraclev2'
        $parameters.Name = $Name
        $parameters.Priority = $Priority
        $parameters.Tags = $Tags
        $parameters.RefreshInterval = $RefreshInterval
        $parameters.ErrorThreshold = $ErrorThreshold
        $parameters.ValidateDoesNotExist = $ValidateDoesNotExist
        $parameters.ValidationParameters = $validationParameters
        $parameters.OtherParameters = $otherParameters
                
        New-PrtgSensor @parameters
    }
}

function New-PrtgSensorPing
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
        $Tags = @("Prtg_$Version", "pingsensor"),

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
        $RefreshInterval = 0,

        [Parameter(ValueFromPipelineByPropertyName)]
        [ValidateRange(0,5)]
        [int]
        $ErrorThreshold = 1,

        [Parameter(ValueFromPipelineByPropertyName)]
        [switch]
        $ValidateDoesNotExist
    )

    Process
    {
        $validationParameters = @()
        $validationParameters += "filter_parentid=$ParentId"
        $validationParameters += 'filter_type=ping'

        $otherParameters = @()
        $otherParameters += "timeout_=$Timeout"
        $otherParameters += "size_=$Size"
        $otherParameters += "count_=$Count"
        $otherParameters += "delay_=$Delay"

        $parameters = @{}
        $parameters.ParentId = $ParentId
        $parameters.SensorType = 'ping'
        $parameters.Name = $Name
        $parameters.Priority = $Priority
        $parameters.Tags = $Tags
        $parameters.RefreshInterval = $RefreshInterval
        $parameters.ErrorThreshold = $ErrorThreshold
        $parameters.ValidateDoesNotExist = $ValidateDoesNotExist
        $parameters.ValidationParameters = $validationParameters
        $parameters.OtherParameters = $otherParameters

	    New-PrtgSensor @parameters
    }
}

function New-PrtgSensorRdp
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
        [int]
        $Timeout = 60,

        [Parameter(ValueFromPipelineByPropertyName)]
        [int]
        $RDPPort = 3389,

        [Parameter(ValueFromPipelineByPropertyName)]
        [string[]]
        $Tags = @("Prtg_$Version", "rdpsensor"),

        [Parameter(ValueFromPipelineByPropertyName)]
        [ValidateRange(1,5)]
        [int]
        $Priority = 3,

        [Parameter(ValueFromPipelineByPropertyName)]
        [ValidateSet(0, 30, 60, 300, 600, 900, 1800, 3600, 14400, 21600, 43200, 86400)]
        [int]
        $RefreshInterval = 0,

        [Parameter(ValueFromPipelineByPropertyName)]
        [ValidateRange(0,5)]
        [int]
        $ErrorThreshold = 1,

        [Parameter(ValueFromPipelineByPropertyName)]
        [switch]
        $ValidateDoesNotExist
    )

    Process
    {
        $validationParameters = @()
        $validationParameters += "filter_parentid=$ParentId"
        $validationParameters += 'filter_type=remotedesktop'

        $otherParameters = @()
        $otherParameters += "timeout_=$Timeout"
        $otherParameters += "port_=$RDPPort"

        $parameters = @{}
        $parameters.ParentId = $ParentId
        $parameters.SensorType = 'remotedesktop'
        $parameters.Name = $Name
        $parameters.Priority = $Priority
        $parameters.Tags = $Tags
        $parameters.RefreshInterval = $RefreshInterval
        $parameters.ErrorThreshold = $ErrorThreshold
        $parameters.ValidateDoesNotExist = $ValidateDoesNotExist
        $parameters.ValidationParameters = $validationParameters
        $parameters.OtherParameters = $otherParameters

	    New-PrtgSensor @parameters
    }
}

function New-PrtgSensorCpuLoad
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
        $Tags = @("Prtg_$Version", "snmp", "cpu", "cpuloadsensor"),

        [Parameter(ValueFromPipelineByPropertyName)]
        [ValidateRange(1,5)]
        [int]
        $Priority = 3,

        [Parameter(ValueFromPipelineByPropertyName)]
        [ValidateSet(0, 30, 60, 300, 600, 900, 1800, 3600, 14400, 21600, 43200, 86400)]
        [int]
        $RefreshInterval = 0,

        [Parameter(ValueFromPipelineByPropertyName)]
        [ValidateRange(0,5)]
        [int]
        $ErrorThreshold = 1,

        [Parameter(ValueFromPipelineByPropertyName)]
        [switch]
        $ValidateDoesNotExist
    )

    Process
    {
        $validationParameters = @()
        $validationParameters += "filter_parentid=$ParentId"
        $validationParameters += 'filter_type=snmpcpu'

        $parameters = @{}
        $parameters.ParentId = $ParentId
        $parameters.SensorType = 'snmpcpu'
        $parameters.Name = $Name
        $parameters.Priority = $Priority
        $parameters.Tags = $Tags
        $parameters.RefreshInterval = $RefreshInterval
        $parameters.ErrorThreshold = $ErrorThreshold
        $parameters.ValidateDoesNotExist = $ValidateDoesNotExist
        $parameters.ValidationParameters = $validationParameters
        
        New-PrtgSensor @parameters
    }
}

function New-PrtgSensorSystemUptime
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
        $Tags = @("Prtg_$Version", "snmpuptimesensor"),

        [Parameter(ValueFromPipelineByPropertyName)]
        [ValidateRange(1,5)]
        [int]
        $Priority = 3,

        [Parameter(ValueFromPipelineByPropertyName)]
        [ValidateSet(0, 30, 60, 300, 600, 900, 1800, 3600, 14400, 21600, 43200, 86400)]
        [int]
        $RefreshInterval = 0,

        [Parameter(ValueFromPipelineByPropertyName)]
        [ValidateRange(0,5)]
        [int]
        $ErrorThreshold = 1,

        [Parameter(ValueFromPipelineByPropertyName)]
        [switch]
        $ValidateDoesNotExist
    )

    Process
    {
        $validationParameters = @()
        $validationParameters += "filter_parentid=$ParentId"
        $validationParameters += 'filter_type=snmpuptime'

        $parameters = @{}
        $parameters.ParentId = $ParentId
        $parameters.SensorType = 'snmpuptime'
        $parameters.Name = $Name
        $parameters.Priority = $Priority
        $parameters.Tags = $Tags
        $parameters.RefreshInterval = $RefreshInterval
        $parameters.ErrorThreshold = $ErrorThreshold
        $parameters.ValidateDoesNotExist = $ValidateDoesNotExist
        $parameters.ValidationParameters = $validationParameters

        New-PrtgSensor @parameters
    }
}

function New-PrtgSensor
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
        [ValidateRange(0,5)]
        [int]
        $ErrorThreshold,

        [Parameter(ValueFromPipelineByPropertyName)]
        [switch]
        $ValidateDoesNotExist,

        [Parameter(ValueFromPipelineByPropertyName)]
        [string[]]
        $ValidationParameters,

        [Parameter(ValueFromPipelineByPropertyName)]
        [string]
        $ValidateName,

        [Parameter(ValueFromPipelineByPropertyName)]
        [string[]]
        $OtherParameters
    )

    Process
    {
        if ($ValidateDoesNotExist)
        {
            $xml = ([xml](Get-PrtgTable -Content sensors -OtherParameters $ValidationParameters).Content).Sensors
            
            if ($xml.TotalCount -gt 0 -and (-not $ValidateName -or ($ValidateName -and ($xml.Item | Where-Object Sensor -match $ValidateName)))
            {
                Write-Verbose "Sensor already exists, skipping it"
                return
            }
        }
                
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
            $parameters += "errorintervalsdown_=$ErrorThreshold" 
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

        $result = (Invoke-PrtgCommand -CommandPath addsensor5.htm -Parameters $parameters).Content

        $success = [regex]::Match($result, "<title>.*</title>", "IgnoreCase").Value -notmatch "System Error"

        if (!$success)
        {
            $PSCmdlet.ThrowTerminatingError((New-ErrorRecord "Failed to create sensor with sensor type $SensorType on object id $ParentId"))
        }
    }
}

function New-PrtgGroup
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

        [Parameter(ValueFromPipelineByPropertyName)]
        [string[]]
        $Tags = @("PrtgFn_$Version")
    )

    Process
    {
        $parameters = @()

        $parameters += "name_=$Name"
        $parameters += "id=$ParentId"
        $parameters += "tags_=$($Tags -join ' ')"

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

        $result = (Invoke-PrtgCommand -CommandPath addgroup2.htm -Parameters $parameters).Content

        [regex]::Match($result, "<title>.*</title>", "IgnoreCase").Value -notmatch "System Error"
    }
}

function New-PrtgDevice
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
        $Tags = @("PrtgFn_$Version")
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

        $result = (Invoke-PrtgCommand -CommandPath adddevice2.htm -Parameters $parameters).Content

        [regex]::Match($result, "<title>.*</title>", "IgnoreCase").Value -notmatch "System Error"
    }
}

function Get-PrtgSensorValidValues
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [Alias('Id')]
        [int]
        $DeviceId,

        [Parameter(Mandatory, ValueFromPipelineByPropertyName)]
        [ValidateSet('SnmpMemory', 'SnmpTraffic', 'SnmpDiskFree', 'SnmpNetAppEnclosureStatus', 'SnmpNetAppLun', 'SnmpNetAppNetworkInterface', 'SnmpNetAppDiskFree', 'VmwareDatastoreExtern', 'PcIISAppPool', 'EsxServerHealthSensorExtern')]        
        [string]
        $SensorType
    )

    Process
    {
        $result = Invoke-PrtgCommand -CommandPath controls/addsensor2.htm -Id $DeviceId -Parameters "sensortype=$SensorType"
        
        $tmpid = (($result.BaseResponse.ResponseUri.ToString() -split 'tmpid=')[1] -split '&')[0]
        
        do 
        {
            # With the sleep at the start it will always take a min of 500ms
            # but let's remember that the server needs to in many of the cases contact the probe and the probe needs to contact the device (and the results sent back and processed)
            # So I don't think that a min delay of 500ms is too much nor that it justifies re-writing this to ensure a 
            #Start-Sleep is only invoked after the progress is already retrieved and only when it's not at 100% 
            # (which it would pretty much always be, even if you were querying the PRTG server itself)
            Start-Sleep -Milliseconds 500 
            $progress = ((Invoke-PrtgCommand -CommandPath api/getaddsensorprogress.htm -Id $DeviceId -Parameters "tmpid=$tmpid").Content | ConvertFrom-Json).Progress
        } until ($progress -eq 100)
        
        $result = (Invoke-PrtgCommand -CommandPath addsensor4.htm -Id $DeviceId -Parameters "tmpid=$tmpid")
        
        $elementName = switch ($SensorType)
        {
            'SnmpMemory' 
            {
                $index = 1
                'memory__check'
            }
            'SnmpTraffic' 
            {
                $index = 6
                'interfacenumber__check'
            }
            'SnmpDiskFree' 
            {
                $index = 1
                'disk__check'
            }
            'SnmpNetAppEnclosureStatus' 
            {
                $index = 4
                'enclosure__check'
            }
            'SnmpNetAppLun' 
            {
                $index = 0
                'lun__check'
            }
            'SnmpNetAppNetworkInterface' 
            {
                $index = 0
                'interface__check'
            }
            'SnmpNetAppDiskFree' 
            {
                $index = 0
                'filesystem__check'
            }
            'VmwareDatastoreExtern' 
            {
                $index = 1
                'datafieldlist__check'
            }
            'PcIISAppPool'
            {
                $index = 1
                'instance__check'
            }
            'EsxServerHealthSensorExtern'
            {
                $index = 1
                'datafieldlist__check'
            }
        }

        $regMatches = ([regex]::Matches($result.Content, "<[^<]+$elementName((?!\/?>).)*").Value | ForEach-Object {[xml] ($_ + "/>")}).Input.Value

        $regMatches | ForEach-Object {[PSCustomObject] @{'ParentId' = $DeviceId; 'Name' = $_.Split('|')[$index]; $elementName = $_}}
    }
}

function New-PrtgTriggerVolume
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [Alias('objid', 'ObjectId')]
        [int]
        $Id
    )

    DynamicParam
    {
        $dictionary = New-Object System.Management.Automation.RuntimeDefinedParameterDictionary

        $values = Get-PrtgNewTriggerValues -Id $Id -Class Volume

        foreach ($value in $values)
        {
            $validateSet = $null
            if ($value.Type -eq 'select')
            {
                $validateSet = $value.Items.Value
            }

            $parameter = New-DynamicParameterFn -Name $value.Name -Type string -DefaultValue $value.Default -ValidateSetAttribute $validateSet -ValueFromPipelineByPropertyName $true
            $dictionary.Add($value.Name, $parameter)
        }

        $dictionary
    }

    Process
    {
        $values = @{}
        foreach ($key in $dictionary.Keys)
        {
            $values.($key) = $dictionary[$key].Value
        }

        New-PrtgTrigger -Id $Id -Class Volume -Values $values
    }
}

function New-PrtgTriggerState
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [Alias('objid', 'ObjectId')]
        [int]
        $Id
    )

    DynamicParam
    {
        $dictionary = New-Object System.Management.Automation.RuntimeDefinedParameterDictionary

        $values = Get-PrtgNewTriggerValues -Id $Id -Class State

        foreach ($value in $values)
        {
            $validateSet = $null
            if ($value.Type -eq 'select')
            {
                $validateSet = $value.Items.Value
            }

            $parameter = New-DynamicParameterFn -Name $value.Name -Type string -DefaultValue $value.Default -ValidateSetAttribute $validateSet -ValueFromPipelineByPropertyName $true
            $dictionary.Add($value.Name, $parameter)
        }

        $dictionary
    }

    Process
    {
        $values = @{}
        foreach ($key in $dictionary.Keys)
        {
            $values.($key) = $dictionary[$key].Value
        }

        New-PrtgTrigger -Id $Id -Class State -Values $values
    }
}

function New-PrtgTriggerThreshold
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [Alias('objid', 'ObjectId')]
        [int]
        $Id
    )

    DynamicParam
    {
        $dictionary = New-Object System.Management.Automation.RuntimeDefinedParameterDictionary

        $values = Get-PrtgNewTriggerValues -Id $Id -Class Threshold

        foreach ($value in $values)
        {
            $validateSet = $null
            if ($value.Type -eq 'select')
            {
                $validateSet = $value.Items.Value
            }

            $parameter = New-DynamicParameterFn -Name $value.Name -Type string -DefaultValue $value.Default -ValidateSetAttribute $validateSet -ValueFromPipelineByPropertyName $true
            $dictionary.Add($value.Name, $parameter)
        }

        $dictionary
    }

    Process
    {
        $values = @{}
        foreach ($key in $dictionary.Keys)
        {
            $values.($key) = $dictionary[$key].Value
        }

        New-PrtgTrigger -Id $Id -Class Threshold -Values $values
    }
}

function New-PrtgTriggerChange
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [Alias('objid', 'ObjectId')]
        [int]
        $Id
    )

    DynamicParam
    {
        $dictionary = New-Object System.Management.Automation.RuntimeDefinedParameterDictionary

        $values = Get-PrtgNewTriggerValues -Id $Id -Class Change

        foreach ($value in $values)
        {
            $validateSet = $null
            if ($value.Type -eq 'select')
            {
                $validateSet = $value.Items.Value
            }

            $parameter = New-DynamicParameterFn -Name $value.Name -Type string -DefaultValue $value.Default -ValidateSetAttribute $validateSet -ValueFromPipelineByPropertyName $true
            $dictionary.Add($value.Name, $parameter)
        }

        $dictionary
    }

    Process
    {
        $values = @{}
        foreach ($key in $dictionary.Keys)
        {
            $values.($key) = $dictionary[$key].Value
        }

        New-PrtgTrigger -Id $Id -Class Change -Values $values
    }
}

function New-PrtgTriggerSpeed
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [Alias('objid', 'ObjectId')]
        [int]
        $Id
    )

    DynamicParam
    {
        $dictionary = New-Object System.Management.Automation.RuntimeDefinedParameterDictionary

        $values = Get-PrtgNewTriggerValues -Id $Id -Class Speed

        foreach ($value in $values)
        {
            $validateSet = $null
            if ($value.Type -eq 'select')
            {
                $validateSet = $value.Items.Value
            }

            $parameter = New-DynamicParameterFn -Name $value.Name -Type string -DefaultValue $value.Default -ValidateSetAttribute $validateSet -ValueFromPipelineByPropertyName $true
            $dictionary.Add($value.Name, $parameter)
        }

        $dictionary
    }

    Process
    {
        $values = @{}
        foreach ($key in $dictionary.Keys)
        {
            $values.($key) = $dictionary[$key].Value
        }

        New-PrtgTrigger -Id $Id -Class Speed -Values $values
    }
}

function New-PrtgTrigger
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [Alias('objid', 'ObjectId')]
        [int]
        $Id,

        [Parameter(Mandatory, ValueFromPipelineByPropertyName)]
        [ValidateSet('Volume', 'State', 'Threshold', 'Change', 'Speed')]
        [string]
        $Class,

        [Parameter(Mandatory, ValueFromPipelineByPropertyName)]
        [Hashtable]
        $Values
    )

    Process
    {
        $properValues = @()
        
        foreach ($value in $Values.Keys)
        {
            $properValues += "$value=$($Values[$value])"
        }
        
        $properValues += 'subid=new'
        $properValues += "class=$Class"
        $properValues += "objecttype=nodetrigger"

        Invoke-PrtgCommand -CommandPath editsettings -Id $Id -Parameters $properValues
    }
}

function Get-PrtgNewTriggerValues
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [Alias('objid', 'ObjectId')]
        [int]
        $Id,

        [Parameter(Mandatory, ValueFromPipelineByPropertyName)]
        [ValidateSet('Volume', 'State', 'Threshold', 'Change', 'Speed')]
        [string]
        $Class
    )

    Process
    {
        $result = Invoke-PrtgCommand -CommandPath api/newtrigger.json -Parameters "parid=$Id", "class=$Class"
        $properties = ($result.Content | ConvertFrom-Json).PSObject.Properties | Where Name -match '_' 
        
        foreach ($property in $properties)
        {
            if (-not [regex]::Matches($property.Value, "<[^<]+$").Value.Contains('/'))
            {
                $property.Value = $property.Value.Replace('>', '/>')
            }

            $xml = [xml]$property.Value

            foreach ($childNode in $xml.ChildNodes)
            {
                $option = @{}
                $option.Name = $childNode.Name
                $option.Default = if ($childNode.Value) {$childNode.Value} else {$childNode.ChildNodes[0].Value}
                $option.Items = @()
                $option.Type = $xml.DocumentElement.ToString()

                foreach ($childChildNode in $childNode.ChildNodes)
                {
                    $child = @{}
                    $child.Value = $childChildNode.Value
                    $child.Name = $childChildNode.'#text'
                    
                    $option.Items += [PSCustomObject] $child
                }

                [PSCustomObject] $option
            }
        }
    }
}

function Get-PrtgTable
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

        Invoke-PrtgCommand -CommandPath api/table.xml -Parameters $OtherParameters
    }
}

function Invoke-PrtgCommand
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
        $DoNotUseBasicParsing,

        [Parameter()]
        [ValidateSet('Get', 'Post')]
        [string]
        $Method = 'Get'
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
            Invoke-WebRequest -Uri $urlString -MaximumRedirection $MaximumRedirection -UseBasicParsing:(-not $DoNotUseBasicParsing) -ErrorAction Stop -WebSession $Script:Session -Method $Method
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