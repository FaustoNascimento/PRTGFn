
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
        [void] (Invoke-PRTGCommand -CommandPath api/setobjectproperty.htm -Id $Id -Parameters "name=$PropertyName", "value=$Value")
    }
}

function Get-PRTGObjectProperty
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
        [Parameter(Mandatory=$True, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
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
        [Parameter(Mandatory=$True, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
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
        [Parameter(Mandatory=$True, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [Alias('objid')]
        [int]
        $Id
    )
    
    Process
    {
        [void] (Invoke-PRTGCommand -CommandPath "api/pause.htm" -Id $Id -Parameters action=1)
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
            $result = Invoke-PRTGCommand -CommandPath 'api/getpasshash.htm' -Username $Credential.UserName -Password $Credential.GetNetworkCredential().Password
            $result.Content
        }
        catch
        {
            $PSCmdlet.ThrowTerminatingError((New-ErrorRecord $_.Exception))
        }
    }
}

function Copy-PRTGObject
{
    [CmdletBinding(DefaultParameterSetName = 'Device')]
    param
    (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true, ParameterSetName = 'Device')]
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true, ParameterSetName = 'Sensor')]
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true, ParameterSetName = 'Group')]
        [Alias('objid')]
        [int]
        $DeviceToCloneId,

        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true, ParameterSetName = 'Device')]
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true, ParameterSetName = 'Sensor')]
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true, ParameterSetName = 'Group')]
        [string]
        $DisplayName,

        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true, ParameterSetName = 'Device')]
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true, ParameterSetName = 'Sensor')]
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true, ParameterSetName = 'Group')]
        [string]
        $ParentGroupId,

        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true, ParameterSetName = 'Device')]
        [string]
        $Hostname,

        [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'Device')]
        [switch]
        $Device,

        [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'Sensor')]
        [switch]
        $Sensor,

        [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'Group')]
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
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
        [string]
        $Interface,

        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [Alias('Id')]
        [Int]
        $ParentId,

        [Parameter(ValueFromPipelineByPropertyName = $true)]
        [string]
        $Name = $Interface,

        [Parameter(ValueFromPipelineByPropertyName = $true)]
        [string]
        $Comments = $Interface,

        [Parameter(ValueFromPipelineByPropertyName = $true)]
        [Switch]
        $Is64Bit = $false,

        [Parameter(ValueFromPipelineByPropertyName = $true)]
        [int64]
        $LineSpeed = 0,

        [Parameter(ValueFromPipelineByPropertyName = $true)]
        [string[]]
        $Tags = @("PRTGFn_$Version", 'snmptrafficsensor', 'bandwidthsensor'),

        [Parameter(ValueFromPipelineByPropertyName = $true)]
        [ValidateRange(1,5)]
        [int]
        $Priority = 3,

        [Parameter(ValueFromPipelineByPropertyName = $true)]
        [string[]]
        [ValidateSet('errors', 'discards', 'unicast', 'nonunicast', 'multicast', 'broadcast', 'unknown')]
        $TrafficMode
    )
    Process
    {
        $parameters = @()

        $parameters += "interfacenumber__check=$Interface|$Name|||$Comments|$([int][bool]$Is64Bit)||$LineSpeed"
        $parameters += "id=$ParentId"
        $parameters += "priority_=$Priority"
        $parameters += "tags_=$($Tags -join ' ')"
        $parameters += "sensortype=snmptraffic"
        $parameters += "interfacenumber_=1"

        foreach ($mode in $TrafficMode)
        {
            $parameters += "trafficmode_=$mode"
        }

        $result = (Invoke-PRTGCommand -CommandPath addsensor5.htm -Parameters $parameters).Content

        [regex]::Match($result, "<title>.*</title>", "IgnoreCase").Value -notmatch "System Error"
    }
}

function New-PRTGSNMPDiskFreeSensor
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
        [string]
        $Disk,

        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [Alias('Id')]
        [Int]
        $ParentId,

        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
        [int]
        $Index,

        [Parameter(ValueFromPipelineByPropertyName = $true)]
        [string[]]
        $Tags = @("PRTGFn_$Version", 'snmpdiskfreesensor', 'diskspacesensor', 'diskfree', 'snmp'),

        [Parameter(ValueFromPipelineByPropertyName = $true)]
        [ValidateRange(1,5)]
        [int]
        $Priority = 3
    )
    Process
    {
        $parameters = @()

        $parameters += "disk__check=$Index|$Disk|Fixed Disk|"
        $parameters += "id=$ParentId"
        $parameters += "priority_=$Priority"
        $parameters += "tags_=$($Tags -join ' ')"
        $parameters += "sensortype=snmpdiskfree"
        $parameters += "disk_=1"

        $result = (Invoke-PRTGCommand -CommandPath addsensor5.htm -Parameters $parameters).Content

        [regex]::Match($result, "<title>.*</title>", "IgnoreCase").Value -notmatch "System Error"
    }
}

# NOT COMPLETE
# Examining the XML shows that some properties are missing from the object (passwords are in clear text)
function New-PRTGDevice
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [Alias('Id')]
        [int]
        $ParentId,

        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
        [string]
        $DeviceName,

        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
        [string]
        $Hostname,

        [Parameter(ValueFromPipelineByPropertyName = $true)]
        [string]
        $DeviceIcon,

        [Parameter(ValueFromPipelineByPropertyName = $true)]
        [ValidateSet('IPv4', 'IPv6')]
        [string]
        $IPVersion = 'IPv4',

        [Parameter(ValueFromPipelineByPropertyName = $true)]
        [string[]]
        $Tags
    )

    Process
    {
	    $parameters = @()

        $parameters += "name_=$DeviceName"
        $parameters += "id=$ParentId"
        $parameters += "ipversion_=$([int] ($IPVersion -eq 'IPv6'))"
        $parameters += "tags_=$($Tags -join ' ')"
        $parameters += "host$([regex]::Match($IPVersion, 'v6').Value)_=$Hostname"
        $parameters += "deviceicon_=$DeviceIcon"

        $result = (Invoke-PRTGCommand -CommandPath adddevice2.htm -Parameters $parameters).Content

        [regex]::Match($result, "<title>.*</title>", "IgnoreCase").Value -notmatch "System Error"
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

        Invoke-PRTGCommand -CommandPath api/table.htm -Parameters $OtherParameters
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
        $CommandPath,

        [Parameter()]
        [int]
        $Id,

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
        [string[]]
        $Parameters,

        [Parameter()]
        [int]
        $MaximumRedirection = 5
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

        if ($Username)
        {
            $urlString += "username=$([System.Net.WebUtility]::UrlEncode($Username))&"
        }

        if ($Password)
        {
            $urlString += "password=$([System.Net.WebUtility]::UrlEncode($Password))&"
        }
        
        # Since we're assigning the PasswordHash a default value we need to check it this way
        if ($PasswordHash -and -not $Password)
        {
            $urlString += "passhash=$PasswordHash&"
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
            Invoke-WebRequest -Uri $urlString -UseBasicParsing -MaximumRedirection $MaximumRedirection
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
