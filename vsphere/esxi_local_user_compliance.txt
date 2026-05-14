Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ============================================================================
# Configurable settings
# ============================================================================
$RequiredUsernames = @(
    'SOCVA'
)

$ReportDirectory = Join-Path -Path $PSScriptRoot -ChildPath 'reports'
$LogDirectory = Join-Path -Path $PSScriptRoot -ChildPath 'logs'
$InputCsvHostColumn = 'Host'
$DesiredLockdownMode = 'lockdownNormal'
$DefaultUserDescription = 'Managed by vsphere-esxi-hardening script'

# ============================================================================
# Runtime state
# ============================================================================
$Script:LogFile = $null
$Script:ReportFile = $null
$Script:ReportRows = New-Object System.Collections.Generic.List[object]

function Show-Usage {
    @'
Usage:
  .\vsphere-esxi-hardening_v0.0.1.ps1 --validate --host esxi01
  .\vsphere-esxi-hardening_v0.0.1.ps1 --remediate --host esxi01,esxi02 --pass MyPassword!
  .\vsphere-esxi-hardening_v0.0.1.ps1 --check-connectivity --csv .\hosts.csv --username SOCVA --pass MyPassword!

Supported arguments:
  --validate
  --remediate
  --check-connectivity
  --host <host1,host2>
  --csv <path-to-csv>
  --username <username>
  --pass <password>
  --help

Notes:
  - Connect to one or more vCenters before running this script.
  - CSV input should contain a host column. Default column name is "Host".
  - The same password is used for all usernames listed in $RequiredUsernames.
  - --validate and --check-connectivity default to all hosts in connected vCenters if no host input is provided.
'@
}

function Initialize-OutputPaths {
    $timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'

    foreach ($directory in @($ReportDirectory, $LogDirectory)) {
        if (-not (Test-Path -Path $directory)) {
            New-Item -Path $directory -ItemType Directory -Force | Out-Null
        }
    }

    $Script:LogFile = Join-Path -Path $LogDirectory -ChildPath "vsphere-esxi-hardening_$timestamp.log"
    $Script:ReportFile = Join-Path -Path $ReportDirectory -ChildPath "vsphere-esxi-hardening_$timestamp.csv"
}

function Write-Log {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Message,

        [ValidateSet('INFO', 'WARN', 'ERROR', 'SUCCESS')]
        [string]$Level = 'INFO'
    )

    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $line = "[{0}] [{1}] {2}" -f $timestamp, $Level, $Message

    switch ($Level) {
        'ERROR' { Write-Host $line -ForegroundColor Red }
        'WARN' { Write-Host $line -ForegroundColor Yellow }
        'SUCCESS' { Write-Host $line -ForegroundColor Green }
        default { Write-Host $line }
    }

    Add-Content -Path $Script:LogFile -Value $line
}

function Parse-Arguments {
    param(
        [string[]]$Arguments
    )

    $parsed = [ordered]@{
        Mode = $null
        HostArgument = $null
        CsvPath = $null
        Username = $null
        Password = $null
        Help = $false
    }

    $index = 0
    while ($index -lt $Arguments.Count) {
        $token = $Arguments[$index]
        $value = $null

        if ($token -match '^(--?[A-Za-z0-9-]+)=(.+)$') {
            $token = $matches[1]
            $value = $matches[2]
        }

        switch -Regex ($token) {
            '^--?validate$' {
                if ($parsed.Mode -and $parsed.Mode -ne 'validate') {
                    throw 'Specify only one mode: --validate, --remediate, or --check-connectivity.'
                }
                $parsed.Mode = 'validate'
                break
            }
            '^--?remediate$' {
                if ($parsed.Mode -and $parsed.Mode -ne 'remediate') {
                    throw 'Specify only one mode: --validate, --remediate, or --check-connectivity.'
                }
                $parsed.Mode = 'remediate'
                break
            }
            '^--?check-connectivity$' {
                if ($parsed.Mode -and $parsed.Mode -ne 'check-connectivity') {
                    throw 'Specify only one mode: --validate, --remediate, or --check-connectivity.'
                }
                $parsed.Mode = 'check-connectivity'
                break
            }
            '^--?hosts?$' {
                if (-not $value) {
                    $index++
                    if ($index -ge $Arguments.Count) {
                        throw "Missing value for $token"
                    }
                    $value = $Arguments[$index]
                }
                $parsed.HostArgument = $value
                break
            }
            '^--?csv$' {
                if (-not $value) {
                    $index++
                    if ($index -ge $Arguments.Count) {
                        throw "Missing value for $token"
                    }
                    $value = $Arguments[$index]
                }
                $parsed.CsvPath = $value
                break
            }
            '^--?user(name)?$' {
                if (-not $value) {
                    $index++
                    if ($index -ge $Arguments.Count) {
                        throw "Missing value for $token"
                    }
                    $value = $Arguments[$index]
                }
                $parsed.Username = $value
                break
            }
            '^--?pass(word)?$' {
                if (-not $value) {
                    $index++
                    if ($index -ge $Arguments.Count) {
                        throw "Missing value for $token"
                    }
                    $value = $Arguments[$index]
                }
                $parsed.Password = $value
                break
            }
            '^--?help$' {
                $parsed.Help = $true
                break
            }
            default {
                throw "Unknown argument: $token"
            }
        }

        $index++
    }

    return [pscustomobject]$parsed
}

function Get-RequiredValue {
    param(
        [string]$ProvidedValue,
        [string]$PromptMessage
    )

    if ($ProvidedValue -and $ProvidedValue.Trim()) {
        return $ProvidedValue.Trim()
    }

    $value = Read-Host -Prompt $PromptMessage
    if (-not $value -or -not $value.Trim()) {
        throw "$PromptMessage is required."
    }

    return $value.Trim()
}

function Get-PlainTextPassword {
    param(
        [string]$ProvidedPassword,
        [string]$PromptMessage = 'Enter password'
    )

    if ($ProvidedPassword -and $ProvidedPassword.Trim()) {
        return $ProvidedPassword
    }

    $securePassword = Read-Host -Prompt $PromptMessage -AsSecureString
    $ptr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($securePassword)

    try {
        $plainTextPassword = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($ptr)
        if (-not $plainTextPassword -or -not $plainTextPassword.Trim()) {
            throw "$PromptMessage is required."
        }

        return $plainTextPassword
    }
    finally {
        if ($ptr -ne [IntPtr]::Zero) {
            [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($ptr)
        }
    }
}

function Get-ConnectedVCenterServers {
    if (Get-Variable -Name DefaultVIServers -Scope Global -ErrorAction SilentlyContinue) {
        $servers = @($global:DefaultVIServers | Where-Object { $_.IsConnected -eq $true })
        if ($servers.Count -gt 0) {
            return $servers
        }
    }

    if (Get-Variable -Name DefaultVIServer -Scope Global -ErrorAction SilentlyContinue) {
        return @($global:DefaultVIServer | Where-Object { $_.IsConnected -eq $true })
    }

    return @()
}

function Get-HostNamesFromInput {
    param(
        [string]$HostArgument,
        [string]$CsvPath
    )

    $names = New-Object System.Collections.Generic.List[string]

    if ($HostArgument) {
        foreach ($entry in ($HostArgument -split ',')) {
            $trimmed = $entry.Trim()
            if ($trimmed) {
                $names.Add($trimmed)
            }
        }
    }

    if ($CsvPath) {
        if (-not (Test-Path -Path $CsvPath)) {
            throw "CSV file not found: $CsvPath"
        }

        $rows = Import-Csv -Path $CsvPath
        foreach ($row in $rows) {
            $propertyName = $InputCsvHostColumn

            if (-not ($row.PSObject.Properties.Name -contains $propertyName)) {
                $propertyName = $row.PSObject.Properties.Name | Select-Object -First 1
                if (-not $propertyName) {
                    continue
                }
            }

            $value = [string]$row.$propertyName
            if ($value -and $value.Trim()) {
                $names.Add($value.Trim())
            }
        }
    }

    return @($names | Sort-Object -Unique)
}

function Resolve-TargetHosts {
    param(
        [string[]]$HostNames,
        [array]$VIServers
    )

    $resolvedHosts = New-Object System.Collections.Generic.List[object]

    foreach ($hostName in $HostNames) {
        $matches = New-Object System.Collections.Generic.List[object]

        foreach ($viServer in $VIServers) {
            $vmHosts = @(Get-VMHost -Server $viServer -Name $hostName -ErrorAction SilentlyContinue)
            foreach ($vmHost in $vmHosts) {
                $matches.Add([pscustomobject]@{
                    VMHost = $vmHost
                    VCenter = $viServer.Name
                })
            }
        }

        if ($matches.Count -eq 0) {
            Write-Log -Level 'ERROR' -Message "Host '$hostName' was not found in any connected vCenter."
            continue
        }

        foreach ($match in $matches) {
            $resolvedHosts.Add($match)
        }
    }

    return @($resolvedHosts)
}

function Get-AllConnectedHosts {
    param(
        [array]$VIServers
    )

    $resolvedHosts = New-Object System.Collections.Generic.List[object]

    foreach ($viServer in $VIServers) {
        $vmHosts = @(Get-VMHost -Server $viServer -ErrorAction SilentlyContinue)
        foreach ($vmHost in $vmHosts) {
            $resolvedHosts.Add([pscustomobject]@{
                VMHost = $vmHost
                VCenter = $viServer.Name
            })
        }
    }

    return @(
        $resolvedHosts |
            Sort-Object -Property @{ Expression = { $_.VCenter } }, @{ Expression = { $_.VMHost.Name } } -Unique
    )
}

function Get-HostContext {
    param(
        [Parameter(Mandatory = $true)]
        [object]$VMHost,

        [Parameter(Mandatory = $true)]
        [string]$VCenter
    )

    $hostView = Get-View -Id $VMHost.Id
    $cluster = @(Get-Cluster -VMHost $VMHost -ErrorAction SilentlyContinue | Select-Object -First 1)

    $userDirectoryView = $null
    $accountManagerView = $null
    $hostAccessManagerView = $null

    if ($hostView.ConfigManager.UserDirectory) {
        $userDirectoryView = Get-View -Id $hostView.ConfigManager.UserDirectory
    }

    if ($hostView.ConfigManager.AccountManager) {
        $accountManagerView = Get-View -Id $hostView.ConfigManager.AccountManager
    }

    if ($hostView.ConfigManager.HostAccessManager) {
        $hostAccessManagerView = Get-View -Id $hostView.ConfigManager.HostAccessManager
    }

    return [pscustomobject]@{
        VMHost = $VMHost
        VCenter = $VCenter
        Cluster = if ($cluster) { $cluster.Name } else { 'Standalone' }
        HostView = $hostView
        UserDirectory = $userDirectoryView
        AccountManager = $accountManagerView
        AccessManager = $hostAccessManagerView
    }
}

function Test-HostUserPresence {
    param(
        [Parameter(Mandatory = $true)]
        [object]$Context,

        [Parameter(Mandatory = $true)]
        [string]$Username
    )

    if (-not $Context.UserDirectory) {
        throw "UserDirectory is not available for host $($Context.VMHost.Name)."
    }

    $results = @($Context.UserDirectory.RetrieveUserGroups('', $Username, '', '', $true, $true, $false))
    return ($results | Where-Object { $_.Principal -eq $Username }).Count -gt 0
}

function Get-HostAccessEntry {
    param(
        [Parameter(Mandatory = $true)]
        [object]$Context,

        [Parameter(Mandatory = $true)]
        [string]$Username
    )

    if (-not $Context.AccessManager) {
        throw "HostAccessManager is not available for host $($Context.VMHost.Name)."
    }

    $entries = @($Context.AccessManager.RetrieveHostAccessControlEntries())
    return $entries | Where-Object { $_.Group -eq $false -and $_.Principal -eq $Username } | Select-Object -First 1
}

function Get-LockdownExceptions {
    param(
        [Parameter(Mandatory = $true)]
        [object]$Context
    )

    if (-not $Context.AccessManager) {
        throw "HostAccessManager is not available for host $($Context.VMHost.Name)."
    }

    return @($Context.AccessManager.QueryLockdownExceptions())
}

function Ensure-HostUser {
    param(
        [Parameter(Mandatory = $true)]
        [object]$Context,

        [Parameter(Mandatory = $true)]
        [string]$Username,

        [Parameter(Mandatory = $true)]
        [string]$Password
    )

    if (Test-HostUserPresence -Context $Context -Username $Username) {
        Write-Log -Message "User '$Username' already exists on host '$($Context.VMHost.Name)'."
        return
    }

    if (-not $Context.AccountManager) {
        throw "AccountManager is not available for host $($Context.VMHost.Name)."
    }

    $userSpec = New-Object VMware.Vim.HostAccountSpec
    $userSpec.Id = $Username
    $userSpec.Password = $Password
    $userSpec.Description = $DefaultUserDescription

    $Context.AccountManager.CreateUser($userSpec)
    Write-Log -Level 'SUCCESS' -Message "Created user '$Username' on host '$($Context.VMHost.Name)'."
}

function Ensure-ReadOnlyAccess {
    param(
        [Parameter(Mandatory = $true)]
        [object]$Context,

        [Parameter(Mandatory = $true)]
        [string]$Username
    )

    $entry = Get-HostAccessEntry -Context $Context -Username $Username
    if ($entry -and $entry.AccessMode -eq 'accessReadOnly') {
        Write-Log -Message "User '$Username' already has ReadOnly access on host '$($Context.VMHost.Name)'."
        return
    }

    $Context.AccessManager.ChangeAccessMode($Username, $false, 'accessReadOnly')
    Write-Log -Level 'SUCCESS' -Message "Assigned ReadOnly access to '$Username' on host '$($Context.VMHost.Name)'."
}

function Ensure-LockdownMode {
    param(
        [Parameter(Mandatory = $true)]
        [object]$Context
    )

    $currentMode = [string]$Context.AccessManager.LockdownMode
    if ($currentMode -eq $DesiredLockdownMode) {
        Write-Log -Message "Host '$($Context.VMHost.Name)' is already in lockdown mode '$DesiredLockdownMode'."
        return
    }

    $Context.AccessManager.ChangeLockdownMode($DesiredLockdownMode)
    Write-Log -Level 'SUCCESS' -Message "Set lockdown mode to '$DesiredLockdownMode' on host '$($Context.VMHost.Name)'."
}

function Get-CurrentLockdownMode {
    param(
        [Parameter(Mandatory = $true)]
        [object]$Context
    )

    if (-not $Context.AccessManager) {
        throw "HostAccessManager is not available for host $($Context.VMHost.Name)."
    }

    $Context.AccessManager.UpdateViewData('LockdownMode')
    return [string]$Context.AccessManager.LockdownMode
}

function Set-LockdownMode {
    param(
        [Parameter(Mandatory = $true)]
        [object]$Context,

        [Parameter(Mandatory = $true)]
        [string]$Mode
    )

    $currentMode = Get-CurrentLockdownMode -Context $Context
    if ($currentMode -eq $Mode) {
        Write-Log -Message "Host '$($Context.VMHost.Name)' is already in lockdown mode '$Mode'."
        return $currentMode
    }

    $Context.AccessManager.ChangeLockdownMode($Mode)
    $updatedMode = Get-CurrentLockdownMode -Context $Context
    Write-Log -Level 'SUCCESS' -Message "Changed lockdown mode on host '$($Context.VMHost.Name)' from '$currentMode' to '$updatedMode'."
    return $updatedMode
}

function Ensure-LockdownExceptionUser {
    param(
        [Parameter(Mandatory = $true)]
        [object]$Context,

        [Parameter(Mandatory = $true)]
        [string]$Username
    )

    $currentExceptions = New-Object System.Collections.Generic.List[string]
    foreach ($user in (Get-LockdownExceptions -Context $Context)) {
        [void]$currentExceptions.Add($user)
    }

    if ($currentExceptions.Contains($Username)) {
        Write-Log -Message "User '$Username' is already in the lockdown exception list on host '$($Context.VMHost.Name)'."
        return
    }

    [void]$currentExceptions.Add($Username)
    $Context.AccessManager.UpdateLockdownExceptions(@($currentExceptions | Sort-Object -Unique))
    Write-Log -Level 'SUCCESS' -Message "Added '$Username' to lockdown exceptions on host '$($Context.VMHost.Name)'."
}

function Test-HostConnectivity {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Hostname,

        [Parameter(Mandatory = $true)]
        [string]$Username,

        [Parameter(Mandatory = $true)]
        [string]$Password
    )

    $result = [ordered]@{
        ConnectivityAttempted = $true
        ConnectivityStatus = 'Failed'
        ConnectivityMessage = $null
    }

    try {
        $hostConnection = Connect-VIServer -Server $Hostname -User $Username -Password $Password -Force -NotDefault -WarningAction SilentlyContinue
        $result.ConnectivityStatus = 'Success'
        $result.ConnectivityMessage = "Connected successfully as '$Username'."

        if ($hostConnection) {
            Disconnect-VIServer -Server $hostConnection -Confirm:$false | Out-Null
        }
    }
    catch {
        $result.ConnectivityMessage = $_.Exception.Message
    }

    return [pscustomobject]$result
}

function Invoke-ConnectivityCheckWithLockdownHandling {
    param(
        [Parameter(Mandatory = $true)]
        [object]$Context,

        [Parameter(Mandatory = $true)]
        [string]$Username,

        [Parameter(Mandatory = $true)]
        [string]$Password
    )

    $result = [ordered]@{
        ConnectivityAttempted = $true
        ConnectivityStatus = 'Failed'
        ConnectivityMessage = $null
        PreLockdownMode = $null
        PostLockdownMode = $null
        LockdownTemporarilyDisabled = $false
        LockdownRestoreStatus = 'NotRequired'
    }

    $originalMode = Get-CurrentLockdownMode -Context $Context
    $result.PreLockdownMode = $originalMode

    try {
        if ($originalMode -ne 'lockdownDisabled') {
            Write-Log -Level 'WARN' -Message "Host '$($Context.VMHost.Name)' is in lockdown mode '$originalMode'. Disabling lockdown temporarily for connectivity validation."
            $null = Set-LockdownMode -Context $Context -Mode 'lockdownDisabled'
            $result.LockdownTemporarilyDisabled = $true
        }

        $connectivity = Test-HostConnectivity -Hostname $Context.VMHost.Name -Username $Username -Password $Password
        $result.ConnectivityStatus = $connectivity.ConnectivityStatus
        $result.ConnectivityMessage = $connectivity.ConnectivityMessage
    }
    catch {
        $result.ConnectivityMessage = $_.Exception.Message
    }
    finally {
        try {
            if ($result.LockdownTemporarilyDisabled) {
                Write-Log -Message "Restoring lockdown mode '$originalMode' on host '$($Context.VMHost.Name)' after connectivity validation."
                $null = Set-LockdownMode -Context $Context -Mode $originalMode
                $result.LockdownRestoreStatus = 'Restored'
            }

            $result.PostLockdownMode = Get-CurrentLockdownMode -Context $Context
        }
        catch {
            $result.LockdownRestoreStatus = 'Failed'

            if ($result.ConnectivityMessage) {
                $result.ConnectivityMessage = "$($result.ConnectivityMessage) Lockdown restore error: $($_.Exception.Message)"
            }
            else {
                $result.ConnectivityMessage = "Lockdown restore error: $($_.Exception.Message)"
            }
        }
    }

    return [pscustomobject]$result
}

function Add-ReportRow {
    param(
        [Parameter(Mandatory = $true)]
        [psobject]$Row
    )

    $Script:ReportRows.Add($Row)
}

function Export-Report {
    if ($Script:ReportRows.Count -eq 0) {
        Write-Log -Level 'WARN' -Message 'No report rows were generated.'
        return
    }

    $Script:ReportRows |
        Export-Csv -Path $Script:ReportFile -NoTypeInformation -Force

    Write-Log -Level 'SUCCESS' -Message "Report written to $($Script:ReportFile)"
    Write-Log -Level 'SUCCESS' -Message "Log written to $($Script:LogFile)"
}

Initialize-OutputPaths

try {
    $cli = Parse-Arguments -Arguments $args

    if ($cli.Help) {
        Show-Usage
        exit 0
    }

    if (-not $cli.Mode) {
        throw 'Select one mode: --validate, --remediate, or --check-connectivity.'
    }

    $connectedVIServers = @(Get-ConnectedVCenterServers)
    if ($connectedVIServers.Count -eq 0) {
        throw 'No connected vCenters were found. Connect to one or more vCenters first, then rerun the script.'
    }

    Write-Log -Message ("Connected vCenters detected: {0}" -f (($connectedVIServers | Select-Object -ExpandProperty Name) -join ', '))

    $hostNames = @(Get-HostNamesFromInput -HostArgument $cli.HostArgument -CsvPath $cli.CsvPath)
    $resolvedHosts = @()

    if ($hostNames.Count -eq 0) {
        if ($cli.Mode -in @('validate', 'check-connectivity')) {
            Write-Log -Level 'WARN' -Message "No host input was provided. Defaulting to all hosts across connected vCenters for mode '$($cli.Mode)'."
            $resolvedHosts = @(Get-AllConnectedHosts -VIServers $connectedVIServers)
        }
        else {
            throw 'Provide at least one target host by using --host or --csv.'
        }
    }
    else {
        $resolvedHosts = @(Resolve-TargetHosts -HostNames $hostNames -VIServers $connectedVIServers)
    }

    if ($resolvedHosts.Count -eq 0) {
        throw 'None of the requested hosts could be resolved from the connected vCenters.'
    }

    $plainTextPassword = $null
    $connectivityUsername = $null
    if ($cli.Mode -eq 'remediate') {
        $plainTextPassword = Get-PlainTextPassword -ProvidedPassword $cli.Password -PromptMessage 'Enter password for required host user account(s)'
    }
    if ($cli.Mode -eq 'check-connectivity') {
        $connectivityUsername = Get-RequiredValue -ProvidedValue $cli.Username -PromptMessage 'Enter username for ESXi connectivity check'
        $plainTextPassword = Get-PlainTextPassword -ProvidedPassword $cli.Password -PromptMessage 'Enter password for ESXi connectivity check'
    }

    foreach ($resolvedHost in $resolvedHosts) {
        $context = Get-HostContext -VMHost $resolvedHost.VMHost -VCenter $resolvedHost.VCenter
        Write-Log -Message "Processing host '$($context.VMHost.Name)' in vCenter '$($context.VCenter)' and cluster '$($context.Cluster)'."

        $hostConnectivityResult = [pscustomobject]@{
            ConnectivityAttempted = $false
            ConnectivityStatus = 'NotRequested'
            ConnectivityMessage = $null
            PreLockdownMode = $null
            PostLockdownMode = $null
            LockdownTemporarilyDisabled = $false
            LockdownRestoreStatus = 'NotRequested'
        }

        if ($cli.Mode -eq 'check-connectivity') {
            $hostConnectivityResult = Invoke-ConnectivityCheckWithLockdownHandling -Context $context -Username $connectivityUsername -Password $plainTextPassword
        }

        foreach ($username in $RequiredUsernames) {
            $userPresent = $false
            $readOnly = $false
            $lockdownException = $false
            $lockdownMode = $null
            $actionStatus = 'Validated'
            $actionMessage = $null
            $connectivityResult = [pscustomobject]@{
                ConnectivityAttempted = $false
                ConnectivityStatus = 'NotRequested'
                ConnectivityMessage = $null
                PreLockdownMode = $null
                PostLockdownMode = $null
                LockdownTemporarilyDisabled = $false
                LockdownRestoreStatus = 'NotRequested'
            }

            try {
                if ($cli.Mode -eq 'remediate') {
                    Ensure-HostUser -Context $context -Username $username -Password $plainTextPassword
                    Ensure-ReadOnlyAccess -Context $context -Username $username
                    Ensure-LockdownMode -Context $context
                    Ensure-LockdownExceptionUser -Context $context -Username $username
                    $actionStatus = 'Remediated'
                }

                $userPresent = Test-HostUserPresence -Context $context -Username $username

                if ($userPresent) {
                    $entry = Get-HostAccessEntry -Context $context -Username $username
                    $readOnly = ($entry -and $entry.AccessMode -eq 'accessReadOnly')
                }

                $lockdownException = (Get-LockdownExceptions -Context $context) -contains $username
                $lockdownMode = Get-CurrentLockdownMode -Context $context

                if ($cli.Mode -eq 'check-connectivity') {
                    $connectivityResult = $hostConnectivityResult
                    if ($connectivityResult.LockdownRestoreStatus -eq 'Failed') {
                        $actionStatus = 'Failed'
                        $actionMessage = $connectivityResult.ConnectivityMessage
                    }
                }

                if (-not $actionMessage) {
                    $actionMessage = 'Completed successfully.'
                }

                if ($actionStatus -eq 'Failed') {
                    Write-Log -Level 'ERROR' -Message "Completed checks with errors for user '$username' on host '$($context.VMHost.Name)'."
                }
                else {
                    Write-Log -Level 'SUCCESS' -Message "Completed checks for user '$username' on host '$($context.VMHost.Name)'."
                }
            }
            catch {
                $actionStatus = 'Failed'
                $actionMessage = $_.Exception.Message
                Write-Log -Level 'ERROR' -Message "Failed on host '$($context.VMHost.Name)' for user '$username': $actionMessage"
            }

            Add-ReportRow -Row ([pscustomobject]@{
                Timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
                Mode = $cli.Mode
                VCenter = $context.VCenter
                Cluster = $context.Cluster
                Host = $context.VMHost.Name
                Username = $username
                ConnectivityUsername = $connectivityUsername
                UserPresent = $userPresent
                ReadOnlyAccess = $readOnly
                LockdownMode = $lockdownMode
                PreLockdownMode = $connectivityResult.PreLockdownMode
                PostLockdownMode = $connectivityResult.PostLockdownMode
                LockdownTemporarilyDisabled = $connectivityResult.LockdownTemporarilyDisabled
                LockdownRestoreStatus = $connectivityResult.LockdownRestoreStatus
                InLockdownExceptionList = $lockdownException
                ConnectivityAttempted = $connectivityResult.ConnectivityAttempted
                ConnectivityStatus = $connectivityResult.ConnectivityStatus
                ConnectivityMessage = $connectivityResult.ConnectivityMessage
                ActionStatus = $actionStatus
                ActionMessage = $actionMessage
            })
        }
    }

    Export-Report
}
catch {
    Write-Log -Level 'ERROR' -Message $_.Exception.Message
    throw
}
