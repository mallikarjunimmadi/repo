<#
.SYNOPSIS
v0.0.2 of the ESXi local user compliance script.

.DESCRIPTION
This version preserves the existing validation, remediation, and connectivity
behavior while adding clearer documentation for each configuration block,
runtime block, helper function, and the main execution flow.

.NOTES
- Requires an existing PowerCLI session connected to one or more vCenters.
- Uses host-side APIs exposed through vCenter to inspect and manage ESXi
  local users, access mode, lockdown mode, and lockdown exceptions.
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ============================================================================
# Script identity
# The version is logged at runtime so operators can confirm which script
# revision produced the output.
# ============================================================================
$ScriptVersion = '0.0.2'

# ============================================================================
# Configurable settings
# Update these values to match your environment and policy requirements.
#
# RequiredUsernames:
#   One or more ESXi local accounts that must exist on every target host.
#
# ReportDirectory / LogDirectory:
#   Local output folders created under the script directory if they do not
#   already exist.
#
# InputCsvHostColumn:
#   Preferred CSV column name used when importing hosts from a file.
#
# DesiredLockdownMode:
#   Lockdown mode enforced during remediation.
#
# DefaultUserDescription:
#   Description written to newly created ESXi local users.
#
# AllowedHostConnectionStates:
#   Hosts in other states are skipped and recorded as skipped in the report.
# ============================================================================
$RequiredUsernames = @(
    'SOCVA'
)

$ReportDirectory = Join-Path -Path $PSScriptRoot -ChildPath 'reports'
$LogDirectory = Join-Path -Path $PSScriptRoot -ChildPath 'logs'
$InputCsvHostColumn = 'Host'
$DesiredLockdownMode = 'lockdownNormal'
$DefaultUserDescription = 'Managed by vsphere-esxi-hardening script'
$AllowedHostConnectionStates = @('Connected', 'Maintenance')

# ============================================================================
# Runtime state
# These script-scoped variables are shared across helper functions so that
# logging, reporting, and summary tracking stay centralized.
# ============================================================================
$Script:LogFile = $null
$Script:ReportFile = $null
$Script:ReportRows = New-Object System.Collections.Generic.List[object]
$Script:Summary = [ordered]@{
    InputHostCount = 0
    ResolvedHostCount = 0
    ProcessedHostCount = 0
    SkippedHostCount = 0
    SuccessCount = 0
    FailedCount = 0
    SkippedCount = 0
}
$Script:RunStartTime = $null

function Show-Usage {
    <#
    .SYNOPSIS
    Displays command-line usage and examples.

    .DESCRIPTION
    Prints the supported execution modes, accepted parameters, and a few
    operational notes so the script can be run without opening external
    documentation.
    #>
    @'
Usage:
  .\esxi_local_user_compliance_v0.0.2.ps1 --validate --host esxi01
  .\esxi_local_user_compliance_v0.0.2.ps1 --remediate --host esxi01,esxi02 --pass MyPassword!
  .\esxi_local_user_compliance_v0.0.2.ps1 --check-connectivity --csv .\hosts.csv --username SOCVA --pass MyPassword! --lockdown-mode enable

Supported arguments:
  --validate
  --remediate
  --check-connectivity
  --host <host1,host2>
  --csv <path-to-csv>
  --username <username>
  --pass <password>
  --lockdown-mode <enable|disable>
  --help

Notes:
  - Connect to one or more vCenters before running this script.
  - CSV input should contain a host column. Default column name is "Host".
  - The same password is used for all usernames listed in $RequiredUsernames.
  - --validate and --check-connectivity default to all hosts in connected vCenters if no host input is provided.
'@
}

function Initialize-OutputPaths {
    <#
    .SYNOPSIS
    Creates output folders and prepares unique log/report filenames.

    .DESCRIPTION
    Every run gets its own timestamped log and CSV report so results from
    separate executions do not overwrite each other.
    #>
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
    <#
    .SYNOPSIS
    Writes a message to both console and log file.

    .DESCRIPTION
    Standardizes timestamped logging across the script and adds simple color
    coding for warning, error, and success messages in the console.
    #>
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
    <#
    .SYNOPSIS
    Parses CLI arguments into a structured object.

    .DESCRIPTION
    Supports both separated and equals-sign argument styles, validates that
    only one primary mode is chosen, and normalizes the optional lockdown
    preference for connectivity checks.
    #>
    param(
        [string[]]$Arguments
    )

    $parsed = [ordered]@{
        Mode = $null
        HostArgument = $null
        CsvPath = $null
        Username = $null
        Password = $null
        LockdownMode = $null
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
            '^--?lockdown-mode$' {
                if (-not $value) {
                    $index++
                    if ($index -ge $Arguments.Count) {
                        throw "Missing value for $token"
                    }
                    $value = $Arguments[$index]
                }

                $normalizedValue = $value.Trim().ToLowerInvariant()
                if ($normalizedValue -notin @('enable', 'disable')) {
                    throw "--lockdown-mode accepts only 'enable' or 'disable'."
                }

                $parsed.LockdownMode = $normalizedValue
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
    <#
    .SYNOPSIS
    Returns a provided value or prompts the operator for one.

    .DESCRIPTION
    Used for values such as the direct ESXi username during connectivity
    checks, where an empty value should be treated as an execution error.
    #>
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
    <#
    .SYNOPSIS
    Returns a provided password or securely prompts for one.

    .DESCRIPTION
    When prompting, PowerShell returns a SecureString. This helper converts it
    temporarily into plain text because the PowerCLI connection and ESXi user
    creation APIs in this script require a plain-text value.
    #>
    param(
        [string]$ProvidedPassword,
        [string]$PromptMessage = 'Enter password'
    )

    if ($ProvidedPassword -and $ProvidedPassword.Trim()) {
        return $ProvidedPassword.Trim()
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

function Expand-HostTokens {
    <#
    .SYNOPSIS
    Splits a host string into individual host entries.

    .DESCRIPTION
    Accepts commas, spaces, and semicolons so operators can pass host input in
    a flexible format from the command line or from raw CSV/file content.
    #>
    param(
        [AllowNull()]
        [AllowEmptyString()]
        [string]$Value
    )

    if (-not $Value) {
        return @()
    }

    return @(
        ($Value -split '[,\s;]+') |
            Where-Object { $_ -and $_.Trim() } |
            ForEach-Object { $_.Trim() }
    )
}

function Get-ConnectedVCenterServers {
    <#
    .SYNOPSIS
    Returns currently connected PowerCLI vCenter sessions.

    .DESCRIPTION
    Checks both multi-server and single-server PowerCLI globals so the script
    can work whether the operator connected to one vCenter or many.
    #>
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
    <#
    .SYNOPSIS
    Collects target hostnames from CLI and/or CSV input.

    .DESCRIPTION
    Supports both a structured CSV import and a fallback raw-line read. This
    keeps the script resilient even when the CSV is very simple or does not
    perfectly match the preferred column name.
    #>
    param(
        [string]$HostArgument,
        [string]$CsvPath
    )

    $names = New-Object System.Collections.Generic.List[string]

    if ($HostArgument) {
        foreach ($entry in (Expand-HostTokens -Value $HostArgument)) {
            [void]$names.Add($entry)
        }
    }

    if ($CsvPath) {
        if (-not (Test-Path -Path $CsvPath)) {
            throw "CSV file not found: $CsvPath"
        }

        $importedHosts = New-Object System.Collections.Generic.List[string]
        $rows = @()

        try {
            $rows = @(Import-Csv -Path $CsvPath -ErrorAction Stop)
        }
        catch {
            $rows = @()
        }

        foreach ($row in $rows) {
            $propertyName = $InputCsvHostColumn

            if (-not ($row.PSObject.Properties.Name -contains $propertyName)) {
                $propertyName = $row.PSObject.Properties.Name | Select-Object -First 1
                if (-not $propertyName) {
                    continue
                }
            }

            $value = [string]$row.$propertyName
            foreach ($entry in (Expand-HostTokens -Value $value)) {
                [void]$importedHosts.Add($entry)
            }
        }

        if ($importedHosts.Count -gt 0) {
            foreach ($entry in $importedHosts) {
                [void]$names.Add($entry)
            }
        }
        else {
            $rawLines = @(Get-Content -Path $CsvPath -ErrorAction Stop)
            foreach ($line in $rawLines) {
                $trimmedLine = $line.Trim()
                if (-not $trimmedLine) {
                    continue
                }

                if ($trimmedLine -ieq $InputCsvHostColumn) {
                    continue
                }

                foreach ($entry in (Expand-HostTokens -Value $trimmedLine)) {
                    [void]$names.Add($entry)
                }
            }
        }
    }

    return @($names | Sort-Object -Unique)
}

function Resolve-TargetHosts {
    <#
    .SYNOPSIS
    Resolves requested hostnames across all connected vCenters.

    .DESCRIPTION
    Produces a normalized host record containing the VMHost object, parent
    vCenter, host connection state, and a flag that says whether the host is
    eligible for processing.
    #>
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
                [void]$matches.Add([pscustomobject]@{
                    VMHost = $vmHost
                    VCenter = $viServer.Name
                    ConnectionState = $vmHost.ConnectionState.ToString()
                    IsEligible = ($vmHost.ConnectionState.ToString() -in $AllowedHostConnectionStates)
                })
            }
        }

        if ($matches.Count -eq 0) {
            Write-Log -Level 'ERROR' -Message "Host '$hostName' was not found in any connected vCenter."
            continue
        }

        foreach ($match in $matches) {
            [void]$resolvedHosts.Add($match)
        }
    }

    return @($resolvedHosts.ToArray())
}

function Get-AllConnectedHosts {
    <#
    .SYNOPSIS
    Returns all hosts visible through the connected vCenter sessions.

    .DESCRIPTION
    Used when the operator does not specify host input for validation or
    connectivity mode and wants the script to operate on the full inventory.
    #>
    param(
        [array]$VIServers
    )

    $resolvedHosts = New-Object System.Collections.Generic.List[object]

    foreach ($viServer in $VIServers) {
        $vmHosts = @(Get-VMHost -Server $viServer -ErrorAction SilentlyContinue)
        foreach ($vmHost in $vmHosts) {
            [void]$resolvedHosts.Add([pscustomobject]@{
                VMHost = $vmHost
                VCenter = $viServer.Name
                ConnectionState = $vmHost.ConnectionState.ToString()
                IsEligible = ($vmHost.ConnectionState.ToString() -in $AllowedHostConnectionStates)
            })
        }
    }

    return @(
        $resolvedHosts |
            Sort-Object -Property @{ Expression = { $_.VCenter } }, @{ Expression = { $_.VMHost.Name } } -Unique
    )
}

function Get-HostContext {
    <#
    .SYNOPSIS
    Builds the reusable management context for a host.

    .DESCRIPTION
    Loads the host view plus the specific manager objects needed later for user
    enumeration, account creation, access rights, and lockdown operations.
    #>
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
        AccessManagerMoRef = $hostView.ConfigManager.HostAccessManager
        UserDirectory = $userDirectoryView
        AccountManager = $accountManagerView
        AccessManager = $hostAccessManagerView
    }
}

function Test-HostUserPresence {
    <#
    .SYNOPSIS
    Checks whether a local user exists on the host.

    .DESCRIPTION
    Queries the host user directory and matches the returned principal names
    case-insensitively to avoid false negatives caused by casing differences.
    #>
    param(
        [Parameter(Mandatory = $true)]
        [object]$Context,

        [Parameter(Mandatory = $true)]
        [string]$Username
    )

    if (-not $Context.UserDirectory) {
        throw "UserDirectory is not available for host $($Context.VMHost.Name)."
    }

    $normalizedUsername = $Username.Trim().ToLowerInvariant()

    try {
        $results = @($Context.UserDirectory.RetrieveUserGroups('', $Username, '', '', $true, $true, $false))
        return ($results | Where-Object {
            $_.Principal -and $_.Principal.ToString().Trim().ToLowerInvariant() -eq $normalizedUsername
        }).Count -gt 0
    }
    catch {
        if ($_.Exception.Message -match 'could not be found') {
            return $false
        }

        throw
    }
}

function Get-HostAccessEntry {
    <#
    .SYNOPSIS
    Returns the host access entry for a specific local user.

    .DESCRIPTION
    Reads the host access control list and filters for a non-group entry
    matching the requested username.
    #>
    param(
        [Parameter(Mandatory = $true)]
        [object]$Context,

        [Parameter(Mandatory = $true)]
        [string]$Username
    )

    if (-not $Context.AccessManager) {
        throw "HostAccessManager is not available for host $($Context.VMHost.Name)."
    }

    $normalizedUsername = $Username.Trim().ToLowerInvariant()
    $entries = @($Context.AccessManager.RetrieveHostAccessControlEntries())
    return $entries |
        Where-Object {
            $_.Group -eq $false -and
            $_.Principal -and
            $_.Principal.ToString().Trim().ToLowerInvariant() -eq $normalizedUsername
        } |
        Select-Object -First 1
}

function Get-LockdownExceptions {
    <#
    .SYNOPSIS
    Returns the current lockdown exception users for the host.

    .DESCRIPTION
    Wraps the host access manager call and centralizes the availability check
    for clearer downstream error messages.
    #>
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
    <#
    .SYNOPSIS
    Creates the local user if it does not already exist.

    .DESCRIPTION
    Remediation helper that leaves existing accounts unchanged and creates only
    the missing local ESXi user with the configured default description.
    #>
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
    <#
    .SYNOPSIS
    Ensures the local user has ReadOnly host access.

    .DESCRIPTION
    If the access mode is already correct nothing changes; otherwise the host
    access manager updates the account to `accessReadOnly`.
    #>
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
    <#
    .SYNOPSIS
    Ensures the host is in the configured lockdown mode.

    .DESCRIPTION
    Used during remediation so the host-side security posture matches the
    policy defined at the top of the script.
    #>
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
    <#
    .SYNOPSIS
    Reads the current lockdown mode directly from the host view.

    .DESCRIPTION
    Pulls a fresh view instead of relying on cached state so the script can
    verify real-time results after a lockdown change operation.
    #>
    param(
        [Parameter(Mandatory = $true)]
        [object]$Context
    )

    if (-not $Context.VMHost) {
        throw "VMHost is not available in context."
    }

    $freshHostView = Get-View -Id $Context.VMHost.Id -Property Config.LockdownMode
    $lockdownMode = @($freshHostView.Config.LockdownMode | Select-Object -First 1)

    if ($lockdownMode.Count -eq 0 -or -not $lockdownMode[0]) {
        return $null
    }

    return [string]$lockdownMode[0]
}

function Set-LockdownMode {
    <#
    .SYNOPSIS
    Changes the host lockdown mode and verifies the updated value.

    .DESCRIPTION
    This helper is mainly used by connectivity checks that may need to
    temporarily disable lockdown and later restore the original mode.
    #>
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
    <#
    .SYNOPSIS
    Adds the local user to the lockdown exception list if needed.

    .DESCRIPTION
    Reads the current exception list, appends the user if missing, and writes
    back a unique sorted list to avoid duplicate entries.
    #>
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
    <#
    .SYNOPSIS
    Attempts a direct PowerCLI login to an ESXi host.

    .DESCRIPTION
    Used only in connectivity-check mode. The function returns a structured
    result object instead of throwing immediately so the report captures both
    success and failure outcomes cleanly.
    #>
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
    <#
    .SYNOPSIS
    Runs the ESXi connectivity check while honoring lockdown handling rules.

    .DESCRIPTION
    If `--lockdown-mode disable` is chosen and the host is locked down, the
    script temporarily disables lockdown, tests connectivity, and restores the
    original mode in a finally block.
    #>
    param(
        [Parameter(Mandatory = $true)]
        [object]$Context,

        [Parameter(Mandatory = $true)]
        [string]$Username,

        [Parameter(Mandatory = $true)]
        [string]$Password,

        [Parameter(Mandatory = $true)]
        [string]$LockdownModePreference
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
        if ($originalMode -ne 'lockdownDisabled' -and $LockdownModePreference -eq 'disable') {
            Write-Log -Level 'WARN' -Message "Host '$($Context.VMHost.Name)' is in lockdown mode '$originalMode'. Disabling lockdown temporarily for connectivity validation."
            $null = Set-LockdownMode -Context $Context -Mode 'lockdownDisabled'
            $result.LockdownTemporarilyDisabled = $true
        }
        elseif ($originalMode -ne 'lockdownDisabled' -and $LockdownModePreference -eq 'enable') {
            Write-Log -Message "Host '$($Context.VMHost.Name)' is in lockdown mode '$originalMode'. Preserving lockdown because --lockdown-mode enable was requested."
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
    <#
    .SYNOPSIS
    Adds a row to the in-memory and on-disk report.

    .DESCRIPTION
    The report is appended incrementally so data still exists on disk even if
    the run stops partway through a large host list.
    #>
    param(
        [Parameter(Mandatory = $true)]
        [psobject]$Row
    )

    $Script:ReportRows.Add($Row)

    if (Test-Path -Path $Script:ReportFile) {
        $Row | Export-Csv -Path $Script:ReportFile -NoTypeInformation -Append -Force
    }
    else {
        $Row | Export-Csv -Path $Script:ReportFile -NoTypeInformation -Force
    }
}

function Export-Report {
    <#
    .SYNOPSIS
    Finalizes report output messaging.

    .DESCRIPTION
    The CSV itself is written incrementally by Add-ReportRow. This function
    simply reports whether any rows were generated and where the output lives.
    #>
    if ($Script:ReportRows.Count -eq 0) {
        Write-Log -Level 'WARN' -Message 'No report rows were generated.'
        return
    }

    Write-Log -Level 'SUCCESS' -Message "Report written to $($Script:ReportFile)"
    Write-Log -Level 'SUCCESS' -Message "Log written to $($Script:LogFile)"
}

function Write-Summary {
    <#
    .SYNOPSIS
    Writes end-of-run summary metrics to the log.

    .DESCRIPTION
    Produces a compact table showing counts for the active execution mode along
    with start time, end time, and elapsed runtime.
    #>
    $elapsed = $null
    $endTime = Get-Date
    if ($Script:RunStartTime) {
        $elapsed = $endTime - $Script:RunStartTime
    }

    $modeKey = switch ($cli.Mode) {
        'validate' { 'Validate' }
        'remediate' { 'Remediate' }
        'check-connectivity' { 'CheckConnectivity' }
        default { 'Validate' }
    }

    $metrics = @(
        [ordered]@{ Metric = 'InputHosts'; Validate = 0; Remediate = 0; CheckConnectivity = 0 },
        [ordered]@{ Metric = 'ResolvedHosts'; Validate = 0; Remediate = 0; CheckConnectivity = 0 },
        [ordered]@{ Metric = 'ProcessedHosts'; Validate = 0; Remediate = 0; CheckConnectivity = 0 },
        [ordered]@{ Metric = 'SkippedHosts'; Validate = 0; Remediate = 0; CheckConnectivity = 0 },
        [ordered]@{ Metric = 'SuccessRows'; Validate = 0; Remediate = 0; CheckConnectivity = 0 },
        [ordered]@{ Metric = 'FailedRows'; Validate = 0; Remediate = 0; CheckConnectivity = 0 },
        [ordered]@{ Metric = 'SkippedRows'; Validate = 0; Remediate = 0; CheckConnectivity = 0 }
    )

    $metrics[0][$modeKey] = $Script:Summary.InputHostCount
    $metrics[1][$modeKey] = $Script:Summary.ResolvedHostCount
    $metrics[2][$modeKey] = $Script:Summary.ProcessedHostCount
    $metrics[3][$modeKey] = $Script:Summary.SkippedHostCount
    $metrics[4][$modeKey] = $Script:Summary.SuccessCount
    $metrics[5][$modeKey] = $Script:Summary.FailedCount
    $metrics[6][$modeKey] = $Script:Summary.SkippedCount

    Write-Log -Message 'Summary Table:'
    $tableLines = $metrics |
        ForEach-Object { [pscustomobject]$_ } |
        Format-Table -AutoSize |
        Out-String -Width 200

    foreach ($line in ($tableLines -split "`r?`n")) {
        if ($line.Trim()) {
            Write-Log -Message $line
        }
    }

    if ($Script:RunStartTime) {
        Write-Log -Message ("StartTime: {0}" -f $Script:RunStartTime.ToString('yyyy-MM-dd HH:mm:ss'))
    }

    Write-Log -Message ("EndTime: {0}" -f $endTime.ToString('yyyy-MM-dd HH:mm:ss'))

    if ($elapsed) {
        $elapsedLine = "ElapsedTime: {0:00}:{1:00}:{2:00}" -f [int]$elapsed.TotalHours, $elapsed.Minutes, $elapsed.Seconds
        Write-Log -Message $elapsedLine
    }
}

# ============================================================================
# Main execution bootstrap
# Initializes output files and records the run start time before any work is
# done so even early failures are captured in the log.
# ============================================================================
Initialize-OutputPaths
$Script:RunStartTime = Get-Date
Write-Log -Message "Starting ESXi local user compliance script version $ScriptVersion."

try {
    # Parse and validate CLI input before touching vCenter inventory.
    $cli = Parse-Arguments -Arguments $args

    if ($cli.Help) {
        Show-Usage
        exit 0
    }

    if (-not $cli.Mode) {
        throw 'Select one mode: --validate, --remediate, or --check-connectivity.'
    }

    if ($cli.LockdownMode -and $cli.Mode -ne 'check-connectivity') {
        throw '--lockdown-mode can be used only with --check-connectivity.'
    }

    # Discover the current PowerCLI vCenter context. This script intentionally
    # reuses existing authenticated sessions instead of opening new ones.
    $connectedVIServers = @(Get-ConnectedVCenterServers)
    if ($connectedVIServers.Count -eq 0) {
        throw 'No connected vCenters were found. Connect to one or more vCenters first, then rerun the script.'
    }

    Write-Log -Message ("Connected vCenters detected: {0}" -f (($connectedVIServers | Select-Object -ExpandProperty Name) -join ', '))

    # Build the list of requested hostnames from CLI and/or CSV input, then
    # resolve them against the connected vCenter inventory.
    $hostNames = @(Get-HostNamesFromInput -HostArgument $cli.HostArgument -CsvPath $cli.CsvPath)
    $Script:Summary.InputHostCount = $hostNames.Count
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

    $Script:Summary.ResolvedHostCount = $resolvedHosts.Count

    # Gather credentials only for modes that require them.
    $plainTextPassword = $null
    $connectivityUsername = $null
    $connectivityLockdownMode = 'enable'
    if ($cli.Mode -eq 'remediate') {
        $plainTextPassword = Get-PlainTextPassword -ProvidedPassword $cli.Password -PromptMessage 'Enter password for required host user account(s)'
    }
    if ($cli.Mode -eq 'check-connectivity') {
        $connectivityUsername = Get-RequiredValue -ProvidedValue $cli.Username -PromptMessage 'Enter username for ESXi connectivity check'
        $plainTextPassword = Get-PlainTextPassword -ProvidedPassword $cli.Password -PromptMessage 'Enter password for ESXi connectivity check'
        if ($cli.LockdownMode) {
            $connectivityLockdownMode = $cli.LockdownMode
        }
    }

    # Process each resolved host independently so failures on one host do not
    # prevent later hosts from being evaluated and reported.
    foreach ($resolvedHost in $resolvedHosts) {
        $context = Get-HostContext -VMHost $resolvedHost.VMHost -VCenter $resolvedHost.VCenter
        Write-Log -Message "Processing host '$($context.VMHost.Name)' in vCenter '$($context.VCenter)' and cluster '$($context.Cluster)'."

        # Hosts in disallowed states are skipped but still reported for each
        # required username so the CSV stays complete and auditable.
        if (-not $resolvedHost.IsEligible) {
            $Script:Summary.SkippedHostCount++
            $skippedMessage = "Host connection state '$($resolvedHost.ConnectionState)' is not eligible. Allowed states: $($AllowedHostConnectionStates -join ', ')."
            Write-Log -Level 'WARN' -Message "Skipping host '$($context.VMHost.Name)' in vCenter '$($context.VCenter)' because $skippedMessage"

            foreach ($username in $RequiredUsernames) {
                Add-ReportRow -Row ([pscustomobject]@{
                    Timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
                    Mode = $cli.Mode
                    VCenter = $context.VCenter
                    Cluster = $context.Cluster
                    Host = $context.VMHost.Name
                    HostConnectionState = $resolvedHost.ConnectionState
                    Username = $username
                    ConnectivityUsername = $connectivityUsername
                    RequestedLockdownMode = $connectivityLockdownMode
                    UserPresent = $false
                    ReadOnlyAccess = $false
                    LockdownMode = $null
                    PreLockdownMode = $null
                    PostLockdownMode = $null
                    LockdownTemporarilyDisabled = $false
                    LockdownRestoreStatus = 'NotRequested'
                    InLockdownExceptionList = $false
                    ConnectivityAttempted = $false
                    ConnectivityStatus = 'Skipped'
                    ConnectivityMessage = $null
                    ActionStatus = 'Skipped'
                    ActionMessage = $skippedMessage
                })
                $Script:Summary.SkippedCount++
            }

            continue
        }

        $Script:Summary.ProcessedHostCount++

        # Connectivity mode performs a host-level login test once, then the
        # result is reused for each required user row in the report.
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
            $hostConnectivityResult = Invoke-ConnectivityCheckWithLockdownHandling -Context $context -Username $connectivityUsername -Password $plainTextPassword -LockdownModePreference $connectivityLockdownMode
        }

        # Evaluate each required username on the current host. In remediation
        # mode, the script first enforces the desired state and then re-reads
        # the host so the report reflects the post-remediation outcome.
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

                $entry = Get-HostAccessEntry -Context $context -Username $username
                $userPresent = Test-HostUserPresence -Context $context -Username $username

                # Some hosts may return an ACL entry even when UserDirectory does
                # not positively enumerate the account. In that case, keep the
                # report practical by accepting the ACL as evidence of presence.
                if (-not $userPresent -and $entry) {
                    Write-Log -Level 'WARN' -Message "UserDirectory did not return user '$username' on host '$($context.VMHost.Name)'. Falling back to host access entry presence."
                    $userPresent = $true
                }

                $readOnly = ($entry -and $entry.AccessMode -eq 'accessReadOnly')

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
                HostConnectionState = $resolvedHost.ConnectionState
                Username = $username
                ConnectivityUsername = $connectivityUsername
                RequestedLockdownMode = $connectivityLockdownMode
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

            switch ($actionStatus) {
                'Failed' { $Script:Summary.FailedCount++ }
                'Skipped' { $Script:Summary.SkippedCount++ }
                default { $Script:Summary.SuccessCount++ }
            }
        }
    }

    # Final reporting always runs at the end of a successful pass.
    Export-Report
    Write-Summary
}
catch {
    # Even on fatal errors, write the summary and rethrow so callers still see
    # the original failure while logs remain complete.
    Write-Log -Level 'ERROR' -Message $_.Exception.Message
    Write-Summary
    throw
}
