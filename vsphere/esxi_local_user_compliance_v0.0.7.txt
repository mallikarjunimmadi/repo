<#
.SYNOPSIS
v0.0.7 of the ESXi local user compliance script.

.DESCRIPTION
This version preserves the v0.0.5 compliance scope while switching the entry
model to native PowerShell parameters such as `-Validate`, `-Remediate`,
`-CheckConnectivity`, and `-VMHost`.

.NOTES
- Requires an existing PowerCLI session connected to one or more vCenters.
- Uses host-side APIs exposed through vCenter to inspect and manage ESXi
  local users, access mode, lockdown mode, and lockdown exceptions.
#>

[CmdletBinding()]
param(
    [switch]$Validate,
    [switch]$Remediate,
    [switch]$CheckConnectivity,
    [Alias('Host', 'Hosts')]
    [string[]]$VMHost,
    [string]$CsvPath,
    [string[]]$Username,
    [string]$Password,
    [switch]$ForceReset,
    [string]$EsxAdminsGroup,
    [int]$ResolutionChunkSize,
    [ValidateSet('enable', 'disable')]
    [string]$LockdownMode,
    [switch]$Help
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$ScriptVersion = '0.0.7'

$RequiredUsernames = @(
    'SOCVA'
)

$ReportDirectory = Join-Path -Path $PSScriptRoot -ChildPath 'reports'
$LogDirectory = Join-Path -Path $PSScriptRoot -ChildPath 'logs'
$InputCsvHostColumn = 'Host'
$DesiredLockdownMode = 'lockdownNormal'
$DefaultUserDescription = 'Managed by vsphere-esxi-hardening script'
$EsxAdminsGroupSettingName = 'Config.HostAgent.plugins.hostsvc.esxAdminsGroup'
$DesiredEsxAdminsGroupValue = 'CHANGE_ME'
$AllowedHostConnectionStates = @('Connected', 'Maintenance')

$Script:LogFile = $null
$Script:ReportFile = $null
$Script:ReportRows = New-Object System.Collections.Generic.List[object]
$Script:Summary = [ordered]@{
    InputHostCount = 0
    ResolvedHostCount = 0
    ProcessedHostCount = 0
    SkippedHostCount = 0
    TotalPlannedRows = 0
    CompletedRows = 0
    SuccessCount = 0
    FailedCount = 0
    SkippedCount = 0
}
$Script:RunStartTime = $null

function Show-Usage {
    @'
Usage:
  .\esxi_local_user_compliance_v0.0.7.ps1 -Validate -VMHost esxi01 -EsxAdminsGroup 'DOMAIN\ESX-ADMINS'
  .\esxi_local_user_compliance_v0.0.7.ps1 -Validate -VMHost esxi01 -Username SOCVA -EsxAdminsGroup 'DOMAIN\ESX-ADMINS'
  .\esxi_local_user_compliance_v0.0.7.ps1 -Remediate -VMHost esxi01,esxi02 -EsxAdminsGroup 'DOMAIN\ESX-ADMINS'
  .\esxi_local_user_compliance_v0.0.7.ps1 -Remediate -VMHost esxi01 -Username SOCVA -Password MyPassword! -EsxAdminsGroup 'DOMAIN\ESX-ADMINS'
  .\esxi_local_user_compliance_v0.0.7.ps1 -Remediate -VMHost esxi01 -Username SOCVA -Password MyPassword! -ForceReset -EsxAdminsGroup 'DOMAIN\ESX-ADMINS'
  .\esxi_local_user_compliance_v0.0.7.ps1 -CheckConnectivity -CsvPath .\hosts.csv -Username SOCVA -Password MyPassword! -LockdownMode enable
  .\esxi_local_user_compliance_v0.0.7.ps1 -CheckConnectivity -CsvPath .\hosts.csv -Username SOCVA -Password MyPassword! -ResolutionChunkSize 200

Supported arguments:
  -Validate
  -Remediate
  -CheckConnectivity
  -VMHost <host1,host2>
  -CsvPath <path-to-csv>
  -Username <username>
  -Password <password>
  -ForceReset
  -EsxAdminsGroup <value>
  -ResolutionChunkSize <positive-integer>
  -LockdownMode <enable|disable>
  -Help

Notes:
  - Connect to one or more vCenters before running this script.
  - CSV input should contain a host column. Default column name is "Host".
  - For -Validate and -Remediate, -Username overrides $RequiredUsernames and only the supplied username(s) are processed.
  - For -Validate and -Remediate, define the desired esxAdminsGroup value in $DesiredEsxAdminsGroupValue or override it with -EsxAdminsGroup.
  - For remediation, password is required when creating a missing user and optional otherwise unless -ForceReset is used.
  - -ForceReset resets the password only for users that already exist.
  - -Validate, -Remediate, and -CheckConnectivity default to all hosts in connected vCenters if no host input is provided.
  - Host resolution is unchunked by default. Use -ResolutionChunkSize only when you explicitly want chunked host lookup batches.
'@
}

function Initialize-OutputPaths {
    param(
        [string]$Mode
    )

    $timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
    $modeSuffix = if ($Mode -and $Mode.Trim()) {
        $Mode.Trim().ToLowerInvariant().Replace('-', '_')
    }
    else {
        'run'
    }

    foreach ($directory in @($ReportDirectory, $LogDirectory)) {
        if (-not (Test-Path -Path $directory)) {
            New-Item -Path $directory -ItemType Directory -Force | Out-Null
        }
    }

    $Script:LogFile = Join-Path -Path $LogDirectory -ChildPath "vsphere-esxi-hardening_${modeSuffix}_$timestamp.log"
    $Script:ReportFile = Join-Path -Path $ReportDirectory -ChildPath "vsphere-esxi-hardening_${modeSuffix}_$timestamp.csv"
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

    if ($Script:LogFile) {
        Add-Content -Path $Script:LogFile -Value $line
    }
}

function Write-RunProgress {
    param(
        [switch]$Completed
    )

    $total = [int]$Script:Summary.TotalPlannedRows
    $done = [int]$Script:Summary.CompletedRows

    if ($total -le 0) {
        return
    }

    $percentComplete = [int](($done / $total) * 100)
    if ($percentComplete -gt 100) {
        $percentComplete = 100
    }

    $status = "$done of $total completed"
    $currentOperation = if ($Completed) { 'Run complete' } else { 'Processing host user checks' }

    Write-Progress -Activity 'ESXi local user compliance' -Status $status -CurrentOperation $currentOperation -PercentComplete $percentComplete -Completed:$Completed
}

function Write-DiscoveryProgress {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Activity,

        [Parameter(Mandatory = $true)]
        [string]$Status,

        [string]$CurrentOperation,

        [int]$PercentComplete = -1,

        [switch]$Completed
    )

    Write-Progress -Id 1 -Activity $Activity -Status $Status -CurrentOperation $CurrentOperation -PercentComplete $PercentComplete -Completed:$Completed
}

function Write-ValidationSnapshotLog {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Mode,

        [Parameter(Mandatory = $true)]
        [object]$Context,

        [string]$Username,

        [Parameter(Mandatory = $true)]
        [object]$Snapshot
    )

    $identityLabel = if ($Mode -eq 'check-connectivity') { 'Connectivity user' } else { 'User' }
    $identityValue = if ($Mode -eq 'check-connectivity') { $Username } else { $Username }
    $identityText = if ($identityValue) { "$identityLabel '$identityValue'" } else { $identityLabel }

    Write-Log -Message "Validation results for $identityText on host '$($Context.VMHost.Name)':"
    Write-Log -Message "  UserPresent: $($Snapshot.UserPresent)"
    Write-Log -Message "  ReadOnlyAccess: $($Snapshot.ReadOnlyAccess)"
    Write-Log -Message "  DomainJoined: $($Snapshot.DomainJoined)"
    Write-Log -Message "  DomainName: $($Snapshot.DomainName)"
    Write-Log -Message "  DomainMembershipStatus: $($Snapshot.DomainMembershipStatus)"
    Write-Log -Message "  EsxAdminsGroupExpected: $($Snapshot.EsxAdminsGroupExpected)"
    Write-Log -Message "  EsxAdminsGroupActual: $($Snapshot.EsxAdminsGroupActual)"
    Write-Log -Message "  EsxAdminGroupStatus: $($Snapshot.EsxAdminGroupStatus)"
    Write-Log -Message "  LockdownMode: $($Snapshot.LockdownMode)"
    Write-Log -Message "  InLockdownExceptionList: $($Snapshot.InLockdownExceptionList)"
}

function Get-ReportColumnNames {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Mode
    )

    switch ($Mode) {
        'validate' {
            return @(
                'Timestamp',
                'Mode',
                'VCenter',
                'Cluster',
                'Host',
                'HostConnectionState',
                'Username',
                'UserPresent',
                'ReadOnlyAccess',
                'DomainJoined',
                'DomainName',
                'DomainMembershipStatus',
                'EsxAdminsGroupExpected',
                'EsxAdminsGroupActual',
                'EsxAdminGroupStatus',
                'LockdownMode',
                'InLockdownExceptionList',
                'ActionStatus',
                'ActionMessage'
            )
        }
        'remediate' {
            return @(
                'Timestamp',
                'Mode',
                'VCenter',
                'Cluster',
                'Host',
                'HostConnectionState',
                'Username',
                'UserPresent',
                'ReadOnlyAccess',
                'DomainJoined',
                'DomainName',
                'DomainMembershipStatus',
                'EsxAdminsGroupExpected',
                'EsxAdminsGroupActual',
                'EsxAdminGroupStatus',
                'EsxAdminsGroupRemediationStatus',
                'LockdownMode',
                'InLockdownExceptionList',
                'PasswordResetStatus',
                'ActionStatus',
                'ActionMessage'
            )
        }
        'check-connectivity' {
            return @(
                'Timestamp',
                'Mode',
                'VCenter',
                'Cluster',
                'Host',
                'HostConnectionState',
                'ConnectivityUsername',
                'RequestedLockdownMode',
                'PreLockdownMode',
                'PostLockdownMode',
                'LockdownTemporarilyDisabled',
                'LockdownRestoreStatus',
                'ConnectivityAttempted',
                'ConnectivityStatus',
                'ConnectivityMessage',
                'ActionStatus',
                'ActionMessage'
            )
        }
        default {
            throw "Unsupported report mode: $Mode"
        }
    }
}

function New-ModeReportRow {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Mode,

        [Parameter(Mandatory = $true)]
        [hashtable]$Data
    )

    $row = [ordered]@{}
    foreach ($columnName in (Get-ReportColumnNames -Mode $Mode)) {
        $row[$columnName] = if ($Data.Contains($columnName)) { $Data[$columnName] } else { $null }
    }

    return [pscustomobject]$row
}

function New-CliOptionsFromParameters {
    $selectedModes = @(
        if ($Validate) { 'validate' }
        if ($Remediate) { 'remediate' }
        if ($CheckConnectivity) { 'check-connectivity' }
    )

    if ($selectedModes.Count -gt 1) {
        throw 'Specify only one mode: -Validate, -Remediate, or -CheckConnectivity.'
    }

    return [pscustomobject]@{
        Mode = if ($selectedModes.Count -eq 1) { $selectedModes[0] } else { $null }
        HostArgument = @($VMHost)
        CsvPath = $CsvPath
        Username = if ($Username) { ($Username -join ',') } else { $null }
        Password = $Password
        ForceReset = [bool]$ForceReset
        EsxAdminsGroup = $EsxAdminsGroup
        ResolutionChunkSize = $ResolutionChunkSize
        ResolutionChunkingEnabled = ($PSBoundParameters.ContainsKey('ResolutionChunkSize') -and $ResolutionChunkSize -gt 0)
        LockdownMode = $LockdownMode
        Help = [bool]$Help
    }
}

function Get-EffectiveRequiredUsernames {
    param(
        [string]$OverrideValue
    )

    if ($OverrideValue -and $OverrideValue.Trim()) {
        return @(Expand-HostTokens -Value $OverrideValue | Sort-Object -Unique)
    }

    return @(
        $RequiredUsernames |
            Where-Object {
                $_ -and
                $_.ToString().Trim() -and
                $_.ToString().Trim() -cne 'CHANGE_ME'
            } |
            ForEach-Object { $_.ToString().Trim() } |
            Sort-Object -Unique
    )
}

function Get-EffectiveEsxAdminsGroupValue {
    param(
        [string]$OverrideValue
    )

    if ($OverrideValue -and $OverrideValue.Trim()) {
        return $OverrideValue.Trim()
    }

    if ($DesiredEsxAdminsGroupValue -and $DesiredEsxAdminsGroupValue.Trim() -and $DesiredEsxAdminsGroupValue.Trim() -cne 'CHANGE_ME') {
        return $DesiredEsxAdminsGroupValue.Trim()
    }

    return $null
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

function Get-UsernameWithDefault {
    param(
        [string]$ProvidedValue,
        [string]$PromptMessage,
        [string]$DefaultValue = 'SOCVA'
    )

    if ($ProvidedValue -and $ProvidedValue.Trim()) {
        Write-Log -Message "Username source: command-line parameter provided ('$($ProvidedValue.Trim())')."
        return $ProvidedValue.Trim()
    }

    $promptSuffix = if ($DefaultValue -and $DefaultValue.Trim()) {
        "$PromptMessage [$DefaultValue]"
    }
    else {
        $PromptMessage
    }

    $value = Read-Host -Prompt $promptSuffix
    if ($value -and $value.Trim()) {
        $selectedValue = $value.Trim()
    }
    elseif ($DefaultValue -and $DefaultValue.Trim()) {
        $selectedValue = $DefaultValue.Trim()
    }
    else {
        throw "$PromptMessage is required."
    }

    Write-Log -Message "Username source: interactive prompt selected '$selectedValue'."
    return $selectedValue
}

function Confirm-Remediation {
    param(
        [string[]]$TargetHosts,
        [string[]]$TargetUsernames
    )

    $hostSummary = if ($TargetHosts -and $TargetHosts.Count -gt 0) {
        ($TargetHosts -join ', ')
    }
    else {
        'ALL HOSTS'
    }

    $userSummary = if ($TargetUsernames -and $TargetUsernames.Count -gt 0) {
        ($TargetUsernames -join ', ')
    }
    else {
        'configured target users'
    }

    $confirmation = Read-Host -Prompt "Confirm remediation for hosts [$hostSummary] and users [$userSummary]. Type YES to continue"
    Write-Log -Message "Remediation confirmation response received: '$confirmation'."
    if ($confirmation -notin @('YES', 'Yes', 'Y', 'y')) {
        throw 'Remediation cancelled by user.'
    }
}

function Get-PlainTextPassword {
    param(
        [string]$ProvidedPassword,
        [string]$PromptMessage = 'Enter password'
    )

    if ($ProvidedPassword -and $ProvidedPassword.Trim()) {
        Write-Log -Message 'Password source: command-line parameter provided.'
        return $ProvidedPassword.Trim()
    }

    Write-Log -Message "Password source: interactive prompt ('$PromptMessage')."
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
        [string[]]$HostArgument,
        [string]$CsvPath
    )

    $names = New-Object System.Collections.Generic.List[string]

    if ($HostArgument) {
        foreach ($hostValue in $HostArgument) {
            foreach ($entry in (Expand-HostTokens -Value $hostValue)) {
                [void]$names.Add($entry)
            }
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

function Split-Collection {
    param(
        [Parameter(Mandatory = $true)]
        [object[]]$Items,

        [int]$ChunkSize = 200
    )

    if ($ChunkSize -le 0) {
        throw 'ChunkSize must be greater than zero.'
    }

    $chunks = New-Object System.Collections.Generic.List[object[]]
    for ($index = 0; $index -lt $Items.Count; $index += $ChunkSize) {
        $remaining = $Items.Count - $index
        $currentSize = [Math]::Min($ChunkSize, $remaining)
        $chunk = New-Object object[] $currentSize
        [Array]::Copy($Items, $index, $chunk, 0, $currentSize)
        [void]$chunks.Add($chunk)
    }

    return @($chunks.ToArray())
}

function Get-ReportLoopIdentities {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Mode,

        [string[]]$TargetUsernames
    )

    if ($Mode -eq 'check-connectivity') {
        return @('__connectivity__')
    }

    return @($TargetUsernames)
}

function Resolve-TargetHosts {
    param(
        [string[]]$HostNames,
        [array]$VIServers,
        [int]$ChunkSize = 0
    )

    $resolvedHosts = New-Object System.Collections.Generic.List[object]
    $resolvedByKey = @{}
    $resolvedEntryKeys = @{}
    $totalVIServers = @($VIServers).Count

    if ($ChunkSize -gt 0) {
        $hostNameChunks = @(Split-Collection -Items $HostNames -ChunkSize $ChunkSize)
        $totalChunks = [Math]::Max(($totalVIServers * $hostNameChunks.Count), 1)
        $completedChunks = 0
        Write-Log -Message "Resolving $($HostNames.Count) requested host name(s) across $totalVIServers connected vCenter(s) in $($hostNameChunks.Count) chunk(s) of size $ChunkSize."
        foreach ($viServer in $VIServers) {
            $currentChunkIndex = 0
            foreach ($hostNameChunk in $hostNameChunks) {
                $currentChunkIndex++
                $completedChunks++
                $percentComplete = [int](($completedChunks / $totalChunks) * 100)
                Write-DiscoveryProgress -Activity 'Resolving target hosts' -Status "Scanning vCenter chunk $completedChunks of $totalChunks" -CurrentOperation "$($viServer.Name) [chunk $currentChunkIndex of $($hostNameChunks.Count)]" -PercentComplete $percentComplete
                Write-Log -Message "Resolving host chunk $currentChunkIndex of $($hostNameChunks.Count) against vCenter '$($viServer.Name)'."
                $vmHosts = @(Get-VMHost -Server $viServer -Name $hostNameChunk -ErrorAction SilentlyContinue)
                Write-Log -Message "Resolved $($vmHosts.Count) host(s) in chunk $currentChunkIndex from vCenter '$($viServer.Name)'."

                foreach ($vmHost in $vmHosts) {
                    $inventoryEntry = [pscustomobject]@{
                        VMHost = $vmHost
                        VCenter = $viServer.Name
                        ConnectionState = $vmHost.ConnectionState.ToString()
                        IsEligible = ($vmHost.ConnectionState.ToString() -in $AllowedHostConnectionStates)
                    }

                    $hostNameKeys = New-Object System.Collections.Generic.List[string]
                    if ($vmHost.Name) {
                        [void]$hostNameKeys.Add($vmHost.Name.ToString())

                        $shortHostName = $vmHost.Name.ToString().Split('.')[0]
                        if ($shortHostName) {
                            [void]$hostNameKeys.Add($shortHostName)
                        }
                    }

                    foreach ($lookupKey in ($hostNameKeys | Select-Object -Unique)) {
                        if (-not $lookupKey) {
                            continue
                        }

                        $normalizedKey = $lookupKey.ToString().Trim().ToLowerInvariant()
                        if (-not $normalizedKey) {
                            continue
                        }

                        if (-not $resolvedByKey.ContainsKey($normalizedKey)) {
                            $resolvedByKey[$normalizedKey] = New-Object System.Collections.Generic.List[object]
                            $resolvedEntryKeys[$normalizedKey] = @{}
                        }

                        $entryKey = "$($viServer.Name)|$($vmHost.Id)"
                        if (-not $resolvedEntryKeys[$normalizedKey].ContainsKey($entryKey)) {
                            [void]$resolvedByKey[$normalizedKey].Add($inventoryEntry)
                            $resolvedEntryKeys[$normalizedKey][$entryKey] = $true
                        }
                    }
                }
            }
        }
    }
    else {
        Write-Log -Message "Resolving $($HostNames.Count) requested host name(s) across $totalVIServers connected vCenter(s) without chunking."
        $currentVIServerIndex = 0

        foreach ($viServer in $VIServers) {
            $currentVIServerIndex++
            $percentComplete = [int](($currentVIServerIndex / [Math]::Max($totalVIServers, 1)) * 100)
            Write-DiscoveryProgress -Activity 'Resolving target hosts' -Status "Scanning vCenter $currentVIServerIndex of $totalVIServers" -CurrentOperation $viServer.Name -PercentComplete $percentComplete
            Write-Log -Message "Resolving all requested hosts against vCenter '$($viServer.Name)' without chunking."
            $vmHosts = @(Get-VMHost -Server $viServer -Name $HostNames -ErrorAction SilentlyContinue)
            Write-Log -Message "Resolved $($vmHosts.Count) host(s) from vCenter '$($viServer.Name)' without chunking."

            foreach ($vmHost in $vmHosts) {
                $inventoryEntry = [pscustomobject]@{
                    VMHost = $vmHost
                    VCenter = $viServer.Name
                    ConnectionState = $vmHost.ConnectionState.ToString()
                    IsEligible = ($vmHost.ConnectionState.ToString() -in $AllowedHostConnectionStates)
                }

                $hostNameKeys = New-Object System.Collections.Generic.List[string]
                if ($vmHost.Name) {
                    [void]$hostNameKeys.Add($vmHost.Name.ToString())

                    $shortHostName = $vmHost.Name.ToString().Split('.')[0]
                    if ($shortHostName) {
                        [void]$hostNameKeys.Add($shortHostName)
                    }
                }

                foreach ($lookupKey in ($hostNameKeys | Select-Object -Unique)) {
                    if (-not $lookupKey) {
                        continue
                    }

                    $normalizedKey = $lookupKey.ToString().Trim().ToLowerInvariant()
                    if (-not $normalizedKey) {
                        continue
                    }

                    if (-not $resolvedByKey.ContainsKey($normalizedKey)) {
                        $resolvedByKey[$normalizedKey] = New-Object System.Collections.Generic.List[object]
                        $resolvedEntryKeys[$normalizedKey] = @{}
                    }

                    $entryKey = "$($viServer.Name)|$($vmHost.Id)"
                    if (-not $resolvedEntryKeys[$normalizedKey].ContainsKey($entryKey)) {
                        [void]$resolvedByKey[$normalizedKey].Add($inventoryEntry)
                        $resolvedEntryKeys[$normalizedKey][$entryKey] = $true
                    }
                }
            }
        }
    }

    foreach ($hostName in $HostNames) {
        $normalizedHostName = $hostName.Trim().ToLowerInvariant()
        $matches = @(
            if ($resolvedByKey.ContainsKey($normalizedHostName)) {
                $resolvedByKey[$normalizedHostName].ToArray()
            }
        )

        if ($matches.Count -eq 0) {
            Write-Log -Level 'ERROR' -Message "Host '$hostName' was not found in any connected vCenter."
            continue
        }

        foreach ($match in $matches) {
            [void]$resolvedHosts.Add($match)
        }
    }

    Write-DiscoveryProgress -Activity 'Resolving target hosts' -Status "Resolved $($resolvedHosts.Count) host(s)" -CurrentOperation 'Host resolution complete' -Completed

    return @($resolvedHosts.ToArray())
}

function Get-AllConnectedHosts {
    param(
        [array]$VIServers
    )

    $resolvedHosts = New-Object System.Collections.Generic.List[object]
    $totalVIServers = @($VIServers).Count
    $currentVIServerIndex = 0

    Write-Log -Message "Enumerating all ESXi hosts from $totalVIServers connected vCenter(s)."

    foreach ($viServer in $VIServers) {
        $currentVIServerIndex++
        Write-DiscoveryProgress -Activity 'Enumerating connected hosts' -Status "Scanning vCenter $currentVIServerIndex of $totalVIServers" -CurrentOperation $viServer.Name -PercentComplete ([int](($currentVIServerIndex / [Math]::Max($totalVIServers, 1)) * 100))
        Write-Log -Message "Fetching all ESXi hosts from vCenter '$($viServer.Name)'."
        $vmHosts = @(Get-VMHost -Server $viServer -ErrorAction SilentlyContinue)
        Write-Log -Message "Fetched $($vmHosts.Count) host(s) from vCenter '$($viServer.Name)'."
        foreach ($vmHost in $vmHosts) {
            [void]$resolvedHosts.Add([pscustomobject]@{
                VMHost = $vmHost
                VCenter = $viServer.Name
                ConnectionState = $vmHost.ConnectionState.ToString()
                IsEligible = ($vmHost.ConnectionState.ToString() -in $AllowedHostConnectionStates)
            })
        }
    }

    Write-DiscoveryProgress -Activity 'Enumerating connected hosts' -Status "Resolved $($resolvedHosts.Count) host(s)" -CurrentOperation 'Host enumeration complete' -Completed

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
        AccessManagerMoRef = $hostView.ConfigManager.HostAccessManager
        UserDirectory = $userDirectoryView
        AccountManager = $accountManagerView
        AccessManager = $hostAccessManagerView
    }
}

function Get-ConnectivityHostContext {
    param(
        [Parameter(Mandatory = $true)]
        [object]$VMHost,

        [Parameter(Mandatory = $true)]
        [string]$VCenter
    )

    $cluster = @(Get-Cluster -VMHost $VMHost -ErrorAction SilentlyContinue | Select-Object -First 1)
    $hostView = Get-View -Id $VMHost.Id -Property ConfigManager.HostAccessManager
    $hostAccessManagerView = $null

    if ($hostView.ConfigManager.HostAccessManager) {
        $hostAccessManagerView = Get-View -Id $hostView.ConfigManager.HostAccessManager
    }

    return [pscustomobject]@{
        VMHost = $VMHost
        VCenter = $VCenter
        Cluster = if ($cluster) { $cluster.Name } else { 'Standalone' }
        HostView = $hostView
        AccessManagerMoRef = $hostView.ConfigManager.HostAccessManager
        UserDirectory = $null
        AccountManager = $null
        AccessManager = $hostAccessManagerView
    }
}

function Get-HostDomainMembershipInfo {
    param(
        [Parameter(Mandatory = $true)]
        [object]$Context
    )

    $result = [ordered]@{
        DomainJoined = $null
        DomainName = $null
        DomainMembershipStatus = $null
    }

    $freshHostView = Get-View -Id $Context.VMHost.Id -Property Config.AuthenticationManagerInfo
    $authConfig = @($freshHostView.Config.AuthenticationManagerInfo.AuthConfig)
    $adConfig = @(
        $authConfig | Where-Object {
            $_ -and (
                $_.GetType().Name -eq 'HostActiveDirectoryInfo' -or
                $_.PSObject.Properties.Name -contains 'JoinedDomain'
            )
        } | Select-Object -First 1
    )

    if ($adConfig.Count -eq 0 -or -not $adConfig[0]) {
        return [pscustomobject]$result
    }

    $result.DomainJoined = [bool]$adConfig[0].Enabled

    if ($adConfig[0].PSObject.Properties.Name -contains 'JoinedDomain') {
        $result.DomainName = [string]$adConfig[0].JoinedDomain
    }

    if ($adConfig[0].PSObject.Properties.Name -contains 'DomainMembershipStatus') {
        $result.DomainMembershipStatus = [string]$adConfig[0].DomainMembershipStatus
    }

    return [pscustomobject]$result
}

function Get-EsxAdminsGroupState {
    param(
        [Parameter(Mandatory = $true)]
        [object]$Context,

        [string]$ExpectedValue
    )

    $result = [ordered]@{
        EsxAdminsGroupExpected = $ExpectedValue
        EsxAdminsGroupActual = $null
        EsxAdminGroupStatus = if ($ExpectedValue -eq $null) { 'Skipped' } else { $null }
    }

    $setting = @(Get-AdvancedSetting -Entity $Context.VMHost -Name $EsxAdminsGroupSettingName -ErrorAction SilentlyContinue | Select-Object -First 1)
    if ($setting.Count -eq 0 -or -not $setting[0]) {
        return [pscustomobject]$result
    }

    $actualValue = [string]$setting[0].Value
    $result.EsxAdminsGroupActual = $actualValue

    if ($ExpectedValue -ne $null) {
        $result.EsxAdminGroupStatus = if ($actualValue -ceq $ExpectedValue) { 'Valid' } else { 'Invalid' }
    }
    else {
        $result.EsxAdminGroupStatus = 'Skipped'
    }

    return [pscustomobject]$result
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

    $normalizedUsername = $Username.Trim().ToLowerInvariant()

    $queries = @(
        @{ Search = $Username; ExactMatch = $true },
        @{ Search = $Username; ExactMatch = $false },
        @{ Search = ''; ExactMatch = $false }
    )

    foreach ($query in $queries) {
        try {
            $results = @($Context.UserDirectory.RetrieveUserGroups('', $query.Search, '', '', $true, $true, $query.ExactMatch))
            $matchingResults = @($results | Where-Object {
                $_.Principal -and $_.Principal.ToString().Trim().ToLowerInvariant() -eq $normalizedUsername
            })

            if ($matchingResults.Count -gt 0) {
                return $true
            }
        }
        catch {
            if ($_.Exception.Message -match 'could not be found') {
                continue
            }

            throw
        }
    }

    return $false
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

    if ((Test-HostUserPresence -Context $Context -Username $Username) -or
        (Get-HostAccessEntry -Context $Context -Username $Username)) {
        Write-Log -Message "User '$Username' already exists on host '$($Context.VMHost.Name)'."
        return $false
    }

    if (-not $Context.AccountManager) {
        throw "AccountManager is not available for host $($Context.VMHost.Name)."
    }

    $userSpec = New-Object VMware.Vim.HostAccountSpec
    $userSpec.Id = $Username
    $userSpec.Password = $Password
    $userSpec.Description = $DefaultUserDescription

    try {
        $Context.AccountManager.CreateUser($userSpec)
        Write-Log -Level 'SUCCESS' -Message "Created user '$Username' on host '$($Context.VMHost.Name)'."
        return $true
    }
    catch {
        if ($_.Exception.Message -match 'already exists') {
            Write-Log -Level 'WARN' -Message "User '$Username' already exists on host '$($Context.VMHost.Name)'. Continuing with access validation."
            return $false
        }

        throw
    }
}

function Reset-HostUserPassword {
    param(
        [Parameter(Mandatory = $true)]
        [object]$Context,

        [Parameter(Mandatory = $true)]
        [string]$Username,

        [Parameter(Mandatory = $true)]
        [string]$Password
    )

    if (-not $Context.AccountManager) {
        throw "AccountManager is not available for host $($Context.VMHost.Name)."
    }

    $userSpec = New-Object VMware.Vim.HostAccountSpec
    $userSpec.Id = $Username
    $userSpec.Password = $Password

    $Context.AccountManager.UpdateUser($userSpec)
    Write-Log -Level 'SUCCESS' -Message "Reset password for user '$Username' on host '$($Context.VMHost.Name)'."
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

    $currentMode = Get-CurrentLockdownMode -Context $Context
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

    if (-not $Context.VMHost) {
        throw 'VMHost is not available in context.'
    }

    $freshHostView = Get-View -Id $Context.VMHost.Id -Property Config.LockdownMode
    $lockdownMode = @($freshHostView.Config.LockdownMode | Select-Object -First 1)

    if ($lockdownMode.Count -eq 0 -or -not $lockdownMode[0]) {
        return $null
    }

    return [string]$lockdownMode[0]
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

    $existingExceptions = @($currentExceptions | ForEach-Object { $_.ToString().Trim().ToLowerInvariant() })
    if ($existingExceptions -contains $Username.Trim().ToLowerInvariant()) {
        Write-Log -Message "User '$Username' is already in the lockdown exception list on host '$($Context.VMHost.Name)'."
        return
    }

    [void]$currentExceptions.Add($Username)
    $Context.AccessManager.UpdateLockdownExceptions(@($currentExceptions | Sort-Object -Unique))
    Write-Log -Level 'SUCCESS' -Message "Added '$Username' to lockdown exceptions on host '$($Context.VMHost.Name)'."
}

function Get-UserComplianceSnapshot {
    param(
        [Parameter(Mandatory = $true)]
        [object]$Context,

        [Parameter(Mandatory = $true)]
        [string]$Username,

        [string]$ExpectedEsxAdminsGroupValue
    )

    $snapshot = [ordered]@{
        UserPresent = $false
        ReadOnlyAccess = $false
        LockdownMode = $null
        InLockdownExceptionList = $false
        DomainJoined = $null
        DomainName = $null
        DomainMembershipStatus = $null
        EsxAdminsGroupExpected = $ExpectedEsxAdminsGroupValue
        EsxAdminsGroupActual = $null
        EsxAdminGroupStatus = $null
    }

    try {
        $entry = Get-HostAccessEntry -Context $Context -Username $Username
        $userPresent = Test-HostUserPresence -Context $Context -Username $Username

        if (-not $userPresent -and $entry) {
            Write-Log -Level 'WARN' -Message "UserDirectory did not return user '$Username' on host '$($Context.VMHost.Name)'. Falling back to host access entry presence."
            $userPresent = $true
        }

        $snapshot.UserPresent = $userPresent
        $snapshot.ReadOnlyAccess = ($entry -and $entry.AccessMode -eq 'accessReadOnly')

        $exceptions = @(Get-LockdownExceptions -Context $Context | ForEach-Object { $_.ToString().Trim().ToLowerInvariant() })
        $snapshot.InLockdownExceptionList = $exceptions -contains $Username.Trim().ToLowerInvariant()
        $snapshot.LockdownMode = Get-CurrentLockdownMode -Context $Context

        $domainInfo = Get-HostDomainMembershipInfo -Context $Context
        $snapshot.DomainJoined = $domainInfo.DomainJoined
        $snapshot.DomainName = $domainInfo.DomainName
        $snapshot.DomainMembershipStatus = $domainInfo.DomainMembershipStatus

        $esxAdminsGroupState = Get-EsxAdminsGroupState -Context $Context -ExpectedValue $ExpectedEsxAdminsGroupValue
        $snapshot.EsxAdminsGroupExpected = $esxAdminsGroupState.EsxAdminsGroupExpected
        $snapshot.EsxAdminsGroupActual = $esxAdminsGroupState.EsxAdminsGroupActual
        $snapshot.EsxAdminGroupStatus = $esxAdminsGroupState.EsxAdminGroupStatus
    }
    catch {
        Write-Log -Level 'WARN' -Message "Unable to fully refresh compliance state for user '$Username' on host '$($Context.VMHost.Name)': $($_.Exception.Message)"
    }

    return [pscustomobject]$snapshot
}

function Ensure-EsxAdminsGroupSetting {
    param(
        [Parameter(Mandatory = $true)]
        [object]$Context,

        [string]$DesiredValue
    )

    if (-not $DesiredValue) {
        Write-Log -Level 'WARN' -Message "Skipping advanced setting '$EsxAdminsGroupSettingName' remediation on host '$($Context.VMHost.Name)' because no desired value is configured."
        return 'Skipped'
    }

    $setting = @(Get-AdvancedSetting -Entity $Context.VMHost -Name $EsxAdminsGroupSettingName -ErrorAction SilentlyContinue | Select-Object -First 1)
    if ($setting.Count -gt 0 -and $setting[0]) {
        if ([string]$setting[0].Value -ceq $DesiredValue) {
            Write-Log -Message "Advanced setting '$EsxAdminsGroupSettingName' already matches the desired value '$([string]$setting[0].Value)' on host '$($Context.VMHost.Name)'."
            return 'AlreadyCompliant'
        }

        $null = ($setting[0] | Set-AdvancedSetting -Value $DesiredValue -Confirm:$false)
        Write-Log -Level 'SUCCESS' -Message "Updated advanced setting '$EsxAdminsGroupSettingName' to '$DesiredValue' on host '$($Context.VMHost.Name)'."
        return 'Success'
    }

    $null = New-AdvancedSetting -Entity $Context.VMHost -Name $EsxAdminsGroupSettingName -Value $DesiredValue -Confirm:$false
    Write-Log -Level 'SUCCESS' -Message "Created advanced setting '$EsxAdminsGroupSettingName' with value '$DesiredValue' on host '$($Context.VMHost.Name)'."
    return 'Success'
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
        Write-Log -Level 'SUCCESS' -Message "Connectivity test succeeded for host '$Hostname' with username '$Username'."

        if ($hostConnection) {
            Disconnect-VIServer -Server $hostConnection -Confirm:$false | Out-Null
            Write-Log -Message "Disconnected connectivity test session from host '$Hostname'."
        }
    }
    catch {
        $result.ConnectivityMessage = $_.Exception.Message
        Write-Log -Level 'ERROR' -Message "Connectivity test failed for host '$Hostname' with username '$Username': $($result.ConnectivityMessage)"
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
            Write-Log -Message "Host '$($Context.VMHost.Name)' is in lockdown mode '$originalMode'. Preserving lockdown because -LockdownMode enable was requested."
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

    if (Test-Path -Path $Script:ReportFile) {
        $Row | Export-Csv -Path $Script:ReportFile -NoTypeInformation -Append -Force
    }
    else {
        $Row | Export-Csv -Path $Script:ReportFile -NoTypeInformation -Force
    }

    $Script:Summary.CompletedRows++
    Write-RunProgress
}

function Export-Report {
    if ($Script:ReportRows.Count -eq 0) {
        Write-Log -Level 'WARN' -Message 'No report rows were generated.'
        return
    }

    Write-Log -Level 'SUCCESS' -Message "Report written to $($Script:ReportFile)"
    Write-Log -Level 'SUCCESS' -Message "Log written to $($Script:LogFile)"
}

function Write-Summary {
    $elapsed = $null
    $endTime = Get-Date
    if ($Script:RunStartTime) {
        $elapsed = $endTime - $Script:RunStartTime
    }

    $modeName = $null
    if (Get-Variable -Name cli -Scope Script -ErrorAction SilentlyContinue) {
        $modeName = $script:cli.Mode
    }

    $modeKey = switch ($modeName) {
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

try {
    $cli = New-CliOptionsFromParameters
    $script:cli = $cli

    if ($cli.Help) {
        Show-Usage
        exit 0
    }

    if (-not $cli.Mode) {
        throw 'Select one mode: -Validate, -Remediate, or -CheckConnectivity.'
    }

    Initialize-OutputPaths -Mode $cli.Mode
    $Script:RunStartTime = Get-Date
    Write-Log -Message "Starting ESXi local user compliance script version $ScriptVersion."

    Write-Log -Message "Execution mode selected: $($cli.Mode)"
    if ($cli.HostArgument -and $cli.HostArgument.Count -gt 0) {
        Write-Log -Message ("Host input provided via -VMHost: {0}" -f ($cli.HostArgument -join ', '))
    }
    else {
        Write-Log -Message 'Host input provided via -VMHost: none'
    }

    if ($cli.CsvPath) {
        Write-Log -Message "CSV input path provided: $($cli.CsvPath)"
    }
    else {
        Write-Log -Message 'CSV input path provided: none'
    }

    if ($cli.Username) {
        Write-Log -Message "Username argument provided: $($cli.Username)"
    }
    else {
        $configuredRequiredUsernames = @(
            $RequiredUsernames |
                Where-Object { $_ -ne $null } |
                ForEach-Object { $_.ToString().Trim() } |
                Where-Object { $_ }
        )
        $configuredRequiredUsernamesText = if ($configuredRequiredUsernames.Count -gt 0) {
            $configuredRequiredUsernames -join ', '
        }
        else {
            'none'
        }
        Write-Log -Message "Username argument provided: none. Script default username(s): $configuredRequiredUsernamesText"
    }

    Write-Log -Message ("ForceReset selected: {0}" -f $cli.ForceReset)
    if ($cli.EsxAdminsGroup) {
        Write-Log -Message "EsxAdminsGroup override provided: $($cli.EsxAdminsGroup)"
    }
    else {
        $configuredEsxAdminsGroupValue = if (
            $DesiredEsxAdminsGroupValue -and
            $DesiredEsxAdminsGroupValue.Trim() -and
            $DesiredEsxAdminsGroupValue.Trim() -cne 'CHANGE_ME'
        ) {
            $DesiredEsxAdminsGroupValue.Trim()
        }
        else {
            'none'
        }
        Write-Log -Message "EsxAdminsGroup override provided: none. Script default value: $configuredEsxAdminsGroupValue"
    }

    if ($cli.LockdownMode) {
        Write-Log -Message "LockdownMode argument provided: $($cli.LockdownMode)"
    }
    else {
        Write-Log -Message 'LockdownMode argument provided: none'
    }

    if ($cli.ResolutionChunkingEnabled) {
        Write-Log -Message "ResolutionChunkSize argument provided: $($cli.ResolutionChunkSize)"
    }
    else {
        Write-Log -Message 'ResolutionChunkSize argument provided: none'
    }

    Write-Log -Message ("Password argument provided: {0}" -f ([bool]($cli.Password)))

    if ($cli.ResolutionChunkSize -lt 0) {
        throw '-ResolutionChunkSize must be a positive integer when provided.'
    }

    if ($cli.ResolutionChunkingEnabled) {
        Write-Log -Message "Host resolution mode: chunked (chunk size $($cli.ResolutionChunkSize))."
    }
    else {
        Write-Log -Message 'Host resolution mode: unchunked.'
    }

    if ($cli.LockdownMode -and $cli.Mode -ne 'check-connectivity') {
        throw '-LockdownMode can be used only with -CheckConnectivity.'
    }

    if ($cli.ForceReset -and $cli.Mode -ne 'remediate') {
        throw '-ForceReset can be used only with -Remediate.'
    }

    if ($cli.Mode -eq 'validate' -and $cli.Password) {
        throw '-Password can be used only with -Remediate or -CheckConnectivity.'
    }

    if ($cli.Mode -eq 'check-connectivity') {
        if ($cli.ForceReset) {
            Write-Log -Level 'WARN' -Message 'Ignoring -ForceReset in -CheckConnectivity mode.'
        }

        if ($cli.EsxAdminsGroup) {
            Write-Log -Level 'WARN' -Message 'Ignoring -EsxAdminsGroup in -CheckConnectivity mode.'
        }
    }

    $connectedVIServers = @(Get-ConnectedVCenterServers)
    if ($connectedVIServers.Count -eq 0) {
        throw 'No connected vCenters were found. Connect to one or more vCenters first, then rerun the script.'
    }

    Write-Log -Message ("Connected vCenters detected: {0}" -f (($connectedVIServers | Select-Object -ExpandProperty Name) -join ', '))

    $hostNames = @(Get-HostNamesFromInput -HostArgument $cli.HostArgument -CsvPath $cli.CsvPath)
    $Script:Summary.InputHostCount = $hostNames.Count
    $resolvedHosts = @()

    if ($hostNames.Count -eq 0) {
        if ($cli.Mode -in @('validate', 'remediate', 'check-connectivity')) {
            Write-Log -Level 'WARN' -Message "No host input was provided. Defaulting to all hosts across connected vCenters for mode '$($cli.Mode)'."
            $resolvedHosts = @(Get-AllConnectedHosts -VIServers $connectedVIServers)
        }
        else {
            throw 'Provide at least one target host by using -VMHost or -CsvPath.'
        }
    }
    else {
        $effectiveResolutionChunkSize = if ($cli.ResolutionChunkingEnabled) { $cli.ResolutionChunkSize } else { 0 }
        $resolvedHosts = @(Resolve-TargetHosts -HostNames $hostNames -VIServers $connectedVIServers -ChunkSize $effectiveResolutionChunkSize)
    }

    if ($resolvedHosts.Count -eq 0) {
        throw 'None of the requested hosts could be resolved from the connected vCenters.'
    }

    $Script:Summary.ResolvedHostCount = $resolvedHosts.Count

    $plainTextPassword = $null
    $connectivityUsername = $null
    $connectivityLockdownMode = 'enable'
    $effectiveEsxAdminsGroupValue = $null
    $targetUsernames = @()

    if ($cli.Mode -in @('validate', 'remediate')) {
        $targetUsernames = @(Get-EffectiveRequiredUsernames -OverrideValue $cli.Username)

        if ($targetUsernames.Count -eq 0) {
            $promptedUsernames = Get-RequiredValue -ProvidedValue $null -PromptMessage 'Enter username(s) for validate/remediate'
            $targetUsernames = @(Expand-HostTokens -Value $promptedUsernames | Sort-Object -Unique)
            Write-Log -Message ("Username source: interactive prompt selected '{0}'." -f ($targetUsernames -join ', '))
        }
    }

    if ($cli.Mode -in @('validate', 'remediate') -and $targetUsernames.Count -eq 0) {
        throw 'At least one target username is required for validate or remediate mode.'
    }

    if ($cli.Mode -eq 'check-connectivity' -and $Username -and $Username.Count -gt 1) {
        throw '-CheckConnectivity accepts only one -Username value.'
    }

    if ($cli.Mode -in @('validate', 'remediate')) {
        $effectiveEsxAdminsGroupValue = Get-EffectiveEsxAdminsGroupValue -OverrideValue $cli.EsxAdminsGroup
        if ($effectiveEsxAdminsGroupValue) {
            Write-Log -Message "Effective esxAdminsGroup desired value: $effectiveEsxAdminsGroupValue"
        }
        else {
            Write-Log -Level 'WARN' -Message "Skipping validation/remediation of advanced setting '$EsxAdminsGroupSettingName' because no desired value is configured in the script and -EsxAdminsGroup was not provided."
        }
    }

    if ($cli.Mode -eq 'remediate') {
        $confirmationHosts = if ($hostNames.Count -gt 0) {
            $hostNames
        }
        else {
            @("ALL HOSTS ($($resolvedHosts.Count))")
        }

        Confirm-Remediation -TargetHosts $confirmationHosts -TargetUsernames $targetUsernames
        $plainTextPassword = Get-PlainTextPassword -ProvidedPassword $cli.Password -PromptMessage 'Enter password for required host user account(s)'
    }

    if ($cli.Mode -eq 'check-connectivity') {
        $connectivityUsername = Get-UsernameWithDefault -ProvidedValue $cli.Username -PromptMessage 'Enter username for ESXi connectivity check' -DefaultValue 'SOCVA'
        $plainTextPassword = Get-PlainTextPassword -ProvidedPassword $cli.Password -PromptMessage 'Enter password for ESXi connectivity check'
        $connectivityLockdownMode = if ($cli.LockdownMode) { $cli.LockdownMode } else { 'enable' }
    }

    $Script:Summary.TotalPlannedRows = if ($cli.Mode -eq 'check-connectivity') {
        $resolvedHosts.Count
    }
    else {
        $resolvedHosts.Count * $targetUsernames.Count
    }
    Write-RunProgress

    foreach ($resolvedHost in $resolvedHosts) {
        $context = if ($cli.Mode -eq 'check-connectivity') {
            Get-ConnectivityHostContext -VMHost $resolvedHost.VMHost -VCenter $resolvedHost.VCenter
        }
        else {
            Get-HostContext -VMHost $resolvedHost.VMHost -VCenter $resolvedHost.VCenter
        }
        Write-Log -Message "Processing host '$($context.VMHost.Name)' in vCenter '$($context.VCenter)' and cluster '$($context.Cluster)'."

        if (-not $resolvedHost.IsEligible) {
            $Script:Summary.SkippedHostCount++
            $skippedMessage = "Host connection state '$($resolvedHost.ConnectionState)' is not eligible. Allowed states: $($AllowedHostConnectionStates -join ', ')."
            Write-Log -Level 'WARN' -Message "Skipping host '$($context.VMHost.Name)' in vCenter '$($context.VCenter)' because $skippedMessage"

            $reportUsernames = @(Get-ReportLoopIdentities -Mode $cli.Mode -TargetUsernames $targetUsernames)
            foreach ($currentUsername in $reportUsernames) {
                Add-ReportRow -Row (New-ModeReportRow -Mode $cli.Mode -Data ([ordered]@{
                    Timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
                    Mode = $cli.Mode
                    VCenter = $context.VCenter
                    Cluster = $context.Cluster
                    Host = $context.VMHost.Name
                    HostConnectionState = $resolvedHost.ConnectionState
                    Username = if ($cli.Mode -eq 'check-connectivity') { $null } else { $currentUsername }
                    ConnectivityUsername = $connectivityUsername
                    RequestedLockdownMode = $connectivityLockdownMode
                    UserPresent = $false
                    ReadOnlyAccess = $false
                    DomainJoined = $null
                    DomainName = $null
                    DomainMembershipStatus = $null
                    EsxAdminsGroupExpected = $effectiveEsxAdminsGroupValue
                    EsxAdminsGroupActual = $null
                    EsxAdminGroupStatus = 'Skipped'
                    EsxAdminsGroupRemediationStatus = 'Skipped'
                    LockdownMode = $null
                    PreLockdownMode = $null
                    PostLockdownMode = $null
                    LockdownTemporarilyDisabled = $false
                    LockdownRestoreStatus = 'NotRequested'
                    InLockdownExceptionList = $false
                    ConnectivityAttempted = $false
                    ConnectivityStatus = 'Skipped'
                    ConnectivityMessage = $null
                    PasswordResetStatus = 'Skipped'
                    ActionStatus = 'Skipped'
                    ActionMessage = $skippedMessage
                }))
                $Script:Summary.SkippedCount++
            }

            continue
        }

        $Script:Summary.ProcessedHostCount++

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

        $reportUsernames = @(Get-ReportLoopIdentities -Mode $cli.Mode -TargetUsernames $targetUsernames)
        foreach ($currentUsername in $reportUsernames) {
            $logIdentityLabel = if ($cli.Mode -eq 'check-connectivity') { 'connectivity user' } else { 'user' }
            $logIdentityValue = if ($cli.Mode -eq 'check-connectivity') { $connectivityUsername } else { $currentUsername }
            $snapshot = [pscustomobject]@{
                UserPresent = $false
                ReadOnlyAccess = $false
                DomainJoined = $null
                DomainName = $null
                DomainMembershipStatus = $null
                EsxAdminsGroupExpected = $effectiveEsxAdminsGroupValue
                EsxAdminsGroupActual = $null
                EsxAdminGroupStatus = $null
                LockdownMode = $null
                InLockdownExceptionList = $false
            }
            $userCreatedThisRun = $false
            $esxAdminsGroupRemediationStatus = if ($cli.Mode -eq 'remediate') {
                if ($effectiveEsxAdminsGroupValue) { 'NotRequested' } else { 'Skipped' }
            } else { 'NotApplicable' }
            $passwordResetStatus = if ($cli.Mode -eq 'remediate') { 'NotRequested' } else { 'NotApplicable' }
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
                    $snapshot = Get-UserComplianceSnapshot -Context $context -Username $currentUsername -ExpectedEsxAdminsGroupValue $effectiveEsxAdminsGroupValue

                    if (-not $snapshot.UserPresent) {
                        if (-not $plainTextPassword) {
                            $plainTextPassword = Get-PlainTextPassword -ProvidedPassword $cli.Password -PromptMessage "Enter password to create missing host user '$currentUsername'"
                        }

                        $userCreatedThisRun = Ensure-HostUser -Context $context -Username $currentUsername -Password $plainTextPassword
                        $snapshot = Get-UserComplianceSnapshot -Context $context -Username $currentUsername -ExpectedEsxAdminsGroupValue $effectiveEsxAdminsGroupValue
                    }
                    else {
                        Write-Log -Message "User '$currentUsername' already exists on host '$($context.VMHost.Name)'."
                    }

                    Ensure-ReadOnlyAccess -Context $context -Username $currentUsername
                    if (-not $effectiveEsxAdminsGroupValue) {
                        $esxAdminsGroupRemediationStatus = 'Skipped'
                    }
                    elseif ($snapshot.EsxAdminGroupStatus -eq 'Invalid' -or -not $snapshot.EsxAdminsGroupActual) {
                        $esxAdminsGroupRemediationStatus = Ensure-EsxAdminsGroupSetting -Context $context -DesiredValue $effectiveEsxAdminsGroupValue
                    }
                    else {
                        Write-Log -Message "Advanced setting '$EsxAdminsGroupSettingName' already matches the desired value '$($snapshot.EsxAdminsGroupActual)' on host '$($context.VMHost.Name)'."
                        $esxAdminsGroupRemediationStatus = 'AlreadyCompliant'
                    }
                    Ensure-LockdownMode -Context $context
                    Ensure-LockdownExceptionUser -Context $context -Username $currentUsername

                    if ($cli.ForceReset -and -not $userCreatedThisRun) {
                        Reset-HostUserPassword -Context $context -Username $currentUsername -Password $plainTextPassword
                        $passwordResetStatus = 'Success'
                    }
                    elseif ($userCreatedThisRun) {
                        $passwordResetStatus = 'NotRequired'
                    }
                    else {
                        $passwordResetStatus = 'Skipped'
                    }

                    $actionStatus = 'Remediated'
                }

                if ($cli.Mode -eq 'check-connectivity') {
                    $connectivityResult = $hostConnectivityResult
                    if ($connectivityResult.ConnectivityStatus -eq 'Failed' -or
                        $connectivityResult.LockdownRestoreStatus -eq 'Failed') {
                        $actionStatus = 'Failed'
                        $actionMessage = $connectivityResult.ConnectivityMessage
                    }
                }
                else {
                    $snapshot = Get-UserComplianceSnapshot -Context $context -Username $currentUsername -ExpectedEsxAdminsGroupValue $effectiveEsxAdminsGroupValue
                    if ($cli.Mode -eq 'validate') {
                        Write-ValidationSnapshotLog -Mode $cli.Mode -Context $context -Username $currentUsername -Snapshot $snapshot
                    }
                }

                if (-not $actionMessage) {
                    $actionMessage = 'Completed successfully.'
                }

                if ($actionStatus -eq 'Failed') {
                    Write-Log -Level 'ERROR' -Message "Completed checks with errors for $logIdentityLabel '$logIdentityValue' on host '$($context.VMHost.Name)'."
                }
                else {
                    Write-Log -Level 'SUCCESS' -Message "Completed checks for $logIdentityLabel '$logIdentityValue' on host '$($context.VMHost.Name)'."
                }
            }
            catch {
                if ($cli.Mode -eq 'remediate' -and $esxAdminsGroupRemediationStatus -eq 'NotRequested') {
                    $esxAdminsGroupRemediationStatus = 'Failed'
                }
                if ($cli.Mode -eq 'remediate' -and $cli.ForceReset -and $passwordResetStatus -ne 'Success') {
                    $passwordResetStatus = 'Failed'
                }
                elseif ($cli.Mode -eq 'remediate' -and $passwordResetStatus -eq 'NotRequested') {
                    $passwordResetStatus = 'Skipped'
                }

                $actionStatus = 'Failed'
                $actionMessage = $_.Exception.Message
                Write-Log -Level 'ERROR' -Message "Failed on host '$($context.VMHost.Name)' for $logIdentityLabel '$logIdentityValue': $actionMessage"
                if ($cli.Mode -ne 'check-connectivity') {
                    $snapshot = Get-UserComplianceSnapshot -Context $context -Username $currentUsername -ExpectedEsxAdminsGroupValue $effectiveEsxAdminsGroupValue
                }
            }

            Add-ReportRow -Row (New-ModeReportRow -Mode $cli.Mode -Data ([ordered]@{
                Timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
                Mode = $cli.Mode
                VCenter = $context.VCenter
                Cluster = $context.Cluster
                Host = $context.VMHost.Name
                HostConnectionState = $resolvedHost.ConnectionState
                Username = if ($cli.Mode -eq 'check-connectivity') { $null } else { $currentUsername }
                ConnectivityUsername = $connectivityUsername
                RequestedLockdownMode = $connectivityLockdownMode
                UserPresent = $snapshot.UserPresent
                ReadOnlyAccess = $snapshot.ReadOnlyAccess
                DomainJoined = $snapshot.DomainJoined
                DomainName = $snapshot.DomainName
                DomainMembershipStatus = $snapshot.DomainMembershipStatus
                EsxAdminsGroupExpected = $snapshot.EsxAdminsGroupExpected
                EsxAdminsGroupActual = $snapshot.EsxAdminsGroupActual
                EsxAdminGroupStatus = $snapshot.EsxAdminGroupStatus
                EsxAdminsGroupRemediationStatus = $esxAdminsGroupRemediationStatus
                LockdownMode = $snapshot.LockdownMode
                PreLockdownMode = $connectivityResult.PreLockdownMode
                PostLockdownMode = $connectivityResult.PostLockdownMode
                LockdownTemporarilyDisabled = $connectivityResult.LockdownTemporarilyDisabled
                LockdownRestoreStatus = $connectivityResult.LockdownRestoreStatus
                InLockdownExceptionList = $snapshot.InLockdownExceptionList
                ConnectivityAttempted = $connectivityResult.ConnectivityAttempted
                ConnectivityStatus = $connectivityResult.ConnectivityStatus
                ConnectivityMessage = $connectivityResult.ConnectivityMessage
                PasswordResetStatus = $passwordResetStatus
                ActionStatus = $actionStatus
                ActionMessage = $actionMessage
            }))

            switch ($actionStatus) {
                'Failed' { $Script:Summary.FailedCount++ }
                'Skipped' { $Script:Summary.SkippedCount++ }
                default { $Script:Summary.SuccessCount++ }
            }
        }
    }

    Write-RunProgress -Completed
    Export-Report
    Write-Summary
}
catch {
    Write-RunProgress -Completed
    Write-Log -Level 'ERROR' -Message $_.Exception.Message
    Write-Summary
    throw
}
