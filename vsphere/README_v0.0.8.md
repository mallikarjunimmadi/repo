# vSphere ESXi Local User Compliance v0.0.8

Documentation for `esxi_local_user_compliance_v0.0.8.ps1`.

## Overview

`esxi_local_user_compliance_v0.0.8.ps1` validates, remediates, and tests ESXi local-user compliance across one or more connected vCenters by using native PowerShell parameters.

It supports three mutually exclusive modes:

- `-Validate`
- `-Remediate`
- `-CheckConnectivity`

The script can inspect and report on:

- ESXi local user presence
- `ReadOnly` host access
- Active Directory join state
- `Config.HostAgent.plugins.hostsvc.esxAdminsGroup`
- Host-level `Admin` access for the provided ESX admin group
- Lockdown mode
- Lockdown exception membership
- Direct host connectivity in connectivity mode

In `-Remediate` mode, the script can:

1. Create a missing local user.
2. Ensure `ReadOnly` access for the user.
3. Set `Config.HostAgent.plugins.hostsvc.esxAdminsGroup` to the desired value.
4. Ensure the provided ESX admin group has `Admin` access on the ESXi host.
5. Ensure lockdown mode is `lockdownNormal`.
6. Ensure the user is present in the lockdown exception list.
7. Reset the password only when `-ForceReset` is supplied for an already existing user.

## Requirements

- PowerShell with VMware PowerCLI installed
- An active connection to one or more vCenters
- Permissions to inspect and update ESXi users, host access, advanced settings, and lockdown configuration

Example:

```powershell
Connect-VIServer -Server vcsa01.example.com
Connect-VIServer -Server vcsa02.example.com
```

## Script Configuration

Important script-level settings:

- `RequiredUsernames`
- `DesiredLockdownMode`
- `DesiredEsxAdminsGroupValue`
- `DesiredEsxAdminsGroupAccessMode`
- `EsxAdminsGroupSettingName`
- `ReportDirectory`
- `LogDirectory`
- `InputCsvHostColumn`
- `AllowedHostConnectionStates`

If `DesiredEsxAdminsGroupValue` is still set to `CHANGE_ME`, provide `-EsxAdminsGroup` at runtime.

If the provided ESX admin group is not already domain-qualified, the script attempts to resolve a host-visible principal automatically by checking directory results and joined-domain variants such as `DOMAIN\GroupName`.

## Parameters

- `-Validate`
- `-Remediate`
- `-CheckConnectivity`
- `-VMHost`
- `-CsvPath`
- `-Username`
- `-Password`
- `-ForceReset`
- `-EsxAdminsGroup`
- `-ResolutionChunkSize`
- `-LockdownMode`
- `-Help`

## Parameter Rules

- Use only one of `-Validate`, `-Remediate`, or `-CheckConnectivity`.
- `-Password` is valid only with `-Remediate` or `-CheckConnectivity`.
- `-ForceReset` is valid only with `-Remediate`.
- `-LockdownMode` is valid only with `-CheckConnectivity`.
- `-CheckConnectivity` accepts only one `-Username` value.
- `-EsxAdminsGroup` is meaningful only in `-Validate` and `-Remediate`.
- `-Help` prints usage and exits.

## Host Input

Hosts can be provided by:

- `-VMHost esxi01.example.com`
- `-VMHost esxi01.example.com,esxi02.example.com`
- `-VMHost esxi01.example.com esxi02.example.com`
- `-CsvPath .\hosts.csv`

Example CSV:

```csv
Host
esxi01.example.com
esxi02.example.com
```

If no host input is provided, the script defaults to all ESXi hosts across connected vCenters for all three modes.

## Host Resolution Behavior

Host resolution is unchunked by default.

- Default behavior: one host lookup pass per connected vCenter
- Optional behavior: use `-ResolutionChunkSize <positive-integer>` to split host resolution into batches

Example:

```powershell
.\esxi_local_user_compliance_v0.0.8.ps1 -Validate -CsvPath .\hosts.csv -EsxAdminsGroup 'DOMAIN\ESX-ADMINS' -ResolutionChunkSize 200
```

## Mode Behavior

### Validate

Behavior:

- `-Username` is optional.
- If `-Username` is omitted, the script uses `RequiredUsernames`.
- `-Password` is rejected.
- `-EsxAdminsGroup` should be provided unless `DesiredEsxAdminsGroupValue` is already configured in the script.
- When an ESX admin group is provided, validation also checks that the host grants that group `Admin` access.

Examples:

```powershell
.\esxi_local_user_compliance_v0.0.8.ps1 -Validate -VMHost esxi01.example.com -EsxAdminsGroup 'DOMAIN\ESX-ADMINS'
```

```powershell
.\esxi_local_user_compliance_v0.0.8.ps1 -Validate -VMHost esxi01.example.com,esxi02.example.com -EsxAdminsGroup 'DOMAIN\ESX-ADMINS'
```

```powershell
.\esxi_local_user_compliance_v0.0.8.ps1 -Validate -CsvPath .\hosts.csv -EsxAdminsGroup 'DOMAIN\ESX-ADMINS'
```

```powershell
.\esxi_local_user_compliance_v0.0.8.ps1 -Validate -VMHost esxi01.example.com -Username SOCVA -EsxAdminsGroup 'DOMAIN\ESX-ADMINS'
```

```powershell
.\esxi_local_user_compliance_v0.0.8.ps1 -Validate -EsxAdminsGroup 'DOMAIN\ESX-ADMINS'
```

### Remediate

Behavior:

- `-Username` is optional.
- If `-Username` is omitted, the script uses `RequiredUsernames`.
- `-Password` is required for user creation and for `-ForceReset`, and is otherwise optional.
- If `-Password` is not supplied when needed, the script prompts for it.
- The script always asks for confirmation before making changes.
- If no host input is supplied, the script targets all hosts in connected vCenters.
- `-ForceReset` resets the password only for users that already existed before remediation.
- When an ESX admin group is provided, remediation also ensures that group has `Admin` access on each ESXi host.

Examples:

```powershell
.\esxi_local_user_compliance_v0.0.8.ps1 -Remediate -VMHost esxi01.example.com -EsxAdminsGroup 'DOMAIN\ESX-ADMINS'
```

```powershell
.\esxi_local_user_compliance_v0.0.8.ps1 -Remediate -VMHost esxi01.example.com,esxi02.example.com -EsxAdminsGroup 'DOMAIN\ESX-ADMINS'
```

```powershell
.\esxi_local_user_compliance_v0.0.8.ps1 -Remediate -VMHost esxi01.example.com -Username SOCVA -Password 'StrongPassword123!' -EsxAdminsGroup 'DOMAIN\ESX-ADMINS'
```

```powershell
.\esxi_local_user_compliance_v0.0.8.ps1 -Remediate -VMHost esxi01.example.com -Username SOCVA -Password 'StrongPassword123!' -ForceReset -EsxAdminsGroup 'DOMAIN\ESX-ADMINS'
```

```powershell
.\esxi_local_user_compliance_v0.0.8.ps1 -Remediate -CsvPath .\hosts.csv -Username SOCVA -Password 'StrongPassword123!' -EsxAdminsGroup 'DOMAIN\ESX-ADMINS'
```

### CheckConnectivity

Behavior:

- `-Username` is optional.
- If `-Username` is omitted, the script prompts and defaults to `SOCVA`.
- `-Password` can be supplied or entered at the prompt.
- `-LockdownMode` accepts `enable` or `disable`.
- If `-LockdownMode enable` is used or omitted, the script preserves existing lockdown mode during the connectivity test.
- If `-LockdownMode disable` is used and the host is not already `lockdownDisabled`, the script temporarily disables lockdown, performs the connectivity check, and then restores the original mode.
- If no host input is supplied, the script checks all hosts in connected vCenters.

Examples:

```powershell
.\esxi_local_user_compliance_v0.0.8.ps1 -CheckConnectivity -VMHost esxi01.example.com
```

```powershell
.\esxi_local_user_compliance_v0.0.8.ps1 -CheckConnectivity -VMHost esxi01.example.com -Username SOCVA -Password 'StrongPassword123!'
```

```powershell
.\esxi_local_user_compliance_v0.0.8.ps1 -CheckConnectivity -CsvPath .\hosts.csv -Username SOCVA -Password 'StrongPassword123!'
```

```powershell
.\esxi_local_user_compliance_v0.0.8.ps1 -CheckConnectivity -Username SOCVA -Password 'StrongPassword123!'
```

```powershell
.\esxi_local_user_compliance_v0.0.8.ps1 -CheckConnectivity -VMHost esxi01.example.com -Username SOCVA -Password 'StrongPassword123!' -LockdownMode enable
```

```powershell
.\esxi_local_user_compliance_v0.0.8.ps1 -CheckConnectivity -VMHost esxi01.example.com -Username SOCVA -Password 'StrongPassword123!' -LockdownMode disable
```

## Reporting

Each run writes:

- A timestamped log file in `logs`
- A timestamped CSV report in `reports`

The filenames include the selected mode.

### Validate Report Columns

- `Timestamp`
- `Mode`
- `VCenter`
- `Cluster`
- `Host`
- `HostConnectionState`
- `Username`
- `UserPresent`
- `ReadOnlyAccess`
- `DomainJoined`
- `DomainName`
- `DomainMembershipStatus`
- `EsxAdminsGroupExpected`
- `EsxAdminsGroupActual`
- `EsxAdminGroupStatus`
- `EsxAdminsGroupAdminAccessExpected`
- `EsxAdminsGroupAdminAccessActual`
- `EsxAdminsGroupAdminAccessStatus`
- `LockdownMode`
- `InLockdownExceptionList`
- `ActionStatus`
- `ActionMessage`

### Remediate Report Columns

- `Timestamp`
- `Mode`
- `VCenter`
- `Cluster`
- `Host`
- `HostConnectionState`
- `Username`
- `UserPresent`
- `ReadOnlyAccess`
- `DomainJoined`
- `DomainName`
- `DomainMembershipStatus`
- `EsxAdminsGroupExpected`
- `EsxAdminsGroupActual`
- `EsxAdminGroupStatus`
- `EsxAdminsGroupAdminAccessExpected`
- `EsxAdminsGroupAdminAccessActual`
- `EsxAdminsGroupAdminAccessStatus`
- `EsxAdminsGroupRemediationStatus`
- `EsxAdminsGroupAdminAccessRemediationStatus`
- `LockdownMode`
- `InLockdownExceptionList`
- `PasswordResetStatus`
- `ActionStatus`
- `ActionMessage`

### Check-Connectivity Report Columns

- `Timestamp`
- `Mode`
- `VCenter`
- `Cluster`
- `Host`
- `HostConnectionState`
- `ConnectivityUsername`
- `RequestedLockdownMode`
- `PreLockdownMode`
- `PostLockdownMode`
- `LockdownTemporarilyDisabled`
- `LockdownRestoreStatus`
- `ConnectivityAttempted`
- `ConnectivityStatus`
- `ConnectivityMessage`
- `ActionStatus`
- `ActionMessage`

## Status Values

Common row-level status values include:

- `Validated`
- `Remediated`
- `Skipped`
- `Failed`

`EsxAdminGroupStatus` values:

- `Valid`
- `Invalid`
- `Skipped`

`EsxAdminsGroupAdminAccessStatus` values:

- `Valid`
- `Invalid`
- `Missing`
- `Skipped`

## Operational Notes

- Hosts not found in any connected vCenter are logged as errors and excluded from processing.
- Hosts outside the allowed connection states are written as skipped rows.
- In connectivity mode, failed connection attempts still generate report rows.
- The script logs operator choices such as mode, host input, username source, password source, and effective host-resolution mode.
