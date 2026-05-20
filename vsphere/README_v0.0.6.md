# vSphere ESXi Local User Compliance v0.0.6

Documentation for `esxi_local_user_compliance_v0.0.6.ps1`.

## Overview

This script validates, remediates, and tests ESXi local user compliance across hosts managed by one or more connected vCenters by using native PowerShell parameters.

It checks and reports on:

- ESXi local user presence
- `ReadOnly` host access
- Domain join status
- `Config.HostAgent.plugins.hostsvc.esxAdminsGroup`
- Lockdown mode
- Lockdown exception list membership
- Connectivity status in connectivity mode

In `-Remediate` mode, it:

1. Creates the user if missing.
2. Ensures `ReadOnly` access.
3. Replaces `Config.HostAgent.plugins.hostsvc.esxAdminsGroup` with the desired value.
4. Ensures lockdown mode is `lockdownNormal`.
5. Ensures the user is in the lockdown exception list.
6. Resets the password only if `-ForceReset` is used and the user already existed.

## Requirements

- PowerShell with VMware PowerCLI installed
- Active connection to one or more vCenters
- Privileges to inspect and change ESXi users, advanced settings, and lockdown configuration

Example vCenter connection:

```powershell
Connect-VIServer -Server vcsa01.example.com
Connect-VIServer -Server vcsa02.example.com
```

## Configuration

Important script-level settings:

- `RequiredUsernames`
- `DesiredLockdownMode`
- `DesiredEsxAdminsGroupValue`
- `EsxAdminsGroupSettingName`
- `ReportDirectory`
- `LogDirectory`
- `InputCsvHostColumn`
- `AllowedHostConnectionStates`

If `DesiredEsxAdminsGroupValue` is still `CHANGE_ME`, provide `-EsxAdminsGroup` at runtime.

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
- `-LockdownMode`
- `-Help`

Parameter rules:

- Use only one of `-Validate`, `-Remediate`, or `-CheckConnectivity`.
- `-Password` is valid only with `-Remediate` and `-CheckConnectivity`.
- `-CheckConnectivity` accepts an optional `-Username` and an optional `-Password`.
- In `-CheckConnectivity`, `-LockdownMode` is supported. Other flags besides host selection, `-Username`, `-Password`, and `-LockdownMode` are ignored.
- In `-Remediate` and `-CheckConnectivity`, `-Password` may be supplied as an argument or entered at the prompt.
- In `-Remediate` and `-CheckConnectivity`, if `-Username` is not supplied, the script prompts and defaults to the value defined in `$RequiredUsernames`.
- In `-Remediate`, the script asks for confirmation before making changes.

## Host Input

Hosts can be supplied with:

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

If no host input is provided:

- `-Validate` runs against all hosts in connected vCenters.
- `-CheckConnectivity` runs against all hosts in connected vCenters.
- `-Remediate` requires explicit host input.

## Mode Behavior

### Validate

Behavior:

- `-Password` is rejected.
- `-Username` is optional.
- If `-Username` is omitted, the script uses `RequiredUsernames`.
- `-EsxAdminsGroup` should be supplied unless `DesiredEsxAdminsGroupValue` is already configured in the script.

Examples:

Validate a single host:

```powershell
.\esxi_local_user_compliance_v0.0.6.ps1 -Validate -VMHost esxi01.example.com -EsxAdminsGroup 'DOMAIN\ESX-ADMINS'
```

Validate multiple hosts in one comma-separated argument:

```powershell
.\esxi_local_user_compliance_v0.0.6.ps1 -Validate -VMHost esxi01.example.com,esxi02.example.com -EsxAdminsGroup 'DOMAIN\ESX-ADMINS'
```

Validate multiple hosts as separate values:

```powershell
.\esxi_local_user_compliance_v0.0.6.ps1 -Validate -VMHost esxi01.example.com esxi02.example.com -EsxAdminsGroup 'DOMAIN\ESX-ADMINS'
```

Validate hosts from CSV:

```powershell
.\esxi_local_user_compliance_v0.0.6.ps1 -Validate -CsvPath .\hosts.csv -EsxAdminsGroup 'DOMAIN\ESX-ADMINS'
```

Validate a specific username:

```powershell
.\esxi_local_user_compliance_v0.0.6.ps1 -Validate -VMHost esxi01.example.com -Username <custom-username> -EsxAdminsGroup 'DOMAIN\ESX-ADMINS'
```

Validate multiple usernames:

```powershell
.\esxi_local_user_compliance_v0.0.6.ps1 -Validate -VMHost esxi01.example.com -Username <custom-username>,AUDITUSR -EsxAdminsGroup 'DOMAIN\ESX-ADMINS'
```

Validate all hosts in connected vCenters:

```powershell
.\esxi_local_user_compliance_v0.0.6.ps1 -Validate -EsxAdminsGroup 'DOMAIN\ESX-ADMINS'
```

### Remediate

Behavior:

- `-VMHost` or `-CsvPath` is required.
- `-Username` is optional.
- If `-Username` is omitted, the script prompts and defaults to the value defined in `$RequiredUsernames`.
- `-Password` is optional.
- If `-Password` is omitted, the script prompts for it.
- Remediation always asks for confirmation before changes are made.
- `-ForceReset` resets the password only for users that already existed before remediation.

Examples:

Remediate a single host and prompt for username/password:

```powershell
.\esxi_local_user_compliance_v0.0.6.ps1 -Remediate -VMHost esxi01.example.com -EsxAdminsGroup 'DOMAIN\ESX-ADMINS'
```

Remediate multiple hosts in one comma-separated argument:

```powershell
.\esxi_local_user_compliance_v0.0.6.ps1 -Remediate -VMHost esxi01.example.com,esxi02.example.com -EsxAdminsGroup 'DOMAIN\ESX-ADMINS'
```

Remediate multiple hosts as separate values:

```powershell
.\esxi_local_user_compliance_v0.0.6.ps1 -Remediate -VMHost esxi01.example.com esxi02.example.com -EsxAdminsGroup 'DOMAIN\ESX-ADMINS'
```

Remediate a specific username and prompt for password:

```powershell
.\esxi_local_user_compliance_v0.0.6.ps1 -Remediate -VMHost esxi01.example.com -Username <custom-username> -EsxAdminsGroup 'DOMAIN\ESX-ADMINS'
```

Remediate a specific username with an explicit password:

```powershell
.\esxi_local_user_compliance_v0.0.6.ps1 -Remediate -VMHost esxi01.example.com -Username <custom-username> -Password 'StrongPassword123!' -EsxAdminsGroup 'DOMAIN\ESX-ADMINS'
```

Remediate with forced password reset:

```powershell
.\esxi_local_user_compliance_v0.0.6.ps1 -Remediate -VMHost esxi01.example.com -Username <custom-username> -Password 'StrongPassword123!' -ForceReset -EsxAdminsGroup 'DOMAIN\ESX-ADMINS'
```

Remediate hosts from CSV:

```powershell
.\esxi_local_user_compliance_v0.0.6.ps1 -Remediate -CsvPath .\hosts.csv -Username <custom-username> -Password 'StrongPassword123!' -EsxAdminsGroup 'DOMAIN\ESX-ADMINS'
```

### Check Connectivity

Behavior:

- `-Username` is optional.
- If `-Username` is omitted, the script prompts and defaults to the value defined in `$RequiredUsernames`.
- `-Password` is optional.
- If `-Password` is omitted, the script prompts for it.
- `-LockdownMode` accepts `enable` or `disable`.
- Other flags besides host selection, `-Username`, `-Password`, and `-LockdownMode` are ignored in this mode.
- If no host input is provided, all hosts in connected vCenters are checked.

Examples:

Check connectivity for one host and prompt for username/password:

```powershell
.\esxi_local_user_compliance_v0.0.6.ps1 -CheckConnectivity -VMHost esxi01.example.com
```

Check connectivity for one host with explicit credentials:

```powershell
.\esxi_local_user_compliance_v0.0.6.ps1 -CheckConnectivity -VMHost esxi01.example.com -Username <custom-username> -Password 'StrongPassword123!'
```

Check connectivity from CSV:

```powershell
.\esxi_local_user_compliance_v0.0.6.ps1 -CheckConnectivity -CsvPath .\hosts.csv -Username <custom-username> -Password 'StrongPassword123!'
```

Check connectivity for all hosts in connected vCenters:

```powershell
.\esxi_local_user_compliance_v0.0.6.ps1 -CheckConnectivity -Username <custom-username> -Password 'StrongPassword123!'
```

Check connectivity while preserving lockdown:

```powershell
.\esxi_local_user_compliance_v0.0.6.ps1 -CheckConnectivity -VMHost esxi01.example.com -Username <custom-username> -Password 'StrongPassword123!' -LockdownMode enable
```

Check connectivity while temporarily disabling lockdown:

```powershell
.\esxi_local_user_compliance_v0.0.6.ps1 -CheckConnectivity -VMHost esxi01.example.com -Username <custom-username> -Password 'StrongPassword123!' -LockdownMode disable
```

## Reporting

Each run writes:

- A timestamped log file with the selected mode in the filename
- A timestamped CSV report with the selected mode in the filename

Report columns are mode-specific so each CSV includes only the fields relevant to that run.

Validate and remediate report fields:

- `Timestamp`
- `Mode`
- `VCenter`
- `Cluster`
- `Host`
- `HostConnectionState`
- `Username`
- `ConnectivityUsername`
- `RequestedLockdownMode`
- `UserPresent`
- `ReadOnlyAccess`
- `DomainJoined`
- `DomainName`
- `DomainMembershipStatus`
- `EsxAdminsGroupExpected`
- `EsxAdminsGroupActual`
- `EsxAdminGroupStatus`
- `LockdownMode`
- `InLockdownExceptionList`
- `ActionStatus`
- `ActionMessage`

Additional remediate-only fields:

- `EsxAdminsGroupRemediationStatus`
- `PasswordResetStatus`

Check-connectivity report fields:

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

`EsxAdminGroupStatus` values:

- `Valid`
- `Invalid`
- `Skipped`

## Notes

- Hosts not found in a connected vCenter are logged and skipped.
- Hosts outside the allowed connection states are reported as skipped.
- The script logs operator choices such as mode, host input, username input, password source, remediation confirmation response, and effective `EsxAdminsGroup` value.
