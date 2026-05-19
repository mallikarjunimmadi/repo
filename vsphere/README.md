# vSphere ESXi Local User Compliance

PowerCLI automation for validating and remediating ESXi local user compliance across hosts managed by one or more connected vCenters.

Current script:

- `esxi_local_user_compliance_v0.0.4.ps1`

## What It Does

- Validates whether required local users exist on each ESXi host.
- Validates whether each user has `ReadOnly` host access.
- Validates whether each user is in the lockdown exception list.
- Reads the host's current lockdown mode.
- Remediates missing or non-compliant configuration in a fixed order.
- Can test direct ESXi connectivity with a supplied username and password.
- Writes a timestamped log file and CSV report for every run.

## Remediation Order

In `--remediate` mode, version `0.0.4` processes each target user in this order:

1. If the user does not exist, create it.
2. Ensure the user has `ReadOnly` access.
3. Ensure lockdown mode is enabled as `lockdownNormal`.
4. Ensure the user is in the lockdown exception list.
5. Reset the password only when `--force-reset` is used and the user already existed before remediation.

This avoids the earlier behavior where password reset could fail first and make the report look like the user was absent.

## Requirements

- PowerShell with VMware PowerCLI available.
- An active connection to one or more vCenters before running the script.
- Sufficient privileges to inspect and modify ESXi local users, access mode, and lockdown settings.

Example:

```powershell
Connect-VIServer -Server vcsa01.example.com
Connect-VIServer -Server vcsa02.example.com
```

## Script Configuration

These values are defined near the top of the script:

- `RequiredUsernames`
- `ReportDirectory`
- `LogDirectory`
- `InputCsvHostColumn`
- `DesiredLockdownMode`
- `DefaultUserDescription`
- `AllowedHostConnectionStates`

Default behavior:

- `RequiredUsernames` contains `SOCVA`.
- `DesiredLockdownMode` is `lockdownNormal`.
- Only hosts in `Connected` or `Maintenance` state are processed.

## Input Options

Hosts can be supplied with:

- `--host esxi01.example.com`
- `--host esxi01.example.com,esxi02.example.com`
- `--csv .\hosts.csv`

CSV input defaults to a `Host` column.

Example CSV:

```csv
Host
esxi01.example.com
esxi02.example.com
```

If no host input is provided:

- `--validate` runs against all hosts in connected vCenters.
- `--check-connectivity` runs against all hosts in connected vCenters.
- `--remediate` requires explicit host input.

## Modes

### Validate

Checks current state only.

Example:

```powershell
.\esxi_local_user_compliance_v0.0.4.ps1 --validate --host esxi01.example.com
```

### Remediate

Brings the host into compliance for each target username.

Password behavior:

- If a target user is missing, the script needs a password to create it.
- If `--force-reset` is not used, existing users are remediated without password reset.
- If `--force-reset` is used, the script resets the password only for users that already existed.
- A newly created user is not immediately reset again in the same run.

Examples:

```powershell
.\esxi_local_user_compliance_v0.0.4.ps1 --remediate --host esxi01.example.com
```

```powershell
.\esxi_local_user_compliance_v0.0.4.ps1 --remediate --host esxi01.example.com --username SOCVA --pass 'StrongPassword123!'
```

```powershell
.\esxi_local_user_compliance_v0.0.4.ps1 --remediate --host esxi01.example.com --username SOCVA --pass 'StrongPassword123!' --force-reset
```

### Check Connectivity

Attempts a direct `Connect-VIServer` login to each ESXi host with the supplied credentials.

Lockdown behavior:

- `--lockdown-mode enable` preserves lockdown during the test.
- `--lockdown-mode disable` temporarily disables lockdown when needed, runs the test, and restores the original mode.
- If `--lockdown-mode` is omitted, the default is `enable`.

Example:

```powershell
.\esxi_local_user_compliance_v0.0.4.ps1 --check-connectivity --host esxi01.example.com --username SOCVA --pass 'StrongPassword123!' --lockdown-mode enable
```

## Command Reference

- `--validate` Run validation only.
- `--remediate` Run remediation for target users.
- `--check-connectivity` Validate direct ESXi login.
- `--host` One host or a comma-separated list of hosts.
- `--csv` CSV file containing hosts.
- `--username` Overrides `RequiredUsernames` in `--validate` and `--remediate`. In `--check-connectivity`, it is the login username.
- `--pass` Password for remediation or connectivity checks.
- `--force-reset` In remediation mode, reset password only for users that already exist.
- `--lockdown-mode` Connectivity-only option. Accepts `enable` or `disable`.
- `--help` Show built-in usage.

Only one mode can be used per run.

## Reporting

Each run creates:

- A timestamped log file in `LogDirectory`
- A timestamped CSV report in `ReportDirectory`

The report includes:

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
- `LockdownMode`
- `PreLockdownMode`
- `PostLockdownMode`
- `LockdownTemporarilyDisabled`
- `LockdownRestoreStatus`
- `InLockdownExceptionList`
- `ConnectivityAttempted`
- `ConnectivityStatus`
- `ConnectivityMessage`
- `PasswordResetStatus`
- `ActionStatus`
- `ActionMessage`

Version `0.0.4` refreshes the host state after remediation attempts and after failures, so the report better reflects actual user presence and compliance state.

## Common Examples

Validate all hosts in connected vCenters:

```powershell
.\esxi_local_user_compliance_v0.0.4.ps1 --validate
```

Validate a specific username:

```powershell
.\esxi_local_user_compliance_v0.0.4.ps1 --validate --host esxi01.example.com --username SOCVA
```

Remediate multiple hosts from CSV:

```powershell
.\esxi_local_user_compliance_v0.0.4.ps1 --remediate --csv .\hosts.csv
```

Connectivity test for all hosts in connected vCenters:

```powershell
.\esxi_local_user_compliance_v0.0.4.ps1 --check-connectivity --username SOCVA --lockdown-mode enable
```

## Notes

- The script uses existing PowerCLI sessions and does not log in to vCenter on its own.
- Hosts not found in any connected vCenter are logged and skipped.
- Hosts outside the allowed connection states are reported as skipped.
- If `UserDirectory` does not enumerate a user but host access entries show it, the script treats the access entry as evidence that the user exists.
