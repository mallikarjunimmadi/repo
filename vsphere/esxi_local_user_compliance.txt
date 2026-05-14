# vSphere ESXi Hardening

PowerCLI script to validate and remediate ESXi local user access and lockdown configuration across hosts managed by one or more connected vCenters.

Script file:

- `vsphere-esxi-hardening_v0.0.1.ps1`

## Features

- Uses existing PowerCLI vCenter sessions and stops if no vCenter is connected.
- Supports one host, multiple comma-separated hosts with a single `--host` argument, or CSV input.
- In `--validate` and `--check-connectivity` mode, defaults to all hosts in connected vCenters when no host input is supplied.
- Resolves the parent vCenter and cluster for each target host.
- Writes live logs to console and to a timestamped log file.
- Exports a timestamped CSV report for every run.
- Validates whether required local users exist on each ESXi host.
- Validates whether each required user has `ReadOnly` host access.
- Validates whether each required user is in the lockdown exception list.
- Can remediate missing local users, assign `ReadOnly` access, enable lockdown mode, and add users to lockdown exceptions.
- Can test direct connectivity to each ESXi host by using a specific supplied or prompted username and password.
- In `--check-connectivity` mode, temporarily disables lockdown when needed, tests connectivity, and restores the original lockdown mode.

## Requirements

- PowerShell with VMware PowerCLI available.
- You must connect to one or more vCenters before running the script.
- Your current vCenter session must have enough privileges to inspect and change ESXi host local accounts and lockdown settings.

Example vCenter connection:

```powershell
Connect-VIServer -Server vcsa01.example.com
Connect-VIServer -Server vcsa02.example.com
```

## Configurable Settings

Update these values near the top of the script:

- `RequiredUsernames`
- `ReportDirectory`
- `LogDirectory`
- `InputCsvHostColumn`
- `DesiredLockdownMode`
- `DefaultUserDescription`

Notes:

- `RequiredUsernames` supports one or more usernames.
- In remediation and connectivity mode, the same password is used for every username in `RequiredUsernames`.
- Default lockdown mode is `lockdownNormal`.

## Input Options

The script accepts hosts in any one of these ways:

- `--host esxi01.example.com`
- `--host esxi01.example.com,esxi02.example.com`
- `--csv .\hosts.csv`

CSV input should contain a host column named `Host` by default. You can change that by editing `InputCsvHostColumn` at the top of the script.

If no host input is provided:

- `--validate` checks all hosts in all connected vCenters
- `--check-connectivity` checks all hosts in all connected vCenters
- `--remediate` still requires explicit host input

Example CSV:

```csv
Host
esxi01.example.com
esxi02.example.com
```

## Modes

### Validate

Checks:

- Whether each required username exists on the ESXi host
- Whether the user has `ReadOnly` host access
- Whether the user is in the lockdown exception list
- Current lockdown mode

Example:

```powershell
.\vsphere-esxi-hardening_v0.0.1.ps1 --validate --host esxi01.example.com,esxi02.example.com
```

### Remediate

Performs these actions for each configured username:

- Creates the local user if it does not already exist
- Assigns `ReadOnly` host access
- Sets the host lockdown mode to the configured value
- Adds the user to the lockdown exception list

Password behavior:

- Use `--pass <password>` to supply the password on the command line
- If `--pass` is not provided, the script prompts securely

Example:

```powershell
.\vsphere-esxi-hardening_v0.0.1.ps1 --remediate --csv .\hosts.csv --pass 'StrongPassword123!'
```

### Check Connectivity

Performs all validation checks and then attempts a direct `Connect-VIServer` login to each ESXi host by using the specific username and password supplied on the command line or entered at the prompt.

Credential behavior:

- Use `--username <username>` and `--pass <password>` to provide credentials directly
- If one or both are not passed, the script prompts for the missing value
- If the prompted username or password is left blank, the script fails
- If no host input is provided, connectivity is tested against all hosts in connected vCenters
- If the host is in lockdown mode, the script temporarily disables lockdown, attempts connectivity, and then restores the original mode
- The report captures the pre-check and post-check lockdown modes, whether lockdown was temporarily disabled, the restore status, and the connectivity result

Example:

```powershell
.\vsphere-esxi-hardening_v0.0.1.ps1 --check-connectivity --host esxi01.example.com --username SOCVA --pass 'StrongPassword123!'
```

## Command Reference

- `--validate` Run validation checks only.
- `--remediate` Validate and fix local user / lockdown configuration.
- `--check-connectivity` Validate and test direct ESXi login.
- `--host` One ESXi host or a comma-separated list of ESXi hosts.
- `--csv` CSV file containing hosts.
- `--username` Specific username for `--check-connectivity`.
- `--pass` Password used for remediation or connectivity checks.
- `--help` Show built-in usage output.

Only one mode should be used in a single run.

## Output

Each run creates:

- A log file under the configured `LogDirectory`
- A CSV report under the configured `ReportDirectory`

The report includes:

- Timestamp
- Mode
- vCenter
- Cluster
- Host
- Username
- User present status
- Read-only access status
- Lockdown mode
- Pre-check lockdown mode
- Post-check lockdown mode
- Lockdown temporarily disabled status
- Lockdown restore status
- Lockdown exception membership
- Connectivity test result
- Action status and message

## Examples

Validate a single host:

```powershell
.\vsphere-esxi-hardening_v0.0.1.ps1 --validate --host esxi01.example.com
```

Validate multiple hosts:

```powershell
.\vsphere-esxi-hardening_v0.0.1.ps1 --validate --host esxi01.example.com,esxi02.example.com
```

Remediate using secure prompt for password:

```powershell
.\vsphere-esxi-hardening_v0.0.1.ps1 --remediate --host esxi01.example.com,esxi02.example.com
```

Check connectivity from CSV input:

```powershell
.\vsphere-esxi-hardening_v0.0.1.ps1 --check-connectivity --csv .\hosts.csv --username SOCVA
```

Check connectivity for all hosts in connected vCenters:

```powershell
.\vsphere-esxi-hardening_v0.0.1.ps1 --check-connectivity --username SOCVA
```

Validate all hosts in connected vCenters:

```powershell
.\vsphere-esxi-hardening_v0.0.1.ps1 --validate
```

## Notes

- The script works only if you already have at least one active PowerCLI vCenter connection.
- Hosts not found in any connected vCenter are logged and skipped.
- The script uses ESXi host-side APIs exposed through vCenter to manage local accounts and lockdown exceptions.
