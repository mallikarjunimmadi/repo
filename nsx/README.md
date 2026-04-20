# NSX-T Unused Objects Report

Inventory NSX-T Services and Groups, scan DFW and Gateway Firewall rules, and generate CSV reports showing where objects are used and which objects appear unused.

The current working version is:

```bash
nsxt_unused_objects_v0.0.2.py
```

## Requirements

- Python 3.8+
- `requests`

Install the Python dependency if needed:

```bash
pip install requests
```

## What It Reports

The script generates five CSV reports:

- `<prefix>_services_usage_<timestamp>.csv`
- `<prefix>_services_unused_<timestamp>.csv`
- `<prefix>_groups_usage_<timestamp>.csv`
- `<prefix>_groups_unused_<timestamp>.csv`
- `<prefix>_groups_empty_<timestamp>.csv`

The timestamp format is:

```text
YYYYMMDD_HHMMSS
```

All reports include a `source_nsx` column. This column identifies which NSX Manager the row came from, and it is included even when only one NSX Manager is scanned.

## Basic Usage

Run against one NSX Manager:

```bash
python3 nsxt_unused_objects_v0.0.2.py --nsx nsx01.example.local --user admin
```

If `--password` is omitted, the script prompts securely for it.

The NSX Manager value should be a hostname or IP only. Do not include `https://`.

Correct:

```text
nsx01.example.local
```

Incorrect:

```text
https://nsx01.example.local
```

## Multiple NSX Managers

You can scan multiple NSX Managers in one run. The script creates one combined set of CSV files and adds the source NSX Manager to each row.

Comma-separated:

```bash
python3 nsxt_unused_objects_v0.0.2.py --nsx nsx01.example.local,nsx02.example.local --user admin
```

Repeated `--nsx`:

```bash
python3 nsxt_unused_objects_v0.0.2.py --nsx nsx01.example.local --nsx nsx02.example.local --user admin
```

For multiple managers, the default output prefix is:

```text
nsx_managers
```

Example output:

```text
nsx_managers_services_usage_20260420_171500.csv
nsx_managers_services_unused_20260420_171500.csv
nsx_managers_groups_usage_20260420_171500.csv
nsx_managers_groups_unused_20260420_171500.csv
nsx_managers_groups_empty_20260420_171500.csv
```

## Custom Output Prefix

Use `--out-prefix` to control the filename prefix:

```bash
python3 nsxt_unused_objects_v0.0.2.py --nsx nsx01.example.local --user admin --out-prefix prod_nsx
```

Example output:

```text
prod_nsx_services_usage_20260420_171500.csv
```

## CSV Columns

### Services Usage

```text
source_nsx,service_name,service_id,service_path,entry_count,l4_app_protocol,ports,used_in_count,used_in
```

### Services Unused

```text
source_nsx,service_name,service_id,service_path,entry_count,l4_app_protocol,ports
```

### Groups Usage

```text
source_nsx,group_name,group_id,group_path,used_in_count,used_in
```

### Groups Unused

```text
source_nsx,group_name,group_id,group_path
```

### Groups Empty

```text
source_nsx,group_name,group_id,group_path
```

The empty-groups report uses a simple expression heuristic:

- If the group has no `expression`, it is reported as empty.
- If the group has a non-empty `expression`, it is not reported as empty.

## Useful Options

```text
--nsx              NSX Manager FQDN/IP. Repeat or use commas for multiple managers.
--user             Username.
--password         Password. Omit for secure prompt.
--verify-ssl       Verify SSL certificates. Default: false.
--exclude-system   Exclude system-owned/default objects. Default: true.
--out-prefix       Output filename prefix.
--timeout          HTTP timeout in seconds. Default: 30.
--retries          Max retries for transient HTTP errors. Default: 3.
--retry-sleep      Minimum sleep before retry. Default: 2.0.
--backoff          Exponential backoff base. Default: 1.5.
--jitter           Random jitter added to retry delay. Default: 0.25.
--page-size        Page size for NSX list APIs. Default: 1000.
--threads          Worker threads, clamped between 1 and 10. Default: 5.
--log-file         Optional rotating log file path.
--log-level        DEBUG, INFO, WARNING, ERROR. Default: INFO.
```

## Examples

Single manager with a log file:

```bash
python3 nsxt_unused_objects_v0.0.2.py \
  --nsx nsx01.example.local \
  --user admin \
  --log-file nsxt_unused_objects.log
```

Multiple managers with a custom prefix:

```bash
python3 nsxt_unused_objects_v0.0.2.py \
  --nsx nsx01.example.local,nsx02.example.local \
  --user admin \
  --out-prefix prod
```

Use SSL verification:

```bash
python3 nsxt_unused_objects_v0.0.2.py \
  --nsx nsx01.example.local \
  --user admin \
  --verify-ssl true
```

Run more conservatively:

```bash
python3 nsxt_unused_objects_v0.0.2.py \
  --nsx nsx01.example.local \
  --user admin \
  --threads 1 \
  --page-size 200
```

## Notes

- The script reads objects through the NSX Policy API.
- Services and Groups are fetched in detail so system-owned flags can be checked more accurately.
- DFW and Gateway Firewall rules are scanned for service and group references.
- `--exclude-system true` checks several common system/default flags, including `system_owned`, `_system_owned`, `is_system_owned`, `is_default`, and `is_policy_default`.
- If multiple NSX Managers are scanned and one fails, reports are still written for successful managers, then the script exits with an error listing failed managers.
