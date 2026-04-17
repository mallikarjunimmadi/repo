# Bulk VS Creation

Bulk-create Avi Virtual Services, Pools, and VSVIPs from a CSV file.

Current script:

```bash
bulk_vs_creation_v0.0.2.py
```

Version:

```bash
python3 bulk_vs_creation_v0.0.2.py --version
```

Expected output:

```text
bulk_vs_creation_v0.0.2.py 0.0.2
```

## Features

- CSV-driven Virtual Service and Pool creation
- VSVIP creation or reuse by existing VSVIP name/IP
- Pool server members from CSV
- Application profile and health monitor references from CSV
- SSL profile and default certificate attachment for `System-Secure-HTTP`
- NSX-T placement network payload for VIP and Pool networks
- Dry-run mode for payload validation
- Debug mode for payload and response logging
- Sample CSV generation

## Requirements

Use a Python environment where `avisdk` is installed. If using a virtual environment, activate it first:

```bash
source <venv>/bin/activate
```

Run commands from this directory:

```bash
cd <repo>/bulk_vs_creation
```

## Help

```bash
python3 bulk_vs_creation_v0.0.2.py --help
```

## Generate Sample CSV

```bash
python3 bulk_vs_creation_v0.0.2.py --generate-sample-csv
```

This creates a file named like:

```text
avi_vs_sample_template_YYYYMMDD_HHMMSS.csv
```

## CSV Columns

The generated CSV contains these columns:

```csv
vs_name,vs_ip,vs_port,pool_name,pool_members,vip_network,pool_network,se_group,vsvip_name,application_profile,health_monitor,ssl_profile,cloud_name
```

Column notes:

- `vs_name`: Virtual Service name.
- `vs_ip`: VIP IP address, or `auto` for auto allocation.
- `vs_port`: Virtual Service port.
- `pool_name`: Pool name.
- `pool_members`: Pool members separated by semicolon, for example `10.10.20.11:80;10.10.20.12:80`.
- `vip_network`: Network name, UUID, relative `/api/network/...` ref, or full placement network ref for the VIP/VSVIP.
- `pool_network`: Network name, UUID, relative `/api/network/...` ref, or full placement network ref for the Pool.
- `se_group`: Service Engine Group name.
- `vsvip_name`: Optional VSVIP name. If blank, the script uses `<vs_name>_vsvip`.
- `application_profile`: Application profile name, for example `System-L4-Application`, `System-HTTP`, or `System-Secure-HTTP`.
- `health_monitor`: One or more health monitor names separated by comma.
- `ssl_profile`: Optional SSL profile name for the Virtual Service.
- `cloud_name`: Avi cloud name. Defaults to `Default-Cloud` if blank.

## Placement Network Input

For `vip_network` and `pool_network`, the script accepts any of these formats:

```text
network-app
network-a223286c-6313-4c22-b317-abf82fdb5704
/api/network/network-a223286c-6313-4c22-b317-abf82fdb5704
https://avilb.vmi.local/api/network/network-a223286c-6313-4c22-b317-abf82fdb5704#network-app
```

The script fetches the network object and builds placement payload like:

```json
"placement_networks": [
  {
    "network_ref": "https://avilb.vmi.local/api/network/network-a223286c-6313-4c22-b317-abf82fdb5704#network-app",
    "subnet": {
      "ip_addr": {
        "addr": "10.187.66.128",
        "type": "V4"
      },
      "mask": 25
    }
  }
]
```

The subnet `addr` and `mask` are taken from the network object's IPv4 `configured_subnets` entry. If that is not present, the script also checks `subnet_runtime`.

## Examples

### Dry Run

Use this first to validate CSV input and generated payloads without creating objects:

```bash
python3 bulk_vs_creation_v0.0.2.py \
  --controller avilb.vmi.local \
  --csv my_vs_list.csv \
  --dry-run
```

### Dry Run With Debug Payloads

```bash
python3 bulk_vs_creation_v0.0.2.py \
  --controller avilb.vmi.local \
  --csv my_vs_list.csv \
  --dry-run \
  --debug
```

### Actual Creation

```bash
python3 bulk_vs_creation_v0.0.2.py \
  --controller avilb.vmi.local \
  --csv my_vs_list.csv
```

### Actual Creation With Username

The script prompts for the password if `--password` is omitted:

```bash
python3 bulk_vs_creation_v0.0.2.py \
  --controller avilb.vmi.local \
  --username admin \
  --csv my_vs_list.csv
```

### Actual Creation With Tenant

```bash
python3 bulk_vs_creation_v0.0.2.py \
  --controller avilb.vmi.local \
  --username admin \
  --tenant admin \
  --csv my_vs_list.csv
```

### Custom Log Directory

```bash
python3 bulk_vs_creation_v0.0.2.py \
  --controller avilb.vmi.local \
  --csv my_vs_list.csv \
  --log-dir ./logs
```

### Debug Mode For API Responses

```bash
python3 bulk_vs_creation_v0.0.2.py \
  --controller avilb.vmi.local \
  --csv my_vs_list.csv \
  --debug
```

### Show Version

```bash
python3 bulk_vs_creation_v0.0.2.py --version
```

## Logs

By default, logs are written under:

```text
./logs
```

The log file name format is:

```text
avi_vs_create_YYYYMMDD_HHMMSS.log
```

## Recommended Workflow

1. Generate a sample CSV.
2. Fill in VS, Pool, VIP network, Pool network, and cloud details.
3. Run with `--dry-run --debug`.
4. Review the generated payloads in the log.
5. Run without `--dry-run` to create objects.
