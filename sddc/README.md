# SDDC Manager Credential Lookup

Fetch credentials from VMware SDDC Manager and optionally export the full credentials API response to CSV.

## Features

- Authenticates to SDDC Manager using `/v1/tokens`.
- Fetches credentials from `/v1/credentials`.
- Supports fetching all credentials, by credential ID, by resource name, or by resource type.
- Supports optional domain filtering.
- Prints a readable terminal table.
- Exports CSV using every key/value returned by the credentials API.
- Flattens nested response data into dotted CSV columns, such as `resource.resourceName`.
- Handles paginated credential API responses.

## Install

Create and activate a virtual environment:

```bash
python3 -m venv sddc-venv
source sddc-venv/bin/activate
```

Install dependencies:

```bash
pip install -r requirements.txt
```

## Usage

Run interactively:

```bash
python lookup_passwords.py
```

Fetch all credentials and export to an auto-named CSV file:

```bash
python lookup_passwords.py --host <sddc-manager-fqdn-or-ip> --username <user> --all --export
```

Fetch by resource name and export to a specific CSV file:

```bash
python lookup_passwords.py --host <sddc-manager-fqdn-or-ip> --username <user> --resource-name <name> --export credentials.csv
```

Fetch by credential ID:

```bash
python lookup_passwords.py --host <sddc-manager-fqdn-or-ip> --username <user> --id <credential-id>
```

Show passwords in terminal output:

```bash
python lookup_passwords.py --host <sddc-manager-fqdn-or-ip> --username <user> --all --show
```

## Options

- `--host` - SDDC Manager FQDN or IP address.
- `--username` - SDDC Manager username.
- `--password` - SDDC Manager password. If omitted, the script prompts securely.
- `--all` - Fetch all credentials.
- `--id` - Fetch one credential by credential ID.
- `--resource-name` - Fetch credentials matching a resource name. Partial match is supported client-side.
- `--resource-type` - Fetch by resource type, such as `ESXI`, `NSXT_MANAGER`, `VCENTER`, `BACKUP`, or `PSC`.
- `--domain-name` - Filter by domain name.
- `--show` - Include password values in the terminal table.
- `--export` - Export to CSV. With no filename, the script creates `<host>_credentials_<YYYYMMDD_HHMMSS>.csv`.
- `--verbose` - Enable debug logging.

## CSV Export Behavior

CSV export includes all fields returned by the credentials API, not only the fields displayed in the terminal table.

Nested dictionaries are flattened using dotted column names:

```text
resource.resourceName
resource.resourceType
resource.resourceIp
```

Lists are flattened using numeric indexes:

```text
tags.0.key
tags.0.value
```

Complex values that cannot be represented as simple scalars are serialized as JSON.

## Security Notes

- SSL verification is disabled by default for lab environments.
- Use this only on trusted networks unless you update the script to enable certificate verification.
- CSV exports may contain sensitive credentials. Store and delete exported files carefully.

## Requirements

- Python 3.8 or newer.
- Network access to SDDC Manager.
- SDDC Manager credentials with permission to read credential records.
