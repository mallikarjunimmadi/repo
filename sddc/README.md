# SDDC Manager Credential Utilities

Scripts to look up and rotate credentials from VMware SDDC Manager.

## Lookup Features

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

### Lookup Credentials

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

### Lookup Options

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

### Lookup CSV Export Behavior

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

### Lookup Security Notes

- SSL verification is disabled by default for lab environments.
- Use this only on trusted networks unless you update the script to enable certificate verification.
- CSV exports may contain sensitive credentials. Store and delete exported files carefully.

## Rotate Features

- Authenticates to SDDC Manager using `/v1/tokens`.
- Takes a full JSON backup of `/v1/credentials` before any rotation.
- Supports rotating one or more specific resources by exact resource name.
- Supports AND-based matching across provided resource name, resource type, and credential type filters.
- Rotates credentials through `PATCH /v1/credentials`.
- Tracks progress through `GET /v1/credentials/tasks/{id}` and logs task and sub-task updates.
- Cancels failed credential tasks through `DELETE /v1/credentials/tasks/{id}`.
- Keeps service accounts and `administrator@vsphere.local` protected by default.
- Supports filtering by resource type and credential type.
- Writes a separate rotation status CSV with resource type, resource name, credential type, credential, task ID, and status.
- Uses `--limit` to control the number of resources sent in each rotation API request and supports dry-run mode.
- Can prompt at the end to optionally email the backup/report summary.

## Rotate Usage

Rotate eligible credentials after taking a full JSON backup first:

```bash
python rotate_passwords_v0.0.2.py --host sddc-manager.example.com --username administrator@local --all
```

Rotate only selected resource and credential types, with more resources per API request:

```bash
python rotate_passwords_v0.0.2.py --host sddc-manager.example.com --username administrator@local --resource-type ESXI,VCENTER --credential-type SSH,API --limit 25
```

Rotate one or more specific resources by name:

```bash
python rotate_passwords_v0.0.2.py --host sddc-manager.example.com --username administrator@local --resource-name esx01.corp.local,esx02.corp.local
```

Rotate only when all provided include filters match:

```bash
python rotate_passwords_v0.0.2.py --host sddc-manager.example.com --username administrator@local --resource-name esx01.corp.local --resource-type ESXI --credential-type SSH
```

Preview what would be rotated without sending any PATCH requests:

```bash
python rotate_passwords_v0.0.2.py --host sddc-manager.example.com --username administrator@local --all --dry-run
```

Skip the end-of-run notify prompt:

```bash
python rotate_passwords_v0.0.2.py --host sddc-manager.example.com --username administrator@local --all --notify no
```

Send the notification email without prompting:

```bash
python rotate_passwords_v0.0.2.py --host sddc-manager.example.com --username administrator@local --all --notify yes --email ops@example.com
```

Exclude only the records that match all provided exclusion categories:

```bash
python rotate_passwords_v0.0.2.py --host sddc-manager.example.com --username administrator@local --all \
  --exclude-username admin1@corp.local \
  --exclude-account-type SYSTEM \
  --exclude-resource-type BACKUP \
  --exclude-credential-type API
```

## Rotate Notes

- Default resources per rotation API request is `10`.
- Default `--limit` is `10`, which means up to 10 resources per rotation API request.
- `rotate_passwords_v0.0.2.py` leaves `rotate_passwords_v0.0.1.py` untouched and changes only the matching logic.
- `--all` rotates all eligible credentials after the hard safety exclusions are applied.
- `--resource-name` accepts one resource or many comma-separated values, and can also be repeated multiple times.
- Resource name matching is exact name match, handled case-insensitively by the script.
- Within a single category, multiple values behave as OR.
- Across categories, include filters behave as AND. If you specify `--resource-name`, `--resource-type`, and `--credential-type`, a credential is rotated only if all specified categories match.
- Across categories, user-provided `--exclude-*` filters also behave as AND. A credential is excluded only if all specified exclusion categories match.
- The built-in safety defaults are still hard exclusions. If a credential matches `ALWAYS_EXCLUDED_*`, it is never rotated.
- The script processes all eligible resources; `--limit` does not cap the total run, it only controls request chunk size.
- Service accounts and `administrator@vsphere.local` are protected by default.
- The rotation script writes a full backup JSON, a detailed log file, and a separate status CSV before and during execution.
- The status CSV is written to the `reports` directory by default and is updated as tasks move from `PENDING` to `SUBMITTED` to their final status.
- In the status CSV, the `credential` column stores the username being rotated.
- By default, the script asks at the end whether to send an email notification.
- If you answer `Y` in prompt mode, the script asks for the recipient email address and sends the backup/report summary plus attaches the backup JSON and report CSV when available.
- If you use `--notify yes`, you must also provide `--email`, and the script sends the email without prompting.
- If you use `--notify no`, no notify prompt is shown.
- SMTP defaults are defined near the top of [rotate_passwords_v0.0.2.py](/Users/mi013830/tools/scripts/vsphere/sddc-m/rotate_passwords_v0.0.2.py:44) in:
  `SMTP_HOST`, `SMTP_PORT`, `SMTP_USERNAME`, `SMTP_PASSWORD`, `SMTP_SENDER`, and `SMTP_USE_TLS`.
- You can keep mail settings permanently in that top config section, or override them with `--smtp-host`, `--smtp-port`, `--smtp-username`, `--smtp-password`, `--smtp-use-tls`, and `--email-from`.
- To change built-in default safety exclusions, update these variables in [rotate_passwords_v0.0.2.py](/Users/mi013830/tools/scripts/vsphere/sddc-m/rotate_passwords_v0.0.2.py:45):
  `ALWAYS_EXCLUDED_USERNAMES`, `ALWAYS_EXCLUDED_ACCOUNT_TYPES`, `ALWAYS_EXCLUDED_RESOURCE_TYPES`, and `ALWAYS_EXCLUDED_CREDENTIAL_TYPES`.
- The same section in `rotate_passwords_v0.0.2.py` also includes a commented CLI example for composite `--exclude-*` usage.
- Permanent exclusion example in the script:

```python
ALWAYS_EXCLUDED_USERNAMES = {
    "administrator@vsphere.local",
    "admin1@corp.local",
    "admin2@corp.local",
}
ALWAYS_EXCLUDED_ACCOUNT_TYPES = {"SERVICE", "SYSTEM"}
ALWAYS_EXCLUDED_RESOURCE_TYPES: Set[str] = {"BACKUP", "NSXT_MANAGER"}
ALWAYS_EXCLUDED_CREDENTIAL_TYPES: Set[str] = {"API", "FTP"}
```

- Use lowercase or normal username values for `ALWAYS_EXCLUDED_USERNAMES`. The script normalizes usernames before comparison.
- Use uppercase values for `ALWAYS_EXCLUDED_ACCOUNT_TYPES`, `ALWAYS_EXCLUDED_RESOURCE_TYPES`, and `ALWAYS_EXCLUDED_CREDENTIAL_TYPES`.
- For ad hoc exclusions, use `--exclude-username`, `--exclude-account-type`, `--exclude-resource-type`, and `--exclude-credential-type`.
- Each exclusion flag accepts comma-separated values and can also be provided multiple times in the same command.

## Requirements

- Python 3.8 or newer.
- Network access to SDDC Manager.
- SDDC Manager credentials with permission to read credential records.
- Rotation script also requires permission to rotate credential records and cancel failed credential tasks.
