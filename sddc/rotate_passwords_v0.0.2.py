#!/usr/bin/env python3
"""
rotate_passwords_v0.0.2

Rotate VMware Cloud Foundation credentials from SDDC Manager.

Features
- Authenticates to SDDC Manager using /v1/tokens
- Backs up the full /v1/credentials dataset before any rotation
- Supports rotating specific resources by exact resource name
- Uses AND logic across provided include filters
- Uses AND logic across user-specified exclusion filters
- Always protects default excluded usernames/account types/resource types/credential types
- Supports rotating all eligible credentials with --all
- Uses --limit to control the number of resources sent per rotation API request
- Polls credential task progress and logs task/sub-task status changes
- Cancels failed credential tasks via DELETE /v1/credentials/tasks/{id}
- Can prompt to email the backup/report summary when execution finishes

Requires: requests
  pip install requests
"""

import argparse
from collections import Counter
import csv
from datetime import datetime
from email.message import EmailMessage
import getpass
import json
import logging
import mimetypes
from pathlib import Path
import smtplib
import socket
import sys
import time
from typing import Any, Dict, Iterable, List, Optional, Sequence, Set, Tuple

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# --- defaults ---
RETRIES = 3
BACKOFF_FACTOR = 1.0
TIMEOUT = 30
PAGE_SIZE = 200
DEFAULT_LIMIT = 10
DEFAULT_POLL_INTERVAL = 15

# SMTP defaults for end-of-run email notifications.
# Update these values if you want the script to use a fixed mail relay by default.
# Example:
# SMTP_HOST = "smtp.example.com"
# SMTP_PORT = 587
# SMTP_USERNAME = "svc_sddc_notify@example.com"
# SMTP_PASSWORD = "change-me"
# SMTP_SENDER = "svc_sddc_notify@example.com"
# SMTP_USE_TLS = True
SMTP_HOST = "localhost"
SMTP_PORT = 25
SMTP_USERNAME = ""
SMTP_PASSWORD = ""
SMTP_SENDER = f"sddc-rotation@{socket.getfqdn()}"
SMTP_USE_TLS = False

# Always-protected defaults. These are applied as hard exclusions.
# Update these sets if you want permanent protection in every run.
# Example:
# ALWAYS_EXCLUDED_USERNAMES = {
#     "administrator@vsphere.local",
#     "admin1@corp.local",
#     "admin2@corp.local",
# }
# ALWAYS_EXCLUDED_ACCOUNT_TYPES = {"SERVICE", "SYSTEM"}
# ALWAYS_EXCLUDED_RESOURCE_TYPES: Set[str] = {"BACKUP", "NSXT_MANAGER"}
# ALWAYS_EXCLUDED_CREDENTIAL_TYPES: Set[str] = {"API", "FTP"}
# Composite exclude example from CLI:
#   python rotate_passwords_v0.0.2.py --host sddc-manager.example.com --username administrator@local --all \
#     --exclude-username admin1@corp.local \
#     --exclude-account-type SYSTEM \
#     --exclude-resource-type BACKUP \
#     --exclude-credential-type API
# This excludes only credentials where all specified exclusion categories match together.
ALWAYS_EXCLUDED_USERNAMES = {"administrator@vsphere.local"}
ALWAYS_EXCLUDED_ACCOUNT_TYPES = {"SERVICE"}
ALWAYS_EXCLUDED_RESOURCE_TYPES: Set[str] = set()
ALWAYS_EXCLUDED_CREDENTIAL_TYPES: Set[str] = set()

TERMINAL_TASK_STATES = {
    "SUCCESSFUL",
    "FAILED",
    "USER_CANCELLED",
    "CANCELLED",
    "COMPLETED_WITH_WARNING",
    "SKIPPED",
    "INCONSISTENT",
}


LOG = logging.getLogger("sddc_rotate_credentials")

ROTATION_REPORT_FIELDS = [
    "resource_type",
    "resource_name",
    "credential_type",
    "credential",
    "task_id",
    "status",
]


def configure_logging(log_file: Path, verbose: bool = False) -> None:
    LOG.setLevel(logging.DEBUG)
    LOG.handlers.clear()

    formatter = logging.Formatter("%(asctime)s %(levelname)s: %(message)s")

    file_handler = logging.FileHandler(log_file, encoding="utf-8")
    file_handler.setLevel(logging.DEBUG)
    file_handler.setFormatter(formatter)

    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(logging.DEBUG if verbose else logging.INFO)
    console_handler.setFormatter(formatter)

    LOG.addHandler(file_handler)
    LOG.addHandler(console_handler)


def requests_session(retries: int = RETRIES, backoff: float = BACKOFF_FACTOR, verify: bool = False):
    session = requests.Session()
    retry = Retry(
        total=retries,
        backoff_factor=backoff,
        status_forcelist=(429, 500, 502, 503, 504),
        allowed_methods=frozenset(["GET", "POST", "PUT", "DELETE", "PATCH"]),
    )
    session.mount("https://", HTTPAdapter(max_retries=retry))
    session.verify = verify
    if not verify:
        from urllib3.exceptions import InsecureRequestWarning
        import urllib3

        urllib3.disable_warnings(InsecureRequestWarning)
        LOG.warning("SSL verification disabled. Use only in trusted environments.")
    return session


def get_token(session: requests.Session, base_url: str, username: str, password: str) -> str:
    url = f"{base_url.rstrip('/')}/v1/tokens"
    response = session.post(
        url,
        json={"username": username, "password": password},
        headers={"Content-Type": "application/json"},
        timeout=TIMEOUT,
    )
    if response.status_code != 200:
        raise RuntimeError(f"Failed to get token: HTTP {response.status_code} - {response.text}")

    payload = response.json()
    token = (
        payload.get("accessToken")
        or payload.get("access_token")
        or (payload.get("data") or {}).get("accessToken")
        or (payload.get("data") or {}).get("access_token")
        or (payload.get("token") or {}).get("accessToken")
    )
    if not token:
        raise RuntimeError(f"Token response missing access token: {payload}")
    return token


def _parse_credentials_payload(payload: Any) -> List[Dict[str, Any]]:
    if isinstance(payload, list):
        return payload
    if isinstance(payload, dict):
        for key in ("elements", "content", "credentials", "result", "items", "data"):
            value = payload.get(key)
            if isinstance(value, list):
                return value
        if any(key in payload for key in ("id", "username", "resource")):
            return [payload]
    return []


def fetch_credentials_list(session: requests.Session, base_url: str, token: str) -> List[Dict[str, Any]]:
    url = f"{base_url.rstrip('/')}/v1/credentials"
    headers = {"Authorization": f"Bearer {token}", "Accept": "application/json"}
    page_number = 0
    results: List[Dict[str, Any]] = []

    while True:
        response = session.get(
            url,
            headers=headers,
            params={"pageSize": PAGE_SIZE, "pageNumber": page_number},
            timeout=TIMEOUT,
        )
        response.raise_for_status()
        payload = response.json()
        results.extend(_parse_credentials_payload(payload))

        metadata = payload.get("pageMetadata") if isinstance(payload, dict) else None
        if metadata and metadata.get("pageNumber", 0) + 1 < metadata.get("totalPages", 1):
            page_number = metadata["pageNumber"] + 1
            continue
        break

    return results


def save_backup(backup_dir: Path, host: str, credentials: List[Dict[str, Any]]) -> Path:
    backup_dir.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    backup_file = backup_dir / f"{host}_credentials_backup_{timestamp}.json"
    with backup_file.open("w", encoding="utf-8") as handle:
        json.dump(credentials, handle, indent=2, sort_keys=True)
    LOG.info("Backed up %d credential records to %s", len(credentials), backup_file)
    return backup_file


def write_rotation_report(report_file: Path, rows: List[Dict[str, str]]) -> None:
    report_file.parent.mkdir(parents=True, exist_ok=True)
    with report_file.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=ROTATION_REPORT_FIELDS)
        writer.writeheader()
        for row in rows:
            writer.writerow({field: row.get(field, "") for field in ROTATION_REPORT_FIELDS})


def prompt_yes_no(message: str, default: str = "no") -> bool:
    default = default.lower()
    suffix = " [Y/n]: " if default == "yes" else " [y/N]: "
    while True:
        value = input(f"{message}{suffix}").strip().lower()
        if not value:
            value = default
        if value in {"y", "yes"}:
            return True
        if value in {"n", "no"}:
            return False
        print("Please enter yes or no.")


def prompt_text(message: str) -> str:
    while True:
        value = input(f"{message}: ").strip()
        if value:
            return value
        print("A value is required.")


def compose_notification_body(
    status: str,
    host: str,
    backup_file: Optional[Path],
    report_file: Optional[Path],
    log_file: Path,
) -> str:
    lines = [
        f"SDDC Manager password rotation finished with status: {status}",
        f"Host: {host}",
        "",
        "Generated files:",
        f"- Backup JSON: {backup_file if backup_file else 'Not generated'}",
        f"- Report CSV: {report_file if report_file else 'Not generated'}",
        f"- Log file: {log_file}",
        "",
        "The backup JSON and report CSV are attached when available.",
    ]
    return "\n".join(lines)


def attach_file(message: EmailMessage, file_path: Path) -> None:
    mime_type, _ = mimetypes.guess_type(str(file_path))
    if mime_type:
        maintype, subtype = mime_type.split("/", 1)
    else:
        maintype, subtype = "application", "octet-stream"
    with file_path.open("rb") as handle:
        message.add_attachment(handle.read(), maintype=maintype, subtype=subtype, filename=file_path.name)


def send_notification_email(
    smtp_host: str,
    smtp_port: int,
    smtp_username: str,
    smtp_password: str,
    smtp_use_tls: bool,
    sender: str,
    recipient: str,
    subject: str,
    body: str,
    attachments: Sequence[Path],
) -> None:
    message = EmailMessage()
    message["From"] = sender
    message["To"] = recipient
    message["Subject"] = subject
    message.set_content(body)

    for attachment in attachments:
        if attachment.exists():
            attach_file(message, attachment)

    with smtplib.SMTP(smtp_host, smtp_port, timeout=30) as smtp:
        if smtp_use_tls:
            smtp.starttls()
        if smtp_username:
            smtp.login(smtp_username, smtp_password)
        smtp.send_message(message)


def parse_csv_set(values: Optional[Sequence[str]]) -> Set[str]:
    parsed: Set[str] = set()
    for value in values or []:
        for item in value.split(","):
            cleaned = item.strip()
            if cleaned:
                parsed.add(cleaned.upper())
    return parsed


def parse_csv_preserve_case(values: Optional[Sequence[str]]) -> Set[str]:
    parsed: Set[str] = set()
    for value in values or []:
        for item in value.split(","):
            cleaned = item.strip()
            if cleaned:
                parsed.add(cleaned)
    return parsed


def normalize_usernames(values: Iterable[str]) -> Set[str]:
    return {value.strip().lower() for value in values if value and value.strip()}


def normalize_names(values: Iterable[str]) -> Set[str]:
    return {value.strip().lower() for value in values if value and value.strip()}


def category_match(actual: str, allowed: Set[str]) -> bool:
    return not allowed or actual in allowed


def include_match(
    rotate_all: bool,
    include_resource_names: Set[str],
    include_resource_types: Set[str],
    include_credential_types: Set[str],
    resource_name: str,
    resource_type: str,
    credential_type: str,
) -> bool:
    if rotate_all and not include_resource_names and not include_resource_types and not include_credential_types:
        return True

    if include_resource_names and resource_name not in include_resource_names:
        return False
    if include_resource_types and resource_type not in include_resource_types:
        return False
    if include_credential_types and credential_type not in include_credential_types:
        return False

    return bool(include_resource_names or include_resource_types or include_credential_types or rotate_all)


def composite_exclusion_match(
    excluded_usernames: Set[str],
    excluded_account_types: Set[str],
    excluded_resource_types: Set[str],
    excluded_credential_types: Set[str],
    username: str,
    account_type: str,
    resource_type: str,
    credential_type: str,
) -> bool:
    if not any((excluded_usernames, excluded_account_types, excluded_resource_types, excluded_credential_types)):
        return False
    if excluded_usernames and username not in excluded_usernames:
        return False
    if excluded_account_types and account_type not in excluded_account_types:
        return False
    if excluded_resource_types and resource_type not in excluded_resource_types:
        return False
    if excluded_credential_types and credential_type not in excluded_credential_types:
        return False
    return True


def build_rotation_targets(
    credentials: List[Dict[str, Any]],
    include_resource_names: Set[str],
    include_resource_types: Set[str],
    include_credential_types: Set[str],
    always_excluded_resource_types: Set[str],
    always_excluded_credential_types: Set[str],
    always_excluded_usernames: Set[str],
    always_excluded_account_types: Set[str],
    excluded_resource_types: Set[str],
    excluded_credential_types: Set[str],
    excluded_usernames: Set[str],
    excluded_account_types: Set[str],
    rotate_all: bool,
) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    selected: List[Dict[str, Any]] = []
    skipped: List[Dict[str, Any]] = []

    for credential in credentials:
        resource = credential.get("resource") or {}
        resource_name = str(resource.get("resourceName") or "")
        resource_name_normalized = resource_name.lower()
        resource_type = str(resource.get("resourceType") or "").upper()
        credential_type = str(credential.get("credentialType") or "").upper()
        account_type = str(credential.get("accountType") or "").upper()
        username = str(credential.get("username") or "")
        username_normalized = username.lower()

        skip_reason = None
        if not resource_name:
            skip_reason = "missing_resource_name"
        elif username_normalized in always_excluded_usernames:
            skip_reason = "always_excluded_username"
        elif account_type in always_excluded_account_types:
            skip_reason = "always_excluded_account_type"
        elif resource_type in always_excluded_resource_types:
            skip_reason = "always_excluded_resource_type"
        elif credential_type in always_excluded_credential_types:
            skip_reason = "always_excluded_credential_type"
        elif composite_exclusion_match(
            excluded_usernames=excluded_usernames,
            excluded_account_types=excluded_account_types,
            excluded_resource_types=excluded_resource_types,
            excluded_credential_types=excluded_credential_types,
            username=username_normalized,
            account_type=account_type,
            resource_type=resource_type,
            credential_type=credential_type,
        ):
            skip_reason = "composite_exclusion_match"
        elif not include_match(
            rotate_all=rotate_all,
            include_resource_names=include_resource_names,
            include_resource_types=include_resource_types,
            include_credential_types=include_credential_types,
            resource_name=resource_name_normalized,
            resource_type=resource_type,
            credential_type=credential_type,
        ):
            skip_reason = "include_filter_not_matched"

        if skip_reason:
            skipped.append({"credential": credential, "reason": skip_reason})
            continue

        selected.append(credential)

    return selected, skipped


def summarize_selection(selected: List[Dict[str, Any]], skipped: List[Dict[str, Any]]) -> None:
    resource_counter = Counter()
    credential_counter = Counter()
    skip_counter = Counter(entry["reason"] for entry in skipped)

    for credential in selected:
        resource = credential.get("resource") or {}
        resource_counter[str(resource.get("resourceType") or "UNKNOWN")] += 1
        credential_counter[str(credential.get("credentialType") or "UNKNOWN")] += 1

    LOG.info("Eligible credentials selected: %d", len(selected))
    if resource_counter:
        LOG.info("Selected by resource type: %s", dict(sorted(resource_counter.items())))
    if credential_counter:
        LOG.info("Selected by credential type: %s", dict(sorted(credential_counter.items())))
    if skip_counter:
        LOG.info("Skipped credentials by reason: %s", dict(sorted(skip_counter.items())))


def collect_effective_types(credentials: Iterable[Dict[str, Any]]) -> Tuple[List[str], List[str]]:
    resource_types = sorted(
        {
            str((credential.get("resource") or {}).get("resourceType") or "").upper()
            for credential in credentials
            if str((credential.get("resource") or {}).get("resourceType") or "").strip()
        }
    )
    credential_types = sorted(
        {
            str(credential.get("credentialType") or "").upper()
            for credential in credentials
            if str(credential.get("credentialType") or "").strip()
        }
    )
    return resource_types, credential_types


def _resource_key(resource_name: str, resource_type: str, credential_type: str, username: str) -> Tuple[str, str, str, str]:
    return (
        str(resource_name or ""),
        str(resource_type or "").upper(),
        str(credential_type or "").upper(),
        str(username or "").lower(),
    )


def initialize_rotation_report(resources: List[Dict[str, Any]]) -> List[Dict[str, str]]:
    report_rows: List[Dict[str, str]] = []
    for resource in resources:
        resource_name = str(resource.get("resourceName") or "")
        resource_type = str(resource.get("resourceType") or "")
        for credential in resource.get("credentials") or []:
            username = str(credential.get("username") or "")
            credential_type = str(credential.get("credentialType") or "")
            report_rows.append(
                {
                    "_key": _resource_key(resource_name, resource_type, credential_type, username),
                    "resource_type": resource_type,
                    "resource_name": resource_name,
                    "credential_type": credential_type,
                    "credential": username,
                    "task_id": "",
                    "status": "PENDING",
                }
            )
    return report_rows


def set_report_status(rows: List[Dict[str, str]], status: str) -> None:
    for row in rows:
        row["status"] = status


def assign_task_to_report_rows(rows: List[Dict[str, str]], batch: List[Dict[str, Any]], task_id: str) -> None:
    batch_keys = set()
    for resource in batch:
        resource_name = str(resource.get("resourceName") or "")
        resource_type = str(resource.get("resourceType") or "")
        for credential in resource.get("credentials") or []:
            batch_keys.add(
                _resource_key(
                    resource_name,
                    resource_type,
                    str(credential.get("credentialType") or ""),
                    str(credential.get("username") or ""),
                )
            )

    for row in rows:
        if row.get("_key") in batch_keys:
            row["task_id"] = task_id
            row["status"] = "SUBMITTED"


def update_report_from_task(rows: List[Dict[str, str]], task_id: str, task_payload: Dict[str, Any]) -> None:
    final_status = str(task_payload.get("status") or "UNKNOWN").upper()

    for subtask in task_payload.get("subTasks") or []:
        key = _resource_key(
            str(subtask.get("resourceName") or ""),
            "",
            str(subtask.get("credentialType") or ""),
            str(subtask.get("username") or ""),
        )
        for row in rows:
            row_key = row.get("_key")
            if not isinstance(row_key, tuple):
                continue
            if row.get("task_id") == task_id and row_key[0] == key[0] and row_key[2] == key[2] and row_key[3] == key[3]:
                row["status"] = str(subtask.get("status") or final_status).upper()

    for row in rows:
        if row.get("task_id") == task_id and row["status"] == "SUBMITTED":
            row["status"] = final_status


def group_targets_by_resource(credentials: Iterable[Dict[str, Any]]) -> List[Dict[str, Any]]:
    grouped: Dict[Tuple[str, str, str], Dict[str, Any]] = {}

    for credential in credentials:
        resource = credential.get("resource") or {}
        resource_name = str(resource.get("resourceName") or "")
        resource_type = str(resource.get("resourceType") or "")
        resource_id = str(resource.get("resourceId") or "")
        key = (resource_name, resource_type, resource_id)

        if key not in grouped:
            grouped[key] = {
                "resourceName": resource_name,
                "resourceType": resource_type,
                "credentials": [],
            }
            if resource_id:
                grouped[key]["resourceId"] = resource_id

        entry = {
            "credentialType": credential.get("credentialType"),
            "username": credential.get("username"),
        }

        account_type = credential.get("accountType")
        if account_type:
            entry["accountType"] = account_type

        if entry not in grouped[key]["credentials"]:
            grouped[key]["credentials"].append(entry)

    grouped_list = list(grouped.values())
    grouped_list.sort(key=lambda item: (item["resourceType"], item["resourceName"]))
    return grouped_list


def chunked(items: Sequence[Dict[str, Any]], size: int) -> Iterable[List[Dict[str, Any]]]:
    for idx in range(0, len(items), size):
        yield list(items[idx: idx + size])


def submit_rotation_task(
    session: requests.Session,
    base_url: str,
    token: str,
    elements: List[Dict[str, Any]],
) -> Dict[str, Any]:
    url = f"{base_url.rstrip('/')}/v1/credentials"
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
        "Accept": "application/json",
    }
    payload = {
        "operationType": "ROTATE",
        "elements": elements,
    }
    response = session.patch(url, headers=headers, json=payload, timeout=TIMEOUT)
    if response.status_code != 202:
        raise RuntimeError(f"Rotation request failed: HTTP {response.status_code} - {response.text}")
    return response.json() if response.text.strip() else {"id": response.headers.get("Location", "").split("/")[-1]}


def get_credentials_task(session: requests.Session, base_url: str, token: str, task_id: str) -> Dict[str, Any]:
    url = f"{base_url.rstrip('/')}/v1/credentials/tasks/{task_id}"
    headers = {"Authorization": f"Bearer {token}", "Accept": "application/json"}
    response = session.get(url, headers=headers, timeout=TIMEOUT)
    response.raise_for_status()
    return response.json()


def cancel_credentials_task(session: requests.Session, base_url: str, token: str, task_id: str) -> Dict[str, Any]:
    url = f"{base_url.rstrip('/')}/v1/credentials/tasks/{task_id}"
    headers = {"Authorization": f"Bearer {token}", "Accept": "application/json"}
    response = session.delete(url, headers=headers, timeout=TIMEOUT)
    if response.status_code not in (200, 202):
        raise RuntimeError(f"Failed to cancel task {task_id}: HTTP {response.status_code} - {response.text}")
    return response.json() if response.text.strip() else {"id": task_id, "status": "CANCEL_REQUESTED"}


def task_status_summary(task_payload: Dict[str, Any]) -> Dict[str, int]:
    statuses = Counter()
    for subtask in task_payload.get("subTasks") or []:
        statuses[str(subtask.get("status") or "UNKNOWN")] += 1
    return dict(sorted(statuses.items()))


def log_task_errors(task_payload: Dict[str, Any]) -> None:
    for error in task_payload.get("errors") or []:
        LOG.error(
            "Task error: code=%s type=%s message=%s remediation=%s ref=%s",
            error.get("errorCode"),
            error.get("errorType"),
            error.get("message"),
            error.get("remediationMessage"),
            error.get("referenceToken"),
        )

    for subtask in task_payload.get("subTasks") or []:
        for error in subtask.get("errors") or []:
            LOG.error(
                "Sub-task failure: resource=%s credentialType=%s username=%s message=%s ref=%s",
                subtask.get("resourceName"),
                subtask.get("credentialType"),
                subtask.get("username"),
                error.get("message"),
                error.get("referenceToken"),
            )


def wait_for_task_completion(
    session: requests.Session,
    base_url: str,
    token: str,
    task_id: str,
    poll_interval: int,
) -> Dict[str, Any]:
    last_status = None
    last_summary = None

    while True:
        task_payload = get_credentials_task(session, base_url, token, task_id)
        status = str(task_payload.get("status") or "UNKNOWN").upper()
        summary = task_status_summary(task_payload)

        if status != last_status or summary != last_summary:
            LOG.info("Task %s status=%s subTaskSummary=%s", task_id, status, summary or {})
            last_status = status
            last_summary = summary

        if status in TERMINAL_TASK_STATES:
            return task_payload

        time.sleep(poll_interval)


def prompt_missing_args(args: argparse.Namespace) -> argparse.Namespace:
    def ask(prompt: str, default: Optional[str] = None) -> str:
        value = input(f"{prompt}{' [' + default + ']' if default else ''}: ").strip()
        return value if value else (default or "")

    if not args.host:
        args.host = ask("Enter SDDC Manager FQDN or IP")
    if not args.username:
        args.username = ask("Enter username")
    if not args.password:
        args.password = getpass.getpass("Enter password: ")
    return args


def parse_args() -> argparse.Namespace:
    examples = """Examples:
  Rotate all eligible credentials:
    python rotate_passwords_v0.0.2.py --host sddc-manager.example.com --username administrator@local --all

  Rotate specific resources by name:
    python rotate_passwords_v0.0.2.py --host sddc-manager.example.com --username administrator@local --resource-name esx01.corp.local,esx02.corp.local

  Rotate selected resource and credential types:
    python rotate_passwords_v0.0.2.py --host sddc-manager.example.com --username administrator@local --resource-type ESXI,VCENTER --credential-type SSH,API --limit 25

  Rotate with AND-based include filters:
    python rotate_passwords_v0.0.2.py --host sddc-manager.example.com --username administrator@local --resource-name esx01.corp.local --resource-type ESXI --credential-type SSH

  Exclude only the specific combination that matches all given categories:
    python rotate_passwords_v0.0.2.py --host sddc-manager.example.com --username administrator@local --all --exclude-username admin1@corp.local --exclude-account-type SYSTEM --exclude-resource-type BACKUP --exclude-credential-type API

  Skip end-of-run notify prompt:
    python rotate_passwords_v0.0.2.py --host sddc-manager.example.com --username administrator@local --all --notify no

  Send notification email without prompting:
    python rotate_passwords_v0.0.2.py --host sddc-manager.example.com --username administrator@local --all --notify yes --email ops@example.com

  Preview without sending rotation requests:
    python rotate_passwords_v0.0.2.py --host sddc-manager.example.com --username administrator@local --all --dry-run
"""
    parser = argparse.ArgumentParser(
        description="Rotate VMware Cloud Foundation credentials from SDDC Manager",
        epilog=examples,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--host", help="SDDC Manager FQDN or IP")
    parser.add_argument("--username", help="Username")
    parser.add_argument("--password", help="Password (prompted if omitted)")
    parser.add_argument(
        "--resource-name",
        action="append",
        help="Exact resource name(s) to rotate. Multiple names are OR within this category; categories are AND together.",
    )
    parser.add_argument(
        "--resource-type",
        action="append",
        help="Resource type(s) to rotate. Multiple types are OR within this category; categories are AND together.",
    )
    parser.add_argument(
        "--credential-type",
        action="append",
        help="Credential type(s) to rotate. Multiple types are OR within this category; categories are AND together.",
    )
    parser.add_argument("--all", action="store_true", help="Rotate all eligible credentials after hard safety exclusions are applied")
    parser.add_argument(
        "--limit",
        type=int,
        default=DEFAULT_LIMIT,
        help=f"Maximum number of resources per rotation API call. Default: {DEFAULT_LIMIT}",
    )
    parser.add_argument(
        "--poll-interval",
        type=int,
        default=DEFAULT_POLL_INTERVAL,
        help=f"Task polling interval in seconds. Default: {DEFAULT_POLL_INTERVAL}",
    )
    parser.add_argument(
        "--backup-dir",
        default="rotation_backups",
        help="Directory for full credentials backup JSON files. Default: rotation_backups",
    )
    parser.add_argument(
        "--log-dir",
        default="logs",
        help="Directory for rotation log files. Default: logs",
    )
    parser.add_argument(
        "--report-dir",
        default="reports",
        help="Directory for rotation status CSV files. Default: reports",
    )
    parser.add_argument(
        "--notify",
        choices=("ask", "yes", "no"),
        default="ask",
        help="Notify by email after execution finishes. Default: ask",
    )
    parser.add_argument("--email", help="Recipient address for notification emails. Required with --notify yes.")
    parser.add_argument(
        "--smtp-host",
        default=SMTP_HOST,
        help=f"SMTP host for notification emails. Default: {SMTP_HOST}",
    )
    parser.add_argument(
        "--smtp-port",
        type=int,
        default=SMTP_PORT,
        help=f"SMTP port for notification emails. Default: {SMTP_PORT}",
    )
    parser.add_argument(
        "--smtp-username",
        default=SMTP_USERNAME,
        help="SMTP username for notification emails. Default: value from top-of-file SMTP config",
    )
    parser.add_argument(
        "--smtp-password",
        default=SMTP_PASSWORD,
        help="SMTP password for notification emails. Default: value from top-of-file SMTP config",
    )
    parser.add_argument(
        "--smtp-use-tls",
        action="store_true",
        default=SMTP_USE_TLS,
        help="Enable STARTTLS for notification emails. Default: value from top-of-file SMTP config",
    )
    parser.add_argument(
        "--email-from",
        default=SMTP_SENDER,
        help="Sender address for notification emails. Default: value from top-of-file SMTP config",
    )
    parser.add_argument(
        "--exclude-resource-type",
        action="append",
        help="Resource type(s) for composite exclusion matching. Multiple values are OR within this category; categories are AND together.",
    )
    parser.add_argument(
        "--exclude-credential-type",
        action="append",
        help="Credential type(s) for composite exclusion matching. Multiple values are OR within this category; categories are AND together.",
    )
    parser.add_argument(
        "--exclude-username",
        action="append",
        help="Username(s) for composite exclusion matching. Multiple values are OR within this category; categories are AND together.",
    )
    parser.add_argument(
        "--exclude-account-type",
        action="append",
        help="Account type(s) for composite exclusion matching. Multiple values are OR within this category; categories are AND together.",
    )
    parser.add_argument("--dry-run", action="store_true", help="Show what would be rotated without sending PATCH requests")
    parser.add_argument("--verbose", action="store_true", help="Enable debug logging")
    return parser.parse_args()


def validate_args(args: argparse.Namespace) -> None:
    if args.limit < 1:
        raise ValueError("--limit must be at least 1")
    if args.poll_interval < 1:
        raise ValueError("--poll-interval must be at least 1")
    if not args.all and not args.resource_name and not args.resource_type and not args.credential_type:
        raise ValueError("Specify --all or at least one --resource-name/--resource-type/--credential-type filter")
    if args.notify == "yes" and not args.email:
        raise ValueError("--email is required when --notify yes is used")
    if args.notify == "no" and args.email:
        raise ValueError("--email cannot be used with --notify no")


def main() -> None:
    args = parse_args()
    args = prompt_missing_args(args)
    validate_args(args)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    log_dir = Path(args.log_dir)
    log_dir.mkdir(parents=True, exist_ok=True)
    log_file = log_dir / f"sddc_password_rotation_{timestamp}.log"
    report_dir = Path(args.report_dir)
    report_file = report_dir / f"sddc_password_rotation_status_{timestamp}.csv"
    email_sender = args.email_from
    configure_logging(log_file, verbose=args.verbose)

    requested_resource_names = parse_csv_preserve_case(args.resource_name)
    include_resource_names = normalize_names(requested_resource_names)
    include_resource_types = parse_csv_set(args.resource_type)
    include_credential_types = parse_csv_set(args.credential_type)

    excluded_resource_types = parse_csv_set(args.exclude_resource_type)
    excluded_credential_types = parse_csv_set(args.exclude_credential_type)
    excluded_account_types = parse_csv_set(args.exclude_account_type)
    excluded_usernames = normalize_usernames(parse_csv_preserve_case(args.exclude_username))

    always_excluded_resource_types = ALWAYS_EXCLUDED_RESOURCE_TYPES
    always_excluded_credential_types = ALWAYS_EXCLUDED_CREDENTIAL_TYPES
    always_excluded_account_types = ALWAYS_EXCLUDED_ACCOUNT_TYPES
    always_excluded_usernames = normalize_usernames(ALWAYS_EXCLUDED_USERNAMES)

    LOG.info("Rotation log file: %s", log_file)
    LOG.info("Rotation status CSV: %s", report_file)
    LOG.info("Requested resource names: %s", sorted(requested_resource_names) or ["AUTO-DETECT FROM ELIGIBLE INVENTORY"])
    LOG.info("Requested resource types: %s", sorted(include_resource_types) or ["AUTO-DETECT FROM ELIGIBLE INVENTORY"])
    LOG.info("Requested credential types: %s", sorted(include_credential_types) or ["AUTO-DETECT FROM ELIGIBLE INVENTORY"])
    LOG.info("Always excluded resource types: %s", sorted(always_excluded_resource_types) or ["NONE"])
    LOG.info("Always excluded credential types: %s", sorted(always_excluded_credential_types) or ["NONE"])
    LOG.info("Always excluded account types: %s", sorted(always_excluded_account_types) or ["NONE"])
    LOG.info("Always excluded usernames: %s", sorted(always_excluded_usernames) or ["NONE"])
    LOG.info("Composite exclude resource types: %s", sorted(excluded_resource_types) or ["NONE"])
    LOG.info("Composite exclude credential types: %s", sorted(excluded_credential_types) or ["NONE"])
    LOG.info("Composite exclude account types: %s", sorted(excluded_account_types) or ["NONE"])
    LOG.info("Composite exclude usernames: %s", sorted(excluded_usernames) or ["NONE"])
    LOG.info("Notify mode: %s", args.notify)
    LOG.info("SMTP host: %s", args.smtp_host)
    LOG.info("SMTP port: %s", args.smtp_port)
    LOG.info("SMTP username configured: %s", "YES" if args.smtp_username else "NO")
    LOG.info("SMTP TLS enabled: %s", "YES" if args.smtp_use_tls else "NO")
    LOG.info("SMTP sender: %s", email_sender)

    base_url = f"https://{args.host}"
    session = requests_session(verify=False)
    exit_code = 0
    run_status = "SUCCESS"
    backup_file: Optional[Path] = None

    try:
        token = get_token(session, base_url, args.username, args.password)
        LOG.info("Authenticated to SDDC Manager %s", args.host)
    except Exception as exc:
        LOG.error("Authentication failed: %s", exc)
        exit_code = 2
        run_status = "AUTHENTICATION_FAILED"
        token = None

    if token:
        try:
            credentials = fetch_credentials_list(session, base_url, token)
            backup_file = save_backup(Path(args.backup_dir), args.host, credentials)
            LOG.info("Backup completed before rotation: %s", backup_file)

            selected, skipped = build_rotation_targets(
                credentials=credentials,
                include_resource_names=include_resource_names,
                include_resource_types=include_resource_types,
                include_credential_types=include_credential_types,
                always_excluded_resource_types=always_excluded_resource_types,
                always_excluded_credential_types=always_excluded_credential_types,
                always_excluded_usernames=always_excluded_usernames,
                always_excluded_account_types=always_excluded_account_types,
                excluded_resource_types=excluded_resource_types,
                excluded_credential_types=excluded_credential_types,
                excluded_usernames=excluded_usernames,
                excluded_account_types=excluded_account_types,
                rotate_all=args.all,
            )
            effective_resource_types, effective_credential_types = collect_effective_types(selected)
            LOG.info("Effective resource types for this run: %s", effective_resource_types or ["NONE"])
            LOG.info("Effective credential types for this run: %s", effective_credential_types or ["NONE"])
            summarize_selection(selected, skipped)

            grouped_resources = group_targets_by_resource(selected)
            if not grouped_resources:
                LOG.warning("No eligible resources matched the requested scope after exclusions.")
                run_status = "NO_ELIGIBLE_RESOURCES"
            else:
                report_rows = initialize_rotation_report(grouped_resources)
                write_rotation_report(report_file, report_rows)
                LOG.info("Initialized rotation status CSV with %d rows", len(report_rows))

                LOG.info("Resources selected for rotation: %d", len(grouped_resources))
                LOG.info("Resources per rotation API request: %d", args.limit)
                for resource in grouped_resources:
                    LOG.info(
                        "Planned rotation target: resource=%s type=%s credentials=%s",
                        resource["resourceName"],
                        resource["resourceType"],
                        [
                            f"{entry.get('credentialType')}:{entry.get('username')}"
                            for entry in resource["credentials"]
                        ],
                    )

                if args.dry_run:
                    set_report_status(report_rows, "DRY_RUN")
                    write_rotation_report(report_file, report_rows)
                    LOG.info("Dry run enabled. No rotation requests were sent.")
                    run_status = "DRY_RUN"
                else:
                    successful_tasks: List[str] = []
                    failed_tasks: List[str] = []

                    for batch_number, batch in enumerate(chunked(grouped_resources, args.limit), start=1):
                        task_response = submit_rotation_task(session, base_url, token, batch)
                        task_id = str(task_response.get("id") or "")
                        if not task_id:
                            raise RuntimeError(f"Rotation response missing task ID: {task_response}")

                        LOG.info(
                            "Submitted rotation batch %d with %d resources. Task ID: %s",
                            batch_number,
                            len(batch),
                            task_id,
                        )
                        assign_task_to_report_rows(report_rows, batch, task_id)
                        write_rotation_report(report_file, report_rows)

                        final_task = wait_for_task_completion(
                            session=session,
                            base_url=base_url,
                            token=token,
                            task_id=task_id,
                            poll_interval=args.poll_interval,
                        )
                        final_status = str(final_task.get("status") or "UNKNOWN").upper()
                        LOG.info("Task %s completed with status %s", task_id, final_status)
                        update_report_from_task(report_rows, task_id, final_task)
                        write_rotation_report(report_file, report_rows)

                        if final_status == "FAILED":
                            failed_tasks.append(task_id)
                            log_task_errors(final_task)
                            try:
                                cancel_response = cancel_credentials_task(session, base_url, token, task_id)
                                LOG.warning("Cancel requested for failed task %s: %s", task_id, cancel_response)
                                for row in report_rows:
                                    if row.get("task_id") == task_id and row.get("status") == "FAILED":
                                        row["status"] = "FAILED_CANCEL_REQUESTED"
                                write_rotation_report(report_file, report_rows)
                            except Exception as cancel_exc:
                                LOG.error("Failed to cancel failed task %s: %s", task_id, cancel_exc)
                        else:
                            successful_tasks.append(task_id)

                    LOG.info("Rotation finished. Successful tasks=%s Failed tasks=%s", successful_tasks, failed_tasks)

                    if failed_tasks:
                        exit_code = 1
                        run_status = "FAILED"
                    else:
                        run_status = "SUCCESS"

        except Exception as exc:
            LOG.error("Rotation failed: %s", exc)
            exit_code = 1
            run_status = "FAILED"

    if args.notify != "no":
        should_notify = args.notify == "yes" or prompt_yes_no("Send completion email notification?", default="no")
        if should_notify:
            recipient_email = args.email or prompt_text("Enter recipient email")
            email_subject = f"SDDC rotation {run_status} - {args.host}"
            email_body = compose_notification_body(
                status=run_status,
                host=args.host,
                backup_file=backup_file,
                report_file=report_file if report_file.exists() else None,
                log_file=log_file,
            )
            attachments = [path for path in (backup_file, report_file) if path and path.exists()]
            try:
                send_notification_email(
                    smtp_host=args.smtp_host,
                    smtp_port=args.smtp_port,
                    smtp_username=args.smtp_username,
                    smtp_password=args.smtp_password,
                    smtp_use_tls=args.smtp_use_tls,
                    sender=email_sender,
                    recipient=recipient_email,
                    subject=email_subject,
                    body=email_body,
                    attachments=attachments,
                )
                LOG.info("Notification email sent to %s", recipient_email)
            except Exception as exc:
                LOG.error("Failed to send notification email: %s", exc)

    sys.exit(exit_code)


if __name__ == "__main__":
    main()
