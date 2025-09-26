#!/usr/bin/env python3
"""
fetchSDDCCredentials.py

Fetch credentials from VMware SDDC Manager.

Features
- Prompts for missing inputs (host, username, password, mode)
- Precedence rules:
    1) --all → fetch every credential (ignores name/type)
    2) --resource-name → fetch by name (partial match allowed). Name wins over type
    3) --resource-type → interactive picker (ESXI, NSXT_MANAGER, VCENTER, BACKUP, PSC) then list all of that type
- SSL verification DISABLED by default (for labs). Don't use on untrusted networks
- PrettyTable output; add --show to include password column
- CSV export via --export [optional_filename]. If no filename, auto: <host>_credentials_<YYYYMMDD_HHMMSS>.csv
- Robust response parsing (elements/content/credentials/result/items or list) + pagination via pageMetadata

Requires: requests, prettytable
  pip install requests prettytable
"""

import argparse
import csv
from datetime import datetime
import getpass
import json
import logging
import sys
from typing import Optional, Dict, Any, List

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from prettytable import PrettyTable

# --- defaults ---
RETRIES = 3
BACKOFF_FACTOR = 1.0
TIMEOUT = 30  # seconds
PAGE_SIZE = 200

# --- logging ---
LOG = logging.getLogger("fetch_sddc_credentials")
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s: %(message)s")


# -----------------------------
# HTTP session (SSL verify off by default)
# -----------------------------

def requests_session(retries: int = RETRIES, backoff: float = BACKOFF_FACTOR, verify: bool = False):
    s = requests.Session()
    retry = Retry(
        total=retries,
        backoff_factor=backoff,
        status_forcelist=(429, 500, 502, 503, 504),
        allowed_methods=frozenset(["GET", "POST", "PUT", "DELETE", "PATCH"]),
    )
    s.mount("https://", HTTPAdapter(max_retries=retry))
    s.verify = verify
    if not verify:
        from urllib3.exceptions import InsecureRequestWarning
        import urllib3
        urllib3.disable_warnings(InsecureRequestWarning)
        LOG.warning("⚠️ SSL verification disabled (default). Use only in trusted environments.")
    return s


# -----------------------------
# Auth & API helpers
# -----------------------------

def get_token(session: requests.Session, base_url: str, username: str, password: str) -> str:
    url = f"{base_url.rstrip('/')}/v1/tokens"
    payload = {"username": username, "password": password}
    headers = {"Content-Type": "application/json"}
    r = session.post(url, json=payload, headers=headers, timeout=TIMEOUT)
    if r.status_code != 200:
        raise RuntimeError(f"Failed to get token: HTTP {r.status_code} - {r.text}")
    j = r.json()
    # support multiple shapes
    access = (
        j.get("accessToken")
        or j.get("access_token")
        or (j.get("data") or {}).get("accessToken")
        or (j.get("data") or {}).get("access_token")
        or (j.get("token") or {}).get("accessToken")
    )
    if not access:
        raise RuntimeError(f"Token response missing access token: {j}")
    return access


def _parse_credentials_payload(j: Any) -> List[Dict[str, Any]]:
    """Normalize various SDDC Manager response shapes to a list of credential dicts."""
    if isinstance(j, list):
        return j
    if isinstance(j, dict):
        for key in ("elements", "content", "credentials", "result", "items", "data"):
            v = j.get(key)
            if isinstance(v, list):
                return v
        if any(k in j for k in ("id", "username", "resource")):
            return [j]
    return []


def fetch_credentials_list(
    session: requests.Session,
    base_url: str,
    token: str,
    resource_name: Optional[str] = None,
    resource_type: Optional[str] = None,
    domain_name: Optional[str] = None,
    fetch_all: bool = False,
) -> List[Dict[str, Any]]:
    url = f"{base_url.rstrip('/')}/v1/credentials"
    headers = {"Authorization": f"Bearer {token}", "Accept": "application/json"}

    results: List[Dict[str, Any]] = []
    params: Dict[str, Any] = {"pageSize": PAGE_SIZE, "pageNumber": 0}
    if resource_name:
        params["resourceName"] = resource_name
    if resource_type:
        params["resourceType"] = resource_type
    if domain_name:
        params["domainName"] = domain_name

    while True:
        r = session.get(url, headers=headers, params=params, timeout=TIMEOUT)
        if r.status_code in (401, 403):
            r.raise_for_status()
        r.raise_for_status()
        j = r.json()
        page_items = _parse_credentials_payload(j)
        results.extend(page_items)

        meta = j.get("pageMetadata") if isinstance(j, dict) else None
        if meta and isinstance(meta, dict):
            page_num = meta.get("pageNumber", 0)
            total_pages = meta.get("totalPages", 1)
            if page_num + 1 < total_pages:
                params["pageNumber"] = page_num + 1
                continue
        break

    return results


def fetch_credential_by_id(session: requests.Session, base_url: str, token: str, cred_id: str) -> Dict[str, Any]:
    url = f"{base_url.rstrip('/')}/v1/credentials/{cred_id}"
    headers = {"Authorization": f"Bearer {token}", "Accept": "application/json"}
    r = session.get(url, headers=headers, timeout=TIMEOUT)
    if r.status_code == 404:
        raise KeyError(f"Credential id {cred_id} not found")
    r.raise_for_status()
    return r.json()


# -----------------------------
# CLI & prompts
# -----------------------------

def parse_args():
    p = argparse.ArgumentParser(description="Fetch credentials from VMware SDDC Manager")
    p.add_argument("--host", help="SDDC Manager FQDN or IP")
    p.add_argument("--username", help="Username")
    p.add_argument("--password", help="Password (or prompt if omitted)")
    p.add_argument("--resource-name", help="Resource name (exact or partial; client-side partial match supported)")
    p.add_argument("--resource-type", help="Resource type (optional; ESXI, NSXT_MANAGER, VCENTER, BACKUP, PSC)")
    p.add_argument("--domain-name", help="Domain name filter (optional)")
    p.add_argument("--id", help="Fetch by credential ID")
    p.add_argument("--all", action="store_true", help="Fetch all credentials")
    p.add_argument("--show", action="store_true", help="Include password column in output/CSV")
    p.add_argument("--export", nargs='?', const='__AUTO__', help="Export to CSV; optional filename. If omitted, auto-name: <host>_credentials_<YYYYMMDD_HHMMSS>.csv")
    p.add_argument("--verbose", action="store_true")
    return p.parse_args()


def prompt_missing_args(args):
    def ask(msg, default=None):
        inp = input(f"{msg}{' [' + default + ']' if default else ''}: ").strip()
        return inp if inp else default

    def select_from_list(title: str, options: List[str], default: Optional[str] = None) -> str:
        print(title)
        for i, opt in enumerate(options, 1):
            mark = " (default)" if default and opt.upper() == (default or "").upper() else ""
            print(f"{i}. {opt}{mark}")
        while True:
            choice = ask("Enter choice number", default=str(options.index(default) + 1) if default and default in options else "1")
            try:
                idx = int(choice)
                if 1 <= idx <= len(options):
                    return options[idx - 1]
            except Exception:
                pass
            print("Invalid choice. Try again.")

    allowed_types = ["ESXI", "NSXT_MANAGER", "VCENTER", "BACKUP", "PSC"]

    if not args.host:
        args.host = ask("Enter SDDC Manager FQDN or IP")
    if not args.username:
        args.username = ask("Enter username")
    if not args.password:
        args.password = getpass.getpass("Enter password: ")

    # Precedence: --all > --resource-name > --resource-type
    if args.all:
        return args

    if args.resource_name:
        # Name wins; type will be ignored later
        return args

    if args.resource_type:
        default = args.resource_type.upper()
        if default not in allowed_types:
            default = None
        args.resource_type = select_from_list("Select resource type:", allowed_types, default=default)
        return args

    # Nothing specific given: prompt for mode
    print("Choose fetch mode:\n1. Fetch all\n2. Fetch by ID\n3. Fetch by name\n4. Fetch by type")
    choice = ask("Enter choice", default="1")
    if choice == "1":
        args.all = True
    elif choice == "2":
        args.id = ask("Enter credential ID")
    elif choice == "3":
        args.resource_name = ask("Enter resource name (exact or partial)")
    elif choice == "4":
        args.resource_type = select_from_list("Select resource type:", allowed_types)
    else:
        print("Invalid choice. Defaulting to Fetch all.")
        args.all = True
    return args


# -----------------------------
# Output helpers
# -----------------------------

def _matches_client_side(res_name: str, query: Optional[str]) -> bool:
    if not query:
        return True
    return query.lower() in (res_name or "").lower()


def print_table(results: List[Dict[str, Any]], show_password: bool = False) -> List[str]:
    if not results:
        print("No credentials found.")
        return ["id", "resourceName", "resourceType", "resourceIp", "username", "credentialType", "accountType"] + (["password"] if show_password else [])

    fields = ["id", "resourceName", "resourceType", "resourceIp", "username", "credentialType", "accountType"]
    if show_password:
        fields.append("password")

    table = PrettyTable()
    table.field_names = fields

    for c in results:
        res = c.get("resource") or {}
        row_map = {
            "id": c.get("id", ""),
            "resourceName": res.get("resourceName", ""),
            "resourceType": res.get("resourceType", ""),
            "resourceIp": res.get("resourceIp", ""),
            "username": c.get("username", ""),
            "credentialType": c.get("credentialType", ""),
            "accountType": c.get("accountType", ""),
            "password": c.get("password", "") if show_password else "",
        }
        table.add_row([row_map.get(f, "") for f in fields])

    print(table)
    return fields


def export_csv(host: str, results: List[Dict[str, Any]], fields: List[str], show_password: bool, export_arg: Optional[str]):
    if not export_arg:
        return
    if export_arg == "__AUTO__":
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        fname = f"{host}_credentials_{ts}.csv"
    else:
        fname = export_arg
        if not fname.lower().endswith(".csv"):
            fname += ".csv"

    try:
        with open(fname, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(fields)
            for c in results:
                res = c.get("resource") or {}
                row_map = {
                    "id": c.get("id", ""),
                    "resourceName": res.get("resourceName", ""),
                    "resourceType": res.get("resourceType", ""),
                    "resourceIp": res.get("resourceIp", ""),
                    "username": c.get("username", ""),
                    "credentialType": c.get("credentialType", ""),
                    "accountType": c.get("accountType", ""),
                    "password": c.get("password", "") if show_password else "",
                }
                writer.writerow([row_map.get(col, "") for col in fields])
        LOG.info("Exported %d rows to %s", len(results), fname)
    except Exception as e:
        LOG.error("Failed to export CSV: %s", e)


# -----------------------------
# Main
# -----------------------------

def main():
    args = parse_args()
    args = prompt_missing_args(args)
    if args.verbose:
        LOG.setLevel(logging.DEBUG)

    base_url = f"https://{args.host}"
    session = requests_session(verify=False)

    try:
        token = get_token(session, base_url, args.username, args.password)
    except Exception as e:
        LOG.error("Authentication failed: %s", e)
        sys.exit(2)

    try:
        results: List[Dict[str, Any]] = []

        if args.id:
            results.append(fetch_credential_by_id(session, base_url, token, args.id))
        else:
            # Precedence & effective filters
            effective_type = None if args.all or args.resource_name else (args.resource_type or None)

            server_results = fetch_credentials_list(
                session,
                base_url,
                token,
                resource_name=args.resource_name or None,  # server-side filter if supported
                resource_type=effective_type,
                domain_name=args.domain_name or None,
                fetch_all=args.all,
            )

            # Client-side partial match on resource_name if provided
            if args.resource_name:
                results = [
                    c for c in server_results
                    if _matches_client_side((c.get("resource") or {}).get("resourceName", ""), args.resource_name)
                ]
            else:
                results = server_results

        if not results:
            LOG.warning("No credentials found. Check privileges and resource name spelling (partial match supported).")

        fields = print_table(results, show_password=args.show)
        export_csv(args.host, results, fields, args.show, args.export)

    except Exception as e:
        LOG.error("Failed to fetch credentials: %s", e)
        sys.exit(1)


if __name__ == "__main__":
    main()
