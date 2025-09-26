#!/usr/bin/env python3
"""
fetch_sddc_credentials.py

Fetch credentials from VMware SDDC Manager with full prompts, secure password input,
SSL verification disabled by default, robust response parsing (supports `elements` + pagination),
and PrettyTable output.
"""

import argparse
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
PAGE_SIZE = 200  # ask for many per page to minimize round-trips

# --- logging ---
LOG = logging.getLogger("fetch_sddc_credentials")
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s: %(message)s")


def requests_session(retries: int = RETRIES, backoff: float = BACKOFF_FACTOR, verify: bool = False):
    s = requests.Session()
    retry = Retry(total=retries,
                  backoff_factor=backoff,
                  status_forcelist=(429, 500, 502, 503, 504),
                  allowed_methods=frozenset(["GET", "POST", "PUT", "DELETE", "PATCH"]))
    s.mount("https://", HTTPAdapter(max_retries=retry))
    s.verify = verify
    if not verify:
        from urllib3.exceptions import InsecureRequestWarning
        import urllib3
        urllib3.disable_warnings(InsecureRequestWarning)
        LOG.warning("\u26a0\ufe0f SSL verification disabled (default). Use only in trusted environments.")
    return s


def get_token(session: requests.Session, base_url: str, username: str, password: str) -> str:
    url = f"{base_url.rstrip('/')}/v1/tokens"
    payload = {"username": username, "password": password}
    headers = {"Content-Type": "application/json"}
    r = session.post(url, json=payload, headers=headers, timeout=TIMEOUT)
    if r.status_code != 200:
        raise RuntimeError(f"Failed to get token: HTTP {r.status_code} - {r.text}")
    j = r.json()
    # support different shapes
    access = (j.get("accessToken") or j.get("access_token") or
              (j.get("data") or {}).get("accessToken") or (j.get("data") or {}).get("access_token") or
              ((j.get("token") or {}).get("accessToken")))
    if not access:
        raise RuntimeError(f"Token response missing access token: {j}")
    return access


def _parse_credentials_payload(j: Any) -> List[Dict[str, Any]]:
    """Handle various SDDC Manager response shapes.
    Known shapes:
      {"elements": [...], "pageMetadata": {...}}
      {"content": [...]}
      {"credentials": [...]}
      {"result": [...]}
      [...]
    """
    if isinstance(j, list):
        return j
    if isinstance(j, dict):
        for key in ("elements", "content", "credentials", "result", "items", "data"):
            v = j.get(key)
            if isinstance(v, list):
                return v
        # sometimes a single credential dict might be returned
        if any(k in j for k in ("id", "username", "resource")):
            return [j]
    return []


def fetch_credentials_list(session, base_url, token, resource_name: Optional[str] = None,
                            resource_type: Optional[str] = None, domain_name: Optional[str] = None,
                            fetch_all: bool = False) -> List[Dict[str, Any]]:
    url = f"{base_url.rstrip('/')}/v1/credentials"
    headers = {"Authorization": f"Bearer {token}", "Accept": "application/json"}

    results: List[Dict[str, Any]] = []

    # Server-side filters (if supported). resourceType is optional; resourceName alone is allowed.
    params: Dict[str, Any] = {"pageSize": PAGE_SIZE, "pageNumber": 0}
    if resource_name:
        params["resourceName"] = resource_name
    if resource_type:
        params["resourceType"] = resource_type
    if domain_name:
        params["domainName"] = domain_name

    # If fetch_all or resource_name not supplied, paginate until all pages consumed.
    while True:
        r = session.get(url, headers=headers, params=params, timeout=TIMEOUT)
        if r.status_code in (401, 403):
            r.raise_for_status()
        r.raise_for_status()
        j = r.json()
        page_items = _parse_credentials_payload(j)
        results.extend(page_items)

        # handle pagination via pageMetadata
        meta = j.get("pageMetadata") if isinstance(j, dict) else None
        if meta and isinstance(meta, dict):
            page_num = meta.get("pageNumber", 0)
            total_pages = meta.get("totalPages", 1)
            if page_num + 1 < total_pages:
                params["pageNumber"] = page_num + 1
                continue
        break

    return results


def fetch_credential_by_id(session, base_url, token, cred_id):
    url = f"{base_url.rstrip('/')}/v1/credentials/{cred_id}"
    headers = {"Authorization": f"Bearer {token}", "Accept": "application/json"}
    r = session.get(url, headers=headers, timeout=TIMEOUT)
    if r.status_code == 404:
        raise KeyError(f"Credential id {cred_id} not found")
    r.raise_for_status()
    return r.json()


def parse_args():
    p = argparse.ArgumentParser(description="Fetch credentials from VMware SDDC Manager")
    p.add_argument("--host", help="SDDC Manager FQDN or IP")
    p.add_argument("--username", help="Username")
    p.add_argument("--password", help="Password (or prompt if omitted)")
    p.add_argument("--resource-name", help="Resource name (exact or partial; client-side partial filter supported)")
    p.add_argument("--resource-type", help="Resource type (optional, e.g. VCENTER, NSXT_MANAGER, ESXI, BACKUP)")
    p.add_argument("--domain-name", help="Domain name filter (optional)")
    p.add_argument("--id", help="Fetch by credential ID")
    p.add_argument("--all", action="store_true", help="Fetch all credentials")
    p.add_argument("--show", action="store_true", help="Show passwords")
    p.add_argument("--verbose", action="store_true")
    return p.parse_args()


def prompt_missing_args(args):
    def ask(msg, default=None):
        inp = input(f"{msg}{' [' + default + ']' if default else ''}: ").strip()
        return inp if inp else default

    if not args.host:
        args.host = ask("Enter SDDC Manager FQDN or IP")
    if not args.username:
        args.username = ask("Enter username")
    if not args.password:
        args.password = getpass.getpass("Enter password: ")
    if not (args.all or args.id or args.resource_name):
        print("Choose fetch mode:\n1. Fetch all\n2. Fetch by ID\n3. Fetch by name")
        choice = ask("Enter choice", default="1")
        if choice == "1":
            args.all = True
        elif choice == "2":
            args.id = ask("Enter credential ID")
        elif choice == "3":
            args.resource_name = ask("Enter resource name (exact or partial)")
    return args


def _matches_client_side(res_name: str, query: Optional[str]) -> bool:
    if not query:
        return True
    return query.lower() in (res_name or "").lower()


def print_table(results: List[Dict[str, Any]], show_password=False):
    if not results:
        print("No credentials found.")
        return

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
            # Server-side filters first (if resource_name is provided, still send it; we'll also client-filter for partials)
            server_results = fetch_credentials_list(
                session,
                base_url,
                token,
                resource_name=args.resource_name or None,
                resource_type=args.resource_type or None,
                domain_name=args.domain_name or None,
                fetch_all=args.all,
            )
            # Client-side partial match on resource_name if provided
            if args.resource_name:
                results = [c for c in server_results if _matches_client_side((c.get("resource") or {}).get("resourceName", ""), args.resource_name)]
            else:
                results = server_results

        if not results:
            LOG.warning("No credentials found. Check privileges and resource name spelling (supports partial match).")

        print_table(results, show_password=args.show)

    except Exception as e:
        LOG.error("Failed to fetch credentials: %s", e)
        sys.exit(1)


if __name__ == "__main__":
    main()
