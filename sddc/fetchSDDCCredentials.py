#!/usr/bin/env python3
"""
fetch_sddc_credentials.py

Fetch credentials from VMware SDDC Manager.

Usage examples
--------------
# get a single resource by name:
python fetch_sddc_credentials.py --host sddc-mgr.example.com --username administrator@vsphere.local --resource-name "sfo-vcenter"

# fetch all credentials (ADMIN role required):
python fetch_sddc_credentials.py --host sddc-mgr.example.com --username admin@local --all --show

Security notes
--------------
- By default the script will NOT print secret passwords. Use --show only on a secure terminal.
- API caller must have appropriate privileges (ADMIN for password management APIs).
- Use --insecure only for labs (disables SSL verification).
"""

from __future__ import annotations
import argparse
import getpass
import json
import logging
import sys
import time
from typing import Optional, Dict, Any, List

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# --- defaults ---
TOKEN_TTL = 3600
RETRIES = 3
BACKOFF_FACTOR = 1.0
TIMEOUT = 30  # seconds

# --- logging ---
LOG = logging.getLogger("fetch_sddc_credentials")
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s: %(message)s")


def requests_session(retries: int = RETRIES, backoff: float = BACKOFF_FACTOR, verify: bool = True):
    s = requests.Session()
    retry = Retry(total=retries,
                  backoff_factor=backoff,
                  status_forcelist=(429, 500, 502, 503, 504),
                  allowed_methods=frozenset(["GET", "POST", "PUT", "DELETE", "PATCH"]))
    s.mount("https://", HTTPAdapter(max_retries=retry))
    s.verify = verify
    return s


def get_token(session: requests.Session, base_url: str, username: str, password: str) -> str:
    """
    Create a token pair using POST /v1/tokens and return access token.
    See SDDC Manager Token API docs for details.
    """
    url = f"{base_url.rstrip('/')}/v1/tokens"
    payload = {"username": username, "password": password}
    headers = {"Content-Type": "application/json"}
    LOG.debug("Requesting token from %s", url)
    r = session.post(url, json=payload, headers=headers, timeout=TIMEOUT)
    if r.status_code != 200:
        raise RuntimeError(f"Failed to get token: HTTP {r.status_code} - {r.text}")
    j = r.json()
    # API returns an object containing accessToken / refreshToken (docs vary slightly by version)
    access = j.get("accessToken") or j.get("access_token") or (j.get("token") and j["token"].get("accessToken"))
    if not access:
        # try nested keys sometimes used
        if "data" in j and isinstance(j["data"], dict):
            access = j["data"].get("accessToken") or j["data"].get("access_token")
    if not access:
        raise RuntimeError(f"Token response missing access token: {j}")
    LOG.debug("Got access token (len=%d)", len(access))
    return access


def fetch_credentials_list(session: requests.Session, base_url: str, token: str,
                           resource_name: Optional[str] = None,
                           resource_type: Optional[str] = None,
                           domain_name: Optional[str] = None) -> List[Dict[str, Any]]:
    """
    GET /v1/credentials with optional query params resourceName, resourceType, domainName
    Returns a list of credential objects (may contain username, and possibly password field)
    """
    url = f"{base_url.rstrip('/')}/v1/credentials"
    headers = {"Authorization": f"Bearer {token}", "Accept": "application/json"}
    params: Dict[str, str] = {}
    if resource_name:
        params["resourceName"] = resource_name
    if resource_type:
        params["resourceType"] = resource_type
    if domain_name:
        params["domainName"] = domain_name
    LOG.debug("Fetching credentials list: %s params=%s", url, params)
    r = session.get(url, headers=headers, params=params, timeout=TIMEOUT)
    if r.status_code == 401:
        raise RuntimeError("Unauthorized (401) - token may be invalid/expired or insufficient privileges")
    if r.status_code == 403:
        raise RuntimeError("Forbidden (403) - insufficient role privileges (ADMIN required for some ops)")
    r.raise_for_status()
    # Response typically: { "content": [ {credential...}, ... ], "totalElements": n, ... } OR directly a list depending on version
    j = r.json()
    if isinstance(j, dict):
        # some API versions wrap in 'content'
        if "content" in j and isinstance(j["content"], list):
            return j["content"]
        # other versions return list under 'credentials' or 'result' - try to sensibly pick
        for key in ("credentials", "result", "data", "items"):
            if isinstance(j.get(key), list):
                return j.get(key)
        # fallback: if dict seems like single credential, return as single-item list
        if any(k in j for k in ("id", "username", "resource")):
            return [j]
        # unknown wrap -> attempt to find lists inside
        for v in j.values():
            if isinstance(v, list):
                return v
        raise RuntimeError(f"Unexpected credentials payload shape: {j}")
    elif isinstance(j, list):
        return j
    else:
        raise RuntimeError("Unexpected response type for credentials list")


def fetch_credential_by_id(session: requests.Session, base_url: str, token: str, cred_id: str) -> Dict[str, Any]:
    """
    GET /v1/credentials/{id} - returns full credential object incl. (optionally) password
    """
    url = f"{base_url.rstrip('/')}/v1/credentials/{cred_id}"
    headers = {"Authorization": f"Bearer {token}", "Accept": "application/json"}
    r = session.get(url, headers=headers, timeout=TIMEOUT)
    if r.status_code == 404:
        raise KeyError(f"Credential id {cred_id} not found")
    r.raise_for_status()
    return r.json()


def parse_args():
    p = argparse.ArgumentParser(description="Fetch credentials from VMware SDDC Manager")
    p.add_argument("--host", required=True, help="SDDC Manager FQDN or IP (e.g. sddc-mgr.example.com)")
    p.add_argument("--username", required=True, help="Username (e.g. administrator@vsphere.local or admin@local)")
    p.add_argument("--password", help="Password (if omitted, you will be prompted)")
    p.add_argument("--resource-name", help="Resource name to fetch (resourceName query param)")
    p.add_argument("--resource-type", help="Resource type (e.g. VCENTER, NSXT_MANAGER, ESXI, BACKUP)")
    p.add_argument("--id", help="Fetch a single credential by credential id (/v1/credentials/{id})")
    p.add_argument("--all", action="store_true", help="Fetch all credentials (requires ADMIN role; can be large)")
    p.add_argument("--show", action="store_true", help="Show secret fields (password) in output (DANGEROUS!)")
    p.add_argument("--insecure", action="store_true", help="Disable SSL verification (for lab only)")
    p.add_argument("--verbose", action="store_true", help="Verbose logging")
    return p.parse_args()


def main():
    args = parse_args()
    if args.verbose:
        LOG.setLevel(logging.DEBUG)

    base_url = f"https://{args.host}"
    password = args.password or getpass.getpass("SDDC Manager password: ")

    session = requests_session(verify=not args.insecure)

    try:
        token = get_token(session, base_url, args.username, password)
    except Exception as e:
        LOG.error("Authentication failed: %s", e)
        sys.exit(2)

    try:
        results = []
        if args.id:
            # fetch specific credential by id
            cred = fetch_credential_by_id(session, base_url, token, args.id)
            results.append(cred)
        else:
            if not args.all and not args.resource_name and not args.resource_type:
                LOG.error("Either --id, --resource-name/--resource-type, or --all must be provided")
                sys.exit(2)
            if args.all:
                creds = fetch_credentials_list(session, base_url, token)
            else:
                creds = fetch_credentials_list(session, base_url, token,
                                               resource_name=args.resource_name,
                                               resource_type=args.resource_type)
            # creds is a list
            results.extend(creds)

        # By default, avoid printing sensitive fields; show summary
        safe_output = []
        for c in results:
            # common fields: id, username, resource, credentialType, accountType, creationTimestamp
            safe_fields = {k: c.get(k) for k in ("id", "username", "credentialType", "accountType", "resource", "creationTimestamp", "modificationTimestamp")}
            # if user wants full detail including password, fetch by id if necessary (some list endpoints omit password)
            if args.show:
                try:
                    if not c.get("password") and c.get("id"):
                        LOG.debug("Fetching full credential for id %s to reveal password", c["id"])
                        full = fetch_credential_by_id(session, base_url, token, c["id"])
                        safe_fields.update(full)
                    else:
                        safe_fields.update(c)
                except Exception as e:
                    LOG.warning("Could not fetch full credential for %s: %s", c.get("id") or c.get("resource"), e)
            safe_output.append(safe_fields)

        # print JSON result
        print(json.dumps(safe_output, indent=2, default=str))

    except Exception as e:
        LOG.error("Failed to fetch credentials: %s", e)
        sys.exit(1)


if __name__ == "__main__":
    main()
