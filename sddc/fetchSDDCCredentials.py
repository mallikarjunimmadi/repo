#!/usr/bin/env python3
"""
fetch_sddc_credentials.py

Fetch credentials from VMware SDDC Manager with full prompts, secure password input,
and SSL verification disabled by default.
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

# --- defaults ---
TOKEN_TTL = 3600
RETRIES = 3
BACKOFF_FACTOR = 1.0
TIMEOUT = 30  # seconds

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
    access = j.get("accessToken") or j.get("access_token")
    if not access and "data" in j:
        access = j["data"].get("accessToken") or j["data"].get("access_token")
    if not access:
        raise RuntimeError(f"Token response missing access token: {j}")
    return access


def fetch_credentials_list(session, base_url, token, resource_name=None, resource_type=None, domain_name=None):
    url = f"{base_url.rstrip('/')}/v1/credentials"
    headers = {"Authorization": f"Bearer {token}", "Accept": "application/json"}
    params: Dict[str, str] = {}
    if resource_name:
        params["resourceName"] = resource_name
    if resource_type:
        params["resourceType"] = resource_type
    if domain_name:
        params["domainName"] = domain_name
    r = session.get(url, headers=headers, params=params, timeout=TIMEOUT)
    if r.status_code == 401:
        raise RuntimeError("Unauthorized (401) - token may be invalid or insufficient privileges")
    if r.status_code == 403:
        raise RuntimeError("Forbidden (403) - insufficient role privileges")
    r.raise_for_status()
    j = r.json()
    if isinstance(j, dict):
        return j.get("content") or j.get("credentials") or j.get("result") or []
    elif isinstance(j, list):
        return j
    raise RuntimeError("Unexpected credentials response format")


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
    p.add_argument("--resource-name", help="Resource name")
    p.add_argument("--resource-type", help="Resource type (optional)")
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
            args.resource_name = ask("Enter resource name")
    return args


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
        results = []
        if args.id:
            results.append(fetch_credential_by_id(session, base_url, token, args.id))
        else:
            creds = fetch_credentials_list(session, base_url, token,
                                           resource_name=args.resource_name or None,
                                           resource_type=args.resource_type or None)
            results.extend(creds)

        output = []
        for c in results:
            safe = {k: c.get(k) for k in ("id", "username", "credentialType", "accountType",
                                          "resource", "creationTimestamp", "modificationTimestamp")}
            if args.show:
                try:
                    if not c.get("password") and c.get("id"):
                        full = fetch_credential_by_id(session, base_url, token, c["id"])
                        safe.update(full)
                    else:
                        safe.update(c)
                except Exception as e:
                    LOG.warning("Could not fetch full credential for id=%s: %s", c.get("id"), e)
            output.append(safe)

        print(json.dumps(output, indent=2))

    except Exception as e:
        LOG.error("Failed to fetch credentials: %s", e)
        sys.exit(1)


if __name__ == "__main__":
    main()
