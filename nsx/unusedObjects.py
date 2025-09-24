#!/usr/bin/env python3
# nsx_objects_where_used.py
#
# Inventory NSX-T Services and Groups; report where each is used (DFW/GW-FW rules).
# Excludes system-owned/system-created Services & Groups by default.
# Outputs auto-prefixed with the NSX host (FQDN/IP):
#   <host>_services_usage.csv
#   <host>_services_unused.csv
#   <host>_groups_usage.csv
#   <host>_groups_unused.csv
#
# Requirements: Python 3.8+, requests
#   pip install requests

import argparse
import csv
import getpass
import logging
from logging.handlers import RotatingFileHandler
import random
import sys
import time
from typing import Dict, List, Tuple, Optional

import requests

# -----------------------------
# Logging
# -----------------------------

def setup_logging(log_file: Optional[str], level: str = "INFO") -> None:
    logger = logging.getLogger()
    logger.setLevel(getattr(logging, level.upper(), logging.INFO))
    fmt = logging.Formatter(
        "%(asctime)s.%(msecs)03d %(levelname)-8s %(name)s %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    ch = logging.StreamHandler(sys.stdout)
    ch.setFormatter(fmt)
    logger.addHandler(ch)
    if log_file:
        fh = RotatingFileHandler(log_file, maxBytes=10 * 1024 * 1024, backupCount=5)
        fh.setFormatter(fmt)
        logger.addHandler(fh)

# -----------------------------
# Utilities
# -----------------------------

SYSTEM_BOOL_FLAGS = (
    "is_default",
    "is_policy_default",
    "system_owned",
    "is_system_owned",
    "predefined",
    "read_only",
    "is_readonly",
    "is_internal",
    "is_protected",
)

def bool_from_str(s: str) -> bool:
    return str(s).strip().lower() in ("1","true","t","yes","y","on")

def is_group_path(s: str) -> bool:
    return isinstance(s, str) and "/infra/domains/" in s and "/groups/" in s

def ensure_value(v: Optional[str], prompt_text: str, secret: bool = False) -> str:
    """Prompt until a non-empty value is provided. Uses getpass for secrets."""
    if v and v.strip():
        return v.strip()
    while True:
        entered = getpass.getpass(prompt_text) if secret else input(prompt_text)
        if entered and entered.strip():
            return entered.strip()

def is_system_object(obj: dict) -> Tuple[bool, List[str]]:
    """Return (is_system, reasons[]) based on common system flags across NSX versions."""
    reasons = [k for k in SYSTEM_BOOL_FLAGS if isinstance(obj.get(k), bool) and obj[k]]
    return (len(reasons) > 0, reasons)

# -----------------------------
# NSX Client (retries, backoff)
# -----------------------------

class NSXClient:
    def __init__(
        self,
        host: str,              # FQDN/IP (no scheme)
        username: str,
        password: str,
        verify_ssl: bool = False,  # default false
        timeout: int = 30,
        max_retries: int = 3,
        backoff: float = 1.5,
        jitter: float = 0.25,
    ):
        # Always https
        self.base = f"https://{host.strip()}"
        self.host = host.strip()
        self.verify = verify_ssl
        self.timeout = timeout
        self.max_retries = max_retries
        self.backoff = backoff
        self.jitter = jitter

        self.session = requests.Session()
        self.session.auth = (username, password)
        self.session.headers.update({"Accept": "application/json"})

        if not verify_ssl:
            requests.packages.urllib3.disable_warnings(
                category=requests.packages.urllib3.exceptions.InsecureRequestWarning
            )

        self.log = logging.getLogger(self.__class__.__name__)

    def _sleep_backoff(self, attempt: int) -> None:
        delay = (self.backoff ** attempt) + random.uniform(0, self.jitter)
        time.sleep(delay)

    def _req(self, method: str, path: str, params=None) -> dict:
        url = f"{self.base}{path}"
        attempt = 0
        while True:
            try:
                self.log.debug("HTTP %s %s params=%s", method, url, params)
                r = self.session.request(
                    method, url, params=params, timeout=self.timeout, verify=self.verify
                )
                if r.status_code == 401:
                    raise RuntimeError("Unauthorized (401). Check credentials/RBAC.")
                if r.status_code == 404:
                    self.log.debug("HTTP 404 for %s %s (returning empty {})", method, path)
                    return {}
                r.raise_for_status()
                return r.json() if r.text.strip() else {}
            except (requests.ConnectionError, requests.Timeout) as e:
                attempt += 1
                self.log.warning(
                    "Transient HTTP error on %s %s: %s (attempt %d/%d)",
                    method, path, e, attempt, self.max_retries
                )
                if attempt > self.max_retries:
                    raise
                self._sleep_backoff(attempt)
            except requests.HTTPError as e:
                self.log.error("HTTP error on %s %s: %s", method, path, e)
                raise

    def paged_get_all(self, path: str, params=None, items_key="results") -> List[dict]:
        items: List[dict] = []
        cursor = None
        while True:
            p = dict(params or {})
            if cursor:
                p["cursor"] = cursor
            data = self._req("GET", path, params=p)
            page_items = data.get(items_key, [])
            items.extend(page_items)
            cursor = data.get("cursor")
            self.log.debug("Collected %d items (total %d) from %s", len(page_items), len(items), path)
            if not cursor:
                break
        return items

# -----------------------------
# Collectors (with system filtering)
# -----------------------------

def list_services(nsx: NSXClient, exclude_system: bool) -> Dict[str, dict]:
    svcs = nsx.paged_get_all("/policy/api/v1/infra/services")
    out: Dict[str, dict] = {}
    sys_excluded = 0
    for s in svcs:
        path = s.get("path")
        if not path:
            continue
        if exclude_system:
            is_sys, reasons = is_system_object(s)
            if is_sys:
                sys_excluded += 1
                logging.debug("Excluding system Service id=%s name=%s reasons=%s",
                              s.get("id"), s.get("display_name"), ",".join(reasons))
                continue
        out[path] = s
    logging.info("Discovered %d Services (excluded %d system-owned)", len(out), sys_excluded)
    return out

def list_domains(nsx: NSXClient) -> List[dict]:
    domains = nsx.paged_get_all("/policy/api/v1/infra/domains")
    logging.info("Discovered %d Domains", len(domains))
    return domains

def list_groups_for_domain(nsx: NSXClient, domain_id: str, exclude_system: bool) -> Dict[str, dict]:
    groups = nsx.paged_get_all(f"/policy/api/v1/infra/domains/{domain_id}/groups")
    m: Dict[str, dict] = {}
    sys_excluded = 0
    for g in groups:
        path = g.get("path")
        if not path:
            continue
        if exclude_system:
            is_sys, reasons = is_system_object(g)
            if is_sys:
                sys_excluded += 1
                logging.debug("Excluding system Group id=%s name=%s domain=%s reasons=%s",
                              g.get("id"), g.get("display_name"), domain_id, ",".join(reasons))
                continue
        m[path] = g
    logging.info("Domain '%s': %d Groups (excluded %d system-owned)", domain_id, len(m), sys_excluded)
    return m

def list_security_policies(nsx: NSXClient, domain_id: str) -> List[dict]:
    return nsx.paged_get_all(f"/policy/api/v1/infra/domains/{domain_id}/security-policies")

def list_sp_rules(nsx: NSXClient, domain_id: str, policy_id: str) -> List[dict]:
    return nsx.paged_get_all(f"/policy/api/v1/infra/domains/{domain_id}/security-policies/{policy_id}/rules")

def list_t0s(nsx: NSXClient) -> List[dict]:
    t0s = nsx.paged_get_all("/policy/api/v1/infra/tier-0s")
    logging.info("Discovered %d Tier-0s", len(t0s))
    return t0s

def list_t1s(nsx: NSXClient) -> List[dict]:
    t1s = nsx.paged_get_all("/policy/api/v1/infra/tier-1s")
    logging.info("Discovered %d Tier-1s", len(t1s))
    return t1s

def list_gateway_policies_for_t0(nsx: NSXClient, t0_id: str) -> List[dict]:
    return nsx.paged_get_all(f"/policy/api/v1/infra/tier-0s/{t0_id}/gateway-policies")

def list_gateway_policies_for_t1(nsx: NSXClient, t1_id: str) -> List[dict]:
    return nsx.paged_get_all(f"/policy/api/v1/infra/tier-1s/{t1_id}/gateway-policies")

def list_gp_rules(nsx: NSXClient, base_path: str, policy_id: str) -> List[dict]:
    return nsx.paged_get_all(f"{base_path}/{policy_id}/rules")

# -----------------------------
# Index where-used
# -----------------------------

def index_dfw_usage(nsx: NSXClient):
    svc_hits = []
    grp_hits = []
    for d in list_domains(nsx):
        did = d.get("id")
        if not did:
            continue
        for pol in list_security_policies(nsx, did):
            pid = pol.get("id")
            if not pid:
                continue
            rules = list_sp_rules(nsx, did, pid)
            for rule in rules:
                if rule.get("services"):
                    svc_hits.append((did, pid, rule))
                if rule.get("source_groups") or rule.get("destination_groups") or rule.get("scope"):
                    grp_hits.append((did, pid, rule))
    logging.info("DFW: %d rules with Services, %d rules with Group refs", len(svc_hits), len(grp_hits))
    return svc_hits, grp_hits

def index_gwfw_usage(nsx: NSXClient):
    svc_hits = []
    grp_hits = []

    for t0 in list_t0s(nsx):
        t0id = t0.get("id")
        if not t0id:
            continue
        base = f"/policy/api/v1/infra/tier-0s/{t0id}/gateway-policies"
        for pol in list_gateway_policies_for_t0(nsx, t0id):
            pid = pol.get("id")
            if not pid:
                continue
            for rule in list_gp_rules(nsx, base, pid):
                if rule.get("services"):
                    svc_hits.append(("tier-0", t0id, pid, rule))
                if rule.get("source_groups") or rule.get("destination_groups") or rule.get("scope"):
                    grp_hits.append(("tier-0", t0id, pid, rule))

    for t1 in list_t1s(nsx):
        t1id = t1.get("id")
        if not t1id:
            continue
        base = f"/policy/api/v1/infra/tier-1s/{t1id}/gateway-policies"
        for pol in list_gateway_policies_for_t1(nsx, t1id):
            pid = pol.get("id")
            if not pid:
                continue
            for rule in list_gp_rules(nsx, base, pid):
                if rule.get("services"):
                    svc_hits.append(("tier-1", t1id, pid, rule))
                if rule.get("source_groups") or rule.get("destination_groups") or rule.get("scope"):
                    grp_hits.append(("tier-1", t1id, pid, rule))

    logging.info("GW-FW: %d rules with Services, %d rules with Group refs", len(svc_hits), len(grp_hits))
    return svc_hits, grp_hits

# -----------------------------
# Reports
# -----------------------------

def summarize_service_entry(entry: dict):
    proto = entry.get("l4_protocol") or entry.get("protocol") or ""
    ports_list = entry.get("destination_ports") or entry.get("ports") or []
    ports = ",".join(ports_list) if isinstance(ports_list, list) else str(ports_list)
    return proto, ports

def build_reports(nsx: NSXClient, out_prefix: str, exclude_system: bool):
    # Services (optionally excluding system)
    services_by_path = list_services(nsx, exclude_system=exclude_system)

    # Groups (optionally excluding system) across all domains
    groups_by_path: Dict[str, dict] = {}
    domains = list_domains(nsx)
    for d in domains:
        did = d.get("id")
        if not did:
            continue
        groups_by_path.update(list_groups_for_domain(nsx, did, exclude_system=exclude_system))
    logging.info("Total Groups across all domains (after filtering): %d", len(groups_by_path))

    # Initialize usage indexes
    svc_usage: Dict[str, List[str]] = {p: [] for p in services_by_path.keys()}
    grp_usage: Dict[str, List[str]] = {p: [] for p in groups_by_path.keys()}

    # DFW references
    dfw_svc_hits, dfw_grp_hits = index_dfw_usage(nsx)
    for (domain_id, policy_id, rule) in dfw_svc_hits:
        rid = rule.get("id") or rule.get("display_name") or "<unnamed>"
        for sp in (rule.get("services") or []):
            if sp in svc_usage:
                svc_usage[sp].append(f"DFW: domain={domain_id}, policy={policy_id}, rule={rid}")

    for (domain_id, policy_id, rule) in dfw_grp_hits:
        rid = rule.get("id") or rule.get("display_name") or "<unnamed>"
        for gp in (rule.get("source_groups") or []):
            if gp in grp_usage:
                grp_usage[gp].append(f"DFW(SRC): domain={domain_id}, policy={policy_id}, rule={rid}")
        for gp in (rule.get("destination_groups") or []):
            if gp in grp_usage:
                grp_usage[gp].append(f"DFW(DST): domain={domain_id}, policy={policy_id}, rule={rid}")
        for sc in (rule.get("scope") or []):
            if is_group_path(sc) and sc in grp_usage:
                grp_usage[sc].append(f"DFW(SCOPE): domain={domain_id}, policy={policy_id}, rule={rid}")

    # Gateway FW references
    gw_svc_hits, gw_grp_hits = index_gwfw_usage(nsx)
    for (tier, tier_id, policy_id, rule) in gw_svc_hits:
        rid = rule.get("id") or rule.get("display_name") or "<unnamed>"
        for sp in (rule.get("services") or []):
            if sp in svc_usage:
                svc_usage[sp].append(f"{tier.upper()} FW: {tier_id}, policy={policy_id}, rule={rid}")

    for (tier, tier_id, policy_id, rule) in gw_grp_hits:
        rid = rule.get("id") or rule.get("display_name") or "<unnamed>"
        for gp in (rule.get("source_groups") or []):
            if gp in grp_usage:
                grp_usage[gp].append(f"{tier.upper()} FW(SRC): {tier_id}, policy={policy_id}, rule={rid}")
        for gp in (rule.get("destination_groups") or []):
            if gp in grp_usage:
                grp_usage[gp].append(f"{tier.upper()} FW(DST): {tier_id}, policy={policy_id}, rule={rid}")
        for sc in (rule.get("scope") or []):
            if is_group_path(sc) and sc in grp_usage:
                grp_usage[sc].append(f"{tier.upper()} FW(SCOPE): {tier_id}, policy={policy_id}, rule={rid}")

    # Services reports
    services_usage_csv = f"{out_prefix}_services_usage.csv"
    with open(services_usage_csv, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["service_name", "service_id", "service_path", "entry_count", "l4_app_protocol", "ports", "used_in_count", "used_in"])
        for sp, svc in services_by_path.items():
            name = svc.get("display_name") or svc.get("id") or ""
            sid  = svc.get("id") or ""
            entries = svc.get("service_entries", []) or []
            entry_count = len(entries)
            proto, ports = ("","")
            if entries and isinstance(entries[0], dict):
                proto, ports = summarize_service_entry(entries[0])
            refs = svc_usage.get(sp, [])
            w.writerow([name, sid, sp, entry_count, proto, ports, len(refs), " | ".join(refs)])

    services_unused_csv = f"{out_prefix}_services_unused.csv"
    with open(services_unused_csv, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["service_name", "service_id", "service_path", "entry_count", "l4_app_protocol", "ports"])
        for sp, svc in services_by_path.items():
            refs = svc_usage.get(sp, [])
            if not refs:
                name = svc.get("display_name") or svc.get("id") or ""
                sid  = svc.get("id") or ""
                entries = svc.get("service_entries", []) or []
                entry_count = len(entries)
                proto, ports = ("","")
                if entries and isinstance(entries[0], dict):
                    proto, ports = summarize_service_entry(entries[0])
                w.writerow([name, sid, sp, entry_count, proto, ports])

    # Groups reports
    groups_usage_csv = f"{out_prefix}_groups_usage.csv"
    with open(groups_usage_csv, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["group_name", "group_id", "group_path", "used_in_count", "used_in"])
        for gp, grp in groups_by_path.items():
            name = grp.get("display_name") or grp.get("id") or ""
            gid  = grp.get("id") or ""
            refs = grp_usage.get(gp, [])
            w.writerow([name, gid, gp, len(refs), " | ".join(refs)])

    groups_unused_csv = f"{out_prefix}_groups_unused.csv"
    with open(groups_unused_csv, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["group_name", "group_id", "group_path"])
        for gp, grp in groups_by_path.items():
            refs = grp_usage.get(gp, [])
            if not refs:
                name = grp.get("display_name") or grp.get("id") or ""
                gid  = grp.get("id") or ""
                w.writerow([name, gid, gp])

    return services_usage_csv, services_unused_csv, groups_usage_csv, groups_unused_csv

# -----------------------------
# CLI
# -----------------------------

def main():
    ap = argparse.ArgumentParser(description="NSX-T: List Services & Groups and where they are used (DFW/GW-FW).")
    # Accept only host/FQDN/IP (no scheme)
    ap.add_argument("--nsx", help="NSX Manager FQDN or IP (no scheme), e.g. nsx01.acme.local")
    ap.add_argument("--user", help="Username")
    ap.add_argument("--password", help="Password (omit for secure prompt)")
    ap.add_argument("--verify-ssl", default="false", help="Verify SSL certificates (true/false). Default false.")
    ap.add_argument("--exclude-system", default="true", help="Exclude system-owned/system-created Services and Groups (true/false). Default true.")
    ap.add_argument("--out-prefix", default=None, help="Output filename prefix. Default = NSX host")
    ap.add_argument("--timeout", type=int, default=30, help="HTTP timeout seconds (default 30)")
    ap.add_argument("--retries", type=int, default=3, help="Max retries on transient errors (default 3)")
    ap.add_argument("--backoff", type=float, default=1.5, help="Exponential backoff base (default 1.5)")
    ap.add_argument("--jitter", type=float, default=0.25, help="Random jitter seconds added to backoff (default 0.25)")
    ap.add_argument("--log-file", default=None, help="Path to log file (rotating, 10MB x 5)")
    ap.add_argument("--log-level", default="INFO", help="Log level (DEBUG, INFO, WARNING, ERROR)")
    args = ap.parse_args()

    # Logging first
    setup_logging(args.log_file, args.log_level)

    # Prompt for any missing critical inputs
    nsx_host = ensure_value(args.nsx,    "NSX Manager FQDN/IP: ", secret=False)
    username = ensure_value(args.user,   "Username: ",            secret=False)
    password = ensure_value(args.password, "Password: ",         secret=True)

    verify_ssl = bool_from_str(args.verify_ssl)
    exclude_system = bool_from_str(args.exclude_system)
    out_prefix = args.out_prefix or nsx_host

    logging.info("Starting where-used scan: nsx_host=%s verify_ssl=%s exclude_system=%s prefix=%s",
                 nsx_host, verify_ssl, exclude_system, out_prefix)

    nsx = NSXClient(
        host=nsx_host,                 # always host only
        username=username,
        password=password,             # captured via getpass if missing
        verify_ssl=verify_ssl,         # FALSE by default
        timeout=args.timeout,
        max_retries=args.retries,
        backoff=args.backoff,
        jitter=args.jitter,
    )

    try:
        s_usage, s_unused, g_usage, g_unused = build_reports(nsx, out_prefix, exclude_system=exclude_system)
    except Exception as e:
        logging.exception("Fatal error during report generation: %s", e)
        sys.exit(2)

    logging.info("Wrote: %s", s_usage)
    logging.info("Wrote: %s", s_unused)
    logging.info("Wrote: %s", g_usage)
    logging.info("Wrote: %s", g_unused)
    print(f"[OK] Wrote:\n  {s_usage}\n  {s_unused}\n  {g_usage}\n  {g_unused}")

if __name__ == "__main__":
    main()
