#!/usr/bin/env python3
# nsx_objects_where_used.py
#
# Inventory NSX-T Services and Groups; report where each is used (DFW/GW-FW rules).
# Includes an "empty groups (by expression)" report.
#
# Key features:
# - Pass only FQDN/IP (no scheme); script uses https://<host>
# - Prompts for missing nsx/user/password (password via secure getpass)
# - verify-ssl default false
# - Excludes system-owned Services/Groups by default (configurable)
# - Per-object GETs to read authoritative system flags
# - Multithreaded (default 5, configurable 1–10)
# - Retry with fixed sleep (default 2s) + exponential backoff + jitter
#
# Outputs (auto-prefixed by host except the last one which is fixed):
#   <host>_services_usage.csv
#   <host>_services_unused.csv
#   <host>_groups_usage.csv
#   <host>_groups_unused.csv
#   nsxmanager_groups_empty.csv
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
from typing import Dict, List, Tuple, Optional, Iterable
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed

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
    if v and v.strip():
        return v.strip()
    while True:
        entered = getpass.getpass(prompt_text) if secret else input(prompt_text)
        if entered and entered.strip():
            return entered.strip()

def is_system_object(obj: dict) -> Tuple[bool, List[str]]:
    reasons = [k for k in SYSTEM_BOOL_FLAGS if isinstance(obj.get(k), bool) and obj[k]]
    return (len(reasons) > 0, reasons)

def clamp_threads(n: int) -> int:
    if n < 1: return 1
    if n > 10: return 10
    return n

# -----------------------------
# NSX Client (retries, backoff, per-thread sessions)
# -----------------------------

class NSXClient:
    def __init__(
        self,
        host: str,                 # FQDN/IP (no scheme)
        username: str,
        password: str,
        verify_ssl: bool = False,  # default false
        timeout: int = 30,
        max_retries: int = 3,
        backoff: float = 1.5,
        jitter: float = 0.25,
        retry_sleep: float = 2.0,  # fixed sleep before retry (seconds)
    ):
        self.base = f"https://{host.strip()}"
        self.host = host.strip()
        self.verify = verify_ssl
        self.timeout = timeout
        self.max_retries = max_retries
        self.backoff = backoff
        self.jitter = jitter
        self.retry_sleep = max(0.0, retry_sleep)

        self._auth = (username, password)
        self._tls = threading.local()  # per-thread session

        if not verify_ssl:
            requests.packages.urllib3.disable_warnings(
                category=requests.packages.urllib3.exceptions.InsecureRequestWarning
            )

        self.log = logging.getLogger(self.__class__.__name__)

    def _get_session(self) -> requests.Session:
        sess = getattr(self._tls, "session", None)
        if sess is None:
            sess = requests.Session()
            sess.auth = self._auth
            sess.headers.update({"Accept": "application/json"})
            self._tls.session = sess
        return sess

    def _sleep_backoff(self, attempt: int) -> None:
        # Always wait at least retry_sleep seconds; optionally add backoff + jitter
        delay = max(self.retry_sleep, (self.backoff ** attempt)) + random.uniform(0, self.jitter)
        self.log.info("Retrying in %.2fs (attempt %d/%d)...", delay, attempt, self.max_retries)
        time.sleep(delay)

    def _req(self, method: str, path: str, params=None) -> dict:
        url = f"{self.base}{path}"
        attempt = 0
        while True:
            try:
                self.log.debug("HTTP %s %s params=%s", method, url, params)
                r = self._get_session().request(
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

    def get_by_policy_path(self, policy_path: str) -> dict:
        """
        Accepts '/infra/...' or '/policy/api/v1/infra/...'
        Returns the full object via GET.
        """
        if policy_path.startswith("/policy/api/v1/"):
            path = policy_path
        elif policy_path.startswith("/infra/"):
            path = "/policy/api/v1" + policy_path
        else:
            path = policy_path
        return self._req("GET", path)

# -----------------------------
# Collectors (threaded, with per-object GETs)
# -----------------------------

def collect_all_service_paths(nsx: NSXClient) -> List[str]:
    items = nsx.paged_get_all("/policy/api/v1/infra/services")
    paths = [it["path"] for it in items if isinstance(it, dict) and it.get("path")]
    logging.info("Listed %d Services (shallow)", len(paths))
    return paths

def collect_all_group_paths(nsx: NSXClient) -> List[str]:
    paths: List[str] = []
    domains = nsx.paged_get_all("/policy/api/v1/infra/domains")
    logging.info("Discovered %d Domains", len(domains))
    for d in domains:
        did = d.get("id")
        if not did:
            continue
        groups = nsx.paged_get_all(f"/policy/api/v1/infra/domains/{did}/groups")
        gpaths = [g["path"] for g in groups if isinstance(g, dict) and g.get("path")]
        logging.info("Domain '%s': %d Groups (shallow)", did, len(gpaths))
        paths.extend(gpaths)
    logging.info("Total Groups (shallow across domains): %d", len(paths))
    return paths

def fetch_objects_threaded(nsx: NSXClient, policy_paths: Iterable[str], threads: int) -> Dict[str, dict]:
    """Threaded GET of each policy object by path. Returns {path: full_object}."""
    results: Dict[str, dict] = {}
    paths = list(policy_paths)
    logging.info("Fetching %d objects in detail (threads=%d)...", len(paths), threads)

    def _fetch(p: str):
        try:
            obj = nsx.get_by_policy_path(p)
            return p, obj
        except Exception as e:
            logging.warning("Failed to fetch %s: %s", p, e)
            return p, {}

    with ThreadPoolExecutor(max_workers=threads) as ex:
        futures = [ex.submit(_fetch, p) for p in paths]
        for fut in as_completed(futures):
            p, obj = fut.result()
            if obj:
                results[p] = obj
    logging.info("Fetched %d/%d objects", len(results), len(paths))
    return results

def load_services_full_filtered(nsx: NSXClient, exclude_system: bool, threads: int) -> Dict[str, dict]:
    svc_paths = collect_all_service_paths(nsx)
    svc_map = fetch_objects_threaded(nsx, svc_paths, threads)
    kept, excluded = {}, 0
    for p, o in svc_map.items():
        if exclude_system:
            is_sys, reasons = is_system_object(o)
            if is_sys:
                excluded += 1
                logging.debug("Excluding system Service id=%s name=%s reasons=%s",
                              o.get("id"), o.get("display_name"), ",".join(reasons))
                continue
        kept[p] = o
    logging.info("Services kept: %d (excluded system: %d)", len(kept), excluded)
    return kept

def load_groups_full_filtered(nsx: NSXClient, exclude_system: bool, threads: int) -> Dict[str, dict]:
    grp_paths = collect_all_group_paths(nsx)
    grp_map = fetch_objects_threaded(nsx, grp_paths, threads)
    kept, excluded = {}, 0
    for p, o in grp_map.items():
        if exclude_system:
            is_sys, reasons = is_system_object(o)
            if is_sys:
                excluded += 1
                logging.debug("Excluding system Group id=%s name=%s reasons=%s",
                              o.get("id"), o.get("display_name"), ",".join(reasons))
                continue
        kept[p] = o
    logging.info("Groups kept: %d (excluded system: %d)", len(kept), excluded)
    return kept

# -----------------------------
# Rule scanners (threaded)
# -----------------------------

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

def scan_dfw_threaded(nsx: NSXClient, threads: int):
    svc_hits, grp_hits = [], []
    domains = nsx.paged_get_all("/policy/api/v1/infra/domains")

    def _scan_policy(did: str, pid: str):
        local_svc, local_grp = [], []
        for rule in list_sp_rules(nsx, did, pid):
            if rule.get("services"):
                local_svc.append((did, pid, rule))
            if rule.get("source_groups") or rule.get("destination_groups") or rule.get("scope"):
                local_grp.append((did, pid, rule))
        return local_svc, local_grp

    tasks = []
    for d in domains:
        did = d.get("id")
        if not did:
            continue
        for pol in list_security_policies(nsx, did):
            pid = pol.get("id")
            if pid:
                tasks.append((did, pid))

    logging.info("DFW: scheduling %d policy scans (threads=%d)", len(tasks), threads)
    with ThreadPoolExecutor(max_workers=threads) as ex:
        futures = [ex.submit(_scan_policy, did, pid) for (did, pid) in tasks]
        for fut in as_completed(futures):
            s, g = fut.result()
            svc_hits.extend(s)
            grp_hits.extend(g)

    logging.info("DFW: %d rules with Services, %d rules with Group refs", len(svc_hits), len(grp_hits))
    return svc_hits, grp_hits

def scan_gwfw_threaded(nsx: NSXClient, threads: int):
    svc_hits, grp_hits = [], []
    gw_tasks = []
    for t0 in list_t0s(nsx):
        t0id = t0.get("id")
        if not t0id:
            continue
        base = f"/policy/api/v1/infra/tier-0s/{t0id}/gateway-policies"
        for pol in list_gateway_policies_for_t0(nsx, t0id):
            pid = pol.get("id")
            if pid:
                gw_tasks.append(("tier-0", t0id, pid, base))
    for t1 in list_t1s(nsx):
        t1id = t1.get("id")
        if not t1id:
            continue
        base = f"/policy/api/v1/infra/tier-1s/{t1id}/gateway-policies"
        for pol in list_gateway_policies_for_t1(nsx, t1id):
            pid = pol.get("id")
            if pid:
                gw_tasks.append(("tier-1", t1id, pid, base))

    logging.info("GW-FW: scheduling %d policy scans (threads=%d)", len(gw_tasks), threads)

    def _scan_gw_policy(tier: str, tid: str, pid: str, base: str):
        local_svc, local_grp = [], []
        for rule in list_gp_rules(nsx, base, pid):
            if rule.get("services"):
                local_svc.append((tier, tid, pid, rule))
            if rule.get("source_groups") or rule.get("destination_groups") or rule.get("scope"):
                local_grp.append((tier, tid, pid, rule))
        return local_svc, local_grp

    with ThreadPoolExecutor(max_workers=threads) as ex:
        futures = [ex.submit(_scan_gw_policy, tier, tid, pid, base) for (tier, tid, pid, base) in gw_tasks]
        for fut in as_completed(futures):
            s, g = fut.result()
            svc_hits.extend(s)
            grp_hits.extend(g)

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

def is_group_empty_by_expression(group_obj: dict) -> bool:
    """
    Your requested heuristic:
    - If 'expression' is missing or empty -> the group is considered empty.
    - If 'expression' exists (non-empty) -> not empty (may have objects).
    """
    expr = group_obj.get("expression")
    return not expr  # True if None or empty list

def build_reports(nsx: NSXClient, out_prefix: str, exclude_system: bool, threads: int):
    # Load full objects and filter by system flags using per-object GETs
    services_by_path = load_services_full_filtered(nsx, exclude_system=exclude_system, threads=threads)
    groups_by_path   = load_groups_full_filtered(nsx, exclude_system=exclude_system, threads=threads)

    # Initialize usage indexes
    svc_usage: Dict[str, List[str]] = {p: [] for p in services_by_path.keys()}
    grp_usage: Dict[str, List[str]] = {p: [] for p in groups_by_path.keys()}

    # DFW references (threaded)
    dfw_svc_hits, dfw_grp_hits = scan_dfw_threaded(nsx, threads=threads)
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

    # Gateway FW references (threaded)
    gw_svc_hits, gw_grp_hits = scan_gwfw_threaded(nsx, threads=threads)
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

    # Groups reports (usage & unused)
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

    # NEW: Groups empty by expression (fixed filename)
    groups_empty_expr_csv = f"{out_prefix}_groups_empty.csv"
    with open(groups_empty_expr_csv, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["group_name", "group_id", "group_path"])
        empty_count = 0
        for gp, grp in groups_by_path.items():
            if is_group_empty_by_expression(grp):
                empty_count += 1
                w.writerow([
                    grp.get("display_name") or grp.get("id") or "",
                    grp.get("id") or "",
                    gp
                ])
    logging.info("Groups empty by expression: %d (file: %s)", empty_count, groups_empty_expr_csv)

    return services_usage_csv, services_unused_csv, groups_usage_csv, groups_unused_csv, groups_empty_expr_csv

# -----------------------------
# CLI
# -----------------------------

def main():
    ap = argparse.ArgumentParser(description="NSX-T: List Services & Groups and where they are used (DFW/GW-FW), plus empty groups report.")
    # Accept only host/FQDN/IP (no scheme)
    ap.add_argument("--nsx", help="NSX Manager FQDN or IP (no scheme), e.g. nsx01.acme.local")
    ap.add_argument("--user", help="Username")
    ap.add_argument("--password", help="Password (omit for secure prompt)")
    ap.add_argument("--verify-ssl", default="false", help="Verify SSL certificates (true/false). Default false.")
    ap.add_argument("--exclude-system", default="true", help="Exclude system-owned/system-created Services and Groups (true/false). Default true.")
    ap.add_argument("--out-prefix", default=None, help="Output filename prefix (for the 4 host-prefixed CSVs). Default = NSX host")
    ap.add_argument("--timeout", type=int, default=30, help="HTTP timeout seconds (default 30)")
    ap.add_argument("--retries", type=int, default=3, help="Max retries on transient errors (default 3)")
    ap.add_argument("--backoff", type=float, default=1.5, help="Exponential backoff base (default 1.5)")
    ap.add_argument("--jitter", type=float, default=0.25, help="Random jitter seconds added to backoff (default 0.25)")
    ap.add_argument("--retry-sleep", type=float, default=2.0, help="Fixed sleep (seconds) before each retry. Default 2.0")
    ap.add_argument("--threads", type=int, default=5, help="Number of worker threads (1-10). Default 5")
    ap.add_argument("--log-file", default=None, help="Path to log file (rotating, 10MB x 5)")
    ap.add_argument("--log-level", default="INFO", help="Log level (DEBUG, INFO, WARNING, ERROR)")
    args = ap.parse_args()

    setup_logging(args.log_file, args.log_level)

    # Prompt for any missing critical inputs
    nsx_host = ensure_value(args.nsx,    "NSX Manager FQDN/IP: ", secret=False)
    username = ensure_value(args.user,   "Username: ",            secret=False)
    password = ensure_value(args.password, "Password: ",         secret=True)

    verify_ssl = bool_from_str(args.verify_ssl)
    exclude_system = bool_from_str(args.exclude_system)
    threads = clamp_threads(args.threads)
    out_prefix = args.out_prefix or nsx_host

    logging.info("Starting where-used scan: nsx_host=%s verify_ssl=%s exclude_system=%s threads=%d prefix=%s",
                 nsx_host, verify_ssl, exclude_system, threads, out_prefix)

    nsx = NSXClient(
        host=nsx_host,
        username=username,
        password=password,
        verify_ssl=verify_ssl,
        timeout=args.timeout,
        max_retries=args.retries,
        backoff=args.backoff,
        jitter=args.jitter,
        retry_sleep=args.retry_sleep,
    )

    try:
        s_usage, s_unused, g_usage, g_unused, g_empty = build_reports(
            nsx, out_prefix, exclude_system=exclude_system, threads=threads
        )
    except Exception as e:
        logging.exception("Fatal error during report generation: %s", e)
        sys.exit(2)

    logging.info("Wrote: %s", s_usage)
    logging.info("Wrote: %s", s_unused)
    logging.info("Wrote: %s", g_usage)
    logging.info("Wrote: %s", g_unused)
    logging.info("Wrote: %s", g_empty)
    print(f"[OK] Wrote:\n  {s_usage}\n  {s_unused}\n  {g_usage}\n  {g_unused}\n  {g_empty}")

if __name__ == "__main__":
    main()
