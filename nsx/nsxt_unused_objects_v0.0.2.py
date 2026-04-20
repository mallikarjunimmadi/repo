#!/usr/bin/env python3
# nsxt_unused_objects_v0.0.2.py
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
# - Multithreaded object, group, DFW, and GW-FW discovery (default 5, configurable 1-10)
# - Requests larger pages by default to reduce API calls
# - Retry with fixed sleep (default 2s) + exponential backoff + jitter
#
# Outputs auto-prefixed with the NSX host:
#   <host>_services_usage.csv
#   <host>_services_unused.csv
#   <host>_groups_usage.csv
#   <host>_groups_unused.csv
#   <host>_groups_empty.csv
# All CSVs include a source_nsx column.
#
# Requirements: Python 3.8+, requests
#   pip install requests

import argparse
import csv
import getpass
import logging
from logging.handlers import RotatingFileHandler
import random
import re
import socket
import sys
import time
from datetime import datetime
from typing import Dict, List, Tuple, Optional, Iterable
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests

# -----------------------------
# Logging
# -----------------------------

def setup_logging(log_file: str, level: str = "INFO", include_runtime_identity: bool = False) -> None:
    logger = logging.getLogger()
    logger.setLevel(getattr(logging, level.upper(), logging.INFO))
    log_format = "%(asctime)s.%(msecs)03d %(levelname)-8s %(message)s"
    if include_runtime_identity:
        log_format = "%(asctime)s.%(msecs)03d %(levelname)-8s %(runtime_identity)s %(message)s"
    fmt = logging.Formatter(log_format, datefmt="%Y-%m-%d %H:%M:%S")
    ch = logging.StreamHandler(sys.stdout)
    ch.setFormatter(fmt)
    if include_runtime_identity:
        identity_filter = RuntimeIdentityFilter()
        ch.addFilter(identity_filter)
    logger.addHandler(ch)
    fh = RotatingFileHandler(log_file, maxBytes=10 * 1024 * 1024, backupCount=5)
    fh.setFormatter(fmt)
    if include_runtime_identity:
        fh.addFilter(identity_filter)
    logger.addHandler(fh)
    logger.info("Logging to: %s", log_file)

class RuntimeIdentityFilter(logging.Filter):
    def __init__(self) -> None:
        super().__init__()
        self.runtime_identity = f"{getpass.getuser()}@{socket.gethostname()}"

    def filter(self, record: logging.LogRecord) -> bool:
        record.runtime_identity = self.runtime_identity
        return True

# -----------------------------
# Utilities
# -----------------------------

SYSTEM_BOOL_FLAGS = (
    "is_default",
    "is_policy_default",
    "system_owned",
    "_system_owned",
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

def append_unique(target: List[str], value: str) -> None:
    if value not in target:
        target.append(value)

def parse_nsx_hosts(raw_values: Iterable[str]) -> List[str]:
    hosts: List[str] = []
    seen = set()
    for raw_value in raw_values:
        for item in str(raw_value).split(","):
            host = item.strip()
            if host and host not in seen:
                hosts.append(host)
                seen.add(host)
    return hosts

def filename_safe(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]+", "_", value.strip())

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

def log_progress(label: str, completed: int, total: int, every: int) -> None:
    if total <= 0:
        return
    if completed == 1 or completed == total or (every > 0 and completed % every == 0):
        logging.info("%s: %d/%d complete (%.1f%%)", label, completed, total, completed * 100.0 / total)

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
        page_size: int = 1000,
    ):
        self.base = f"https://{host.strip()}"
        self.host = host.strip()
        self.verify = verify_ssl
        self.timeout = timeout
        self.max_retries = max_retries
        self.backoff = backoff
        self.jitter = jitter
        self.retry_sleep = max(0.0, retry_sleep)
        self.page_size = max(1, page_size)

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
            p.setdefault("page_size", self.page_size)
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

def collect_all_group_paths(nsx: NSXClient, threads: int, progress_every: int) -> List[str]:
    paths: List[str] = []
    domains = nsx.paged_get_all("/policy/api/v1/infra/domains")
    logging.info("Discovered %d Domains", len(domains))
    domain_ids = [d.get("id") for d in domains if d.get("id")]

    def _list_domain_groups(did: str) -> List[str]:
        groups = nsx.paged_get_all(f"/policy/api/v1/infra/domains/{did}/groups")
        gpaths = [g["path"] for g in groups if isinstance(g, dict) and g.get("path")]
        logging.info("Domain '%s': %d Groups (shallow)", did, len(gpaths))
        return gpaths

    with ThreadPoolExecutor(max_workers=clamp_threads(min(threads, len(domain_ids)) or 1)) as ex:
        futures = [ex.submit(_list_domain_groups, did) for did in domain_ids]
        completed = 0
        for fut in as_completed(futures):
            paths.extend(fut.result())
            completed += 1
            log_progress(f"{nsx.host} group domain discovery", completed, len(futures), progress_every)

    logging.info("Total Groups (shallow across domains): %d", len(paths))
    return paths

def fetch_objects_threaded(nsx: NSXClient, policy_paths: Iterable[str], threads: int, progress_every: int, object_label: str) -> Dict[str, dict]:
    """Threaded GET of each policy object by path. Returns {path: full_object}."""
    results: Dict[str, dict] = {}
    paths = list(policy_paths)
    logging.info("Fetching %d %s objects in detail (threads=%d)...", len(paths), object_label, threads)

    def _fetch(p: str):
        try:
            obj = nsx.get_by_policy_path(p)
            return p, obj
        except Exception as e:
            logging.warning("Failed to fetch %s: %s", p, e)
            return p, {}

    with ThreadPoolExecutor(max_workers=threads) as ex:
        futures = [ex.submit(_fetch, p) for p in paths]
        completed = 0
        for fut in as_completed(futures):
            p, obj = fut.result()
            if obj:
                results[p] = obj
            completed += 1
            log_progress(f"{nsx.host} detail fetch for {object_label}", completed, len(futures), progress_every)
    logging.info("Fetched %d/%d %s objects", len(results), len(paths), object_label)
    return results

def load_services_full_filtered(nsx: NSXClient, exclude_system: bool, threads: int, progress_every: int) -> Dict[str, dict]:
    svc_paths = collect_all_service_paths(nsx)
    svc_map = fetch_objects_threaded(nsx, svc_paths, threads, progress_every, "Service")
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

def load_groups_full_filtered(nsx: NSXClient, exclude_system: bool, threads: int, progress_every: int) -> Dict[str, dict]:
    grp_paths = collect_all_group_paths(nsx, threads, progress_every)
    grp_map = fetch_objects_threaded(nsx, grp_paths, threads, progress_every, "Group")
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

def scan_dfw_threaded(nsx: NSXClient, threads: int, progress_every: int):
    svc_hits, grp_hits = [], []
    domains = nsx.paged_get_all("/policy/api/v1/infra/domains")
    domain_ids = [d.get("id") for d in domains if d.get("id")]

    def _scan_policy(did: str, pid: str):
        local_svc, local_grp = [], []
        for rule in list_sp_rules(nsx, did, pid):
            if rule.get("services"):
                local_svc.append((did, pid, rule))
            if rule.get("source_groups") or rule.get("destination_groups") or rule.get("scope"):
                local_grp.append((did, pid, rule))
        return local_svc, local_grp

    def _list_policy_tasks(did: str) -> List[Tuple[str, str]]:
        return [(did, pol["id"]) for pol in list_security_policies(nsx, did) if pol.get("id")]

    tasks = []
    with ThreadPoolExecutor(max_workers=clamp_threads(min(threads, len(domain_ids)) or 1)) as ex:
        futures = [ex.submit(_list_policy_tasks, did) for did in domain_ids]
        completed = 0
        for fut in as_completed(futures):
            tasks.extend(fut.result())
            completed += 1
            log_progress(f"{nsx.host} DFW policy discovery by domain", completed, len(futures), progress_every)

    logging.info("DFW: scheduling %d policy scans (threads=%d)", len(tasks), threads)
    with ThreadPoolExecutor(max_workers=threads) as ex:
        futures = [ex.submit(_scan_policy, did, pid) for (did, pid) in tasks]
        completed = 0
        for fut in as_completed(futures):
            s, g = fut.result()
            svc_hits.extend(s)
            grp_hits.extend(g)
            completed += 1
            log_progress(f"{nsx.host} DFW rule scan", completed, len(futures), progress_every)

    logging.info("DFW: %d rules with Services, %d rules with Group refs", len(svc_hits), len(grp_hits))
    return svc_hits, grp_hits

def scan_gwfw_threaded(nsx: NSXClient, threads: int, progress_every: int):
    svc_hits, grp_hits = [], []
    gw_tasks: List[Tuple[str, str, str, str]] = []
    tier_tasks: List[Tuple[str, str]] = []
    for t0 in list_t0s(nsx):
        t0id = t0.get("id")
        if t0id:
            tier_tasks.append(("tier-0", t0id))
    for t1 in list_t1s(nsx):
        t1id = t1.get("id")
        if t1id:
            tier_tasks.append(("tier-1", t1id))

    def _list_gateway_policy_tasks(tier: str, tid: str) -> List[Tuple[str, str, str, str]]:
        base = f"/policy/api/v1/infra/{'tier-0s' if tier == 'tier-0' else 'tier-1s'}/{tid}/gateway-policies"
        policies = list_gateway_policies_for_t0(nsx, tid) if tier == "tier-0" else list_gateway_policies_for_t1(nsx, tid)
        return [(tier, tid, pol["id"], base) for pol in policies if pol.get("id")]

    with ThreadPoolExecutor(max_workers=clamp_threads(min(threads, len(tier_tasks)) or 1)) as ex:
        futures = [ex.submit(_list_gateway_policy_tasks, tier, tid) for tier, tid in tier_tasks]
        completed = 0
        for fut in as_completed(futures):
            gw_tasks.extend(fut.result())
            completed += 1
            log_progress(f"{nsx.host} GW-FW policy discovery by gateway", completed, len(futures), progress_every)

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
        completed = 0
        for fut in as_completed(futures):
            s, g = fut.result()
            svc_hits.extend(s)
            grp_hits.extend(g)
            completed += 1
            log_progress(f"{nsx.host} GW-FW rule scan", completed, len(futures), progress_every)

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

def timestamped_csv(out_prefix: str, report_name: str, run_timestamp: str) -> str:
    return f"{out_prefix}_{report_name}_{run_timestamp}.csv"

def build_report_rows(nsx: NSXClient, source_nsx: str, exclude_system: bool, threads: int, progress_every: int) -> Dict[str, List[List[object]]]:
    logging.info("[%s] Stage 1/5: loading Services", source_nsx)
    # Load full objects and filter by system flags using per-object GETs
    services_by_path = load_services_full_filtered(nsx, exclude_system=exclude_system, threads=threads, progress_every=progress_every)

    logging.info("[%s] Stage 2/5: loading Groups", source_nsx)
    groups_by_path = load_groups_full_filtered(nsx, exclude_system=exclude_system, threads=threads, progress_every=progress_every)

    # Initialize usage indexes
    svc_usage: Dict[str, List[str]] = {p: [] for p in services_by_path.keys()}
    grp_usage: Dict[str, List[str]] = {p: [] for p in groups_by_path.keys()}

    # DFW references (threaded)
    logging.info("[%s] Stage 3/5: scanning DFW rules", source_nsx)
    dfw_svc_hits, dfw_grp_hits = scan_dfw_threaded(nsx, threads=threads, progress_every=progress_every)
    for (domain_id, policy_id, rule) in dfw_svc_hits:
        rid = rule.get("id") or rule.get("display_name") or "<unnamed>"
        for sp in (rule.get("services") or []):
            if sp in svc_usage:
                append_unique(svc_usage[sp], f"DFW: domain={domain_id}, policy={policy_id}, rule={rid}")

    for (domain_id, policy_id, rule) in dfw_grp_hits:
        rid = rule.get("id") or rule.get("display_name") or "<unnamed>"
        for gp in (rule.get("source_groups") or []):
            if gp in grp_usage:
                append_unique(grp_usage[gp], f"DFW(SRC): domain={domain_id}, policy={policy_id}, rule={rid}")
        for gp in (rule.get("destination_groups") or []):
            if gp in grp_usage:
                append_unique(grp_usage[gp], f"DFW(DST): domain={domain_id}, policy={policy_id}, rule={rid}")
        for sc in (rule.get("scope") or []):
            if is_group_path(sc) and sc in grp_usage:
                append_unique(grp_usage[sc], f"DFW(SCOPE): domain={domain_id}, policy={policy_id}, rule={rid}")

    # Gateway FW references (threaded)
    logging.info("[%s] Stage 4/5: scanning Gateway Firewall rules", source_nsx)
    gw_svc_hits, gw_grp_hits = scan_gwfw_threaded(nsx, threads=threads, progress_every=progress_every)
    for (tier, tier_id, policy_id, rule) in gw_svc_hits:
        rid = rule.get("id") or rule.get("display_name") or "<unnamed>"
        for sp in (rule.get("services") or []):
            if sp in svc_usage:
                append_unique(svc_usage[sp], f"{tier.upper()} FW: {tier_id}, policy={policy_id}, rule={rid}")

    for (tier, tier_id, policy_id, rule) in gw_grp_hits:
        rid = rule.get("id") or rule.get("display_name") or "<unnamed>"
        for gp in (rule.get("source_groups") or []):
            if gp in grp_usage:
                append_unique(grp_usage[gp], f"{tier.upper()} FW(SRC): {tier_id}, policy={policy_id}, rule={rid}")
        for gp in (rule.get("destination_groups") or []):
            if gp in grp_usage:
                append_unique(grp_usage[gp], f"{tier.upper()} FW(DST): {tier_id}, policy={policy_id}, rule={rid}")
        for sc in (rule.get("scope") or []):
            if is_group_path(sc) and sc in grp_usage:
                append_unique(grp_usage[sc], f"{tier.upper()} FW(SCOPE): {tier_id}, policy={policy_id}, rule={rid}")

    rows: Dict[str, List[List[object]]] = {
        "services_usage": [],
        "services_unused": [],
        "groups_usage": [],
        "groups_unused": [],
        "groups_empty": [],
    }

    logging.info("[%s] Stage 5/5: building CSV rows", source_nsx)
    for sp, svc in services_by_path.items():
        name = svc.get("display_name") or svc.get("id") or ""
        sid  = svc.get("id") or ""
        entries = svc.get("service_entries", []) or []
        entry_count = len(entries)
        proto, ports = ("","")
        if entries and isinstance(entries[0], dict):
            proto, ports = summarize_service_entry(entries[0])
        refs = svc_usage.get(sp, [])
        rows["services_usage"].append([source_nsx, name, sid, sp, entry_count, proto, ports, len(refs), " | ".join(refs)])
        if not refs:
            rows["services_unused"].append([source_nsx, name, sid, sp, entry_count, proto, ports])

    for gp, grp in groups_by_path.items():
        name = grp.get("display_name") or grp.get("id") or ""
        gid  = grp.get("id") or ""
        refs = grp_usage.get(gp, [])
        rows["groups_usage"].append([source_nsx, name, gid, gp, len(refs), " | ".join(refs)])
        if not refs:
            rows["groups_unused"].append([source_nsx, name, gid, gp])
        if is_group_empty_by_expression(grp):
            rows["groups_empty"].append([source_nsx, name, gid, gp])

    logging.info("Groups empty by expression for %s: %d", source_nsx, len(rows["groups_empty"]))
    logging.info(
        "[%s] Row totals: services_usage=%d services_unused=%d groups_usage=%d groups_unused=%d groups_empty=%d",
        source_nsx,
        len(rows["services_usage"]),
        len(rows["services_unused"]),
        len(rows["groups_usage"]),
        len(rows["groups_unused"]),
        len(rows["groups_empty"]),
    )
    return rows

def extend_report_rows(target: Dict[str, List[List[object]]], source: Dict[str, List[List[object]]]) -> None:
    for report_name, report_rows in source.items():
        target.setdefault(report_name, []).extend(report_rows)

def write_combined_reports(out_prefix: str, run_timestamp: str, rows: Dict[str, List[List[object]]]) -> Tuple[str, str, str, str, str]:
    report_specs = [
        ("services_usage", ["source_nsx", "service_name", "service_id", "service_path", "entry_count", "l4_app_protocol", "ports", "used_in_count", "used_in"]),
        ("services_unused", ["source_nsx", "service_name", "service_id", "service_path", "entry_count", "l4_app_protocol", "ports"]),
        ("groups_usage", ["source_nsx", "group_name", "group_id", "group_path", "used_in_count", "used_in"]),
        ("groups_unused", ["source_nsx", "group_name", "group_id", "group_path"]),
        ("groups_empty", ["source_nsx", "group_name", "group_id", "group_path"]),
    ]
    written_files = []
    for report_name, header in report_specs:
        csv_path = timestamped_csv(out_prefix, report_name, run_timestamp)
        with open(csv_path, "w", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow(header)
            w.writerows(rows.get(report_name, []))
        logging.info("Wrote: %s", csv_path)
        written_files.append(csv_path)
    return tuple(written_files)

# -----------------------------
# CLI
# -----------------------------

def main():
    ap = argparse.ArgumentParser(description="NSX-T: List Services & Groups and where they are used (DFW/GW-FW), plus empty groups report.")
    # Accept only host/FQDN/IP (no scheme)
    ap.add_argument(
        "--nsx",
        action="append",
        help="NSX Manager FQDN/IP (no scheme). Repeat this option or use comma-separated values for multiple managers.",
    )
    ap.add_argument("--user", help="Username")
    ap.add_argument("--password", help="Password (omit for secure prompt)")
    ap.add_argument("--verify-ssl", default="false", help="Verify SSL certificates (true/false). Default false.")
    ap.add_argument("--exclude-system", default="true", help="Exclude system-owned/system-created Services and Groups (true/false). Default true.")
    ap.add_argument("--out-prefix", default=None, help="Output filename prefix. Default = NSX host")
    ap.add_argument("--timeout", type=int, default=30, help="HTTP timeout seconds (default 30)")
    ap.add_argument("--retries", type=int, default=3, help="Max retries on transient errors (default 3)")
    ap.add_argument("--backoff", type=float, default=1.5, help="Exponential backoff base (default 1.5)")
    ap.add_argument("--jitter", type=float, default=0.25, help="Random jitter seconds added to backoff (default 0.25)")
    ap.add_argument("--retry-sleep", type=float, default=2.0, help="Fixed sleep (seconds) before each retry. Default 2.0")
    ap.add_argument("--page-size", type=int, default=1000, help="Page size for NSX list APIs (default 1000)")
    ap.add_argument("--threads", type=int, default=5, help="Number of worker threads (1-10). Default 5")
    ap.add_argument("--log-file", default=None, help="Path to log file (rotating, 10MB x 5). Default: current directory with timestamp.")
    ap.add_argument("--debug", action="store_true", help="Enable detailed debug logging, including every progress update and HTTP/page-level details.")
    args = ap.parse_args()

    run_timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    log_file = args.log_file or f"nsxt_unused_objects_{run_timestamp}.log"
    setup_logging(log_file, "DEBUG" if args.debug else "INFO", include_runtime_identity=args.debug)

    # Prompt for any missing critical inputs
    raw_nsx_hosts = args.nsx or [ensure_value(None, "NSX Manager FQDN/IP(s): ", secret=False)]
    nsx_hosts = parse_nsx_hosts(raw_nsx_hosts)
    if not nsx_hosts:
        logging.error("No NSX managers were provided.")
        sys.exit(2)
    username = ensure_value(args.user,   "Username: ",            secret=False)
    password = ensure_value(args.password, "Password: ",         secret=True)

    verify_ssl = bool_from_str(args.verify_ssl)
    exclude_system = bool_from_str(args.exclude_system)
    threads = clamp_threads(args.threads)
    progress_every = 1 if args.debug else 50
    out_prefix = args.out_prefix or (filename_safe(nsx_hosts[0]) if len(nsx_hosts) == 1 else "nsx_managers")
    combined_rows: Dict[str, List[List[object]]] = {
        "services_usage": [],
        "services_unused": [],
        "groups_usage": [],
        "groups_unused": [],
        "groups_empty": [],
    }
    successful_hosts: List[str] = []
    failed_hosts: List[str] = []

    for nsx_host in nsx_hosts:
        logging.info(
            "Starting where-used scan: nsx_host=%s verify_ssl=%s exclude_system=%s threads=%d prefix=%s timestamp=%s",
            nsx_host, verify_ssl, exclude_system, threads, out_prefix, run_timestamp,
        )

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
            page_size=args.page_size,
        )

        try:
            rows = build_report_rows(
                nsx,
                nsx_host,
                exclude_system=exclude_system,
                threads=threads,
                progress_every=progress_every,
            )
        except Exception as e:
            failed_hosts.append(nsx_host)
            logging.exception("Fatal error during report generation for %s: %s", nsx_host, e)
            continue

        extend_report_rows(combined_rows, rows)
        successful_hosts.append(nsx_host)

    if successful_hosts:
        written_files = write_combined_reports(out_prefix, run_timestamp, combined_rows)
        print("[OK] Wrote:\n  " + "\n  ".join(written_files))
    if failed_hosts:
        print("[ERROR] Failed NSX managers:\n  " + "\n  ".join(failed_hosts))
        sys.exit(2)
    if not successful_hosts:
        logging.error("No NSX managers completed successfully.")
        sys.exit(2)

if __name__ == "__main__":
    main()
