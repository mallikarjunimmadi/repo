#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
alb-vsInventory-v0.4_no_metrics.py — NSX ALB (Avi) Virtual Service Inventory Collector (Inventory API edition, NO METRICS)
=========================================================================================================================

What this script does
---------------------
• Uses INVENTORY endpoints for speed & completeness:
    - /api/virtualservice-inventory?include_name=true
    - /api/serviceengine-inventory?include_name=true
• Paginates across ALL records (handles absolute and relative 'next' URLs).
• Resolves VIP, runtime state, and **attached Service Engines** (names/IPs/roles).
• Outputs one CSV with a fixed column order (no metrics columns).
• Prints per-controller summary: SE count, VS count, timings (inventory/total).

Config.ini (same layout you already use)
----------------------------------------
[DEFAULT]
avi_user = admin
avi_pass = <secret>

[CONTROLLERS]
m00aviblb.local =
# or: controller.fqdn = user,password

[SETTINGS]
report_output_dir = .
log_output_dir = .
# The following settings are now ignored:
# avi_version = 22.1.7
# api_step = 21600
# api_limit = 1
# metrics_list = l4_client.avg_bandwidth,l4_client.avg_new_established_conns, ...

CLI
---
--config PATH        config file path (default ./config.ini)
--threads N          parallel controllers (default 5)
--debug              verbose logging

Dependencies
------------
pip install requests
"""

import argparse
import configparser
import csv
import logging
import os
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, Any, List, Tuple

import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)


# -----------------------------------------------------------------------------
# Logging
# -----------------------------------------------------------------------------
def setup_logger(debug: bool = False):
    level = logging.DEBUG if debug else logging.INFO
    logging.basicConfig(
        format="%(asctime)s: %(levelname)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
        level=level,
    )


# -----------------------------------------------------------------------------
# HTTP helpers
# -----------------------------------------------------------------------------
def retry_get_json(session: requests.Session, url: str, retries: int = 3, delay: int = 2) -> Dict[str, Any]:
    """
    GET JSON with backoff. Returns {} on failure.
    """
    for attempt in range(retries):
        try:
            r = session.get(url, timeout=45, verify=False)
            if r.status_code == 200:
                try:
                    return r.json()
                except ValueError:
                    logging.warning(f"GET {url} returned non-JSON 200.")
                    return {}
            else:
                logging.warning(f"GET {url} failed {r.status_code}: {r.text[:180]}...")
        except requests.RequestException as e:
            logging.warning(f"Connection error retrying {url}: {e}")
        time.sleep(delay * (attempt + 1))
    logging.error(f"Giving up after {retries} retries: {url}")
    return {}


def paginate_all(session: requests.Session, first_url: str, debug: bool = False) -> List[Dict[str, Any]]:
    """
    Paginate across Avi endpoints. Some versions return absolute 'next', others relative.
    Returns a list of aggregated 'results' from all pages.
    """
    results: List[Dict[str, Any]] = []
    url = first_url
    base = None
    if "://" in first_url and "/api/" in first_url:
        base = first_url.split("/api/")[0]
    page = 1
    while url:
        if debug:
            logging.debug(f"Pagination GET (page {page}): {url}")
        data = retry_get_json(session, url)
        if not data:
            break
        items = data.get("results", [])
        results.extend(items)
        nxt = data.get("next")
        if nxt:
            # Normalize relative next
            if nxt.startswith("/"):
                nxt = f"{base}{nxt}"
        url = nxt
        page += 1
    return results


# -----------------------------------------------------------------------------
# Auth
# -----------------------------------------------------------------------------
def login_controller(controller: str, user: str, password: str) -> Tuple[requests.Session, str]:
    base_url = f"https://{controller}"
    login_url = f"{base_url}/login"
    try:
        s = requests.Session()
        r = s.post(login_url, json={"username": user, "password": password}, verify=False, timeout=30)
        if r.status_code == 200:
            logging.info(f"[{controller}] Logged in")
            return s, base_url
        logging.error(f"[{controller}] Login failed {r.status_code}: {r.text[:180]}")
        return None, base_url
    except Exception as e:
        logging.error(f"[{controller}] Login error: {e}")
        return None, base_url


# -----------------------------------------------------------------------------
# Utilities
# -----------------------------------------------------------------------------
def refname(ref: Any) -> Any:
    """
    Extract trailing name after '#' from Avi ref strings.
    Accepts None | str | list[str].
    """
    if not ref:
        return None
    if isinstance(ref, list):
        if not ref:
            return None
        ref = ref[0]
    return ref.split("#")[-1] if isinstance(ref, str) and "#" in ref else ref


def first_port(vs_cfg: Dict[str, Any]) -> Any:
    """
    Get first service port from VS config services[].
    """
    try:
        return vs_cfg.get("services", [{}])[0].get("port")
    except Exception:
        return None


def ssl_enabled_from_services(vs_cfg: Dict[str, Any]) -> bool:
    """
    Any service with enable_ssl == True => SSL_Enabled True.
    """
    for s in vs_cfg.get("services", []):
        if s.get("enable_ssl"):
            return True
    return False


def vip_from_inventory(vs_inv: Dict[str, Any]) -> Any:
    """
    Prefer vip_summary[].vip. Fallback to config.vip[].ip_address.addr.
    """
    try:
        vs = vs_inv
        vsum = vs.get("vip_summary") or vs.get("vsvip_summary")  # some versions
        if vsum and isinstance(vsum, list) and vsum:
            return vsum[0].get("vip")
    except Exception:
        pass
    try:
        cfg = vs_inv.get("config", {})
        return cfg.get("vip", [{}])[0]["ip_address"]["addr"]
    except Exception:
        return None


def ip_type_from_inventory(vs_inv: Dict[str, Any]) -> Any:
    """
    Derive IP type (V4/V6) from config vip ip_address.type if present.
    """
    try:
        cfg = vs_inv.get("config", {})
        return cfg.get("vip", [{}])[0]["ip_address"]["type"]
    except Exception:
        return None


# -----------------------------------------------------------------------------
# Inventory fetchers
# -----------------------------------------------------------------------------
def build_se_cache(session: requests.Session, base_url: str, debug: bool = False) -> Dict[str, Dict[str, Any]]:
    """
    Use /api/serviceengine-inventory?include_name=true to build:
        { se_uuid: {"name": ..., "mgmt_ip": ...} }
    """
    url = f"{base_url}/api/serviceengine-inventory?include_name=true"
    se_inv = paginate_all(session, url, debug=debug)
    cache: Dict[str, Dict[str, Any]] = {}
    for se in se_inv:
        uuid = se.get("uuid") or (se.get("config") or {}).get("uuid")
        name = se.get("name") or (se.get("config") or {}).get("name")
        mgmt_ip = (
            se.get("mgmt_ip") or
            (se.get("config") or {}).get("mgmt_ip_address", {}).get("addr")
        )
        if uuid:
            cache[uuid] = {"name": name, "mgmt_ip": mgmt_ip}
    logging.info(f"Service Engine cache built: {len(cache)} entries")
    return cache


def fetch_vs_inventory(session: requests.Session, base_url: str, debug: bool = False) -> List[Dict[str, Any]]:
    """
    Use /api/virtualservice-inventory?include_name=true to fetch ALL VS inventory.
    """
    url = f"{base_url}/api/virtualservice-inventory?include_name=true"
    vs_list = paginate_all(session, url, debug=debug)
    logging.info(f"[{base_url.split('//')[1]}] VS inventory fetched: {len(vs_list)} items")
    return vs_list


# -----------------------------------------------------------------------------
# Row assembly (CSV)
# -----------------------------------------------------------------------------
# Removed "Real_Time_Metrics_Enabled" as it's less relevant without metrics, 
# and all metrics columns are gone.
FIXED_COLS = [
    "Controller", "Virtual_Service_Name", "VS_VIP", "Port", "Type(IPv4_/IPv6)",
    "VS_Enabled", "Traffic_Enabled", "SSL_Enabled", "VIP_as_SNAT", "Auto_Gateway_Enabled",
    "VH_Type", "Application_Profile", "SSL_Profile", "SSL_Certificate_Name",
    "Analytics_Profile", "Network_Profile", "State", "Reason", "Pool",
    "Service_Engine_Group", "Primary_SE_Name", "Primary_SE_IP", "Primary_SE_UUID",
    "Secondary_SE_Name", "Secondary_SE_IP", "Secondary_SE_UUID",
    "Active_Standby_SE_Tag", "Cloud", "Cloud_Type", "Tenant",
    "VS_UUID" # Added UUID here to be the final column
]


def process_vs_row(vs_inv: Dict[str, Any],
                   se_cache: Dict[str, Dict[str, Any]],
                   controller: str) -> Dict[str, Any]:
    """
    Build a single CSV row from VS inventory + SE cache.
    """
    cfg = vs_inv.get("config", {})  # inventory includes a 'config' subset
    # VS basics
    name = vs_inv.get("name") or cfg.get("name")
    uuid = vs_inv.get("uuid") or cfg.get("uuid")

    vip = vip_from_inventory(vs_inv)
    ip_type = ip_type_from_inventory(vs_inv)

    # Ports & flags
    port = first_port(cfg)
    vs_enabled = str(cfg.get("enabled", False)).upper()
    traffic_enabled = str(cfg.get("traffic_enabled", False)).upper()
    ssl_enabled = str(ssl_enabled_from_services(cfg)).upper()
    vip_snat = str(cfg.get("use_vip_as_snat", False)).upper()
    auto_gw = str(cfg.get("enable_autogw", False)).upper()
    vh_type = cfg.get("vh_type")

    # Profiles & refs
    application_profile = refname(cfg.get("application_profile_ref"))
    ssl_profile = refname(cfg.get("ssl_profile_ref"))
    ssl_cert = refname(cfg.get("ssl_key_and_certificate_refs"))
    analytics_profile = refname(cfg.get("analytics_profile_ref"))
    network_profile = refname(cfg.get("network_profile_ref"))

    # Runtime
    oper = vs_inv.get("oper_status", {}) or vs_inv.get("runtime", {}).get("oper_status", {})
    state = oper.get("state", "UNKNOWN")
    reason = oper.get("reason")

    # Pool, SE group, cloud/tenant
    pool = refname(cfg.get("pool_ref"))
    se_group = refname(cfg.get("se_group_ref"))
    cloud = refname(vs_inv.get("cloud_ref") or cfg.get("cloud_ref"))
    cloud_type = vs_inv.get("cloud_type") or cfg.get("cloud_type")
    tenant = refname(vs_inv.get("tenant_ref") or cfg.get("tenant_ref"))
    
    # Active/Standby tag
    active_standby_tag = cfg.get("active_standby_se_tag")

    # Primary/Secondary SEs from vs inventory (prefer explicit list if present)
    primary_name = primary_ip = primary_uuid = None
    secondary_name = secondary_ip = secondary_uuid = None

    # Different Avi versions expose attached SEs in different places:
    # Try 'serviceengine' (inventory), fallback to 'vip_runtime[].se_list[].se_ref'
    se_attach = vs_inv.get("serviceengine") or vs_inv.get("se_list") or []
    if se_attach:
        # Look for roles; if none, first=primary, second=secondary
        prim = None
        sec = None
        for se in se_attach:
            role = (se.get("role") or "").lower()
            if role in ("primary", "active") and not prim:
                prim = se
            elif role in ("secondary", "standby") and not sec:
                sec = se
        if not prim and se_attach:
            prim = se_attach[0]
        if not sec and len(se_attach) > 1:
            sec = se_attach[1]

        if prim:
            primary_uuid = prim.get("uuid") or (prim.get("se_ref", "").split("/")[-1].split("#")[0] if prim.get("se_ref") else None)
            if primary_uuid and primary_uuid in se_cache:
                primary_name = se_cache[primary_uuid].get("name")
                primary_ip = se_cache[primary_uuid].get("mgmt_ip")

        if sec:
            secondary_uuid = sec.get("uuid") or (sec.get("se_ref", "").split("/")[-1].split("#")[0] if sec.get("se_ref") else None)
            if secondary_uuid and secondary_uuid in se_cache:
                secondary_name = se_cache[secondary_uuid].get("name")
                secondary_ip = se_cache[secondary_uuid].get("mgmt_ip")

    # Build row in the fixed column order
    row = {
        "Controller": controller,
        "Virtual_Service_Name": name,
        "VS_VIP": vip,
        "Port": port,
        "Type(IPv4_/IPv6)": ip_type,
        "VS_Enabled": vs_enabled,
        "Traffic_Enabled": traffic_enabled,
        "SSL_Enabled": ssl_enabled,
        "VIP_as_SNAT": vip_snat,
        "Auto_Gateway_Enabled": auto_gw,
        "VH_Type": vh_type,
        "Application_Profile": application_profile,
        "SSL_Profile": ssl_profile,
        "SSL_Certificate_Name": ssl_cert,
        "Analytics_Profile": analytics_profile,
        "Network_Profile": network_profile,
        "State": state,
        "Reason": reason,
        "Pool": pool,
        "Service_Engine_Group": se_group,
        "Primary_SE_Name": primary_name,
        "Primary_SE_IP": primary_ip,
        "Primary_SE_UUID": primary_uuid,
        "Secondary_SE_Name": secondary_name,
        "Secondary_SE_IP": secondary_ip,
        "Secondary_SE_UUID": secondary_uuid,
        "Active_Standby_SE_Tag": active_standby_tag,
        "Cloud": cloud,
        "Cloud_Type": cloud_type,
        "Tenant": tenant,
        "VS_UUID": uuid,
    }
    
    # Ensure all fixed columns are present, even if data is None
    final_row = {col: row.get(col, None) for col in FIXED_COLS}

    return final_row


# -----------------------------------------------------------------------------
# Per-controller worker
# -----------------------------------------------------------------------------
def controller_worker(controller: str, user: str, password: str,
                      debug: bool) -> Tuple[List[Dict[str, Any]], str, int, int, float, float]:
    t0 = time.time()
    session, base_url = login_controller(controller, user, password)
    if not session:
        return [], controller, 0, 0, 0.0, 0.0

    # Build SE cache (INVENTORY + pagination)
    se_cache = build_se_cache(session, base_url, debug=debug)
    se_count = len(se_cache)

    t1 = time.time()
    # Fetch VS inventory (INVENTORY + pagination)
    vs_list = fetch_vs_inventory(session, base_url, debug=debug)
    vs_count = len(vs_list)
    t2 = time.time()

    # Build rows
    rows: List[Dict[str, Any]] = []
    for vs in vs_list:
        # No metrics fetch here
        row = process_vs_row(vs, se_cache, controller)
        rows.append(row)

    t3 = time.time()
    inventory_time = round(t2 - t1, 2)
    total_time = round(t3 - t0, 2)
    # Changed the logging to reflect the removal of metrics timing
    logging.info(f"[{controller}] SEs={se_count} VSs={vs_count} | inventory={inventory_time}s total={total_time}s")
    return rows, controller, se_count, vs_count, inventory_time, total_time


# -----------------------------------------------------------------------------
# Main
# -----------------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(description="NSX ALB (Avi) VS inventory collector (Inventory API, NO METRICS)")
    parser.add_argument("--config", default="./config.ini", help="Path to config.ini")
    parser.add_argument("--threads", type=int, default=5, help="Parallel controllers (default 5)")
    # Removed --skip-metrics as it's now the default/only mode
    parser.add_argument("--debug", action="store_true", help="Enable debug logging")
    args = parser.parse_args()

    setup_logger(args.debug)

    cfg = configparser.ConfigParser()
    if not cfg.read(args.config):
        logging.error(f"Config not found/readable: {args.config}")
        sys.exit(1)

    # Defaults
    default_user = cfg.get("DEFAULT", "avi_user", fallback="admin")
    default_pass = cfg.get("DEFAULT", "avi_pass", fallback="Admin@123")

    # Controllers — ONLY keys in [CONTROLLERS]
    if "CONTROLLERS" not in cfg or not cfg["CONTROLLERS"].keys():
        logging.error("No [CONTROLLERS] defined in config.")
        sys.exit(1)
    controllers = list(cfg["CONTROLLERS"].keys())

    # Settings
    report_dir = cfg.get("SETTINGS", "report_output_dir", fallback=".")
    os.makedirs(report_dir, exist_ok=True)

    logging.info(f"Controllers: {', '.join(controllers)}")
    logging.info("Metrics collection is disabled.")

    all_rows: List[Dict[str, Any]] = []
    # Summary format changed: (ctrl, se_cnt, vs_cnt, inv_t, tot_t)
    summary: List[Tuple[str, int, int, float, float]] = []

    with ThreadPoolExecutor(max_workers=args.threads) as pool:
        futures = {}
        for ctrl in controllers:
            creds = cfg["CONTROLLERS"].get(ctrl)
            if creds and "," in creds:
                user, password = creds.split(",", 1)
            else:
                user, password = default_user, default_pass

            fut = pool.submit(
                controller_worker, ctrl, user, password,
                args.debug
            )
            futures[fut] = ctrl

        for fut in as_completed(futures):
            # metrics_time (met_t) is removed from the result tuple
            rows, ctrl, se_cnt, vs_cnt, inv_t, tot_t = fut.result()
            all_rows.extend(rows)
            summary.append((ctrl, se_cnt, vs_cnt, inv_t, tot_t))

    if not all_rows:
        logging.error("No data collected — check credentials/connectivity.")
        sys.exit(2)

    # CSV Header — uses only FIXED_COLS
    fieldnames = FIXED_COLS

    outfile = os.path.join(report_dir, f"avi-VSInventory-NO_METRICS_{time.strftime('%Y%m%dT%H%M%S')}.csv")
    with open(outfile, "w", newline="", encoding="utf-8") as fh:
        # Setting extrasaction="ignore" is good practice for DictWriter
        writer = csv.DictWriter(fh, fieldnames=fieldnames, extrasaction="ignore") 
        writer.writeheader()
        for r in all_rows:
            writer.writerow(r)

    logging.info(f"VS report saved: {outfile}")
    logging.info("---- Controller Summary ----")
    # Updated summary calculation: (ctrl, se_cnt, vs_cnt, inv_t, tot_t)
    total_vs = sum(v for _, _, v, _, _ in summary)
    total_time = sum(t for _, _, _, _, t in summary)
    for ctrl, se_cnt, vs_cnt, inv_t, tot_t in summary:
        # Updated summary output
        logging.info(f"{ctrl:30s} | SEs={se_cnt:4d} VSs={vs_cnt:4d} | inventory={inv_t:6.2f}s total={tot_t:6.2f}s")
    logging.info(f"TOTAL Controllers={len(summary)} | VS={total_vs} | Time={total_time:.2f}s")


if __name__ == "__main__":
    main()
