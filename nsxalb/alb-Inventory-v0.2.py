#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
alb-vsInventory-v1.3_robust_vsvip_ref_extraction.py — NSX ALB (Avi) Virtual Service Inventory Collector
=====================================================================================================
v1.3 FIXES (Targeting VIP/Network Extraction):
• Implemented robust extraction for VIPs defined using either 'ip_address' (V4/V6) 
  or 'ip6_address' keys within the VSVIP object.
• Added a new column 'Placement_Network' derived from vsvip_ref_data->vip->placement_networks->network_ref.
"""

import argparse
import configparser
import csv
import json
import logging
import os
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, Any, List, Tuple

import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning

# Disable warnings for unverified HTTPS requests
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)


# Global list to store raw JSON for debugging purposes
DEBUG_JSONS: List[Dict[str, Any]] = []

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
    Paginate across Avi endpoints.
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
        
        if debug:
            global DEBUG_JSONS
            DEBUG_JSONS.extend(items)

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
def login_controller(controller: str, user: str, password: str) -> Tuple[requests.Session | None, str]:
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
    Extract trailing name after '#' or the last segment after '/' from Avi ref strings.
    """
    if not ref:
        return None
    
    def extract_single_ref(r: str) -> str:
        if "#" in r:
            return r.split("#")[-1]
        elif "/" in r:
            return r.split("/")[-1]
        return r

    if isinstance(ref, list):
        if not ref:
            return None
        results = [extract_single_ref(r) for r in ref if isinstance(r, str)]
        return ", ".join(results)
        
    if isinstance(ref, str):
        return extract_single_ref(ref)
        
    return ref


def first_port(vs_data: Dict[str, Any]) -> Any:
    """
    Get first service port from VS config services[].
    """
    services = vs_data.get("services") or vs_data.get("config", {}).get("services", [])
    try:
        return services[0].get("port")
    except Exception:
        return None


def ssl_enabled_from_services(vs_data: Dict[str, Any]) -> bool:
    """
    Any service with enable_ssl == True => SSL_Enabled True.
    """
    services = vs_data.get("services") or vs_data.get("config", {}).get("services", [])
    for s in services:
        if s.get("enable_ssl"):
            return True
    return False

# --- NEW UTILITY FOR VSVIP REFERENCE LOOKUP ---
def fetch_vsvip_data(session: requests.Session, base_url: str, vs_inv: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Fetches the actual VSVIP object data if a vsvip_ref is present in the VS.
    Returns the 'vip' list from the fetched VSVIP object, or an empty list.
    """
    vsvip_ref = vs_inv.get("vsvip_ref")
    if not vsvip_ref:
        return []

    # Get the raw UUID from the reference string
    vsvip_uuid = vsvip_ref.split("/")[-1].split("#")[0]
    
    # Construct the API URL for the VSVIP object
    vsvip_url = f"{base_url}/api/vsvip/{vsvip_uuid}"

    logging.debug(f"Fetching VSVIP data from: {vsvip_url}")
    
    # Use the existing retry function
    vsvip_data = retry_get_json(session, vsvip_url, retries=2, delay=1)
    
    # The VIPs will be in the 'vip' list inside the fetched VSVIP object
    return vsvip_data.get("vip", [])
# -----------------------------------------------

# --- UTILITY FOR PLACEMENT NETWORK EXTRACTION ---
def get_placement_network(vip_entry: Dict[str, Any]) -> str | None:
    """
    Extracts the network name from the first placement_networks entry.
    """
    placement_networks = vip_entry.get("placement_networks")
    if placement_networks and isinstance(placement_networks, list):
        try:
            # Get the network_ref from the first entry
            network_ref = placement_networks[0].get("network_ref")
            if network_ref:
                # Use refname utility to extract the part after '#'
                return refname(network_ref)
        except Exception:
            pass
    return None
# -------------------------------------------------


# --- VIP EXTRACTION LOGIC (v1.3) ---
def get_all_vip_addresses(session: requests.Session, base_url: str, vs_inv: Dict[str, Any]) -> Tuple[str | None, str | None, str | None]:
    """
    Collects all unique IPv4/IPv6 addresses and their placement networks.
    
    Returns: (semicolon_separated_ips, semicolon_separated_types, semicolon_separated_networks)
    """
    ip_list: List[str] = []
    type_list: List[str] = []
    network_list: List[str] = []
    unique_ips = set() 
    
    # 1. Load VIP lists from different possible sources (Priority: VSVIP object reference lookup)
    vip_lists_to_check: List[List[Dict[str, Any]]] = []

    # A. Fetch VSVIP object via reference (if session is available)
    if session:
        vsvip_vips = fetch_vsvip_data(session, base_url, vs_inv)
        if vsvip_vips:
             vip_lists_to_check.append(vsvip_vips)
    
    # B. Embedded config/runtime paths (Fallback if no reference used)
    vip_lists_to_check.append(vs_inv.get("vsvip_ref_data", {}).get("vip", []))
    vip_lists_to_check.append(vs_inv.get("config", {}).get("vip", []))
    vip_lists_to_check.append(vs_inv.get("runtime", {}).get("vip_summary", []))
    vip_lists_to_check.append(vs_inv.get("vip_summary", []))

    
    # 2. Iterate through all discovered VIP lists
    for vip_list in vip_lists_to_check:
        if not vip_list or not isinstance(vip_list, list):
            continue
            
        for vip_entry in vip_list:
            addr = None
            addr_type = None
            
            # --- Primary check for the presence of V4/V6 IP keys in the entry ---
            
            # a. Check for the specific 'ip_address' structure (V4 or V6 VIP)
            ip_address_data = vip_entry.get("ip_address")
            if isinstance(ip_address_data, dict) and ip_address_data.get("addr"):
                addr = ip_address_data.get("addr")
                addr_type = ip_address_data.get("type", "V4")
            
            # b. Check for the specific 'ip6_address' structure (V6 only VIP)
            elif 'ip6_address' in vip_entry:
                ip6_address_data = vip_entry.get("ip6_address")
                if isinstance(ip6_address_data, dict) and ip6_address_data.get("addr"):
                    addr = ip6_address_data.get("addr") 
                    addr_type = ip6_address_data.get("type", "V6") 
            
            # c. Fallback for simpler runtime/status summaries (addr/type at top level)
            elif 'addr' in vip_entry and 'type' in vip_entry:
                addr = vip_entry.get('addr')
                addr_type = vip_entry.get('type')


            # 3. Process the discovered address
            if addr and addr_type:
                if addr not in unique_ips:
                    unique_ips.add(addr)
                    ip_list.append(addr)
                    
                    # Standardize type output
                    type_str = "V4" if 'V4' in addr_type.upper() else "V6" if 'V6' in addr_type.upper() else "Unknown"
                    type_list.append(type_str)
                    
                    # Extract Placement Network for this VIP entry
                    network_list.append(get_placement_network(vip_entry) or "N/A")
    
    ip_str = "; ".join(ip_list) if ip_list else None
    type_str = "; ".join(type_list) if type_list else None
    network_str = "; ".join(network_list) if network_list else None

    # Returns three strings now
    return ip_str, type_str, network_str
# --- VIP EXTRACTION LOGIC ENDS ---

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
        # Check top level first, then config
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
    join_params = (
        "vsvip," 
        "network_profile_ref,server_network_profile_ref,application_profile_ref,"
        "pool_ref,pool_group_ref,cloud_ref,ssl_profile_ref,"
        "ssl_key_and_certificate_refs,vsvip_ref,networkprofile"
    )
    url = f"{base_url}/api/virtualservice?include_name=true&join={join_params}&page_size=200"
    vs_list = paginate_all(session, url, debug=debug)
    logging.info(f"[{base_url.split('//')[1]}] VS inventory fetched: {len(vs_list)} items")
    return vs_list


# -----------------------------------------------------------------------------
# Row assembly (CSV)
# -----------------------------------------------------------------------------
# --- CSV COLUMN DEFINITION (NEW COLUMN ADDED) ---
FIXED_COLS = [
    "Controller", "Virtual_Service_Name", "VS_VIP_Addresses", "VS_VIP_Types", "Placement_Network",
    "Port", "VS_Enabled", "Traffic_Enabled", "SSL_Enabled", "VIP_as_SNAT", "Auto_Gateway_Enabled",
    "VH_Type", "Application_Profile", "SSL_Profile", "SSL_Certificate_Name",
    "Analytics_Profile", "Network_Profile", "State", "Reason", "Pool",
    "Service_Engine_Group", "Primary_SE_Name", "Primary_SE_IP", "Primary_SE_UUID",
    "Secondary_SE_Name", "Secondary_SE_IP", "Secondary_SE_UUID",
    "Active_Standby_SE_Tag", "Cloud", "Cloud_Type", "Tenant",
    "VS_UUID" 
]
# -----------------------------


def process_vs_row(vs_inv: Dict[str, Any],
                   se_cache: Dict[str, Dict[str, Any]],
                   controller: str,
                   session: requests.Session,
                   base_url: str) -> Dict[str, Any]:
    """
    Build a single CSV row from VS inventory + SE cache.
    """
    cfg = vs_inv.get("config", {}) 
    
    # VS basics
    name = vs_inv.get("name") or cfg.get("name")
    uuid = vs_inv.get("uuid") or cfg.get("uuid")

    # --- VIP EXTRACTION (Updated Call for 3 values) ---
    vip_addresses_str, vip_types_str, placement_network_str = get_all_vip_addresses(session, base_url, vs_inv)
    # --------------------------------------------------

    # Ports & flags - Use vs_inv keys first, fall back to cfg
    port = first_port(vs_inv)
    vs_enabled = str(vs_inv.get("enabled", cfg.get("enabled", False))).upper()
    traffic_enabled = str(vs_inv.get("traffic_enabled", cfg.get("traffic_enabled", False))).upper()
    ssl_enabled = str(ssl_enabled_from_services(vs_inv)).upper() 
    vip_snat = str(vs_inv.get("use_vip_as_snat", cfg.get("use_vip_as_snat", False))).upper()
    auto_gw = str(vs_inv.get("enable_autogw", cfg.get("enable_autogw", False))).upper()
    
    # Profiles & refs 
    vh_type = vs_inv.get("vh_type") or cfg.get("vh_type")
    application_profile = refname(vs_inv.get("application_profile_ref") or cfg.get("application_profile_ref"))
    ssl_profile = refname(vs_inv.get("ssl_profile_ref") or cfg.get("ssl_profile_ref"))
    ssl_cert_refs = vs_inv.get("ssl_key_and_certificate_refs") or cfg.get("ssl_key_and_certificate_refs")
    ssl_cert = refname(ssl_cert_refs)
    analytics_profile = refname(vs_inv.get("analytics_profile_ref") or cfg.get("analytics_profile_ref"))
    network_profile = refname(vs_inv.get("network_profile_ref") or cfg.get("network_profile_ref"))

    # Runtime
    oper = vs_inv.get("oper_status", {}) or vs_inv.get("runtime", {}).get("oper_status", {})
    state = oper.get("state", "UNKNOWN")
    reason = oper.get("reason")

    # Pool, SE group, cloud/tenant 
    pool = refname(vs_inv.get("pool_ref") or cfg.get("pool_ref"))
    se_group = refname(vs_inv.get("se_group_ref") or cfg.get("se_group_ref"))
    cloud = refname(vs_inv.get("cloud_ref") or cfg.get("cloud_ref"))
    cloud_type = vs_inv.get("cloud_type") or cfg.get("cloud_type")
    tenant = refname(vs_inv.get("tenant_ref") or cfg.get("tenant_ref"))
    active_standby_tag = vs_inv.get("active_standby_se_tag") or cfg.get("active_standby_se_tag")

    # Primary/Secondary SEs (Names/IPs/UUIDs) - Logic remains the same
    primary_name = primary_ip = primary_uuid = None
    secondary_name = secondary_ip = secondary_uuid = None

    se_runtime_list = []
    try:
        se_runtime_list = vs_inv.get("vip_runtime", [{}])[0].get("se_list", [])
    except Exception:
        pass
    
    se_runtime_summary = []
    if not se_runtime_list:
        try:
            se_runtime_summary = vs_inv.get("runtime", {}).get("vip_summary", [{}])[0].get("service_engine", [])
        except Exception:
            pass

    se_attach = vs_inv.get("serviceengine") or vs_inv.get("se_list") or se_runtime_list or se_runtime_summary

    if se_attach:
        prim = None
        sec = None
        
        for se in se_attach:
            # Check is_primary/is_standby flags
            if se.get("is_primary") and not prim:
                prim = se
            elif se.get("is_standby") and not sec:
                sec = se
            elif se.get("primary") and not prim:
                prim = se
            elif se.get("standby") and not sec:
                sec = se

            # Check 'role' string
            role = (se.get("role") or "").lower()
            if role in ("primary", "active") and not prim:
                prim = se
            elif role in ("secondary", "standby") and not sec:
                sec = se
                
        if not prim and se_attach:
            prim = se_attach[0]
        if not sec and len(se_attach) > 1 and se_attach[1] is not prim:
            sec = se_attach[1]

        # Extract Primary SE data
        if prim:
            primary_uuid = prim.get("uuid") or (prim.get("se_ref", "").split("/")[-1].split("#")[0] if prim.get("se_ref") else None)
            if primary_uuid and primary_uuid in se_cache:
                primary_name = se_cache[primary_uuid].get("name")
                primary_ip = se_cache[primary_uuid].get("mgmt_ip")

        # Extract Secondary SE data
        if sec:
            secondary_uuid = sec.get("uuid") or (sec.get("se_ref", "").split("/")[-1].split("#")[0] if sec.get("se_ref") else None)
            if secondary_uuid and secondary_uuid in se_cache:
                secondary_name = se_cache[secondary_uuid].get("name")
                secondary_ip = se_cache[secondary_uuid].get("mgmt_ip")


    # Build row in the fixed column order
    row = {
        "Controller": controller,
        "Virtual_Service_Name": name,
        "VS_VIP_Addresses": vip_addresses_str,
        "VS_VIP_Types": vip_types_str,
        "Placement_Network": placement_network_str, # <--- NEW VALUE
        "Port": port,
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
    
    # Ensure all fixed columns are present and use None for missing data
    final_row = {col: row.get(col) for col in FIXED_COLS}

    return final_row

# -----------------------------------------------------------------------------
# Debug Dump Function
# -----------------------------------------------------------------------------
def dump_debug_jsons(report_dir: str):
    """
    Dumps the collected raw VS JSONs to a file for debugging.
    """
    if not DEBUG_JSONS:
        logging.info("No raw JSON data collected to dump.")
        return
        
    outfile = os.path.join(report_dir, f"avi-VSInventory-DEBUG-JSON_{time.strftime('%Y%m%dT%H%M%S')}.json")
    try:
        with open(outfile, "w", encoding="utf-8") as fh:
            # We only dump the primary VS objects, not the secondary VSVIP objects 
            # as they were fetched separately and aren't aggregated in DEBUG_JSONS
            json.dump(DEBUG_JSONS, fh, indent=2)
        logging.info(f"DEBUG: Raw VS JSON data saved: {outfile} ({len(DEBUG_JSONS)} VS objects)")
    except Exception as e:
        logging.error(f"Failed to write debug JSON file: {e}")


# -----------------------------------------------------------------------------
# Per-controller worker
# -----------------------------------------------------------------------------
def controller_worker(controller: str, user: str, password: str,
                      debug: bool) -> Tuple[List[Dict[str, Any]], str, int, int, float, float]:
    t0 = time.time()
    session, base_url = login_controller(controller, user, password)
    if not session:
        return [], controller, 0, 0, 0.0, 0.0

    # Build SE cache
    se_cache = build_se_cache(session, base_url, debug=debug)
    se_count = len(se_cache)

    t1 = time.time()
    # Fetch VS inventory
    vs_list = fetch_vs_inventory(session, base_url, debug=debug) 
    vs_count = len(vs_list)
    t2 = time.time()

    # Build rows
    rows: List[Dict[str, Any]] = []
    for vs in vs_list:
        # PASS session and base_url to process_vs_row for VSVIP lookup
        row = process_vs_row(vs, se_cache, controller, session, base_url)
        rows.append(row)

    t3 = time.time()
    inventory_time = round(t2 - t1, 2)
    total_time = round(t3 - t0, 2)
    logging.info(f"[{controller}] SEs={se_count} VSs={vs_count} | inventory={inventory_time}s total={total_time}s")
    
    # Close session
    session.close()

    return rows, controller, se_count, vs_count, inventory_time, total_time


# -----------------------------------------------------------------------------
# Main
# -----------------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(description="NSX ALB (Avi) VS inventory collector (Inventory API, NO METRICS)")
    parser.add_argument("--config", default="./config.ini", help="Path to config.ini")
    parser.add_argument("--threads", type=int, default=5, help="Parallel controllers (default 5)")
    parser.add_argument("--debug", action="store_true", help="Enable debug logging and raw JSON dump")
    args = parser.parse_args()

    setup_logger(args.debug)

    cfg = configparser.ConfigParser()
    if not cfg.read(args.config):
        logging.error(f"Config not found/readable: {args.config}")
        sys.exit(1)

    # Defaults
    default_user = cfg.get("DEFAULT", "avi_user", fallback="admin")
    default_pass = cfg.get("DEFAULT", "avi_pass", fallback="Admin@123")

    # Controllers
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
            rows, ctrl, se_cnt, vs_cnt, inv_t, tot_t = fut.result()
            all_rows.extend(rows)
            summary.append((ctrl, se_cnt, vs_cnt, inv_t, tot_t))

    if not all_rows:
        logging.error("No data collected — check credentials/connectivity.")
        sys.exit(2)

    # DUMP RAW JSON IF DEBUG IS ENABLED
    if args.debug:
        dump_debug_jsons(report_dir)

    # CSV Header
    fieldnames = FIXED_COLS

    outfile = os.path.join(report_dir, f"avi-VSInventory-NO_METRICS_{time.strftime('%Y%m%dT%H%M%S')}.csv")
    with open(outfile, "w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=fieldnames, extrasaction="ignore") 
        writer.writeheader()
        for r in all_rows:
            writer.writerow(r)

    logging.info(f"VS report saved: {outfile}")
    logging.info("---- Controller Summary ----")
    total_vs = sum(v for _, _, v, _, _ in summary)
    total_time = sum(t for _, _, _, _, t in summary)
    for ctrl, se_cnt, vs_cnt, inv_t, tot_t in summary:
        logging.info(f"{ctrl:30s} | SEs={se_cnt:4d} VSs={vs_cnt:4d} | inventory={inv_t:6.2f}s total={tot_t:6.2f}s")
    logging.info(f"TOTAL Controllers={len(summary)} | VS={total_vs} | Time={total_time:.2f}s")


if __name__ == "__main__":
    main()
