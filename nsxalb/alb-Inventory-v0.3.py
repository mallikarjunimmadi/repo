#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
alb-vsInventory-v0.9.1_ipv6fix.py — NSX ALB (Avi) VS Inventory Collector

What's new in v0.9.1:
• Dual-stack VIP support: collects ALL IPv4 and IPv6 VIPs (no duplicates).
• "VS_VIP" and "Type(IPv4_/IPv6)" report semicolon-separated values (e.g., "10.1.2.3;2405:..."; "V4;V6").
• Debug logging of parsed VIPs to a LOG FILE only when --debug is provided (and echoed to console).
• Uses joined VirtualService API with page_size=200 to reduce follow-up API calls.
• Per-controller summary: SE count, VS count, inventory time, total time.
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
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

DEBUG_JSONS: List[Dict[str, Any]] = []

# ------------------------------- Logging ------------------------------------ #
def setup_logger(debug: bool, log_dir: str) -> None:
    """Console logger always on. File logger ONLY when --debug is given."""
    os.makedirs(log_dir, exist_ok=True)

    fmt = "%(asctime)s: %(levelname)s: %(message)s"
    datefmt = "%Y-%m-%d %H:%M:%S"

    root = logging.getLogger()
    root.handlers.clear()
    root.setLevel(logging.DEBUG if debug else logging.INFO)

    # Console handler
    ch = logging.StreamHandler(sys.stdout)
    ch.setLevel(logging.DEBUG if debug else logging.INFO)
    ch.setFormatter(logging.Formatter(fmt, datefmt))
    root.addHandler(ch)

    # File handler (ONLY when debug)
    if debug:
        log_name = os.path.join(log_dir, f"avi_vsInventory_DEBUG_{time.strftime('%Y%m%dT%H%M%S')}.log")
        fh = logging.FileHandler(log_name, encoding="utf-8")
        fh.setLevel(logging.DEBUG)
        fh.setFormatter(logging.Formatter(fmt, datefmt))
        root.addHandler(fh)
        logging.debug(f"Debug log file: {log_name}")

# ------------------------------- HTTP utils --------------------------------- #
def retry_get_json(session: requests.Session, url: str, retries: int = 3, delay: int = 2) -> Dict[str, Any]:
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
            DEBUG_JSONS.extend(items)
        results.extend(items)
        nxt = data.get("next")
        if nxt and nxt.startswith("/"):
            nxt = f"{base}{nxt}"
        url = nxt
        page += 1
    return results

# --------------------------------- Auth ------------------------------------- #
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

# ------------------------------- Helpers ------------------------------------ #
def refname(ref: Any) -> Any:
    """Extract trailing name after '#' or last segment after '/' from Avi ref strings. Supports list[str]."""
    if not ref:
        return None

    def one(r: str) -> str:
        if "#" in r:
            return r.split("#")[-1]
        if "/" in r:
            return r.split("/")[-1]
        return r

    if isinstance(ref, list):
        vals = [one(x) for x in ref if isinstance(x, str)]
        return ", ".join(vals) if vals else None
    if isinstance(ref, str):
        return one(ref)
    return ref

def first_port(vs: Dict[str, Any]) -> Any:
    services = vs.get("services") or vs.get("config", {}).get("services", [])
    try:
        return services[0].get("port")
    except Exception:
        return None

def ssl_enabled_from_services(vs: Dict[str, Any]) -> bool:
    services = vs.get("services") or vs.get("config", {}).get("services", [])
    for s in services:
        if s.get("enable_ssl"):
            return True
    return False

def get_vip_ips(vs: Dict[str, Any]) -> Tuple[List[str], List[str]]:
    """
    Collect ALL IPv4 and IPv6 VIP addresses from multiple places:
    Priority:
      1) vsvip_ref_data.vip[].ip_address
      2) config.vip[].ip_address
      3) runtime.vip_summary[].ip_address
      4) vip_runtime[].se_list[].vip_intf_list[].vip_intf_ip / vip_intf_ip6 (fallback)
    Returns (v4_list, v6_list) without duplicates.
    """
    v4, v6 = set(), set()

    # 1) vsvip_ref_data.vip[]
    vsvip = (vs.get("vsvip_ref_data") or {}).get("vip", [])
    for vip in vsvip:
        ip = (vip.get("ip_address") or {}).get("addr")
        typ = (vip.get("ip_address") or {}).get("type")
        if ip and typ == "V4":
            v4.add(ip)
        elif ip and typ == "V6":
            v6.add(ip)

    # 2) config.vip[]
    cfg_vip = vs.get("config", {}).get("vip", [])
    for vip in cfg_vip:
        ip = (vip.get("ip_address") or {}).get("addr")
        typ = (vip.get("ip_address") or {}).get("type")
        if ip and typ == "V4":
            v4.add(ip)
        elif ip and typ == "V6":
            v6.add(ip)

    # 3) runtime.vip_summary[]
    vip_sum = (vs.get("runtime") or {}).get("vip_summary", [])
    for vip in vip_sum:
        ip_obj = vip.get("ip_address") or {}
        ip, typ = ip_obj.get("addr"), ip_obj.get("type")
        if ip and typ == "V4":
            v4.add(ip)
        elif ip and typ == "V6":
            v6.add(ip)

    # 4) vip_runtime[].se_list[].vip_intf_list[] (fallback; interface VIPs)
    try:
        for vr in vs.get("vip_runtime", []):
            for se in vr.get("se_list", []):
                for intf in se.get("vip_intf_list", []):
                    ip4 = (intf.get("vip_intf_ip") or {}).get("addr")
                    ip6 = (intf.get("vip_intf_ip6") or {}).get("addr")
                    if ip4:
                        v4.add(ip4)
                    if ip6:
                        v6.add(ip6)
    except Exception:
        pass

    return sorted(v4), sorted(v6)

# ------------------------- Inventory fetchers -------------------------------- #
def build_se_cache(session: requests.Session, base_url: str, debug: bool = False) -> Dict[str, Dict[str, Any]]:
    url = f"{base_url}/api/serviceengine-inventory?include_name=true&page_size=200"
    se_inv = paginate_all(session, url, debug=debug)
    cache: Dict[str, Dict[str, Any]] = {}
    for se in se_inv:
        uuid = se.get("uuid") or (se.get("config") or {}).get("uuid")
        name = se.get("name") or (se.get("config") or {}).get("name")
        mgmt_ip = se.get("mgmt_ip") or (se.get("config") or {}).get("mgmt_ip_address", {}).get("addr")
        if uuid:
            cache[uuid] = {"name": name, "mgmt_ip": mgmt_ip}
    logging.info(f"Service Engine cache built: {len(cache)} entries")
    return cache

def fetch_vs_inventory(session: requests.Session, base_url: str, debug: bool = False) -> List[Dict[str, Any]]:
    join = ("vsvip,network_profile_ref,server_network_profile_ref,application_profile_ref,"
            "pool_ref,pool_group_ref,cloud_ref,ssl_profile_ref,ssl_key_and_certificate_refs,"
            "vsvip_ref,networkprofile")
    url = (f"{base_url}/api/virtualservice?include_name=true"
           f"&join={requests.utils.quote(join, safe='')}"
           f"&page_size=200")
    vs_list = paginate_all(session, url, debug=debug)
    logging.info(f"[{base_url.split('//')[1]}] VS inventory fetched: {len(vs_list)} items")
    return vs_list

# ------------------------------ CSV layout ---------------------------------- #
FIXED_COLS = [
    "Controller", "Virtual_Service_Name", "VS_VIP", "Port", "Type(IPv4_/IPv6)",
    "VS_Enabled", "Traffic_Enabled", "SSL_Enabled", "VIP_as_SNAT", "Auto_Gateway_Enabled",
    "VH_Type", "Application_Profile", "SSL_Profile", "SSL_Certificate_Name",
    "Analytics_Profile", "Network_Profile", "State", "Reason", "Pool",
    "Service_Engine_Group", "Primary_SE_Name", "Primary_SE_IP", "Primary_SE_UUID",
    "Secondary_SE_Name", "Secondary_SE_IP", "Secondary_SE_UUID",
    "Active_Standby_SE_Tag", "Cloud", "Cloud_Type", "Tenant", "VS_UUID"
]

def process_vs_row(vs: Dict[str, Any], se_cache: Dict[str, Dict[str, Any]], controller: str, debug: bool) -> Dict[str, Any]:
    cfg = vs.get("config", {})
    name = vs.get("name") or cfg.get("name")
    uuid = vs.get("uuid") or cfg.get("uuid")

    # Dual-stack VIPs (semicolon-separated)
    v4_list, v6_list = get_vip_ips(vs)
    vip_vals = []
    type_vals = []
    if v4_list:
        vip_vals.append(";".join(v4_list))
        type_vals.append("V4")
    if v6_list:
        vip_vals.append(";".join(v6_list))
        type_vals.append("V6")
    vs_vip = ";".join(vip_vals) if vip_vals else None
    ip_type = ";".join(type_vals) if type_vals else None

    if debug:
        logging.debug(f"[{name or uuid}] IPv4 VIPs: {v4_list}")
        logging.debug(f"[{name or uuid}] IPv6 VIPs: {v6_list}")

    port = first_port(vs)
    vs_enabled = str(vs.get("enabled", cfg.get("enabled", False))).upper()
    traffic_enabled = str(vs.get("traffic_enabled", cfg.get("traffic_enabled", False))).upper()
    ssl_enabled = str(ssl_enabled_from_services(vs)).upper()
    vip_snat = str(vs.get("use_vip_as_snat", cfg.get("use_vip_as_snat", False))).upper()
    auto_gw = str(vs.get("enable_autogw", cfg.get("enable_autogw", False))).upper()

    vh_type = vs.get("vh_type") or cfg.get("vh_type")

    application_profile = refname(vs.get("application_profile_ref") or cfg.get("application_profile_ref"))
    ssl_profile = refname(vs.get("ssl_profile_ref") or cfg.get("ssl_profile_ref"))
    ssl_cert = refname(vs.get("ssl_key_and_certificate_refs") or cfg.get("ssl_key_and_certificate_refs"))
    analytics_profile = refname(vs.get("analytics_profile_ref") or cfg.get("analytics_profile_ref"))
    network_profile = refname(vs.get("network_profile_ref") or cfg.get("network_profile_ref"))

    oper = vs.get("oper_status", {}) or (vs.get("runtime") or {}).get("oper_status", {})
    state = oper.get("state", "UNKNOWN")
    reason = oper.get("reason")

    pool = refname(vs.get("pool_ref") or cfg.get("pool_ref"))
    se_group = refname(vs.get("se_group_ref") or cfg.get("se_group_ref"))
    cloud = refname(vs.get("cloud_ref") or cfg.get("cloud_ref"))
    cloud_type = vs.get("cloud_type") or cfg.get("cloud_type")
    tenant = refname(vs.get("tenant_ref") or cfg.get("tenant_ref"))
    active_standby_tag = vs.get("active_standby_se_tag") or cfg.get("active_standby_se_tag")

    primary_name = primary_ip = primary_uuid = None
    secondary_name = secondary_ip = secondary_uuid = None

    se_attach = []
    try:
        se_attach = vs.get("vip_runtime", [{}])[0].get("se_list", [])
    except Exception:
        pass
    if not se_attach:
        try:
            se_attach = (vs.get("runtime") or {}).get("vip_summary", [{}])[0].get("service_engine", [])
        except Exception:
            pass
    if not se_attach:
        se_attach = vs.get("serviceengine") or vs.get("se_list") or []

    prim = sec = None
    for se in se_attach:
        if se.get("is_primary") or se.get("primary") or (se.get("role", "").lower() in ("primary", "active")):
            prim = prim or se
        if se.get("is_standby") or se.get("standby") or (se.get("role", "").lower() in ("secondary", "standby")):
            sec = sec or se
    if not prim and se_attach:
        prim = se_attach[0]
    if not sec and len(se_attach) > 1 and se_attach[1] is not prim:
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

    row = {
        "Controller": controller,
        "Virtual_Service_Name": name,
        "VS_VIP": vs_vip,
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
    return {col: row.get(col) for col in FIXED_COLS}

# ------------------------------ Debug dump ---------------------------------- #
def dump_debug_jsons(report_dir: str):
    if not DEBUG_JSONS:
        logging.info("No raw JSON data collected to dump.")
        return
    outfile = os.path.join(report_dir, f"avi-VSInventory-DEBUG-JSON_{time.strftime('%Y%m%dT%H%M%S')}.json")
    try:
        with open(outfile, "w", encoding="utf-8") as fh:
            json.dump(DEBUG_JSONS, fh, indent=2)
        logging.info(f"DEBUG: Raw VS JSON data saved: {outfile} ({len(DEBUG_JSONS)} VS objects)")
    except Exception as e:
        logging.error(f"Failed to write debug JSON file: {e}")

# --------------------------- Per-controller worker -------------------------- #
def controller_worker(controller: str, user: str, password: str, debug: bool) -> Tuple[List[Dict[str, Any]], str, int, int, float, float]:
    t0 = time.time()
    session, base_url = login_controller(controller, user, password)
    if not session:
        return [], controller, 0, 0, 0.0, 0.0

    se_cache = build_se_cache(session, base_url, debug=debug)
    se_count = len(se_cache)

    t1 = time.time()
    vs_list = fetch_vs_inventory(session, base_url, debug=debug)
    vs_count = len(vs_list)
    t2 = time.time()

    rows = [process_vs_row(vs, se_cache, controller, debug) for vs in vs_list]

    t3 = time.time()
    inventory_time = round(t2 - t1, 2)
    total_time = round(t3 - t0, 2)
    logging.info(f"[{controller}] SEs={se_count} VSs={vs_count} | inventory={inventory_time}s total={total_time}s")
    return rows, controller, se_count, vs_count, inventory_time, total_time

# ---------------------------------- Main ------------------------------------ #
def main():
    parser = argparse.ArgumentParser(description="NSX ALB (Avi) VS inventory collector (joined API, NO metrics)")
    parser.add_argument("--config", default="./config.ini", help="Path to config.ini")
    parser.add_argument("--threads", type=int, default=5, help="Parallel controllers (default 5)")
    parser.add_argument("--debug", action="store_true", help="Enable debug logging and write a debug log file")
    args = parser.parse_args()

    cfg = configparser.ConfigParser()
    if not cfg.read(args.config):
        print(f"Config not found/readable: {args.config}", file=sys.stderr)
        sys.exit(1)

    report_dir = cfg.get("SETTINGS", "report_output_dir", fallback=".")
    log_dir = cfg.get("SETTINGS", "log_output_dir", fallback=report_dir)
    setup_logger(args.debug, log_dir)

    default_user = cfg.get("DEFAULT", "avi_user", fallback="admin")
    default_pass = cfg.get("DEFAULT", "avi_pass", fallback="Admin@123")

    if "CONTROLLERS" not in cfg:
        logging.error("No [CONTROLLERS] section defined in config.")
        sys.exit(1)

    # Avoid accidental DEFAULT bleed: filter out obvious creds-like keys
    controllers = [k for k in cfg["CONTROLLERS"].keys() if k not in ("avi_user", "avi_pass")]
    if not controllers:
        logging.error("No controllers listed under [CONTROLLERS].")
        sys.exit(1)

    logging.info(f"Controllers: {', '.join(controllers)}")
    logging.info("Metrics collection is disabled (inventory only).")

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
            futures[pool.submit(controller_worker, ctrl, user, password, args.debug)] = ctrl

        for fut in as_completed(futures):
            try:
                rows, ctrl, se_cnt, vs_cnt, inv_t, tot_t = fut.result()
                all_rows.extend(rows)
                summary.append((ctrl, se_cnt, vs_cnt, inv_t, tot_t))
            except Exception as e:
                logging.error(f"Controller task error: {e}")

    if args.debug:
        dump_debug_jsons(report_dir)

    if not all_rows:
        logging.error("No data collected — check credentials/connectivity.")
        sys.exit(2)

    fieldnames = FIXED_COLS
    outfile = os.path.join(report_dir, f"avi-VSInventory_{time.strftime('%Y%m%dT%H%M%S')}.csv")
    with open(outfile, "w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        for r in all_rows:
            writer.writerow(r)

    logging.info(f"VS report saved: {outfile}")
    logging.info("---- Controller Summary ----")
    total_vs = sum(v for _, _, v, _, _ in summary) if summary else 0
    total_time = sum(t for _, _, _, _, t in summary) if summary else 0.0
    for ctrl, se_cnt, vs_cnt, inv_t, tot_t in summary:
        logging.info(f"{ctrl:30s} | SEs={se_cnt:4d} VSs={vs_cnt:4d} | inventory={inv_t:6.2f}s total={tot_t:6.2f}s")
    logging.info(f"TOTAL Controllers={len(summary)} | VS={total_vs} | Time={total_time:.2f}s")

if __name__ == "__main__":
    main()
