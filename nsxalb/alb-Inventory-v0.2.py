#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
alb-vsInventory-v0.9_joinedAPI.py — NSX ALB (Avi) Virtual Service Inventory Collector

• Uses joined /api/virtualservice?include_name=true&join=...&page_size=200
• Builds Service Engine cache from /api/serviceengine-inventory
• Parses VH Type, profiles (Application/SSL/Analytics/Network), SSL cert names,
  pool, cloud, tenant, SE Group, Active/Standby tag, VIP, IP type, port, flags
• Primary/Secondary SE details via vip_runtime / runtime.vip_summary + SE cache
• Robust pagination for absolute/relative “next”
• Single CSV output; integers for numeric fields; no metrics
• Per-controller summary + timings; optional raw JSON dump on --debug
"""

import argparse
import configparser
import csv
import json
import logging
import os
import sys
import time
from typing import Any, Dict, List, Tuple

import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

# ------------------------- Logging ------------------------------------------
def setup_logger(debug: bool = False) -> None:
    level = logging.DEBUG if debug else logging.INFO
    logging.basicConfig(
        format="%(asctime)s: %(levelname)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
        level=level,
    )

# ------------------------- HTTP helpers -------------------------------------
def retry_get_json(sess: requests.Session, url: str, retries: int = 3, delay: float = 1.5) -> Dict[str, Any]:
    for attempt in range(retries):
        try:
            r = sess.get(url, timeout=45, verify=False)
            if r.status_code == 200:
                try:
                    return r.json()
                except ValueError:
                    logging.warning("GET %s returned non-JSON 200.", url)
                    return {}
            else:
                logging.warning("GET %s failed %s: %s...", url, r.status_code, r.text[:180])
        except requests.RequestException as e:
            logging.warning("Connection error retrying %s: %s", url, e)
        time.sleep(delay * (attempt + 1))
    logging.error("Giving up after %d retries: %s", retries, url)
    return {}

def paginate_all(sess: requests.Session, first_url: str, debug: bool = False) -> List[Dict[str, Any]]:
    """Return aggregated results from paginated Avi endpoints."""
    results: List[Dict[str, Any]] = []
    url = first_url
    base = None
    if "://" in first_url and "/api/" in first_url:
        base = first_url.split("/api/")[0]
    page = 1
    while url:
        if debug:
            logging.debug("Pagination GET (page %d): %s", page, url)
        data = retry_get_json(sess, url)
        if not data:
            break
        items = data.get("results", [])
        results.extend(items)
        nxt = data.get("next")
        if nxt:
            if nxt.startswith("/"):              # relative → absolute
                nxt = f"{base}{nxt}"
        url = nxt
        page += 1
    return results

# ------------------------- Auth ---------------------------------------------
def login(controller: str, user: str, password: str) -> Tuple[requests.Session, str]:
    base = f"https://{controller}"
    try:
        s = requests.Session()
        r = s.post(f"{base}/login", json={"username": user, "password": password}, verify=False, timeout=30)
        if r.status_code == 200:
            logging.info("[%s] Logged in", controller)
            return s, base
        logging.error("[%s] Login failed %s: %s", controller, r.status_code, r.text[:180])
        return None, base
    except Exception as e:
        logging.error("[%s] Login error: %s", controller, e)
        return None, base

# ------------------------- Small utils --------------------------------------
def refname(ref: Any) -> Any:
    """Extract display name from Avi *_ref strings or *_refs lists (handles '#', bare UUID, or URL)."""
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

def first_service_port(vs: Dict[str, Any]) -> Any:
    services = vs.get("services") or vs.get("config", {}).get("services") or []
    if services and isinstance(services, list):
        return services[0].get("port")
    return None

def ssl_enabled(vs: Dict[str, Any]) -> bool:
    services = vs.get("services") or vs.get("config", {}).get("services") or []
    for s in services:
        if s.get("enable_ssl"):
            return True
    return False

def pick_vip_ip(vs: Dict[str, Any]) -> Any:
    # Prefer joined VsVip (if join includes vsvip)
    try:
        vsvip = vs.get("vsvip") or vs.get("vsvip_ref_data")
        if vsvip:
            vip = vsvip.get("vip") if isinstance(vsvip, dict) else None
            if isinstance(vip, list) and vip:
                return vip[0]["ip_address"]["addr"]
    except Exception:
        pass
    # For inventory-like shape
    try:
        vip_list = vs.get("config", {}).get("vip")
        if isinstance(vip_list, list) and vip_list:
            return vip_list[0]["ip_address"]["addr"]
    except Exception:
        pass
    # runtime.vip_summary
    try:
        vsum = vs.get("runtime", {}).get("vip_summary")
        if isinstance(vsum, list) and vsum:
            return vsum[0]["ip_address"]["addr"]
    except Exception:
        pass
    return None

def pick_ip_type(vs: Dict[str, Any]) -> Any:
    # From VsVip join
    try:
        vsvip = vs.get("vsvip") or vs.get("vsvip_ref_data")
        if vsvip:
            vip = vsvip.get("vip") if isinstance(vsvip, dict) else None
            if isinstance(vip, list) and vip:
                return vip[0]["ip_address"]["type"]
    except Exception:
        pass
    # From config.vip
    try:
        vip_list = vs.get("config", {}).get("vip")
        if isinstance(vip_list, list) and vip_list:
            return vip_list[0]["ip_address"]["type"]
    except Exception:
        pass
    # From runtime.vip_summary
    try:
        vsum = vs.get("runtime", {}).get("vip_summary")
        if isinstance(vsum, list) and vsum:
            return vsum[0]["ip_address"]["type"]
    except Exception:
        pass
    return None

# ------------------------- Caches & fetchers --------------------------------
def build_se_cache(sess: requests.Session, base: str, debug: bool = False) -> Dict[str, Dict[str, Any]]:
    """se_uuid -> {name, mgmt_ip} from /api/serviceengine-inventory?include_name=true"""
    url = f"{base}/api/serviceengine-inventory?include_name=true&page_size=200"
    items = paginate_all(sess, url, debug)
    cache: Dict[str, Dict[str, Any]] = {}
    for se in items:
        # Accept both top-level and config shape
        uuid = se.get("uuid") or se.get("config", {}).get("uuid")
        name = se.get("name") or se.get("config", {}).get("name")
        mgmt = None
        if "mgmt_ip" in se and isinstance(se["mgmt_ip"], dict):
            mgmt = se["mgmt_ip"].get("addr") or se["mgmt_ip"].get("ip_addr", {}).get("addr")
        if not mgmt:
            mgmt = se.get("config", {}).get("mgmt_ip_address", {}).get("addr")
        if uuid:
            cache[uuid] = {"name": name, "mgmt_ip": mgmt}
    logging.info("Service Engine cache built: %d entries", len(cache))
    return cache

JOIN_QS = (
    "include_name=true&"
    "join=vsvip%2Cnetwork_profile_ref%2Cserver_network_profile_ref%2Capplication_profile_ref%2C"
    "pool_ref%2Cpool_group_ref%2Ccloud_ref%2Cssl_profile_ref%2Cssl_key_and_certificate_refs%2C"
    "vsvip_ref%2Cnetworkprofile&"
    "page_size=200"
)

def fetch_vs_joined(sess: requests.Session, base: str, debug: bool = False) -> List[Dict[str, Any]]:
    url = f"{base}/api/virtualservice?{JOIN_QS}"
    items = paginate_all(sess, url, debug)
    logging.info("[%s] VS fetched: %d", base.split("//")[1], len(items))
    return items

# ------------------------- CSV shaping --------------------------------------
FIXED_COLS = [
    "Controller", "Virtual_Service_Name", "VS_VIP", "Port", "Type(IPv4_/IPv6)",
    "VS_Enabled", "Traffic_Enabled", "SSL_Enabled", "VIP_as_SNAT", "Auto_Gateway_Enabled",
    "VH_Type", "Application_Profile", "SSL_Profile", "SSL_Certificate_Name",
    "Analytics_Profile", "Network_Profile", "State", "Reason", "Pool",
    "Service_Engine_Group", "Primary_SE_Name", "Primary_SE_IP", "Primary_SE_UUID",
    "Secondary_SE_Name", "Secondary_SE_IP", "Secondary_SE_UUID",
    "Active_Standby_SE_Tag", "Cloud", "Cloud_Type", "Tenant", "VS_UUID",
]

def process_vs_row(vs: Dict[str, Any], se_cache: Dict[str, Dict[str, Any]], controller: str) -> Dict[str, Any]:
    cfg = vs.get("config", {})  # tolerate inventory-like shape

    # Basics
    name = vs.get("name") or cfg.get("name")
    uuid = vs.get("uuid") or cfg.get("uuid")
    vip_ip = pick_vip_ip(vs)
    ip_type = pick_ip_type(vs)
    port = first_service_port(vs)

    vs_enabled = str(vs.get("enabled", cfg.get("enabled", False))).upper()
    traffic_enabled = str(vs.get("traffic_enabled", cfg.get("traffic_enabled", False))).upper()
    ssl_is_enabled = str(ssl_enabled(vs)).upper()
    vip_as_snat = str(vs.get("use_vip_as_snat", cfg.get("use_vip_as_snat", False))).upper()
    auto_gw = str(vs.get("enable_autogw", cfg.get("enable_autogw", False))).upper()

    vh_type = vs.get("vh_type") or cfg.get("vh_type")

    # Profiles (prefer joined *_ref_data name, fall back to *_ref#name)
    def join_name(obj_key: str, ref_key: str) -> Any:
        if vs.get(obj_key) and isinstance(vs[obj_key], dict) and vs[obj_key].get("name"):
            return vs[obj_key]["name"]
        return refname(vs.get(ref_key) or cfg.get(ref_key))

    application_profile = join_name("application_profile_ref_data", "application_profile_ref")
    ssl_profile = join_name("ssl_profile_ref_data", "ssl_profile_ref")
    analytics_profile = join_name("analytics_profile_ref_data", "analytics_profile_ref")
    network_profile = join_name("network_profile_ref_data", "network_profile_ref")

    # SSL certificates – joined doesn’t normally expand cert objects; use refs
    ssl_cert = refname(vs.get("ssl_key_and_certificate_refs") or cfg.get("ssl_key_and_certificate_refs"))

    # Runtime state/reason (joined /virtualservice may not include runtime.oper_status; guard)
    oper = vs.get("oper_status") or vs.get("runtime", {}).get("oper_status") or {}
    state = oper.get("state", "UNKNOWN")
    reason = oper.get("reason")

    # Pool / SE group / Cloud / Tenant
    pool = join_name("pool_ref_data", "pool_ref")
    se_group = join_name("se_group_ref_data", "se_group_ref")
    cloud = join_name("cloud_ref_data", "cloud_ref")
    cloud_type = vs.get("cloud_type") or cfg.get("cloud_type")
    tenant = join_name("tenant_ref_data", "tenant_ref")

    # Active/Standby tag
    active_standby = vs.get("active_standby_se_tag") or cfg.get("active_standby_se_tag")

    # Primary/Secondary SE mapping: use vip_runtime then fallback to runtime.vip_summary
    primary_name = primary_ip = primary_uuid = None
    secondary_name = secondary_ip = secondary_uuid = None

    se_attach = []
    try:
        se_attach = (vs.get("vip_runtime") or [{}])[0].get("se_list", [])
    except Exception:
        pass
    if not se_attach:
        try:
            se_attach = (vs.get("runtime", {}).get("vip_summary") or [{}])[0].get("service_engine", [])
        except Exception:
            pass

    prim = sec = None
    for entry in se_attach:
        # normalize uuid
        entry_uuid = entry.get("uuid")
        if not entry_uuid and entry.get("se_ref"):
            entry_uuid = entry["se_ref"].split("/")[-1].split("#")[0]
        # mark back for later
        entry["_uuid"] = entry_uuid

        if (entry.get("is_primary") or entry.get("primary") or (entry.get("role", "").lower() in ("primary", "active"))) and not prim:
            prim = entry
        elif (entry.get("is_standby") or entry.get("standby") or (entry.get("role", "").lower() in ("secondary", "standby"))) and not sec:
            sec = entry

    if not prim and se_attach:
        prim = se_attach[0]
    if not sec and len(se_attach) > 1 and se_attach[1] is not prim:
        sec = se_attach[1]

    if prim and prim.get("_uuid") and prim["_uuid"] in se_cache:
        primary_uuid = prim["_uuid"]
        primary_name = se_cache[primary_uuid].get("name")
        primary_ip = se_cache[primary_uuid].get("mgmt_ip")
    if sec and sec.get("_uuid") and sec["_uuid"] in se_cache:
        secondary_uuid = sec["_uuid"]
        secondary_name = se_cache[secondary_uuid].get("name")
        secondary_ip = se_cache[secondary_uuid].get("mgmt_ip")

    row = {
        "Controller": controller,
        "Virtual_Service_Name": name,
        "VS_VIP": vip_ip,
        "Port": port,
        "Type(IPv4_/IPv6)": ip_type,
        "VS_Enabled": vs_enabled,
        "Traffic_Enabled": traffic_enabled,
        "SSL_Enabled": ssl_is_enabled,
        "VIP_as_SNAT": vip_as_snat,
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
        "Active_Standby_SE_Tag": active_standby,
        "Cloud": cloud,
        "Cloud_Type": cloud_type,
        "Tenant": tenant,
        "VS_UUID": uuid,
    }
    # ensure fixed columns order
    return {k: row.get(k) for k in FIXED_COLS}

# ------------------------- Debug dump ---------------------------------------
def dump_raw(vs_objects: List[Dict[str, Any]], out_dir: str) -> None:
    if not vs_objects:
        return
    path = os.path.join(out_dir, f"avi-VSInventory-DEBUG-JSON_{time.strftime('%Y%m%dT%H%M%S')}.json")
    try:
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(vs_objects, fh, indent=2)
        logging.info("DEBUG raw JSON saved: %s (%d VS objects)", path, len(vs_objects))
    except Exception as e:
        logging.error("Failed to write debug JSON: %s", e)

# ------------------------- Main ---------------------------------------------
def main():
    ap = argparse.ArgumentParser(
        description="NSX ALB (Avi) VS inventory collector using joined /api/virtualservice.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    ap.add_argument("--config", default="./config.ini", help="Path to config.ini")
    ap.add_argument("--threads", type=int, default=4, help="Parallel controllers to fetch")
    ap.add_argument("--debug", action="store_true", help="Enable verbose logging and save raw VS JSON")
    args = ap.parse_args()

    setup_logger(args.debug)

    cfg = configparser.ConfigParser()
    if not cfg.read(args.config):
        logging.error("Config not found/readable: %s", args.config)
        sys.exit(1)

    default_user = cfg.get("DEFAULT", "avi_user", fallback="admin")
    default_pass = cfg.get("DEFAULT", "avi_pass", fallback="Admin@123")

    if "CONTROLLERS" not in cfg or not list(cfg["CONTROLLERS"].keys()):
        logging.error("No [CONTROLLERS] defined in config.")
        sys.exit(1)

    controllers: List[Tuple[str, Tuple[str, str]]] = []
    for host, val in cfg["CONTROLLERS"].items():
        host = host.strip()
        if not host:
            continue
        if val and "," in val:
            u, p = val.split(",", 1)
            controllers.append((host, (u.strip(), p.strip())))
        else:
            controllers.append((host, (default_user, default_pass)))

    out_dir = cfg.get("SETTINGS", "report_output_dir", fallback=".")
    os.makedirs(out_dir, exist_ok=True)

    logging.info("Controllers: %s", ", ".join([c for c, _ in controllers]))

    # serial per-controller (threading omitted for simplicity & clear logging)
    all_rows: List[Dict[str, Any]] = []
    summary: List[Tuple[str, int, int, float]] = []
    debug_raw_all: List[Dict[str, Any]] = []

    for ctrl, (user, password) in controllers:
        t0 = time.time()
        sess, base = login(ctrl, user, password)
        if not sess:
            continue

        # SE cache
        se_cache = build_se_cache(sess, base, debug=args.debug)
        # VS list (joined)
        vs_list = fetch_vs_joined(sess, base, debug=args.debug)

        # Build rows
        for vs in vs_list:
            row = process_vs_row(vs, se_cache, ctrl)
            all_rows.append(row)
        if args.debug:
            debug_raw_all.extend(vs_list)

        t_total = time.time() - t0
        summary.append((ctrl, len(se_cache), len(vs_list), t_total))
        logging.info("[%s] SEs=%d VSs=%d | total=%.2fs", ctrl, len(se_cache), len(vs_list), t_total)

    if not all_rows:
        logging.error("No data collected — check credentials/connectivity.")
        sys.exit(2)

    if args.debug and debug_raw_all:
        dump_raw(debug_raw_all, out_dir)

    # Write CSV
    out_csv = os.path.join(out_dir, f"avi-VSInventory_{time.strftime('%Y%m%dT%H%M%S')}.csv")
    with open(out_csv, "w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=FIXED_COLS, extrasaction="ignore")
        w.writeheader()
        for r in all_rows:
            w.writerow(r)

    logging.info("VS report saved: %s", out_csv)

    # Controller summary
    logging.info("---- Controller Summary ----")
    tot_vs = sum(v for _, _, v, _ in summary)
    tot_time = sum(t for _, _, _, t in summary)
    for ctrl, se_cnt, vs_cnt, t in summary:
        logging.info("%-30s | SEs=%4d VSs=%4d | total=%6.2fs", ctrl, se_cnt, vs_cnt, t)
    logging.info("TOTAL Controllers=%d | VS=%d | Time=%.2fs", len(summary), tot_vs, tot_time)

if __name__ == "__main__":
    main()
