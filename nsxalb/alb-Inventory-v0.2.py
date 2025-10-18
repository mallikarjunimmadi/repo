#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
alb-vsInventory-v0.4.py — NSX ALB (Avi) VS Inventory + Metrics (Inventory API edition)

Key features
------------
• Inventory endpoints (fewer calls, richer data):
  - /api/serviceengine-inventory?include_name=true
  - /api/virtualservice-inventory?include_name=true
• Robust pagination for absolute or relative `next` URLs.
• VIP, IP type, runtime state, and attached SEs resolved from inventory.
• Metrics fetched in ONE call per VS with %2C-joined metric IDs and &end=<epoch>.
• Metrics written as INTEGER values only (missing/empty → 0).
• Exact CSV column order preserved; metrics expanded to dedicated columns.
• One consolidated CSV for all controllers + per-controller summary.

CLI
---
--config PATH        config file path (default ./config.ini)
--threads N          parallel controllers (default 5)
--skip-metrics       skip metrics collection
--debug              verbose logging

Config (same layout you already use)
------------------------------------
[DEFAULT]
avi_user = admin
avi_pass = <secret>

[CONTROLLERS]
m00aviblb.local =
# or: controller.fqdn = username,password

[SETTINGS]
avi_version = 22.1.7
api_step = 21600
api_limit = 1
metrics_list = l4_client.avg_bandwidth,l4_client.avg_new_established_conns,...
report_output_dir = .
log_output_dir = .

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
    GET JSON with simple backoff. Returns {} on failure.
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
    Follow Avi pagination. Some versions return absolute 'next', others relative.
    Returns list of aggregated 'results'.
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
            if nxt.startswith("/"):  # normalize relative next
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
def refname(ref):
    """
    Extract trailing name after '#' from Avi ref strings.
    Accepts None | str | list[str] | dict (returns best-effort).
    """
    if not ref:
        return None
    if isinstance(ref, list):
        if not ref:
            return None
        ref = ref[0]
    if isinstance(ref, dict):
        # try common shapes like {"ref": "...#Name"}
        for k in ("ref", "url"):
            if k in ref and isinstance(ref[k], str):
                s = ref[k]
                return s.split("#")[-1] if "#" in s else s
        return None
    if isinstance(ref, str):
        return ref.split("#")[-1] if "#" in ref else ref
    return None


def first_port_from_config(vs_cfg: Dict[str, Any]):
    try:
        return vs_cfg.get("services", [{}])[0].get("port")
    except Exception:
        return None


def ssl_enabled_from_services(vs_cfg: Dict[str, Any]) -> bool:
    for s in vs_cfg.get("services", []):
        if s.get("enable_ssl"):
            return True
    return False


def vip_from_vs_inventory(vs_inv: Dict[str, Any]):
    """
    Prefer vip_summary[].vip (inventory). Fallback to config.vip[].ip_address.addr.
    """
    try:
        vsum = vs_inv.get("vip_summary") or vs_inv.get("vsvip_summary")
        if isinstance(vsum, list) and vsum:
            if isinstance(vsum[0], dict) and "vip" in vsum[0]:
                return vsum[0]["vip"]
    except Exception:
        pass
    try:
        cfg = vs_inv.get("config", {})
        return cfg.get("vip", [{}])[0]["ip_address"]["addr"]
    except Exception:
        return None


def ip_type_from_vs_inventory(vs_inv: Dict[str, Any]):
    """
    Derive V4/V6 from config.vip ip_address.type if present.
    """
    try:
        cfg = vs_inv.get("config", {})
        return cfg.get("vip", [{}])[0]["ip_address"]["type"]
    except Exception:
        return None


def normalize_metric_value(datapoints: Any) -> int:
    """
    Return ONLY the first VALUE as an integer. Missing or malformed → 0.

    Accepts:
      [{'timestamp': '...', 'value': X}, ...]  => X
      [[ts, val], ...]                         => val
      [[val], ...]                             => val
      [val, ...]                               => val
      scalar                                   => scalar
    """
    if not datapoints:
        return 0

    first = datapoints[0]

    # dict form
    if isinstance(first, dict):
        if "value" in first:
            val = first["value"]
        else:
            # try common numeric keys
            for k in ("avg", "sum", "min", "max"):
                if k in first:
                    val = first[k]
                    break
            else:
                return 0
        try:
            return int(float(val))
        except Exception:
            return 0

    # list/tuple
    if isinstance(first, (list, tuple)):
        if len(first) > 1:
            val = first[1]
        elif len(first) == 1:
            val = first[0]
        else:
            return 0
        try:
            return int(float(val))
        except Exception:
            return 0

    # scalar
    try:
        return int(float(first))
    except Exception:
        return 0


# -----------------------------------------------------------------------------
# Inventory + metrics fetchers
# -----------------------------------------------------------------------------
def build_se_cache(session: requests.Session, base_url: str, debug: bool = False) -> Dict[str, Dict[str, Any]]:
    """
    Build { se_uuid: {"name": ..., "mgmt_ip": ...} } using serviceengine-inventory.
    Handles variations where uuid/name/ip live in different levels.
    """
    url = f"{base_url}/api/serviceengine-inventory?include_name=true"
    se_inv = paginate_all(session, url, debug=debug)
    cache: Dict[str, Dict[str, Any]] = {}
    for se in se_inv:
        cfg = se.get("config", {})
        uuid = se.get("uuid") or cfg.get("uuid")

        # Try to salvage uuid if missing using ref/url
        if not uuid:
            maybe = se.get("url") or cfg.get("url") or se.get("serviceengine_ref")
            if isinstance(maybe, str) and "/serviceengine/" in maybe:
                uuid = maybe.split("/serviceengine/")[-1].split("#")[0]

        name = se.get("name") or cfg.get("name")
        mgmt_ip = (
            se.get("mgmt_ip") or
            (se.get("mgmt_ip_address") or {}).get("addr") or
            (cfg.get("mgmt_ip_address") or {}).get("addr")
        )
        if uuid:
            cache[uuid] = {"name": name, "mgmt_ip": mgmt_ip}
    logging.info(f"Service Engine cache built: {len(cache)} entries")
    return cache


def fetch_vs_inventory(session: requests.Session, base_url: str, debug: bool = False) -> List[Dict[str, Any]]:
    url = f"{base_url}/api/virtualservice-inventory?include_name=true"
    vs_list = paginate_all(session, url, debug=debug)
    logging.info(f"[{base_url.split('//')[1]}] VS inventory fetched: {len(vs_list)} items")
    return vs_list


def fetch_vs_metrics(session: requests.Session, base_url: str, vs_uuid: str,
                     metrics: List[str], limit: str, step: str, debug: bool = False) -> Dict[str, Any]:
    if not metrics:
        return {}
    metric_param = "%2C".join(metrics)  # URL-encoded comma
    end = int(time.time())              # current epoch so we get recent sample
    url = f"{base_url}/api/analytics/metrics/virtualservice/{vs_uuid}/?metric_id={metric_param}&limit={limit}&step={step}&end={end}"
    if debug:
        logging.debug(f"[{vs_uuid}] Metrics URL: {url}")
    return retry_get_json(session, url)


# -----------------------------------------------------------------------------
# Row assembly (CSV)
# -----------------------------------------------------------------------------
FIXED_COLS = [
    "Controller", "Virtual_Service_Name", "VS_VIP", "Port", "Type(IPv4_/IPv6)",
    "VS_Enabled", "Traffic_Enabled", "SSL_Enabled", "VIP_as_SNAT", "Auto_Gateway_Enabled",
    "VH_Type", "Application_Profile", "SSL_Profile", "SSL_Certificate_Name",
    "Analytics_Profile", "Network_Profile", "State", "Reason", "Pool",
    "Service_Engine_Group", "Primary_SE_Name", "Primary_SE_IP", "Primary_SE_UUID",
    "Secondary_SE_Name", "Secondary_SE_IP", "Secondary_SE_UUID",
    "Active_Standby_SE_Tag", "Cloud", "Cloud_Type", "Tenant",
    "Real_Time_Metrics_Enabled"
]


def resolve_attached_ses(vs_inv: Dict[str, Any]) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    """
    Try multiple inventory locations to find primary/secondary SEs.
    Returns (primary_dict, secondary_dict) where dict has keys: uuid, name, mgmt_ip.
    """
    # Priority 1: runtime.se_list (has is_primary/is_standby, mgmt_ip, se_ref)
    runtime = vs_inv.get("runtime") or {}
    se_list = runtime.get("se_list") or []

    # Priority 2: vip_runtime[].se_list (common in runtime payloads)
    if not se_list:
        for vr in vs_inv.get("vip_runtime") or []:
            if isinstance(vr, dict) and isinstance(vr.get("se_list"), list) and vr["se_list"]:
                se_list = vr["se_list"]
                break

    # Priority 3: a flattened 'serviceengine' list (some inventory builds)
    if not se_list:
        se_list = vs_inv.get("serviceengine") or vs_inv.get("se_list") or []

    prim = None
    sec = None
    # Identify roles where present
    for se in se_list:
        is_prim = se.get("is_primary") or (str(se.get("role", "")).lower() in ("primary", "active"))
        is_stby = se.get("is_standby") or (str(se.get("role", "")).lower() in ("secondary", "standby"))
        if is_prim and prim is None:
            prim = se
        elif is_stby and sec is None:
            sec = se

    # Fallback: first=primary, second=secondary
    if prim is None and se_list:
        prim = se_list[0]
    if sec is None and len(se_list) > 1:
        sec = se_list[1]

    def extract_se_min(sed: Dict[str, Any]) -> Dict[str, Any]:
        if not sed:
            return {}
        # uuid
        uuid = sed.get("uuid")
        if not uuid:
            se_ref = sed.get("se_ref") or sed.get("url")
            if isinstance(se_ref, str) and "/serviceengine/" in se_ref:
                uuid = se_ref.split("/serviceengine/")[-1].split("#")[0]
        # name
        name = sed.get("name")
        if not name:
            se_ref = sed.get("se_ref") or sed.get("url")
            if isinstance(se_ref, str) and "#" in se_ref:
                name = se_ref.split("#")[-1]
        # mgmt_ip
        mgmt_ip = None
        if isinstance(sed.get("mgmt_ip"), dict):
            mgmt_ip = sed["mgmt_ip"].get("addr")
        if not mgmt_ip:
            mgmt_ip = sed.get("mgmt_ip_addr") or sed.get("mgmt_ip_address")  # some variants
        return {"uuid": uuid, "name": name, "mgmt_ip": mgmt_ip}

    return extract_se_min(prim), extract_se_min(sec)


def process_vs_row(vs_inv: Dict[str, Any],
                   se_cache: Dict[str, Dict[str, Any]],
                   metrics_data: Dict[str, Any],
                   controller: str,
                   metrics_list: List[str]) -> Dict[str, Any]:
    cfg = vs_inv.get("config", {})

    # VS basics
    name = vs_inv.get("name") or cfg.get("name")
    uuid = vs_inv.get("uuid") or cfg.get("uuid")

    vip = vip_from_vs_inventory(vs_inv)
    ip_type = ip_type_from_vs_inventory(vs_inv)

    # Ports & flags (merge inventory + config fallbacks)
    port = first_port_from_config(cfg)
    vs_enabled = str(cfg.get("enabled", False)).upper()
    traffic_enabled = str(cfg.get("traffic_enabled", False)).upper()
    ssl_enabled = str(ssl_enabled_from_services(cfg)).upper()
    vip_snat = str(cfg.get("use_vip_as_snat", False)).upper()
    auto_gw = str(cfg.get("enable_autogw", False)).upper()
    vh_type = vs_inv.get("vh_type") or cfg.get("vh_type")

    # Profiles (prefer config refs; fallback to top-level if present)
    application_profile = refname(cfg.get("application_profile_ref") or vs_inv.get("application_profile_ref"))
    ssl_profile = refname(cfg.get("ssl_profile_ref") or vs_inv.get("ssl_profile_ref"))
    ssl_cert = refname(cfg.get("ssl_key_and_certificate_refs") or vs_inv.get("ssl_key_and_certificate_refs"))
    analytics_profile = refname(cfg.get("analytics_profile_ref") or vs_inv.get("analytics_profile_ref"))
    network_profile = refname(cfg.get("network_profile_ref") or vs_inv.get("network_profile_ref"))

    # Runtime status
    oper = vs_inv.get("oper_status", {}) or (vs_inv.get("runtime", {}) or {}).get("oper_status", {})
    state = oper.get("state", "UNKNOWN")
    reason = oper.get("reason")

    # Pool / SE group / Cloud / Tenant
    pool = refname(cfg.get("pool_ref") or vs_inv.get("pool_ref"))
    se_group = refname(cfg.get("se_group_ref") or vs_inv.get("se_group_ref"))
    cloud = refname(vs_inv.get("cloud_ref") or cfg.get("cloud_ref"))
    cloud_type = vs_inv.get("cloud_type") or cfg.get("cloud_type") or "UNKNOWN"
    tenant = refname(vs_inv.get("tenant_ref") or cfg.get("tenant_ref"))

    # Real-time metrics flag
    rt_enabled = False
    try:
        rt_enabled = bool((cfg.get("analytics_policy") or {}).get("metrics_realtime_update", {}).get("enabled", False))
    except Exception:
        rt_enabled = False
    real_time_metrics_enabled = str(rt_enabled).upper()

    # Active/Standby tag
    active_standby_tag = cfg.get("active_standby_se_tag") or (vs_inv.get("runtime") or {}).get("active_standby_se_tag")

    # Resolve attached SEs
    prim, sec = resolve_attached_ses(vs_inv)

    # Enrich from SE cache if missing name/ip
    if prim:
        if (not prim.get("name") or not prim.get("mgmt_ip")) and prim.get("uuid") in se_cache:
            prim.setdefault("name", se_cache[prim["uuid"]].get("name"))
            prim.setdefault("mgmt_ip", se_cache[prim["uuid"]].get("mgmt_ip"))
    if sec:
        if (not sec.get("name") or not sec.get("mgmt_ip")) and sec.get("uuid") in se_cache:
            sec.setdefault("name", se_cache[sec["uuid"]].get("name"))
            sec.setdefault("mgmt_ip", se_cache[sec["uuid"]].get("mgmt_ip"))

    # Metrics (ONLY integer values)
    series_map: Dict[str, int] = {}
    for s in (metrics_data or {}).get("series", []):
        mname = s.get("header", {}).get("name")
        datapoints = s.get("data", [])
        series_map[mname] = normalize_metric_value(datapoints)

    # Build row (metrics appended later)
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
        "Primary_SE_Name": prim.get("name") if prim else None,
        "Primary_SE_IP": prim.get("mgmt_ip") if prim else None,
        "Primary_SE_UUID": prim.get("uuid") if prim else None,
        "Secondary_SE_Name": sec.get("name") if sec else None,
        "Secondary_SE_IP": sec.get("mgmt_ip") if sec else None,
        "Secondary_SE_UUID": sec.get("uuid") if sec else None,
        "Active_Standby_SE_Tag": active_standby_tag,
        "Cloud": cloud,
        "Cloud_Type": cloud_type,
        "Tenant": tenant,
        "Real_Time_Metrics_Enabled": real_time_metrics_enabled,
        "VS_UUID": uuid,
    }

    # Add metrics columns in the same order requested
    for m in metrics_list:
        row[m] = series_map.get(m, 0)

    return row


# -----------------------------------------------------------------------------
# Per-controller worker
# -----------------------------------------------------------------------------
def controller_worker(controller: str, user: str, password: str,
                      metrics_list: List[str], limit: str, step: str,
                      skip_metrics: bool, debug: bool) -> Tuple[List[Dict[str, Any]], str, int, int, float, float, float]:
    t0 = time.time()
    session, base_url = login_controller(controller, user, password)
    if not session:
        return [], controller, 0, 0, 0.0, 0.0, 0.0

    # Build SE cache
    se_cache = build_se_cache(session, base_url, debug=debug)
    se_count = len(se_cache)

    # Fetch VS inventory
    t1 = time.time()
    vs_list = fetch_vs_inventory(session, base_url, debug=debug)
    t2 = time.time()
    vs_count = len(vs_list)

    # Build rows
    rows: List[Dict[str, Any]] = []
    for vs in vs_list:
        vs_uuid = vs.get("uuid") or (vs.get("config", {}) or {}).get("uuid")
        metrics_data = {}
        if not skip_metrics and metrics_list and vs_uuid:
            metrics_data = fetch_vs_metrics(session, base_url, vs_uuid, metrics_list, limit, step, debug)
        row = process_vs_row(vs, se_cache, metrics_data, controller, metrics_list)
        rows.append(row)

    t3 = time.time()
    inventory_time = round(t2 - t1, 2)
    metrics_time = round(t3 - t2, 2)
    total_time = round(t3 - t0, 2)
    logging.info(f"[{controller}] SEs={se_count} VSs={vs_count} | inventory={inventory_time}s metrics={metrics_time}s total={total_time}s")
    return rows, controller, se_count, vs_count, inventory_time, metrics_time, total_time


# -----------------------------------------------------------------------------
# Main
# -----------------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(description="NSX ALB (Avi) VS inventory + metrics collector (Inventory API)")
    parser.add_argument("--config", default="./config.ini", help="Path to config.ini")
    parser.add_argument("--threads", type=int, default=5, help="Parallel controllers (default 5)")
    parser.add_argument("--skip-metrics", action="store_true", help="Skip metrics collection")
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

    # Controllers — ONLY keys under [CONTROLLERS]
    if "CONTROLLERS" not in cfg or not list(cfg["CONTROLLERS"].keys()):
        logging.error("No [CONTROLLERS] defined in config.")
        sys.exit(1)
    controllers = list(cfg["CONTROLLERS"].keys())

    # Settings
    step = cfg.get("SETTINGS", "api_step", fallback="3600")
    limit = cfg.get("SETTINGS", "api_limit", fallback="1")
    metrics_list = [m.strip() for m in cfg.get("SETTINGS", "metrics_list", fallback="").split(",") if m.strip()]

    report_dir = cfg.get("SETTINGS", "report_output_dir", fallback=".")
    os.makedirs(report_dir, exist_ok=True)

    logging.info(f"Controllers: {', '.join(controllers)}")
    logging.info(f"Metrics: {metrics_list} | step={step} | limit={limit}")

    all_rows: List[Dict[str, Any]] = []
    summary: List[Tuple[str, int, int, float, float, float]] = []

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
                metrics_list, limit, step,
                args.skip_metrics, args.debug
            )
            futures[fut] = ctrl

        for fut in as_completed(futures):
            rows, ctrl, se_cnt, vs_cnt, inv_t, met_t, tot_t = fut.result()
            all_rows.extend(rows)
            summary.append((ctrl, se_cnt, vs_cnt, inv_t, met_t, tot_t))

    if not all_rows:
        logging.error("No data collected — check credentials/connectivity.")
        sys.exit(2)

    # CSV header: fixed cols + metrics + VS_UUID (already in fixed cols)
    # Your requested order places metrics before VS_UUID; we already include VS_UUID in FIXED_COLS tail.
    # We'll re-order to: FIXED_COLS (without VS_UUID) + metrics_list + VS_UUID
    fixed_wo_uuid = [c for c in FIXED_COLS if c != "VS_UUID"]
    fieldnames = fixed_wo_uuid + metrics_list + ["VS_UUID"]

    outfile = os.path.join(report_dir, f"avi-VSInventory_{time.strftime('%Y%m%dT%H%M%S')}.csv")
    with open(outfile, "w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        for r in all_rows:
            writer.writerow(r)

    logging.info(f"VS report saved: {outfile}")
    logging.info("---- Controller Summary ----")
    total_vs = sum(v for _, _, v, _, _, _ in [(c, s, v, i, m, t) for c, s, v, i, m, t in summary])
    total_time = sum(t for _, _, _, _, _, t in summary)
    for ctrl, se_cnt, vs_cnt, inv_t, met_t, tot_t in summary:
        logging.info(f"{ctrl:30s} | SEs={se_cnt:4d} VSs={vs_cnt:4d} | inventory={inv_t:6.2f}s metrics={met_t:6.2f}s total={tot_t:6.2f}s")
    logging.info(f"TOTAL Controllers={len(summary)} | VS={total_vs} | Time={total_time:.2f}s")


if __name__ == "__main__":
    main()
