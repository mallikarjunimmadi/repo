#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
alb-vsInventory-v1.3.3.py — NSX ALB (Avi) Virtual Service Inventory Collector
==============================================================================
Collects Virtual Service inventory, runtime details, Service Engine mapping,
and aggregated metrics from multiple Avi Controllers.

Highlights:
------------
✅ Single metrics API call per VS (metric_id=...%2C...).
✅ Resolves Service Engine names/IPs using /serviceengine?include_name=true.
✅ Extracts VIP IPv4/IPv6 correctly from vip_runtime/vip.
✅ Uses multi-threading across Controllers (default 5 threads).
✅ Logs per-Controller timing for inventory + metrics.
✅ Robust config.ini handling with DEFAULT fallback credentials.
✅ Fully commented for long-term readability.

Usage Example:
--------------
python3 alb-vsInventory-v1.3.3.py --config ./config.ini --threads 5 --debug

Requires:
---------
pip install requests pandas
"""

import argparse
import configparser
import csv
import logging
import sys
import time
import urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)


# ---------------------------------------------------------------------------
# Logging setup
# ---------------------------------------------------------------------------
def setup_logger(debug=False):
    level = logging.DEBUG if debug else logging.INFO
    logging.basicConfig(
        format="%(asctime)s: %(levelname)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
        level=level,
    )


# ---------------------------------------------------------------------------
# Safe retry wrapper for GET calls
# ---------------------------------------------------------------------------
def retry_request(session, url, retries=3, delay=2):
    for attempt in range(retries):
        try:
            r = session.get(url, timeout=30, verify=False)
            if r.status_code == 200:
                return r.json()
            else:
                logging.warning(f"GET {url} failed {r.status_code}: {r.text[:120]}...")
        except requests.RequestException as e:
            logging.warning(f"Connection error retrying {url}: {e}")
        time.sleep(delay * (attempt + 1))
    logging.error(f"Giving up after {retries} retries: {url}")
    return {}


# ---------------------------------------------------------------------------
# Login to Avi Controller
# ---------------------------------------------------------------------------
def login_controller(controller, user, password):
    """Authenticate to controller and return session + base_url."""
    base_url = f"https://{controller}"
    login_url = f"{base_url}/login"
    payload = {"username": user, "password": password}

    try:
        s = requests.Session()
        r = s.post(login_url, json=payload, verify=False, timeout=20)
        if r.status_code == 200:
            logging.info(f"[{controller}] Logged in")
            return s, base_url
        else:
            logging.error(f"[{controller}] Login failed {r.status_code}: {r.text}")
            return None, base_url
    except Exception as e:
        logging.error(f"[{controller}] Login error: {e}")
        return None, base_url


# ---------------------------------------------------------------------------
# Build Service Engine cache: UUID → {name, mgmt_ip}
# ---------------------------------------------------------------------------
def build_se_cache(session, base_url):
    url = f"{base_url}/api/serviceengine?include_name=true"
    data = retry_request(session, url)
    cache = {}
    if data:
        for se in data.get("results", []):
            cache[se.get("uuid")] = {
                "name": se.get("name"),
                "mgmt_ip": se.get("mgmt_ip_address", {}).get("addr"),
            }
    logging.info(f"Service Engine cache built: {len(cache)} entries")
    return cache


# ---------------------------------------------------------------------------
# Fetch Virtual Service inventory with include_name=true
# ---------------------------------------------------------------------------
def fetch_vs_inventory(session, base_url):
    url = f"{base_url}/api/virtualservice?include_name=true"
    data = retry_request(session, url)
    vs_list = data.get("results", []) if data else []
    logging.info(f"[{base_url.split('//')[1]}] VS inventory fetched: {len(vs_list)} items")
    return vs_list


# ---------------------------------------------------------------------------
# Fetch all metrics in one call (comma list URL-encoded as %2C)
# ---------------------------------------------------------------------------
def fetch_vs_metrics(session, base_url, vs_uuid, metrics, limit, step, debug=False):
    metric_param = "%2C".join(metrics)
    url = f"{base_url}/api/analytics/metrics/virtualservice/{vs_uuid}/?metric_id={metric_param}&limit={limit}&step={step}"
    if debug:
        logging.debug(f"[{vs_uuid}] Metrics URL: {url}")

    try:
        r = session.get(url, verify=False, timeout=30)
        if r.status_code != 200:
            logging.warning(f"[{vs_uuid}] Metrics HTTP {r.status_code}: {r.text[:120]}...")
            return {}
        return r.json()
    except Exception as e:
        logging.error(f"[{vs_uuid}] Metrics error: {e}")
        return {}


# ---------------------------------------------------------------------------
# Helper to extract reference names (ref.split('#')[-1])
# ---------------------------------------------------------------------------
def refname(ref):
    if not ref:
        return None
    return ref.split("#")[-1]


# ---------------------------------------------------------------------------
# Process one VS record: config + metrics + SE mapping
# ---------------------------------------------------------------------------
def process_vs(vs, se_cache, metrics_data, controller):
    vip = None
    # Extract VIP address (IPv4/IPv6)
    if vs.get("vip"):
        vip = vs["vip"][0].get("ip_address", {}).get("addr")
    elif vs.get("vip_runtime"):
        vip = vs["vip_runtime"][0].get("vip", {}).get("addr")

    # Primary & secondary SE from vip_runtime.se_list
    primary_se = secondary_se = None
    se_list = vs.get("vip_runtime", [{}])[0].get("se_list", [])
    if len(se_list) >= 1:
        puid = se_list[0].get("se_ref", "").split("/")[-1]
        primary_se = se_cache.get(puid)
    if len(se_list) >= 2:
        suid = se_list[1].get("se_ref", "").split("/")[-1]
        secondary_se = se_cache.get(suid)

    # Parse metrics data
    metrics_values = {}
    if metrics_data:
        for series in metrics_data.get("series", []):
            name = series.get("header", {}).get("name")
            datapoints = series.get("data", [])
            metrics_values[name] = datapoints[0][1] if datapoints else "N/A"

    row = {
        "Controller": controller,
        "Virtual_Service_Name": vs.get("name"),
        "VS_VIP": vip,
        "Port": vs.get("services", [{}])[0].get("port"),
        "Type(IPv4_/IPv6)": vs.get("ip_address", {}).get("type"),
        "VS_Enabled": str(vs.get("enabled", False)).upper(),
        "Traffic_Enabled": str(vs.get("traffic_enabled", False)).upper(),
        "SSL_Enabled": str(vs.get("enable_ssl", False)).upper(),
        "VIP_as_SNAT": str(vs.get("use_vip_as_snat", False)).upper(),
        "Auto_Gateway_Enabled": str(vs.get("enable_autogw", False)).upper(),
        "VH_Type": vs.get("vh_type"),
        "Application_Profile": refname(vs.get("application_profile_ref")),
        "SSL_Profile": refname(vs.get("ssl_profile_ref")),
        "SSL_Certificate_Name": refname(vs.get("ssl_key_and_certificate_refs")),
        "Analytics_Profile": refname(vs.get("analytics_profile_ref")),
        "Network_Profile": refname(vs.get("network_profile_ref")),
        "State": vs.get("runtime", {}).get("oper_status", {}).get("state", "UNKNOWN"),
        "Reason": vs.get("runtime", {}).get("oper_status", {}).get("reason"),
        "Pool": refname(vs.get("pool_ref")),
        "Service_Engine_Group": refname(vs.get("se_group_ref")),
        "Primary_SE_Name": primary_se.get("name") if primary_se else None,
        "Primary_SE_IP": primary_se.get("mgmt_ip") if primary_se else None,
        "Primary_SE_UUID": next((uuid for uuid, se in se_cache.items() if se == primary_se), None),
        "Secondary_SE_Name": secondary_se.get("name") if secondary_se else None,
        "Secondary_SE_IP": secondary_se.get("mgmt_ip") if secondary_se else None,
        "Secondary_SE_UUID": next((uuid for uuid, se in se_cache.items() if se == secondary_se), None),
        "Active_Standby_SE_Tag": vs.get("active_standby_se_tag"),
        "Cloud": refname(vs.get("cloud_ref")),
        "Cloud_Type": vs.get("cloud_type"),
        "Tenant": refname(vs.get("tenant_ref")),
        "Real_Time_Metrics_Enabled": str(vs.get("metrics_realtime_update", False)).upper(),
        "VS_UUID": vs.get("uuid"),
    }
    row.update(metrics_values)
    return row


# ---------------------------------------------------------------------------
# Per-controller worker
# ---------------------------------------------------------------------------
def worker(controller, user, password, metrics, limit, step, skip_metrics, debug):
    t0 = time.time()
    session, base_url = login_controller(controller, user, password)
    if not session:
        return [], controller, 0, 0, 0

    # Build SE cache
    t1 = time.time()
    se_cache = build_se_cache(session, base_url)
    t2 = time.time()
    vs_list = fetch_vs_inventory(session, base_url)
    t3 = time.time()

    results = []
    for vs in vs_list:
        metrics_data = {}
        if not skip_metrics:
            metrics_data = fetch_vs_metrics(session, base_url, vs.get("uuid"), metrics, limit, step, debug)
        row = process_vs(vs, se_cache, metrics_data, controller)
        results.append(row)

    t4 = time.time()
    config_time = round(t3 - t1, 2)
    metrics_time = round(t4 - t3, 2)
    total_time = round(t4 - t0, 2)
    logging.info(f"[{controller}] inventory={config_time}s metrics={metrics_time}s total={total_time}s ({len(results)} VSs)")
    return results, controller, config_time, metrics_time, total_time


# ---------------------------------------------------------------------------
# Main entrypoint
# ---------------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(description="NSX ALB Virtual Service Inventory Collector")
    parser.add_argument("--config", default="./config.ini", help="Path to config.ini")
    parser.add_argument("--threads", type=int, default=5, help="Parallel threads (default 5)")
    parser.add_argument("--skip-metrics", action="store_true", help="Skip metrics collection")
    parser.add_argument("--debug", action="store_true", help="Enable debug logging")
    args = parser.parse_args()

    setup_logger(args.debug)

    # Load config
    cfg = configparser.ConfigParser()
    cfg.read(args.config)

    default_user = cfg.get("DEFAULT", "avi_user", fallback="admin")
    default_pass = cfg.get("DEFAULT", "avi_pass", fallback="Admin@123")

    controllers = [c.strip() for c in cfg["CONTROLLERS"] if c.strip()]
    limit = cfg.get("SETTINGS", "api_limit", fallback="1")
    step = cfg.get("SETTINGS", "api_step", fallback="3600")
    metrics = cfg.get("SETTINGS", "metrics_list", fallback="").split(",")

    logging.info(f"Controllers: {', '.join(controllers)}")
    logging.info(f"Metrics: {metrics} | step={step} | limit={limit}")

    all_results = []
    summary = []

    with ThreadPoolExecutor(max_workers=args.threads) as pool:
        futures = {}
        for c in controllers:
            creds = cfg["CONTROLLERS"].get(c)
            if creds and "," in creds:
                user, password = creds.split(",", 1)
            else:
                user, password = default_user, default_pass
            futures[pool.submit(worker, c, user, password, metrics, limit, step, args.skip_metrics, args.debug)] = c

        for fut in as_completed(futures):
            res, ctrl, ct, mt, tt = fut.result()
            all_results.extend(res)
            summary.append((ctrl, ct, mt, tt))

    if not all_results:
        logging.error("No data collected — check credentials or connectivity.")
        sys.exit(1)

    # Write CSV
    outfile = f"avi-VSInventory_{time.strftime('%Y%m%dT%H%M%S')}.csv"
    with open(outfile, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=list(all_results[0].keys()))
        writer.writeheader()
        writer.writerows(all_results)

    logging.info(f"VS report saved: {outfile}")
    logging.info("---- Controller Summary ----")
    for c, ct, mt, tt in summary:
        logging.info(f"{c:25s} | inventory={ct:6.2f}s metrics={mt:6.2f}s total={tt:6.2f}s")


if __name__ == "__main__":
    main()
