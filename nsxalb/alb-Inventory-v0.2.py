#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
alb-vsInventory-v0.2_WIP.py — NSX ALB (Avi) Virtual Service Inventory Collector
===============================================================================
This script collects Virtual Service (VS) inventory with selected runtime fields,
resolves Service Engine (SE) names/IPs via a one-time cache, and fetches multiple
VS metrics in a **single** API call per VS (metric_id joined and URL-encoded with %2C).

What this version fixes / adds
------------------------------
- Avoids treating DEFAULT keys (avi_user/avi_pass) as controllers
- **Pagination** for /api/serviceengine-inventory and /api/virtualservice-inventory (follows absolute 'next')
- Robust metrics parsing (no KeyError on datapoints)
- Correct VIP extraction from config (vip[]) or runtime (vip_runtime[])
- Correct booleans: VS_Enabled, Traffic_Enabled, SSL_Enabled (from services[].enable_ssl),
  VIP_as_SNAT, Auto_Gateway_Enabled, Real_Time_Metrics_Enabled (analytics_policy.metrics_realtime_update.enabled)
- Per-controller summary: SE count, VS count, time for inventory/metrics/total
- Metrics columns expanded individually in CSV following metrics_list order
- Uses report_output_dir from config.ini

Args
----
--config        Path to config.ini (default ./config.ini)
--threads       Parallel controllers (default 5)
--skip-metrics  Skip metrics collection
--debug         Verbose logging (shows metrics URLs, pagination steps)

Config.ini expectations
-----------------------
[DEFAULT]
avi_user = admin
avi_pass = <secret>
[CONTROLLERS]
m00aviblb.corp.ad.sbi =
# or: other.controller = user,password
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
def retry_get_json(session: requests.Session, url: str, retries: int = 3, delay: int = 2):
    """
    GET JSON with simple backoff. Returns {} on failure.
    """
    for attempt in range(retries):
        try:
            r = session.get(url, timeout=30, verify=False)
            if r.status_code == 200:
                try:
                    return r.json()
                except ValueError:
                    logging.warning(f"GET {url} returned non-JSON 200.")
                    return {}
            else:
                logging.warning(f"GET {url} failed {r.status_code}: {r.text[:160]}...")
        except requests.RequestException as e:
            logging.warning(f"Connection error retrying {url}: {e}")
        time.sleep(delay * (attempt + 1))
    logging.error(f"Giving up after {retries} retries: {url}")
    return {}


def paginate_all(session: requests.Session, first_url: str, debug: bool = False):
    """
    Follow Avi paginated endpoints. Some versions return absolute 'next', others relative.
    Returns a list of items aggregated across all pages.
    """
    results = []
    url = first_url
    base = None
    if "://" in first_url:
        base = first_url.split("/api/")[0]
    page = 1
    while url:
        if debug:
            logging.debug(f"Pagination GET (page {page}): {url}")
        data = retry_get_json(session, url)
        if not data:
            break
        results.extend(data.get("results", []))
        nxt = data.get("next")
        if nxt:
            # Handle relative next
            if nxt.startswith("/"):
                nxt = f"{base}{nxt}"
        url = nxt
        page += 1
    return results

# -----------------------------------------------------------------------------
# Auth
# -----------------------------------------------------------------------------
def login_controller(controller: str, user: str, password: str):
    base_url = f"https://{controller}"
    login_url = f"{base_url}/login"
    try:
        s = requests.Session()
        r = s.post(login_url, json={"username": user, "password": password}, verify=False, timeout=20)
        if r.status_code == 200:
            logging.info(f"[{controller}] Logged in")
            return s, base_url
        logging.error(f"[{controller}] Login failed {r.status_code}: {r.text}")
        return None, base_url
    except Exception as e:
        logging.error(f"[{controller}] Login error: {e}")
        return None, base_url


# -----------------------------------------------------------------------------
# Caches & fetchers
# -----------------------------------------------------------------------------
def build_se_cache(session: requests.Session, base_url: str, debug: bool = False):
    """
    Build Service Engine cache: { uuid: {name, mgmt_ip} }
    Uses pagination to fetch ALL SEs.
    """
    url = f"{base_url}/api/serviceengine-inventory?include_name=true"
    se_list = paginate_all(session, url, debug=debug)
    cache = {}
    for se in se_list:
        cache[se.get("uuid")] = {
            "name": se.get("name"),
            "mgmt_ip": se.get("mgmt_ip_address", {}).get("addr"),
        }
    logging.info(f"Service Engine cache built: {len(cache)} entries")
    return cache


def fetch_vs_inventory(session: requests.Session, base_url: str, debug: bool = False):
    """
    Fetch ALL Virtual Services with include_name=true via pagination.
    """
    url = f"{base_url}/api/virtualservice-inventory?include_name=true"
    vs_list = paginate_all(session, url, debug=debug)
    logging.info(f"[{base_url.split('//')[1]}] VS inventory fetched: {len(vs_list)} items")
    return vs_list


def fetch_vs_metrics(session: requests.Session, base_url: str, vs_uuid: str,
                     metrics: list[str], limit: str, step: str, debug: bool = False):
    """
    Fetch all requested metrics in ONE call using %2C-joined metric_id.
    """
    if not metrics:
        return {}
    metric_param = "%2C".join(metrics)
    url = f"{base_url}/api/analytics/metrics/virtualservice/{vs_uuid}/?metric_id={metric_param}&limit={limit}&step={step}"
    if debug:
        logging.debug(f"[{vs_uuid}] Metrics URL: {url}")
    return retry_get_json(session, url)


# -----------------------------------------------------------------------------
# Utilities
# -----------------------------------------------------------------------------
def refname(ref):
    """
    Extract the 'name' part from an Avi ref URL (thing#Name).
    Accepts None, str, or list[str]; returns str|None.
    """
    if not ref:
        return None
    if isinstance(ref, list):
        if not ref:
            return None
        ref = ref[0]
    return ref.split("#")[-1] if "#" in ref else ref


def get_vip_addr(vs: dict):
    """
    Try to extract VIP IP (v4/v6) from config (vip[]) or runtime (vip_runtime[]).
    """
    # Config path
    try:
        return vs["vip"][0]["ip_address"]["addr"]
    except Exception:
        pass
    # Runtime path
    try:
        return vs["vip_runtime"][0]["vip"]["addr"]
    except Exception:
        pass
    return None


def get_ip_type(vs: dict):
    """
    Resolve IP type ('V4' or 'V6') from config vip ip_address.type or runtime vip.type.
    """
    try:
        return vs["vip"][0]["ip_address"]["type"]
    except Exception:
        pass
    try:
        return vs["vip_runtime"][0]["vip"]["type"]
    except Exception:
        pass
    return None


def get_ssl_enabled(vs: dict):
    """
    SSL_Enabled: read from the service port block(s). If any service has enable_ssl==True, return True.
    """
    for svc in vs.get("services", []):
        if svc.get("enable_ssl"):
            return True
    return False


def get_metrics_realtime_enabled(vs: dict):
    """
    Real_Time_Metrics_Enabled: from analytics_policy.metrics_realtime_update.enabled if present.
    """
    try:
        return bool(vs["analytics_policy"]["metrics_realtime_update"]["enabled"])
    except Exception:
        return False


# -----------------------------------------------------------------------------
# Row assembler
# -----------------------------------------------------------------------------
def process_vs_row(vs: dict, se_cache: dict, metrics_data: dict, controller: str, metric_list: list[str]):
    # VIP + type
    vip = get_vip_addr(vs)
    ip_type = get_ip_type(vs)

    # Primary / Secondary SE details from runtime
    primary_name = primary_ip = primary_uuid = None
    secondary_name = secondary_ip = secondary_uuid = None

    se_list = []
    try:
        se_list = vs.get("vip_runtime", [])[0].get("se_list", [])
    except Exception:
        pass

    if len(se_list) >= 1:
        primary_uuid = (se_list[0].get("se_ref", "")).split("/")[-1] or None
        if primary_uuid and primary_uuid in se_cache:
            primary_name = se_cache[primary_uuid]["name"]
            primary_ip = se_cache[primary_uuid]["mgmt_ip"]

    if len(se_list) >= 2:
        secondary_uuid = (se_list[1].get("se_ref", "")).split("/")[-1] or None
        if secondary_uuid and secondary_uuid in se_cache:
            secondary_name = se_cache[secondary_uuid]["name"]
            secondary_ip = se_cache[secondary_uuid]["mgmt_ip"]

    # State & reason (runtime.oper_status.*)
    state = vs.get("runtime", {}).get("oper_status", {}).get("state", "UNKNOWN")
    reason = vs.get("runtime", {}).get("oper_status", {}).get("reason")

    # Build base row (fixed columns in your order)
    row = {
        "Controller": controller,
        "Virtual_Service_Name": vs.get("name"),
        "VS_VIP": vip,
        "Port": (vs.get("services") or [{}])[0].get("port"),
        "Type(IPv4_/IPv6)": ip_type,
        "VS_Enabled": str(vs.get("enabled", False)).upper(),
        "Traffic_Enabled": str(vs.get("traffic_enabled", False)).upper(),
        "SSL_Enabled": str(get_ssl_enabled(vs)).upper(),
        "VIP_as_SNAT": str(vs.get("use_vip_as_snat", False)).upper(),
        "Auto_Gateway_Enabled": str(vs.get("enable_autogw", False)).upper(),
        "VH_Type": vs.get("vh_type"),
        "Application_Profile": refname(vs.get("application_profile_ref")),
        "SSL_Profile": refname(vs.get("ssl_profile_ref")),
        "SSL_Certificate_Name": refname(vs.get("ssl_key_and_certificate_refs")),
        "Analytics_Profile": refname(vs.get("analytics_profile_ref")),
        "Network_Profile": refname(vs.get("network_profile_ref")),
        "State": state,
        "Reason": reason,
        "Pool": refname(vs.get("pool_ref")),
        "Service_Engine_Group": refname(vs.get("se_group_ref")),
        "Primary_SE_Name": primary_name,
        "Primary_SE_IP": primary_ip,
        "Primary_SE_UUID": primary_uuid,
        "Secondary_SE_Name": secondary_name,
        "Secondary_SE_IP": secondary_ip,
        "Secondary_SE_UUID": secondary_uuid,
        "Active_Standby_SE_Tag": vs.get("active_standby_se_tag"),
        "Cloud": refname(vs.get("cloud_ref")),
        "Cloud_Type": vs.get("cloud_type"),
        "Tenant": refname(vs.get("tenant_ref")),
        "Real_Time_Metrics_Enabled": str(get_metrics_realtime_enabled(vs)).upper(),
        # Metrics will be appended below
        "VS_UUID": vs.get("uuid"),
    }

    # Add metrics columns in the same order as metrics_list
    # metrics_data format: { series: [ { header: {name: <metric>}, data: [[ts, val], ...] }, ... ] }
    series_map = {}
    for s in (metrics_data or {}).get("series", []):
        mname = s.get("header", {}).get("name")
        datapoints = s.get("data", [])
        # Defensive extraction:
        if datapoints:
            first = datapoints[0]
            # handle both [ts, val] and [val]
            if isinstance(first, (list, tuple)):
                if len(first) > 1:
                    series_map[mname] = first[1]
                elif len(first) == 1:
                    series_map[mname] = first[0]
                else:
                    series_map[mname] = "N/A"
            else:
                # sometimes a scalar
                series_map[mname] = first
        else:
            series_map[mname] = "N/A"

    for m in metric_list:
        row[m] = series_map.get(m, "N/A")

    return row


# -----------------------------------------------------------------------------
# Worker per controller
# -----------------------------------------------------------------------------
def controller_worker(controller: str, user: str, password: str,
                      metrics_list: list[str], limit: str, step: str,
                      skip_metrics: bool, debug: bool, report_dir: str):
    t0 = time.time()
    session, base_url = login_controller(controller, user, password)
    if not session:
        return [], controller, 0, 0, 0, 0, 0

    # Build SE cache (paginated)
    se_cache = build_se_cache(session, base_url, debug=debug)
    se_count = len(se_cache)

    t1 = time.time()
    # Fetch VS list (paginated)
    vs_list = fetch_vs_inventory(session, base_url, debug=debug)
    vs_count = len(vs_list)
    t2 = time.time()

    # Build rows
    results = []
    for vs in vs_list:
        metrics_data = {}
        if not skip_metrics and metrics_list:
            metrics_data = fetch_vs_metrics(session, base_url, vs.get("uuid"), metrics_list, limit, step, debug)
        row = process_vs_row(vs, se_cache, metrics_data, controller, metrics_list)
        results.append(row)

    t3 = time.time()
    inventory_time = round(t2 - t1, 2)
    metrics_time = round(t3 - t2, 2)
    total_time = round(t3 - t0, 2)

    logging.info(
        f"[{controller}] SEs={se_count} VSs={vs_count} | inventory={inventory_time}s metrics={metrics_time}s total={total_time}s"
    )
    return results, controller, se_count, vs_count, inventory_time, metrics_time, total_time


# -----------------------------------------------------------------------------
# Main
# -----------------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(description="NSX ALB (Avi) VS inventory + metrics collector")
    parser.add_argument("--config", default="./config.ini", help="Path to config.ini")
    parser.add_argument("--threads", type=int, default=5, help="Parallel controllers (default 5)")
    parser.add_argument("--skip-metrics", action="store_true", help="Skip metrics collection")
    parser.add_argument("--debug", action="store_true", help="Enable debug logging")
    args = parser.parse_args()

    setup_logger(args.debug)

    cfg = configparser.ConfigParser()
    cfg.read(args.config)

    # Defaults
    default_user = cfg.get("DEFAULT", "avi_user", fallback="admin")
    default_pass = cfg.get("DEFAULT", "avi_pass", fallback="Admin@123")

    # Controllers (IMPORTANT: only explicit keys from CONTROLLERS)
    controllers = list(cfg["CONTROLLERS"].keys())

    # Settings
    step = cfg.get("SETTINGS", "api_step", fallback="3600")
    limit = cfg.get("SETTINGS", "api_limit", fallback="1")
    metrics_list = [m.strip() for m in cfg.get("SETTINGS", "metrics_list", fallback="").split(",") if m.strip()]
    report_dir = cfg.get("SETTINGS", "report_output_dir", fallback=".")
    os.makedirs(report_dir, exist_ok=True)

    logging.info(f"Controllers: {', '.join(controllers)}")
    logging.info(f"Metrics: {metrics_list} | step={step} | limit={limit}")

    all_rows = []
    summary = []

    with ThreadPoolExecutor(max_workers=args.threads) as pool:
        futures = {}
        for ctrl in controllers:
            # Per-controller credentials (user,password) or default
            creds = cfg["CONTROLLERS"].get(ctrl)
            if creds and "," in creds:
                user, password = creds.split(",", 1)
            else:
                user, password = default_user, default_pass

            fut = pool.submit(
                controller_worker,
                ctrl, user, password,
                metrics_list, limit, step,
                args.skip_metrics, args.debug,
                report_dir
            )
            futures[fut] = ctrl

        for fut in as_completed(futures):
            rows, ctrl, se_cnt, vs_cnt, inv_t, met_t, tot_t = fut.result()
            all_rows.extend(rows)
            summary.append((ctrl, se_cnt, vs_cnt, inv_t, met_t, tot_t))

    if not all_rows:
        logging.error("No data collected — check credentials/connectivity.")
        sys.exit(1)

    # Output CSV with columns in your required order
    fixed_cols = [
        "Controller", "Virtual_Service_Name", "VS_VIP", "Port", "Type(IPv4_/IPv6)",
        "VS_Enabled", "Traffic_Enabled", "SSL_Enabled", "VIP_as_SNAT", "Auto_Gateway_Enabled",
        "VH_Type", "Application_Profile", "SSL_Profile", "SSL_Certificate_Name",
        "Analytics_Profile", "Network_Profile", "State", "Reason", "Pool",
        "Service_Engine_Group", "Primary_SE_Name", "Primary_SE_IP", "Primary_SE_UUID",
        "Secondary_SE_Name", "Secondary_SE_IP", "Secondary_SE_UUID",
        "Active_Standby_SE_Tag", "Cloud", "Cloud_Type", "Tenant",
        "Real_Time_Metrics_Enabled"
    ]
    # metrics columns in the same order as metrics_list, then VS_UUID last
    fieldnames = fixed_cols + metrics_list + ["VS_UUID"]

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
