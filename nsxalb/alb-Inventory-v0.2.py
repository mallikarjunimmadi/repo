#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
alb-VS-Inventory-v0.3.py — NSX Advanced Load Balancer (Avi) Virtual Service Inventory + Metrics

PURPOSE
-------
Collects Virtual Service (VS) configuration, runtime, and performance metrics from one or more
Avi/NSX-ALB Controllers and writes a single CSV report with a fixed, user-specified column order.

WHAT YOU GET
------------
- One CSV per run, e.g.:
  avi-VSInventory_YYYYMMDDTHHMMSS.csv
- Columns (in this exact order):
  Controller,Virtual_Service_Name,VS_VIP,Port,Type(IPv4_/IPv6),VS_Enabled,Traffic_Enabled,SSL_Enabled,
  VIP_as_SNAT,Auto_Gateway_Enabled,VH_Type,Application_Profile,SSL_Profile,SSL_Certificate_Name,
  Analytics_Profile,Network_Profile,State,Reason,Pool,Service_Engine_Group,Primary_SE_Name,
  Primary_SE_IP,Primary_SE_UUID,Secondary_SE_Name,Secondary_SE_IP,Secondary_SE_UUID,
  Active_Standby_SE_Tag,Cloud,Cloud_Type,Tenant,Real_Time_Metrics_Enabled,Metrics,VS_UUID

KEY BEHAVIORS
-------------
- Reads controllers and settings from a shared config.ini (see CONFIG below).
- Optionally processes controllers in parallel (ThreadPoolExecutor).
- Robust logging to file + console (use --debug for verbose logs).
- Backoff + retry for metrics fetch.
- “Metrics” is a single CSV field containing comma-separated metric values in the same order as
  SETTINGS.vsmetrics_list.

CONFIG (config.ini)
-------------------
[DEFAULT]
avi_user = admin
avi_pass = Admin@123

[SETTINGS]
avi_version       = 22.1.4
api_step          = 21600
api_limit         = 1
vsmetrics_list    = l4_client.avg_bandwidth,l4_client.avg_complete_conns
semetrics_list    = se_if.avg_bandwidth,se_if.max_peak_bandwidth
report_output_dir = ./reports
log_output_dir    = ./logs

[CONTROLLERS]
m00avientlb = admin,Admin@123
h00avientlb = admin,Admin@123

USAGE
-----
python3 alb-VS-Inventory-v0.3.py [--debug] [--parallel] [--processes 8]

REQUIREMENTS
------------
- Python 3.8+
- requests
- A reachable Avi/NSX-ALB Controller over HTTPS
- Controller user must have permissions to read VS inventory & metrics

NOTES
-----
- This script focuses only on Virtual Service inventory + metrics.
- The companion script alb-SE-Inventory-v0.3.py generates the SE inventory + metrics CSV.
"""

import os
import csv
import time
import json
import logging
import argparse
import configparser
from datetime import datetime
from urllib.parse import urlencode
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# -----------------------------
# Globals populated from config
# -----------------------------
AVI_VERSION = None
API_STEP = None
API_LIMIT = None
VSMETRICS = None


# ============ Logging ============
def _log(msg, level="info"):
    """Thin wrapper over logging so we can use strings for level."""
    getattr(logging, level)(msg)


def configure_logging(debug: bool, log_file_path: str) -> None:
    """
    Configure logging to file + console.
    """
    os.makedirs(os.path.dirname(log_file_path), exist_ok=True)
    level = logging.DEBUG if debug else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s: %(levelname)s: %(message)s",
        handlers=[logging.FileHandler(log_file_path), logging.StreamHandler()]
    )
    _log(f"Logging initialized. Level={'DEBUG' if debug else 'INFO'}")


# ============ Utilities ============
def validate_step(step: int) -> int:
    """
    Avi metrics 'step' must be >= 300 and a multiple of 300.
    We auto-correct to keep queries valid.
    """
    if step < 300:
        return 300
    if step % 300 != 0:
        step = ((step // 300) + 1) * 300
    return step


def convert_to_mbps(bits_per_sec):
    """
    Convert bits-per-second → MB/s (MiB/s). Returns 'N/A' on bad inputs.
    Useful for l4_client.avg_bandwidth.
    """
    return round(bits_per_sec / 1048576, 2) if isinstance(bits_per_sec, (int, float)) else "N/A"


def name_from_ref(ref: str) -> str:
    """
    Avi object references often end with `#<name>`. This extracts the trailing name if present.
    If not present, returns the raw ref tail.
    """
    if not ref or ref == "null":
        return "null"
    # Try splitting by '#', else fall back to last URL segment
    if "#" in ref:
        return ref.split("#")[-1]
    return ref.rstrip("/").split("/")[-1]


def semicolon_join(values):
    """Join non-empty values by ';' or return 'null' if nothing present."""
    values = [v for v in values if v]
    return ";".join(values) if values else "null"


# ============ HTTP / API ============
def avi_login(controller: str, user: str, pwd: str):
    """
    Perform Avi login: returns (sessionid, csrftoken) or (None, None) on failure.
    """
    url = f"https://{controller}/login"
    try:
        r = requests.post(url, data={"username": user, "password": pwd}, verify=False, timeout=15)
        if r.status_code != 200:
            _log(f"[{controller}] Login failed: {r.status_code} {r.text}", "error")
            return None, None
        cookies = r.cookies.get_dict()
        sid, csrft = cookies.get("avi-sessionid"), cookies.get("csrftoken")
        if not sid or not csrft:
            _log(f"[{controller}] Missing session/CSRF token after login", "error")
            return None, None
        _log(f"[{controller}] Login successful")
        return sid, csrft
    except Exception as e:
        _log(f"[{controller}] Login error: {e}", "error")
        return None, None


def _headers(controller: str, sid: str, csrft: str) -> dict:
    """Common Avi headers for API calls."""
    return {
        "X-Avi-Tenant": "admin",
        "X-Avi-Version": AVI_VERSION,
        "X-Csrftoken": csrft,
        "Cookie": f"avi-sessionid={sid}; csrftoken={csrft}"
    }


def backoff_get(url: str, headers: dict, attempts: int = 5, base_wait: int = 2):
    """
    GET with exponential backoff.
    - Logs attempts and returns Response or None after exhausting retries.
    """
    wait = base_wait
    for i in range(1, attempts + 1):
        try:
            _log(f"GET {url} (attempt {i}/{attempts})", "debug")
            r = requests.get(url, headers=headers, verify=False, timeout=60)
            if r.status_code == 200:
                return r
            _log(f"HTTP {r.status_code}: {r.text[:300]}...", "warning")
        except Exception as e:
            _log(f"GET error: {e}", "warning")
        time.sleep(wait)
        wait *= 2
    _log(f"Failed after {attempts} attempts: {url}", "error")
    return None


# ============ VS inventory + metrics ============
def fetch_vs_inventory(controller: str, sid: str, csrft: str):
    """
    Walk the paginated /api/virtualservice-inventory/ and yield normalized VS records.
    Each yielded record is a list *without* metrics; we append metrics right before writing.
    """
    url = f"https://{controller}/api/virtualservice-inventory/"
    headers = _headers(controller, sid, csrft)
    total = 0

    while url:
        r = backoff_get(url, headers=headers, attempts=3, base_wait=2)
        if not r:
            break
        payload = r.json()
        for item in payload.get("results", []):
            cfg, rt = item.get("config", {}), item.get("runtime", {})
            total += 1

            # Core identifiers
            vs_name = cfg.get("name", "null")
            vs_uuid = cfg.get("uuid", "null")

            # VIPs (IPv4 + IPv6) and Types
            vip_addrs, types = [], []
            for vip in cfg.get("vip", []):
                if "ip_address" in vip:
                    vip_addrs.append(vip["ip_address"].get("addr", ""))
                    types.append(vip["ip_address"].get("type", ""))
                if "ip6_address" in vip:
                    vip_addrs.append(vip["ip6_address"].get("addr", ""))
                    types.append(vip["ip6_address"].get("type", ""))
            vs_vip = semicolon_join(vip_addrs)
            vip_type = semicolon_join(types)

            # Port (first service)
            port = "null"
            if cfg.get("services"):
                port = cfg["services"][0].get("port", "null")

            # Flags
            vs_enabled = bool(cfg.get("enabled", False))
            traffic_enabled = bool(cfg.get("traffic_enabled", False))
            vip_as_snat = bool(cfg.get("use_vip_as_snat", False))
            auto_gw = bool(cfg.get("enable_autogw", False))
            vh_type = cfg.get("vh_type", "null")

            # Refs (names from '#')
            app_prof = name_from_ref(cfg.get("application_profile_ref", "null"))
            ssl_prof = name_from_ref(cfg.get("ssl_profile_ref", "null"))
            ssl_certs = semicolon_join([name_from_ref(x) for x in cfg.get("ssl_key_and_certificate_refs", [])])
            analytics_prof = name_from_ref(cfg.get("analytics_profile_ref", "null"))
            net_prof = name_from_ref(cfg.get("network_profile_ref", "null"))
            pool = name_from_ref(cfg.get("pool_ref", "null"))
            se_group = name_from_ref(cfg.get("se_group_ref", "null"))
            cloud = name_from_ref(cfg.get("cloud_ref", "null"))
            tenant = name_from_ref(cfg.get("tenant_ref", "null"))
            ssl_enabled = True if cfg.get("ssl_key_and_certificate_refs") else False

            # Runtime state
            state = rt.get("oper_status", {}).get("state", "null")
            reason = rt.get("oper_status", {}).get("reason", "null")
            cloud_type = rt.get("cloud_type", "null")

            # Real-time metrics flag + active/standby tag
            realtime_metrics = bool(cfg.get("metrics_realtime_update", False))
            active_standby_tag = cfg.get("active_standby_se_tag", "null")

            # Primary / Secondary SE (from vip_summary.service_engine list)
            pri_name = pri_ip = pri_uuid = "null"
            sec_name = sec_ip = sec_uuid = "null"
            for vsum in rt.get("vip_summary", []):
                for se in vsum.get("service_engine", []):
                    if se.get("primary"):
                        pri_name = se.get("name", "null")
                        pri_ip = se.get("mgmt_ip", {}).get("addr", "null")
                        pri_uuid = se.get("uuid", "null")
                    elif se.get("standby"):
                        sec_name = se.get("name", "null")
                        sec_ip = se.get("mgmt_ip", {}).get("addr", "null")
                        sec_uuid = se.get("uuid", "null")

            # Return list in the exact order requested (without metrics yet)
            yield [
                controller,                 # Controller
                vs_name,                    # Virtual_Service_Name
                vs_vip,                     # VS_VIP
                port,                       # Port
                vip_type,                   # Type(IPv4_/IPv6)
                vs_enabled,                 # VS_Enabled
                traffic_enabled,            # Traffic_Enabled
                ssl_enabled,                # SSL_Enabled
                vip_as_snat,                # VIP_as_SNAT
                auto_gw,                    # Auto_Gateway_Enabled
                vh_type,                    # VH_Type
                app_prof,                   # Application_Profile
                ssl_prof,                   # SSL_Profile
                ssl_certs,                  # SSL_Certificate_Name
                analytics_prof,             # Analytics_Profile
                net_prof,                   # Network_Profile
                state,                      # State
                reason,                     # Reason
                pool,                       # Pool
                se_group,                   # Service_Engine_Group
                pri_name,                   # Primary_SE_Name
                pri_ip,                     # Primary_SE_IP
                pri_uuid,                   # Primary_SE_UUID
                sec_name,                   # Secondary_SE_Name
                sec_ip,                     # Secondary_SE_IP
                sec_uuid,                   # Secondary_SE_UUID
                active_standby_tag,         # Active_Standby_SE_Tag
                cloud,                      # Cloud
                cloud_type,                 # Cloud_Type
                tenant,                     # Tenant
                realtime_metrics,           # Real_Time_Metrics_Enabled
                # (Metrics goes here later)
                vs_uuid                     # VS_UUID (we append metrics before this at write time)
            ]
        url = payload.get("next")

    _log(f"[{controller}] VS inventory fetched: {total} items")


def fetch_vs_metrics(controller: str, sid: str, csrft: str, vs_uuid: str):
    """
    Fetch per-VS metrics (per SETTINGS.vsmetrics_list) and return them as a list
    of values in the same order. Some metrics may be post-processed (e.g., bandwidth).
    """
    if not VSMETRICS:
        return []

    headers = _headers(controller, sid, csrft)
    step = validate_step(API_STEP)
    params = {"metric_id": VSMETRICS, "limit": API_LIMIT, "step": step}
    url = f"https://{controller}/api/analytics/metrics/virtualservice/{vs_uuid}/?" + urlencode(params)

    r = backoff_get(url, headers=headers, attempts=3, base_wait=2)
    if not r:
        # Return placeholders so CSV width remains constant
        return ["N/A"] * len(VSMETRICS.split(","))

    data = r.json()
    metrics = []
    for metric in VSMETRICS.split(","):
        series = next((s for s in data.get("series", []) if s.get("header", {}).get("name") == metric), None)
        value = series.get("data", [{}])[0].get("value", "N/A") if series and series.get("data") else "N/A"
        if metric == "l4_client.avg_bandwidth":
            value = convert_to_mbps(value)
        metrics.append(value)
    return metrics


# ============ Controller worker ============
def process_controller(controller: str, creds: tuple, writer: csv.writer):
    """
    Per-controller flow:
      1) Login, 2) Iterate VS inventory, 3) Fetch metrics per VS, 4) Write CSV rows.
    We keep CSV IO in the main process; this function receives the writer.
    """
    user, pwd = creds
    sid, csrft = avi_login(controller, user, pwd)
    if not sid or not csrft:
        return

    for row in fetch_vs_inventory(controller, sid, csrft):
        # row currently ends with VS_UUID. We need to inject Metrics before VS_UUID.
        vs_uuid = row[-1]
        metrics_values = fetch_vs_metrics(controller, sid, csrft, vs_uuid)
        metrics_cell = ",".join(map(str, metrics_values)) if metrics_values else ""
        final = row[:-1] + [metrics_cell] + [vs_uuid]
        writer.writerow(final)


# ============ Main ============
def main():
    # CLI
    parser = argparse.ArgumentParser(description="NSX ALB Virtual Service Inventory + Metrics (VS-only)")
    parser.add_argument("--debug", action="store_true", help="Enable debug logging")
    parser.add_argument("--parallel", action="store_true", help="Process controllers in parallel")
    parser.add_argument("--processes", type=int, default=8, help="Max parallel workers")
    args = parser.parse_args()

    # Config
    cfg = configparser.ConfigParser()
    if not cfg.read("config.ini"):
        print("ERROR: config.ini not found or unreadable.")
        return

    global AVI_VERSION, API_STEP, API_LIMIT, VSMETRICS
    AVI_VERSION = cfg.get("SETTINGS", "avi_version", fallback="22.1.4")
    API_STEP    = cfg.getint("SETTINGS", "api_step", fallback=21600)
    API_LIMIT   = cfg.getint("SETTINGS", "api_limit", fallback=1)
    VSMETRICS   = cfg.get("SETTINGS", "vsmetrics_list", fallback="").strip()

    report_dir = cfg.get("SETTINGS", "report_output_dir", fallback=".")
    log_dir    = cfg.get("SETTINGS", "log_output_dir", fallback=".")
    os.makedirs(report_dir, exist_ok=True)
    os.makedirs(log_dir, exist_ok=True)

    ts = datetime.now().strftime("%Y%m%dT%H%M%S")
    vs_csv = os.path.join(report_dir, f"avi-VSInventory_{ts}.csv")
    log_file = os.path.join(log_dir, f"{datetime.now():%Y-%m-%dT%H-%M-%S}_vs_inventory.log")
    configure_logging(args.debug, log_file)

    # Controllers
    default_user = cfg.get("DEFAULT", "avi_user", fallback="admin")
    default_pass = cfg.get("DEFAULT", "avi_pass", fallback="Admin@123")
    controllers = {}
    if "CONTROLLERS" in cfg:
        for name, combo in cfg["CONTROLLERS"].items():
            parts = [p.strip() for p in combo.split(",")]
            if len(parts) == 2:
                controllers[name.strip()] = (parts[0], parts[1])
            else:
                controllers[name.strip()] = (default_user, default_pass)
    else:
        _log("No [CONTROLLERS] found in config.ini", "error")
        return

    # Header as requested
    header = [
        "Controller","Virtual_Service_Name","VS_VIP","Port","Type(IPv4_/IPv6)","VS_Enabled",
        "Traffic_Enabled","SSL_Enabled","VIP_as_SNAT","Auto_Gateway_Enabled","VH_Type",
        "Application_Profile","SSL_Profile","SSL_Certificate_Name","Analytics_Profile",
        "Network_Profile","State","Reason","Pool","Service_Engine_Group","Primary_SE_Name",
        "Primary_SE_IP","Primary_SE_UUID","Secondary_SE_Name","Secondary_SE_IP","Secondary_SE_UUID",
        "Active_Standby_SE_Tag","Cloud","Cloud_Type","Tenant","Real_Time_Metrics_Enabled","Metrics","VS_UUID"
    ]

    with open(vs_csv, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(header)

        if args.parallel:
            _log(f"Parallel mode ON (workers={args.processes})")
            with ThreadPoolExecutor(max_workers=args.processes) as ex:
                futures = [ex.submit(process_controller, c, creds, writer) for c, creds in controllers.items()]
                for fut in as_completed(futures):
                    try:
                        fut.result()
                    except Exception as e:
                        _log(f"Worker error: {e}", "error")
        else:
            _log("Parallel mode OFF")
            for c, creds in controllers.items():
                process_controller(c, creds, writer)

    _log(f"VS report saved: {vs_csv}")


if __name__ == "__main__":
    main()
