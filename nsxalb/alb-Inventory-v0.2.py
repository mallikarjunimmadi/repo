#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
alb-VS-Inventory-v0.4.py — NSX Advanced Load Balancer (Avi) Virtual Service Inventory + Metrics

PURPOSE
-------
Collects Virtual Service (VS) configuration, runtime, and performance metrics from one or more
Avi/NSX-ALB Controllers and writes a CSV report with a fixed, user-specified column order.
All object reference names (Application Profile, SSL Profile, Cloud, SE Group, etc.) are
made human-readable without extra API calls by appending ?include_name=true to inventory requests.

OUTPUT
------
One CSV per run (timestamped), e.g.:
  avi-VSInventory_YYYYMMDDTHHMMSS.csv

Columns (exact order):
  Controller,Virtual_Service_Name,VS_VIP,Port,Type(IPv4_/IPv6),VS_Enabled,Traffic_Enabled,SSL_Enabled,
  VIP_as_SNAT,Auto_Gateway_Enabled,VH_Type,Application_Profile,SSL_Profile,SSL_Certificate_Name,
  Analytics_Profile,Network_Profile,State,Reason,Pool,Service_Engine_Group,Primary_SE_Name,
  Primary_SE_IP,Primary_SE_UUID,Secondary_SE_Name,Secondary_SE_IP,Secondary_SE_UUID,
  Active_Standby_SE_Tag,Cloud,Cloud_Type,Tenant,Real_Time_Metrics_Enabled,
  <one column per metric in SETTINGS.vsmetrics_list>,VS_UUID

CONFIG (config.ini)
-------------------
[DEFAULT]
avi_user = admin
avi_pass = Admin@123

[SETTINGS]
avi_version       = 22.1.4
api_step          = 21600           ; Will be auto-corrected to >=300 and multiple of 300
api_limit         = 1
vsmetrics_list    = l4_client.avg_bandwidth,l4_client.avg_complete_conns,l7_client.avg_client_rtt
report_output_dir = ./reports
log_output_dir    = ./logs

; (Backward compatibility: if vsmetrics_list is missing,
;  the script will also look for metrics_list/default_metrics like older versions.)

[CONTROLLERS]
m00avientlb = admin,Admin@123
h00avientlb = admin,Admin@123

USAGE
-----
python3 alb-VS-Inventory-v0.4.py [--debug] [--parallel] [--processes 8]
Optional: --controllers "m00avientlb,h00avientlb"

REQUIREMENTS
------------
- Python 3.8+
- requests

CHANGELOG
---------
v0.4 — Oct 2025
- Added '?include_name=true' to VS inventory to embed readable names, no extra ref lookups.
- Restored stable metrics-fetching flow from earlier script; now expands metrics to separate columns.
- Correct metrics query formatting: repeated 'metric_id=' params (not comma-encoded).
- Detailed docstrings, inline comments, and clearer logging.
- CSV write concurrency made safe in parallel mode via a threading lock.

v0.3 — (internal)
- Column order alignment and refactoring (this script supersedes v0.3).

v0.1 — (legacy)
- Monolithic inventory + metrics; metrics logic proved stable and is reused here.
"""

import os
import csv
import time
import json
import logging
import argparse
import configparser
from datetime import datetime
from typing import Dict, List, Tuple
from concurrent.futures import ThreadPoolExecutor, as_completed
from threading import Lock

import requests
from requests import Response
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# -----------------------------
# Globals populated from config
# -----------------------------
AVI_VERSION: str = None
API_STEP: int = None
API_LIMIT: int = None
VSMETRICS: str = None  # Comma-separated list from config (vsmetrics_list)

# Global CSV lock (for safe parallel writes)
CSV_LOCK = Lock()


# ============ Logging ============
def _log(msg: str, level: str = "info") -> None:
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
    Convert bits-per-second → MiB/s (MB/s base 2). Returns 'N/A' on bad inputs.
    Useful for l4_client.avg_bandwidth and similar.
    """
    return round(bits_per_sec / 1048576, 2) if isinstance(bits_per_sec, (int, float)) else "N/A"


def name_from_ref(ref: str) -> str:
    """
    Extract the readable name from an Avi ref (works when ?include_name=true is used).
    Example: ".../api/cloud/cloud-uuid#NSX-T-PROD" → "NSX-T-PROD"
    If '#' is missing, fall back to the last URL segment.
    """
    if not ref or ref == "null":
        return "null"
    if "#" in ref:
        return ref.split("#")[-1]
    return ref.rstrip("/").split("/")[-1]


def semicolon_join(values: List[str]) -> str:
    """Join non-empty values by ';' or return 'null' if nothing present."""
    vals = [v for v in values if v]
    return ";".join(vals) if vals else "null"


# ============ HTTP / API ============
def avi_login(controller: str, user: str, pwd: str) -> Tuple[str, str]:
    """
    Perform Avi login and return (sessionid, csrftoken) or (None, None) on failure.
    """
    url = f"https://{controller}/login"
    try:
        _log(f"[{controller}] Login as {user}")
        r = requests.post(url, data={"username": user, "password": pwd}, verify=False, timeout=15)
        if r.status_code != 200:
            _log(f"[{controller}] Login failed: {r.status_code} {r.text[:300]}...", "error")
            return None, None
        cookies = r.cookies.get_dict()
        sid, csrft = cookies.get("avi-sessionid"), cookies.get("csrftoken")
        if not sid or not csrft:
            _log(f"[{controller}] Missing session/CSRF token after login", "error")
            return None, None
        _log(f"[{controller}] Login OK")
        return sid, csrft
    except Exception as e:
        _log(f"[{controller}] Login error: {e}", "error")
        return None, None


def _headers(sid: str, csrft: str) -> Dict[str, str]:
    """Common Avi headers for API calls."""
    return {
        "X-Avi-Tenant": "admin",
        "X-Avi-Version": AVI_VERSION,
        "X-Csrftoken": csrft,
        "Cookie": f"avi-sessionid={sid}; csrftoken={csrft}"
    }


def backoff_get(url: str, headers: Dict[str, str], attempts: int = 5, base_wait: int = 2) -> Response | None:
    """
    GET with exponential backoff. Returns Response or None after exhausting retries.
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


# ============ Service Engine name lookup (fallback only) ============
def build_se_name_lookup(controller: str, sid: str, csrft: str) -> Dict[str, str]:
    """
    Build a mapping of SE UUID → SE Name using /api/serviceengine-inventory/.
    This is a fallback to populate SE names if runtime doesn't include 'name'.
    """
    headers = _headers(sid, csrft)
    url = f"https://{controller}/api/serviceengine-inventory/?include_name=true"
    lookup: Dict[str, str] = {}
    total = 0

    while url:
        r = backoff_get(url, headers=headers, attempts=3, base_wait=2)
        if not r:
            break
        payload = r.json()
        for item in payload.get("results", []):
            total += 1
            se_uuid = item.get("uuid")
            se_name = item.get("config", {}).get("name", "null")
            if se_uuid:
                lookup[se_uuid] = se_name
        url = payload.get("next")

    _log(f"[{controller}] SE name lookup size: {len(lookup)} (scanned {total} SEs)")
    return lookup


# ============ VS inventory + metrics ============
def iter_vs_rows(controller: str, sid: str, csrft: str, se_name_lookup: Dict[str, str]):
    """
    Iterate the paginated /api/virtualservice-inventory/?include_name=true and
    yield normalized VS rows (WITHOUT metrics). Metrics will be appended before write.
    """
    headers = _headers(sid, csrft)
    # IMPORTANT: include_name=true makes refs end in '#Readable-Name' → no extra lookups needed
    url = f"https://{controller}/api/virtualservice-inventory/?include_name=true"
    total = 0

    while url:
        r = backoff_get(url, headers=headers, attempts=3, base_wait=2)
        if not r:
            break
        payload = r.json()
        for item in payload.get("results", []):
            total += 1
            cfg, rt = item.get("config", {}), item.get("runtime", {})
            vs_name = cfg.get("name", "null")
            vs_uuid = cfg.get("uuid", "null")

            # VIPs + Types (IPv4 + IPv6, semicolon separated)
            vip_addrs, vip_types = [], []
            for vip in cfg.get("vip", []):
                if "ip_address" in vip:
                    vip_addrs.append(vip["ip_address"].get("addr", ""))
                    vip_types.append(vip["ip_address"].get("type", ""))
                if "ip6_address" in vip:
                    vip_addrs.append(vip["ip6_address"].get("addr", ""))
                    vip_types.append(vip["ip6_address"].get("type", ""))
            vs_vip = semicolon_join(vip_addrs)
            vip_type = semicolon_join(vip_types)

            # Port (first service)
            port = "null"
            if cfg.get("services"):
                port = cfg["services"][0].get("port", "null")

            # Flags / Config
            vs_enabled       = bool(cfg.get("enabled", False))
            traffic_enabled  = bool(cfg.get("traffic_enabled", False))
            ssl_enabled      = True if cfg.get("ssl_key_and_certificate_refs") else False
            vip_as_snat      = bool(cfg.get("use_vip_as_snat", False))
            auto_gw          = bool(cfg.get("enable_autogw", False))
            vh_type          = cfg.get("vh_type", "null")

            # Ref names via include_name=true
            app_prof     = name_from_ref(cfg.get("application_profile_ref", "null"))
            ssl_prof     = name_from_ref(cfg.get("ssl_profile_ref", "null"))
            ssl_certs    = semicolon_join([name_from_ref(x) for x in cfg.get("ssl_key_and_certificate_refs", [])])
            analytics_pr = name_from_ref(cfg.get("analytics_profile_ref", "null"))
            net_prof     = name_from_ref(cfg.get("network_profile_ref", "null"))
            pool_name    = name_from_ref(cfg.get("pool_ref", "null"))
            se_group     = name_from_ref(cfg.get("se_group_ref", "null"))
            cloud_name   = name_from_ref(cfg.get("cloud_ref", "null"))
            tenant_name  = name_from_ref(cfg.get("tenant_ref", "null"))

            # Runtime
            state      = rt.get("oper_status", {}).get("state", "null")
            reason     = rt.get("oper_status", {}).get("reason", "null")
            cloud_type = rt.get("cloud_type", "null")

            # Real-time metrics & Active/Standby tag
            realtime_metrics = bool(cfg.get("metrics_realtime_update", False))
            active_standby   = cfg.get("active_standby_se_tag", "null")

            # Primary / Secondary SE
            pri_name = pri_ip = pri_uuid = "null"
            sec_name = sec_ip = sec_uuid = "null"
            for vsum in rt.get("vip_summary", []):
                for se in vsum.get("service_engine", []):
                    is_primary = bool(se.get("primary"))
                    is_standby = bool(se.get("standby"))
                    se_uuid = se.get("uuid")
                    # Prefer runtime-provided name; fallback to lookup map
                    se_name = se.get("name") or (se_name_lookup.get(se_uuid, "null") if se_uuid else "null")
                    se_mgmt = se.get("mgmt_ip", {}).get("addr", "null")
                    if is_primary:
                        pri_uuid, pri_name, pri_ip = se_uuid or "null", se_name, se_mgmt
                    elif is_standby:
                        sec_uuid, sec_name, sec_ip = se_uuid or "null", se_name, se_mgmt

            # Yield in EXACT requested order (without metrics yet):
            # NOTE: We put VS_UUID at the end; metrics will be appended just before it at write time.
            yield [
                controller,             # Controller
                vs_name,                # Virtual_Service_Name
                vs_vip,                 # VS_VIP
                port,                   # Port
                vip_type,               # Type(IPv4_/IPv6)
                vs_enabled,             # VS_Enabled
                traffic_enabled,        # Traffic_Enabled
                ssl_enabled,            # SSL_Enabled
                vip_as_snat,            # VIP_as_SNAT
                auto_gw,                # Auto_Gateway_Enabled
                vh_type,                # VH_Type
                app_prof,               # Application_Profile
                ssl_prof,               # SSL_Profile
                ssl_certs,              # SSL_Certificate_Name
                analytics_pr,           # Analytics_Profile
                net_prof,               # Network_Profile
                state,                  # State
                reason,                 # Reason
                pool_name,              # Pool
                se_group,               # Service_Engine_Group
                pri_name,               # Primary_SE_Name
                pri_ip,                 # Primary_SE_IP
                pri_uuid,               # Primary_SE_UUID
                sec_name,               # Secondary_SE_Name
                sec_ip,                 # Secondary_SE_IP
                sec_uuid,               # Secondary_SE_UUID
                active_standby,         # Active_Standby_SE_Tag
                cloud_name,             # Cloud
                cloud_type,             # Cloud_Type
                tenant_name,            # Tenant
                realtime_metrics,       # Real_Time_Metrics_Enabled
                vs_uuid                 # VS_UUID (metrics will be appended before this)
            ]
        url = payload.get("next")

    _log(f"[{controller}] VS inventory fetched: {total} items")


def fetch_vs_metrics(controller: str, sid: str, csrft: str, vs_uuid: str, metric_ids: List[str]) -> List:
    """
    Fetch per-VS metrics and return values in the same order as 'metric_ids'.
    Uses repeated 'metric_id=' query params (not comma-separated) to avoid encoding issues.
    """
    if not metric_ids:
        return []

    headers = _headers(sid, csrft)
    step = validate_step(API_STEP)

    # Build params as a list of tuples to repeat 'metric_id'
    params = [("metric_id", m) for m in metric_ids]
    params += [("limit", API_LIMIT), ("step", step)]

    url = f"https://{controller}/api/analytics/metrics/virtualservice/{vs_uuid}/"
    try:
        r = requests.get(url, headers=headers, params=params, verify=False, timeout=45)
        if r.status_code != 200:
            _log(f"[{controller}] Metrics fetch failed for VS {vs_uuid}: {r.status_code} {r.text[:200]}...", "warning")
            return ["N/A"] * len(metric_ids)

        data = r.json()
        series = data.get("series", [])
        out: List = []
        for m in metric_ids:
            s = next((x for x in series if x.get("header", {}).get("name") == m), None)
            val = s.get("data", [{}])[0].get("value", "N/A") if s and s.get("data") else "N/A"
            # Post-process known units
            if m == "l4_client.avg_bandwidth":
                val = convert_to_mbps(val)
            out.append(val)

        _log(f"[{controller}] Metrics OK for VS {vs_uuid}: {len(series)} series", "debug")
        return out

    except Exception as e:
        _log(f"[{controller}] Metrics error for VS {vs_uuid}: {e}", "error")
        return ["N/A"] * len(metric_ids)


# ============ Controller worker ============
def process_controller(controller: str, creds: Tuple[str, str], writer: csv.writer, metric_headers: List[str]) -> None:
    """
    Per-controller flow:
      1) Login
      2) Optionally build SE name lookup (fallback)
      3) Iterate VS inventory rows
      4) Fetch metrics per VS
      5) Write CSV rows (thread-safe)
    """
    user, pwd = creds
    sid, csrft = avi_login(controller, user, pwd)
    if not sid or not csrft:
        return

    # Fallback SE name map (runtime usually includes names, but this helps if missing)
    se_name_lookup = build_se_name_lookup(controller, sid, csrft)

    metric_ids = metric_headers[:]  # already in desired order (names as in config)
    for row in iter_vs_rows(controller, sid, csrft, se_name_lookup):
        # row currently ends with VS_UUID; inject metrics before VS_UUID
        vs_uuid = row[-1]
        metrics_vals = fetch_vs_metrics(controller, sid, csrft, vs_uuid, metric_ids)
        final = row[:-1] + metrics_vals + [vs_uuid]

        # Thread-safe CSV write
        with CSV_LOCK:
            writer.writerow(final)


# ============ Main ============
def main():
    # CLI
    parser = argparse.ArgumentParser(description="NSX ALB Virtual Service Inventory + Metrics (VS-only)")
    parser.add_argument("--debug", action="store_true", help="Enable debug logging")
    parser.add_argument("--parallel", action="store_true", help="Process controllers in parallel")
    parser.add_argument("--processes", type=int, default=8, help="Max parallel workers")
    parser.add_argument("--controllers", type=str, help="Comma-separated list of controllers (override config.ini)")
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

    # Metrics list: prefer vsmetrics_list; else fallback to old keys for backward compatibility
    VSMETRICS = (
        cfg.get("SETTINGS", "vsmetrics_list", fallback="").strip()
        or cfg.get("SETTINGS", "metrics_list", fallback="").strip()
        or cfg.get("SETTINGS", "default_metrics", fallback="l4_client.avg_bandwidth,l4_client.avg_complete_conns").strip()
    )

    report_dir = cfg.get("SETTINGS", "report_output_dir", fallback=".")
    log_dir    = cfg.get("SETTINGS", "log_output_dir", fallback=".")
    os.makedirs(report_dir, exist_ok=True)
    os.makedirs(log_dir, exist_ok=True)

    ts = datetime.now().strftime("%Y%m%dT%H%M%S")
    vs_csv  = os.path.join(report_dir, f"avi-VSInventory_{ts}.csv")
    log_file = os.path.join(log_dir, f"{datetime.now():%Y-%m-%dT%H-%M-%S}_vs_inventory.log")
    configure_logging(args.debug, log_file)
    _log(f"Using metrics: {VSMETRICS}")

    # Controllers
    default_user = cfg.get("DEFAULT", "avi_user", fallback="admin")
    default_pass = cfg.get("DEFAULT", "avi_pass", fallback="Admin@123")
    controllers_cfg: Dict[str, Tuple[str, str]] = {}

    if "CONTROLLERS" in cfg:
        for name, combo in cfg["CONTROLLERS"].items():
            parts = [p.strip() for p in combo.split(",")]
            if len(parts) == 2 and parts[0] and parts[1]:
                controllers_cfg[name.strip()] = (parts[0], parts[1])
            else:
                controllers_cfg[name.strip()] = (default_user, default_pass)
    else:
        _log("No [CONTROLLERS] found in config.ini", "error")
        return

    if args.controllers:
        requested = [c.strip() for c in args.controllers.split(",") if c.strip()]
        controllers = {c: controllers_cfg[c] for c in requested if c in controllers_cfg}
        missing = [c for c in requested if c not in controllers_cfg]
        if missing:
            _log(f"Requested controllers not found in config.ini: {', '.join(missing)}", "warning")
        if not controllers:
            _log("No valid controllers to process. Exiting.", "error")
            return
    else:
        controllers = controllers_cfg

    # Build header in the EXACT order you requested
    fixed_header = [
        "Controller","Virtual_Service_Name","VS_VIP","Port","Type(IPv4_/IPv6)","VS_Enabled",
        "Traffic_Enabled","SSL_Enabled","VIP_as_SNAT","Auto_Gateway_Enabled","VH_Type",
        "Application_Profile","SSL_Profile","SSL_Certificate_Name","Analytics_Profile",
        "Network_Profile","State","Reason","Pool","Service_Engine_Group","Primary_SE_Name",
        "Primary_SE_IP","Primary_SE_UUID","Secondary_SE_Name","Secondary_SE_IP","Secondary_SE_UUID",
        "Active_Standby_SE_Tag","Cloud","Cloud_Type","Tenant","Real_Time_Metrics_Enabled"
    ]
    metric_headers = [m.strip() for m in VSMETRICS.split(",")] if VSMETRICS else []
    final_header = fixed_header + metric_headers + ["VS_UUID"]

    with open(vs_csv, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(final_header)

        if args.parallel:
            _log(f"Parallel mode ON (workers={args.processes})")
            with ThreadPoolExecutor(max_workers=args.processes) as ex:
                futures = [ex.submit(process_controller, c, creds, writer, metric_headers)
                           for c, creds in controllers.items()]
                for fut in as_completed(futures):
                    try:
                        fut.result()
                    except Exception as e:
                        _log(f"Worker error: {e}", "error")
        else:
            _log("Parallel mode OFF")
            for c, creds in controllers.items():
                process_controller(c, creds, writer, metric_headers)

    _log(f"VS report saved: {vs_csv}")


if __name__ == "__main__":
    main()
