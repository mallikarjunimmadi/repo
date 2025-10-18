#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
alb-VS-Inventory-SDK-v1.0.py — NSX Advanced Load Balancer (Avi) Virtual Service Inventory + Metrics (SDK-based)

PURPOSE
-------
Generate a CSV report of Virtual Services across one or more NSX ALB (Avi) Controllers using the official Avi SDK.
This script:
  1) Logs into each controller using avisdk.ApiSession (handles cookies, CSRF, retries).
  2) Fetches VS *config* via /api/virtualservice?include_name=true (so all *_ref fields have '#Friendly-Name').
  3) Fetches VS *runtime* via /api/virtualservice-inventory/ (oper_status, SE primary/standby, cloud_type, etc.).
  4) Merges CONFIG + RUNTIME by VS UUID.
  5) Fetches VS *metrics* (expanded into individual columns, order driven by config).
  6) Writes a single CSV (timestamped) with a fixed header order.

WHY SDK?
--------
- Removes manual login/header/pagination code (less fragile).
- Easier metrics calls (multi 'metric_id' params).
- Provides utilities (ApiUtils) to extract names from refs (#suffix or object lookups).
- Aligns with Avi Controller API versions.

CONFIGURATION (config.ini)
--------------------------
[DEFAULT]
avi_user = admin
avi_pass = <your_password>

[SETTINGS]
avi_version       = 22.1.7
api_step          = 21600                     ; metrics step; script auto-falls back to 900 then 300 if no data
api_limit         = 1                         ; samples per series (1 = most recent)
vsmetrics_list    = l4_client.avg_bandwidth,l4_client.avg_new_established_conns,l4_client.avg_complete_conns
metrics_list      = <optional fallback>
default_metrics   = l4_client.avg_bandwidth,l4_client.avg_complete_conns
report_output_dir = /home/imallikarjun/scripts/reports
log_output_dir    = /home/imallikarjun/scripts/nsxalb/logs

[CONTROLLERS]
m00avientlb =                 ; uses DEFAULT creds
; h00avientlb = user,Secret!  ; example of per-controller override

USAGE
-----
python3 alb-VS-Inventory-SDK-v1.0.py [--debug] [--parallel] [--processes 8] [--controllers "m00avientlb,h00avientlb"]

OUTPUT
------
CSV saved to report_output_dir as: avi-VSInventory_YYYYMMDDTHHMMSS.csv

CSV COLUMNS (exact order; metrics expand in the middle)
------------------------------------------------------
Controller,Virtual_Service_Name,VS_VIP,Port,Type(IPv4_/IPv6),VS_Enabled,Traffic_Enabled,SSL_Enabled,
VIP_as_SNAT,Auto_Gateway_Enabled,VH_Type,Application_Profile,SSL_Profile,SSL_Certificate_Name,
Analytics_Profile,Network_Profile,State,Reason,Pool,Service_Engine_Group,Primary_SE_Name,
Primary_SE_IP,Primary_SE_UUID,Secondary_SE_Name,Secondary_SE_IP,Secondary_SE_UUID,
Active_Standby_SE_Tag,Cloud,Cloud_Type,Tenant,Real_Time_Metrics_Enabled,<metric_1>,...,<metric_N>,VS_UUID
"""

import os
import csv
import sys
import time
import logging
import argparse
import configparser
from datetime import datetime
from typing import Dict, List, Tuple, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed
from threading import Lock

# --- Third-party: Avi SDK ---
# pip install avisdk
from avi.sdk.avi_api import ApiSession, APIError
from avi.sdk.utils.api_utils import ApiUtils

# ========= Globals populated from config =========
AVI_VERSION: str = "22.1.7"
API_STEP: int = 21600
API_LIMIT: int = 1
METRIC_IDS: List[str] = []
CSV_LOCK = Lock()

# ========= Logging =========
def _log(msg: str, level: str = "info") -> None:
    getattr(logging, level)(msg)

def configure_logging(debug: bool, log_file_path: str) -> None:
    os.makedirs(os.path.dirname(log_file_path), exist_ok=True)
    level = logging.DEBUG if debug else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s: %(levelname)s: %(message)s",
        handlers=[logging.FileHandler(log_file_path), logging.StreamHandler(sys.stdout)]
    )
    _log(f"Logging initialized. Level={'DEBUG' if debug else 'INFO'}")

# ========= Small helpers =========
def validate_step(step: int) -> int:
    """Avi metrics step must be >=300 and multiple of 300."""
    if step < 300:
        return 300
    if step % 300 != 0:
        step = ((step // 300) + 1) * 300
    return step

def semicolon_join(values: List[str]) -> str:
    vals = [v for v in values if v]
    return ";".join(vals) if vals else "null"

def extract_vips_and_types(cfg: dict) -> Tuple[str, str]:
    """Return (vip_addrs, vip_types) as semicolon-joined strings from VS config.vip[]."""
    vip_addrs, vip_types = [], []
    for v in cfg.get("vip", []):
        if "ip_address" in v:
            vip_addrs.append(v["ip_address"].get("addr", ""))
            vip_types.append(v["ip_address"].get("type", ""))
        if "ip6_address" in v:
            vip_addrs.append(v["ip6_address"].get("addr", ""))
            vip_types.append(v["ip6_address"].get("type", ""))
    return semicolon_join(vip_addrs), semicolon_join(vip_types)

def ssl_enabled_from_config(cfg: dict) -> bool:
    """SSL is 'enabled' if any service.enable_ssl is True OR ssl profile/cert is linked."""
    services = [s for s in cfg.get("services", []) if isinstance(s, dict)]
    ssl_service = any(s.get("enable_ssl") for s in services)
    return bool(ssl_service or cfg.get("ssl_profile_ref") or cfg.get("ssl_key_and_certificate_refs"))

def realtime_metrics_enabled(cfg: dict) -> bool:
    """Check analytics_policy.metrics_realtime_update.enabled OR top-level metrics_realtime_update."""
    ap = cfg.get("analytics_policy", {})
    if isinstance(ap, dict):
        mru = ap.get("metrics_realtime_update", {})
        if isinstance(mru, dict) and mru.get("enabled"):
            return True
    # some versions expose a top-level metrics_realtime_update
    mru_top = cfg.get("metrics_realtime_update")
    if isinstance(mru_top, dict):
        return bool(mru_top.get("enabled"))
    if isinstance(mru_top, bool):
        return mru_top
    return False

# ========= Metric fetch (with fallback steps) =========
def fetch_vs_metrics(api: ApiSession, controller: str, vs_uuid: str, metric_ids: List[str]) -> List:
    """
    Fetch metrics for a VS with smart fallbacks:
      1) configured step
      2) step=900 (15m)
      3) step=300 (5m)
    Each try uses repeated ('metric_id', <id>) params and current API_LIMIT.
    """
    if not metric_ids:
        return []
    def try_fetch(step: int, limit: int) -> Optional[List]:
        params = [("metric_id", m) for m in metric_ids]
        params += [("limit", limit), ("step", step)]
        try:
            resp = api.get(f"analytics/metrics/virtualservice/{vs_uuid}/", params=params)
        except APIError as e:
            _log(f"[{controller}] Metrics APIError {vs_uuid}: {e}", "warning")
            return None
        if resp.status_code != 200:
            _log(f"[{controller}] Metrics HTTP {resp.status_code} {vs_uuid}: {resp.text[:180]}...", "warning")
            return None
        series = resp.json().get("series", [])
        out = []
        # Preserve the order in metric_ids
        for m in metric_ids:
            s = next((x for x in series if x.get("header", {}).get("name") == m), None)
            val = "N/A"
            if s:
                data = s.get("data") or s.get("series") or []  # versions vary: 'data' preferred
                if isinstance(data, list) and data:
                    val = data[0].get("value", "N/A")
            # optionally convert bandwidth from bits/s -> MiB/s if you prefer
            if m == "l4_client.avg_bandwidth" and isinstance(val, (int, float)):
                val = round(val / 1048576, 2)  # MiB/s
            out.append(val)
        return out

    step1 = validate_step(API_STEP)
    vals = try_fetch(step1, API_LIMIT)
    if vals and any(v != "N/A" for v in vals):
        _log(f"[{controller}] Metrics OK {vs_uuid} @ step={step1}", "debug")
        return vals

    vals = try_fetch(900, max(API_LIMIT, 5))
    if vals and any(v != "N/A" for v in vals):
        _log(f"[{controller}] Metrics OK {vs_uuid} @ step=900", "debug")
        return vals

    vals = try_fetch(300, max(API_LIMIT, 10))
    if vals and any(v != "N/A" for v in vals):
        _log(f"[{controller}] Metrics OK {vs_uuid} @ step=300", "debug")
        return vals

    _log(f"[{controller}] No metrics for {vs_uuid} after fallbacks", "warning")
    return vals if vals else ["N/A"] * len(metric_ids)

# ========= Per-controller worker =========
def process_controller(controller: str, creds: Tuple[str, str], writer: csv.writer, metric_headers: List[str]) -> None:
    user, pwd = creds
    try:
        api = ApiSession.get_session(controller, user, pwd, tenant='admin', api_version=AVI_VERSION)
        api_utils = ApiUtils(api)
    except Exception as e:
        _log(f"[{controller}] Login error: {e}", "error")
        return

    # 1) CONFIG with include_name=true (ensures '#Friendly-Name' suffixes exist on refs)
    cfg_map: Dict[str, dict] = {}  # vs_uuid -> config dict (normalized subset)
    total_cfg = 0
    for cfg in api.get_iter('virtualservice', params={'include_name': True, 'page_size': 200}):
        total_cfg += 1
        vs_uuid = cfg.get("uuid", "null")
        vs_name = cfg.get("name", "null")

        # VIPs + address type
        vs_vip, vip_type = extract_vips_and_types(cfg)

        # Primary port (first service if present)
        port = cfg.get("services", [{}])[0].get("port", "null") if cfg.get("services") else "null"

        # Flags
        vs_enabled      = bool(cfg.get("enabled", False))
        traffic_enabled = bool(cfg.get("traffic_enabled", False))
        vip_as_snat     = bool(cfg.get("use_vip_as_snat", False))
        auto_gw         = bool(cfg.get("enable_autogw", False))
        vh_type         = cfg.get("vh_type", "null")
        ssl_enabled     = ssl_enabled_from_config(cfg)
        rtm             = realtime_metrics_enabled(cfg)

        # Friendly names from refs (ApiUtils handles '#name' OR resolves by GET)
        def nm(ref: Optional[str]) -> str:
            if not ref:
                return "null"
            try:
                return api_utils.get_name_from_ref(ref) or "null"
            except Exception:
                return "null"

        app_prof     = nm(cfg.get("application_profile_ref"))
        ssl_prof     = nm(cfg.get("ssl_profile_ref"))
        analytics_pr = nm(cfg.get("analytics_profile_ref"))
        net_prof     = nm(cfg.get("network_profile_ref"))
        pool_name    = nm(cfg.get("pool_ref"))
        se_group     = nm(cfg.get("se_group_ref"))
        cloud_name   = nm(cfg.get("cloud_ref"))
        tenant_name  = nm(cfg.get("tenant_ref"))
        cloud_type   = cfg.get("cloud_type", "null")
        active_stby  = cfg.get("active_standby_se_tag", "null")

        # Multiple certs → join by ';'
        cert_refs = cfg.get("ssl_key_and_certificate_refs", [])
        ssl_certs = []
        for ref in cert_refs or []:
            try:
                ssl_certs.append(api_utils.get_name_from_ref(ref) or "")
            except Exception:
                pass
        ssl_certs_join = semicolon_join(ssl_certs)

        cfg_map[vs_uuid] = {
            "vs_name": vs_name, "vs_vip": vs_vip, "vip_type": vip_type, "port": port,
            "vs_enabled": vs_enabled, "traffic_enabled": traffic_enabled, "ssl_enabled": ssl_enabled,
            "vip_as_snat": vip_as_snat, "auto_gw": auto_gw, "vh_type": vh_type,
            "app_prof": app_prof, "ssl_prof": ssl_prof, "ssl_certs": ssl_certs_join,
            "analytics_pr": analytics_pr, "net_prof": net_prof, "pool_name": pool_name,
            "se_group": se_group, "cloud_name": cloud_name, "tenant_name": tenant_name,
            "cloud_type": cloud_type, "active_stby": active_stby, "rtm": rtm
        }
    _log(f"[{controller}] VS config fetched: {total_cfg} items", "info")

    # 2) RUNTIME via inventory (state, reason, SE primary/standby, cloud_type runtime)
    rt_map: Dict[str, dict] = {}
    total_rt = 0
    for inv in api.get_iter('virtualservice-inventory', params={'page_size': 200}):
        total_rt += 1
        cfg = inv.get("config", {})
        rt  = inv.get("runtime", {})
        vs_uuid = cfg.get("uuid", "null")

        state  = rt.get("oper_status", {}).get("state", "null")
        reason = rt.get("oper_status", {}).get("reason", "null")
        cloud_type_rt = rt.get("cloud_type", "null")

        # Derive primary/secondary SE info from runtime.vip_summary[].service_engine[]
        pri_name = pri_ip = pri_uuid = "null"
        sec_name = sec_ip = sec_uuid = "null"
        for vsum in rt.get("vip_summary", []):
            for se in vsum.get("service_engine", []):
                se_name = se.get("name", "null")
                if not se_name and se.get("se_ref"):
                    try:
                        se_name = ApiUtils(api).get_name_from_ref(se["se_ref"]) or "null"
                    except Exception:
                        se_name = "null"
                se_ip   = se.get("mgmt_ip", {}).get("addr", "null")
                # uuid best-effort from ref path (SDK lacks direct helper for UUID slicing)
                se_ref  = se.get("se_ref", "")
                se_uuid = "null"
                if se_ref:
                    try:
                        se_uuid = se_ref.split("/")[-1].split("#")[0] or "null"
                    except Exception:
                        pass

                if se.get("primary"):
                    pri_name, pri_ip, pri_uuid = se_name, se_ip, se_uuid
                elif se.get("standby"):
                    sec_name, sec_ip, sec_uuid = se_name, se_ip, se_uuid

        rt_map[vs_uuid] = {
            "state": state, "reason": reason, "cloud_type_rt": cloud_type_rt,
            "pri_name": pri_name, "pri_ip": pri_ip, "pri_uuid": pri_uuid,
            "sec_name": sec_name, "sec_ip": sec_ip, "sec_uuid": sec_uuid
        }
    _log(f"[{controller}] VS runtime fetched: {total_rt} items", "info")

    # 3) Emit rows (merge config + runtime + metrics) in the exact requested order
    for vs_uuid, c in cfg_map.items():
        r = rt_map.get(vs_uuid, {})
        state  = r.get("state", "null")
        reason = r.get("reason", "null")
        cloud_type_final = c["cloud_type"] if c["cloud_type"] not in (None, "null") else r.get("cloud_type_rt", "null")

        # Metrics (expanded columns)
        metric_vals = fetch_vs_metrics(api, controller, vs_uuid, metric_headers)

        row = [
            controller,                          # Controller
            c["vs_name"],                        # Virtual_Service_Name
            c["vs_vip"],                         # VS_VIP
            c["port"],                           # Port
            c["vip_type"],                       # Type(IPv4_/IPv6)
            c["vs_enabled"],                     # VS_Enabled
            c["traffic_enabled"],                # Traffic_Enabled
            c["ssl_enabled"],                    # SSL_Enabled
            c["vip_as_snat"],                    # VIP_as_SNAT
            c["auto_gw"],                        # Auto_Gateway_Enabled
            c["vh_type"],                        # VH_Type
            c["app_prof"],                       # Application_Profile
            c["ssl_prof"],                       # SSL_Profile
            c["ssl_certs"],                      # SSL_Certificate_Name
            c["analytics_pr"],                   # Analytics_Profile
            c["net_prof"],                       # Network_Profile
            state,                               # State
            reason,                              # Reason
            c["pool_name"],                      # Pool
            c["se_group"],                       # Service_Engine_Group
            r.get("pri_name", "null"),           # Primary_SE_Name
            r.get("pri_ip", "null"),             # Primary_SE_IP
            r.get("pri_uuid", "null"),           # Primary_SE_UUID
            r.get("sec_name", "null"),           # Secondary_SE_Name
            r.get("sec_ip", "null"),             # Secondary_SE_IP
            r.get("sec_uuid", "null"),           # Secondary_SE_UUID
            c["active_stby"],                    # Active_Standby_SE_Tag
            c["cloud_name"],                     # Cloud
            cloud_type_final,                    # Cloud_Type
            c["tenant_name"],                    # Tenant
            c["rtm"],                            # Real_Time_Metrics_Enabled
        ] + metric_vals + [vs_uuid]              # metrics..., VS_UUID

        with CSV_LOCK:
            writer.writerow(row)

# ========= Main =========
def main():
    parser = argparse.ArgumentParser(description="NSX ALB Virtual Service Inventory + Metrics (SDK-based)")
    parser.add_argument("--debug", action="store_true", help="Enable debug logging")
    parser.add_argument("--parallel", action="store_true", help="Process controllers in parallel")
    parser.add_argument("--processes", type=int, default=8, help="Max worker threads")
    parser.add_argument("--controllers", type=str, help="Comma-separated controllers to run (override config.ini)")
    args = parser.parse_args()

    # Load config.ini
    cfg = configparser.ConfigParser()
    if not cfg.read("config.ini"):
        print("ERROR: config.ini not found or unreadable.", file=sys.stderr)
        sys.exit(1)

    # Require DEFAULT credentials (your preference)
    d_user = cfg.get("DEFAULT", "avi_user", fallback="")
    d_pass = cfg.get("DEFAULT", "avi_pass", fallback="")
    if not d_user or not d_pass:
        print("ERROR: [DEFAULT] avi_user/avi_pass missing in config.ini", file=sys.stderr)
        sys.exit(1)

    global AVI_VERSION, API_STEP, API_LIMIT, METRIC_IDS
    AVI_VERSION = cfg.get("SETTINGS", "avi_version", fallback="22.1.7")
    API_STEP    = cfg.getint("SETTINGS", "api_step", fallback=21600)
    API_LIMIT   = cfg.getint("SETTINGS", "api_limit", fallback=1)

    metrics_str = (
        cfg.get("SETTINGS", "vsmetrics_list", fallback="").strip()
        or cfg.get("SETTINGS", "metrics_list", fallback="").strip()
        or cfg.get("SETTINGS", "default_metrics", fallback="l4_client.avg_bandwidth,l4_client.avg_complete_conns").strip()
    )
    METRIC_IDS = [m.strip() for m in metrics_str.split(",") if m.strip()]

    report_dir = cfg.get("SETTINGS", "report_output_dir", fallback=".")
    log_dir    = cfg.get("SETTINGS", "log_output_dir", fallback=".")
    os.makedirs(report_dir, exist_ok=True)
    os.makedirs(log_dir, exist_ok=True)

    ts = datetime.now().strftime("%Y%m%dT%H%M%S")
    out_csv = os.path.join(report_dir, f"avi-VSInventory_{ts}.csv")
    log_file= os.path.join(log_dir, f"{datetime.now():%Y-%m-%dT%H-%M-%S}_vs_inventory_sdk.log")
    configure_logging(args.debug, log_file)
    _log(f"Controllers mode: {'parallel' if args.parallel else 'sequential'}")
    _log(f"Metrics: {METRIC_IDS} | step={API_STEP} | limit={API_LIMIT}")

    # Build controller -> (user, pass) map
    controllers_cfg: Dict[str, Tuple[str, str]] = {}
    if "CONTROLLERS" in cfg:
        for name, combo in cfg["CONTROLLERS"].items():
            key = name.strip()
            if not key:
                continue
            parts = [p.strip() for p in (combo or "").split(",")] if combo is not None else []
            if len(parts) == 2 and parts[0] and parts[1]:
                controllers_cfg[key] = (parts[0], parts[1])    # inline override
            else:
                controllers_cfg[key] = (d_user, d_pass)        # default creds
    else:
        _log("ERROR: No [CONTROLLERS] section in config.ini", "error")
        sys.exit(1)

    # CLI override
    if args.controllers:
        requested = [c.strip() for c in args.controllers.split(",") if c.strip()]
        missing = [c for c in requested if c not in controllers_cfg]
        if missing:
            _log(f"Requested controllers not found in config.ini: {', '.join(missing)}", "error")
            sys.exit(1)
        controllers = {c: controllers_cfg[c] for c in requested}
    else:
        controllers = controllers_cfg

    # CSV header (fixed + metric headers + VS_UUID)
    fixed_header = [
        "Controller","Virtual_Service_Name","VS_VIP","Port","Type(IPv4_/IPv6)","VS_Enabled",
        "Traffic_Enabled","SSL_Enabled","VIP_as_SNAT","Auto_Gateway_Enabled","VH_Type",
        "Application_Profile","SSL_Profile","SSL_Certificate_Name","Analytics_Profile",
        "Network_Profile","State","Reason","Pool","Service_Engine_Group","Primary_SE_Name",
        "Primary_SE_IP","Primary_SE_UUID","Secondary_SE_Name","Secondary_SE_IP","Secondary_SE_UUID",
        "Active_Standby_SE_Tag","Cloud","Cloud_Type","Tenant","Real_Time_Metrics_Enabled"
    ]
    final_header = fixed_header + METRIC_IDS + ["VS_UUID"]

    with open(out_csv, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(final_header)

        if args.parallel:
            with ThreadPoolExecutor(max_workers=args.processes) as ex:
                futs = [ex.submit(process_controller, c, creds, writer, METRIC_IDS)
                        for c, creds in controllers.items()]
                for fut in as_completed(futs):
                    try:
                        fut.result()
                    except Exception as e:
                        _log(f"Worker error: {e}", "error")
        else:
            for c, creds in controllers.items():
                process_controller(c, creds, writer, METRIC_IDS)

    _log(f"VS report saved: {out_csv}", "info")


if __name__ == "__main__":
    main()
