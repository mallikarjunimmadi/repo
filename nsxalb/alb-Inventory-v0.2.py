#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
alb-VS-Inventory-SDK-v1.2.py — NSX ALB (Avi) VS Inventory + Metrics (single consolidated CSV)

Fixes over v1.1:
- Removed ApiSession.get_iter usage (not available in your SDK build). Uses explicit pagination with api.get().
- Strict controller parsing: only take keys from [CONTROLLERS]; ignore avi_user/avi_pass leakage.
- Added progress logs: counts for CONFIG, RUNTIME, METRICS per controller.

What this does
--------------
For each controller:
  - Login via Avi SDK (ApiSession).
  - Fetch VS CONFIG from /api/virtualservice?include_name=true&page_size=200 (friendly names in *_ref).
  - Fetch VS RUNTIME from /api/virtualservice-inventory?page_size=200 (state, SE primary/standby, runtime cloud_type).
  - Merge by VS UUID.
  - Fetch VS METRICS from /api/analytics/metrics/virtualservice/<uuid> with repeated metric_id params.
  - Append rows to ONE consolidated CSV across all controllers.

CSV headers (exact order)
-------------------------
Controller,Virtual_Service_Name,VS_VIP,Port,Type(IPv4_/IPv6),VS_Enabled,Traffic_Enabled,SSL_Enabled,
VIP_as_SNAT,Auto_Gateway_Enabled,VH_Type,Application_Profile,SSL_Profile,SSL_Certificate_Name,
Analytics_Profile,Network_Profile,State,Reason,Pool,Service_Engine_Group,Primary_SE_Name,
Primary_SE_IP,Primary_SE_UUID,Secondary_SE_Name,Secondary_SE_IP,Secondary_SE_UUID,
Active_Standby_SE_Tag,Cloud,Cloud_Type,Tenant,Real_Time_Metrics_Enabled,<metric...>,VS_UUID

Config (config.ini)
-------------------
[DEFAULT]
avi_user = admin
avi_pass = <password>

[SETTINGS]
avi_version       = 22.1.7
api_step          = 21600
api_limit         = 1
vsmetrics_list    = l4_client.avg_bandwidth,l4_client.avg_new_established_conns,l4_client.avg_complete_conns
metrics_list      = <optional fallback>
default_metrics   = l4_client.avg_bandwidth,l4_client.avg_complete_conns
report_output_dir = /home/imallikarjun/scripts/reports
log_output_dir    = /home/imallikarjun/scripts/nsxalb/logs

[CONTROLLERS]
m00avientlb.local =
; h00avientlb.local = user,Secret!

Usage
-----
python3 alb-VS-Inventory-SDK-v1.2.py \
  [--config config.ini] \
  [--controllers "m00avientlb.local,m01avientlb.local"] \
  [--user admin --password '***'] \
  [--api-version 22.1.7] \
  [--output-dir /path/to/reports] \
  [--threads 8] \
  [--debug]
"""

import os
import sys
import csv
import logging
import argparse
import configparser
from datetime import datetime
from typing import Dict, List, Tuple, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed
from threading import Lock

# Suppress TLS warnings if you use self-signed controllers
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Avi SDK
from avi.sdk.avi_api import ApiSession, APIError
from avi.sdk.utils.api_utils import ApiUtils

# ---------- Globals ----------
AVI_VERSION: str = "22.1.7"
API_STEP: int = 21600
API_LIMIT: int = 1
METRIC_IDS: List[str] = []
CSV_LOCK = Lock()

# ---------- Logging ----------
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

# ---------- Helpers ----------
def validate_step(step: int) -> int:
    """Avi metrics step must be >=300 and a multiple of 300."""
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
    mru_top = cfg.get("metrics_realtime_update")
    if isinstance(mru_top, dict):
        return bool(mru_top.get("enabled"))
    if isinstance(mru_top, bool):
        return mru_top
    return False

# ---------- Pagination wrappers (replace get_iter) ----------
def paged_get(api: ApiSession, path_or_url: str, params: Optional[dict] = None):
    """Yield items from a GET that returns a {results:[], next:...} response."""
    try:
        resp = api.get(path_or_url, params=params, verify=False)
    except APIError as e:
        _log(f"GET {path_or_url} APIError: {e}", "error")
        return
    if resp.status_code != 200:
        _log(f"GET {path_or_url} HTTP {resp.status_code}: {resp.text[:180]}...", "error")
        return
    payload = resp.json()
    for itm in payload.get("results", []):
        yield itm
        next_url = payload.get("next")
    while next_url:
        if next_url.startswith("/api/"):
            # relative path; remove duplicate prefix if needed
            next_url = next_url.lstrip("/")
            resp = api.get(next_url, verify=False)
        else:
            # absolute URL
            resp = api.get(next_url, verify=False)
        if resp.status_code != 200:
            _log(f"GET next HTTP {resp.status_code}: {resp.text[:180]}...", "error")
            return
        payload = resp.json()
        for itm in payload.get("results", []):
            yield itm
        next_url = payload.get("next")

# ---------- Metrics fetch with fallback ----------
def fetch_vs_metrics(api: ApiSession, controller: str, vs_uuid: str, metric_ids: List[str]) -> List:
    if not metric_ids:
        return []

    def try_fetch(step: int, limit: int) -> Optional[List]:
        params = [("metric_id", m) for m in metric_ids]
        params += [("limit", limit), ("step", step)]
        try:
            resp = api.get(f"analytics/metrics/virtualservice/{vs_uuid}/", params=params, verify=False)
        except APIError as e:
            _log(f"[{controller}] Metrics APIError {vs_uuid}: {e}", "warning")
            return None
        if resp.status_code != 200:
            _log(f"[{controller}] Metrics HTTP {resp.status_code} {vs_uuid}: {resp.text[:180]}...", "warning")
            return None
        series = resp.json().get("series", [])
        out = []
        for m in metric_ids:
            s = next((x for x in series if x.get("header", {}).get("name") == m), None)
            val = "N/A"
            if s:
                data = s.get("data") or s.get("series") or []
                if isinstance(data, list) and data:
                    val = data[0].get("value", "N/A")
            if m == "l4_client.avg_bandwidth" and isinstance(val, (int, float)):
                val = round(val / 1048576, 2)  # MiB/s
            out.append(val)
        return out

    step1 = validate_step(API_STEP)
    vals = try_fetch(step1, API_LIMIT)
    if vals and any(v != "N/A" for v in vals):
        return vals
    vals = try_fetch(900, max(API_LIMIT, 5))
    if vals and any(v != "N/A" for v in vals):
        return vals
    vals = try_fetch(300, max(API_LIMIT, 10))
    if vals and any(v != "N/A" for v in vals):
        return vals
    _log(f"[{controller}] No metrics for {vs_uuid} after fallbacks", "warning")
    return vals if vals else ["N/A"] * len(metric_ids)

# ---------- Per-controller worker ----------
def process_controller(controller: str,
                       creds: Tuple[str, str],
                       writer: csv.writer,
                       metric_headers: List[str],
                       api_version: str) -> None:
    user, pwd = creds
    try:
        api = ApiSession.get_session(controller, user, pwd, tenant='admin', api_version=api_version)
        api_utils = ApiUtils(api)
        _log(f"[{controller}] Logged in", "info")
    except Exception as e:
        _log(f"[{controller}] Login error: {e}", "error")
        return

    # 1) CONFIG with include_name=true
    cfg_map: Dict[str, dict] = {}
    cfg_count = 0
    for cfg in paged_get(api, "virtualservice", params={"include_name": True, "page_size": 200}):
        cfg_count += 1
        vs_uuid = cfg.get("uuid", "null")
        vs_name = cfg.get("name", "null")
        vs_vip, vip_type = extract_vips_and_types(cfg)
        port = cfg.get("services", [{}])[0].get("port", "null") if cfg.get("services") else "null"

        vs_enabled      = bool(cfg.get("enabled", False))
        traffic_enabled = bool(cfg.get("traffic_enabled", False))
        vip_as_snat     = bool(cfg.get("use_vip_as_snat", False))
        auto_gw         = bool(cfg.get("enable_autogw", False))
        vh_type         = cfg.get("vh_type", "null")
        ssl_enabled     = ssl_enabled_from_config(cfg)
        rtm             = realtime_metrics_enabled(cfg)

        def nm(ref: Optional[str]) -> str:
            if not ref:
                return "null"
            try:
                val = api_utils.get_name_from_ref(ref)
                return val if val else "null"
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

        cert_refs = cfg.get("ssl_key_and_certificate_refs", [])
        ssl_certs = []
        for ref in cert_refs or []:
            try:
                nmv = api_utils.get_name_from_ref(ref)
                if nmv:
                    ssl_certs.append(nmv)
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
    _log(f"[{controller}] CONFIG fetched: {cfg_count}", "info")

    # 2) RUNTIME via inventory
    rt_map: Dict[str, dict] = {}
    rt_count = 0
    for inv in paged_get(api, "virtualservice-inventory", params={"page_size": 200}):
        rt_count += 1
        cfg = inv.get("config", {})
        rt  = inv.get("runtime", {})
        vs_uuid = cfg.get("uuid", "null")

        state  = rt.get("oper_status", {}).get("state", "null")
        reason = rt.get("oper_status", {}).get("reason", "null")
        cloud_type_rt = rt.get("cloud_type", "null")

        pri_name = pri_ip = pri_uuid = "null"
        sec_name = sec_ip = sec_uuid = "null"
        for vsum in rt.get("vip_summary", []):
            for se in vsum.get("service_engine", []):
                se_name = se.get("name", "null")
                if (not se_name or se_name == "null") and se.get("se_ref"):
                    try: se_name = api_utils.get_name_from_ref(se["se_ref"]) or "null"
                    except Exception: se_name = "null"
                se_ip   = se.get("mgmt_ip", {}).get("addr", "null")
                se_ref  = se.get("se_ref", "")
                se_uuid = "null"
                if se_ref:
                    try: se_uuid = se_ref.split("/")[-1].split("#")[0] or "null"
                    except Exception: pass

                if se.get("is_primary") or se.get("primary"):
                    pri_name, pri_ip, pri_uuid = se_name, se_ip, se_uuid
                elif se.get("is_standby") or se.get("standby"):
                    sec_name, sec_ip, sec_uuid = se_name, se_ip, se_uuid

        rt_map[vs_uuid] = {
            "state": state, "reason": reason, "cloud_type_rt": cloud_type_rt,
            "pri_name": pri_name, "pri_ip": pri_ip, "pri_uuid": pri_uuid,
            "sec_name": sec_name, "sec_ip": sec_ip, "sec_uuid": sec_uuid
        }
    _log(f"[{controller}] RUNTIME fetched: {rt_count}", "info")

    # 3) Emit rows (merge + metrics)
    metrics_ok = 0
    for vs_uuid, c in cfg_map.items():
        r = rt_map.get(vs_uuid, {})
        state  = r.get("state", "null")
        reason = r.get("reason", "null")
        cloud_type_final = c["cloud_type"] if c["cloud_type"] not in (None, "null") else r.get("cloud_type_rt", "null")

        metric_vals = fetch_vs_metrics(api, controller, vs_uuid, metric_headers)
        if any(v != "N/A" for v in metric_vals):
            metrics_ok += 1

        row = [
            controller,
            c["vs_name"],
            c["vs_vip"],
            c["port"],
            c["vip_type"],
            c["vs_enabled"],
            c["traffic_enabled"],
            c["ssl_enabled"],
            c["vip_as_snat"],
            c["auto_gw"],
            c["vh_type"],
            c["app_prof"],
            c["ssl_prof"],
            c["ssl_certs"],
            c["analytics_pr"],
            c["net_prof"],
            state,
            reason,
            c["pool_name"],
            c["se_group"],
            r.get("pri_name", "null"),
            r.get("pri_ip", "null"),
            r.get("pri_uuid", "null"),
            r.get("sec_name", "null"),
            r.get("sec_ip", "null"),
            r.get("sec_uuid", "null"),
            c["active_stby"],
            c["cloud_name"],
            cloud_type_final,
            c["tenant_name"],
            c["rtm"],
        ] + metric_vals + [vs_uuid]

        with CSV_LOCK:
            writer.writerow(row)

    _log(f"[{controller}] Rows written: {len(cfg_map)} | Metrics non-empty: {metrics_ok}", "info")

# ---------- MAIN ----------
def main():
    parser = argparse.ArgumentParser(
        description="NSX ALB (Avi) VS inventory + metrics (Avi SDK, consolidated CSV).",
        epilog=(
            "Examples:\n"
            "  python3 alb-VS-Inventory-SDK-v1.2.py --config config.ini --debug\n"
            "  python3 alb-VS-Inventory-SDK-v1.2.py --controllers m00avientlb.local --user admin --password '***'\n"
            "  python3 alb-VS-Inventory-SDK-v1.2.py --controllers 'm00.local,m01.local' --threads 8 --output-dir /tmp/reports\n"
        ),
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument("--config", default="config.ini", help="Path to config.ini (default: config.ini)")
    parser.add_argument("--controllers", help="Comma-separated controller list (override [CONTROLLERS] in config.ini)")
    parser.add_argument("--user", help="Override [DEFAULT] avi_user for all controllers (unless controller has inline creds)")
    parser.add_argument("--password", help="Override [DEFAULT] avi_pass for all controllers (unless controller has inline creds)")
    parser.add_argument("--api-version", help="Override API version (default from [SETTINGS].avi_version)")
    parser.add_argument("--output-dir", help="Override report_output_dir from config.ini")
    parser.add_argument("--threads", type=int, default=8, help="Parallel workers (default: 8)")
    parser.add_argument("--debug", action="store_true", help="Enable verbose logging")
    args = parser.parse_args()

    cfg = configparser.ConfigParser()
    if not cfg.read(args.config):
        print(f"ERROR: {args.config} not found or unreadable.", file=sys.stderr); sys.exit(1)

    # Credentials: CLI override > [DEFAULT]
    d_user = args.user or cfg.get("DEFAULT", "avi_user", fallback="")
    d_pass = args.password or cfg.get("DEFAULT", "avi_pass", fallback="")
    if not d_user or not d_pass:
        print("ERROR: Missing creds. Provide --user/--password or set [DEFAULT] avi_user/avi_pass in config.ini", file=sys.stderr)
        sys.exit(1)

    global AVI_VERSION, API_STEP, API_LIMIT, METRIC_IDS
    AVI_VERSION = args.api_version or cfg.get("SETTINGS", "avi_version", fallback="22.1.7")
    API_STEP    = cfg.getint("SETTINGS", "api_step", fallback=21600)
    API_LIMIT   = cfg.getint("SETTINGS", "api_limit", fallback=1)

    metrics_str = (
        cfg.get("SETTINGS", "vsmetrics_list", fallback="").strip()
        or cfg.get("SETTINGS", "metrics_list", fallback="").strip()
        or cfg.get("SETTINGS", "default_metrics", fallback="l4_client.avg_bandwidth,l4_client.avg_complete_conns").strip()
    )
    METRIC_IDS = [m.strip() for m in metrics_str.split(",") if m.strip()]

    report_dir = args.output_dir or cfg.get("SETTINGS", "report_output_dir", fallback=".")
    log_dir    = cfg.get("SETTINGS", "log_output_dir", fallback=".")
    os.makedirs(report_dir, exist_ok=True)
    os.makedirs(log_dir, exist_ok=True)

    ts = datetime.now().strftime("%Y%m%dT%H%M%S")
    out_csv = os.path.join(report_dir, f"avi-VSInventory_{ts}.csv")
    log_file= os.path.join(log_dir, f"{datetime.now():%Y-%m-%dT%H-%M-%S}_vs_inventory_sdk.log")
    configure_logging(args.debug, log_file)

    # Build controller map (ONLY from [CONTROLLERS] unless CLI overrides)
    controllers_cfg: Dict[str, Tuple[str, str]] = {}

    def looks_like_setting(key: str) -> bool:
        kl = key.lower()
        return any(part in kl for part in [
            "avi_user", "avi_pass", "avi_version", "api_step", "api_limit",
            "metrics", "default", "setting", "report_output_dir", "log_output_dir"
        ])

    if args.controllers:
        for item in [c.strip() for c in args.controllers.split(",") if c.strip()]:
            controllers_cfg[item] = (d_user, d_pass)
    elif "CONTROLLERS" in cfg:
        for name, combo in cfg["CONTROLLERS"].items():
            key = name.strip()
            if not key or looks_like_setting(key):
                continue
            parts = [p.strip() for p in (combo or "").split(",")] if combo is not None else []
            if len(parts) == 2 and parts[0] and parts[1]:
                controllers_cfg[key] = (parts[0], parts[1])    # inline creds
            else:
                controllers_cfg[key] = (d_user, d_pass)        # default creds
    else:
        _log("ERROR: No controllers specified (CLI or config.ini).", "error"); sys.exit(1)

    _log(f"Controllers: {', '.join(controllers_cfg.keys())}")
    _log(f"Metrics: {METRIC_IDS} | step={API_STEP} | limit={API_LIMIT}")

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

    # Open ONE consolidated CSV and write rows from all controllers
    with open(out_csv, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(final_header)

        with ThreadPoolExecutor(max_workers=args.threads) as ex:
            futs = [
                ex.submit(process_controller, c, creds, writer, METRIC_IDS, AVI_VERSION)
                for c, creds in controllers_cfg.items()
            ]
            for fut in as_completed(futs):
                try:
                    fut.result()
                except Exception as e:
                    _log(f"Worker error: {e}", "error")

    _log(f"VS report saved: {out_csv}", "info")


if __name__ == "__main__":
    main()
