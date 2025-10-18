#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
alb-VS-Inventory-v0.4.1.py — NSX Advanced Load Balancer (Avi) Virtual Service Inventory + Metrics

PURPOSE
-------
Collects Virtual Service (VS) configuration, runtime, and performance metrics from one or more
Avi/NSX-ALB Controllers and writes a CSV report with a fixed, user-specified column order.
- Minimizes API calls: uses '?include_name=true' so refs carry '#Readable-Name'
- Expands metrics into separate CSV columns (order = config.ini list)
- Robust ref-name fallback with single-call caching only when '#' is missing

OUTPUT
------
CSV: avi-VSInventory_YYYYMMDDTHHMMSS.csv
Columns (exact order):
  Controller,Virtual_Service_Name,VS_VIP,Port,Type(IPv4_/IPv6),VS_Enabled,Traffic_Enabled,SSL_Enabled,
  VIP_as_SNAT,Auto_Gateway_Enabled,VH_Type,Application_Profile,SSL_Profile,SSL_Certificate_Name,
  Analytics_Profile,Network_Profile,State,Reason,Pool,Service_Engine_Group,Primary_SE_Name,
  Primary_SE_IP,Primary_SE_UUID,Secondary_SE_Name,Secondary_SE_IP,Secondary_SE_UUID,
  Active_Standby_SE_Tag,Cloud,Cloud_Type,Tenant,Real_Time_Metrics_Enabled,
  <metric_1>,<metric_2>,...,<metric_N>,VS_UUID

CONFIG (config.ini)
-------------------
[DEFAULT]
avi_user = admin
avi_pass = VMware1!VMware1!

[SETTINGS]
avi_version       = 22.1.7
api_step          = 21600               ; auto-corrected to >=300 and multiple of 300
api_limit         = 1
vsmetrics_list    = l4_client.avg_bandwidth,l4_client.avg_new_established_conns,...
; If vsmetrics_list missing, fallback to metrics_list or default_metrics
report_output_dir = /home/imallikarjun/scripts/reports
log_output_dir    = /home/imallikarjun/scripts/nsxalb/logs

[CONTROLLERS]
; Empty value -> use DEFAULT creds
m00avientlb =
; Or explicit: h00avientlb = admin,Secret!

USAGE
-----
python3 alb-VS-Inventory-v0.4.1.py [--debug] [--parallel] [--processes 8] [--controllers "c1,c2"]

CHANGELOG
---------
v0.4.1 — Oct 2025
- Controllers parsing hardened (skips stray keys, applies defaults cleanly)
- Booleans fixed: SSL from services[].enable_ssl OR cert/ssl profile; traffic/autogw/snat direct
- Real_Time_Metrics_Enabled from analytics_policy.metrics_realtime_update.enabled
  OR metrics_realtime_update.enabled
- Cloud_Type from config.cloud_type else runtime.cloud_type
- Ref names resolved via include_name; if missing '#', resolve once with cache
- SE primary/secondary names from runtime->se_ref->SE inventory lookup
- Metrics expanded into separate columns; correct repeated metric_id usage

"""

import os
import csv
import time
import logging
import argparse
import configparser
from datetime import datetime
from typing import Dict, List, Tuple, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed
from threading import Lock
from urllib.parse import urlparse

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
VSMETRICS: str = None  # Comma-separated metric ids (from config)
CSV_LOCK = Lock()

# -------- Logging ----------
def _log(msg: str, level: str = "info") -> None:
    getattr(logging, level)(msg)

def configure_logging(debug: bool, log_file_path: str) -> None:
    os.makedirs(os.path.dirname(log_file_path), exist_ok=True)
    level = logging.DEBUG if debug else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s: %(levelname)s: %(message)s",
        handlers=[logging.FileHandler(log_file_path), logging.StreamHandler()]
    )
    _log(f"Logging initialized. Level={'DEBUG' if debug else 'INFO'}")

# -------- Utils ----------
def validate_step(step: int) -> int:
    """Ensure step >= 300 and multiple of 300."""
    if step < 300:
        return 300
    if step % 300 != 0:
        step = ((step // 300) + 1) * 300
    return step

def convert_to_mbps(bits_per_sec):
    """bits/s -> MiB/s numeric or 'N/A'."""
    return round(bits_per_sec / 1048576, 2) if isinstance(bits_per_sec, (int, float)) else "N/A"

def name_from_ref(ref: str) -> str:
    """Prefer '#Name' trail; fallback to last URL segment."""
    if not ref or ref == "null":
        return "null"
    if "#" in ref:
        return ref.split("#")[-1]
    return ref.rstrip("/").split("/")[-1]

def semicolon_join(values: List[str]) -> str:
    vals = [v for v in values if v]
    return ";".join(vals) if vals else "null"

def last_segment(path: str) -> str:
    return path.rstrip("/").split("/")[-1]

# -------- HTTP ----------
def avi_login(controller: str, user: str, pwd: str) -> Tuple[Optional[str], Optional[str]]:
    url = f"https://{controller}/login"
    try:
        _log(f"[{controller}] Login attempt as {user}", "debug")
        r = requests.post(url, data={"username": user, "password": pwd}, verify=False, timeout=15)
        if r.status_code != 200:
            _log(f"[{controller}] Login failed: {r.status_code} {r.text[:300]}...", "error")
            return None, None
        ck = r.cookies.get_dict()
        sid, csrft = ck.get("avi-sessionid"), ck.get("csrftoken")
        if not sid or not csrft:
            _log(f"[{controller}] Missing session/CSRF token after login", "error")
            return None, None
        _log(f"[{controller}] Login successful")
        return sid, csrft
    except Exception as e:
        _log(f"[{controller}] Login error: {e}", "error")
        return None, None

def _headers(sid: str, csrft: str) -> Dict[str, str]:
    return {
        "X-Avi-Tenant": "admin",
        "X-Avi-Version": AVI_VERSION,
        "X-Csrftoken": csrft,
        "Cookie": f"avi-sessionid={sid}; csrftoken={csrft}"
    }

def backoff_get(url: str, headers: Dict[str, str], attempts: int = 5, base_wait: int = 2) -> Optional[Response]:
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

# -------- Lightweight ref-name resolver with cache (only when '#' missing) ----------
class RefNameResolver:
    def __init__(self, controller: str, sid: str, csrft: str):
        self.controller = controller
        self.headers = _headers(sid, csrft)
        self.cache: Dict[str, str] = {}

    def resolve(self, ref: str) -> str:
        """If ref lacks '#', try GET once and cache the object's 'name'."""
        if not ref or ref == "null":
            return "null"
        if "#" in ref:
            return ref.split("#")[-1]
        if ref in self.cache:
            return self.cache[ref]
        try:
            r = requests.get(ref, headers=self.headers, verify=False, timeout=15)
            if r.status_code == 200:
                nm = r.json().get("name") or last_segment(ref)
                self.cache[ref] = nm
                return nm
        except Exception:
            pass
        # fallback
        nm = last_segment(ref)
        self.cache[ref] = nm
        return nm

# -------- SE name lookup (inventory) ----------
def build_se_name_lookup(controller: str, sid: str, csrft: str) -> Dict[str, str]:
    """
    Map Service Engine UUID -> SE Name using /api/serviceengine-inventory/?include_name=true.
    Helpful when runtime only provides se_ref without 'name'.
    """
    headers = _headers(sid, csrft)
    url = f"https://{controller}/api/serviceengine-inventory/?include_name=true"
    lookup: Dict[str, str] = {}
    while url:
        r = backoff_get(url, headers=headers, attempts=3, base_wait=2)
        if not r:
            break
        payload = r.json()
        for item in payload.get("results", []):
            se_uuid = item.get("uuid")
            se_name = item.get("config", {}).get("name") or item.get("runtime", {}).get("name") or "null"
            if se_uuid:
                lookup[se_uuid] = se_name
        url = payload.get("next")
    _log(f"[{controller}] SE name lookup entries: {len(lookup)}", "debug")
    return lookup

# -------- VS inventory iterator ----------
def iter_vs_rows(controller: str, sid: str, csrft: str,
                 se_name_lookup: Dict[str, str], resolver: RefNameResolver):
    """
    Iterate /api/virtualservice-inventory/?include_name=true and yield VS rows (without metrics).
    """
    headers = _headers(sid, csrft)
    url = f"https://{controller}/api/virtualservice-inventory/?include_name=true"
    count = 0

    while url:
        r = backoff_get(url, headers=headers, attempts=3, base_wait=2)
        if not r:
            break
        payload = r.json()

        for item in payload.get("results", []):
            count += 1
            cfg = item.get("config", {})
            rt  = item.get("runtime", {})

            vs_name = cfg.get("name", "null")
            vs_uuid = cfg.get("uuid", "null")

            # VIPs & Types (IPv4 + IPv6)
            vip_addrs, vip_types = [], []
            for vip in cfg.get("vip", []):
                if "ip_address" in vip:
                    vip_addrs.append(vip["ip_address"].get("addr", ""))
                    vip_types.append(vip["ip_address"].get("type", ""))
                if "ip6_address" in vip:
                    vip_addrs.append(vip["ip6_address"].get("addr", ""))
                    vip_types.append(vip["ip6_address"].get("type", ""))
            vs_vip  = semicolon_join(vip_addrs)
            vip_type= semicolon_join(vip_types)

            # Port (first service)
            port = "null"
            if cfg.get("services"):
                port = cfg["services"][0].get("port", "null")

            # Flags / Booleans
            vs_enabled      = bool(cfg.get("enabled", False))
            traffic_enabled = bool(cfg.get("traffic_enabled", False))
            vip_as_snat     = bool(cfg.get("use_vip_as_snat", False))
            auto_gw         = bool(cfg.get("enable_autogw", False))
            vh_type         = cfg.get("vh_type", "null")

            # SSL enabled: prefer services[].enable_ssl; else presence of ssl key/profile
            ssl_from_services = any(s.get("enable_ssl") for s in cfg.get("services", []) if isinstance(s, dict))
            ssl_enabled = bool(ssl_from_services or
                               cfg.get("ssl_key_and_certificate_refs") or
                               cfg.get("ssl_profile_ref"))

            # Real-time metrics enabled: analytics_policy or top-level metrics_realtime_update
            rtm = False
            ap = cfg.get("analytics_policy", {})
            if isinstance(ap, dict):
                mru = ap.get("metrics_realtime_update", {})
                rtm = bool(mru.get("enabled", False))
            # Some versions expose top-level metrics_realtime_update as dict or bool
            if not rtm and isinstance(cfg.get("metrics_realtime_update"), dict):
                rtm = bool(cfg["metrics_realtime_update"].get("enabled", False))
            elif not rtm and isinstance(cfg.get("metrics_realtime_update"), bool):
                rtm = bool(cfg.get("metrics_realtime_update"))

            # Refs (prefer '#Name'; else 1-shot resolve)
            app_prof   = name_from_ref(cfg.get("application_profile_ref", "null"))
            if app_prof == "null" or "-" in app_prof:  # likely unresolved
                app_prof = resolver.resolve(cfg.get("application_profile_ref", "null"))

            ssl_prof   = name_from_ref(cfg.get("ssl_profile_ref", "null"))
            if ssl_prof == "null" or "-" in ssl_prof:
                ssl_prof = resolver.resolve(cfg.get("ssl_profile_ref", "null"))

            ssl_certs  = [name_from_ref(x) for x in cfg.get("ssl_key_and_certificate_refs", [])]
            if any("-" in c for c in ssl_certs):
                ssl_certs = [resolver.resolve(x) for x in cfg.get("ssl_key_and_certificate_refs", [])]
            ssl_certs_join = semicolon_join(ssl_certs)

            analytics_pr = name_from_ref(cfg.get("analytics_profile_ref", "null"))
            if analytics_pr == "null" or "-" in analytics_pr:
                analytics_pr = resolver.resolve(cfg.get("analytics_profile_ref", "null"))

            net_prof   = name_from_ref(cfg.get("network_profile_ref", "null"))
            if net_prof == "null" or "-" in net_prof:
                net_prof = resolver.resolve(cfg.get("network_profile_ref", "null"))

            pool_name = name_from_ref(cfg.get("pool_ref", "null"))
            if pool_name == "null" or "-" in pool_name:
                pool_name = resolver.resolve(cfg.get("pool_ref", "null"))

            se_group  = name_from_ref(cfg.get("se_group_ref", "null"))
            if se_group == "null" or "-" in se_group:
                se_group = resolver.resolve(cfg.get("se_group_ref", "null"))

            cloud_name = name_from_ref(cfg.get("cloud_ref", "null"))
            if cloud_name == "null" or "-" in cloud_name:
                cloud_name = resolver.resolve(cfg.get("cloud_ref", "null"))

            tenant_name = name_from_ref(cfg.get("tenant_ref", "null"))

            # Runtime / State
            state      = rt.get("oper_status", {}).get("state", "null")
            reason     = rt.get("oper_status", {}).get("reason", "null")
            # Cloud Type: prefer config cloud_type, else runtime
            cloud_type = cfg.get("cloud_type", rt.get("cloud_type", "null"))

            active_standby = cfg.get("active_standby_se_tag", "null")

            # Primary / Secondary SE: from runtime.vip_summary.service_engine
            pri_name = pri_ip = pri_uuid = "null"
            sec_name = sec_ip = sec_uuid = "null"
            for vsum in rt.get("vip_summary", []):
                for se in vsum.get("service_engine", []):
                    # try direct fields
                    se_uuid = se.get("uuid")
                    se_nm   = se.get("name")
                    se_ip   = se.get("mgmt_ip", {}).get("addr", "null")
                    # fallback to se_ref parsing
                    if not se_nm and se.get("se_ref"):
                        se_nm = name_from_ref(se["se_ref"])
                    if not se_uuid and se.get("se_ref"):
                        try:
                            se_uuid = last_segment(urlparse(se["se_ref"]).path)  # e.g. se-xxxxxxxx
                        except Exception:
                            se_uuid = "null"
                    # last fallback: use inventory lookup by uuid
                    if (not se_nm or se_nm == "null") and se_uuid in se_name_lookup:
                        se_nm = se_name_lookup[se_uuid]

                    if se.get("primary"):
                        pri_name, pri_ip, pri_uuid = se_nm or "null", se_ip, se_uuid or "null"
                    elif se.get("standby"):
                        sec_name, sec_ip, sec_uuid = se_nm or "null", se_ip, se_uuid or "null"

            # Yield row (WITHOUT metrics yet)
            yield [
                controller,         # Controller
                vs_name,            # Virtual_Service_Name
                vs_vip,             # VS_VIP
                port,               # Port
                vip_type,           # Type(IPv4_/IPv6)
                vs_enabled,         # VS_Enabled
                traffic_enabled,    # Traffic_Enabled
                ssl_enabled,        # SSL_Enabled
                vip_as_snat,        # VIP_as_SNAT
                auto_gw,            # Auto_Gateway_Enabled
                vh_type,            # VH_Type
                app_prof,           # Application_Profile
                ssl_prof,           # SSL_Profile
                ssl_certs_join,     # SSL_Certificate_Name
                analytics_pr,       # Analytics_Profile
                net_prof,           # Network_Profile
                state,              # State
                reason,             # Reason
                pool_name,          # Pool
                se_group,           # Service_Engine_Group
                pri_name,           # Primary_SE_Name
                pri_ip,             # Primary_SE_IP
                pri_uuid,           # Primary_SE_UUID
                sec_name,           # Secondary_SE_Name
                sec_ip,             # Secondary_SE_IP
                sec_uuid,           # Secondary_SE_UUID
                active_standby,     # Active_Standby_SE_Tag
                cloud_name,         # Cloud
                cloud_type,         # Cloud_Type
                tenant_name,        # Tenant
                rtm,                # Real_Time_Metrics_Enabled
                vs_uuid             # VS_UUID (metrics appended before this)
            ]
        url = payload.get("next")

    _log(f"[{controller}] VS inventory fetched: {count} items")

# -------- VS metrics ----------
def fetch_vs_metrics(controller: str, sid: str, csrft: str, vs_uuid: str, metric_ids: List[str]) -> List:
    """
    Fetch VS metrics using repeated metric_id params to avoid comma encoding issues.
    """
    if not metric_ids:
        return []
    headers = _headers(sid, csrft)
    step = validate_step(API_STEP)

    params = [("metric_id", m) for m in metric_ids]
    params += [("limit", API_LIMIT), ("step", step)]

    url = f"https://{controller}/api/analytics/metrics/virtualservice/{vs_uuid}/"
    try:
        r = requests.get(url, headers=headers, params=params, verify=False, timeout=45)
        if r.status_code != 200:
            _log(f"[{controller}] Metrics failed for {vs_uuid}: {r.status_code} {r.text[:200]}...", "warning")
            return ["N/A"] * len(metric_ids)

        data = r.json()
        series = data.get("series", [])
        out = []
        for m in metric_ids:
            s = next((x for x in series if x.get("header", {}).get("name") == m), None)
            val = s.get("data", [{}])[0].get("value", "N/A") if s and s.get("data") else "N/A"
            if m == "l4_client.avg_bandwidth":
                val = convert_to_mbps(val)
            out.append(val)

        if series:
            _log(f"[{controller}] Metrics OK for {vs_uuid}: {len(series)} series", "debug")
        else:
            _log(f"[{controller}] No metrics for {vs_uuid}", "warning")
        return out

    except Exception as e:
        _log(f"[{controller}] Metrics error for {vs_uuid}: {e}", "error")
        return ["N/A"] * len(metric_ids)

# -------- Controller worker ----------
def process_controller(controller: str, creds: Tuple[str, str], writer: csv.writer, metric_headers: List[str]) -> None:
    user, pwd = creds
    sid, csrft = avi_login(controller, user, pwd)
    if not sid or not csrft:
        return

    # Prepare helpers
    se_lookup = build_se_name_lookup(controller, sid, csrft)
    resolver  = RefNameResolver(controller, sid, csrft)

    for row in iter_vs_rows(controller, sid, csrft, se_lookup, resolver):
        vs_uuid = row[-1]
        metrics_vals = fetch_vs_metrics(controller, sid, csrft, vs_uuid, metric_headers)
        final = row[:-1] + metrics_vals + [vs_uuid]
        with CSV_LOCK:
            writer.writerow(final)

# -------- Main ----------
def main():
    parser = argparse.ArgumentParser(description="NSX ALB Virtual Service Inventory + Metrics (VS-only)")
    parser.add_argument("--debug", action="store_true", help="Enable debug logging")
    parser.add_argument("--parallel", action="store_true", help="Process controllers in parallel")
    parser.add_argument("--processes", type=int, default=8, help="Max parallel workers")
    parser.add_argument("--controllers", type=str, help="Comma-separated controller list (override config.ini)")
    args = parser.parse_args()

    cfg = configparser.ConfigParser()
    if not cfg.read("config.ini"):
        print("ERROR: config.ini not found or unreadable.")
        return

    global AVI_VERSION, API_STEP, API_LIMIT, VSMETRICS
    AVI_VERSION = cfg.get("SETTINGS", "avi_version", fallback="22.1.4")
    API_STEP    = cfg.getint("SETTINGS", "api_step", fallback=21600)
    API_LIMIT   = cfg.getint("SETTINGS", "api_limit", fallback=1)

    # Metrics list preference order
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
    log_file= os.path.join(log_dir, f"{datetime.now():%Y-%m-%dT%H-%M-%S}_vs_inventory.log")
    configure_logging(args.debug, log_file)
    _log(f"Using metrics: {VSMETRICS}")

    # Load defaults
    default_user = cfg.get("DEFAULT", "avi_user", fallback="admin")
    default_pass = cfg.get("DEFAULT", "avi_pass", fallback="Admin@123")

    # Build controller map robustly (skip stray keys)
    controllers_cfg: Dict[str, Tuple[str, str]] = {}
    if "CONTROLLERS" in cfg:
        for name, combo in cfg["CONTROLLERS"].items():
            key = name.strip()
            if not key or key.lower() in {"avi_user", "avi_pass", "avi_version", "api_step", "api_limit"}:
                _log(f"Skipping non-controller key in [CONTROLLERS]: {key}", "debug")
                continue
            parts = [p.strip() for p in (combo or "").split(",")] if combo is not None else []
            if len(parts) == 2 and parts[0] and parts[1]:
                controllers_cfg[key] = (parts[0], parts[1])
                _log(f"[{key}] Using inline credentials", "debug")
            else:
                controllers_cfg[key] = (default_user, default_pass)
                _log(f"[{key}] Using default credentials", "debug")
    else:
        _log("No [CONTROLLERS] found in config.ini", "error")
        return

    # Optional CLI override
    if args.controllers:
        requested = [c.strip() for c in args.controllers.split(",") if c.strip()]
        controllers = {c: controllers_cfg[c] for c in requested if c in controllers_cfg}
        missing = [c for c in requested if c not in controllers_cfg]
        if missing:
            _log(f"Requested controllers not present in config.ini: {', '.join(missing)}", "warning")
        if not controllers:
            _log("No valid controllers to process. Exiting.", "error")
            return
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
