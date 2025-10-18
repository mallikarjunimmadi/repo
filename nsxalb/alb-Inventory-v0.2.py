#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
alb-VS-Inventory-v0.4.3.py — NSX Advanced Load Balancer (Avi) Virtual Service Inventory + Metrics

WHAT THIS SCRIPT DOES
---------------------
1) Pulls VS CONFIG with readable names via:
     GET /api/virtualservice?include_name=true&page_size=200
   -> All *_ref fields carry '#Friendly-Name' suffixes.

2) Pulls VS RUNTIME via:
     GET /api/virtualservice-inventory/?page_size=200
   -> Contains oper_status, vip_summary (SE primary/standby, mgmt IPs), cloud_type.

3) Merges CONFIG+RUNTIME by VS UUID.

4) Fetches VS METRICS per VS:
     GET /api/analytics/metrics/virtualservice/<uuid>/?metric_id=...&metric_id=...
   -> Expands results into individual CSV columns (order from config).

5) Writes a timestamped CSV with this exact header order:
   Controller,Virtual_Service_Name,VS_VIP,Port,Type(IPv4_/IPv6),VS_Enabled,Traffic_Enabled,SSL_Enabled,
   VIP_as_SNAT,Auto_Gateway_Enabled,VH_Type,Application_Profile,SSL_Profile,SSL_Certificate_Name,
   Analytics_Profile,Network_Profile,State,Reason,Pool,Service_Engine_Group,Primary_SE_Name,
   Primary_SE_IP,Primary_SE_UUID,Secondary_SE_Name,Secondary_SE_IP,Secondary_SE_UUID,
   Active_Standby_SE_Tag,Cloud,Cloud_Type,Tenant,Real_Time_Metrics_Enabled,
   <one column per metric_id>,VS_UUID

WHY THIS VERSION FIXES YOUR ISSUES
----------------------------------
- Names: we source *_ref names from /virtualservice?include_name=true (not inventory), so names are present.
- UUIDs/NULLs: if a ref lacks '#Name', we resolve it once and force it through the current controller host.
- Booleans: pulled from correct config fields (ssl from services[].enable_ssl OR cert/profile presence).
- Metrics: correct multi-param 'metric_id' and fallback steps (configured -> 900 -> 300).

CONFIG (config.ini)
-------------------
[DEFAULT]
avi_user = admin
avi_pass = <password>

[SETTINGS]
avi_version       = 22.1.7
api_step          = 21600          ; script will fallback to 900 then 300 if no data
api_limit         = 1
vsmetrics_list    = l4_client.avg_bandwidth,l4_client.avg_new_established_conns,...
report_output_dir = /path/to/reports
log_output_dir    = /path/to/logs

[CONTROLLERS]
m00avientlb =             ; uses DEFAULT creds
; h00avientlb = customuser,Secret!

USAGE
-----
python3 alb-VS-Inventory-v0.4.3.py [--debug] [--parallel] [--processes 8] [--controllers "c1,c2"]
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

# ========== Globals (from config) ==========
AVI_VERSION: str = None
API_STEP: int = None
API_LIMIT: int = None
VSMETRICS: List[str] = []
CSV_LOCK = Lock()

# ========== Logging ==========
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

# ========== Helpers ==========
def validate_step(step: int) -> int:
    """Ensure Avi metric step is >=300 and a multiple of 300."""
    if step < 300:
        return 300
    if step % 300 != 0:
        step = ((step // 300) + 1) * 300
    return step

def convert_to_mibps(bits_per_sec):
    """Convert bits/s to MiB/s (base-2)."""
    return round(bits_per_sec / 1048576, 2) if isinstance(bits_per_sec, (int, float)) else "N/A"

def name_from_ref(ref: str) -> str:
    """
    Extract trailing '#Name' if present; else last path segment.
    - Using [-1] makes this safe even if '#' is absent.
    """
    if not ref or ref == "null":
        return "null"
    if "#" in ref:
        return ref.split("#")[-1]
    return ref.rstrip("/").split("/")[-1]

def semicolon_join(values: List[str]) -> str:
    vals = [v for v in values if v]
    return ";".join(vals) if vals else "null"

def last_segment(path: str) -> str:
    return path.rstrip("/").split("/")[-1] if path else "null"

# ========== HTTP ==========
def _headers(sid: str, csrft: str) -> Dict[str, str]:
    return {
        "X-Avi-Tenant": "admin",
        "X-Avi-Version": AVI_VERSION,
        "X-Csrftoken": csrft,
        "Cookie": f"avi-sessionid={sid}; csrftoken={csrft}"
    }

def avi_login(controller: str, user: str, pwd: str) -> Tuple[Optional[str], Optional[str]]:
    url = f"https://{controller}/login"
    try:
        _log(f"[{controller}] Login as {user}", "debug")
        r = requests.post(url, data={"username": user, "password": pwd}, verify=False, timeout=15)
        if r.status_code != 200:
            _log(f"[{controller}] Login failed: {r.status_code} {r.text[:200]}...", "error")
            return None, None
        ck = r.cookies.get_dict()
        sid, csrft = ck.get("avi-sessionid"), ck.get("csrftoken")
        if not sid or not csrft:
            _log(f"[{controller}] Missing session/CSRF token", "error")
            return None, None
        _log(f"[{controller}] Login OK")
        return sid, csrft
    except Exception as e:
        _log(f"[{controller}] Login error: {e}", "error")
        return None, None

def backoff_get(url: str, headers: Dict[str, str], attempts: int = 5, base_wait: int = 2) -> Optional[Response]:
    wait = base_wait
    for i in range(1, attempts + 1):
        try:
            _log(f"GET {url} (attempt {i}/{attempts})", "debug")
            r = requests.get(url, headers=headers, verify=False, timeout=60)
            if r.status_code == 200:
                return r
            _log(f"HTTP {r.status_code}: {r.text[:200]}...", "warning")
        except Exception as e:
            _log(f"GET error: {e}", "warning")
        time.sleep(wait)
        wait *= 2
    _log(f"Failed after {attempts}: {url}", "error")
    return None

# ========== Name resolver (for rare refs missing '#Name') ==========
class RefNameResolver:
    """
    If a ref lacks '#Name', resolve it ONCE by calling the same path on THIS controller.
    This avoids DNS failures if the ref contains an FQDN your host can't resolve.
    """
    def __init__(self, controller: str, sid: str, csrft: str):
        self.controller = controller
        self.headers = _headers(sid, csrft)
        self.cache: Dict[str, str] = {}

    def _rebuild_url(self, ref: str) -> Optional[str]:
        try:
            p = urlparse(ref)
            path = p.path or ref  # handle already-path refs
            if not path.startswith("/"):
                path = "/" + path
            return f"https://{self.controller}{path}"
        except Exception:
            return None

    def resolve(self, ref: str) -> str:
        if not ref or ref == "null":
            return "null"
        if "#" in ref:
            return ref.split("#")[-1]
        if ref in self.cache:
            return self.cache[ref]
        url = self._rebuild_url(ref)
        if not url:
            nm = last_segment(ref); self.cache[ref] = nm; return nm
        try:
            r = requests.get(url, headers=self.headers, verify=False, timeout=12)
            if r.status_code == 200:
                nm = r.json().get("name") or last_segment(url)
                self.cache[ref] = nm
                return nm
        except Exception:
            pass
        nm = last_segment(ref); self.cache[ref] = nm; return nm

# ========== SE name lookup ==========
def build_se_name_lookup(controller: str, sid: str, csrft: str) -> Dict[str, str]:
    headers = _headers(sid, csrft)
    url = f"https://{controller}/api/serviceengine-inventory/?page_size=200"
    lookup: Dict[str, str] = {}
    while url:
        r = backoff_get(url, headers, 3, 2)
        if not r:
            break
        for item in r.json().get("results", []):
            se_uuid = item.get("uuid")
            se_name = item.get("config", {}).get("name") or item.get("runtime", {}).get("name") or "null"
            if se_uuid:
                lookup[se_uuid] = se_name
        url = r.json().get("next")
    _log(f"[{controller}] SE name map: {len(lookup)}", "debug")
    return lookup

# ========== Fetch CONFIG (names) ==========
def fetch_vs_config_map(controller: str, sid: str, csrft: str, resolver: RefNameResolver) -> Dict[str, dict]:
    """
    Return dict: {vs_uuid: {normalized fields from CONFIG with readable names}}
    Source: /api/virtualservice?include_name=true&page_size=200
    """
    headers = _headers(sid, csrft)
    url = f"https://{controller}/api/virtualservice?include_name=true&page_size=200"
    out: Dict[str, dict] = {}
    total = 0

    while url:
        r = backoff_get(url, headers, 3, 2)
        if not r:
            break
        payload = r.json()
        for vs in payload.get("results", []):
            total += 1
            cfg = vs  # already config object
            vs_uuid = cfg.get("uuid", "null")
            vs_name = cfg.get("name", "null")

            # VIPs + types
            vip_addrs, vip_types = [], []
            for v in cfg.get("vip", []):
                if "ip_address" in v:
                    vip_addrs.append(v["ip_address"].get("addr", ""))
                    vip_types.append(v["ip_address"].get("type", ""))
                if "ip6_address" in v:
                    vip_addrs.append(v["ip6_address"].get("addr", ""))
                    vip_types.append(v["ip6_address"].get("type", ""))
            vs_vip   = semicolon_join(vip_addrs)
            vip_type = semicolon_join(vip_types)

            port = "null"
            if cfg.get("services"):
                port = cfg["services"][0].get("port", "null")

            # Booleans from CONFIG
            vs_enabled      = bool(cfg.get("enabled", False))
            traffic_enabled = bool(cfg.get("traffic_enabled", False))
            vip_as_snat     = bool(cfg.get("use_vip_as_snat", False))
            auto_gw         = bool(cfg.get("enable_autogw", False))
            vh_type         = cfg.get("vh_type", "null")

            # SSL enabled: service flag OR presence of cert/profile
            ssl_from_services = any(s.get("enable_ssl") for s in cfg.get("services", []) if isinstance(s, dict))
            ssl_enabled = bool(ssl_from_services or cfg.get("ssl_key_and_certificate_refs") or cfg.get("ssl_profile_ref"))

            # Real-time metrics: analytics_policy or top-level metrics_realtime_update
            rtm = False
            ap = cfg.get("analytics_policy", {})
            if isinstance(ap, dict):
                mru = ap.get("metrics_realtime_update", {})
                rtm = bool(mru.get("enabled", False))
            if not rtm and isinstance(cfg.get("metrics_realtime_update"), dict):
                rtm = bool(cfg["metrics_realtime_update"].get("enabled", False))
            elif not rtm and isinstance(cfg.get("metrics_realtime_update"), bool):
                rtm = bool(cfg.get("metrics_realtime_update"))

            # Refs with names; if missing '#', resolve once on THIS controller
            def rname(key):
                val = cfg.get(key, "null")
                nm = name_from_ref(val)
                if nm == "null" or "-" in nm:
                    nm = resolver.resolve(val)
                return nm

            app_prof     = rname("application_profile_ref")
            ssl_prof     = rname("ssl_profile_ref")
            ssl_certs    = [resolver.resolve(x) if "-" in name_from_ref(x) else name_from_ref(x)
                            for x in cfg.get("ssl_key_and_certificate_refs", [])]
            ssl_certs_join = semicolon_join(ssl_certs)
            analytics_pr = rname("analytics_profile_ref")
            net_prof     = rname("network_profile_ref")
            pool_name    = rname("pool_ref")
            se_group     = rname("se_group_ref")
            cloud_name   = rname("cloud_ref")
            tenant_name  = name_from_ref(cfg.get("tenant_ref", "null"))

            active_standby = cfg.get("active_standby_se_tag", "null")
            cloud_type_cfg = cfg.get("cloud_type", "null")

            out[vs_uuid] = {
                "vs_name": vs_name, "vs_vip": vs_vip, "vip_type": vip_type, "port": port,
                "vs_enabled": vs_enabled, "traffic_enabled": traffic_enabled, "ssl_enabled": ssl_enabled,
                "vip_as_snat": vip_as_snat, "auto_gw": auto_gw, "vh_type": vh_type,
                "app_prof": app_prof, "ssl_prof": ssl_prof, "ssl_certs": ssl_certs_join,
                "analytics_pr": analytics_pr, "net_prof": net_prof, "pool_name": pool_name,
                "se_group": se_group, "cloud_name": cloud_name, "tenant_name": tenant_name,
                "active_standby": active_standby, "cloud_type_cfg": cloud_type_cfg, "rtm": rtm
            }
        url = payload.get("next")

    _log(f"[{controller}] VS config fetched: {total} items", "info")
    return out

# ========== Fetch RUNTIME ==========
def fetch_vs_runtime_map(controller: str, sid: str, csrft: str) -> Dict[str, dict]:
    """
    Return dict: {vs_uuid: {state, reason, cloud_type_rt, primary/secondary SE info}}
    Source: /api/virtualservice-inventory/?page_size=200
    """
    headers = _headers(sid, csrft)
    url = f"https://{controller}/api/virtualservice-inventory/?page_size=200"
    out: Dict[str, dict] = {}
    total = 0

    while url:
        r = backoff_get(url, headers, 3, 2)
        if not r:
            break
        payload = r.json()
        for item in payload.get("results", []):
            total += 1
            cfg, rt = item.get("config", {}), item.get("runtime", {})
            vs_uuid = cfg.get("uuid", "null")

            state  = rt.get("oper_status", {}).get("state", "null")
            reason = rt.get("oper_status", {}).get("reason", "null")
            cloud_type_rt = rt.get("cloud_type", "null")

            pri_name = pri_ip = pri_uuid = "null"
            sec_name = sec_ip = sec_uuid = "null"
            for vsum in rt.get("vip_summary", []):
                for se in vsum.get("service_engine", []):
                    nm = se.get("name", "null")
                    ip = se.get("mgmt_ip", {}).get("addr", "null")
                    uid = se.get("uuid", "null")
                    if se.get("primary"):
                        pri_name, pri_ip, pri_uuid = nm, ip, uid
                    elif se.get("standby"):
                        sec_name, sec_ip, sec_uuid = nm, ip, uid

            out[vs_uuid] = {
                "state": state, "reason": reason, "cloud_type_rt": cloud_type_rt,
                "pri_name": pri_name, "pri_ip": pri_ip, "pri_uuid": pri_uuid,
                "sec_name": sec_name, "sec_ip": sec_ip, "sec_uuid": sec_uuid
            }
        url = payload.get("next")

    _log(f"[{controller}] VS runtime fetched: {total} items", "info")
    return out

# ========== Metrics (with step fallback) ==========
def fetch_vs_metrics(controller: str, sid: str, csrft: str, vs_uuid: str, metric_ids: List[str]) -> List:
    if not metric_ids:
        return []
    headers = _headers(sid, csrft)

    def try_fetch(step: int, limit: int) -> Optional[List]:
        params = [("metric_id", m) for m in metric_ids]
        params += [("limit", limit), ("step", step)]
        url = f"https://{controller}/api/analytics/metrics/virtualservice/{vs_uuid}/"
        r = requests.get(url, headers=headers, params=params, verify=False, timeout=45)
        if r.status_code != 200:
            _log(f"[{controller}] Metrics HTTP {r.status_code} for {vs_uuid}: {r.text[:180]}...", "warning")
            return None
        series = r.json().get("series", [])
        vals: List = []
        for m in metric_ids:
            s = next((x for x in series if x.get("header", {}).get("name") == m), None)
            v = s.get("data", [{}])[0].get("value", "N/A") if s and s.get("data") else "N/A"
            if m == "l4_client.avg_bandwidth":
                v = convert_to_mibps(v)
            vals.append(v)
        return vals

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

    _log(f"[{controller}] No metrics for {vs_uuid}", "warning")
    return ["N/A"] * len(metric_ids)

# ========== Controller worker ==========
def process_controller(controller: str, creds: Tuple[str, str], writer: csv.writer, metric_headers: List[str]) -> None:
    user, pwd = creds
    sid, csrft = avi_login(controller, user, pwd)
    if not sid or not csrft:
        return

    resolver = RefNameResolver(controller, sid, csrft)

    # Build maps
    cfg_map = fetch_vs_config_map(controller, sid, csrft, resolver)
    rt_map  = fetch_vs_runtime_map(controller, sid, csrft)

    # Optional fallback SE lookup if names are missing in runtime
    need_se_lookup = any(
        (rt_map[k]["pri_name"] == "null" or rt_map[k]["sec_name"] == "null")
        for k in rt_map
    )
    se_lookup = build_se_name_lookup(controller, sid, csrft) if need_se_lookup else {}

    # Emit rows
    for vs_uuid, cfg in cfg_map.items():
        rt = rt_map.get(vs_uuid, {})

        # Fill SE names from lookup if runtime lacked them
        pri_name = rt.get("pri_name", "null")
        sec_name = rt.get("sec_name", "null")
        pri_uuid = rt.get("pri_uuid", "null")
        sec_uuid = rt.get("sec_uuid", "null")
        pri_ip   = rt.get("pri_ip", "null")
        sec_ip   = rt.get("sec_ip", "null")

        if (not pri_name or pri_name == "null") and pri_uuid in se_lookup:
            pri_name = se_lookup[pri_uuid]
        if (not sec_name or sec_name == "null") and sec_uuid in se_lookup:
            sec_name = se_lookup[sec_uuid]

        state  = rt.get("state", "null")
        reason = rt.get("reason", "null")
        cloud_type = cfg.get("cloud_type_cfg") if cfg.get("cloud_type_cfg") not in (None, "null") else rt.get("cloud_type_rt", "null")

        # Metrics
        metrics_vals = fetch_vs_metrics(controller, sid, csrft, vs_uuid, metric_headers)

        row = [
            controller,
            cfg["vs_name"],
            cfg["vs_vip"],
            cfg["port"],
            cfg["vip_type"],
            cfg["vs_enabled"],
            cfg["traffic_enabled"],
            cfg["ssl_enabled"],
            cfg["vip_as_snat"],
            cfg["auto_gw"],
            cfg["vh_type"],
            cfg["app_prof"],
            cfg["ssl_prof"],
            cfg["ssl_certs"],
            cfg["analytics_pr"],
            cfg["net_prof"],
            state,
            reason,
            cfg["pool_name"],
            cfg["se_group"],
            pri_name,
            pri_ip,
            pri_uuid,
            sec_name,
            sec_ip,
            sec_uuid,
            cfg["active_standby"],
            cfg["cloud_name"],
            cloud_type,
            cfg["tenant_name"],
            cfg["rtm"],
        ] + metrics_vals + [vs_uuid]

        with CSV_LOCK:
            writer.writerow(row)

# ========== Main ==========
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

    # STRICT: require [DEFAULT] creds (you asked for this)
    if not cfg.get("DEFAULT", "avi_user", fallback="") or not cfg.get("DEFAULT", "avi_pass", fallback=""):
        print("ERROR: [DEFAULT] avi_user/avi_pass missing in config.ini")
        return
    default_user = cfg["DEFAULT"]["avi_user"]
    default_pass = cfg["DEFAULT"]["avi_pass"]

    global AVI_VERSION, API_STEP, API_LIMIT, VSMETRICS
    AVI_VERSION = cfg.get("SETTINGS", "avi_version", fallback="22.1.4")
    API_STEP    = cfg.getint("SETTINGS", "api_step", fallback=21600)
    API_LIMIT   = cfg.getint("SETTINGS", "api_limit", fallback=1)

    metrics_str = (
        cfg.get("SETTINGS", "vsmetrics_list", fallback="").strip()
        or cfg.get("SETTINGS", "metrics_list", fallback="").strip()
        or cfg.get("SETTINGS", "default_metrics", fallback="l4_client.avg_bandwidth,l4_client.avg_complete_conns").strip()
    )
    VSMETRICS = [m.strip() for m in metrics_str.split(",") if m.strip()]

    report_dir = cfg.get("SETTINGS", "report_output_dir", fallback=".")
    log_dir    = cfg.get("SETTINGS", "log_output_dir", fallback=".")
    os.makedirs(report_dir, exist_ok=True)
    os.makedirs(log_dir, exist_ok=True)

    ts = datetime.now().strftime("%Y%m%dT%H%M%S")
    vs_csv  = os.path.join(report_dir, f"avi-VSInventory_{ts}.csv")
    log_file= os.path.join(log_dir, f"{datetime.now():%Y-%m-%dT%H-%M-%S}_vs_inventory.log")
    configure_logging(args.debug, log_file)
    _log(f"Metric IDs: {VSMETRICS}", "info")

    # Build controllers map (use DEFAULT when value empty). Skip stray keys defensively.
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
                _log(f"[{key}] Using DEFAULT credentials", "debug")
    else:
        _log("No [CONTROLLERS] found in config.ini", "error")
        return

    # CLI override
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
        "Traffic_Enabled","SSL_Enabled","VIP_as_SSNAT","Auto_Gateway_Enabled","VH_Type",  # typo fix? keep "VIP_as_SNAT"
    ]
    # Correct typo back to requested header:
    fixed_header = [
        "Controller","Virtual_Service_Name","VS_VIP","Port","Type(IPv4_/IPv6)","VS_Enabled",
        "Traffic_Enabled","SSL_Enabled","VIP_as_SNAT","Auto_Gateway_Enabled","VH_Type",
        "Application_Profile","SSL_Profile","SSL_Certificate_Name","Analytics_Profile",
        "Network_Profile","State","Reason","Pool","Service_Engine_Group","Primary_SE_Name",
        "Primary_SE_IP","Primary_SE_UUID","Secondary_SE_Name","Secondary_SE_IP","Secondary_SE_UUID",
        "Active_Standby_SE_Tag","Cloud","Cloud_Type","Tenant","Real_Time_Metrics_Enabled"
    ]
    final_header = fixed_header + VSMETRICS + ["VS_UUID"]

    with open(vs_csv, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(final_header)

        if args.parallel:
            _log(f"Parallel mode ON (workers={args.processes})")
            with ThreadPoolExecutor(max_workers=args.processes) as ex:
                futures = [ex.submit(process_controller, c, creds, writer, VSMETRICS)
                           for c, creds in controllers.items()]
                for fut in as_completed(futures):
                    try:
                        fut.result()
                    except Exception as e:
                        _log(f"Worker error: {e}", "error")
        else:
            _log("Parallel mode OFF")
            for c, creds in controllers.items():
                process_controller(c, creds, writer, VSMETRICS)

    _log(f"VS report saved: {vs_csv}", "info")

if __name__ == "__main__":
    main()
