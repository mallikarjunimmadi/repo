#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
alb-VS-Inventory-v0.4.2.py — NSX Advanced Load Balancer (Avi) Virtual Service Inventory + Metrics

PURPOSE
-------
Generate a Virtual Service (VS) report with config, runtime, and expanded analytics metrics.
- Uses '?include_name=true' on inventory so refs carry '#Readable-Name'
- Resolves any remaining refs robustly, even if the ref contains an FQDN your host can't resolve
- Expands metrics into individual CSV columns (from config, in order)
- Retains accurate booleans (SSL, traffic, VIP-as-SNAT, autogw, realtime metrics)

OUTPUT (timestamped in report_output_dir)
-----------------------------------------
avi-VSInventory_YYYYMMDDTHHMMSS.csv

HEADER (exact order)
--------------------
Controller,Virtual_Service_Name,VS_VIP,Port,Type(IPv4_/IPv6),VS_Enabled,Traffic_Enabled,SSL_Enabled,
VIP_as_SNAT,Auto_Gateway_Enabled,VH_Type,Application_Profile,SSL_Profile,SSL_Certificate_Name,
Analytics_Profile,Network_Profile,State,Reason,Pool,Service_Engine_Group,Primary_SE_Name,
Primary_SE_IP,Primary_SE_UUID,Secondary_SE_Name,Secondary_SE_IP,Secondary_SE_UUID,
Active_Standby_SE_Tag,Cloud,Cloud_Type,Tenant,Real_Time_Metrics_Enabled,
<metric_1>,...,<metric_N>,VS_UUID

CONFIG (config.ini)
-------------------
[DEFAULT]
avi_user = admin
avi_pass = VMware1!VMware1!

[SETTINGS]
avi_version       = 22.1.7
api_step          = 21600         ; we will auto-retry with smaller steps if no data
api_limit         = 1
vsmetrics_list    = l4_client.avg_bandwidth,l4_client.avg_new_established_conns,...
; if vsmetrics_list missing, fallback to metrics_list or default_metrics
report_output_dir = /home/imallikarjun/scripts/reports
log_output_dir    = /home/imallikarjun/scripts/nsxalb/logs

[CONTROLLERS]
m00avientlb =
; Optional: h00avientlb = customuser,Secret!

CLI
---
python3 alb-VS-Inventory-v0.4.2.py [--debug] [--parallel] [--processes 8] [--controllers "m00avientlb,..."]

CHANGELOG
---------
v0.4.2 — Oct 2025
- Ref resolver now strips ref host and reuses the logged-in controller host (fixes null/UUID names when FQDNs aren't resolvable)
- Metrics: auto-retry with step=900 then 300 and increased limit if first fetch returns empty
- Booleans fixed: SSL from services[].enable_ssl | ssl_profile | ssl_key_and_certificate
- Real-time metrics detection checks analytics_policy and top-level field
- Defaults: require [DEFAULT]; use only those; skip stray keys in [CONTROLLERS]
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

# -------- Globals (from config) --------
AVI_VERSION: str = None
API_STEP: int = None
API_LIMIT: int = None
VSMETRICS: str = None
CSV_LOCK = Lock()

# -------- Logging --------
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

# -------- Utils --------
def validate_step(step: int) -> int:
    if step < 300:
        return 300
    if step % 300 != 0:
        step = ((step // 300) + 1) * 300
    return step

def convert_to_mibps(bits_per_sec):
    return round(bits_per_sec / 1048576, 2) if isinstance(bits_per_sec, (int, float)) else "N/A"

def name_from_ref(ref: str) -> str:
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

# -------- HTTP --------
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

# -------- Ref resolver (rebuild onto current controller host) --------
class RefNameResolver:
    """
    Resolves object names when '#Name' is missing.
    If ref is absolute (https://otherhost/api/...#Name), we IGNORE its host
    and rebuild the request onto the current controller (https://<controller>/<path>),
    so DNS for the embedded FQDN never matters.
    """
    def __init__(self, controller: str, sid: str, csrft: str):
        self.controller = controller
        self.headers = _headers(sid, csrft)
        self.cache: Dict[str, str] = {}

    def _rebuild_url(self, ref: str) -> Optional[str]:
        if not ref:
            return None
        try:
            p = urlparse(ref)
            path = p.path if p.path else ref  # handle already-path strings
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

        # Try GET against rebuilt URL (current controller host)
        url = self._rebuild_url(ref)
        if not url:
            nm = last_segment(ref)
            self.cache[ref] = nm
            return nm

        try:
            r = requests.get(url, headers=self.headers, verify=False, timeout=15)
            if r.status_code == 200:
                nm = r.json().get("name") or last_segment(url)
                self.cache[ref] = nm
                return nm
        except Exception:
            pass

        nm = last_segment(ref)
        self.cache[ref] = nm
        return nm

# -------- SE name lookup --------
def build_se_name_lookup(controller: str, sid: str, csrft: str) -> Dict[str, str]:
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

# -------- VS inventory iterator --------
def iter_vs_rows(controller: str, sid: str, csrft: str,
                 se_name_lookup: Dict[str, str], resolver: RefNameResolver):
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

            # VIPs + Types
            vip_addrs, vip_types = [], []
            for vip in cfg.get("vip", []):
                if "ip_address" in vip:
                    vip_addrs.append(vip["ip_address"].get("addr", ""))
                    vip_types.append(vip["ip_address"].get("type", ""))
                if "ip6_address" in vip:
                    vip_addrs.append(vip["ip6_address"].get("addr", ""))
                    vip_types.append(vip["ip6_address"].get("type", ""))
            vs_vip   = semicolon_join(vip_addrs)
            vip_type = semicolon_join(vip_types)

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

            # SSL enabled
            ssl_from_services = any(s.get("enable_ssl") for s in cfg.get("services", []) if isinstance(s, dict))
            ssl_enabled = bool(ssl_from_services or cfg.get("ssl_key_and_certificate_refs") or cfg.get("ssl_profile_ref"))

            # Real-time metrics enabled (analytics_policy or top-level)
            rtm = False
            ap = cfg.get("analytics_policy", {})
            if isinstance(ap, dict):
                mru = ap.get("metrics_realtime_update", {})
                rtm = bool(mru.get("enabled", False))
            if not rtm and isinstance(cfg.get("metrics_realtime_update"), dict):
                rtm = bool(cfg["metrics_realtime_update"].get("enabled", False))
            elif not rtm and isinstance(cfg.get("metrics_realtime_update"), bool):
                rtm = bool(cfg.get("metrics_realtime_update"))

            # Refs (via include_name + robust resolver)
            def resolve_ref(key):
                val = cfg.get(key, "null")
                nm = name_from_ref(val)
                if nm == "null" or "-" in nm:
                    nm = resolver.resolve(val)
                return nm

            app_prof     = resolve_ref("application_profile_ref")
            ssl_prof     = resolve_ref("ssl_profile_ref")
            ssl_certs    = [resolver.resolve(x) if "-" in name_from_ref(x) else name_from_ref(x)
                            for x in cfg.get("ssl_key_and_certificate_refs", [])]
            ssl_certs_join = semicolon_join(ssl_certs)
            analytics_pr = resolve_ref("analytics_profile_ref")
            net_prof     = resolve_ref("network_profile_ref")
            pool_name    = resolve_ref("pool_ref")
            se_group     = resolve_ref("se_group_ref")
            cloud_name   = resolve_ref("cloud_ref")
            tenant_name  = name_from_ref(cfg.get("tenant_ref", "null"))

            # Runtime / State
            state      = rt.get("oper_status", {}).get("state", "null")
            reason     = rt.get("oper_status", {}).get("reason", "null")
            cloud_type = cfg.get("cloud_type", rt.get("cloud_type", "null"))

            active_standby = cfg.get("active_standby_se_tag", "null")

            # Primary / Secondary SE from runtime
            pri_name = pri_ip = pri_uuid = "null"
            sec_name = sec_ip = sec_uuid = "null"
            for vsum in rt.get("vip_summary", []):
                for se in vsum.get("service_engine", []):
                    se_uuid = se.get("uuid")
                    se_nm   = se.get("name") or None
                    se_ip   = se.get("mgmt_ip", {}).get("addr", "null")
                    if not se_nm and se.get("se_ref"):
                        se_nm = name_from_ref(se["se_ref"])
                        if "-" in se_nm:
                            se_nm = resolver.resolve(se["se_ref"])
                    if (not se_nm or se_nm == "null") and se_uuid in se_name_lookup:
                        se_nm = se_name_lookup[se_uuid]
                    if se.get("primary"):
                        pri_name, pri_ip, pri_uuid = se_nm or "null", se_ip, se_uuid or "null"
                    elif se.get("standby"):
                        sec_name, sec_ip, sec_uuid = se_nm or "null", se_ip, se_uuid or "null"

            # Yield row (metrics appended just before VS_UUID at write time)
            yield [
                controller, vs_name, vs_vip, port, vip_type, vs_enabled, traffic_enabled, ssl_enabled,
                vip_as_snat, auto_gw, vh_type, app_prof, ssl_prof, ssl_certs_join, analytics_pr,
                net_prof, state, reason, pool_name, se_group, pri_name, pri_ip, pri_uuid,
                sec_name, sec_ip, sec_uuid, active_standby, cloud_name, cloud_type, tenant_name,
                rtm, vs_uuid
            ]
        url = payload.get("next")

    _log(f"[{controller}] VS inventory fetched: {count} items")

# -------- Metrics (with smart fallback steps) --------
def fetch_vs_metrics(controller: str, sid: str, csrft: str, vs_uuid: str, metric_ids: List[str]) -> List:
    if not metric_ids:
        return []
    headers = _headers(sid, csrft)

    def try_fetch(step: int, limit: int) -> List:
        params = [("metric_id", m) for m in metric_ids]
        params += [("limit", limit), ("step", step)]
        url = f"https://{controller}/api/analytics/metrics/virtualservice/{vs_uuid}/"
        r = requests.get(url, headers=headers, params=params, verify=False, timeout=45)
        if r.status_code != 200:
            _log(f"[{controller}] Metrics HTTP {r.status_code} for {vs_uuid}: {r.text[:200]}...", "warning")
            return []
        series = r.json().get("series", [])
        vals = []
        for m in metric_ids:
            s = next((x for x in series if x.get("header", {}).get("name") == m), None)
            v = s.get("data", [{}])[0].get("value", "N/A") if s and s.get("data") else "N/A"
            if m == "l4_client.avg_bandwidth":
                v = convert_to_mibps(v)
            vals.append(v)
        return vals

    # 1st attempt: configured step (validated)
    step1 = validate_step(API_STEP)
    vals = try_fetch(step1, API_LIMIT)
    if any(v != "N/A" for v in vals):
        _log(f"[{controller}] Metrics OK for {vs_uuid} @ step={step1}", "debug")
        return vals

    # 2nd attempt: step=900, limit=5
    vals = try_fetch(900, max(API_LIMIT, 5))
    if any(v != "N/A" for v in vals):
        _log(f"[{controller}] Metrics OK for {vs_uuid} @ step=900", "debug")
        return vals

    # 3rd attempt: step=300, limit=10
    vals = try_fetch(300, max(API_LIMIT, 10))
    if any(v != "N/A" for v in vals):
        _log(f"[{controller}] Metrics OK for {vs_uuid} @ step=300", "debug")
        return vals

    _log(f"[{controller}] No metrics for {vs_uuid} after step fallbacks", "warning")
    return vals if vals else ["N/A"] * len(metric_ids)

# -------- Controller worker --------
def process_controller(controller: str, creds: Tuple[str, str], writer: csv.writer, metric_headers: List[str]) -> None:
    user, pwd = creds
    sid, csrft = avi_login(controller, user, pwd)
    if not sid or not csrft:
        return

    se_lookup = build_se_name_lookup(controller, sid, csrft)
    resolver  = RefNameResolver(controller, sid, csrft)

    for row in iter_vs_rows(controller, sid, csrft, se_lookup, resolver):
        vs_uuid = row[-1]
        metrics_vals = fetch_vs_metrics(controller, sid, csrft, vs_uuid, metric_headers)
        final = row[:-1] + metrics_vals + [vs_uuid]
        with CSV_LOCK:
            writer.writerow(final)

# -------- Main --------
def main():
    parser = argparse.ArgumentParser(description="NSX ALB Virtual Service Inventory + Metrics (VS-only)")
    parser.add_argument("--debug", action="store_true", help="Enable debug logging")
    parser.add_argument("--parallel", action="store_true", help="Process controllers in parallel")
    parser.add_argument("--processes", type=int, default=8, help="Max parallel workers")
    parser.add_argument("--controllers", type=str, help="Comma-separated controllers (override config.ini)")
    args = parser.parse_args()

    cfg = configparser.ConfigParser()
    if not cfg.read("config.ini"):
        print("ERROR: config.ini not found or unreadable.")
        return

    # Strictly require [DEFAULT] creds (as you asked)
    if not cfg.get("DEFAULT", "avi_user", fallback="") or not cfg.get("DEFAULT", "avi_pass", fallback=""):
        print("ERROR: [DEFAULT] avi_user/avi_pass missing in config.ini")
        return
    default_user = cfg["DEFAULT"]["avi_user"]
    default_pass = cfg["DEFAULT"]["avi_pass"]

    global AVI_VERSION, API_STEP, API_LIMIT, VSMETRICS
    AVI_VERSION = cfg.get("SETTINGS", "avi_version", fallback="22.1.4")
    API_STEP    = cfg.getint("SETTINGS", "api_step", fallback=21600)
    API_LIMIT   = cfg.getint("SETTINGS", "api_limit", fallback=1)
    VSMETRICS   = (
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

    # Logging after paths exist
    configure_logging(args.debug, log_file)
    _log(f"Using metrics: {VSMETRICS}")

    # Build controllers map (use DEFAULT when value empty)
    controllers_cfg: Dict[str, Tuple[str, str]] = {}
    if "CONTROLLERS" in cfg:
        for name, combo in cfg["CONTROLLERS"].items():
            key = name.strip()
            if not key:
                continue
            # Skip stray setting-like keys if any (defensive)
            if key.lower() in {"avi_user", "avi_pass", "avi_version", "api_step", "api_limit"}:
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

    # CSV header
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
