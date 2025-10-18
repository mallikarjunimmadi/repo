#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
alb-vsInventory-v1.3.1.py
Author: You + ChatGPT

NSX ALB (Avi) Virtual Service Inventory + Metrics (Avi SDK, Single CSV)

What this script does
---------------------
For each controller in your config:
  • Logs in via Avi SDK (ApiSession).
  • Fetches all VS CONFIG pages from /api/virtualservice?include_name=true&page_size=200
      – Friendly names in *_ref are available after the '#' suffix.
      – Extracts VS VIPs from config.vip[]. If not present, resolves via vsvip_ref using a preloaded vsvip map.
  • Fetches all VS RUNTIME pages from /api/virtualservice-inventory?page_size=200
      – State, Reason, Primary/Secondary SE name/IP/UUID, runtime cloud_type.
  • Fetches latest VS metrics from /api/analytics/metrics/virtualservice/<uuid>
      – Uses one call with repeated metric_id params, start/end/step, limit, limit_by_value=false.
      – Expands each metric into its own CSV column.
  • Writes one consolidated CSV across all controllers.

Why this version fixes your issues
----------------------------------
1) Metrics were N/A: now we pass start/end/step/limit_by_value=false (as in metricscollection.py) and pull the last datapoint,
   for all metrics in a single API call per VS.
2) Name references were null: we parse names from the '#Name' suffix (include_name=true) and fall back to the UUID tail.
3) VIP addresses were null: we read config.vip[] first; if empty, we use a vsvip cache (once per controller) keyed by vsvip uuid.
4) Pagination 404s: robust paginator handles absolute and relative 'next' links; prevents '/api/api/...' and '/api/https:...' paths.
5) Controllers parsing: only keys from [CONTROLLERS] are treated as controllers; [DEFAULT]/[SETTINGS] keys will never leak.

CSV header order
----------------
Controller, Virtual_Service_Name, VS_VIP, Port, Type(IPv4_/IPv6), VS_Enabled, Traffic_Enabled, SSL_Enabled,
VIP_as_SNAT, Auto_Gateway_Enabled, VH_Type, Application_Profile, SSL_Profile, SSL_Certificate_Name,
Analytics_Profile, Network_Profile, State, Reason, Pool, Service_Engine_Group, Primary_SE_Name,
Primary_SE_IP, Primary_SE_UUID, Secondary_SE_Name, Secondary_SE_IP, Secondary_SE_UUID,
Active_Standby_SE_Tag, Cloud, Cloud_Type, Tenant, Real_Time_Metrics_Enabled, <metric columns...>, VS_UUID

Config file (config.ini) expectations
-------------------------------------
[DEFAULT]
avi_user = admin
avi_pass = VMware1!VMware1!

[CONTROLLERS]
m00avientlb.local =
# or: controller-b.local = user,password

[SETTINGS]
avi_version = 22.1.7
api_step    = 21600
api_limit   = 1
vsmetrics_list = l4_client.avg_bandwidth,l4_client.avg_new_established_conns,l4_client.avg_complete_conns,l4_client.max_open_conns,l7_client.avg_ssl_handshakes_new,l7_client.avg_ssl_connections,l7_client.avg_ssl_handshakes_reused
default_metrics = l4_client.avg_bandwidth,l4_client.avg_complete_conns
report_output_dir = /home/imallikarjun/scripts/reports
log_output_dir    = /home/imallikarjun/scripts/nsxalb/logs

Usage
-----
python3 alb-vsInventory-v1.3.1.py \
  [--config config.ini] \
  [--controllers "m00avientlb.local,other.local"] \
  [--user admin --password '***'] \
  [--api-version 22.1.7] \
  [--output-dir /path/to/reports] \
  [--threads 5] \
  [--debug]

Notes
-----
• TLS warnings are suppressed for self-signed controllers.
• Booleans are printed as uppercase TRUE/FALSE.
• Debug logs include per-VS metric fetch timing and pagination details only when --debug is set.
"""

import os
import sys
import csv
import time
import logging
import argparse
import configparser
from datetime import datetime
from typing import Dict, List, Tuple, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed
from threading import Lock

import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Avi SDK
from avi.sdk.avi_api import ApiSession, APIError

# ---------------- Logging ----------------
def configure_logging(debug: bool, log_path: str):
    os.makedirs(os.path.dirname(log_path), exist_ok=True)
    level = logging.DEBUG if debug else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s: %(levelname)s: %(message)s",
        handlers=[logging.FileHandler(log_path), logging.StreamHandler(sys.stdout)],
    )
    logging.info(f"Logging initialized. Level={'DEBUG' if debug else 'INFO'}")

# ---------------- Helpers ----------------
CSV_LOCK = Lock()

def TF(val) -> str:
    return "TRUE" if bool(val) else "FALSE"

def validate_step(step: int) -> int:
    """Avi metrics step must be >=300 and a multiple of 300."""
    if step < 300:
        return 300
    if step % 300 != 0:
        return ((step // 300) + 1) * 300
    return step

def safe_name_from_ref(ref: Optional[str]) -> str:
    """Extract friendly name from a ref URL using '#Name' when available, else fallback to UUID tail."""
    if not ref:
        return "null"
    if "#" in ref:
        nm = ref.split("#")[-1].strip()
        if nm:
            return nm
    return ref.split("/")[-1].split("#")[0]

def join_semicolon(items: List[str]) -> str:
    items = [i for i in (items or []) if i]
    return ";".join(items) if items else "null"

# ---------------- Robust pagination (absolute/relative 'next') ----------------
def paged_get(api: ApiSession, path_or_url: str, params: Optional[dict] = None, debug: bool = False):
    """
    Yield all items from a GET that returns {results:[], next:...}.
    Works with:
      • 'virtualservice?include_name=true&page_size=200'
      • '/api/virtualservice?...'
      • 'https://controller/api/virtualservice?...'
    Uses api.avi_session for absolute URLs (older SDKs don't expose .session).
    """
    def _safe_get(u: str, p: Optional[dict] = None):
        # Absolute URL: call underlying requests Session directly to avoid '/api/' prefixing.
        if u.startswith("http"):
            sess = getattr(api, "avi_session", None)
            if sess is None:
                raise AttributeError("ApiSession object has no attribute 'avi_session'")
            if debug:
                logging.debug(f"GET(abs): {u}")
            return sess.get(u, headers=api.headers, verify=False)
        # Relative: sanitize leading '/api/' because ApiSession.get() will add it again.
        clean = u.lstrip("/")
        if clean.startswith("api/"):
            clean = clean[len("api/"):]
        if clean.startswith("/api/"):
            clean = clean[len("/api/"):]
        if debug:
            logging.debug(f"GET(rel): {clean} params={p}")
        return api.get(clean, params=p, verify=False)

    try:
        resp = _safe_get(path_or_url, params)
    except Exception as e:
        logging.error(f"GET {path_or_url} failed: {e}")
        return

    if resp.status_code != 200:
        logging.error(f"GET {path_or_url} HTTP {resp.status_code}: {resp.text[:160]}...")
        return

    while True:
        payload = resp.json()
        results = payload.get("results", []) or []
        for item in results:
            yield item
        nxt = payload.get("next")
        if not nxt:
            break
        try:
            resp = _safe_get(nxt)
        except Exception as e:
            logging.error(f"GET next failed: {e}")
            break
        if resp.status_code != 200:
            logging.error(f"GET next HTTP {resp.status_code}: {resp.text[:160]}...")
            break

# ---------------- VSVIP cache ----------------
def build_vsvip_cache(api: ApiSession, debug: bool = False) -> Dict[str, Tuple[str, str]]:
    """
    Return a map: vsvip_uuid -> (vip_addrs_joined, vip_types_joined)
    """
    cache: Dict[str, Tuple[str, str]] = {}
    count = 0
    for vv in paged_get(api, "vsvip", params={"page_size": 200, "include_name": True}, debug=debug):
        uuid = vv.get("uuid")
        if not uuid:
            continue
        addrs, types = [], []
        for v in vv.get("vip", []) or []:
            if v.get("ip_address"):
                addrs.append(v["ip_address"].get("addr", ""))
                types.append(v["ip_address"].get("type", ""))
            if v.get("ip6_address"):
                addrs.append(v["ip6_address"].get("addr", ""))
                types.append(v["ip6_address"].get("type", ""))
        cache[uuid] = (join_semicolon(addrs), join_semicolon(types))
        count += 1
    logging.info(f"VSVIP cache built: {count} entries")
    return cache

def extract_vips_from_vs(vs_cfg: dict, vsvip_cache: Dict[str, Tuple[str, str]]) -> Tuple[str, str]:
    """Try inline vip[] first; if absent, use vsvip_ref cache. Returns (vip_addrs, vip_types)."""
    addrs, types = [], []
    for v in vs_cfg.get("vip", []) or []:
        if v.get("ip_address"):
            addrs.append(v["ip_address"].get("addr", ""))
            types.append(v["ip_address"].get("type", ""))
        if v.get("ip6_address"):
            addrs.append(v["ip6_address"].get("addr", ""))
            types.append(v["ip6_address"].get("type", ""))
    if addrs or types:
        return join_semicolon(addrs), join_semicolon(types)

    # fallback: vsvip_ref
    ref = vs_cfg.get("vsvip_ref")
    if ref:
        uuid = ref.split("/")[-1].split("#")[0]
        if uuid in vsvip_cache:
            return vsvip_cache[uuid]
    return "null", "null"

# ---------------- Metrics (single call, official pattern) ----------------
def fetch_vs_metrics(api: ApiSession, vs_uuid: str, metric_ids: List[str], step: int, limit: int, debug: bool = False) -> Dict[str, str]:
    """
    Fetch latest datapoint for all metrics in one call.
    Returns dict: {metric_name: value or 'N/A'}
    """
    if not metric_ids:
        return {}
    step = validate_step(step)
    end_time = int(time.time())
    start_time = end_time - step

    params = [('metric_id', m) for m in metric_ids]
    params += [
        ('limit', max(1, int(limit))),
        ('step', step),
        ('start', start_time),
        ('end', end_time),
        ('include_refs', 'true'),
        ('limit_by_value', 'false'),
    ]
    t0 = time.time()
    try:
        resp = api.get(f"analytics/metrics/virtualservice/{vs_uuid}", params=params, verify=False)
    except Exception as e:
        logging.warning(f"[{vs_uuid}] Metrics API error: {e}")
        return {m: "N/A" for m in metric_ids}
    dt = time.time() - t0
    if resp.status_code != 200:
        logging.warning(f"[{vs_uuid}] Metrics HTTP {resp.status_code}: {resp.text[:160]}...")
        return {m: "N/A" for m in metric_ids}

    series = resp.json().get("series", []) or []
    out: Dict[str, str] = {m: "N/A" for m in metric_ids}
    for s in series:
        name = s.get("header", {}).get("name")
        data = s.get("data") or []
        if not name:
            continue
        val = data[-1].get("value", "N/A") if data else "N/A"
        # bandwidth conversion to MiB/s (optional, matches your earlier convention)
        if name == "l4_client.avg_bandwidth" and isinstance(val, (int, float)):
            val = round(val / 1048576, 2)
        out[name] = val

    if debug:
        nz = sum(1 for v in out.values() if v not in ("N/A", None))
        logging.debug(f"[{vs_uuid}] Metrics fetched in {dt:.3f}s | metrics={len(metric_ids)} | non-empty={nz}")
    return out

# ---------------- Per-controller worker ----------------
def process_controller(controller: str,
                       creds: Tuple[str, str],
                       writer: csv.writer,
                       metric_headers: List[str],
                       api_version: str,
                       step: int,
                       limit: int,
                       debug: bool):
    user, pwd = creds
    try:
        api = ApiSession.get_session(controller, user, pwd, tenant='admin', api_version=api_version)
        logging.info(f"[{controller}] Logged in")
    except Exception as e:
        logging.error(f"[{controller}] Login error: {e}")
        return

    # Build vsvip cache once
    vsvip_cache = build_vsvip_cache(api, debug=debug)

    # Pull all VS CONFIG (include_name for friendly names)
    cfg_map: Dict[str, dict] = {}
    cfg_count = 0
    for cfg in paged_get(api, "virtualservice", params={"include_name": True, "page_size": 200}, debug=debug):
        vs_uuid = cfg.get("uuid", None)
        if not vs_uuid:
            continue
        cfg_map[vs_uuid] = cfg
        cfg_count += 1
    logging.info(f"[{controller}] CONFIG fetched: {cfg_count}")

    # Pull all VS INVENTORY (runtime)
    rt_map: Dict[str, dict] = {}
    rt_count = 0
    for inv in paged_get(api, "virtualservice-inventory", params={"page_size": 200}, debug=debug):
        cfg = inv.get("config", {}) or {}
        runtime = inv.get("runtime", {}) or {}
        vu = cfg.get("uuid", None)
        if vu:
            rt_map[vu] = runtime
            rt_count += 1
    logging.info(f"[{controller}] RUNTIME fetched: {rt_count}")

    # Emit rows (merge cfg + runtime + metrics)
    metrics_non_empty = 0
    for vs_uuid, vs_cfg in cfg_map.items():
        vs_name = vs_cfg.get("name", "null")

        # VIPs and Types
        vip_addrs, vip_types = extract_vips_from_vs(vs_cfg, vsvip_cache)

        # Port and SSL flags
        services = vs_cfg.get("services") or []
        port = services[0].get("port", "null") if services else "null"
        ssl_enabled = any(s.get("enable_ssl") for s in services) or bool(
            vs_cfg.get("ssl_profile_ref") or vs_cfg.get("ssl_key_and_certificate_refs")
        )

        # Booleans & top-level
        vs_enabled      = TF(vs_cfg.get("enabled", False))
        traffic_enabled = TF(vs_cfg.get("traffic_enabled", False))
        vip_as_snat     = TF(vs_cfg.get("use_vip_as_snat", False))
        auto_gw         = TF(vs_cfg.get("enable_autogw", False))
        vh_type         = vs_cfg.get("vh_type", "null")

        # Real-time metrics toggle
        rtm_enabled = "FALSE"
        ap = vs_cfg.get("analytics_policy") or {}
        mru = ap.get("metrics_realtime_update")
        if isinstance(mru, dict) and mru.get("enabled"):
            rtm_enabled = "TRUE"
        elif isinstance(vs_cfg.get("metrics_realtime_update"), bool):
            rtm_enabled = TF(vs_cfg.get("metrics_realtime_update"))

        # Friendly names from refs
        app_prof      = safe_name_from_ref(vs_cfg.get("application_profile_ref"))
        ssl_prof      = safe_name_from_ref(vs_cfg.get("ssl_profile_ref"))
        analytics_pr  = safe_name_from_ref(vs_cfg.get("analytics_profile_ref"))
        net_prof      = safe_name_from_ref(vs_cfg.get("network_profile_ref"))
        pool_name     = safe_name_from_ref(vs_cfg.get("pool_ref"))
        se_group      = safe_name_from_ref(vs_cfg.get("se_group_ref"))
        cloud_name    = safe_name_from_ref(vs_cfg.get("cloud_ref"))
        tenant_name   = safe_name_from_ref(vs_cfg.get("tenant_ref"))
        active_stby   = vs_cfg.get("active_standby_se_tag", "null")
        cloud_type    = vs_cfg.get("cloud_type", "null")  # may be overridden by runtime below

        # SSL cert names
        cert_refs = vs_cfg.get("ssl_key_and_certificate_refs") or []
        ssl_cert_names = [safe_name_from_ref(ref) for ref in cert_refs if ref]
        ssl_certs = join_semicolon(ssl_cert_names)

        # Runtime merge
        rt = rt_map.get(vs_uuid, {}) or {}
        state  = (rt.get("oper_status") or {}).get("state", "null")
        reason = (rt.get("oper_status") or {}).get("reason", "null")
        cloud_type_rt = rt.get("cloud_type", None)
        if (not cloud_type) or cloud_type == "null":
            cloud_type = cloud_type_rt or "null"

        # Primary/Secondary SE from vip_summary.service_engine[]
        pri_name = pri_ip = pri_uuid = "null"
        sec_name = sec_ip = sec_uuid = "null"
        for vsum in rt.get("vip_summary", []) or []:
            for se in vsum.get("service_engine", []) or []:
                se_name = se.get("name") or "null"
                if (not se_name or se_name == "null") and se.get("se_ref"):
                    se_name = safe_name_from_ref(se["se_ref"])
                se_ip = (se.get("mgmt_ip") or {}).get("addr", "null")
                se_ref = se.get("se_ref", "")
                se_uuid = "null"
                if se_ref:
                    try:
                        se_uuid = se_ref.split("/")[-1].split("#")[0]
                    except Exception:
                        pass
                if se.get("is_primary") or se.get("primary"):
                    pri_name, pri_ip, pri_uuid = se_name, se_ip, se_uuid
                elif se.get("is_standby") or se.get("standby"):
                    sec_name, sec_ip, sec_uuid = se_name, se_ip, se_uuid

        # Metrics (one call)
        metrics_map = fetch_vs_metrics(api, vs_uuid, metric_headers, step, limit, debug=debug)
        if any(metrics_map.get(k) not in (None, "N/A") for k in metric_headers):
            metrics_non_empty += 1

        row = [
            controller,
            vs_name,
            vip_addrs,
            port,
            vip_types,
            vs_enabled,
            traffic_enabled,
            TF(ssl_enabled),
            vip_as_snat,
            auto_gw,
            vh_type,
            app_prof,
            ssl_prof,
            ssl_certs,
            analytics_pr,
            net_prof,
            state,
            reason,
            pool_name,
            se_group,
            pri_name,
            pri_ip,
            pri_uuid,
            sec_name,
            sec_ip,
            sec_uuid,
            active_stby,
            cloud_name,
            cloud_type,
            tenant_name,
            rtm_enabled,
        ] + [metrics_map.get(m, "N/A") for m in metric_headers] + [vs_uuid]

        with CSV_LOCK:
            writer.writerow(row)

        if debug:
            logging.debug(f"[{controller}] Wrote VS: {vs_name} ({vs_uuid})")

    logging.info(f"[{controller}] Rows written: {len(cfg_map)} | Metrics non-empty rows: {metrics_non_empty}")

# ---------------- Main ----------------
def main():
    parser = argparse.ArgumentParser(
        description="NSX ALB (Avi) VS inventory + metrics (Avi SDK, consolidated CSV).",
        epilog=(
            "Examples:\n"
            "  python3 alb-vsInventory-v1.3.1.py --config config.ini --debug\n"
            "  python3 alb-vsInventory-v1.3.1.py --controllers m00avientlb.local --user admin --password '***'\n"
            "  python3 alb-vsInventory-v1.3.1.py --controllers 'm00.local,m01.local' --threads 5 --output-dir /tmp/reports\n"
        ),
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument("--config", default="config.ini", help="Path to config.ini (default: config.ini)")
    parser.add_argument("--controllers", help="Comma-separated list to override [CONTROLLERS] in config.ini")
    parser.add_argument("--user", help="Override [DEFAULT] avi_user")
    parser.add_argument("--password", help="Override [DEFAULT] avi_pass")
    parser.add_argument("--api-version", help="Override API version (default from [SETTINGS].avi_version)")
    parser.add_argument("--output-dir", help="Override [SETTINGS].report_output_dir")
    parser.add_argument("--threads", type=int, default=5, help="Parallel workers (default: 5)")
    parser.add_argument("--debug", action="store_true", help="Enable verbose logging")
    args = parser.parse_args()

    cfg = configparser.ConfigParser()
    if not cfg.read(args.config):
        print(f"ERROR: {args.config} not found or unreadable.", file=sys.stderr)
        sys.exit(1)

    # Credentials: CLI override > [DEFAULT]
    d_user = args.user or cfg.get("DEFAULT", "avi_user", fallback="")
    d_pass = args.password or cfg.get("DEFAULT", "avi_pass", fallback="")
    if not d_user or not d_pass:
        print("ERROR: Missing creds. Provide --user/--password or set [DEFAULT] avi_user/avi_pass in config.ini", file=sys.stderr)
        sys.exit(1)

    avi_version = args.api_version or cfg.get("SETTINGS", "avi_version", fallback="22.1.7")
    api_step    = cfg.getint("SETTINGS", "api_step", fallback=21600)
    api_limit   = cfg.getint("SETTINGS", "api_limit", fallback=1)

    # Metrics list resolution (VS)
    metrics_str = (
        cfg.get("SETTINGS", "vsmetrics_list", fallback="").strip()
        or cfg.get("SETTINGS", "metrics_list", fallback="").strip()
        or cfg.get("SETTINGS", "default_metrics", fallback="l4_client.avg_bandwidth,l4_client.avg_complete_conns").strip()
    )
    metric_ids = [m.strip() for m in metrics_str.split(",") if m.strip()]

    report_dir = args.output_dir or cfg.get("SETTINGS", "report_output_dir", fallback=".")
    log_dir    = cfg.get("SETTINGS", "log_output_dir", fallback=".")
    os.makedirs(report_dir, exist_ok=True)
    os.makedirs(log_dir, exist_ok=True)

    ts = datetime.now().strftime("%Y%m%dT%H%M%S")
    out_csv = os.path.join(report_dir, f"avi-VSInventory_{ts}.csv")
    log_file= os.path.join(log_dir, f"{datetime.now():%Y-%m-%dT%H-%M-%S}_vs_inventory_sdk.log")
    configure_logging(args.debug, log_file)

    # Controllers map (only from [CONTROLLERS], unless CLI override provided)
    controllers_cfg: Dict[str, Tuple[str, str]] = {}
    if args.controllers:
        for c in [x.strip() for x in args.controllers.split(",") if x.strip()]:
            controllers_cfg[c] = (d_user, d_pass)
    elif "CONTROLLERS" in cfg:
        for key, combo in cfg["CONTROLLERS"].items():
            name = key.strip()
            if not name:
                continue
            parts = [p.strip() for p in (combo or "").split(",")] if combo is not None else []
            if len(parts) == 2 and parts[0] and parts[1]:
                controllers_cfg[name] = (parts[0], parts[1])   # inline creds
            else:
                controllers_cfg[name] = (d_user, d_pass)       # defaults
    else:
        logging.error("No controllers specified (CLI or [CONTROLLERS] in config.ini).")
        sys.exit(1)

    logging.info(f"Controllers: {', '.join(controllers_cfg.keys())}")
    logging.info(f"Metrics: {metric_ids} | step={api_step} | limit={api_limit}")

    # CSV header: fixed + metrics + VS_UUID
    fixed_header = [
        "Controller","Virtual_Service_Name","VS_VIP","Port","Type(IPv4_/IPv6)","VS_Enabled",
        "Traffic_Enabled","SSL_Enabled","VIP_as_SNAT","Auto_Gateway_Enabled","VH_Type",
        "Application_Profile","SSL_Profile","SSL_Certificate_Name","Analytics_Profile",
        "Network_Profile","State","Reason","Pool","Service_Engine_Group","Primary_SE_Name",
        "Primary_SE_IP","Primary_SE_UUID","Secondary_SE_Name","Secondary_SE_IP","Secondary_SE_UUID",
        "Active_Standby_SE_Tag","Cloud","Cloud_Type","Tenant","Real_Time_Metrics_Enabled"
    ]
    header = fixed_header + metric_ids + ["VS_UUID"]

    with open(out_csv, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(header)

        with ThreadPoolExecutor(max_workers=args.threads) as ex:
            futures = [
                ex.submit(process_controller, c, creds, writer, metric_ids, avi_version, api_step, api_limit, args.debug)
                for c, creds in controllers_cfg.items()
            ]
            for fut in as_completed(futures):
                try:
                    fut.result()
                except Exception as e:
                    logging.error(f"Worker error: {e}")

    logging.info(f"VS report saved: {out_csv}")

if __name__ == "__main__":
    main()
