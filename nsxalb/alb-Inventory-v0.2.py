#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
NSX ALB (Avi) - Virtual Service Inventory with Metrics (v0.6 WIP)

What this script does (high level):
- Reads controllers and creds from a config.ini (your same format).
- For each controller:
  - Logs in once (requests.Session).
  - Calls ONE joined endpoint to fetch ALL Virtual Services with referenced objects resolved:
      /api/virtualservice?include_name=true&
        join=network_profile_ref,server_network_profile_ref,application_profile_ref,
             pool_ref,pool_group_ref,cloud_ref,ssl_profile_ref,ssl_key_and_certificate_refs,vsvip_ref
  - Handles pagination via the _next field. Works with absolute or relative URLs.
  - For each VS:
      * Extracts:
        - VIP (IP + Type) from joined vSVip (or runtime fallbacks)
        - Ports, flags, VH Type
        - Names of Application/Network/Analytics/SSL Profiles and SSL Certificate
        - Pool, SE Group, Cloud, Tenant names
        - State/Reason
        - Primary/Secondary SE name/IP/UUID from runtime.vip_summary[].service_engine[] (newer),
          with legacy fallbacks to vip_runtime[].se_list[] if needed
      * Fetches metrics in ONE call per VS:
        /api/analytics/metrics/virtualservice/<uuid>/?metric_id=<urlencoded list>&limit=1&step=<step>
        (values-only; no timestamps in CSV)
  - Builds per-controller summary: counts + timings.

- Writes a SINGLE CSV across all controllers in the order you specified.

Key implementation notes:
- “Name reference” extraction is robust: if the join expands to an object, use obj["name"];
  else fall back to parsing the URL fragment (#NAME). Never returns "null" strings.
- VIP extraction order:
  1) joined vsvip_ref.vip[0].ip_address.addr/type
  2) runtime.vip_summary[0].ip_address.addr/type (inventory-style)
  3) legacy vip_runtime[].vip_intf_list[].vip_intf_ip.addr/type
- Metrics extraction handles both series data formats (newer dicts),
  and returns 0 when not available or HTTP 500.

CLI:
  -c/--config : path to config.ini (default: ./config.ini)
  -o/--outdir : output directory for CSV (default: ./)
  --debug     : verbose debug logs (requests, URLs, parsing decisions)

Config file (same as yours):
[DEFAULT]
avi_user = admin
avi_pass = VMware1!VMware1!

[CONTROLLERS]
m00aviblb.local =
# or controllerA = user,password

[SETTINGS]
avi_version = 22.1.7
api_step = 21600
api_limit = 1
metrics_list = l4_client.avg_bandwidth,l4_client.avg_new_established_conns,...

Output filename:
  alb_vsInventory_<YYYYMMDDThhmmss>.csv

Tested behaviors (based on shared payloads):
- 22.1.7 and 30.2.x structures
- _next pagination (absolute/relative)
- URL fragment (#) name extraction and joined object .name access
- service_engine primary/standby derivation

"""

import argparse
import configparser
import csv
import datetime as dt
import logging
import os
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urljoin, urlencode, quote_plus

import requests
requests.packages.urllib3.disable_warnings()  # SSL verify False warning


# -----------------------------
# Logging helpers
# -----------------------------
def setup_logging(debug: bool):
    fmt = "%Y-%m-%d %H:%M:%S: %(levelname)s: %(message)s"
    level = logging.DEBUG if debug else logging.INFO
    logging.basicConfig(level=level, format=fmt)


# -----------------------------
# Utility helpers
# -----------------------------
def now_timestamp():
    return dt.datetime.now().strftime("%Y%m%dT%H%M%S")


def bool_to_str(x):
    if isinstance(x, bool):
        return "TRUE" if x else "FALSE"
    return "FALSE" if x in (None, "", "null") else str(x)


def safe_get(d, *keys, default=None):
    cur = d
    for k in keys:
        if cur is None:
            return default
        if isinstance(cur, dict):
            cur = cur.get(k, None)
        else:
            return default
    return cur if cur is not None else default


def name_from_ref(ref_val):
    """
    Extract a human name from either:
      - a joined object with {"name": "..."}; or
      - a URL with a #fragment (take the fragment); or
      - a plain string (return as-is).
    """
    if isinstance(ref_val, dict):
        n = ref_val.get("name")
        if n:
            return n
        # fall back to 'url' fragment if present
        url = ref_val.get("url") or ref_val.get("ref")
        if isinstance(url, str) and "#" in url:
            return url.split("#", 1)[-1]
        return ""  # joined but no name
    if isinstance(ref_val, str):
        if "#" in ref_val:
            return ref_val.split("#", 1)[-1]
        # sometimes Avi returns just the name in include_name=true:
        # e.g. "admin#admin" or plain "admin"
        return ref_val.split("#", 1)[-1] if "#" in ref_val else ref_val
    return ""


def abs_or_join(base, nxt):
    """Return an absolute URL for pagination given '_next' which may be absolute or relative."""
    if not nxt:
        return None
    if nxt.startswith("http://") or nxt.startswith("https://"):
        return nxt
    # handle common relative cases like /api/virtualservice?page=2 or api/virtualservice?page=2
    return urljoin(base, nxt)


def parse_metrics_series(json_body):
    """
    Normalize metrics response into {metric_name: value(float|int)}
    Expected formats (Avi variants):
      {
        "series": [
          {
            "header": {"name": "l4_client.avg_bandwidth", ...},
            "data": [{"timestamp": "...", "value": 123.0}, ...]
          },
          ...
        ]
      }
    We return only the LAST (or only) datapoint's 'value' from each series, or 0 if missing.
    """
    out = {}
    series = json_body.get("series", [])
    for s in series:
        # header could be dict or a simple name
        mname = None
        hd = s.get("header")
        if isinstance(hd, dict):
            mname = hd.get("name")
        if not mname:
            # sometimes "name" may be top-level in series
            mname = s.get("name")
        # pick last datapoint with "value"
        val = 0
        data = s.get("data", [])
        if data and isinstance(data, list):
            last = data[-1]
            if isinstance(last, dict):
                v = last.get("value")
                if isinstance(v, (int, float)):
                    val = v
                elif v is None:
                    val = 0
        if mname:
            out[mname] = val
    return out


def first_nonempty(*vals):
    for v in vals:
        if v not in (None, "", [], {}, "null"):
            return v
    return ""


# -----------------------------
# HTTP client (per controller)
# -----------------------------
class AviClient:
    def __init__(self, base_url, user, password, api_version=None, debug=False):
        self.base = base_url.rstrip("/")
        self.sess = requests.Session()
        self.sess.verify = False
        # Default headers; add version if provided
        self.sess.headers.update({"Accept": "application/json"})
        if api_version:
            self.sess.headers.update({"X-Avi-Version": api_version})
        self.debug = debug

    def login(self, user, password):
        url = f"{self.base}/login"
        if self.debug:
            logging.debug("POST %s", url)
        r = self.sess.post(url, json={"username": user, "password": password}, timeout=30)
        r.raise_for_status()
        logging.info("[%s] Logged in", self.base_hostname)

    @property
    def base_hostname(self):
        return self.base.split("://", 1)[-1]

    def get_json(self, url, params=None, allow_relative=False, desc="GET"):
        """
        GET JSON with support for relative URLs (pagination _next).
        """
        if allow_relative:
            url = abs_or_join(self.base, url)
        if self.debug:
            logging.debug("%s %s", desc, url)
        r = self.sess.get(url, params=params, timeout=60)
        # Some metrics endpoints return 200 with no length header (None); still ok if json body parses
        r.raise_for_status()
        return r.json()

    def get_paginated(self, path_with_query):
        """
        Iterate over joined list endpoints with _next.
        Returns combined list of 'results' from all pages and the last response json.
        """
        results = []
        url = f"{self.base}{path_with_query}" if path_with_query.startswith("/api/") else f"{self.base}/api/{path_with_query.lstrip('/')}"
        page = 1
        last_json = None

        while url:
            if self.debug:
                logging.debug("Pagination GET (page %s): %s", page, url)
            r = self.sess.get(url, timeout=120)
            r.raise_for_status()
            j = r.json()
            last_json = j
            recs = j.get("results") or j.get("virtual_service", []) or []
            results.extend(recs)
            nxt = j.get("_next")
            if not nxt:
                break
            url = abs_or_join(self.base, nxt)
            page += 1

        return results, last_json


# -----------------------------
# Data extraction for one VS
# -----------------------------
def extract_vip_and_type(vs_obj):
    """
    Preferred: joined vsvip_ref.vip[0].ip_address.{addr,type}
    Fallbacks:
      - runtime.vip_summary[0].ip_address
      - vip_runtime[].vip_intf_list[].vip_intf_ip
      - (very rare) config.vip[0].ip_address
    """
    # joined vsvip_ref
    vsvip = vs_obj.get("vsvip_ref")
    if isinstance(vsvip, dict):
        vip_list = vsvip.get("vip") or []
        if vip_list and isinstance(vip_list[0], dict):
            ipaddr = safe_get(vip_list[0], "ip_address", "addr")
            iptype = safe_get(vip_list[0], "ip_address", "type")
            if ipaddr:
                return ipaddr, iptype or ""

    # runtime.vip_summary style
    runtime = vs_obj.get("runtime") or {}
    vip_sum = runtime.get("vip_summary") or []
    if vip_sum and isinstance(vip_sum[0], dict):
        ipaddr = safe_get(vip_sum[0], "ip_address", "addr")
        iptype = safe_get(vip_sum[0], "ip_address", "type")
        if ipaddr:
            return ipaddr, iptype or ""

    # legacy vip_runtime[].vip_intf_list[]
    vip_rt = vs_obj.get("vip_runtime") or []
    if vip_rt and isinstance(vip_rt[0], dict):
        intfs = vip_rt[0].get("vip_intf_list") or []
        if intfs and isinstance(intfs[0], dict):
            ipaddr = safe_get(intfs[0], "vip_intf_ip", "addr")
            iptype = safe_get(intfs[0], "vip_intf_ip", "type")
            if ipaddr:
                return ipaddr, iptype or ""

    # config.vip (rare)
    cfg_vip = vs_obj.get("vip") or []
    if cfg_vip and isinstance(cfg_vip[0], dict):
        ipaddr = safe_get(cfg_vip[0], "ip_address", "addr")
        iptype = safe_get(cfg_vip[0], "ip_address", "type")
        if ipaddr:
            return ipaddr, iptype or ""

    return "", ""


def extract_se_roles(vs_obj):
    """
    Return:
      (primary_name, primary_ip, primary_uuid, secondary_name, secondary_ip, secondary_uuid)

    Preferred (newer): runtime.vip_summary[].service_engine[]
      {
        "uuid": "se-....",
        "primary": true/false,
        "standby": true/false,
        "mgmt_ip": {"addr":"..."},
        "url": "...#<SE-NAME>"
      }

    Fallback (legacy): vip_runtime[].se_list[] with is_primary/is_standby and se_ref + mgmt_ip
    """
    # Newer inventory style
    rt = vs_obj.get("runtime") or {}
    vip_sum = rt.get("vip_summary") or []
    if vip_sum:
        searr = safe_get(vip_sum[0], "service_engine") or []
        p_name = p_ip = p_uuid = s_name = s_ip = s_uuid = ""
        for se in searr:
            uuid = se.get("uuid", "")
            ip = safe_get(se, "mgmt_ip", "addr", default="")
            url = se.get("url", "")
            nm = url.split("#", 1)[-1] if "#" in url else ""
            if se.get("primary", False) or se.get("is_primary", False):
                p_name, p_ip, p_uuid = nm, ip, uuid
            elif se.get("standby", False) or se.get("is_standby", False):
                s_name, s_ip, s_uuid = nm, ip, uuid
        return p_name, p_ip, p_uuid, s_name, s_ip, s_uuid

    # Legacy vip_runtime[].se_list[]
    vip_rt = vs_obj.get("vip_runtime") or []
    if vip_rt:
        searr = vip_rt[0].get("se_list") or []
        p_name = p_ip = p_uuid = s_name = s_ip = s_uuid = ""
        for se in searr:
            uuid = name_from_ref(se.get("se_ref"))  # often has #<SE-NAME> as fragment
            # Better UUID from URL path if possible
            if isinstance(se.get("se_ref"), str):
                # /api/serviceengine/se-005056xxxx#name
                seg = se["se_ref"].split("/")[-1].split("#", 1)[0]  # se-0050...
                if seg.startswith("se-"):
                    uuid = seg
            ip = safe_get(se, "mgmt_ip", "addr", default="")
            nm = ""
            ref = se.get("se_ref", "")
            if isinstance(ref, str) and "#" in ref:
                nm = ref.split("#", 1)[-1]
            if se.get("is_primary", False):
                p_name, p_ip, p_uuid = nm, ip, uuid
            elif se.get("is_standby", False):
                s_name, s_ip, s_uuid = nm, ip, uuid
        return p_name, p_ip, p_uuid, s_name, s_ip, s_uuid

    return "", "", "", "", "", ""


def extract_state_and_reason(vs_obj):
    rt = vs_obj.get("runtime") or {}
    oper = rt.get("oper_status") or {}
    state = oper.get("state", "")
    # Some versions supply 'reason' as list or str; normalize to string
    reason = oper.get("reason")
    if isinstance(reason, list):
        reason = "; ".join(map(str, reason))
    if reason is None:
        reason = ""
    return state, reason


def process_vs_row(controller, vs_obj, metrics_names, metrics_map):
    """
    Turn a VS JSON object (from joined response) into a CSV row.
    metrics_map is a dict {metric_name: value} for this VS (already numeric).
    """
    name = vs_obj.get("name", "")
    uuid = vs_obj.get("uuid", "")

    # Ports/flags/basic
    services = vs_obj.get("services") or []
    port = services[0].get("port") if services else ""
    ssl_enabled = bool(services[0].get("enable_ssl")) if services else False

    vs_enabled = bool(vs_obj.get("enabled", False))
    traffic_enabled = bool(vs_obj.get("traffic_enabled", False))
    use_vip_as_snat = bool(vs_obj.get("use_vip_as_snat", False))
    enable_autogw = bool(vs_obj.get("enable_autogw", False))
    vh_type = vs_obj.get("vh_type", "")

    # Profiles/Refs joined or fragments
    application_profile = name_from_ref(vs_obj.get("application_profile_ref"))
    ssl_profile = name_from_ref(vs_obj.get("ssl_profile_ref"))

    # ssl cert name (first)
    ssl_cert_name = ""
    certs = vs_obj.get("ssl_key_and_certificate_refs")
    if isinstance(certs, list) and certs:
        ssl_cert_name = name_from_ref(certs[0])

    analytics_profile = name_from_ref(vs_obj.get("analytics_profile_ref"))
    network_profile = name_from_ref(vs_obj.get("network_profile_ref"))
    pool_name = name_from_ref(vs_obj.get("pool_ref"))
    se_group_name = name_from_ref(vs_obj.get("se_group_ref"))
    cloud_name = name_from_ref(vs_obj.get("cloud_ref"))
    cloud_type = vs_obj.get("cloud_type", "")
    tenant_name = name_from_ref(vs_obj.get("tenant_ref"))
    active_standby_se_tag = vs_obj.get("active_standby_se_tag", "")

    # VIP and type
    vip_ip, vip_type = extract_vip_and_type(vs_obj)

    # Runtime state/reason
    state, reason = extract_state_and_reason(vs_obj)

    # Primary/Secondary SEs
    p_name, p_ip, p_uuid, s_name, s_ip, s_uuid = extract_se_roles(vs_obj)

    # Real-time metrics toggle
    rt_metrics_enabled = safe_get(vs_obj, "analytics_policy", "metrics_realtime_update", "enabled", default=False)

    # Compose row (keep booleans as TRUE/FALSE strings)
    row = [
        controller,
        name,
        vip_ip,
        str(port) if port != "" else "",
        vip_type or "",
        bool_to_str(vs_enabled),
        bool_to_str(traffic_enabled),
        bool_to_str(ssl_enabled),
        bool_to_str(use_vip_as_snat),
        bool_to_str(enable_autogw),
        vh_type or "",
        application_profile or "",
        ssl_profile or "",
        ssl_cert_name or "",
        analytics_profile or "",
        network_profile or "",
        state or "",
        reason or "",
        pool_name or "",
        se_group_name or "",
        p_name or "",
        p_ip or "",
        p_uuid or "",
        s_name or "",
        s_ip or "",
        s_uuid or "",
        active_standby_se_tag or "",
        cloud_name or "",
        cloud_type or "",
        tenant_name or "",
        bool_to_str(rt_metrics_enabled),
    ]

    # Append metrics in the requested order
    for m in metrics_names:
        val = metrics_map.get(m, 0)
        # Keep as int where it makes sense (else float). If it's x.0 => int.
        if isinstance(val, float) and val.is_integer():
            val = int(val)
        row.append(val)

    # VS UUID last
    row.append(uuid)

    return row


# -----------------------------
# Controller worker
# -----------------------------
def fetch_vs_joined(client: AviClient):
    """
    Fetch all VS with include_name and big join to resolve names in one pass.
    """
    join_parts = [
        "network_profile_ref",
        "server_network_profile_ref",
        "application_profile_ref",
        "pool_ref",
        "pool_group_ref",
        "cloud_ref",
        "ssl_profile_ref",
        "ssl_key_and_certificate_refs",
        "vsvip_ref",
    ]
    join_q = "%2C".join(join_parts)
    path = f"/api/virtualservice?include_name=true&join={join_q}"
    vs_list, _ = client.get_paginated(path)
    return vs_list


def fetch_metrics(client: AviClient, vs_uuid: str, metrics_names, step: int, limit: int, debug=False):
    """
    Single call for multiple metrics per VS.
    """
    # Build URL with URL-encoded comma (%2C)
    metric_id_param = "%2C".join([quote_plus(m) for m in metrics_names])
    url = f"{client.base}/api/analytics/metrics/virtualservice/{vs_uuid}/?metric_id={metric_id_param}&limit={limit}&step={step}"
    if debug:
        logging.debug("[metrics] %s", url)
    try:
        j = client.get_json(url)
        return parse_metrics_series(j)
    except requests.HTTPError as he:
        # Common 500 in your logs — return zeros
        logging.warning("[%s] Metrics HTTP %s for %s: %s", client.base_hostname, he.response.status_code if he.response else "ERR", vs_uuid, he)
        return {m: 0 for m in metrics_names}
    except Exception as e:
        logging.warning("[%s] Metrics error for %s: %s", client.base_hostname, vs_uuid, e)
        return {m: 0 for m in metrics_names}


def controller_run(controller, creds, settings, metrics_names, out_rows, debug=False):
    """
    Execute the entire flow for one controller and extend out_rows with processed CSV rows.
    Returns (controller, vs_count, inventory_seconds, metrics_seconds, total_seconds)
    """
    t0 = time.time()
    base_url = f"https://{controller}"
    client = AviClient(base_url, creds[0], creds[1], api_version=settings.get("avi_version"), debug=debug)

    client.login(creds[0], creds[1])

    # Inventory pull (one joined call + pagination)
    t_inv0 = time.time()
    vs_list = fetch_vs_joined(client)
    t_inv1 = time.time()

    # Process rows + metrics
    step = int(settings.get("api_step", 21600))
    limit = int(settings.get("api_limit", 1))
    rows_local = []

    t_met0 = time.time()
    for vs in vs_list:
        vs_uuid = vs.get("uuid", "")
        if not vs_uuid:
            # Safety: some pages might return a subset
            continue
        metrics_map = fetch_metrics(client, vs_uuid, metrics_names, step, limit, debug)
        rows_local.append(process_vs_row(controller, vs, metrics_names, metrics_map))
    t_met1 = time.time()

    # Merge to global list
    out_rows.extend(rows_local)

    total = time.time() - t0
    return controller, len(vs_list), (t_inv1 - t_inv0), (t_met1 - t_met0), total


# -----------------------------
# Main
# -----------------------------
def load_config(path):
    cfg = configparser.ConfigParser()
    if not os.path.exists(path):
        raise FileNotFoundError(f"Config file not found: {path}")
    cfg.read(path)
    return cfg


def parse_controllers(cfg):
    """
    Controllers are keys under [CONTROLLERS].
    If value is empty => use DEFAULT creds.
    If value is 'user,password' => use those creds.
    """
    defaults = cfg["DEFAULT"] if "DEFAULT" in cfg else {}
    def_user = defaults.get("avi_user", "admin")
    def_pass = defaults.get("avi_pass", "Admin@123")

    controllers = []
    if "CONTROLLERS" in cfg:
        for host, val in cfg["CONTROLLERS"].items():
            host = host.strip()
            if not host:
                continue
            if val.strip():
                try:
                    u, p = val.split(",", 1)
                except ValueError:
                    u, p = def_user, def_pass
                    logging.warning("Invalid creds format for %s; using DEFAULT creds.", host)
            else:
                u, p = def_user, def_pass
            controllers.append((host, (u.strip(), p.strip())))
    return controllers


def main():
    parser = argparse.ArgumentParser(
        description="NSX ALB (Avi) Virtual Service Inventory with Metrics — single joined call per controller.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("-c", "--config", default="./config.ini", help="Path to config.ini")
    parser.add_argument("-o", "--outdir", default=".", help="Directory for CSV output")
    parser.add_argument("--debug", action="store_true", help="Enable verbose debug logging")
    args = parser.parse_args()

    setup_logging(args.debug)

    try:
        cfg = load_config(args.config)
    except Exception as e:
        logging.error("Failed to read config: %s", e)
        sys.exit(1)

    settings = cfg["SETTINGS"] if "SETTINGS" in cfg else {}
    # metrics list from settings.metrics_list; fallback to settings.default_metrics (first 7)
    mlist_raw = settings.get("metrics_list") or settings.get("default_metrics", "")
    metrics_names = [m.strip() for m in mlist_raw.split(",") if m.strip()]
    if not metrics_names:
        # sane default set of 7 fields (as discussed)
        metrics_names = [
            "l4_client.avg_bandwidth",
            "l4_client.avg_new_established_conns",
            "l4_client.avg_complete_conns",
            "l4_client.max_open_conns",
            "l7_client.avg_ssl_handshakes_new",
            "l7_client.avg_ssl_connections",
            "l7_client.avg_ssl_handshakes_reused",
        ]
    # Ensure exactly the columns you want — keep the list as-is even if user gives >7
    # We will include ALL metrics provided by config in that order.

    controllers = parse_controllers(cfg)
    if not controllers:
        logging.error("No controllers found in [CONTROLLERS]. Please populate config.ini.")
        sys.exit(2)

    logging.info("Controllers: %s", ", ".join([c for c, _ in controllers]))
    logging.info("Metrics: %s | step=%s | limit=%s", metrics_names, settings.get("api_step", 21600), settings.get("api_limit", 1))

    # Output CSV
    ts = now_timestamp()
    outdir = args.outdir
    os.makedirs(outdir, exist_ok=True)
    out_csv = os.path.join(outdir, f"alb_vsInventory_{ts}.csv")

    # CSV header in the exact order you requested
    header = [
        "Controller",
        "Virtual_Service_Name",
        "VS_VIP",
        "Port",
        "Type(IPv4_/IPv6)",
        "VS_Enabled",
        "Traffic_Enabled",
        "SSL_Enabled",
        "VIP_as_SNAT",
        "Auto_Gateway_Enabled",
        "VH_Type",
        "Application_Profile",
        "SSL_Profile",
        "SSL_Certificate_Name",
        "Analytics_Profile",
        "Network_Profile",
        "State",
        "Reason",
        "Pool",
        "Service_Engine_Group",
        "Primary_SE_Name",
        "Primary_SE_IP",
        "Primary_SE_UUID",
        "Secondary_SE_Name",
        "Secondary_SE_IP",
        "Secondary_SE_UUID",
        "Active_Standby_SE_Tag",
        "Cloud",
        "Cloud_Type",
        "Tenant",
        "Real_Time_Metrics_Enabled",
    ] + metrics_names + [
        "VS_UUID"
    ]

    all_rows = []
    summaries = []

    with ThreadPoolExecutor(max_workers=min(8, len(controllers))) as ex:
        futures = []
        for ctrl, creds in controllers:
            futures.append(ex.submit(controller_run, ctrl, creds, settings, metrics_names, all_rows, args.debug))

        for fut in as_completed(futures):
            try:
                ctrl, vs_count, inv_secs, met_secs, total_secs = fut.result()
                summaries.append((ctrl, vs_count, inv_secs, met_secs, total_secs))
            except Exception as e:
                logging.error("Controller task error: %s", e)

    # Write CSV
    with open(out_csv, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(header)
        w.writerows(all_rows)

    # Summaries
    for (ctrl, vs_count, inv_s, met_s, tot_s) in summaries:
        logging.info("[%s] VS fetched: %s | inventory: %.2fs | metrics: %.2fs | total: %.2fs",
                     ctrl, vs_count, inv_s, met_s, tot_s)
    logging.info("CSV written: %s (rows=%d)", out_csv, len(all_rows))


if __name__ == "__main__":
    main()
