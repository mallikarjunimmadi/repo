#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
NSX Advanced Load Balancer (Avi) - Virtual Service Inventory (v0.6)

What this script does (single CSV output):
1) Reads controllers & credentials from config.ini (no DEFAULT bleed into CONTROLLERS).
2) Logs into each controller (Requests session, no cert verify by default).
3) Lists all Virtual Services via /api/virtualservice?include_name=true with pagination.
4) For each VS:
   - Pulls joined CONFIG+RUNTIME via /api/virtualservice-inventory/<uuid>?include_name=true
     to get VIP IPs, oper state/reason, and primary/secondary SE details.
   - Extracts names from *ref* URLs using the '#<name>' fragment.
   - Fetches ALL requested metrics in a single call:
     /api/analytics/metrics/virtualservice/<uuid>/?metric_id=...%2C...&limit=N&step=S
     and records ONLY the numeric value (latest datapoint), coercing to int when possible.
5) Writes a CSV with the exact requested header order.
6) Prints a per-controller summary (VS count + timings), and total runtime.

Config file expected (config.ini):
[DEFAULT]
avi_user = admin
avi_pass = <password>

[CONTROLLERS]
m00aviblb.corp.ad.sbi =
# or override per host:
# other.controller.fqdn = username,password

[SETTINGS]
avi_version = 22.1.7
api_step = 21600
api_limit = 1
metrics_list = l4_client.avg_bandwidth,l4_client.avg_new_established_conns, ...

Notes & quirks handled:
- Some Avi versions return relative `next` links ("/api/virt..."), others absolute.
  We normalize both.
- name references are taken from the fragment part after '#' on ref URLs.
- Metrics payload shapes vary across versions. We accept both:
  series[i].data=[ [ts,value], ... ] OR series[i].data=[ {"timestamp": "...", "value": ...}, ... ]
- VIP IPs & SE primary/standby are pulled from virtualservice-inventory, which exposes
  config.vip[].ip_address and runtime.vip_summary[].service_engine[].

Tested against controller versions 22.1.x and 30.2.x.

Author: (you)
"""

import argparse
import csv
import datetime
import json
import logging
import os
import sys
import time
from urllib.parse import urljoin, urlencode, quote

import configparser
import requests

# ---------------------------- Logging ---------------------------------

def setup_logging(debug: bool):
    # Use proper datefmt for %Y etc., keep format free of strftime specifiers.
    fmt = "%(asctime)s: %(levelname)s: %(message)s"
    datefmt = "%Y-%m-%d %H:%M:%S"
    level = logging.DEBUG if debug else logging.INFO
    logging.basicConfig(level=level, format=fmt, datefmt=datefmt)
    # Quiet noisy libs unless --debug
    if not debug:
        logging.getLogger("urllib3.connectionpool").setLevel(logging.WARNING)


# ------------------------- Config handling ----------------------------

def read_config(path: str) -> configparser.ConfigParser:
    cfg = configparser.ConfigParser(allow_no_value=True)
    with open(path, "r", encoding="utf-8") as f:
        cfg.read_file(f)
    return cfg

def parse_controllers(cfg: configparser.ConfigParser):
    """
    ONLY read keys truly in [CONTROLLERS] (no DEFAULT merge).
    Each key is a controller FQDN/IP.
    Value: empty (= use DEFAULT creds) OR "user,password".
    """
    if 'CONTROLLERS' not in cfg:
        raise RuntimeError("config.ini missing [CONTROLLERS] section")

    # This mapping excludes DEFAULT interpolation.
    section_map = dict(cfg['CONTROLLERS'])
    controllers = []
    for host, val in section_map.items():
        host = host.strip()
        if not host:
            continue
        if val is None or val.strip() == "":
            controllers.append((host, None))  # use defaults
        else:
            controllers.append((host, val.strip()))
    return controllers

def parse_settings(cfg: configparser.ConfigParser):
    s = cfg['SETTINGS'] if 'SETTINGS' in cfg else {}
    avi_version = s.get('avi_version', '22.1.7')
    api_step = int(s.get('api_step', '21600'))
    api_limit = int(s.get('api_limit', '1'))
    metrics_raw = s.get('metrics_list', '').strip()
    if not metrics_raw:
        metrics_raw = s.get('default_metrics', '').strip()
    metrics = [m.strip() for m in metrics_raw.split(',') if m.strip()]
    out_dir = s.get('report_output_dir', '.').strip() or '.'
    os.makedirs(out_dir, exist_ok=True)
    return {
        'avi_version': avi_version,
        'api_step': api_step,
        'api_limit': api_limit,
        'metrics': metrics,
        'out_dir': out_dir
    }

def default_creds(cfg: configparser.ConfigParser):
    d = cfg['DEFAULT'] if 'DEFAULT' in cfg else {}
    return d.get('avi_user', 'admin'), d.get('avi_pass', 'Admin@123')


# --------------------------- HTTP Client ------------------------------

class AviClient:
    def __init__(self, base_host: str, api_version: str, verify_ssl: bool = False, timeout: int = 30):
        self.base_host = base_host.strip()
        self.base_url = f"https://{self.base_host}"
        self.api = urljoin(self.base_url, "/api/")
        self.sess = requests.Session()
        self.sess.verify = verify_ssl  # typically False for many deployments
        self.sess.headers.update({
            "Accept": "application/json",
            "X-Avi-Version": api_version
        })
        self.timeout = timeout

    def _full(self, maybe_url: str) -> str:
        """Normalize relative/absolute links to absolute."""
        if not maybe_url:
            return ""
        if maybe_url.startswith("http://") or maybe_url.startswith("https://"):
            return maybe_url
        # Leading slash -> join with base_url
        if maybe_url.startswith("/"):
            return urljoin(self.base_url, maybe_url)
        # Otherwise assume relative to /api/
        return urljoin(self.api, maybe_url)

    def login(self, user: str, password: str):
        url = urljoin(self.base_url, "/login")
        r = self.sess.post(url, json={"username": user, "password": password}, timeout=self.timeout)
        r.raise_for_status()
        logging.info("[%s] Logged in", self.base_host)

    def get_all_pages(self, path_with_query: str):
        """
        GET with pagination. Accepts relative ('/api/...') or absolute.
        Returns combined 'results' list.
        """
        results = []
        url = self._full(path_with_query)
        page = 1
        while url:
            logging.debug("Pagination GET (page %d): %s", page, url)
            r = self.sess.get(url, timeout=self.timeout)
            # Some controllers may 404 if a path is malformed; raise for clarity.
            r.raise_for_status()
            payload = r.json()
            chunk = payload.get('results') or payload.get('objs') or []
            results.extend(chunk)
            nxt = payload.get('next') or ""
            url = self._full(nxt) if nxt else None
            page += 1
        return results

    def get(self, path_or_url: str, params: dict | None = None):
        url = self._full(path_or_url)
        r = self.sess.get(url, params=params, timeout=self.timeout)
        r.raise_for_status()
        return r.json()

    def metrics_vs_multi(self, vs_uuid: str, metric_ids: list[str], limit: int, step: int):
        """
        Fetch multiple metrics for a VS in ONE call.
        We must encode commas as '%2C' per your requirement.
        """
        mid = "%2C".join([quote(m, safe="") for m in metric_ids])
        path = f"/api/analytics/metrics/virtualservice/{vs_uuid}/"
        url = self._full(path) + f"?metric_id={mid}&limit={limit}&step={step}"
        logging.debug("[metrics] %s", url)
        r = self.sess.get(url, timeout=self.timeout)
        # Some older/newer controllers 500 when no datapoints exist. Handle gracefully.
        if r.status_code >= 500:
            logging.warning("[%s] Metrics HTTP %s on %s", self.base_host, r.status_code, vs_uuid)
            return {}
        r.raise_for_status()
        return r.json() or {}


# ------------------------ Data extraction utils -----------------------

def name_from_ref(ref: str) -> str:
    """Extract display name from a ref URL fragment after '#'. Returns empty string if not present."""
    if not ref or not isinstance(ref, str):
        return ""
    if "#" in ref:
        frag = ref.split("#", 1)[-1].strip()
        return frag
    return ""

def vip_ip_from_inv(inv_obj: dict) -> tuple[str, str]:
    """
    Extract VIP and type (V4/V6) from virtualservice-inventory payload.
    Prefers runtime.vip_summary[].ip_address, falls back to config.vip[].ip_address.
    """
    rt = inv_obj.get("runtime", {})
    cfg = inv_obj.get("config", {})
    # Try runtime first
    vip_summary = rt.get("vip_summary") or []
    if vip_summary:
        ipa = vip_summary[0].get("ip_address") or {}
        return ipa.get("addr", ""), ipa.get("type", "")
    # Fallback to config
    vip_cfg = cfg.get("vip") or []
    if vip_cfg:
        ipa = vip_cfg[0].get("ip_address") or {}
        return ipa.get("addr", ""), ipa.get("type", "")
    return "", ""

def runtime_state_reason(inv_obj: dict) -> tuple[str, str]:
    rt = inv_obj.get("runtime", {})
    oper = rt.get("oper_status") or {}
    state = oper.get("state", "")
    # Reason could be list or string in different areas; try common places
    reason = oper.get("reason") or ""
    # Some envs place reasons under VS OPER_DOWN at top-level strings; keep as-is if present
    return state, reason

def se_primary_secondary(inv_obj: dict):
    """
    Return: (prim_name, prim_ip, prim_uuid, sec_name, sec_ip, sec_uuid, active_standby_tag)
    Names are parsed from the URL fragments in runtime.vip_summary[].service_engine[].url.
    """
    rt = inv_obj.get("runtime", {})
    vip_summary = rt.get("vip_summary") or []
    prim_name = prim_ip = prim_uuid = ""
    sec_name = sec_ip = sec_uuid = ""
    if vip_summary:
        se_list = vip_summary[0].get("service_engine") or []
        for se in se_list:
            url = se.get("url", "")
            nm = name_from_ref(url)
            ip = (se.get("mgmt_ip") or {}).get("addr", "")
            uid = se.get("uuid", "")
            if se.get("primary"):
                prim_name, prim_ip, prim_uuid = nm, ip, uid
            elif se.get("standby"):
                sec_name, sec_ip, sec_uuid = nm, ip, uid
    tag = ""
    # Try to lift the active_standby tag from config if present
    tag = inv_obj.get("config", {}).get("active_standby_se_tag", "") or tag
    return prim_name, prim_ip, prim_uuid, sec_name, sec_ip, sec_uuid, tag

def bool_to_str(b) -> str:
    return "TRUE" if bool(b) else "FALSE"

def series_to_latest_value(series_entry) -> int | float | str:
    """
    Accepts a single series object. Returns last datapoint value:
    - If data = [ [ts, val], ... ]  => return val of last element
    - If data = [ {"timestamp": "...", "value": X}, ... ] => return X of last element
    Coerce to int when possible (no fractional part).
    """
    if not series_entry:
        return "N/A"
    data = series_entry.get("data") or []
    if not data:
        return 0
    last = data[-1]
    # shape 1: list [ts, val]
    if isinstance(last, (list, tuple)) and len(last) >= 2:
        val = last[-1]
    # shape 2: dict {"timestamp": "...", "value": X}
    elif isinstance(last, dict):
        val = last.get("value", 0)
    else:
        return 0
    try:
        fv = float(val)
        iv = int(fv)
        return iv if fv.is_integer() else fv
    except Exception:
        return 0


# --------------------------- Main logic -------------------------------

COLUMNS = [
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
    # Metrics columns will be appended dynamically in the same order as in config
    # ...,
    "VS_UUID",
]

def controller_run(client: AviClient, creds: tuple[str, str], metrics: list[str], step: int, limit: int):
    """Process one controller; returns (rows, ctrl, vs_count, inv_secs, met_secs, total_secs)."""
    t0 = time.time()
    user, pwd = creds
    client.login(user, pwd)

    # 1) Fetch VS list with include_name and fields that we can rely on for flags/refs
    vs_path = "/api/virtualservice?include_name=true"
    vs_list = client.get_all_pages(vs_path)

    inv_t0 = time.time()
    rows = []
    for vs in vs_list:
        # Basic fields from VS list
        vs_name = vs.get("name", "")
        vs_uuid = vs.get("uuid", "")
        services = vs.get("services") or []
        port = services[0].get("port") if services else ""
        ssl_enabled = bool(services[0].get("enable_ssl")) if services else False

        vs_enabled = bool(vs.get("enabled", True))
        traffic_enabled = bool(vs.get("traffic_enabled", True))
        vip_as_snat = bool(vs.get("use_vip_as_snat", False))
        autogw = bool(vs.get("enable_autogw", False))
        vh_type = vs.get("vh_type", "") or vs.get("type", "")

        app_prof = name_from_ref(vs.get("application_profile_ref", ""))
        ssl_prof = name_from_ref(vs.get("ssl_profile_ref", ""))
        # Certificates (can be multiple)
        ssl_certs = vs.get("ssl_key_and_certificate_refs") or []
        ssl_cert_names = [name_from_ref(x) for x in ssl_certs if x]
        ssl_cert = "|".join([n for n in ssl_cert_names if n])

        analytics_prof = name_from_ref(vs.get("analytics_profile_ref", ""))
        net_prof = name_from_ref(vs.get("network_profile_ref", ""))
        pool_name = name_from_ref(vs.get("pool_ref", ""))
        seg_name = name_from_ref(vs.get("se_group_ref", ""))
        cloud_name = name_from_ref(vs.get("cloud_ref", ""))
        cloud_type = vs.get("cloud_type", "")
        tenant_name = name_from_ref(vs.get("tenant_ref", ""))

        # 2) Pull inventory for VIP + runtime/SE info in ONE call
        inv = client.get(f"/api/virtualservice-inventory/{vs_uuid}?include_name=true")
        vip_ip, ip_type = vip_ip_from_inv(inv)
        state, reason = runtime_state_reason(inv)
        prim_name, prim_ip, prim_uuid, sec_name, sec_ip, sec_uuid, as_tag = se_primary_secondary(inv)

        # 3) Real-time metrics flag (analytics_policy.metrics_realtime_update.enabled) may be in VS
        rt_enabled = False
        apol = vs.get("analytics_policy") or {}
        if isinstance(apol, dict):
            mru = apol.get("metrics_realtime_update") or {}
            rt_enabled = bool(mru.get("enabled", False))

        # 4) Metrics (single call per VS). Values only (int when possible).
        met_values = {}
        if metrics:
            payload = client.metrics_vs_multi(vs_uuid, metrics, limit=limit, step=step)
            # Map back metric_id -> latest value
            # Common shapes:
            # {"series": [{"header":{"name":"m1"},"data":[[ts,val],...]}, ...]}
            # OR {"series": [{"metric_id":"m1","data":[{"timestamp":"...","value":X}, ...]}, ...]}
            series = payload.get("series") or []
            for s in series:
                mname = ""
                hdr = s.get("header") or {}
                if "name" in hdr:
                    mname = hdr.get("name") or hdr.get("metric_id") or ""
                else:
                    mname = s.get("metric_id") or ""
                val = series_to_latest_value(s)
                met_values[mname] = val

        # 5) Compose CSV row
        base = [
            client.base_host,                # Controller
            vs_name,                         # Virtual_Service_Name
            vip_ip,                          # VS_VIP
            port,                            # Port
            ip_type,                         # Type(IPv4_/IPv6)
            bool_to_str(vs_enabled),         # VS_Enabled
            bool_to_str(traffic_enabled),    # Traffic_Enabled
            bool_to_str(ssl_enabled),        # SSL_Enabled
            bool_to_str(vip_as_snat),        # VIP_as_SNAT
            bool_to_str(autogw),             # Auto_Gateway_Enabled
            vh_type,                         # VH_Type
            app_prof,                        # Application_Profile
            ssl_prof,                        # SSL_Profile
            ssl_cert,                        # SSL_Certificate_Name
            analytics_prof,                  # Analytics_Profile
            net_prof,                        # Network_Profile
            state,                           # State
            reason,                          # Reason
            pool_name,                       # Pool
            seg_name,                        # Service_Engine_Group
            prim_name,                       # Primary_SE_Name
            prim_ip,                         # Primary_SE_IP
            prim_uuid,                       # Primary_SE_UUID
            sec_name,                        # Secondary_SE_Name
            sec_ip,                          # Secondary_SE_IP
            sec_uuid,                        # Secondary_SE_UUID
            as_tag,                          # Active_Standby_SE_Tag
            cloud_name,                      # Cloud
            cloud_type,                      # Cloud_Type
            tenant_name,                     # Tenant
            bool_to_str(rt_enabled),         # Real_Time_Metrics_Enabled
        ]
        # Append metrics in the order requested
        for m in metrics:
            base.append(met_values.get(m, 0))
        # Trailing UUID
        base.append(vs_uuid)

        rows.append(base)

    inv_secs = time.time() - inv_t0
    met_secs = 0.0  # metrics are included in inventory loop timing; keep separate label for clarity
    total_secs = time.time() - t0
    return rows, client.base_host, len(vs_list), inv_secs, met_secs, total_secs


# ------------------------------- CLI ----------------------------------

def build_arg_parser():
    p = argparse.ArgumentParser(
        description="NSX ALB (Avi) VS inventory to CSV (config+runtime+metrics)",
        epilog="Example: python3 alb-vsInventory-v0.6.py --config config.ini --debug"
    )
    p.add_argument("--config", default="config.ini", help="Path to config.ini (default: config.ini)")
    p.add_argument("--debug", action="store_true", help="Enable verbose debug logging")
    p.add_argument("--verify-ssl", action="store_true", help="Verify controller TLS certificates")
    return p

def main():
    args = build_arg_parser().parse_args()
    setup_logging(args.debug)

    try:
        cfg = read_config(args.config)
    except Exception as e:
        print(f"Failed to read config file '{args.config}': {e}", file=sys.stderr)
        sys.exit(1)

    controllers = parse_controllers(cfg)
    duser, dpass = default_creds(cfg)
    settings = parse_settings(cfg)
    metrics_list = settings['metrics']
    out_dir = settings['out_dir']

    logging.info("Controllers: %s", ", ".join([c for c, _ in controllers]))
    logging.info("Metrics: %s | step=%s | limit=%s",
                 metrics_list, settings['api_step'], settings['api_limit'])

    # Build CSV header with metrics inserted near the end, before VS_UUID
    header = COLUMNS[:-1] + metrics_list + [COLUMNS[-1]]

    all_rows = []
    grand_t0 = time.time()

    for host, override in controllers:
        # Determine creds
        if override:
            # user,password
            try:
                u, p = override.split(",", 1)
            except ValueError:
                logging.warning("Invalid creds format for %s; using DEFAULT creds.", host)
                u, p = duser, dpass
        else:
            u, p = duser, dpass

        client = AviClient(base_host=host,
                           api_version=settings['avi_version'],
                           verify_ssl=args.verify_ssl)

        try:
            rows, ctrl, vs_cnt, inv_secs, met_secs, total_secs = controller_run(
                client, (u, p), metrics_list, settings['api_step'], settings['api_limit']
            )
            all_rows.extend(rows)
            logging.info("[%s] VS fetched: %s | inventory+metrics: %.2fs | total: %.2fs",
                         ctrl, vs_cnt, inv_secs, total_secs)
        except Exception as e:
            logging.error("Controller task error for %s: %s", host, e)

    # Write CSV
    ts = datetime.datetime.now().strftime("%Y%m%dT%H%M%S")
    out_csv = os.path.join(out_dir, f"alb_vsInventory_{ts}.csv")
    with open(out_csv, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(header)
        w.writerows(all_rows)

    logging.info("CSV written: %s (rows=%d)", out_csv, len(all_rows))
    logging.info("Total runtime: %.2fs", time.time() - grand_t0)


if __name__ == "__main__":
    main()
