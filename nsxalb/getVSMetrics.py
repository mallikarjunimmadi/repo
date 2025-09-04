#!/usr/bin/env python3
import os
import sys
import time
import json
import argparse
import logging
import configparser
from datetime import datetime
from urllib.parse import urlencode
from typing import Optional, List

import requests
import urllib3

# -----------------------------
# Setup
# -----------------------------
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
CONFIG_FILE = "config.ini"


def load_config(profile: str) -> configparser.SectionProxy:
    cfg = configparser.ConfigParser()
    cfg.read(CONFIG_FILE)
    if profile not in cfg:
        raise ValueError(f"Profile '{profile}' not found in {CONFIG_FILE}")
    return cfg[profile]


def setup_logging(log_dir: str, debug: bool) -> str:
    os.makedirs(log_dir, exist_ok=True)
    log_file = os.path.join(log_dir, f"avi_rawdump_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log")
    level = logging.DEBUG if debug else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s %(levelname)s: %(message)s",
        handlers=[logging.FileHandler(log_file), logging.StreamHandler(sys.stdout)],
    )
    return log_file


def log(msg: str, level: str = "info") -> None:
    getattr(logging, level.lower(), logging.info)(msg)


def parse_list(val: Optional[str]) -> List[str]:
    """
    Accepts comma-separated or newline-separated values from config/CLI.
    Example:
      "a,b,c"  or
      "a\nb\nc"
    """
    if not val:
        return []
    parts: List[str] = []
    for line in val.splitlines():
        parts.extend([p.strip() for p in line.split(",") if p.strip()])
    return parts


def avi_login(controller: str, username: str, password: str):
    """Return (session_id, csrf_token) or (None, None)"""
    try:
        r = requests.post(
            f"https://{controller}/login",
            data={"username": username, "password": password},
            verify=False,
            timeout=30,
        )
        if r.status_code != 200:
            log(f"Login failed for {controller}: {r.status_code} {r.text[:200]}", "error")
            return None, None
        cookies = r.cookies.get_dict()
        return cookies.get("avi-sessionid"), cookies.get("csrftoken")
    except Exception as e:
        log(f"Login exception for {controller}: {e}", "error")
        return None, None


def retry_get(url: str, headers: dict, controller: str):
    last = None
    for attempt in range(3):
        try:
            resp = requests.get(url, headers=headers, verify=False, timeout=60)
            if resp.status_code == 429:
                wait = 5 * (attempt + 1)
                log(f"{controller}: 429 rate limit. Retrying in {wait}s (attempt {attempt+1}/3)", "warning")
                time.sleep(wait)
                last = resp
                continue
            return resp
        except Exception as e:
            log(f"{controller}: GET error {e} (attempt {attempt+1}/3)", "warning")
            time.sleep(2)
    return last


def build_metrics_url(
    controller: str,
    vs_uuid: str,
    metric_ids: str,
    limit: int = 720,
    step: Optional[int] = None,
    start: Optional[int] = None,
    end: Optional[int] = None,
) -> str:
    """
    Build the exact analytics URL:
      https://<controller>/api/analytics/metrics/virtualservice/<vs_uuid>/?metric_id=...&limit=...
    Optional: step, start, end (epoch ms)
    """
    base = f"https://{controller}/api/analytics/metrics/virtualservice/{vs_uuid}/"
    q = {"metric_id": metric_ids, "limit": limit}
    if step is not None:
        q["step"] = step
    if start is not None:
        q["start"] = start
    if end is not None:
        q["end"] = end
    return f"{base}?{urlencode(q)}"


def main():
    ap = argparse.ArgumentParser(
        description="Dump raw JSON from Avi/NSX ALB VS metrics API to timestamped files."
    )
    ap.add_argument("--profile", default="default", help="Profile in config.ini")
    ap.add_argument("--controller", help="Override controller (host or FQDN)")
    # VS selection: override config when provided
    ap.add_argument("--vs-uuid", help="Comma-separated VS UUIDs (overrides config vs_uuids)")
    # Metrics selection: override config when provided
    ap.add_argument("--metrics", help="Comma-separated metric_id list (overrides config metrics_default)")
    # API windowing
    ap.add_argument("--limit", type=int, default=None, help="API 'limit' (default from config or 720)")
    ap.add_argument("--step", type=int, default=None, help="Optional API 'step' in seconds")
    ap.add_argument("--start", type=int, default=None, help="Optional API 'start' epoch ms")
    ap.add_argument("--end", type=int, default=None, help="Optional API 'end' epoch ms")
    # Output & misc
    ap.add_argument("--output-dir", help="Output directory (defaults to profile output_dir or ./output)")
    ap.add_argument("--filename-prefix", default=None, help="(Ignored in this version; fixed name format)")
    ap.add_argument("--tenant", default=None, help="Tenant header (defaults to profile or 'admin')")
    ap.add_argument("--debug", action="store_true", help="Debug logging")
    args = ap.parse_args()

    # Load config
    cfg = load_config(args.profile)
    controller = args.controller or cfg.get("controller") or cfg.get("controllers", "").split(",")[0].strip()
    if not controller:
        raise SystemExit("No controller provided (use --controller or set controller/controllers in config).")

    username = cfg.get("username", "admin")
    password = cfg.get("password", "admin")
    avi_version = cfg.get("avi_version", "22.1.7")
    tenant = args.tenant or cfg.get("tenant", "admin")
    log_dir = cfg.get("log_dir", "logs")
    out_dir = args.output_dir or cfg.get("output_dir", "output")
    os.makedirs(out_dir, exist_ok=True)

    # Defaults from config, overridden by CLI when provided
    cfg_metrics_default = ",".join(parse_list(cfg.get("metrics_default", "")))
    metrics_csv = args.metrics if args.metrics else cfg_metrics_default

    cfg_vs_list = parse_list(cfg.get("vs_uuids", ""))
    vs_list = parse_list(args.vs_uuid) if args.vs_uuid else cfg_vs_list

    limit = args.limit if args.limit is not None else int(cfg.get("limit", "720"))

    # Validate presence
    if not metrics_csv:
        raise SystemExit("No metrics provided. Set [profile] metrics_default in config.ini or --metrics on CLI.")
    if not vs_list:
        raise SystemExit("No VS UUIDs provided. Set [profile] vs_uuids in config.ini or --vs-uuid on CLI.")

    setup_logging(log_dir, args.debug)
    log(f"Controller={controller} VS_count={len(vs_list)} limit={limit} step={args.step} start={args.start} end={args.end}")

    # Login once; reuse for all VS in this run
    sid, csrft = avi_login(controller, username, password)
    if not sid:
        raise SystemExit(2)

    headers = {
        "X-Avi-Tenant": tenant,
        "X-Avi-Version": avi_version,
        "X-Csrftoken": csrft,
        "Cookie": f"avi-sessionid={sid}; csrftoken={csrft}",
    }

    for vs_uuid in vs_list:
        url = build_metrics_url(controller, vs_uuid, metrics_csv, limit, args.step, args.start, args.end)
        log(f"GET {url}")
        r = retry_get(url, headers, controller)
        if not r:
            log(f"No response after retries for VS {vs_uuid}.", "error")
            continue
        if r.status_code != 200:
            log(f"Non-200 for VS {vs_uuid}: {r.status_code} {r.text[:500]}", "error")
            continue

        # Filename format: <vs_uuid>_<YYYYMMDDTHHMMSS>.json
        timestamp = datetime.now().strftime("%Y%m%dT%H%M%S")
        safe_vs = vs_uuid.replace("/", "_")
        out_path = os.path.join(out_dir, f"{safe_vs}_{timestamp}.json")

        with open(out_path, "w", encoding="utf-8") as f:
            f.write(r.text)
        log(f"Wrote: {out_path}")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(130)
