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
    Accepts comma- or newline-separated values from config/CLI.
    Example: "a,b,c" or "a\\nb\\nc"
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
    entity: str,   # "virtualservice" | "pool" | "serviceengine"
    uuid: str,
    metric_ids: str,
    limit: int = 720,
    step: Optional[int] = None,
    start: Optional[int] = None,
    end: Optional[int] = None,
) -> str:
    """
    Build the analytics URL:
      https://<controller>/api/analytics/metrics/<entity>/<uuid>/?metric_id=...&limit=...
    entity ∈ {"virtualservice","pool","serviceengine"}
    Optional: step, start, end (epoch ms)
    """
    base = f"https://{controller}/api/analytics/metrics/{entity}/{uuid}/"
    q = {"metric_id": metric_ids, "limit": limit}
    if step is not None:
        q["step"] = step
    if start is not None:
        q["start"] = start
    if end is not None:
        q["end"] = end
    return f"{base}?{urlencode(q)}"


def dump_entity(
    entity_label: str,          # Human label for logs
    entity_path: str,           # "virtualservice" | "pool" | "serviceengine"
    uuids: List[str],
    metrics_csv: str,
    controller: str,
    headers: dict,
    limit: int,
    step: Optional[int],
    start: Optional[int],
    end: Optional[int],
    out_dir: str,
):
    """Fetch and write raw JSON for each UUID of a given entity type."""
    if not uuids or not metrics_csv:
        log(f"Skipping {entity_label}: no UUIDs or no metrics configured.", "info")
        return

    for eid in uuids:
        url = build_metrics_url(controller, entity_path, eid, metrics_csv, limit, step, start, end)
        log(f"[{entity_label}] GET {url}")
        r = retry_get(url, headers, controller)
        if not r:
            log(f"[{entity_label}] No response after retries for {eid}.", "error")
            continue
        if r.status_code != 200:
            log(f"[{entity_label}] Non-200 for {eid}: {r.status_code} {r.text[:500]}", "error")
            continue

        timestamp = datetime.now().strftime("%Y%m%dT%H%M%S")
        safe_id = eid.replace("/", "_")
        out_path = os.path.join(out_dir, f"{safe_id}_{timestamp}.json")
        try:
            data = r.json()  # parse response
            with open(out_path, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2, ensure_ascii=False)  # pretty JSON
        except ValueError:
            # Fallback: if response isn't valid JSON, write raw text so you can inspect it
            with open(out_path, "w", encoding="utf-8") as f:
                f.write(r.text)
        log(f"[{entity_label}] Wrote: {out_path}")



def main():
    ap = argparse.ArgumentParser(
        description="Dump raw JSON from Avi/NSX ALB analytics metrics API (VS, Pool, SE) to timestamped files."
    )
    ap.add_argument("--profile", default="default", help="Profile in config.ini")
    ap.add_argument("--controller", help="Override controller (host or FQDN)")

    # --- VS overrides ---
    ap.add_argument("--vs-uuid", help="Comma-separated VS UUIDs (overrides config vs_uuids)")
    ap.add_argument("--metrics", help="Comma-separated VS metric_id list (overrides config metrics_default)")

    # --- Pool overrides ---
    ap.add_argument("--pool-uuid", help="Comma-separated Pool UUIDs (overrides config pool_uuids)")
    ap.add_argument("--pool-metrics", help="Comma-separated Pool metric_id list (overrides config pool_metrics_default)")

    # --- SE overrides ---
    ap.add_argument("--se-uuid", help="Comma-separated Service Engine UUIDs (overrides config se_uuids)")
    ap.add_argument("--se-metrics", help="Comma-separated SE metric_id list (overrides config se_metrics_default)")

    # API windowing
    ap.add_argument("--limit", type=int, default=None, help="API 'limit' (default from config or 720)")
    ap.add_argument("--step", type=int, default=None, help="Optional API 'step' in seconds")
    ap.add_argument("--start", type=int, default=None, help="Optional API 'start' epoch ms")
    ap.add_argument("--end", type=int, default=None, help="Optional API 'end' epoch ms")

    # Output & misc
    ap.add_argument("--output-dir", help="Output directory (defaults to profile output_dir or ./output)")
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
    # VS
    cfg_vs_metrics_default = ",".join(parse_list(cfg.get("metrics_default", "")))
    vs_metrics_csv = args.metrics if args.metrics else cfg_vs_metrics_default
    cfg_vs_list = parse_list(cfg.get("vs_uuids", ""))
    vs_list = parse_list(args.vs_uuid) if args.vs_uuid else cfg_vs_list

    # Pool
    cfg_pool_metrics_default = ",".join(parse_list(cfg.get("pool_metrics_default", "")))
    pool_metrics_csv = args.pool_metrics if args.pool_metrics else cfg_pool_metrics_default
    cfg_pool_list = parse_list(cfg.get("pool_uuids", ""))
    pool_list = parse_list(args.pool_uuid) if args.pool_uuid else cfg_pool_list

    # Service Engine
    cfg_se_metrics_default = ",".join(parse_list(cfg.get("se_metrics_default", "")))
    se_metrics_csv = args.se_metrics if args.se_metrics else cfg_se_metrics_default
    cfg_se_list = parse_list(cfg.get("se_uuids", ""))
    se_list = parse_list(args.se_uuid) if args.se_uuid else cfg_se_list

    limit = args.limit if args.limit is not None else int(cfg.get("limit", "720"))

    setup_logging(log_dir, args.debug)
    log(f"Controller={controller} limit={limit} step={args.step} start={args.start} end={args.end}", "info")

    # Login once; reuse for all calls in this run
    sid, csrft = avi_login(controller, username, password)
    if not sid:
        raise SystemExit(2)

    headers = {
        "X-Avi-Tenant": tenant,
        "X-Avi-Version": avi_version,
        "X-Csrftoken": csrft,
        "Cookie": f"avi-sessionid={sid}; csrftoken={csrft}",
    }

    # Process each entity only if both UUIDs and metrics are provided (non-empty)
    dump_entity(
        entity_label="VirtualService",
        entity_path="virtualservice",
        uuids=vs_list,
        metrics_csv=vs_metrics_csv,
        controller=controller,
        headers=headers,
        limit=limit,
        step=args.step,
        start=args.start,
        end=args.end,
        out_dir=out_dir,
    )

    dump_entity(
        entity_label="Pool",
        entity_path="pool",
        uuids=pool_list,
        metrics_csv=pool_metrics_csv,
        controller=controller,
        headers=headers,
        limit=limit,
        step=args.step,
        start=args.start,
        end=args.end,
        out_dir=out_dir,
    )

    dump_entity(
        entity_label="ServiceEngine",
        entity_path="serviceengine",
        uuids=se_list,
        metrics_csv=se_metrics_csv,
        controller=controller,
        headers=headers,
        limit=limit,
        step=args.step,
        start=args.start,
        end=args.end,
        out_dir=out_dir,
    )


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(130)
