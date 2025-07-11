#!/usr/bin/env python3

import os
import sys
import time
import json
import gzip
import shutil
import hashlib
import logging
import configparser
import threading
import argparse
import datetime
import pandas as pd
import re

from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, wait, as_completed
from logging.handlers import RotatingFileHandler
from influxdb_client import InfluxDBClient, Point, WriteOptions, WritePrecision
from influxdb_client.domain.bucket_retention_rules import BucketRetentionRules

# =========================
# CONSTANTS
# =========================
TRACK_FILE = "ingested_files.json"
CONFIG_FILE = "config.ini"
LOCK_EXTENSION = ".lock"

PREDEFINED_GROUPS = [
    "Memory",
    "Physical Cpu Load",
    "Physical Cpu",
    "Numa Node",
    "Power",
    "VSAN",
    "Group Cpu",
    "Vcpu",
    "Group Memory",
    "Physical Disk Adapter",
    "Physical Disk NFS Volume",
    "Physical Disk Path",
    "Physical Disk Partition",
    "Physical Disk Per-Device-Per-World",
    "Physical Disk SCSI Device",
    "Physical Disk",
    "Virtual Disk",
    "Network Port",
    "PCPU Power State"
]

# =========================
# GZip-enabled Rotating Handler
# =========================
class GZipRotatingFileHandler(RotatingFileHandler):
    """
    RotatingFileHandler that gzips old rotated logs.
    """
    def doRollover(self):
        super().doRollover()
        rotated = f"{self.baseFilename}.1"
        if os.path.exists(rotated):
            gzipped = rotated + ".gz"
            with open(rotated, 'rb') as f_in, gzip.open(gzipped, 'wb') as f_out:
                shutil.copyfileobj(f_in, f_out)
            os.remove(rotated)

# =========================
# Logging Setup
# =========================
def setup_logger(name, log_file, config=None):
    logger = logging.getLogger(name)
    logger.setLevel(logging.INFO)
    logger.propagate = False

    if logger.hasHandlers():
        return logger

    if config:
        log_max_mb = config.getint('general', 'log_max_mb', fallback=20)
        log_backup_count = config.getint('general', 'log_backup_count', fallback=5)
    else:
        log_max_mb = 20
        log_backup_count = 5

    log_max_bytes = log_max_mb * 1024 * 1024
    formatter = logging.Formatter(
        '[%(asctime)s] [%(levelname)s] [PID=%(process)d] [TID=%(thread)d] %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )

    os.makedirs(os.path.dirname(log_file), exist_ok=True)
    file_handler = GZipRotatingFileHandler(log_file, maxBytes=log_max_bytes, backupCount=log_backup_count)
    file_handler.setFormatter(formatter)

    console_handler = logging.StreamHandler()
    console_handler.setFormatter(formatter)

    logger.addHandler(file_handler)
    logger.addHandler(console_handler)
    return logger

# =========================
# Utility Functions
# =========================
def hash_file(path):
    hasher = hashlib.sha256()
    with open(path, 'rb') as f:
        while chunk := f.read(8192):
            hasher.update(chunk)
    return hasher.hexdigest()

def load_tracking():
    if os.path.exists(TRACK_FILE):
        with open(TRACK_FILE) as f:
            return json.load(f)
    return {}

def save_tracking(data):
    with open(TRACK_FILE, 'w') as f:
        json.dump(data, f, indent=2)

def create_lock(lock_path):
    try:
        with open(lock_path, 'x') as f:
            f.write(str(datetime.datetime.now()))
        return True
    except FileExistsError:
        return False

def remove_lock(lock_path):
    try:
        os.remove(lock_path)
    except FileNotFoundError:
        pass
# =========================
# Header Parsing
# =========================
def parse_header_by_groups(col, log):
    if not col.startswith("\\"):
        return None
    path_segments = col[2:].split('\\')
    if not path_segments:
        log.warning(f"Malformed header: '{col}'")
        return None

    full_hostname = path_segments[0].strip()
    short_hostname = full_hostname.split('.')[0]
    group_and_metric_segments = path_segments[1:]

    found_group = None
    group_index = -1
    for i, segment in enumerate(group_and_metric_segments):
        for group_cand in PREDEFINED_GROUPS:
            variants = [group_cand, group_cand.replace('-', ' '), group_cand.replace(' ', '-')]
            for variant in variants:
                if segment == variant or segment.startswith(f"{variant}("):
                    found_group = group_cand
                    group_index = i
                    break
            if found_group:
                break
        if found_group:
            break

    if found_group is None:
        log.warning(f"No predefined group found in: '{col}'")
        return None

    try:
        group_segment = group_and_metric_segments[group_index]
        instance = "overall"
        metric = ""
        group_part_len = len(found_group)
        for variant in [found_group, found_group.replace('-', ' '), found_group.replace(' ', '-')]:
            if group_segment.startswith(variant):
                group_part_len = len(variant)
                break
        remainder = group_segment[group_part_len:].strip()
        if remainder.startswith("("):
            instance_end = remainder.find(")")
            if instance_end != -1:
                instance = remainder[1:instance_end]
                if group_index + 1 < len(group_and_metric_segments):
                    metric = group_and_metric_segments[group_index + 1].strip()
            else:
                metric = remainder
                log.warning(f"Malformed instance in '{group_segment}', treating as metric.")
        else:
            if group_index + 1 < len(group_and_metric_segments):
                metric = group_and_metric_segments[group_index + 1].strip()
            else:
                metric = remainder.strip()

        if not metric:
            log.warning(f"Empty metric for column: '{col}'. Defaulting to 'value'.")
            metric = "value"

        return {
            "measurement": full_hostname,
            "short_hostname": short_hostname,
            "group": found_group,
            "instance": instance.strip(),
            "metric": metric.strip()
        }
    except Exception as e:
        log.warning(f"Failed to parse header '{col}': {e}")
        return None

def parse_headers(headers, log):
    mapping = {}
    for col in headers:
        if col == "Time" or "(PDH-CSV 4.0) (UTC)(0)" in col:
            continue
        parsed = parse_header_by_groups(col, log)
        if parsed:
            mapping[col] = parsed
    return mapping

# =========================
# Ingestion Function
# =========================
def process_file(filepath, args, tracker, config, master_logger):
    import time
    start_time = time.time()
    influx = None
    write_api = None


    fname = os.path.basename(filepath)
    lock_path = filepath + LOCK_EXTENSION
    log_dir = config.get('general', 'log_dir', fallback='logs')
    flog_path = os.path.join(log_dir, f"{fname}.log")
    flog = setup_logger(fname, flog_path, config)

    pid = os.getpid()
    tid = threading.get_ident()
    flog.info(f"=== Start Processing {fname} === (PID={pid}, TID={tid})")

    if not create_lock(lock_path):
        flog.info(f"Lock exists. Skipping {fname}.")
        return "skipped", fname, None

    try:
        fhash = hash_file(filepath)
        if fhash in tracker:
            flog.info(f"{fname} already ingested. Skipping.")
            return "skipped", fname, None

        flog.info(f"Reading CSV: {filepath}")
        df = pd.read_csv(filepath)
        if df.empty:
            raise ValueError("Empty CSV file")

        # Timestamp
        timestamp_col = None
        for col in df.columns:
            if col == "Time" or "(PDH-CSV 4.0) (UTC)(0)" in col:
                timestamp_col = col
                break
        if not timestamp_col:
            raise ValueError("Timestamp column not found.")
        df.rename(columns={timestamp_col: "Time"}, inplace=True)
        df["Time"] = pd.to_datetime(df["Time"], errors='coerce')
        flog.info(f"Parsed timestamps.")

        flog.info(f"Rows: {len(df)}, Columns: {len(df.columns)}")
        header_map = parse_headers(df.columns, flog)

        # Regex filters
        include_pattern = config.get(args.profile, 'include_metrics_regex', fallback='').strip()
        exclude_pattern = config.get(args.profile, 'exclude_metrics_regex', fallback='').strip()
        include_regex = re.compile(include_pattern) if include_pattern else None
        exclude_regex = re.compile(exclude_pattern) if exclude_pattern else None
        flog.info(f"Include filter: '{include_pattern if include_pattern else 'ALL'}'")
        flog.info(f"Exclude filter: '{exclude_pattern if exclude_pattern else 'NONE'}'")

        # InfluxDB parameters
        batch_size = config.getint('general', 'batch_size', fallback=5000)
        flush_interval = config.getint('general', 'flush_interval', fallback=5000)
        retention_seconds = config.getint('general', 'retention_seconds', fallback=0)
        write_retries = config.getint('general', 'write_retries', fallback=3)
        retry_sleep_seconds = config.getint('general', 'retry_sleep_seconds', fallback=5)

        influx = None
        write_api = None
        if not args.dry_run:
            influx = InfluxDBClient(
                url=args.url,
                token=args.token,
                org=args.org,
                timeout=60000
            )
            if not influx.ping():
                raise Exception("InfluxDB ping failed.")
            flog.info("InfluxDB connection OK.")

            buckets_api = influx.buckets_api()
            bucket_obj = buckets_api.find_bucket_by_name(args.bucket)
            if not bucket_obj:
                retention = BucketRetentionRules(type="expire", every_seconds=retention_seconds)
                buckets_api.create_bucket(bucket_name=args.bucket, org=args.org, retention_rules=retention)
                flog.info(f"Bucket created with retention {retention_seconds}s.")
            else:
                flog.info(f"Bucket exists.")

            write_api = influx.write_api(write_options=WriteOptions(batch_size=batch_size, flush_interval=flush_interval))

        # Writing
        records = 0
        batch_points = []
        for idx, row in enumerate(df.itertuples(index=False, name=None), start=1):
            row_dict = dict(zip(df.columns, row))
            ts = row_dict.get("Time")
            if pd.isna(ts):
                continue

            for col_name in df.columns:
                if col_name == "Time" or col_name not in header_map:
                    continue
                metric_info = header_map[col_name]
                metric_name = metric_info.get('metric', '')

                if exclude_regex and exclude_regex.search(metric_name):
                    continue
                if include_regex and not include_regex.search(metric_name):
                    continue

                val = row_dict.get(col_name)
                if pd.isna(val):
                    continue

                try:
                    val_float = float(val)
                    '''if val_float < 0:
                        flog.info(f"Negative value skipped: {metric_info['measurement']}/{metric_info['metric']}={val_float}")
                        continue'''
                except ValueError:
                    flog.warning(f"Non-numeric skipped: {metric_info['measurement']}/{metric_info['metric']}='{val}'")
                    continue


                if not args.dry_run:
                    point = Point(metric_info["measurement"]).time(ts, WritePrecision.NS)
                    point.tag("group", metric_info["group"])
                    point.tag("instance", metric_info["instance"])
                    if metric_info.get("short_hostname"):
                        point.tag("short_hostname", metric_info["short_hostname"])
                    point.field(metric_info["metric"], val_float)
                    batch_points.append(point)
                    records += 1

                    if len(batch_points) >= batch_size:
                        _write_with_retries(write_api, batch_points, args.bucket, args.org, write_retries, retry_sleep_seconds, flog, fname)
                        batch_points.clear()

            if idx % 10 == 0 or idx == len(df):
                flog.info(f"[{fname}]Progress: Row {idx}/{len(df)}, Records={records}")

        if not args.dry_run and batch_points:
            _write_with_retries(write_api, batch_points, args.bucket, args.org, write_retries, retry_sleep_seconds, flog, fname)
            flog.info(f"Wrote final batch of {len(batch_points)} points to InfluxDB.")

        # Archive with gzip
        if not args.dry_run:
            tracker[fhash] = {"file": fname, "path": str(filepath), "ingested_at": datetime.datetime.now().isoformat()}
            save_tracking(tracker)
            archive_dir = config.get('general','archive_dir', fallback='archive')
            #if args.archive_dir:
            archive_dest = os.path.join(archive_dir, fname + ".gz")
            with open(filepath, 'rb') as f_in, gzip.open(archive_dest, 'wb') as f_out:
                shutil.copyfileobj(f_in, f_out)
            os.remove(filepath)
            flog.info(f"Archived and compressed to {archive_dest}")

        duration = time.time() - start_time
        flog.info(f"Completed {fname} in {duration:.2f}s. Total points={records}")

        return "success", fname, None

    except Exception as e:
        flog.error(f"Error processing {fname}: {e}")
        return "failed", fname, str(e)
    finally:
        remove_lock(lock_path)
        if write_api in locals() and write_api:
            try: write_api.close()
            except: pass
        if influx:
            try: influx.close()
            except: pass

# =========================
# Write with Retry Helper
# =========================
def _write_with_retries(write_api, points, bucket, org, max_retries, sleep_seconds, log, fname):
    attempt = 0
    while attempt < max_retries:
        try:
            write_api.write(bucket=bucket, org=org, record=points)
            log.info(f"[{fname}] Wrote batch of {len(points)} points to InfluxDB.")
            return
        except Exception as e:
            attempt += 1
            if attempt < max_retries:
                log.warning(f"[{fname}] Write failed (attempt {attempt}), retrying in {sleep_seconds}s: {e}")
                time.sleep(sleep_seconds)
            else:
                log.error(f"[{fname}] Write failed after {max_retries} attempts: {e}")
                raise
# =========================
# Watcher Thread
# =========================
def watch_incoming_directory(config, incoming_dir, data_dir, master_log, poll_interval, min_file_age, work_queue):
    master_log.info(f"Started watching incoming_dir: {incoming_dir}")
    while True:
        try:
            archive_dir = config.get('general', 'archive_dir', fallback='archive')
            for fname in os.listdir(incoming_dir):
                src = os.path.join(incoming_dir, fname)
                if not os.path.isfile(src):
                    continue
                if src.endswith(LOCK_EXTENSION):
                    continue
                if not fname.lower().endswith('.csv'):
                    continue

                age = time.time() - os.path.getmtime(src)
                if age < min_file_age:
                    continue

                # Check if already ingested
                file_hash = hash_file(src)
                if file_hash in load_tracking():
                    archive_dest = os.path.join(archive_dir, fname + ".gz")
                    with open(src, 'rb') as f_in, gzip.open(archive_dest, 'wb') as f_out:
                        shutil.copyfileobj(f_in, f_out)
                    os.remove(src)
                    master_log.info(f"Archived incoming already-processed CSV: {fname}")
                    continue

                dest = os.path.join(data_dir, fname)
                if not os.path.exists(dest):
                    shutil.move(src, dest)
                    master_log.info(f"Moved new stable CSV to data_dir: {fname}")
                    work_queue.add(dest)

            time.sleep(poll_interval)
        except Exception as e:
            master_log.error(f"Error in watcher thread: {e}")
            time.sleep(poll_interval)

# =========================
# Daemon Main Loop
# =========================
def daemon_loop(args, config):
    incoming_dir = config.get('general', 'incoming_dir')
    data_dir = config.get('general', 'data_dir')
    archive_dir = config.get('general', 'archive_dir', fallback='archive')
    log_dir = config.get('general', 'log_dir', fallback='logs')

    poll_interval = config.getint('general', 'poll_interval_seconds', fallback=30)
    min_file_age = config.getint('general', 'min_file_age_seconds', fallback=60)
    max_concurrent_files = config.getint('general', 'max_concurrent_files', fallback=2)

    Path(incoming_dir).mkdir(parents=True, exist_ok=True)
    Path(data_dir).mkdir(parents=True, exist_ok=True)
    Path(archive_dir).mkdir(parents=True, exist_ok=True)
    Path(log_dir).mkdir(parents=True, exist_ok=True)

    master_log_path = os.path.join(log_dir, "esxtop.log")
    master_log = setup_logger("master", master_log_path, config)

    master_log.info("========== Daemon Starting ==========")
    master_log.info(f"Incoming Directory: {incoming_dir}")
    master_log.info(f"Data Directory: {data_dir}")
    master_log.info(f"Archive Directory: {archive_dir}")
    master_log.info(f"Log Directory: {log_dir}")
    master_log.info(f"Poll Interval: {poll_interval}s")
    master_log.info(f"Minimum File Age: {min_file_age}s")
    master_log.info(f"Max Concurrent Files: {max_concurrent_files}")

    for section in config.sections():
        master_log.info(f"[{section}]")
        for k, v in config[section].items():
            if "token" in k.lower():
                master_log.info(f"{k} = ***hidden***")
            else:
                master_log.info(f"{k} = {v}")

    tracker = load_tracking()
    work_queue = set()

    # Pick up leftover files in data_dir
    archive_dir = config.get('general', 'archive_dir', fallback='archive')
    for fname in os.listdir(data_dir):
        path = os.path.join(data_dir, fname)
        if not os.path.isfile(path) or path.endswith(LOCK_EXTENSION):
            continue
        if not fname.lower().endswith('.csv'):
            continue

        file_hash = hash_file(path)
        if file_hash in tracker:
            # Already processed ? archive immediately
            archive_dest = os.path.join(archive_dir, fname + ".gz")
            with open(path, 'rb') as f_in, gzip.open(archive_dest, 'wb') as f_out:
                shutil.copyfileobj(f_in, f_out)
            os.remove(path)
            master_log.info(f"Archived already-processed CSV on startup: {fname}")
        else:
            work_queue.add(path)
            master_log.info(f"Queued new CSV on startup: {fname}")


    # Watcher thread
    watcher_thread = threading.Thread(
        target=watch_incoming_directory,
        args=(config, incoming_dir, data_dir, master_log, poll_interval, min_file_age, work_queue),
        daemon=True
    )
    watcher_thread.start()

    # Processing Loop
    with ThreadPoolExecutor(max_workers=max_concurrent_files) as executor:
        futures = {}
        while True:
            # Submit new work
            to_submit = list(work_queue)
            for path in to_submit:
                if path not in futures.values():
                    future = executor.submit(process_file, path, args, tracker, config, master_log)
                    futures[future] = path
                    work_queue.remove(path)
                    master_log.info(f"Submitted {os.path.basename(path)} for ingestion.")

            # Check completed
            done, _ = wait(futures.keys(), timeout=1)
            for f in done:
                try:
                    status, fname, error = f.result()
                    if status == "success":
                        master_log.info(f"[OK] {fname}")
                    elif status == "skipped":
                        master_log.info(f"[SKIP] {fname}")
                    else:
                        master_log.error(f"[FAIL] {fname}: {error}")
                except Exception as ex:
                    master_log.error(f"[EXCEPTION] during task: {ex}")
                del futures[f]

            time.sleep(1)

# =========================
# Main Entry
# =========================
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="""
    esxtop InfluxDB Daemon

    Watches an incoming_dir for new stable CSV files.
    Moves them to data_dir once stable, locking during processing.
    Parses esxtop CSV, applies filtering, writes batches to InfluxDB.
    Archives ingested files as .gz in archive_dir.
    Logs rotating and gzipped in log_dir/esxtop.log
    """)
    parser.add_argument('--profile', default='dev', help='Profile in config.ini (dev, prod)')
    parser.add_argument('--bucket')
    parser.add_argument('--org')
    parser.add_argument('--token')
    parser.add_argument('--url')
    parser.add_argument('--threads', type=int)
    parser.add_argument('--dry-run', action='store_true', help='Parse only, no write to InfluxDB')
    args = parser.parse_args()

    config = configparser.ConfigParser()
    if os.path.exists(CONFIG_FILE):
        config.read(CONFIG_FILE)
    else:
        raise ValueError(f"{CONFIG_FILE} not found!")

    if args.profile not in config:
        raise ValueError(f"Profile '{args.profile}' not found in config.ini")

    # CLI overrides
    args.bucket = args.bucket or config.get(args.profile, 'bucket')
    args.org = args.org or config.get(args.profile, 'org')
    args.token = args.token or config.get(args.profile, 'token')
    args.url = args.url or config.get(args.profile, 'url', fallback='http://localhost:8086')
    args.threads = args.threads or config.getint('general', 'max_concurrent_files', fallback=2)

    if not args.dry_run:
        if not all([args.bucket, args.org, args.token, args.url]):
            raise ValueError("InfluxDB connection details must be provided.")

    daemon_loop(args, config)
