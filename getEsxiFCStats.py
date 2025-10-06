#!/usr/bin/env python3
import subprocess
import json
import csv
import os
import time
import argparse
from datetime import datetime
import socket

def run_command(command):
    try:
        return subprocess.check_output(command, shell=True, text=True).strip()
    except subprocess.CalledProcessError:
        return ""

def parse_stats(output, stat_type):
    blocks = output.split(f"{stat_type}:")
    parsed = []
    for block in blocks:
        lines = block.strip().splitlines()
        if not lines:
            continue
        stat = {}
        for line in lines:
            if ':' in line:
                key, value = line.strip().split(':', 1)
                key = key.strip()
                value = value.strip()
                try:
                    value = int(value)
                except ValueError:
                    pass
                stat[key] = value
        if 'Adapter' in stat:
            stat['Type'] = stat_type
            parsed.append(stat)
    return parsed

def collect_stats():
    timestamp = datetime.now().isoformat()
    fc_output = run_command("localcli storage san fc stats get")
    fcoe_output = run_command("localcli storage san fcoe stats get")

    fc_stats = parse_stats(fc_output, "FcStat")
    fcoe_stats = parse_stats(fcoe_output, "FcoeStat")

    return {
        "timestamp": timestamp,
        "fc_stats": fc_stats,
        "fcoe_stats": fcoe_stats
    }

def ensure_dir(path):
    if not os.path.exists(path):
        os.makedirs(path)

def get_log_files(log_dir, rotation, hostname, max_size_mb):
    now = datetime.now()
    base = f"{hostname}_fc_fcoe_stats"

    if rotation == "daily":
        suffix = now.strftime("%Y%m%d")
    elif rotation == "size":
        suffix = now.strftime("%Y%m%d-%H%M%S")
    else:
        suffix = now.strftime("%Y%m%d")

    json_file = os.path.join(log_dir, f"{base}-{suffix}.json")
    csv_file = os.path.join(log_dir, f"{base}-{suffix}.csv")

    # For "size" rotation, create a new file if the last one exceeds max_size
    if rotation == "size":
        for ext in ["json", "csv"]:
            file = json_file if ext == "json" else csv_file
            if os.path.exists(file) and os.path.getsize(file) > max_size_mb * 1024 * 1024:
                suffix = now.strftime("%Y%m%d-%H%M%S")
                json_file = os.path.join(log_dir, f"{base}-{suffix}.json")
                csv_file = os.path.join(log_dir, f"{base}-{suffix}.csv")

    return json_file, csv_file

def save_json(data, json_file):
    try:
        with open(json_file, "a") as f:
            f.write(json.dumps(data) + "\n")
    except Exception as e:
        print(f"[ERROR] JSON write failed: {e}")

def save_csv(data, csv_file):
    all_stats = data["fc_stats"] + data["fcoe_stats"]
    timestamp = data["timestamp"]

    fieldnames = ["timestamp", "Type", "Adapter"] + sorted({
        key for stat in all_stats for key in stat.keys()
        if key not in ("Type", "Adapter")
    })

    write_header = not os.path.exists(csv_file)

    try:
        with open(csv_file, "a", newline='') as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            if write_header:
                writer.writeheader()
            for stat in all_stats:
                row = {key: stat.get(key, "") for key in fieldnames}
                row["timestamp"] = timestamp
                writer.writerow(row)
    except Exception as e:
        print(f"[ERROR] CSV write failed: {e}")

def main(sleep_interval, log_dir, rotation, max_size):
    hostname = socket.gethostname()
    ensure_dir(log_dir)

    print(f"[INFO] Starting FC/FCoE stats collection on '{hostname}' every {sleep_interval}s")
    print(f"[INFO] Log Dir: {log_dir} | Rotation: {rotation} | Max Size: {max_size}MB")

    while True:
        try:
            stats = collect_stats()
            json_file, csv_file = get_log_files(log_dir, rotation, hostname, max_size)
            save_json(stats, json_file)
            save_csv(stats, csv_file)
            print(f"[INFO] Stats logged at {stats['timestamp']}")
            time.sleep(sleep_interval)
        except KeyboardInterrupt:
            print("\n[INFO] Script terminated by user.")
            break
        except Exception as e:
            print(f"[ERROR] Unexpected error: {e}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Collect FC/FCoE stats with flexible logging and rotation.")
    parser.add_argument("--sleep", type=int, default=5, help="Sleep interval in seconds (default: 5)")
    parser.add_argument("--log-dir", default="logs", help="Directory to store logs (default: ./logs)")
    parser.add_argument("--rotation", choices=["daily", "size"], default="daily", help="Log rotation mode: daily or size-based (default: daily)")
    parser.add_argument("--max-size", type=int, default=5, help="Max file size in MB before rotating (used only with --rotation size)")

    args = parser.parse_args()
    main(args.sleep, args.log_dir, args.rotation, args.max_size)
