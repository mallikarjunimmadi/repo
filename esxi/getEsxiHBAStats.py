#!/usr/bin/env python3
import subprocess
import json
import csv
import os
import time
import argparse
from datetime import datetime
import socket
import sys

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

def validate_log_dir(path):
    try:
        if not os.path.exists(path):
            os.makedirs(path)
        testfile = os.path.join(path, ".write_test")
        with open(testfile, "w") as f:
            f.write("test")
        os.remove(testfile)
    except Exception as e:
        print(f"[ERROR] Cannot write to log directory '{path}': {e}")
        sys.exit(1)

def is_log_dir_writable(path):
    try:
        if not os.path.exists(path):
            os.makedirs(path)
        testfile = os.path.join(path, ".testwrite")
        with open(testfile, "w") as f:
            f.write("test")
        os.remove(testfile)
        return True
    except Exception as e:
        print(f"[WARN] Log directory inaccessible: {e}")
        return False

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

def main(interval, log_dir, rotation, max_size):
    hostname = socket.gethostname()
    validate_log_dir(log_dir)

    print("=" * 70)
    print(f"[INFO] Starting FC/FCoE Stats Collector on host: {hostname}")
    print(f"[INFO] Interval       : {interval} seconds")
    print(f"[INFO] Log Directory  : {log_dir}")
    print(f"[INFO] Rotation Mode  : {rotation}")
    print(f"[INFO] Max Size (MB)  : {max_size} (used only in 'size' rotation)")
    print("=" * 70)

    current_json_file = None
    current_csv_file = None

    while True:
        try:
            stats = collect_stats()

            if is_log_dir_writable(log_dir):
                if rotation == "daily":
                    date_str = datetime.now().strftime("%Y%m%d")
                    base = f"{hostname}_fc_fcoe_stats-{date_str}"
                    json_file = os.path.join(log_dir, f"{base}.json")
                    csv_file = os.path.join(log_dir, f"{base}.csv")
                    save_json(stats, json_file)
                    save_csv(stats, csv_file)

                elif rotation == "size":
                    if (not current_json_file or
                        not os.path.exists(current_json_file) or
                        os.path.getsize(current_json_file) > max_size * 1024 * 1024):

                        timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
                        base = f"{hostname}_fc_fcoe_stats-{timestamp}"
                        current_json_file = os.path.join(log_dir, f"{base}.json")
                        current_csv_file = os.path.join(log_dir, f"{base}.csv")

                    save_json(stats, current_json_file)
                    save_csv(stats, current_csv_file)

                print(f"[INFO] Stats logged at {stats['timestamp']}")
            else:
                print("[WARN] Skipping write — log directory not accessible.")

            time.sleep(interval)

        except KeyboardInterrupt:
            print("\n[INFO] Script terminated by user.")
            break
        except Exception as e:
            print(f"[ERROR] Unexpected error: {e}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Collect FC/FCoE stats with flexible logging and rotation.")
    parser.add_argument("--interval", type=int, default=5, help="Interval between samples in seconds (default: 5)")
    parser.add_argument("--log-dir", default="logs", help="Directory to store logs (default: ./logs)")
    parser.add_argument("--rotation", choices=["daily", "size"], default="daily", help="Log rotation mode: daily or size-based (default: daily)")
    parser.add_argument("--max-size", type=int, default=5, help="Max file size in MB before rotating (only for size mode)")

    args = parser.parse_args()
    main(args.interval, args.log_dir, args.rotation, args.max_size)
