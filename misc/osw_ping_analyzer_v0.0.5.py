#!/usr/bin/env python3
"""
ping_analyzer_v0.1.5.py

Cross-platform (Linux/macOS/Windows) ping spike analyzer for OSWatcher private-network ping logs.

Key behaviors:
- Walks from --root (default: current working directory)
- ONLY processes folders whose name exactly matches --target-dir (default: oswprvtnet)
- Inside each oswprvtnet folder, recursively processes ONLY .dat files by default
  (other extensions only if explicitly specified via --extensions)
- Parses:
  - Header: lines starting with "PING_PRIVATE" and extracts timestamp after "==="
  - PING line: "PING <dst> (...) from <src> : ..." to get src_ip and dst_ip
  - Reply: "<bytes> bytes from ... time=<latency> ms"
- Computes breach event_time using your "global slot" offset logic:
    offset_seconds = ((host_index-1) * pings_per_host + ping_in_host) * interval
    event_time = file_start_time + offset_seconds
- Produces THREE timestamped CSV outputs:
  1) detailed: ping_analysis_<timestamp>.csv
     - only threshold breaches, includes event_time
  2) summary: ping_summary_<timestamp>.csv
     - grouped by (file, src_ip, dst_ip, bytes), includes total_breaches + max_latency
     - NO timestamps in summary
  3) buckets: ping_buckets_<timestamp>.csv
     - grouped by (file, src_ip, dst_ip, bytes)
     - bucket counts computed from ALL ping samples (not filtered by threshold)
     - bucket labels are like: <1, >1 & <5, ..., >200

Notes:
- Timestamp parsing uses datetime.strptime with %Z. It works for common zones (e.g., IST) on many systems.
  If your platform doesn't recognize "IST", consider changing logs to include numeric offset or set TZ.
- Buckets are strict inequalities:
    <edge0
    >edge_i & <edge_{i+1}
    >last_edge
  Values exactly equal to an edge are NOT counted in middle buckets.
  (If you prefer inclusive boundaries, tell me and I’ll adjust.)
"""

import os
import argparse
import datetime
import logging
import csv
from collections import defaultdict


VERSION = "0.1.5"


# -----------------------------
# Logging
# -----------------------------
def setup_logging(log_file: str, debug: bool = False) -> None:
    level = logging.DEBUG if debug else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(message)s",
        handlers=[
            logging.FileHandler(log_file, encoding="utf-8"),
            logging.StreamHandler()
        ]
    )


# -----------------------------
# Timestamp parsing
# -----------------------------
def parse_header_timestamp(line: str):
    """
    Example:
      PING_PRIVATE_DEDICATED(1)===Mon Nov 3 00:48:32 IST 2025
    Returns:
      (file_timestamp_str, datetime_obj) or (None, None)
    """
    try:
        if "===" not in line:
            return None, None
        ts = line.split("===", 1)[1].strip()
        dt = datetime.datetime.strptime(ts, "%a %b %d %H:%M:%S %Z %Y")
        return ts, dt
    except Exception as e:
        logging.warning(f"Timestamp parse failed for header: {line!r} ({e})")
        return None, None


# -----------------------------
# Parse "PING ..." line for src/dst
# -----------------------------
def parse_ping_line(line: str):
    """
    Example:
      PING 10.176.235.156 (10.176.235.156) from 10.176.235.156 : 8972(9000) bytes of data.
    Returns:
      (src_ip, dst_ip) or (None, None)
    """
    try:
        parts = line.split()
        if len(parts) < 5:
            return None, None
        dst = parts[1]
        src = parts[4]
        return src, dst
    except Exception:
        return None, None


# -----------------------------
# Parse reply line for bytes + latency
# -----------------------------
def parse_ping_response(line: str):
    """
    Example:
      8980 bytes from 10.176.235.159: icmp_seq=4 ttl=64 time=0.532 ms
    Returns:
      (bytes_int, latency_ms_float) or (None, None)
    """
    try:
        parts = line.split()
        if not parts:
            return None, None
        bytes_val = int(parts[0])

        if "time=" not in line:
            return bytes_val, None

        latency_part = line.split("time=", 1)[1]
        latency_str = latency_part.split()[0]
        latency = float(latency_str)
        return bytes_val, latency
    except Exception:
        return None, None


# -----------------------------
# Find target directories
# -----------------------------
def find_target_dirs(base_dir: str, target_name: str):
    """
    Yield full paths of directories whose basename exactly equals target_name.
    """
    for dirpath, _, _ in os.walk(base_dir):
        if os.path.basename(dirpath) == target_name:
            yield dirpath


# -----------------------------
# Process a single file
# -----------------------------
def process_file(file_path: str, threshold: float, pph: int, interval: int,
                 breach_rows: list, all_rows: list) -> None:
    file_name = os.path.basename(file_path)
    logging.info(f"Processing: {file_name}")

    file_timestamp = None
    start_time = None

    host_idx = 0
    ping_in_host = 0

    src_ip = None
    dst_ip = None

    try:
        with open(file_path, "r", errors="ignore", encoding="utf-8") as f:
            for raw in f:
                line = raw.strip()

                # Header
                if line.startswith("PING_PRIVATE"):
                    file_timestamp, start_time = parse_header_timestamp(line)
                    host_idx = 0
                    ping_in_host = 0
                    src_ip = None
                    dst_ip = None
                    continue

                # New host block
                if line.startswith("PING "):
                    host_idx += 1
                    ping_in_host = 0
                    src_ip, dst_ip = parse_ping_line(line)
                    continue

                # Response line
                if ("bytes from" in line) and ("time=" in line):
                    bytes_val, latency = parse_ping_response(line)
                    if latency is None:
                        continue

                    ping_in_host += 1

                    # Capture ALL samples for bucket analysis
                    if file_timestamp:
                        all_rows.append({
                            "file": file_name,
                            "file_timestamp": file_timestamp,  # not used in summary/buckets output
                            "src_ip": src_ip,
                            "dst_ip": dst_ip,
                            "bytes": bytes_val,
                            "latency_ms": latency,
                        })

                    # Threshold breach -> detailed output
                    if (latency > threshold) and start_time and file_timestamp:
                        offset = ((host_idx - 1) * pph + ping_in_host) * interval
                        event_time = start_time + datetime.timedelta(seconds=offset)

                        breach_rows.append({
                            "file": file_name,
                            "file_timestamp": file_timestamp,
                            "src_ip": src_ip,
                            "dst_ip": dst_ip,
                            "bytes": bytes_val,
                            "latency_ms": latency,
                            "event_time": event_time.strftime("%Y-%m-%d %H:%M:%S"),
                        })

    except Exception as e:
        logging.error(f"Failed to read {file_path}: {e}")


# -----------------------------
# Write CSV
# -----------------------------
def write_csv(path: str, rows: list, fields: list) -> None:
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)


# -----------------------------
# Summary generation
# -----------------------------
def generate_summary(breach_rows: list) -> list:
    """
    Group by: (file, src_ip, dst_ip, bytes)
    Summary has NO timestamps and NO average.
    """
    grouped = defaultdict(list)

    for r in breach_rows:
        key = (r["file"], r["src_ip"], r["dst_ip"], r["bytes"])
        grouped[key].append(r["latency_ms"])

    out = []
    for (file_name, src, dst, bytes_val), vals in grouped.items():
        out.append({
            "file": file_name,
            "src_ip": src,
            "dst_ip": dst,
            "bytes": bytes_val,
            "total_breaches": len(vals),
            "max_latency": max(vals),
        })

    out.sort(key=lambda x: (x["file"], x["src_ip"], x["dst_ip"], x["bytes"]))
    return out


# -----------------------------
# Buckets / histogram generation
# -----------------------------
def _fmt_edge(e: float) -> str:
    # Clean labels: 1.0 -> 1, 0.5 -> 0.5
    if float(e).is_integer():
        return str(int(e))
    return str(e)


def generate_buckets(all_rows: list, edges: list):
    """
    Group by: (file, src_ip, dst_ip, bytes)
    Count ALL ping samples into bucket labels like:
      <1
      >1 & <5
      ...
      >200
    Strict inequalities are used for middle buckets.
    """
    edges = sorted(float(x) for x in edges)
    if len(edges) < 1:
        raise ValueError("bucket edges must have at least one value")

    labels = []
    labels.append(f"<{_fmt_edge(edges[0])}")
    for i in range(len(edges) - 1):
        labels.append(f">{_fmt_edge(edges[i])} & <{_fmt_edge(edges[i+1])}")
    labels.append(f">{_fmt_edge(edges[-1])}")

    counts = defaultdict(lambda: {lbl: 0 for lbl in labels})

    for r in all_rows:
        key = (r["file"], r["src_ip"], r["dst_ip"], r["bytes"])
        v = float(r["latency_ms"])

        # first bucket
        if v < edges[0]:
            counts[key][labels[0]] += 1
            continue

        # middle buckets
        placed = False
        for i in range(len(edges) - 1):
            if edges[i] < v < edges[i + 1]:
                counts[key][labels[i + 1]] += 1
                placed = True
                break

        # last bucket
        if not placed and v > edges[-1]:
            counts[key][labels[-1]] += 1

        # If v is exactly equal to an edge, it won't count anywhere with strict rules.

    out = []
    for (file_name, src, dst, bytes_val), cdict in counts.items():
        row = {
            "file": file_name,
            "src_ip": src,
            "dst_ip": dst,
            "bytes": bytes_val,
        }
        row.update(cdict)
        out.append(row)

    out.sort(key=lambda x: (x["file"], x["src_ip"], x["dst_ip"], x["bytes"]))
    columns = ["file", "src_ip", "dst_ip", "bytes"] + labels
    return out, columns


# -----------------------------
# Main
# -----------------------------
def main():
    parser = argparse.ArgumentParser(description=f"Ping Analyzer v{VERSION}")

    parser.add_argument("--root", default=".", help="Base directory to search (default: current working directory)")
    parser.add_argument("--target-dir", default="oswprvtnet",
                        help="Only process directories with this exact name (default: oswprvtnet)")
    parser.add_argument("--extensions", default=".dat",
                        help="Comma-separated extensions to process (default: .dat). "
                             "Other types only if explicitly specified.")
    parser.add_argument("--threshold", type=float, default=20.0, help="Latency threshold in ms")
    parser.add_argument("--pings-per-host", type=int, default=10, help="Assumed pings per remote host")
    parser.add_argument("--interval", type=int, default=1, help="Seconds between pings")
    parser.add_argument("--bucket-edges", default="1,5,10,20,50,100,200",
                        help="Comma-separated latency bucket edges in ms (default: 1,5,10,20,50,100,200)")
    parser.add_argument("--outdir", default=".", help="Output directory (default: current directory)")
    parser.add_argument("--log", default="ping_analyzer.log", help="Log file path")
    parser.add_argument("--debug", action="store_true", help="Enable debug logging")

    args = parser.parse_args()

    setup_logging(args.log, args.debug)

    run_ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    detailed_path = os.path.join(args.outdir, f"ping_analysis_{run_ts}.csv")
    summary_path = os.path.join(args.outdir, f"ping_summary_{run_ts}.csv")
    buckets_path = os.path.join(args.outdir, f"ping_buckets_{run_ts}.csv")

    exts = tuple(e.strip() for e in args.extensions.split(",") if e.strip())
    if not exts:
        exts = (".dat",)

    edges = [float(x.strip()) for x in args.bucket_edges.split(",") if x.strip()]
    if not edges:
        raise SystemExit("ERROR: --bucket-edges must contain at least one number")

    breach_rows = []  # threshold breaches -> detailed + summary
    all_rows = []     # all ping samples -> buckets

    if os.path.isfile(args.root):
        if args.root.endswith(exts):
            process_file(args.root, args.threshold, args.pings_per_host, args.interval, breach_rows, all_rows)
        else:
            logging.warning(f"Root is a file but does not match extensions {exts}: {args.root}")
    else:
        found_any = False
        for osw_dir in find_target_dirs(args.root, args.target_dir):
            found_any = True
            logging.info(f"Found target dir: {osw_dir}")
            for dirpath, _, files in os.walk(osw_dir):
                for fn in files:
                    if fn.endswith(exts):
                        process_file(os.path.join(dirpath, fn),
                                     args.threshold, args.pings_per_host, args.interval,
                                     breach_rows, all_rows)
        if not found_any:
            logging.warning(f"No directories named '{args.target_dir}' found under: {args.root}")

    # Detailed report (breaches only)
    write_csv(detailed_path, breach_rows, [
        "file",
        "file_timestamp",
        "src_ip",
        "dst_ip",
        "bytes",
        "latency_ms",
        "event_time",
    ])

    # Summary report (breaches only, no timestamps, no avg)
    summary_rows = generate_summary(breach_rows)
    write_csv(summary_path, summary_rows, [
        "file",
        "src_ip",
        "dst_ip",
        "bytes",
        "total_breaches",
        "max_latency",
    ])

    # Buckets report (ALL samples)
    bucket_rows, bucket_cols = generate_buckets(all_rows, edges)
    write_csv(buckets_path, bucket_rows, bucket_cols)

    logging.info(f"Detailed report: {detailed_path}")
    logging.info(f"Summary report:  {summary_path}")
    logging.info(f"Buckets report:  {buckets_path}")
    logging.info(f"Total breaches:  {len(breach_rows)}")
    logging.info(f"Total samples:   {len(all_rows)}")


if __name__ == "__main__":
    main()
