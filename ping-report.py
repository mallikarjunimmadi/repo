#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
oswbb_ping_report.py — Parse OSWbb ping output and produce latency reports.

Usage:
  python3 oswbb_ping_report.py --root /data/oswbb [--infilename]

Outputs:
  • <root>_ping_report_full_<timestamp>.csv
  • <root>_ping_report_anomalies_<timestamp>.csv
"""

import argparse
import csv
import logging
import re
from datetime import datetime
from pathlib import Path
from typing import Dict, Tuple, Iterable, Optional

# --- Regex Patterns ---
PING_HEADER_RE = re.compile(
    r"^\s*PING\s+(?P<dest_host>[^\s]+)\s*\((?P<dest_ip>\d{1,3}(?:\.\d{1,3}){3})\)"
    r"(?:\s+from\s+(?P<src_ip>\d{1,3}(?:\.\d{1,3}){3}))?",
    re.IGNORECASE
)
PING_REPLY_RE = re.compile(
    r"bytes\s+from\s+(?P<from_ip>\d{1,3}(?:\.\d{1,3}){3})[:].*?\btime=(?P<ms>[0-9]+(?:\.[0-9]+)?)\s*ms\b",
    re.IGNORECASE
)

# ---------------------------------------------------------------------
def bucket_for_latency(ms: float) -> str:
    if ms < 1.0:
        return "lt_1ms"
    if ms < 2.0:
        return "ge_1_lt_2_ms"
    if ms < 5.0:
        return "ge_2_lt_5_ms"
    return "ge_5_ms"


def get_named_subdirectory(path: Path, marker_dir: str) -> Optional[str]:
    """Return the directory immediately above the marker_dir."""
    parts = path.parts
    try:
        idx = len(parts) - 1 - list(reversed(parts)).index(marker_dir)
        if idx - 1 >= 0:
            return parts[idx - 1]
    except ValueError:
        return None
    return None


def should_include(path: Path, marker_dir: str, extensions: Optional[Iterable[str]]) -> bool:
    if not path.is_file():
        return False
    if marker_dir not in path.parts:
        return False
    exts = {e.lower() for e in extensions} if extensions else {".dat"}
    return path.suffix.lower() in exts


def find_files(root: Path, marker_dir: str, extensions: Optional[Iterable[str]]) -> Iterable[Path]:
    for p in root.rglob("*"):
        if should_include(p, marker_dir, extensions):
            yield p


# ---------------------------------------------------------------------
def parse_file(path: Path,
               counters: Dict[Tuple[str, str, str, str], Dict[str, float]],
               marker_dir: str,
               include_file: bool) -> None:
    """Parse a file, update latency bucket counters and min/max."""
    subdir_name = get_named_subdirectory(path, marker_dir)
    if not subdir_name:
        return

    file_name = path.name if include_file else ""
    current_src: Optional[str] = None
    current_dst: Optional[str] = None

    try:
        with path.open("r", encoding="utf-8", errors="ignore") as fh:
            for raw_line in fh:
                line = raw_line.strip()
                if not line:
                    continue

                m_hdr = PING_HEADER_RE.match(line)
                if m_hdr:
                    current_dst = m_hdr.group("dest_ip")
                    current_src = m_hdr.group("src_ip")
                    continue

                m_rep = PING_REPLY_RE.search(line)
                if m_rep:
                    ms = float(m_rep.group("ms"))
                    dst_ip = current_dst or m_rep.group("from_ip")
                    src_ip = current_src or "UNKNOWN"
                    key = (subdir_name, file_name, src_ip, dst_ip)
                    if key not in counters:
                        counters[key] = {
                            "lt_1ms": 0,
                            "ge_1_lt_2_ms": 0,
                            "ge_2_lt_5_ms": 0,
                            "ge_5_ms": 0,
                            "min": ms,
                            "max": ms,
                        }
                    else:
                        # Update min/max
                        counters[key]["min"] = min(counters[key]["min"], ms)
                        counters[key]["max"] = max(counters[key]["max"], ms)
                    # Increment appropriate bucket
                    counters[key][bucket_for_latency(ms)] += 1

    except Exception as e:
        logging.exception("Failed to parse %s: %s", path, e)


# ---------------------------------------------------------------------
def write_csv(out_path: Path,
              counters: Dict[Tuple[str, str, str, str], Dict[str, float]],
              include_file: bool,
              anomalies_only: bool = False) -> int:
    """Write CSV file."""
    rows_written = 0
    header = ["subdirectory"]
    if include_file:
        header.append("file_name")
    header += [
        "source_ip", "destination_ip",
        "<1ms", ">=1ms & <2ms", ">=2ms & <5ms", ">=5ms",
        "min_latency_ms", "max_latency_ms",
    ]

    with out_path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(header)

        for (subdir, fname, src, dst), b in sorted(counters.items()):
            hi1, hi2, hi3 = b["ge_1_lt_2_ms"], b["ge_2_lt_5_ms"], b["ge_5_ms"]
            if anomalies_only and (hi1 == 0 and hi2 == 0 and hi3 == 0):
                continue
            row = [subdir]
            if include_file:
                row.append(fname)
            row += [
                src, dst,
                b["lt_1ms"], hi1, hi2, hi3,
                f"{b['min']:.3f}", f"{b['max']:.3f}",
            ]
            writer.writerow(row)
            rows_written += 1
    return rows_written


# ---------------------------------------------------------------------
def build_output_paths(root: Path, base_output: Path, timestamp: str, kind: str) -> Path:
    """Build output path prefixed with root basename and timestamped."""
    root_prefix = root.name
    return base_output.with_name(
        f"{root_prefix}_ping_report_{kind}_{timestamp}{base_output.suffix}"
    ).resolve()


def main():
    ap = argparse.ArgumentParser(description="Generate latency-bucket report from OSWbb ping outputs.")
    ap.add_argument("--root", required=True, help="Root directory to scan recursively.")
    ap.add_argument("--output", default="ping_report.csv", help="Base filename for reports.")
    ap.add_argument("--marker-dir", default="oswprvtnet", help="Marker directory (default: oswprvtnet).")
    ap.add_argument("--extensions", nargs="*", help="File extensions (default: .dat only).")
    ap.add_argument("--infilename", action="store_true", help="Include file name column in reports.")
    ap.add_argument("--verbose", action="store_true", help="Enable INFO logging.")
    ap.add_argument("--debug", action="store_true", help="Enable DEBUG logging.")
    args = ap.parse_args()

    level = logging.WARNING
    if args.verbose:
        level = logging.INFO
    if args.debug:
        level = logging.DEBUG
    logging.basicConfig(format="%(levelname)s: %(message)s", level=level)

    root = Path(args.root).resolve()
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    counters: Dict[Tuple[str, str, str, str], Dict[str, float]] = {}
    files = list(find_files(root, args.marker_dir, args.extensions))
    logging.info("Found %d matching files", len(files))

    for file_path in files:
        parse_file(file_path, counters, args.marker_dir, include_file=args.infilename)

    base_out = Path(args.output).resolve()
    full_path = build_output_paths(root, base_out, timestamp, "full")
    anomalies_path = build_output_paths(root, base_out, timestamp, "anomalies")

    total = write_csv(full_path, counters, include_file=args.infilename, anomalies_only=False)
    anomalies = write_csv(anomalies_path, counters, include_file=args.infilename, anomalies_only=True)

    print(f"Done.\n- Full report: {full_path} ({total} rows)\n- Anomalies:  {anomalies_path} ({anomalies} rows)")


if __name__ == "__main__":
    main()
