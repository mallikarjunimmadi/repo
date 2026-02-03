#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
oswbb_ping_report.py — Parse OSWbb ping outputs and generate 3 reports (by default).

Outputs (always generated):
  1) Full report:     per (subdir[, file], src, dst) with buckets + min/max
  2) Anomalies:       only rows where any >=1ms bucket is non-zero
  3) Simple summary:  overall totals across all files: <1ms, >1ms & <=10ms, >10ms

Assumptions:
  • Folder layout: <root>/<subdir>/oswprvtnet/<files>
  • Scans only *.dat unless --extensions provided
  • Output filenames start with <root_basename> and include timestamp
  • Min/Max are per (src_ip, dst_ip) pair (optionally split by file if --infilename)

New:
  • Optional auto-extraction of OSWatcher archives under --root:
      --auto-extract extracts .tar/.tar.gz/.tgz/.zip into <root>/__extracted/<archive_name>/
      and scans extracted content.

Run with zero args to scan current directory:
  python3 oswbb_ping_report.py
"""

import argparse
import csv
import logging
import re
from datetime import datetime
from pathlib import Path
from typing import Dict, Tuple, Iterable, Optional, List

import tarfile
import zipfile

# --- Regexes ---
PING_HEADER_RE = re.compile(
    r"^\s*PING\s+(?P<dest_host>[^\s]+)\s*\((?P<dest_ip>\d{1,3}(?:\.\d{1,3}){3})\)"
    r"(?:\s+from\s+(?P<src_ip>\d{1,3}(?:\.\d{1,3}){3}))?",
    re.IGNORECASE
)
PING_REPLY_RE = re.compile(
    r"bytes\s+from\s+(?P<from_ip>\d{1,3}(?:\.\d{1,3}){3})[:].*?\btime=(?P<ms>[0-9]+(?:\.[0-9]+)?)\s*ms\b",
    re.IGNORECASE
)

# ---------------------------
# Bucketing / existing logic
# ---------------------------

def bucket_for_latency(ms: float) -> str:
    if ms < 1.0:
        return "lt_1ms"
    if ms < 2.0:
        return "ge_1_lt_2_ms"
    if ms < 5.0:
        return "ge_2_lt_5_ms"
    return "ge_5_ms"

def get_named_subdirectory(path: Path, marker_dir: str) -> Optional[str]:
    """Return the directory name immediately above marker_dir (e.g., 'db-rac1')."""
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

def parse_file(path: Path,
               counters: Dict[Tuple[str, str, str, str], Dict[str, float]],
               marker_dir: str,
               include_file: bool,
               simple_totals: Dict[str, int]) -> None:
    """
    Parse one file and update:
      - detailed counters per (subdir, [file], src, dst)
      - global simple_totals for the simple summary
    """
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
                        counters[key]["min"] = min(counters[key]["min"], ms)
                        counters[key]["max"] = max(counters[key]["max"], ms)

                    # Detailed bucket
                    counters[key][bucket_for_latency(ms)] += 1

                    # Simple totals
                    if ms < 1.0:
                        simple_totals["lt_1ms"] += 1
                    elif ms <= 10.0:
                        simple_totals["gt_1_le_10_ms"] += 1
                    else:
                        simple_totals["gt_10_ms"] += 1

    except Exception as e:
        logging.exception("Failed to parse %s: %s", path, e)

def write_full_or_anomalies_csv(out_path: Path,
                                counters: Dict[Tuple[str, str, str, str], Dict[str, float]],
                                include_file: bool,
                                anomalies_only: bool = False) -> int:
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

def write_simple_csv(out_path: Path, simple_totals: Dict[str, int]) -> int:
    """Write the overall-only simple summary CSV."""
    with out_path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["category", "count"])
        writer.writerow(["<1ms", simple_totals["lt_1ms"]])
        writer.writerow([">1ms & <=10ms", simple_totals["gt_1_le_10_ms"]])
        writer.writerow([">10ms", simple_totals["gt_10_ms"]])
    return 3

def build_output_path(root: Path, base_output: Path, timestamp: str, kind: str) -> Path:
    """
    Build output path prefixed with root basename and timestamped.
    kind ∈ {"full","anomalies","simple"}.
    Result: <dir>/<root>_ping_report_<kind>_<timestamp>.csv
    """
    root_prefix = root.name
    return base_output.with_name(
        f"{root_prefix}_ping_report_{kind}_{timestamp}{base_output.suffix}"
    ).resolve()

# ---------------------------
# NEW: Auto-extraction logic
# ---------------------------

def is_archive(p: Path) -> bool:
    n = p.name.lower()
    return n.endswith(".tar") or n.endswith(".tar.gz") or n.endswith(".tgz") or n.endswith(".zip")

def archive_stem(archive: Path) -> str:
    n = archive.name
    nl = n.lower()
    if nl.endswith(".tar.gz"):
        return n[:-7]
    if nl.endswith(".tgz"):
        return n[:-4]
    if nl.endswith(".tar"):
        return n[:-4]
    if nl.endswith(".zip"):
        return n[:-4]
    return archive.stem

def safe_extract_tar(tar: tarfile.TarFile, dest: Path) -> None:
    """
    Prevent path traversal. Ensures each member stays within dest.
    """
    dest_resolved = dest.resolve()
    for member in tar.getmembers():
        member_path = (dest / member.name).resolve()
        if not str(member_path).startswith(str(dest_resolved) + str(Path.sep)) and member_path != dest_resolved:
            raise RuntimeError(f"Unsafe tar member path: {member.name}")
    tar.extractall(dest)

def safe_extract_zip(zf: zipfile.ZipFile, dest: Path) -> None:
    """
    Prevent path traversal. Ensures each member stays within dest.
    """
    dest_resolved = dest.resolve()
    for name in zf.namelist():
        member_path = (dest / name).resolve()
        if not str(member_path).startswith(str(dest_resolved) + str(Path.sep)) and member_path != dest_resolved:
            raise RuntimeError(f"Unsafe zip member path: {name}")
    zf.extractall(dest)

def extract_archives(root: Path, extract_to: Path) -> Path:
    """
    Extract all archives under root into extract_to/<archive_stem>/.
    Returns the directory that should be scanned afterward (extract_to).
    """
    extract_to.mkdir(parents=True, exist_ok=True)
    archives: List[Path] = [p for p in root.rglob("*") if p.is_file() and is_archive(p)]
    logging.info("Auto-extract: found %d archive(s) under %s", len(archives), root)

    extracted_ok = 0
    extracted_skip = 0
    extracted_fail = 0

    for a in sorted(archives):
        out_dir = extract_to / archive_stem(a)
        out_dir.mkdir(parents=True, exist_ok=True)

        marker = out_dir / ".extracted.ok"
        if marker.exists():
            extracted_skip += 1
            logging.debug("Skip already extracted: %s -> %s", a, out_dir)
            continue

        logging.info("Extracting %s -> %s", a, out_dir)
        try:
            if a.name.lower().endswith(".zip"):
                with zipfile.ZipFile(a, "r") as zf:
                    safe_extract_zip(zf, out_dir)
            else:
                with tarfile.open(a, "r:*") as tf:
                    safe_extract_tar(tf, out_dir)

            marker.write_text("ok\n", encoding="utf-8")
            extracted_ok += 1
        except Exception as e:
            extracted_fail += 1
            logging.exception("Failed to extract %s: %s", a, e)

    logging.info(
        "Auto-extract summary: ok=%d, skipped=%d, failed=%d",
        extracted_ok, extracted_skip, extracted_fail
    )
    return extract_to

# ---------------------------
# Main
# ---------------------------

def main():
    ap = argparse.ArgumentParser(
        description="Generate latency reports (full, anomalies, and simple summary) from OSWbb ping outputs."
    )
    ap.add_argument("--root", default=".", help="Root directory to scan recursively. Default: current directory.")
    ap.add_argument("--output", default="ping_report.csv", help="Base filename for reports (prefix/timestamp auto).")
    ap.add_argument("--marker-dir", default="oswprvtnet", help="Marker directory name. Default: oswprvtnet")
    ap.add_argument("--extensions", nargs="*", help="File extensions to include. Default: .dat only.")
    ap.add_argument("--infilename", action="store_true", help="Include file name column in detailed reports.")
    ap.add_argument("--verbose", action="store_true", help="Enable INFO logs.")
    ap.add_argument("--debug", action="store_true", help="Enable DEBUG logs.")

    # NEW:
    ap.add_argument("--auto-extract", action="store_true",
                    help="Auto-extract OSWatcher archives (.tar/.tar.gz/.tgz/.zip) under --root before scanning.")
    ap.add_argument("--extract-to", default="__extracted",
                    help="Extraction directory name (created under --root). Default: __extracted")

    args = ap.parse_args()

    # Logging
    level = logging.WARNING
    if args.verbose:
        level = logging.INFO
    if args.debug:
        level = logging.DEBUG
    logging.basicConfig(format="%(levelname)s: %(message)s", level=level)

    root = Path(args.root).resolve()
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    # NEW: optionally extract archives first
    scan_root = root
    if args.auto_extract:
        extract_to = (root / args.extract_to).resolve()
        scan_root = extract_archives(root, extract_to)

    counters: Dict[Tuple[str, str, str, str], Dict[str, float]] = {}
    simple_totals = {"lt_1ms": 0, "gt_1_le_10_ms": 0, "gt_10_ms": 0}

    files = list(find_files(scan_root, args.marker_dir, args.extensions))
    logging.info("Found %d matching files under %s", len(files), scan_root)

    for file_path in files:
        parse_file(
            file_path,
            counters=counters,
            marker_dir=args.marker_dir,
            include_file=args.infilename,
            simple_totals=simple_totals,
        )

    base_out = Path(args.output).resolve()
    full_path = build_output_path(root, base_out, timestamp, "full")
    anomalies_path = build_output_path(root, base_out, timestamp, "anomalies")
    simple_path = build_output_path(root, base_out, timestamp, "simple")

    total_rows = write_full_or_anomalies_csv(full_path, counters, include_file=args.infilename, anomalies_only=False)
    anom_rows = write_full_or_anomalies_csv(anomalies_path, counters, include_file=args.infilename, anomalies_only=True)
    write_simple_csv(simple_path, simple_totals)

    total_samples = simple_totals["lt_1ms"] + simple_totals["gt_1_le_10_ms"] + simple_totals["gt_10_ms"]

    print("Done.")
    print(f"- Full report:    {full_path} ({total_rows} rows)")
    print(f"- Anomalies:      {anomalies_path} ({anom_rows} rows)")
    print(f"- Simple summary: {simple_path} (3 rows)")
    if args.auto_extract:
        print(f"Scanned extracted root: {scan_root}")
    print(f"Totals: samples={total_samples}, <1ms={simple_totals['lt_1ms']}, "
          f">1ms & <=10ms={simple_totals['gt_1_le_10_ms']}, >10ms={simple_totals['gt_10_ms']}")

if __name__ == "__main__":
    main()
