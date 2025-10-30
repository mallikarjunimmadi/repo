#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
oswbb_ping_report_v3.py — Parse OSWbb ping outputs and generate 3 reports (full, anomalies, simple).

✅ NEW IN THIS VERSION
----------------------
• Default extensions: `.dat` and `.dat.gz`
• Processes files inside `.zip` archives (any depth)
• Works even if `oswprvtnet` appears in mixed case (case-insensitive match)
• Handles `.dat.gz` inside `.zip`
• Keeps `--infilename` logic, subdir detection, global min/max tracking

USAGE
-----
python3 oswbb_ping_report_v3.py --root /path/to/osw --infilename
"""

import argparse
import csv
import gzip
import io
import logging
import re
import zipfile
from datetime import datetime
from pathlib import Path
from typing import Dict, Tuple, Iterable, Optional, Union, Iterator

# --------------------------------------------------------------------
# Regex for parsing ping output
# --------------------------------------------------------------------
PING_HEADER_RE = re.compile(
    r"^\s*PING\s+(?P<dest_host>[^\s]+)\s*\((?P<dest_ip>\d{1,3}(?:\.\d{1,3}){3})\)"
    r"(?:\s+from\s+(?P<src_ip>\d{1,3}(?:\.\d{1,3}){3}))?",
    re.IGNORECASE
)
PING_REPLY_RE = re.compile(
    r"bytes\s+from\s+(?P<from_ip>\d{1,3}(?:\.\d{1,3}){3})[:].*?\btime=(?P<ms>[0-9]+(?:\.[0-9]+)?)\s*ms\b",
    re.IGNORECASE
)

# --------------------------------------------------------------------
# Helper functions
# --------------------------------------------------------------------
def bucket_for_latency(ms: float) -> str:
    if ms < 1.0:
        return "lt_1ms"
    if ms < 2.0:
        return "ge_1_lt_2_ms"
    if ms < 5.0:
        return "ge_2_lt_5_ms"
    return "ge_5_ms"

def get_named_subdirectory(parts: Iterable[str], marker_dir: str) -> Optional[str]:
    """Return the directory name immediately above marker_dir (case-insensitive)."""
    parts = list(parts)
    lower_parts = [p.lower() for p in parts]
    marker = marker_dir.lower()
    if marker in lower_parts:
        idx = lower_parts.index(marker)
        if idx > 0:
            return parts[idx - 1]
    return None

def should_include_suffix(suffixes: list[str], extensions: Optional[Iterable[str]]) -> bool:
    """Match extension set like .dat or .dat.gz"""
    ext = None
    if suffixes and suffixes[-1].lower() == ".gz" and len(suffixes) >= 2:
        ext = "".join(suffixes[-2:]).lower()
    elif suffixes:
        ext = suffixes[-1].lower()
    else:
        ext = ""
    exts = {e.lower() for e in extensions} if extensions else {".dat", ".dat.gz"}
    return ext in exts

def build_output_path(root: Path, base_output: Path, timestamp: str, kind: str) -> Path:
    root_prefix = root.name
    return base_output.with_name(f"{root_prefix}_ping_report_{kind}_{timestamp}{base_output.suffix}").resolve()

# --------------------------------------------------------------------
# Source discovery (on disk and inside ZIPs)
# --------------------------------------------------------------------
SourceItem = Union[Tuple[str, Path], Tuple[str, Path, str]]

def iter_disk_files(root: Path, marker_dir: str, extensions: Optional[Iterable[str]]) -> Iterator[SourceItem]:
    for p in root.rglob("*"):
        if not p.is_file() or p.suffix.lower() == ".zip":
            continue
        if marker_dir.lower() not in (s.lower() for s in p.parts):
            continue
        if should_include_suffix(p.suffixes, extensions):
            yield ("disk", p)

def iter_zip_files(root: Path, marker_dir: str, extensions: Optional[Iterable[str]]) -> Iterator[SourceItem]:
    """Scan zip archives under root for oswprvtnet files"""
    for zp in root.rglob("*.zip"):
        try:
            with zipfile.ZipFile(zp, "r") as zf:
                for name in zf.namelist():
                    if name.endswith("/"):
                        continue
                    # case-insensitive folder match
                    if f"/{marker_dir.lower()}/" not in name.lower():
                        continue
                    if should_include_suffix(Path(name).suffixes, extensions):
                        yield ("zip", zp, name)
        except Exception as e:
            logging.error("Error reading zip %s: %s", zp, e)

def find_sources(root: Path, marker_dir: str, extensions: Optional[Iterable[str]]) -> Iterator[SourceItem]:
    """Combine local and zip-based sources."""
    yield from iter_disk_files(root, marker_dir, extensions)
    yield from iter_zip_files(root, marker_dir, extensions)

# --------------------------------------------------------------------
# File opening logic (disk / zip)
# --------------------------------------------------------------------
def open_source(si: SourceItem) -> io.TextIOBase:
    """Open any source as text stream."""
    kind = si[0]
    if kind == "disk":
        _, path = si
        if path.suffix.lower() == ".gz":
            return io.TextIOWrapper(gzip.open(path, "rb"), encoding="utf-8", errors="ignore")
        return path.open("r", encoding="utf-8", errors="ignore")
    else:
        _, zp, inner = si
        zf = zipfile.ZipFile(zp, "r")
        raw = zf.open(inner)
        if inner.lower().endswith(".gz"):
            return io.TextIOWrapper(gzip.GzipFile(fileobj=raw), encoding="utf-8", errors="ignore")
        return io.TextIOWrapper(raw, encoding="utf-8", errors="ignore")

def describe_source(si: SourceItem) -> Tuple[str, list[str]]:
    """Return (label, path_parts) for naming/subdir derivation."""
    if si[0] == "disk":
        _, path = si
        return path.name, list(path.parts)
    else:
        _, zp, inner = si
        return f"{zp.name}::{inner}", Path(inner).parts

# --------------------------------------------------------------------
# Parsing logic
# --------------------------------------------------------------------
def parse_source(
    si: SourceItem,
    counters: Dict[Tuple[str, str, str, str], Dict[str, float]],
    marker_dir: str,
    include_file: bool,
    simple_totals: Dict[str, float],
) -> None:
    label, parts = describe_source(si)
    subdir = get_named_subdirectory(parts, marker_dir)
    if not subdir:
        return

    file_name = label if include_file else ""
    src_ip, dst_ip = None, None

    try:
        with open_source(si) as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue

                m_hdr = PING_HEADER_RE.match(line)
                if m_hdr:
                    dst_ip = m_hdr.group("dest_ip")
                    src_ip = m_hdr.group("src_ip")
                    continue

                m_rep = PING_REPLY_RE.search(line)
                if not m_rep:
                    continue

                ms = float(m_rep.group("ms"))
                dst = dst_ip or m_rep.group("from_ip")
                src = src_ip or "UNKNOWN"

                key = (subdir, file_name, src, dst)
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
                counters[key][bucket_for_latency(ms)] += 1

                # global tallies
                if ms < 1:
                    simple_totals["lt_1ms"] += 1
                elif ms <= 10:
                    simple_totals["gt_1_le_10_ms"] += 1
                else:
                    simple_totals["gt_10_ms"] += 1

                if simple_totals["global_min"] is None or ms < simple_totals["global_min"]:
                    simple_totals["global_min"] = ms
                if simple_totals["global_max"] is None or ms > simple_totals["global_max"]:
                    simple_totals["global_max"] = ms

    except Exception as e:
        logging.error("Error parsing %s: %s", label, e)

# --------------------------------------------------------------------
# Report writers
# --------------------------------------------------------------------
def write_full_csv(path: Path, counters: Dict, include_file: bool, anomalies_only=False) -> int:
    header = ["subdirectory"]
    if include_file:
        header.append("file_name")
    header += [
        "source_ip", "destination_ip",
        "<1ms", ">=1ms & <2ms", ">=2ms & <5ms", ">=5ms",
        "min_latency_ms", "max_latency_ms",
    ]
    rows = 0
    with path.open("w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(header)
        for (sub, fn, s, d), b in sorted(counters.items()):
            if anomalies_only and (b["ge_1_lt_2_ms"] == 0 and b["ge_2_lt_5_ms"] == 0 and b["ge_5_ms"] == 0):
                continue
            row = [sub]
            if include_file:
                row.append(fn)
            row += [s, d, b["lt_1ms"], b["ge_1_lt_2_ms"], b["ge_2_lt_5_ms"], b["ge_5_ms"],
                    f"{b['min']:.3f}", f"{b['max']:.3f}"]
            w.writerow(row)
            rows += 1
    return rows

def write_simple_csv(path: Path, totals: Dict[str, float]) -> None:
    with path.open("w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["category", "count"])
        w.writerow(["<1ms", int(totals["lt_1ms"])])
        w.writerow([">1ms & <=10ms", int(totals["gt_1_le_10_ms"])])
        w.writerow([">10ms", int(totals["gt_10_ms"])])

# --------------------------------------------------------------------
# Main
# --------------------------------------------------------------------
def main():
    ap = argparse.ArgumentParser(description="Generate latency reports (full/anomaly/simple) from OSWbb ping outputs.")
    ap.add_argument("--root", default=".", help="Root directory to scan recursively.")
    ap.add_argument("--marker-dir", default="oswprvtnet", help="Folder name under which ping files reside.")
    ap.add_argument("--output", default="ping_report.csv", help="Base filename for reports (prefix + timestamp auto).")
    ap.add_argument("--extensions", nargs="*", help="Extensions to include. Default: .dat .dat.gz")
    ap.add_argument("--infilename", action="store_true", help="Include file name in detailed reports.")
    ap.add_argument("--verbose", action="store_true")
    ap.add_argument("--debug", action="store_true")
    args = ap.parse_args()

    # Logging
    lvl = logging.WARNING
    if args.verbose: lvl = logging.INFO
    if args.debug: lvl = logging.DEBUG
    logging.basicConfig(format="%(levelname)s: %(message)s", level=lvl)

    root = Path(args.root).resolve()
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    counters = {}
    totals = {"lt_1ms": 0, "gt_1_le_10_ms": 0, "gt_10_ms": 0, "global_min": None, "global_max": None}

    sources = list(find_sources(root, args.marker_dir, args.extensions))
    logging.info("Found %d candidate sources", len(sources))

    for s in sources:
        parse_source(s, counters, args.marker_dir, args.infilename, totals)

    base = Path(args.output).resolve()
    f_full = build_output_path(root, base, timestamp, "full")
    f_anom = build_output_path(root, base, timestamp, "anomalies")
    f_simp = build_output_path(root, base, timestamp, "simple")

    n_full = write_full_csv(f_full, counters, args.infilename, anomalies_only=False)
    n_anom = write_full_csv(f_anom, counters, args.infilename, anomalies_only=True)
    write_simple_csv(f_simp, totals)

    total = int(totals["lt_1ms"] + totals["gt_1_le_10_ms"] + totals["gt_10_ms"])
    gmin = f"{totals['global_min']:.3f}" if totals["global_min"] else "n/a"
    gmax = f"{totals['global_max']:.3f}" if totals["global_max"] else "n/a"

    print("\n✅ Reports generated:")
    print(f"  Full report:    {f_full} ({n_full} rows)")
    print(f"  Anomalies only: {f_anom} ({n_anom} rows)")
    print(f"  Simple summary: {f_simp}")
    print(f"Totals: {total} samples  <1ms={int(totals['lt_1ms'])}  "
          f">1ms&<=10ms={int(totals['gt_1_le_10_ms'])}  >10ms={int(totals['gt_10_ms'])}  "
          f"min={gmin}ms  max={gmax}ms")

if __name__ == "__main__":
    main()
