#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
oswbb_ping_report.py — Parse OSWbb ping outputs and generate 3 reports (by default).

What's new in this version
--------------------------
• Default extensions now: .dat AND .dat.gz
• Also scans inside .zip archives found under --root (recursively)
• Only inspect files that live under an 'oswprvtnet' folder (on disk or inside zips)

Outputs (always generated)
--------------------------
1) Full report:     per (subdir[, file], src, dst) with buckets + min/max
2) Anomalies:       only rows where any >=1ms bucket is non-zero
3) Simple summary:  overall totals across all files: <1ms, >1ms & <=10ms, >10ms

Other behavior
--------------
• Folder layout assumed: <root>/<subdir>/oswprvtnet/<files>
• Output filenames start with <root_basename> and include timestamp
• Min/Max are per (src_ip, dst_ip) pair (optionally split by file if --infilename)
• Console summary prints totals AND global min/max observed
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
from typing import Dict, Tuple, Iterable, Optional, Iterator, Union

# ---------- Regexes ----------
PING_HEADER_RE = re.compile(
    r"^\s*PING\s+(?P<dest_host>[^\s]+)\s*\((?P<dest_ip>\d{1,3}(?:\.\d{1,3}){3})\)"
    r"(?:\s+from\s+(?P<src_ip>\d{1,3}(?:\.\d{1,3}){3}))?",
    re.IGNORECASE
)
PING_REPLY_RE = re.compile(
    r"bytes\s+from\s+(?P<from_ip>\d{1,3}(?:\.\d{1,3}){3})[:].*?\btime=(?P<ms>[0-9]+(?:\.[0-9]+)?)\s*ms\b",
    re.IGNORECASE
)

# ---------- Helpers ----------
def bucket_for_latency(ms: float) -> str:
    if ms < 1.0:
        return "lt_1ms"
    if ms < 2.0:
        return "ge_1_lt_2_ms"
    if ms < 5.0:
        return "ge_2_lt_5_ms"
    return "ge_5_ms"

def get_named_subdirectory_from_parts(parts: Iterable[str], marker_dir: str) -> Optional[str]:
    """Return the directory name immediately above marker_dir from a path parts list."""
    parts = list(parts)
    try:
        # last index of marker_dir
        idx = len(parts) - 1 - list(reversed(parts)).index(marker_dir)
        if idx - 1 >= 0:
            return parts[idx - 1]
    except ValueError:
        return None
    return None

def build_output_path(root: Path, base_output: Path, timestamp: str, kind: str) -> Path:
    root_prefix = root.name
    return base_output.with_name(
        f"{root_prefix}_ping_report_{kind}_{timestamp}{base_output.suffix}"
    ).resolve()

# ---------- File discovery (disk + zip) ----------
# A "source item" can be:
#  - ("disk", Path) for a regular file on disk
#  - ("zip", Path_to_zip, inner_path_str) for an entry inside a .zip
SourceItem = Union[Tuple[str, Path], Tuple[str, Path, str]]

def should_include_suffix(suffix: str, extensions: Optional[Iterable[str]]) -> bool:
    if extensions:
        exts = {e.lower() for e in extensions}
    else:
        exts = {".dat", ".dat.gz"}  # default
    return suffix.lower() in exts

def iter_disk_files(root: Path, marker_dir: str, extensions: Optional[Iterable[str]]) -> Iterator[SourceItem]:
    """Yield ("disk", file_path) for qualifying files under marker_dir."""
    for p in root.rglob("*"):
        if not p.is_file():
            continue
        # Skip zipfiles here; handled separately
        if p.suffix.lower() == ".zip":
            continue
        # Require marker_dir in path parts
        if marker_dir not in p.parts:
            continue
        # Match extension (including .gz)
        # For .dat.gz, Path.suffix is ".gz" and suffixes is [".dat", ".gz"]
        if p.suffix.lower() == ".gz":
            suff = "".join(p.suffixes[-2:]) if len(p.suffixes) >= 2 else p.suffix
        else:
            suff = p.suffix
        if should_include_suffix(suff, extensions):
            yield ("disk", p)

def iter_zip_files(root: Path, marker_dir: str, extensions: Optional[Iterable[str]]) -> Iterator[SourceItem]:
    """Yield ("zip", zip_path, inner_name) for qualifying entries under marker_dir inside zips."""
    for zp in root.rglob("*.zip"):
        try:
            with zipfile.ZipFile(zp, "r") as zf:
                for name in zf.namelist():
                    # Ignore directories
                    if name.endswith("/"):
                        continue
                    inner_parts = Path(name).parts
                    if marker_dir not in inner_parts:
                        continue
                    # compute effective suffix for .dat or .dat.gz
                    inner_suffixes = Path(name).suffixes
                    if inner_suffixes and inner_suffixes[-1].lower() == ".gz":
                        eff = "".join(inner_suffixes[-2:]).lower() if len(inner_suffixes) >= 2 else ".gz"
                    else:
                        eff = (inner_suffixes[-1].lower() if inner_suffixes else "")
                    if should_include_suffix(eff, extensions):
                        yield ("zip", zp, name)
        except Exception as e:
            logging.exception("Failed to read zip %s: %s", zp, e)

def find_sources(root: Path, marker_dir: str, extensions: Optional[Iterable[str]]) -> Iterator[SourceItem]:
    """Combine disk files and zip entries."""
    yield from iter_disk_files(root, marker_dir, extensions)
    yield from iter_zip_files(root, marker_dir, extensions)

# ---------- Unified open + meta for SourceItem ----------
def open_source_text(si: SourceItem) -> Tuple[io.TextIOBase, str, Optional[str]]:
    """
    Open a SourceItem and return a text stream, along with:
      - file_label (used when --infilename is on)
      - subdirectory name (dir immediately above marker_dir), if derivable here (zip needs separate logic)
    Note: We return subdir None here; caller computes from path parts (works for both disk & zip).
    """
    kind = si[0]
    if kind == "disk":
        _, p = si
        # handle .dat.gz as text
        if p.suffix.lower() == ".gz":
            # may be .dat.gz — open with gzip
            fh = gzip.open(p, mode="rt", encoding="utf-8", errors="ignore")
        else:
            fh = p.open("r", encoding="utf-8", errors="ignore")
        return fh, p.name, None
    else:
        _, zp, inner = si  # type: ignore
        zf = zipfile.ZipFile(zp, "r")
        raw = zf.open(inner, "r")
        # If inner is gz, wrap with gzip; else decode
        if inner.lower().endswith(".gz"):
            gz = gzip.GzipFile(fileobj=raw, mode="rb")
            fh = io.TextIOWrapper(gz, encoding="utf-8", errors="ignore")
        else:
            fh = io.TextIOWrapper(raw, encoding="utf-8", errors="ignore")
        label = f"{zp.name}::{inner}"
        # We intentionally do not close zf/raw here; rely on TextIOWrapper to close underlying file.
        return fh, label, None

def parts_for_source(si: SourceItem) -> Tuple[Iterable[str], str]:
    """Return (path_parts_like, file_basename_label) for subdir extraction and logging."""
    kind = si[0]
    if kind == "disk":
        _, p = si
        return p.parts, p.name
    else:
        _, zp, inner = si  # type: ignore
        return Path(inner).parts, f"{zp.name}::{inner}"

# ---------- Parsing ----------
def parse_source(
    si: SourceItem,
    counters: Dict[Tuple[str, str, str, str], Dict[str, float]],
    marker_dir: str,
    include_file: bool,
    simple_totals: Dict[str, float],
) -> None:
    """Parse one SourceItem (disk file or zip entry)."""
    parts, file_label = parts_for_source(si)
    subdir_name = get_named_subdirectory_from_parts(parts, marker_dir)
    if not subdir_name:
        return

    file_name = file_label if include_file else ""
    current_src: Optional[str] = None
    current_dst: Optional[str] = None

    try:
        fh, _, _ = open_source_text(si)
        with fh:
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

                    # Global min/max
                    if simple_totals["global_min"] is None or ms < simple_totals["global_min"]:
                        simple_totals["global_min"] = ms
                    if simple_totals["global_max"] is None or ms > simple_totals["global_max"]:
                        simple_totals["global_max"] = ms

    except Exception as e:
        logging.exception("Failed to parse %s: %s", file_label, e)

# ---------- Writers ----------
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

def write_simple_csv(out_path: Path, simple_totals: Dict[str, float]) -> int:
    with out_path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["category", "count"])
        writer.writerow(["<1ms", int(simple_totals["lt_1ms"])])
        writer.writerow([">1ms & <=10ms", int(simple_totals["gt_1_le_10_ms"])])
        writer.writerow([">10ms", int(simple_totals["gt_10_ms"])])
    return 3

# ---------- Main ----------
def main():
    ap = argparse.ArgumentParser(
        description="Generate latency reports (full, anomalies, and simple summary) from OSWbb ping outputs."
    )
    ap.add_argument("--root", default=".", help="Root directory to scan recursively. Default: current directory.")
    ap.add_argument("--output", default="ping_report.csv", help="Base filename for reports (prefix/timestamp auto).")
    ap.add_argument("--marker-dir", default="oswprvtnet", help="Marker directory name. Default: oswprvtnet")
    ap.add_argument("--extensions", nargs="*", help="Extensions to include. Default: .dat and .dat.gz")
    ap.add_argument("--infilename", action="store_true", help="Include file name column in detailed reports.")
    ap.add_argument("--verbose", action="store_true", help="Enable INFO logs.")
    ap.add_argument("--debug", action="store_true", help="Enable DEBUG logs.")
    args = ap.parse_args()

    # Logging
    level = logging.WARNING
    if args.verbose: level = logging.INFO
    if args.debug:   level = logging.DEBUG
    logging.basicConfig(format="%(levelname)s: %(message)s", level=level)

    root = Path(args.root).resolve()
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    counters: Dict[Tuple[str, str, str, str], Dict[str, float]] = {}
    simple_totals: Dict[str, float] = {
        "lt_1ms": 0,
        "gt_1_le_10_ms": 0,
        "gt_10_ms": 0,
        "global_min": None,  # type: ignore
        "global_max": None,  # type: ignore
    }

    # Discover and parse
    sources = list(find_sources(root, args.marker_dir, args.extensions))
    logging.info("Found %d candidate sources (disk + zip)", len(sources))
    for si in sources:
        parse_source(
            si,
            counters=counters,
            marker_dir=args.marker_dir,
            include_file=args.infilename,
            simple_totals=simple_totals,
        )

    # Write outputs
    base_out = Path(args.output).resolve()
    full_path = build_output_path(root, base_out, timestamp, "full")
    anomalies_path = build_output_path(root, base_out, timestamp, "anomalies")
    simple_path = build_output_path(root, base_out, timestamp, "simple")

    total_rows = write_full_or_anomalies_csv(full_path, counters, include_file=args.infilename, anomalies_only=False)
    anom_rows = write_full_or_anomalies_csv(anomalies_path, counters, include_file=args.infilename, anomalies_only=True)
    write_simple_csv(simple_path, simple_totals)

    total_samples = int(simple_totals["lt_1ms"] + simple_totals["gt_1_le_10_ms"] + simple_totals["gt_10_ms"])
    gmin = simple_totals["global_min"]
    gmax = simple_totals["global_max"]
    gmin_s = f"{gmin:.3f} ms" if gmin is not None else "n/a"
    gmax_s = f"{gmax:.3f} ms" if gmax is not None else "n/a"

    print("\nDone.")
    print(f"- Full report:    {full_path} ({total_rows} rows)")
    print(f"- Anomalies:      {anomalies_path} ({anom_rows} rows)")
    print(f"- Simple summary: {simple_path} (3 rows)")
    print(
        f"Totals: samples={total_samples}, "
        f"<1ms={int(simple_totals['lt_1ms'])}, "
        f">1ms & <=10ms={int(simple_totals['gt_1_le_10_ms'])}, "
        f">10ms={int(simple_totals['gt_10_ms'])}, "
        f"global_min={gmin_s}, global_max={gmax_s}"
    )

if __name__ == "__main__":
    main()
