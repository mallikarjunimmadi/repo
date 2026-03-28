#!/usr/bin/env python3
"""
esxtop-offline_v0.0.6.2.py

Version: v0.0.6.2

Description:
    Offline ESXTOP CSV processor using temp-file merge + external sort.

Features:
    - Auto-detects CSV files from a root directory (default: current working directory)
    - Default scan is non-recursive; use --recursive to scan subdirectories
    - Dynamically detects ESXTOP groups from headers (no predefined group list)
    - Merges multiple CSVs into a single output file per (host, group)
    - Uses disk-backed temp chunk files instead of keeping all merged rows in memory
    - Expands columns when new metrics appear in later files
    - Externally sorts rows in ascending timestamp order
    - Writes output to: output/raw/<host>-<group>.csv
    - Optionally keeps ORIGINAL timestamp and ESXTOP headers exactly as-is via --keep-full-header
    - Shows runtime metrics only when --debug is used

Examples:
    python3 esxtop-offline_v0.0.6.2.py
    python3 esxtop-offline_v0.0.6.2.py --recursive
    python3 esxtop-offline_v0.0.6.2.py --group "Physical Cpu"
    python3 esxtop-offline_v0.0.6.2.py --keep-full-header
    python3 esxtop-offline_v0.0.6.2.py --debug
"""

import argparse
import csv
import heapq
import json
import os
import re
import shutil
import sys
import time
from collections import defaultdict
from datetime import datetime
from pathlib import Path
from typing import Optional

try:
    import resource
except ImportError:
    resource = None

try:
    import psutil
except ImportError:
    psutil = None


TIMESTAMP_FORMATS = [
    "%m/%d/%Y %H:%M:%S",
]

INTERNAL_TS_KEY = "__timestamp__"
METADATA_FILE = "merge_metadata.json"
TEMP_ROOT_NAME = "tmp"
CHUNKS_DIR_NAME = "chunks"
SORTED_DIR_NAME = "sorted"


def format_bytes(num_bytes: Optional[int]) -> str:
    if num_bytes is None:
        return "N/A"

    value = float(num_bytes)
    units = ["B", "KB", "MB", "GB", "TB", "PB"]
    for unit in units:
        if value < 1024.0 or unit == units[-1]:
            return f"{value:.2f} {unit}"
        value /= 1024.0
    return f"{num_bytes} B"


def safe_percent(value) -> str:
    if value is None:
        return "N/A"
    try:
        return f"{float(value):.2f}%"
    except Exception:
        return "N/A"


class RunMetrics:
    def __init__(self):
        self.start_wall = time.perf_counter()
        self.start_cpu = time.process_time()

        self.process = psutil.Process(os.getpid()) if psutil else None

        if self.process:
            try:
                self.process.cpu_percent(None)
            except Exception:
                pass

        if psutil:
            try:
                psutil.cpu_percent(None)
            except Exception:
                pass

        self.start_system_memory = self._get_system_memory()
        self.peak_rss = self._get_rss()

    def _get_rss(self) -> Optional[int]:
        if self.process:
            try:
                return int(self.process.memory_info().rss)
            except Exception:
                return None

        if resource:
            try:
                rss = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
                if sys.platform.startswith("darwin"):
                    return int(rss)
                return int(rss) * 1024
            except Exception:
                return None

        return None

    def _get_system_memory(self):
        if not psutil:
            return None
        try:
            vm = psutil.virtual_memory()
            return {
                "total": int(vm.total),
                "available": int(vm.available),
                "used": int(vm.used),
                "percent": float(vm.percent),
            }
        except Exception:
            return None

    def sample(self):
        rss = self._get_rss()
        if rss is not None and (self.peak_rss is None or rss > self.peak_rss):
            self.peak_rss = rss

    def finalize(self):
        self.sample()

        end_wall = time.perf_counter()
        end_cpu = time.process_time()

        process_cpu = None
        system_cpu = None

        if self.process:
            try:
                process_cpu = self.process.cpu_percent(interval=0.1)
            except Exception:
                process_cpu = None

        if psutil:
            try:
                system_cpu = psutil.cpu_percent(interval=0.1)
            except Exception:
                system_cpu = None

        return {
            "wall": end_wall - self.start_wall,
            "cpu": end_cpu - self.start_cpu,
            "rss_current": self._get_rss(),
            "rss_peak": self.peak_rss,
            "proc_cpu": process_cpu,
            "sys_cpu": system_cpu,
            "sys_mem_start": self.start_system_memory,
            "sys_mem_end": self._get_system_memory(),
            "psutil": psutil is not None,
        }


def print_run_metrics(metrics: dict):
    print("\n[RUN METRICS]")
    print(f"Wall time           : {metrics['wall']:.2f} sec")
    print(f"CPU time            : {metrics['cpu']:.2f} sec")
    print(f"Process CPU %       : {safe_percent(metrics['proc_cpu'])}")
    print(f"System CPU %        : {safe_percent(metrics['sys_cpu'])}")
    print(f"Process RSS current : {format_bytes(metrics['rss_current'])}")
    print(f"Process RSS peak    : {format_bytes(metrics['rss_peak'])}")

    print("\n[SYSTEM MEMORY]")
    if metrics["sys_mem_start"] and metrics["sys_mem_end"]:
        print(
            f"Start : total={format_bytes(metrics['sys_mem_start']['total'])}, "
            f"available={format_bytes(metrics['sys_mem_start']['available'])}, "
            f"used={format_bytes(metrics['sys_mem_start']['used'])}, "
            f"percent={safe_percent(metrics['sys_mem_start']['percent'])}"
        )
        print(
            f"End   : total={format_bytes(metrics['sys_mem_end']['total'])}, "
            f"available={format_bytes(metrics['sys_mem_end']['available'])}, "
            f"used={format_bytes(metrics['sys_mem_end']['used'])}, "
            f"percent={safe_percent(metrics['sys_mem_end']['percent'])}"
        )
    else:
        print("N/A")

    print(f"\n[METRICS SOURCE]")
    print(f"psutil available    : {metrics['psutil']}")


def detect_timestamp_column(headers):
    for col in headers:
        if col == "Time":
            return col
        if "(PDH-CSV 4.0) (UTC)(0)" in col:
            return col
    return None


def normalize_host_name(name: str) -> str:
    short = name.split(".")[0].strip()
    short = re.sub(r"[^A-Za-z0-9._-]+", "_", short)
    short = re.sub(r"_+", "_", short)
    return short.strip("_") or "unknownhost"


def normalize_group_name(name: str) -> str:
    name = name.strip()
    name = name.replace(" ", "_")
    name = re.sub(r"[^A-Za-z0-9._-]+", "_", name)
    name = re.sub(r"_+", "_", name)
    return name.strip("_") or "UnknownGroup"


def safe_metric_name(name: str) -> str:
    name = name.strip()
    name = re.sub(r"\s+", " ", name)
    return name or "value"


def discover_csv_files(root: Path, recursive: bool, outdir_name: str):
    files = []
    iterator = root.rglob("*.csv") if recursive else root.glob("*.csv")

    for path in iterator:
        if outdir_name in path.parts:
            continue
        files.append(path)

    return sorted(set(files))


def parse_group_instance(segment: str):
    segment = segment.strip()
    if not segment:
        return None, None

    match = re.match(r"^(.*?)(?:\((.*?)\))?$", segment)
    if not match:
        return segment, "overall"

    group_name = (match.group(1) or "").strip()
    instance = (match.group(2) or "overall").strip()

    if not group_name:
        return None, None

    return group_name, instance


def parse_esxtop_header(col: str):
    """
    Expected shapes:
        \\host.domain\\Group(instance)\\Metric
        \\host.domain\\Group\\Metric
        \\host.domain\\something\\Group(instance)\\Metric

    Dynamic rule:
        host = first segment
        metric = last segment
        group-bearing segment = second-last segment
    """
    if not col.startswith("\\\\"):
        return None

    segments = col[2:].split("\\")
    if len(segments) < 3:
        return None

    full_hostname = segments[0].strip()
    short_hostname = normalize_host_name(full_hostname)
    remaining = [s.strip() for s in segments[1:] if s.strip()]

    if len(remaining) < 2:
        return None

    metric = remaining[-1]
    group_segment = remaining[-2]

    group_name, instance = parse_group_instance(group_segment)
    if not group_name:
        return None

    return {
        "full_hostname": full_hostname,
        "short_hostname": short_hostname,
        "group": group_name,
        "instance": instance,
        "metric": metric.strip() or "value",
        "original_header": col,
    }


def build_output_header_label(
    instance: str,
    metric: str,
    keep_full: bool,
    original_header: str = None
):
    if keep_full:
        return original_header if original_header is not None else metric

    metric = safe_metric_name(metric)
    instance = (instance or "").strip()

    if not instance or instance.lower() == "overall":
        return metric

    return f"{instance}-{metric}"


def uniquify_with_seen(name: str, seen_counts: dict):
    seen_counts[name] += 1
    if seen_counts[name] == 1:
        return name
    return f"{name}_{seen_counts[name]}"


def parse_timestamp(ts: str):
    ts = (ts or "").strip()
    for fmt in TIMESTAMP_FORMATS:
        try:
            return datetime.strptime(ts, fmt)
        except ValueError:
            continue
    return None


def get_group_id(host: str, group_name: str) -> str:
    return f"{host}__{normalize_group_name(group_name)}"


def load_metadata(metadata_path: Path):
    if not metadata_path.exists():
        return {"groups": {}}

    with metadata_path.open("r", encoding="utf-8") as fh:
        return json.load(fh)


def save_metadata(metadata_path: Path, metadata: dict):
    with metadata_path.open("w", encoding="utf-8") as fh:
        json.dump(metadata, fh, indent=2, ensure_ascii=False)


def ensure_group_metadata(
    metadata: dict,
    group_id: str,
    host: str,
    group_name: str,
    output_timestamp_col: str,
):
    groups = metadata.setdefault("groups", {})
    if group_id not in groups:
        groups[group_id] = {
            "host": host,
            "group_name": group_name,
            "output_timestamp_col": output_timestamp_col,
            "columns": [],
            "chunk_files": []
        }
    else:
        if not groups[group_id].get("output_timestamp_col"):
            groups[group_id]["output_timestamp_col"] = output_timestamp_col

    return groups[group_id]


def ingest_file_to_chunks(
    csv_path: Path,
    tmp_root: Path,
    metadata: dict,
    metadata_path: Path,
    group_filter: str = None,
    delimiter: str = ",",
    keep_full_header: bool = False,
    metrics: Optional[RunMetrics] = None,
):
    try:
        with csv_path.open("r", newline="", encoding="utf-8-sig") as fin:
            reader = csv.reader(fin, delimiter=delimiter)

            try:
                headers = next(reader)
            except StopIteration:
                return "skipped", "empty csv"

            ts_col = detect_timestamp_column(headers)
            if not ts_col:
                return "skipped", "timestamp column not found"

            output_ts_col = ts_col if keep_full_header else "Time"
            header_index = {h: i for i, h in enumerate(headers)}

            file_groups = defaultdict(list)
            temp_seen = defaultdict(lambda: defaultdict(int))

            for col in headers:
                if col == ts_col:
                    continue

                parsed = parse_esxtop_header(col)
                if not parsed:
                    continue

                if group_filter and parsed["group"].lower() != group_filter.lower():
                    continue

                key = (parsed["short_hostname"], parsed["group"])
                candidate = build_output_header_label(
                    parsed["instance"],
                    parsed["metric"],
                    keep_full_header,
                    parsed["original_header"]
                )
                final_header = uniquify_with_seen(candidate, temp_seen[key])
                file_groups[key].append((col, final_header))

            if not file_groups:
                return "skipped", (
                    f'no columns found for group "{group_filter}"'
                    if group_filter else
                    "no ESXTOP-style groups found"
                )

            chunks_dir = tmp_root / CHUNKS_DIR_NAME
            chunks_dir.mkdir(parents=True, exist_ok=True)

            source_stem = csv_path.stem
            sanitized_source = re.sub(r"[^A-Za-z0-9._-]+", "_", source_stem)

            chunk_writers = {}
            chunk_handles = {}

            try:
                for (host, group_name), cols in file_groups.items():
                    group_id = get_group_id(host, group_name)
                    group_meta = ensure_group_metadata(
                        metadata=metadata,
                        group_id=group_id,
                        host=host,
                        group_name=group_name,
                        output_timestamp_col=output_ts_col,
                    )

                    existing_cols = group_meta["columns"]
                    existing_col_set = set(existing_cols)
                    for _, clean_header in cols:
                        if clean_header not in existing_col_set:
                            existing_cols.append(clean_header)
                            existing_col_set.add(clean_header)

                    chunk_path = chunks_dir / (
                        f"{group_id}__{sanitized_source}__part{len(group_meta['chunk_files']) + 1:05d}.csv"
                    )
                    group_meta["chunk_files"].append(str(chunk_path))
                    save_metadata(metadata_path, metadata)

                    fh = chunk_path.open("w", newline="", encoding="utf-8")
                    writer = csv.writer(fh, delimiter=delimiter)

                    writer.writerow([INTERNAL_TS_KEY] + [clean for _, clean in cols])

                    chunk_handles[group_id] = fh
                    chunk_writers[group_id] = {
                        "writer": writer,
                        "cols": cols,
                    }

                row_count = 0
                for row in reader:
                    row_count += 1
                    if len(row) < len(headers):
                        row = row + [""] * (len(headers) - len(row))

                    timestamp_value = row[header_index[ts_col]]

                    for (host, group_name), cols in file_groups.items():
                        group_id = get_group_id(host, group_name)
                        writer_obj = chunk_writers[group_id]
                        out_row = [timestamp_value]
                        for orig_col, _clean_header in writer_obj["cols"]:
                            out_row.append(row[header_index[orig_col]])
                        writer_obj["writer"].writerow(out_row)

                    if metrics and (row_count % 5000 == 0):
                        metrics.sample()

                if metrics:
                    metrics.sample()

                return "ok", f"groups={len(file_groups)}, extracted_rows={row_count * len(file_groups)}"

            finally:
                for fh in chunk_handles.values():
                    try:
                        fh.close()
                    except Exception:
                        pass

    except Exception as exc:
        return "error", str(exc)


def sort_single_chunk(
    chunk_path: Path,
    sorted_path: Path,
    delimiter: str = ",",
    metrics: Optional[RunMetrics] = None,
):
    rows = []

    with chunk_path.open("r", newline="", encoding="utf-8") as fin:
        reader = csv.reader(fin, delimiter=delimiter)
        headers = next(reader)

        for idx, row in enumerate(reader, start=1):
            if len(row) < len(headers):
                row = row + [""] * (len(headers) - len(row))
            rows.append(row)
            if metrics and (idx % 5000 == 0):
                metrics.sample()

    def sort_key(row):
        raw = row[0] if row else ""
        parsed = parse_timestamp(raw)
        if parsed is None:
            return (1, raw)
        return (0, parsed)

    rows.sort(key=sort_key)

    with sorted_path.open("w", newline="", encoding="utf-8") as fout:
        writer = csv.writer(fout, delimiter=delimiter)
        writer.writerow(headers)
        writer.writerows(rows)

    if metrics:
        metrics.sample()


def read_chunk_header(chunk_path: Path, delimiter: str = ","):
    with chunk_path.open("r", newline="", encoding="utf-8") as fin:
        reader = csv.reader(fin, delimiter=delimiter)
        return next(reader)


def finalize_group_output(
    group_id: str,
    group_meta: dict,
    tmp_root: Path,
    raw_output_dir: Path,
    delimiter: str = ",",
    metrics: Optional[RunMetrics] = None,
):
    sorted_dir = tmp_root / SORTED_DIR_NAME
    sorted_dir.mkdir(parents=True, exist_ok=True)

    final_columns = list(group_meta["columns"])
    output_timestamp_col = group_meta["output_timestamp_col"]
    host = group_meta["host"]
    group_name = group_meta["group_name"]

    sorted_chunk_info = []

    for chunk_file_str in group_meta["chunk_files"]:
        chunk_path = Path(chunk_file_str)
        sorted_path = sorted_dir / f"{chunk_path.stem}__sorted.csv"

        sort_single_chunk(chunk_path, sorted_path, delimiter=delimiter, metrics=metrics)

        chunk_headers = read_chunk_header(chunk_path, delimiter=delimiter)
        chunk_cols = chunk_headers[1:]
        chunk_col_index = {name: idx for idx, name in enumerate(chunk_cols)}

        sorted_chunk_info.append({
            "path": sorted_path,
            "chunk_cols": chunk_cols,
            "chunk_col_index": chunk_col_index,
        })

    outfile = raw_output_dir / f"{host}-{normalize_group_name(group_name)}.csv"

    open_files = []
    heap = []
    sequence = 0

    try:
        with outfile.open("w", newline="", encoding="utf-8") as fout:
            writer = csv.writer(fout, delimiter=delimiter)
            writer.writerow([output_timestamp_col] + final_columns)

            for info in sorted_chunk_info:
                fh = info["path"].open("r", newline="", encoding="utf-8")
                reader = csv.reader(fh, delimiter=delimiter)
                headers = next(reader, None)
                if not headers:
                    fh.close()
                    continue

                row = next(reader, None)
                if row is not None:
                    ts_raw = row[0] if row else ""
                    ts_parsed = parse_timestamp(ts_raw)
                    heapq.heappush(
                        heap,
                        (
                            (1, ts_raw) if ts_parsed is None else (0, ts_parsed),
                            sequence,
                            row,
                            reader,
                            fh,
                            info,
                        )
                    )
                    sequence += 1
                    open_files.append(fh)
                else:
                    fh.close()

            rows_written = 0
            while heap:
                _sort_key, _seq, row, reader, fh, info = heapq.heappop(heap)

                ts_raw = row[0] if row else ""
                out_row = [ts_raw]

                chunk_values = row[1:]
                chunk_index = info["chunk_col_index"]

                for final_col in final_columns:
                    idx = chunk_index.get(final_col)
                    if idx is None:
                        out_row.append("")
                    else:
                        out_row.append(chunk_values[idx] if idx < len(chunk_values) else "")

                writer.writerow(out_row)
                rows_written += 1

                if metrics and (rows_written % 5000 == 0):
                    metrics.sample()

                next_row = next(reader, None)
                if next_row is not None:
                    next_ts_raw = next_row[0] if next_row else ""
                    next_ts_parsed = parse_timestamp(next_ts_raw)
                    heapq.heappush(
                        heap,
                        (
                            (1, next_ts_raw) if next_ts_parsed is None else (0, next_ts_parsed),
                            sequence,
                            next_row,
                            reader,
                            fh,
                            info,
                        )
                    )
                    sequence += 1

        if metrics:
            metrics.sample()

        return str(outfile)

    finally:
        for fh in open_files:
            try:
                fh.close()
            except Exception:
                pass



VISUALIZER_FILENAME = "esxtop-visualizer_v0.0.8.html"
VISUALIZER_HTML = '<!DOCTYPE html>\n<html lang="en">\n<head>\n  <meta charset="utf-8" />\n  <title>ESXTOP Viewer v0.0.8</title>\n  <meta name="viewport" content="width=device-width, initial-scale=1" />\n  <script src="https://cdn.plot.ly/plotly-2.35.2.min.js"></script>\n  <style>\n    :root {\n      --bg: #0b1020;\n      --panel: #12192b;\n      --panel-2: #182235;\n      --text: #e9eef8;\n      --muted: #99a6bd;\n      --border: #2b3952;\n      --accent: #4f8cff;\n      --btn: #25324a;\n      --btn-hover: #334564;\n      --input: #0f1728;\n      --success: #35c16f;\n      --danger: #ff6b6b;\n      --shadow: 0 8px 22px rgba(0,0,0,0.24);\n    }\n\n    body.light {\n      --bg: #f3f6fb;\n      --panel: #ffffff;\n      --panel-2: #eef3fb;\n      --text: #101827;\n      --muted: #5f6c80;\n      --border: #d6deeb;\n      --accent: #2563eb;\n      --btn: #e7eefb;\n      --btn-hover: #d7e4fb;\n      --input: #ffffff;\n      --success: #0f9d58;\n      --danger: #dc2626;\n      --shadow: 0 8px 22px rgba(10,20,40,0.08);\n    }\n\n    * { box-sizing: border-box; }\n\n    body {\n      margin: 0;\n      font-family: Arial, Helvetica, sans-serif;\n      background: var(--bg);\n      color: var(--text);\n    }\n\n    .app {\n      min-height: 100vh;\n      display: flex;\n      flex-direction: column;\n    }\n\n    .topbar {\n      display: grid;\n      grid-template-columns: 220px 1fr 54px;\n      gap: 12px;\n      padding: 14px;\n      border-bottom: 1px solid var(--border);\n      background: var(--panel);\n      align-items: start;\n    }\n\n    .brand {\n      font-size: 18px;\n      font-weight: 700;\n      line-height: 1.25;\n      padding-top: 4px;\n    }\n\n    .toolbar {\n      display: grid;\n      grid-template-columns: repeat(4, minmax(220px, 1fr));\n      gap: 12px;\n    }\n\n    .dropdown {\n      position: relative;\n      min-width: 0;\n    }\n\n    .dropdown-btn {\n      width: 100%;\n      border: 1px solid var(--border);\n      background: var(--panel-2);\n      color: var(--text);\n      border-radius: 14px;\n      padding: 10px 12px;\n      cursor: pointer;\n      text-align: left;\n      min-height: 48px;\n      box-shadow: var(--shadow);\n    }\n\n    .dropdown-label {\n      display: block;\n      font-size: 12px;\n      color: var(--muted);\n      margin-bottom: 4px;\n      font-weight: 700;\n    }\n\n    .dropdown-value {\n      display: block;\n      font-size: 13px;\n      font-weight: 600;\n      white-space: nowrap;\n      overflow: hidden;\n      text-overflow: ellipsis;\n    }\n\n    .dropdown-panel {\n      position: absolute;\n      top: calc(100% + 8px);\n      left: 0;\n      right: 0;\n      background: var(--panel);\n      border: 1px solid var(--border);\n      border-radius: 14px;\n      box-shadow: var(--shadow);\n      z-index: 50;\n      display: none;\n      overflow: hidden;\n    }\n\n    .dropdown.open .dropdown-panel {\n      display: block;\n    }\n\n    .dropdown-search {\n      width: calc(100% - 20px);\n      margin: 10px;\n      border: 1px solid var(--border);\n      background: var(--input);\n      color: var(--text);\n      border-radius: 10px;\n      padding: 8px 10px;\n      font-size: 13px;\n    }\n\n    .dropdown-toolbar {\n      display: grid;\n      grid-template-columns: 1fr 1fr;\n      gap: 8px;\n      padding: 0 10px 10px 10px;\n      border-bottom: 1px solid var(--border);\n      background: var(--panel);\n    }\n\n    .dropdown-items {\n      max-height: 260px;\n      overflow: auto;\n      padding: 8px 10px 10px 10px;\n    }\n\n    .dropdown-item {\n      display: flex;\n      align-items: center;\n      gap: 8px;\n      padding: 6px 2px;\n      font-size: 13px;\n    }\n\n    .dropdown-item input {\n      margin: 0;\n      flex: 0 0 auto;\n    }\n\n    button, input[type="file"] {\n      border: 1px solid var(--border);\n      background: var(--btn);\n      color: var(--text);\n      border-radius: 10px;\n      padding: 8px 10px;\n      font-size: 13px;\n    }\n\n    button {\n      cursor: pointer;\n      font-weight: 600;\n    }\n\n    button:hover {\n      background: var(--btn-hover);\n    }\n\n    .theme-btn {\n      height: 40px;\n      font-size: 18px;\n    }\n\n    .meta-panel {\n      padding: 12px 14px 0 14px;\n    }\n\n    .meta-row {\n      display: grid;\n      grid-template-columns: 1fr 1fr;\n      gap: 12px;\n      margin-bottom: 8px;\n    }\n\n    .panel {\n      background: var(--panel);\n      border: 1px solid var(--border);\n      border-radius: 16px;\n      padding: 12px;\n    }\n\n    .field {\n      margin-bottom: 0;\n    }\n\n    .field label {\n      display: block;\n      font-size: 12px;\n      font-weight: 700;\n      margin-bottom: 6px;\n    }\n\n    .status {\n      font-size: 12px;\n      color: var(--muted);\n      line-height: 1.5;\n    }\n\n    .status.ok { color: var(--success); }\n    .status.err { color: var(--danger); }\n\n    .info-line {\n      padding: 0 2px;\n      font-size: 11px;\n      color: var(--muted);\n      line-height: 1.4;\n    }\n\n    .content {\n      padding: 10px 14px 14px 14px;\n      display: grid;\n      grid-template-rows: auto 1fr;\n      gap: 10px;\n      flex: 1;\n      min-height: 0;\n    }\n\n    .chart-toolbar {\n      display: flex;\n      justify-content: flex-end;\n      align-items: center;\n      gap: 8px;\n    }\n\n    #chart {\n      width: 100%;\n      height: 78vh;\n      border: 1px solid var(--border);\n      border-radius: 16px;\n      background: var(--panel);\n    }\n\n    .legend-collapsed #chart {\n      height: 84vh;\n    }\n\n    .small {\n      font-size: 11px;\n      color: var(--muted);\n    }\n\n    @media (max-width: 1320px) {\n      .topbar {\n        grid-template-columns: 1fr;\n      }\n      .toolbar {\n        grid-template-columns: repeat(2, minmax(220px, 1fr));\n      }\n      .meta-row {\n        grid-template-columns: 1fr;\n      }\n    }\n\n    @media (max-width: 860px) {\n      .toolbar {\n        grid-template-columns: 1fr;\n      }\n    }\n  </style>\n</head>\n<body>\n  <div class="app" id="appRoot">\n    <div class="topbar">\n      <div class="brand">ESXTOP Viewer<br>v0.0.8</div>\n\n      <div class="toolbar">\n        <div class="dropdown" id="hostDropdown">\n          <button class="dropdown-btn" type="button">\n            <span class="dropdown-label">Hosts</span>\n            <span class="dropdown-value" id="hostValue">None selected</span>\n          </button>\n          <div class="dropdown-panel">\n            <input class="dropdown-search" id="hostSearch" placeholder="Search hosts..." />\n            <div class="dropdown-toolbar">\n              <button type="button" data-action="all" data-target="hosts">Select All</button>\n              <button type="button" data-action="clear" data-target="hosts">Clear</button>\n            </div>\n            <div class="dropdown-items" id="hostItems"></div>\n          </div>\n        </div>\n\n        <div class="dropdown" id="groupDropdown">\n          <button class="dropdown-btn" type="button">\n            <span class="dropdown-label">Groups</span>\n            <span class="dropdown-value" id="groupValue">None selected</span>\n          </button>\n          <div class="dropdown-panel">\n            <input class="dropdown-search" id="groupSearch" placeholder="Search groups..." />\n            <div class="dropdown-toolbar">\n              <button type="button" data-action="all" data-target="groups">Select All</button>\n              <button type="button" data-action="clear" data-target="groups">Clear</button>\n            </div>\n            <div class="dropdown-items" id="groupItems"></div>\n          </div>\n        </div>\n\n        <div class="dropdown" id="instanceDropdown">\n          <button class="dropdown-btn" type="button">\n            <span class="dropdown-label">Instances</span>\n            <span class="dropdown-value" id="instanceValue">None selected</span>\n          </button>\n          <div class="dropdown-panel">\n            <input class="dropdown-search" id="instanceSearch" placeholder="Search instances..." />\n            <div class="dropdown-toolbar">\n              <button type="button" data-action="all" data-target="instances">Select All</button>\n              <button type="button" data-action="clear" data-target="instances">Clear</button>\n            </div>\n            <div class="dropdown-items" id="instanceItems"></div>\n          </div>\n        </div>\n\n        <div class="dropdown" id="metricDropdown">\n          <button class="dropdown-btn" type="button">\n            <span class="dropdown-label">Metrics</span>\n            <span class="dropdown-value" id="metricValue">None selected</span>\n          </button>\n          <div class="dropdown-panel">\n            <input class="dropdown-search" id="metricSearch" placeholder="Search metrics..." />\n            <div class="dropdown-toolbar">\n              <button type="button" data-action="all" data-target="metrics">Select All</button>\n              <button type="button" data-action="clear" data-target="metrics">Clear</button>\n            </div>\n            <div class="dropdown-items" id="metricItems"></div>\n          </div>\n        </div>\n      </div>\n\n      <button id="themeToggle" class="theme-btn" title="Toggle dark/light mode">🌙</button>\n    </div>\n\n    <div class="meta-panel">\n      <div class="meta-row">\n        <div class="panel">\n          <div class="field">\n            <label for="metadataFile">Metadata JSON</label>\n            <input type="file" id="metadataFile" accept=".json" />\n          </div>\n        </div>\n\n        <div class="panel">\n          <div class="field">\n            <label for="csvFiles">CSV Files (optional fallback)</label>\n            <input type="file" id="csvFiles" accept=".csv" multiple />\n          </div>\n        </div>\n      </div>\n\n      <div class="info-line">\n        <div id="selectionStatus" class="status">No metadata loaded yet.</div>\n        <div id="loadStatus" class="status">Trying to auto-load ./esxtop-metadata.json ...</div>\n      </div>\n    </div>\n\n    <div class="content">\n      <div class="chart-toolbar">\n        <button id="legendToggleBtn" type="button">Hide Legend</button>\n      </div>\n      <div id="chart"></div>\n    </div>\n  </div>\n\n  <script>\n    const state = {\n      metadata: null,\n      csvFileMap: new Map(),\n      selectedHosts: new Set(),\n      selectedGroups: new Set(),\n      selectedInstances: new Set(),\n      selectedMetrics: new Set(),\n      theme: \'dark\',\n      lastTraces: [],\n      lastTitle: \'\',\n      legendVisible: true\n    };\n\n    const els = {\n      appRoot: document.getElementById(\'appRoot\'),\n      metadataFile: document.getElementById(\'metadataFile\'),\n      csvFiles: document.getElementById(\'csvFiles\'),\n      loadStatus: document.getElementById(\'loadStatus\'),\n      selectionStatus: document.getElementById(\'selectionStatus\'),\n      themeToggle: document.getElementById(\'themeToggle\'),\n      legendToggleBtn: document.getElementById(\'legendToggleBtn\'),\n\n      hostItems: document.getElementById(\'hostItems\'),\n      groupItems: document.getElementById(\'groupItems\'),\n      instanceItems: document.getElementById(\'instanceItems\'),\n      metricItems: document.getElementById(\'metricItems\'),\n\n      hostValue: document.getElementById(\'hostValue\'),\n      groupValue: document.getElementById(\'groupValue\'),\n      instanceValue: document.getElementById(\'instanceValue\'),\n      metricValue: document.getElementById(\'metricValue\'),\n\n      hostSearch: document.getElementById(\'hostSearch\'),\n      groupSearch: document.getElementById(\'groupSearch\'),\n      instanceSearch: document.getElementById(\'instanceSearch\'),\n      metricSearch: document.getElementById(\'metricSearch\')\n    };\n\n    function setStatus(el, text, cls = \'\') {\n      el.textContent = text;\n      el.className = cls ? `status ${cls}` : \'status\';\n    }\n\n    function summarizeSelection(arr) {\n      if (!arr || arr.length === 0) return \'None selected\';\n      if (arr.length <= 2) return arr.join(\', \');\n      return `${arr.length} selected`;\n    }\n\n    function refreshDropdownSummaries() {\n      els.hostValue.textContent = summarizeSelection([...state.selectedHosts]);\n      els.groupValue.textContent = summarizeSelection([...state.selectedGroups]);\n      els.instanceValue.textContent = summarizeSelection([...state.selectedInstances]);\n      els.metricValue.textContent = summarizeSelection([...state.selectedMetrics]);\n    }\n\n    function parseTimestamp(ts) {\n      const m = /^(\\d{2})\\/(\\d{2})\\/(\\d{4}) (\\d{2}):(\\d{2}):(\\d{2})$/.exec((ts || \'\').trim());\n      if (!m) return null;\n      return new Date(\n        Number(m[3]),\n        Number(m[1]) - 1,\n        Number(m[2]),\n        Number(m[4]),\n        Number(m[5]),\n        Number(m[6])\n      );\n    }\n\n    function parseCsvLine(line) {\n      const out = [];\n      let cur = \'\';\n      let inQuotes = false;\n\n      for (let i = 0; i < line.length; i++) {\n        const ch = line[i];\n        if (ch === \'"\') {\n          if (inQuotes && line[i + 1] === \'"\') {\n            cur += \'"\';\n            i++;\n          } else {\n            inQuotes = !inQuotes;\n          }\n        } else if (ch === \',\' && !inQuotes) {\n          out.push(cur);\n          cur = \'\';\n        } else {\n          cur += ch;\n        }\n      }\n\n      out.push(cur);\n      return out;\n    }\n\n    async function readFileText(file) {\n      return new Promise((resolve, reject) => {\n        const reader = new FileReader();\n        reader.onload = () => resolve(reader.result);\n        reader.onerror = () => reject(reader.error || new Error(\'Failed to read file\'));\n        reader.readAsText(file);\n      });\n    }\n\n    async function fetchText(url) {\n      const res = await fetch(url, { cache: \'no-store\' });\n      if (!res.ok) throw new Error(`HTTP ${res.status}`);\n      return await res.text();\n    }\n\n    function chartLayout(title = \'\') {\n      return {\n        title,\n        paper_bgcolor: getComputedStyle(document.body).getPropertyValue(\'--panel\'),\n        plot_bgcolor: getComputedStyle(document.body).getPropertyValue(\'--panel\'),\n        font: { color: getComputedStyle(document.body).getPropertyValue(\'--text\').trim() },\n        xaxis: { title: \'Timestamp\', gridcolor: getComputedStyle(document.body).getPropertyValue(\'--border\').trim() },\n        yaxis: { title: \'Value\', gridcolor: getComputedStyle(document.body).getPropertyValue(\'--border\').trim() },\n        legend: {\n          orientation: \'h\',\n          tracegroupgap: 5\n        },\n        showlegend: state.legendVisible,\n        margin: { l: 60, r: 30, t: 50, b: 50 },\n        hovermode: \'closest\',\n        hoverlabel: {\n          align: \'left\',\n          namelength: -1\n        }\n      };\n    }\n\n    function renderChart(traces, title = \'\') {\n      state.lastTraces = traces;\n      state.lastTitle = title;\n\n      Plotly.newPlot(\'chart\', traces, chartLayout(title), {\n        responsive: true,\n        displaylogo: false,\n        modeBarButtonsToRemove: [\'lasso2d\', \'select2d\']\n      });\n    }\n\n    function renderEmptyChart(message = \'\') {\n      renderChart([], message);\n    }\n\n    function loadTheme() {\n      const saved = localStorage.getItem(\'esxtop-viewer-theme\');\n      state.theme = saved || \'dark\';\n      document.body.classList.toggle(\'light\', state.theme === \'light\');\n      els.themeToggle.textContent = state.theme === \'light\' ? \'☀️\' : \'🌙\';\n    }\n\n    els.themeToggle.addEventListener(\'click\', () => {\n      state.theme = state.theme === \'dark\' ? \'light\' : \'dark\';\n      localStorage.setItem(\'esxtop-viewer-theme\', state.theme);\n      loadTheme();\n      renderChart(state.lastTraces, state.lastTitle);\n    });\n\n    els.legendToggleBtn.addEventListener(\'click\', () => {\n      state.legendVisible = !state.legendVisible;\n      els.legendToggleBtn.textContent = state.legendVisible ? \'Hide Legend\' : \'Show Legend\';\n      els.appRoot.classList.toggle(\'legend-collapsed\', !state.legendVisible);\n      renderChart(state.lastTraces, state.lastTitle);\n    });\n\n    function getFilteredValues(values, searchTerm = \'\') {\n      const term = (searchTerm || \'\').trim().toLowerCase();\n      return values.filter(v => v.toLowerCase().includes(term));\n    }\n\n    function createCheckboxList(container, values, selectedSet, onChange, searchTerm = \'\') {\n      container.innerHTML = \'\';\n      const filtered = getFilteredValues(values, searchTerm);\n\n      if (filtered.length === 0) {\n        const empty = document.createElement(\'div\');\n        empty.className = \'small\';\n        empty.textContent = \'No values available\';\n        container.appendChild(empty);\n        return;\n      }\n\n      filtered.forEach(value => {\n        const label = document.createElement(\'label\');\n        label.className = \'dropdown-item\';\n\n        const cb = document.createElement(\'input\');\n        cb.type = \'checkbox\';\n        cb.checked = selectedSet.has(value);\n        cb.addEventListener(\'click\', (e) => e.stopPropagation());\n        cb.addEventListener(\'change\', async () => {\n          if (cb.checked) selectedSet.add(value);\n          else selectedSet.delete(value);\n          await onChange();\n        });\n\n        const span = document.createElement(\'span\');\n        span.textContent = value;\n\n        label.appendChild(cb);\n        label.appendChild(span);\n        container.appendChild(label);\n      });\n    }\n\n    function getAvailableGroups() {\n      const groupSet = new Set();\n      [...state.selectedHosts].forEach(host => {\n        const hostGroups = state.metadata?.host_groups?.[host] || {};\n        Object.keys(hostGroups).forEach(g => groupSet.add(g));\n      });\n      return [...groupSet].sort();\n    }\n\n    function getAvailableInstances() {\n      const instanceSet = new Set();\n      (state.metadata?.files || [])\n        .filter(f => state.selectedHosts.has(f.host) && state.selectedGroups.has(f.group))\n        .forEach(f => (f.instances || []).forEach(i => instanceSet.add(i)));\n      return [...instanceSet].sort();\n    }\n\n    function getAvailableMetricsForGroupOrInstance() {\n      const metricSet = new Set();\n      (state.metadata?.files || [])\n        .filter(f => state.selectedHosts.has(f.host) && state.selectedGroups.has(f.group))\n        .forEach(fileMeta => {\n          const im = fileMeta.instance_metrics || {};\n          if (state.selectedInstances.size > 0) {\n            [...state.selectedInstances].forEach(inst => {\n              (im[inst] || []).forEach(m => metricSet.add(m));\n            });\n          } else {\n            Object.values(im).forEach(metrics => {\n              (metrics || []).forEach(m => metricSet.add(m));\n            });\n          }\n        });\n      return [...metricSet].sort();\n    }\n\n    async function renderHosts() {\n      const hosts = (state.metadata?.hosts || []).slice().sort();\n      createCheckboxList(els.hostItems, hosts, state.selectedHosts, async () => {\n        state.selectedGroups.clear();\n        state.selectedInstances.clear();\n        state.selectedMetrics.clear();\n        await refreshGroups();\n        await refreshInstances();\n        await refreshMetrics();\n        refreshDropdownSummaries();\n        await maybeVisualize();\n      }, els.hostSearch.value);\n    }\n\n    async function refreshGroups() {\n      const groups = getAvailableGroups();\n      state.selectedGroups = new Set([...state.selectedGroups].filter(g => groups.includes(g)));\n      createCheckboxList(els.groupItems, groups, state.selectedGroups, async () => {\n        state.selectedInstances.clear();\n        state.selectedMetrics.clear();\n        await refreshInstances();\n        await refreshMetrics();\n        refreshDropdownSummaries();\n        await maybeVisualize();\n      }, els.groupSearch.value);\n    }\n\n    async function refreshInstances() {\n      const instances = getAvailableInstances();\n      state.selectedInstances = new Set([...state.selectedInstances].filter(i => instances.includes(i)));\n      createCheckboxList(els.instanceItems, instances, state.selectedInstances, async () => {\n        refreshDropdownSummaries();\n        await maybeVisualize();\n      }, els.instanceSearch.value);\n    }\n\n    async function refreshMetrics() {\n      const metrics = getAvailableMetricsForGroupOrInstance();\n      state.selectedMetrics = new Set([...state.selectedMetrics].filter(m => metrics.includes(m)));\n      createCheckboxList(els.metricItems, metrics, state.selectedMetrics, async () => {\n        refreshDropdownSummaries();\n        await maybeVisualize();\n      }, els.metricSearch.value);\n    }\n\n    function updateSelectionStatus(extra = \'\') {\n      const msg =\n        `Hosts: ${state.selectedHosts.size} | ` +\n        `Groups: ${state.selectedGroups.size} | ` +\n        `Instances: ${state.selectedInstances.size} | ` +\n        `Metrics: ${state.selectedMetrics.size} | ` +\n        `CSV uploads: ${state.csvFileMap.size}` +\n        (extra ? ` | ${extra}` : \'\');\n      setStatus(els.selectionStatus, msg, \'ok\');\n    }\n\n    function loadMetadataObject(metadata) {\n      state.metadata = metadata;\n      state.selectedHosts.clear();\n      state.selectedGroups.clear();\n      state.selectedInstances.clear();\n      state.selectedMetrics.clear();\n      renderHosts();\n      refreshGroups();\n      refreshInstances();\n      refreshMetrics();\n      refreshDropdownSummaries();\n      updateSelectionStatus();\n    }\n\n    async function tryAutoLoadMetadata() {\n      try {\n        const text = await fetchText(\'./esxtop-metadata.json\');\n        const metadata = JSON.parse(text);\n        loadMetadataObject(metadata);\n        setStatus(els.loadStatus, `Auto-loaded metadata. Files: ${metadata.file_count || (metadata.files || []).length}`, \'ok\');\n      } catch (err) {\n        setStatus(els.loadStatus, \'Auto-load failed. Select metadata JSON manually.\', \'err\');\n      }\n    }\n\n    async function getCsvTextForMeta(fileMeta) {\n      const uploaded = state.csvFileMap.get(fileMeta.file_name);\n      if (uploaded) return await readFileText(uploaded);\n\n      const tryPaths = [];\n      if (fileMeta.relative_path) tryPaths.push(fileMeta.relative_path);\n      if (fileMeta.full_path) tryPaths.push(fileMeta.full_path);\n      if (fileMeta.file_name) tryPaths.push(fileMeta.file_name);\n\n      for (const p of tryPaths) {\n        try {\n          return await fetchText(p);\n        } catch (_) {}\n      }\n\n      throw new Error(`Cannot access ${fileMeta.file_name}`);\n    }\n\n    function buildLegendName(host, group, instance, metric) {\n      return `${host} | ${group} | ${instance} | ${metric}`;\n    }\n\n    function buildHoverText(instance, metric, value, timestamp) {\n      return `Instance: ${instance}<br>Metric: ${metric}<br>Value: ${value}<br>Timestamp: ${timestamp}`;\n    }\n\n    async function visualize() {\n      if (!state.metadata) {\n        renderEmptyChart();\n        return;\n      }\n\n      const matchingFiles = (state.metadata.files || []).filter(f =>\n        state.selectedHosts.has(f.host) &&\n        state.selectedGroups.has(f.group)\n      );\n\n      if (matchingFiles.length === 0 || state.selectedGroups.size === 0) {\n        renderEmptyChart(\'Select host and group to visualize\');\n        updateSelectionStatus();\n        return;\n      }\n\n      if (state.selectedInstances.size === 0 && state.selectedMetrics.size === 0) {\n        renderEmptyChart(\'Select at least one instance or one metric to visualize\');\n        updateSelectionStatus();\n        return;\n      }\n\n      const traces = [];\n      let inaccessibleFiles = 0;\n\n      for (const fileMeta of matchingFiles) {\n        const selectedColumns = (fileMeta.columns || []).filter(c => {\n          const instSelected = state.selectedInstances.size > 0;\n          const metricSelected = state.selectedMetrics.size > 0;\n\n          if (instSelected && metricSelected) {\n            return state.selectedInstances.has(c.instance) && state.selectedMetrics.has(c.metric);\n          }\n          if (instSelected && !metricSelected) {\n            return state.selectedInstances.has(c.instance);\n          }\n          if (!instSelected && metricSelected) {\n            return state.selectedMetrics.has(c.metric);\n          }\n          return false;\n        });\n\n        if (selectedColumns.length === 0) continue;\n\n        let text;\n        try {\n          text = await getCsvTextForMeta(fileMeta);\n        } catch (_) {\n          inaccessibleFiles++;\n          continue;\n        }\n\n        const lines = text.split(/\\r?\\n/).filter(line => line.trim() !== \'\');\n        if (lines.length < 2) continue;\n\n        const headers = parseCsvLine(lines[0]);\n        const idxMap = new Map();\n        headers.forEach((h, idx) => idxMap.set(h, idx));\n\n        const tsIndex = idxMap.get(fileMeta.timestamp_header);\n        if (tsIndex === undefined) continue;\n\n        const traceMap = new Map();\n\n        selectedColumns.forEach(col => {\n          const idx = idxMap.get(col.header);\n          if (idx === undefined) return;\n\n          const key = `${fileMeta.host}|${fileMeta.group}|${col.instance}|${col.metric}|${col.header}`;\n          if (!traceMap.has(key)) {\n            traceMap.set(key, {\n              x: [],\n              y: [],\n              text: [],\n              name: buildLegendName(fileMeta.host, fileMeta.group, col.instance, col.metric),\n              mode: \'lines\',\n              type: \'scatter\',\n              hovertemplate: \'%{text}<extra></extra>\',\n              meta: {\n                host: fileMeta.host,\n                group: fileMeta.group,\n                instance: col.instance,\n                metric: col.metric\n              },\n              _colIndices: []\n            });\n          }\n          traceMap.get(key)._colIndices.push(idx);\n        });\n\n        for (let i = 1; i < lines.length; i++) {\n          const row = parseCsvLine(lines[i]);\n          const tsRaw = row[tsIndex];\n          const dt = parseTimestamp(tsRaw);\n          if (!dt) continue;\n\n          traceMap.forEach(trace => {\n            for (const colIdx of trace._colIndices) {\n              const rawValue = row[colIdx];\n              if (rawValue === undefined || rawValue === \'\') continue;\n\n              const num = Number(rawValue);\n              if (Number.isNaN(num)) continue;\n\n              trace.x.push(dt);\n              trace.y.push(num);\n              trace.text.push(buildHoverText(trace.meta.instance, trace.meta.metric, rawValue, tsRaw));\n            }\n          });\n        }\n\n        traceMap.forEach(trace => {\n          delete trace._colIndices;\n          if (trace.x.length > 0) traces.push(trace);\n        });\n      }\n\n      if (traces.length === 0) {\n        const msg = state.csvFileMap.size === 0\n          ? \'No chart data. Serve this folder with a local web server or upload the matching CSV files.\'\n          : \'No numeric data found for the current selection.\';\n        renderEmptyChart(msg);\n        updateSelectionStatus(inaccessibleFiles ? `inaccessible files: ${inaccessibleFiles}` : \'\');\n        return;\n      }\n\n      const title =\n        `Hosts: ${state.selectedHosts.size} | ` +\n        `Groups: ${state.selectedGroups.size} | ` +\n        `Instances: ${state.selectedInstances.size} | ` +\n        `Metrics: ${state.selectedMetrics.size}`;\n\n      renderChart(traces, title);\n      updateSelectionStatus(inaccessibleFiles ? `inaccessible files: ${inaccessibleFiles}` : \'\');\n    }\n\n    async function maybeVisualize() {\n      refreshDropdownSummaries();\n      await visualize();\n    }\n\n    els.metadataFile.addEventListener(\'change\', async () => {\n      const file = els.metadataFile.files[0];\n      if (!file) return;\n\n      try {\n        const text = await readFileText(file);\n        const metadata = JSON.parse(text);\n        loadMetadataObject(metadata);\n        setStatus(els.loadStatus, `Metadata loaded. Files: ${metadata.file_count || (metadata.files || []).length}`, \'ok\');\n      } catch (err) {\n        setStatus(els.loadStatus, `Failed to load metadata: ${err.message || err}`, \'err\');\n      }\n    });\n\n    els.csvFiles.addEventListener(\'change\', async () => {\n      state.csvFileMap = new Map();\n      Array.from(els.csvFiles.files || []).forEach(file => state.csvFileMap.set(file.name, file));\n      await maybeVisualize();\n    });\n\n    [\'hostSearch\', \'groupSearch\', \'instanceSearch\', \'metricSearch\'].forEach(id => {\n      els[id].addEventListener(\'input\', async () => {\n        if (id === \'hostSearch\') await renderHosts();\n        if (id === \'groupSearch\') await refreshGroups();\n        if (id === \'instanceSearch\') await refreshInstances();\n        if (id === \'metricSearch\') await refreshMetrics();\n      });\n    });\n\n    document.querySelectorAll(\'.dropdown\').forEach(drop => {\n      const btn = drop.querySelector(\'.dropdown-btn\');\n      btn.addEventListener(\'click\', (e) => {\n        e.stopPropagation();\n        document.querySelectorAll(\'.dropdown.open\').forEach(d => {\n          if (d !== drop) d.classList.remove(\'open\');\n        });\n        drop.classList.toggle(\'open\');\n      });\n\n      drop.querySelector(\'.dropdown-panel\').addEventListener(\'click\', (e) => {\n        e.stopPropagation();\n      });\n    });\n\n    document.addEventListener(\'click\', () => {\n      document.querySelectorAll(\'.dropdown.open\').forEach(d => d.classList.remove(\'open\'));\n    });\n\n    document.querySelectorAll(\'[data-action]\').forEach(btn => {\n      btn.addEventListener(\'click\', async (e) => {\n        e.stopPropagation();\n\n        const target = btn.dataset.target;\n        const action = btn.dataset.action;\n\n        let allValues = [];\n        let filteredValues = [];\n        let setRef = null;\n        let searchTerm = \'\';\n\n        if (target === \'hosts\') {\n          allValues = state.metadata?.hosts || [];\n          searchTerm = els.hostSearch.value;\n          setRef = state.selectedHosts;\n        } else if (target === \'groups\') {\n          allValues = getAvailableGroups();\n          searchTerm = els.groupSearch.value;\n          setRef = state.selectedGroups;\n        } else if (target === \'instances\') {\n          allValues = getAvailableInstances();\n          searchTerm = els.instanceSearch.value;\n          setRef = state.selectedInstances;\n        } else if (target === \'metrics\') {\n          allValues = getAvailableMetricsForGroupOrInstance();\n          searchTerm = els.metricSearch.value;\n          setRef = state.selectedMetrics;\n        }\n\n        if (!setRef) return;\n\n        filteredValues = getFilteredValues(allValues, searchTerm);\n\n        if (action === \'clear\') {\n          filteredValues.forEach(v => setRef.delete(v));\n        } else if (action === \'all\') {\n          filteredValues.forEach(v => setRef.add(v));\n        }\n\n        if (target === \'hosts\') {\n          state.selectedGroups.clear();\n          state.selectedInstances.clear();\n          state.selectedMetrics.clear();\n          await refreshGroups();\n          await refreshInstances();\n          await refreshMetrics();\n          await renderHosts();\n        } else if (target === \'groups\') {\n          state.selectedInstances.clear();\n          state.selectedMetrics.clear();\n          await refreshGroups();\n          await refreshInstances();\n          await refreshMetrics();\n        } else if (target === \'instances\') {\n          await refreshInstances();\n          await refreshMetrics();\n        } else if (target === \'metrics\') {\n          await refreshMetrics();\n        }\n\n        refreshDropdownSummaries();\n        await maybeVisualize();\n      });\n    });\n\n    loadTheme();\n    renderEmptyChart(\'Make selections to visualize\');\n    tryAutoLoadMetadata();\n  </script>\n</body>\n</html>'


def detect_timestamp_column_metadata(headers):
    for col in headers:
        if col == "Time":
            return col
        if "(PDH-CSV 4.0) (UTC)(0)" in col:
            return col
    return None


def normalize_display_group(group_name: str) -> str:
    return group_name.replace("_", " ").strip()


def parse_full_header_metadata(header: str):
    if not header.startswith("\\"):
        return None

    segments = header[2:].split("\\")
    if len(segments) < 3:
        return None

    full_hostname = (segments[0] or "").strip()
    short_hostname = full_hostname.split(".")[0].strip() if full_hostname else ""

    remaining = [s.strip() for s in segments[1:] if s.strip()]
    if len(remaining) < 2:
        return None

    metric = remaining[-1]
    group_segment = remaining[-2]
    group_name, instance = parse_group_instance(group_segment)
    if not group_name:
        return None

    return {
        "mode": "full",
        "full_hostname": full_hostname,
        "short_hostname": short_hostname,
        "group": group_name,
        "instance": instance or "overall",
        "metric": metric or "value",
        "original_header": header,
    }


def parse_clean_header_metadata(header: str):
    header = (header or "").strip()
    if not header:
        return None

    if "-" in header:
        instance, metric = header.rsplit("-", 1)
        instance = instance.strip() or "overall"
        metric = metric.strip() or "value"
    else:
        instance = "overall"
        metric = header

    return {
        "mode": "clean",
        "instance": instance,
        "metric": metric,
        "original_header": header,
    }


def parse_filename_host_group(stem: str):
    if "-" in stem:
        host, group = stem.rsplit("-", 1)
        return host.strip(), group.strip()
    return stem.strip(), stem.strip()


def process_output_csv_for_metadata(csv_path: Path, root: Path):
    try:
        with csv_path.open("r", newline="", encoding="utf-8-sig") as fh:
            reader = csv.reader(fh)
            headers = next(reader, None)

        if not headers:
            return None, "empty csv"

        timestamp_col = detect_timestamp_column_metadata(headers)
        if not timestamp_col:
            return None, "timestamp column not found"

        stem = csv_path.stem
        host_from_name, group_from_name = parse_filename_host_group(stem)

        parsed_columns = []
        instances = set()
        metrics = set()
        full_hostnames = set()
        header_mode = "clean"

        group_name = normalize_display_group(group_from_name)
        short_hostname = host_from_name

        for col in headers:
            if col == timestamp_col:
                continue

            parsed = parse_full_header_metadata(col)
            if parsed:
                header_mode = "full"
                if parsed.get("group"):
                    group_name = parsed["group"]
                if parsed.get("short_hostname"):
                    short_hostname = parsed["short_hostname"]
                if parsed.get("full_hostname"):
                    full_hostnames.add(parsed["full_hostname"])
                instance = parsed["instance"]
                metric = parsed["metric"]
            else:
                parsed = parse_clean_header_metadata(col)
                if not parsed:
                    continue
                instance = parsed["instance"]
                metric = parsed["metric"]

            instances.add(instance)
            metrics.add(metric)
            parsed_columns.append({
                "header": parsed["original_header"],
                "instance": instance,
                "metric": metric,
            })

        instance_metrics = defaultdict(set)
        for c in parsed_columns:
            instance_metrics[c["instance"]].add(c["metric"])

        rel_path = str(csv_path.relative_to(root))
        abs_path = str(csv_path.resolve())

        file_entry = {
            "file_name": csv_path.name,
            "relative_path": rel_path,
            "full_path": rel_path,
            "absolute_path": abs_path,
            "host": short_hostname,
            "group": group_name,
            "timestamp_header": timestamp_col,
            "header_mode": header_mode,
            "full_hostnames": sorted(full_hostnames),
            "instances": sorted(instances),
            "metrics": sorted(metrics),
            "instance_metrics": {k: sorted(v) for k, v in sorted(instance_metrics.items())},
            "columns": parsed_columns,
        }
        return file_entry, None
    except Exception as exc:
        return None, str(exc)


def generate_metadata_json(raw_dir: Path, metadata_json_path: Path):
    csv_files = sorted(set(raw_dir.glob("*.csv")))
    files = []
    groups = set()
    hosts = set()
    all_instances = set()
    all_metrics = set()
    skipped = []
    host_group_map = defaultdict(lambda: defaultdict(lambda: {"instances": set(), "metrics": set(), "files": []}))

    for csv_file in csv_files:
        entry, err = process_output_csv_for_metadata(csv_file, raw_dir)
        if err:
            skipped.append({"file": str(csv_file), "reason": err})
            continue

        files.append(entry)
        groups.add(entry["group"])
        hosts.add(entry["host"])
        all_instances.update(entry["instances"])
        all_metrics.update(entry["metrics"])

        hg = host_group_map[entry["host"]][entry["group"]]
        hg["instances"].update(entry["instances"])
        hg["metrics"].update(entry["metrics"])
        hg["files"].append(entry["file_name"])

    host_groups = {}
    for host, group_data in sorted(host_group_map.items()):
        host_groups[host] = {}
        for group, data in sorted(group_data.items()):
            host_groups[host][group] = {
                "instances": sorted(data["instances"]),
                "metrics": sorted(data["metrics"]),
                "files": sorted(data["files"]),
            }

    metadata = {
        "tool": "esxtop-metadata",
        "version": "0.0.4",
        "root": str(raw_dir.resolve()),
        "file_count": len(files),
        "groups": sorted(groups),
        "hosts": sorted(hosts),
        "instances": sorted(all_instances),
        "metrics": sorted(all_metrics),
        "host_groups": host_groups,
        "files": files,
        "skipped": skipped,
    }

    metadata_json_path.parent.mkdir(parents=True, exist_ok=True)
    with metadata_json_path.open("w", encoding="utf-8") as fh:
        json.dump(metadata, fh, indent=2, ensure_ascii=False)
    return metadata_json_path


def write_visualizer(output_dir: Path):
    out_path = output_dir / VISUALIZER_FILENAME
    out_path.write_text(VISUALIZER_HTML, encoding="utf-8")
    return out_path


def find_available_port() -> int:
    import socket
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("", 0))
        return int(sock.getsockname()[1])


def print_server_hints(output_dir: Path):
    suggested_port = find_available_port()
    print("\n[VISUALIZER]")
    print(f"Metadata JSON   : {output_dir / 'esxtop-metadata.json'}")
    print(f"Visualizer HTML : {output_dir / VISUALIZER_FILENAME}")
    print("\n[HTTP SERVER HINTS]")
    print(f"Auto port hint  : cd \"{output_dir}\" && python3 -m http.server {suggested_port}")
    print(f"Custom port     : cd \"{output_dir}\" && python3 -m http.server <PORT>")
    print(f"Open browser    : http://localhost:{suggested_port}/{VISUALIZER_FILENAME}")

def main():
    parser = argparse.ArgumentParser(
        description="Merge ESXTOP CSV data into a single output file per host/group using temp-file merge and external sort. Also generates metadata JSON and HTML visualizer in the output directory."
    )
    parser.add_argument(
        "--root",
        default=".",
        help="Root directory to scan for CSV files (default: current working directory)"
    )
    parser.add_argument(
        "--outdir",
        default="output",
        help="Output directory root (default: output)"
    )
    parser.add_argument(
        "--group",
        help="Extract only this dynamically detected ESXTOP group"
    )
    parser.add_argument(
        "--delimiter",
        default=",",
        help="CSV delimiter of input/output files (default: ',')"
    )
    parser.add_argument(
        "--recursive",
        action="store_true",
        help="Scan subdirectories recursively"
    )
    parser.add_argument(
        "--keep-full-header",
        action="store_true",
        help="Keep ORIGINAL timestamp and ESXTOP full column headers exactly as-is"
    )
    parser.add_argument(
        "--keep-temp",
        action="store_true",
        help="Keep temp chunk/sorted files after completion"
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Enable runtime metrics and debug statistics"
    )
    args = parser.parse_args()

    metrics = RunMetrics() if args.debug else None

    root = Path(args.root).resolve()
    outdir = Path(args.outdir).resolve()
    raw_output_dir = outdir 
    tmp_root = outdir / TEMP_ROOT_NAME
    metadata_path = tmp_root / METADATA_FILE
    generated_metadata_json = outdir / "esxtop-metadata.json"

    if not root.exists():
        print(f"[ERROR] Root path does not exist: {root}", file=sys.stderr)
        if metrics:
            print_run_metrics(metrics.finalize())
        sys.exit(2)

    if not root.is_dir():
        print(f"[ERROR] Root path is not a directory: {root}", file=sys.stderr)
        if metrics:
            print_run_metrics(metrics.finalize())
        sys.exit(2)

    outdir.mkdir(parents=True, exist_ok=True)
    raw_output_dir.mkdir(parents=True, exist_ok=True)
    tmp_root.mkdir(parents=True, exist_ok=True)

    if metadata_path.exists():
        try:
            metadata_path.unlink()
        except Exception:
            pass

    for child_name in [CHUNKS_DIR_NAME, SORTED_DIR_NAME]:
        child = tmp_root / child_name
        if child.exists():
            shutil.rmtree(child, ignore_errors=True)

    metadata = {"groups": {}}
    save_metadata(metadata_path, metadata)

    csv_files = discover_csv_files(
        root=root,
        recursive=args.recursive,
        outdir_name=outdir.name
    )

    if not csv_files:
        print(f"[INFO] No CSV files found under: {root}")
        if metrics:
            print_run_metrics(metrics.finalize())
        sys.exit(0)

    print(f"[INFO] Root directory : {root}")
    print(f"[INFO] Output dir     : {raw_output_dir}")
    print(f"[INFO] Temp dir       : {tmp_root}")
    print(f"[INFO] Recursive scan : {args.recursive}")
    print(f"[INFO] CSV files      : {len(csv_files)}")
    print(f"[INFO] Group filter   : {args.group or 'ALL'}")
    print(f"[INFO] Full headers   : {args.keep_full_header}")
    print(f"[INFO] Debug          : {args.debug}")

    processed = 0
    skipped = 0
    errors = 0

    for csv_file in csv_files:
        status, message = ingest_file_to_chunks(
            csv_path=csv_file,
            tmp_root=tmp_root,
            metadata=metadata,
            metadata_path=metadata_path,
            group_filter=args.group,
            delimiter=args.delimiter,
            keep_full_header=args.keep_full_header,
            metrics=metrics,
        )

        if status == "ok":
            processed += 1
            print(f"[OK] {csv_file} | {message}")
        elif status == "skipped":
            skipped += 1
            print(f"[SKIP] {csv_file} | {message}")
        else:
            errors += 1
            print(f"[ERROR] {csv_file} | {message}")

        if metrics:
            metrics.sample()

    metadata = load_metadata(metadata_path)
    groups = metadata.get("groups", {})

    if not groups:
        print("\n[SUMMARY]")
        print(f"Processed files : {processed}")
        print(f"Skipped files   : {skipped}")
        print(f"Errored files   : {errors}")
        print("Output CSV files: 0")
        if not args.keep_temp:
            shutil.rmtree(tmp_root, ignore_errors=True)
        if metrics:
            print_run_metrics(metrics.finalize())
        sys.exit(0)

    written = []
    for group_id, group_meta in sorted(groups.items()):
        try:
            out_path = finalize_group_output(
                group_id=group_id,
                group_meta=group_meta,
                tmp_root=tmp_root,
                raw_output_dir=raw_output_dir,
                delimiter=args.delimiter,
                metrics=metrics,
            )
            written.append(out_path)
            print(f"[FINALIZED] {out_path}")
        except Exception as exc:
            errors += 1
            print(f"[ERROR] finalize {group_id} | {exc}")

        if metrics:
            metrics.sample()

    metadata_json_path = generate_metadata_json(raw_output_dir, generated_metadata_json)
    visualizer_path = write_visualizer(outdir)

    if not args.keep_temp:
        shutil.rmtree(tmp_root, ignore_errors=True)

    print("\n[SUMMARY]")
    print(f"Processed files : {processed}")
    print(f"Skipped files   : {skipped}")
    print(f"Errored files   : {errors}")
    print(f"Output CSV files: {len(written)}")
    print(f"Metadata JSON   : {metadata_json_path}")
    print(f"Visualizer HTML : {visualizer_path}")
    print("\n[OUTPUTS]")
    for path in written:
        print(path)

    print_server_hints(outdir)

    if metrics:
        print_run_metrics(metrics.finalize())


if __name__ == "__main__":
    main()
