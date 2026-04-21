#!/usr/bin/env python3
"""
esxtop-offline_v0.0.6.3.py

Version: v0.0.6.3

Description:
    Offline ESXTOP CSV processor using temp-file merge + external sort.

Features:
    - Auto-detects CSV files from a root directory (default: current working directory)
    - Default scan includes CSVs in the root and its immediate subdirectories
    - Use --recursive to scan all nested subdirectories
    - Dynamically detects ESXTOP groups from headers (no predefined group list)
    - Merges multiple CSVs into a single output file per (host, group)
    - Optional no-merge mode via --no-merge / --nm so each source folder is processed independently
    - Uses disk-backed temp chunk files instead of keeping all merged rows in memory
    - Expands columns when new metrics appear in later files
    - Externally sorts rows in ascending timestamp order
    - Writes output to: output/<merge-scope>/<host>-<group>.csv
    - Keeps ORIGINAL timestamp and ESXTOP headers exactly as-is by default
    - Use --normalize-headers to convert headers to the legacy cleaned format
    - Shows runtime metrics only when --debug is used

Examples:
    python3 esxtop-offline_v0.0.6.3.py
    python3 esxtop-offline_v0.0.6.3.py --recursive
    python3 esxtop-offline_v0.0.6.3.py --no-merge
    python3 esxtop-offline_v0.0.6.3.py --group "Physical Cpu"
    python3 esxtop-offline_v0.0.6.3.py --normalize-headers
    python3 esxtop-offline_v0.0.6.3.py --debug
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


def make_csv_writer(handle, delimiter: str = ","):
    return csv.writer(handle, delimiter=delimiter, quoting=csv.QUOTE_ALL)


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


def safe_no_merge_label(label: str) -> str:
    label = (label or "").strip()
    label = label.replace(os.sep, "__")
    label = re.sub(r"[^A-Za-z0-9._-]+", "_", label)
    label = re.sub(r"_+", "_", label)
    return label.strip("_") or "root"


def get_no_merge_scope_label(root: Path, csv_path: Path) -> str:
    parent = csv_path.parent.resolve()
    root = root.resolve()
    if parent == root:
        return "__root__"
    return safe_no_merge_label(str(parent.relative_to(root)))


def discover_csv_files(root: Path, recursive: bool, outdir_name: str):
    files = []
    if recursive:
        iterator = root.rglob("*.csv")
    else:
        iterator = list(root.glob("*.csv"))
        for child in sorted(p for p in root.iterdir() if p.is_dir()):
            iterator.extend(child.glob("*.csv"))

    for path in iterator:
        if outdir_name in path.parts:
            continue
        files.append(path)

    return sorted(set(files))


def group_csv_files_for_no_merge(root: Path, csv_files):
    grouped = defaultdict(list)
    for csv_file in csv_files:
        grouped[get_no_merge_scope_label(root, csv_file)].append(csv_file)
    return {k: sorted(v) for k, v in sorted(grouped.items())}


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
                    writer = make_csv_writer(fh, delimiter=delimiter)

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
        writer = make_csv_writer(fout, delimiter=delimiter)
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
            writer = make_csv_writer(fout, delimiter=delimiter)
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
VISUALIZER_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <title>ESXTOP Viewer v0.0.8</title>
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <script src="https://cdn.plot.ly/plotly-2.35.2.min.js"></script>
  <style>
    :root {
      --bg: #0b1020;
      --panel: #12192b;
      --panel-2: #182235;
      --text: #e9eef8;
      --muted: #99a6bd;
      --border: #2b3952;
      --accent: #4f8cff;
      --btn: #25324a;
      --btn-hover: #334564;
      --input: #0f1728;
      --success: #35c16f;
      --danger: #ff6b6b;
      --shadow: 0 8px 22px rgba(0,0,0,0.24);
    }

    body.light {
      --bg: #f3f6fb;
      --panel: #ffffff;
      --panel-2: #eef3fb;
      --text: #101827;
      --muted: #5f6c80;
      --border: #d6deeb;
      --accent: #2563eb;
      --btn: #e7eefb;
      --btn-hover: #d7e4fb;
      --input: #ffffff;
      --success: #0f9d58;
      --danger: #dc2626;
      --shadow: 0 8px 22px rgba(10,20,40,0.08);
    }

    * { box-sizing: border-box; }

    body {
      margin: 0;
      font-family: Arial, Helvetica, sans-serif;
      background: var(--bg);
      color: var(--text);
    }

    .app {
      min-height: 100vh;
      display: flex;
      flex-direction: column;
    }

    .topbar {
      display: grid;
      grid-template-columns: 220px 1fr 54px;
      gap: 12px;
      padding: 14px;
      border-bottom: 1px solid var(--border);
      background: var(--panel);
      align-items: start;
    }

    .brand {
      font-size: 18px;
      font-weight: 700;
      line-height: 1.25;
      padding-top: 4px;
    }

    .toolbar {
      display: grid;
      grid-template-columns: repeat(4, minmax(220px, 1fr));
      gap: 12px;
    }

    .dropdown {
      position: relative;
      min-width: 0;
    }

    .dropdown-btn {
      width: 100%;
      border: 1px solid var(--border);
      background: var(--panel-2);
      color: var(--text);
      border-radius: 14px;
      padding: 10px 12px;
      cursor: pointer;
      text-align: left;
      min-height: 48px;
      box-shadow: var(--shadow);
    }

    .dropdown-label {
      display: block;
      font-size: 12px;
      color: var(--muted);
      margin-bottom: 4px;
      font-weight: 700;
    }

    .dropdown-value {
      display: block;
      font-size: 13px;
      font-weight: 600;
      white-space: nowrap;
      overflow: hidden;
      text-overflow: ellipsis;
    }

    .dropdown-panel {
      position: absolute;
      top: calc(100% + 8px);
      left: 0;
      right: 0;
      background: var(--panel);
      border: 1px solid var(--border);
      border-radius: 14px;
      box-shadow: var(--shadow);
      z-index: 50;
      display: none;
      overflow: hidden;
    }

    .dropdown.open .dropdown-panel {
      display: block;
    }

    .dropdown-search {
      width: calc(100% - 20px);
      margin: 10px;
      border: 1px solid var(--border);
      background: var(--input);
      color: var(--text);
      border-radius: 10px;
      padding: 8px 10px;
      font-size: 13px;
    }

    .dropdown-toolbar {
      display: grid;
      grid-template-columns: 1fr 1fr;
      gap: 8px;
      padding: 0 10px 10px 10px;
      border-bottom: 1px solid var(--border);
      background: var(--panel);
    }

    .dropdown-items {
      max-height: 260px;
      overflow: auto;
      padding: 8px 10px 10px 10px;
    }

    .dropdown-item {
      display: flex;
      align-items: center;
      gap: 8px;
      padding: 6px 2px;
      font-size: 13px;
    }

    .dropdown-item input {
      margin: 0;
      flex: 0 0 auto;
    }

    button, input[type="file"] {
      border: 1px solid var(--border);
      background: var(--btn);
      color: var(--text);
      border-radius: 10px;
      padding: 8px 10px;
      font-size: 13px;
    }

    button {
      cursor: pointer;
      font-weight: 600;
    }

    button:hover {
      background: var(--btn-hover);
    }

    .theme-btn {
      height: 40px;
      font-size: 18px;
    }

    .meta-panel {
      padding: 12px 14px 0 14px;
    }

    .meta-row {
      display: grid;
      grid-template-columns: 1fr 1fr;
      gap: 12px;
      margin-bottom: 8px;
    }

    .panel {
      background: var(--panel);
      border: 1px solid var(--border);
      border-radius: 16px;
      padding: 12px;
    }

    .field {
      margin-bottom: 0;
    }

    .field label {
      display: block;
      font-size: 12px;
      font-weight: 700;
      margin-bottom: 6px;
    }

    .status {
      font-size: 12px;
      color: var(--muted);
      line-height: 1.5;
    }

    .status.ok { color: var(--success); }
    .status.err { color: var(--danger); }

    .info-line {
      padding: 0 2px;
      font-size: 11px;
      color: var(--muted);
      line-height: 1.4;
    }

    .content {
      padding: 10px 14px 14px 14px;
      display: grid;
      grid-template-rows: auto 1fr;
      gap: 10px;
      flex: 1;
      min-height: 0;
    }

    .chart-toolbar {
      display: flex;
      justify-content: flex-end;
      align-items: center;
      gap: 8px;
      flex-wrap: wrap;
    }

    #chart {
      width: 100%;
      height: 78vh;
      border: 1px solid var(--border);
      border-radius: 16px;
      background: var(--panel);
    }

    .legend-collapsed #chart {
      height: 84vh;
    }

    .small {
      font-size: 11px;
      color: var(--muted);
    }

    @media (max-width: 1320px) {
      .topbar {
        grid-template-columns: 1fr;
      }
      .toolbar {
        grid-template-columns: repeat(2, minmax(220px, 1fr));
      }
      .meta-row {
        grid-template-columns: 1fr;
      }
    }

    @media (max-width: 860px) {
      .toolbar {
        grid-template-columns: 1fr;
      }
    }
  </style>
</head>
<body>
  <div class="app" id="appRoot">
    <div class="topbar">
      <div class="brand">ESXTOP Viewer<br>v0.0.8</div>

      <div class="toolbar">
        <div class="dropdown" id="hostDropdown">
          <button class="dropdown-btn" type="button">
            <span class="dropdown-label">Hosts</span>
            <span class="dropdown-value" id="hostValue">None selected</span>
          </button>
          <div class="dropdown-panel">
            <input class="dropdown-search" id="hostSearch" placeholder="Search hosts..." />
            <div class="dropdown-toolbar">
              <button type="button" data-action="all" data-target="hosts">Select All</button>
              <button type="button" data-action="clear" data-target="hosts">Clear</button>
            </div>
            <div class="dropdown-items" id="hostItems"></div>
          </div>
        </div>

        <div class="dropdown" id="groupDropdown">
          <button class="dropdown-btn" type="button">
            <span class="dropdown-label">Groups</span>
            <span class="dropdown-value" id="groupValue">None selected</span>
          </button>
          <div class="dropdown-panel">
            <input class="dropdown-search" id="groupSearch" placeholder="Search groups..." />
            <div class="dropdown-toolbar">
              <button type="button" data-action="all" data-target="groups">Select All</button>
              <button type="button" data-action="clear" data-target="groups">Clear</button>
            </div>
            <div class="dropdown-items" id="groupItems"></div>
          </div>
        </div>

        <div class="dropdown" id="instanceDropdown">
          <button class="dropdown-btn" type="button">
            <span class="dropdown-label">Instances</span>
            <span class="dropdown-value" id="instanceValue">None selected</span>
          </button>
          <div class="dropdown-panel">
            <input class="dropdown-search" id="instanceSearch" placeholder="Search instances..." />
            <div class="dropdown-toolbar">
              <button type="button" data-action="all" data-target="instances">Select All</button>
              <button type="button" data-action="clear" data-target="instances">Clear</button>
            </div>
            <div class="dropdown-items" id="instanceItems"></div>
          </div>
        </div>

        <div class="dropdown" id="metricDropdown">
          <button class="dropdown-btn" type="button">
            <span class="dropdown-label">Metrics</span>
            <span class="dropdown-value" id="metricValue">None selected</span>
          </button>
          <div class="dropdown-panel">
            <input class="dropdown-search" id="metricSearch" placeholder="Search metrics..." />
            <div class="dropdown-toolbar">
              <button type="button" data-action="all" data-target="metrics">Select All</button>
              <button type="button" data-action="clear" data-target="metrics">Clear</button>
            </div>
            <div class="dropdown-items" id="metricItems"></div>
          </div>
        </div>
      </div>

      <button id="themeToggle" class="theme-btn" title="Toggle dark/light mode">🌙</button>
    </div>

    <div class="meta-panel">
      <div class="meta-row">
        <div class="panel">
          <div class="field">
            <label for="metadataFile">Metadata JSON</label>
            <input type="file" id="metadataFile" accept=".json" />
          </div>
        </div>

        <div class="panel">
          <div class="field">
            <label for="csvFiles">CSV Files (optional fallback)</label>
            <input type="file" id="csvFiles" accept=".csv" multiple />
          </div>
        </div>
      </div>

      <div class="info-line">
        <div id="selectionStatus" class="status">No metadata loaded yet.</div>
        <div id="loadStatus" class="status">Trying to auto-load ./esxtop-metadata.json ...</div>
      </div>
    </div>

    <div class="content">
      <div class="chart-toolbar">
        <button id="legendToggleBtn" type="button">Hide Legend</button>
      </div>
      <div id="chart"></div>
    </div>
  </div>

  <script>
    const state = {
      metadata: null,
      csvFileMap: new Map(),
      selectedHosts: new Set(),
      selectedGroups: new Set(),
      selectedInstances: new Set(),
      selectedMetrics: new Set(),
      theme: 'dark',
      lastTraces: [],
      lastTitle: '',
      legendVisible: true
    };

    const els = {
      appRoot: document.getElementById('appRoot'),
      metadataFile: document.getElementById('metadataFile'),
      csvFiles: document.getElementById('csvFiles'),
      loadStatus: document.getElementById('loadStatus'),
      selectionStatus: document.getElementById('selectionStatus'),
      themeToggle: document.getElementById('themeToggle'),
      legendToggleBtn: document.getElementById('legendToggleBtn'),

      hostItems: document.getElementById('hostItems'),
      groupItems: document.getElementById('groupItems'),
      instanceItems: document.getElementById('instanceItems'),
      metricItems: document.getElementById('metricItems'),

      hostValue: document.getElementById('hostValue'),
      groupValue: document.getElementById('groupValue'),
      instanceValue: document.getElementById('instanceValue'),
      metricValue: document.getElementById('metricValue'),

      hostSearch: document.getElementById('hostSearch'),
      groupSearch: document.getElementById('groupSearch'),
      instanceSearch: document.getElementById('instanceSearch'),
      metricSearch: document.getElementById('metricSearch')
    };

    function setStatus(el, text, cls = '') {
      el.textContent = text;
      el.className = cls ? `status ${cls}` : 'status';
    }

    function summarizeSelection(arr) {
      if (!arr || arr.length === 0) return 'None selected';
      if (arr.length <= 2) return arr.join(', ');
      return `${arr.length} selected`;
    }

    function refreshDropdownSummaries() {
      els.hostValue.textContent = summarizeSelection([...state.selectedHosts]);
      els.groupValue.textContent = summarizeSelection([...state.selectedGroups]);
      els.instanceValue.textContent = summarizeSelection([...state.selectedInstances]);
      els.metricValue.textContent = summarizeSelection([...state.selectedMetrics]);
    }

    function parseTimestamp(ts) {
      const m = /^(\\d{2})\\/(\\d{2})\\/(\\d{4}) (\\d{2}):(\\d{2}):(\\d{2})$/.exec((ts || '').trim());
      if (!m) return null;
      return new Date(
        Number(m[3]),
        Number(m[1]) - 1,
        Number(m[2]),
        Number(m[4]),
        Number(m[5]),
        Number(m[6])
      );
    }

    function parseCsvLine(line) {
      const out = [];
      let cur = '';
      let inQuotes = false;

      for (let i = 0; i < line.length; i++) {
        const ch = line[i];
        if (ch === '"') {
          if (inQuotes && line[i + 1] === '"') {
            cur += '"';
            i++;
          } else {
            inQuotes = !inQuotes;
          }
        } else if (ch === ',' && !inQuotes) {
          out.push(cur);
          cur = '';
        } else {
          cur += ch;
        }
      }

      out.push(cur);
      return out;
    }

    async function readFileText(file) {
      return new Promise((resolve, reject) => {
        const reader = new FileReader();
        reader.onload = () => resolve(reader.result);
        reader.onerror = () => reject(reader.error || new Error('Failed to read file'));
        reader.readAsText(file);
      });
    }

    async function fetchText(url) {
      const res = await fetch(url, { cache: 'no-store' });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      return await res.text();
    }

    function chartLayout(title = '') {
      return {
        title,
        paper_bgcolor: getComputedStyle(document.body).getPropertyValue('--panel'),
        plot_bgcolor: getComputedStyle(document.body).getPropertyValue('--panel'),
        font: { color: getComputedStyle(document.body).getPropertyValue('--text').trim() },
        xaxis: { title: 'Timestamp', gridcolor: getComputedStyle(document.body).getPropertyValue('--border').trim() },
        yaxis: { title: 'Value', gridcolor: getComputedStyle(document.body).getPropertyValue('--border').trim() },
        legend: {
          orientation: 'h',
          tracegroupgap: 5
        },
        showlegend: state.legendVisible,
        margin: { l: 60, r: 30, t: 50, b: 50 },
        hovermode: 'closest',
        hoverlabel: {
          align: 'left',
          namelength: -1
        }
      };
    }

    function renderChart(traces, title = '') {
      state.lastTraces = traces;
      state.lastTitle = title;

      Plotly.newPlot('chart', traces, chartLayout(title), {
        responsive: true,
        displaylogo: false,
        modeBarButtonsToRemove: ['lasso2d', 'select2d']
      });
    }

    function updateLegendVisibility() {
      const chartEl = document.getElementById('chart');
      if (!chartEl || !chartEl.data) return;
      Plotly.relayout(chartEl, { showlegend: state.legendVisible });
    }

    function renderEmptyChart(message = '') {
      renderChart([], message);
    }

    function loadTheme() {
      const saved = localStorage.getItem('esxtop-viewer-theme');
      state.theme = saved || 'dark';
      document.body.classList.toggle('light', state.theme === 'light');
      els.themeToggle.textContent = state.theme === 'light' ? '☀️' : '🌙';
    }

    els.themeToggle.addEventListener('click', () => {
      state.theme = state.theme === 'dark' ? 'light' : 'dark';
      localStorage.setItem('esxtop-viewer-theme', state.theme);
      loadTheme();
      renderChart(state.lastTraces, state.lastTitle);
    });

    els.legendToggleBtn.addEventListener('click', () => {
      state.legendVisible = !state.legendVisible;
      els.legendToggleBtn.textContent = state.legendVisible ? 'Hide Legend' : 'Show Legend';
      els.appRoot.classList.toggle('legend-collapsed', !state.legendVisible);
      updateLegendVisibility();
    });

    function getFilteredValues(values, searchTerm = '') {
      const term = (searchTerm || '').trim().toLowerCase();
      return values.filter(v => v.toLowerCase().includes(term));
    }

    function createCheckboxList(container, values, selectedSet, onChange, searchTerm = '') {
      container.innerHTML = '';
      const filtered = getFilteredValues(values, searchTerm);

      if (filtered.length === 0) {
        const empty = document.createElement('div');
        empty.className = 'small';
        empty.textContent = 'No values available';
        container.appendChild(empty);
        return;
      }

      filtered.forEach(value => {
        const label = document.createElement('label');
        label.className = 'dropdown-item';

        const cb = document.createElement('input');
        cb.type = 'checkbox';
        cb.checked = selectedSet.has(value);
        cb.addEventListener('click', (e) => e.stopPropagation());
        cb.addEventListener('change', async () => {
          if (cb.checked) selectedSet.add(value);
          else selectedSet.delete(value);
          await onChange();
        });

        const span = document.createElement('span');
        span.textContent = value;

        label.appendChild(cb);
        label.appendChild(span);
        container.appendChild(label);
      });
    }

    function getAvailableGroups() {
      const groupSet = new Set();
      [...state.selectedHosts].forEach(host => {
        const hostGroups = state.metadata?.host_groups?.[host] || {};
        Object.keys(hostGroups).forEach(g => groupSet.add(g));
      });
      return [...groupSet].sort();
    }

    function getAvailableInstances() {
      const instanceSet = new Set();
      (state.metadata?.files || [])
        .filter(f => state.selectedHosts.has(f.host) && state.selectedGroups.has(f.group))
        .forEach(f => (f.instances || []).forEach(i => instanceSet.add(i)));
      return [...instanceSet].sort();
    }

    function getAvailableMetricsForGroupOrInstance() {
      const metricSet = new Set();
      (state.metadata?.files || [])
        .filter(f => state.selectedHosts.has(f.host) && state.selectedGroups.has(f.group))
        .forEach(fileMeta => {
          const im = fileMeta.instance_metrics || {};
          if (state.selectedInstances.size > 0) {
            [...state.selectedInstances].forEach(inst => {
              (im[inst] || []).forEach(m => metricSet.add(m));
            });
          } else {
            Object.values(im).forEach(metrics => {
              (metrics || []).forEach(m => metricSet.add(m));
            });
          }
        });
      return [...metricSet].sort();
    }

    async function renderHosts() {
      const hosts = (state.metadata?.hosts || []).slice().sort();
      createCheckboxList(els.hostItems, hosts, state.selectedHosts, async () => {
        state.selectedGroups.clear();
        state.selectedInstances.clear();
        state.selectedMetrics.clear();
        await refreshGroups();
        await refreshInstances();
        await refreshMetrics();
        refreshDropdownSummaries();
        await maybeVisualize();
      }, els.hostSearch.value);
    }

    async function refreshGroups() {
      const groups = getAvailableGroups();
      state.selectedGroups = new Set([...state.selectedGroups].filter(g => groups.includes(g)));
      createCheckboxList(els.groupItems, groups, state.selectedGroups, async () => {
        state.selectedInstances.clear();
        state.selectedMetrics.clear();
        await refreshInstances();
        await refreshMetrics();
        refreshDropdownSummaries();
        await maybeVisualize();
      }, els.groupSearch.value);
    }

    async function refreshInstances() {
      const instances = getAvailableInstances();
      state.selectedInstances = new Set([...state.selectedInstances].filter(i => instances.includes(i)));
      createCheckboxList(els.instanceItems, instances, state.selectedInstances, async () => {
        refreshDropdownSummaries();
        await maybeVisualize();
      }, els.instanceSearch.value);
    }

    async function refreshMetrics() {
      const metrics = getAvailableMetricsForGroupOrInstance();
      state.selectedMetrics = new Set([...state.selectedMetrics].filter(m => metrics.includes(m)));
      createCheckboxList(els.metricItems, metrics, state.selectedMetrics, async () => {
        refreshDropdownSummaries();
        await maybeVisualize();
      }, els.metricSearch.value);
    }

    function updateSelectionStatus(extra = '') {
      const msg =
        `Hosts: ${state.selectedHosts.size} | ` +
        `Groups: ${state.selectedGroups.size} | ` +
        `Instances: ${state.selectedInstances.size} | ` +
        `Metrics: ${state.selectedMetrics.size} | ` +
        `CSV uploads: ${state.csvFileMap.size}` +
        (extra ? ` | ${extra}` : '');
      setStatus(els.selectionStatus, msg, 'ok');
    }

    function loadMetadataObject(metadata) {
      state.metadata = metadata;
      state.selectedHosts.clear();
      state.selectedGroups.clear();
      state.selectedInstances.clear();
      state.selectedMetrics.clear();
      renderHosts();
      refreshGroups();
      refreshInstances();
      refreshMetrics();
      refreshDropdownSummaries();
      updateSelectionStatus();
    }

    async function tryAutoLoadMetadata() {
      try {
        const text = await fetchText('./esxtop-metadata.json');
        const metadata = JSON.parse(text);
        loadMetadataObject(metadata);
        setStatus(els.loadStatus, `Auto-loaded metadata. Files: ${metadata.file_count || (metadata.files || []).length}`, 'ok');
      } catch (err) {
        setStatus(els.loadStatus, 'Auto-load failed. Select metadata JSON manually.', 'err');
      }
    }

    async function getCsvTextForMeta(fileMeta) {
      const uploaded = state.csvFileMap.get(fileMeta.file_name);
      if (uploaded) return await readFileText(uploaded);

      const tryPaths = [];
      if (fileMeta.relative_path) tryPaths.push(fileMeta.relative_path);
      if (fileMeta.full_path) tryPaths.push(fileMeta.full_path);
      if (fileMeta.file_name) tryPaths.push(fileMeta.file_name);

      for (const p of tryPaths) {
        try {
          return await fetchText(p);
        } catch (_) {}
      }

      throw new Error(`Cannot access ${fileMeta.file_name}`);
    }

    function buildLegendName(host, group, instance, metric) {
      return `${host} | ${group} | ${instance} | ${metric}`;
    }

    function buildHoverText(instance, metric, value, timestamp) {
      return `Instance: ${instance}<br>Metric: ${metric}<br>Value: ${value}<br>Timestamp: ${timestamp}`;
    }

    async function visualize() {
      if (!state.metadata) {
        renderEmptyChart();
        return;
      }

      const matchingFiles = (state.metadata.files || []).filter(f =>
        state.selectedHosts.has(f.host) &&
        state.selectedGroups.has(f.group)
      );

      if (matchingFiles.length === 0 || state.selectedGroups.size === 0) {
        renderEmptyChart('Select host and group to visualize');
        updateSelectionStatus();
        return;
      }

      if (state.selectedInstances.size === 0 && state.selectedMetrics.size === 0) {
        renderEmptyChart('Select at least one instance or one metric to visualize');
        updateSelectionStatus();
        return;
      }

      const traces = [];
      let inaccessibleFiles = 0;

      for (const fileMeta of matchingFiles) {
        const selectedColumns = (fileMeta.columns || []).filter(c => {
          const instSelected = state.selectedInstances.size > 0;
          const metricSelected = state.selectedMetrics.size > 0;

          if (instSelected && metricSelected) {
            return state.selectedInstances.has(c.instance) && state.selectedMetrics.has(c.metric);
          }
          if (instSelected && !metricSelected) {
            return state.selectedInstances.has(c.instance);
          }
          if (!instSelected && metricSelected) {
            return state.selectedMetrics.has(c.metric);
          }
          return false;
        });

        if (selectedColumns.length === 0) continue;

        let text;
        try {
          text = await getCsvTextForMeta(fileMeta);
        } catch (_) {
          inaccessibleFiles++;
          continue;
        }

        const lines = text.split(/\\r?\\n/).filter(line => line.trim() !== '');
        if (lines.length < 2) continue;

        const headers = parseCsvLine(lines[0]);
        const idxMap = new Map();
        headers.forEach((h, idx) => idxMap.set(h, idx));

        const tsIndex = idxMap.get(fileMeta.timestamp_header);
        if (tsIndex === undefined) continue;

        const traceMap = new Map();

        selectedColumns.forEach(col => {
          const idx = idxMap.get(col.header);
          if (idx === undefined) return;

          const key = `${fileMeta.host}|${fileMeta.group}|${col.instance}|${col.metric}|${col.header}`;
          if (!traceMap.has(key)) {
            traceMap.set(key, {
              x: [],
              y: [],
              text: [],
              name: buildLegendName(fileMeta.host, fileMeta.group, col.instance, col.metric),
              mode: 'lines',
              type: 'scatter',
              hovertemplate: '%{text}<extra></extra>',
              meta: {
                host: fileMeta.host,
                group: fileMeta.group,
                instance: col.instance,
                metric: col.metric
              },
              _colIndices: []
            });
          }
          traceMap.get(key)._colIndices.push(idx);
        });

        for (let i = 1; i < lines.length; i++) {
          const row = parseCsvLine(lines[i]);
          const tsRaw = row[tsIndex];
          const dt = parseTimestamp(tsRaw);
          if (!dt) continue;

          traceMap.forEach(trace => {
            for (const colIdx of trace._colIndices) {
              const rawValue = row[colIdx];
              if (rawValue === undefined || rawValue === '') continue;

              const num = Number(rawValue);
              if (Number.isNaN(num)) continue;

              trace.x.push(dt);
              trace.y.push(num);
              trace.text.push(buildHoverText(trace.meta.instance, trace.meta.metric, rawValue, tsRaw));
            }
          });
        }

        traceMap.forEach(trace => {
          delete trace._colIndices;
          if (trace.x.length > 0) traces.push(trace);
        });
      }

      if (traces.length === 0) {
        const msg = state.csvFileMap.size === 0
          ? 'No chart data. Serve this folder with a local web server or upload the matching CSV files.'
          : 'No numeric data found for the current selection.';
        renderEmptyChart(msg);
        updateSelectionStatus(inaccessibleFiles ? `inaccessible files: ${inaccessibleFiles}` : '');
        return;
      }

      const title =
        `Hosts: ${state.selectedHosts.size} | ` +
        `Groups: ${state.selectedGroups.size} | ` +
        `Instances: ${state.selectedInstances.size} | ` +
        `Metrics: ${state.selectedMetrics.size}`;

      renderChart(traces, title);
      updateSelectionStatus(inaccessibleFiles ? `inaccessible files: ${inaccessibleFiles}` : '');
    }

    async function maybeVisualize() {
      refreshDropdownSummaries();
      await visualize();
    }

    els.metadataFile.addEventListener('change', async () => {
      const file = els.metadataFile.files[0];
      if (!file) return;

      try {
        const text = await readFileText(file);
        const metadata = JSON.parse(text);
        loadMetadataObject(metadata);
        setStatus(els.loadStatus, `Metadata loaded. Files: ${metadata.file_count || (metadata.files || []).length}`, 'ok');
      } catch (err) {
        setStatus(els.loadStatus, `Failed to load metadata: ${err.message || err}`, 'err');
      }
    });

    els.csvFiles.addEventListener('change', async () => {
      state.csvFileMap = new Map();
      Array.from(els.csvFiles.files || []).forEach(file => state.csvFileMap.set(file.name, file));
      await maybeVisualize();
    });

    ['hostSearch', 'groupSearch', 'instanceSearch', 'metricSearch'].forEach(id => {
      els[id].addEventListener('input', async () => {
        if (id === 'hostSearch') await renderHosts();
        if (id === 'groupSearch') await refreshGroups();
        if (id === 'instanceSearch') await refreshInstances();
        if (id === 'metricSearch') await refreshMetrics();
      });
    });

    document.querySelectorAll('.dropdown').forEach(drop => {
      const btn = drop.querySelector('.dropdown-btn');
      btn.addEventListener('click', (e) => {
        e.stopPropagation();
        document.querySelectorAll('.dropdown.open').forEach(d => {
          if (d !== drop) d.classList.remove('open');
        });
        drop.classList.toggle('open');
      });

      drop.querySelector('.dropdown-panel').addEventListener('click', (e) => {
        e.stopPropagation();
      });
    });

    document.addEventListener('click', () => {
      document.querySelectorAll('.dropdown.open').forEach(d => d.classList.remove('open'));
    });

    document.querySelectorAll('[data-action]').forEach(btn => {
      btn.addEventListener('click', async (e) => {
        e.stopPropagation();

        const target = btn.dataset.target;
        const action = btn.dataset.action;

        let allValues = [];
        let filteredValues = [];
        let setRef = null;
        let searchTerm = '';

        if (target === 'hosts') {
          allValues = state.metadata?.hosts || [];
          searchTerm = els.hostSearch.value;
          setRef = state.selectedHosts;
        } else if (target === 'groups') {
          allValues = getAvailableGroups();
          searchTerm = els.groupSearch.value;
          setRef = state.selectedGroups;
        } else if (target === 'instances') {
          allValues = getAvailableInstances();
          searchTerm = els.instanceSearch.value;
          setRef = state.selectedInstances;
        } else if (target === 'metrics') {
          allValues = getAvailableMetricsForGroupOrInstance();
          searchTerm = els.metricSearch.value;
          setRef = state.selectedMetrics;
        }

        if (!setRef) return;

        filteredValues = getFilteredValues(allValues, searchTerm);

        if (action === 'clear') {
          filteredValues.forEach(v => setRef.delete(v));
        } else if (action === 'all') {
          filteredValues.forEach(v => setRef.add(v));
        }

        if (target === 'hosts') {
          state.selectedGroups.clear();
          state.selectedInstances.clear();
          state.selectedMetrics.clear();
          await refreshGroups();
          await refreshInstances();
          await refreshMetrics();
          await renderHosts();
        } else if (target === 'groups') {
          state.selectedInstances.clear();
          state.selectedMetrics.clear();
          await refreshGroups();
          await refreshInstances();
          await refreshMetrics();
        } else if (target === 'instances') {
          await refreshInstances();
          await refreshMetrics();
        } else if (target === 'metrics') {
          await refreshMetrics();
        }

        refreshDropdownSummaries();
        await maybeVisualize();
      });
    });

    loadTheme();
    renderEmptyChart('Make selections to visualize');
    tryAutoLoadMetadata();
  </script>
</body>
</html>"""


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
    try:
        suggested_port = find_available_port()
    except Exception:
        suggested_port = 8000
    print("\n[VISUALIZER]")
    print(f"Metadata JSON   : {output_dir / 'esxtop-metadata.json'}")
    print(f"Visualizer HTML : {output_dir / VISUALIZER_FILENAME}")
    print("\n[HTTP SERVER HINTS]")
    print(f"Auto port hint  : cd \"{output_dir}\" && python3 -m http.server {suggested_port}")
    print(f"Custom port     : cd \"{output_dir}\" && python3 -m http.server <PORT>")
    print(f"Open browser    : http://localhost:{suggested_port}/{VISUALIZER_FILENAME}")


def process_csv_batch(batch_name: str, csv_files, batch_outdir: Path, args, metrics: Optional[RunMetrics] = None):
    raw_output_dir = batch_outdir
    tmp_root = batch_outdir / TEMP_ROOT_NAME
    metadata_path = tmp_root / METADATA_FILE
    generated_metadata_json = batch_outdir / "esxtop-metadata.json"

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

    print(f"\n[BATCH] {batch_name}")
    print(f"[INFO] Output dir     : {raw_output_dir}")
    print(f"[INFO] Temp dir       : {tmp_root}")
    print(f"[INFO] CSV files      : {len(csv_files)}")

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

    written = []
    if groups:
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
        visualizer_path = write_visualizer(batch_outdir)
    else:
        metadata_json_path = None
        visualizer_path = None

    if not args.keep_temp:
        shutil.rmtree(tmp_root, ignore_errors=True)

    print("[SUMMARY]")
    print(f"Processed files : {processed}")
    print(f"Skipped files   : {skipped}")
    print(f"Errored files   : {errors}")
    print(f"Output CSV files: {len(written)}")
    if metadata_json_path:
        print(f"Metadata JSON   : {metadata_json_path}")
    if visualizer_path:
        print(f"Visualizer HTML : {visualizer_path}")
        print("[OUTPUTS]")
        for path in written:
            print(path)

    return {
        "batch_name": batch_name,
        "processed": processed,
        "skipped": skipped,
        "errors": errors,
        "written": written,
        "metadata_json_path": metadata_json_path,
        "visualizer_path": visualizer_path,
        "outdir": batch_outdir,
    }

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
        help="Scan all nested subdirectories instead of only the root + immediate subdirectories"
    )
    parser.add_argument(
        "--no-merge",
        "--nm",
        dest="no_merge",
        action="store_true",
        help="Do not merge CSVs across folders; process each source folder independently"
    )
    header_mode = parser.add_mutually_exclusive_group()
    header_mode.add_argument(
        "--keep-full-header",
        action="store_true",
        default=True,
        help="Keep ORIGINAL timestamp and ESXTOP full column headers exactly as-is (default)"
    )
    header_mode.add_argument(
        "--normalize-headers",
        dest="keep_full_header",
        action="store_false",
        help="Normalize timestamp/header names to the legacy cleaned output format"
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
    print(f"[INFO] Recursive scan : {args.recursive}")
    print(f"[INFO] Scan scope     : {'root + all nested subdirectories' if args.recursive else 'root + immediate subdirectories'}")
    print(f"[INFO] CSV files      : {len(csv_files)}")
    print(f"[INFO] Output dir     : {outdir}")
    print(f"[INFO] Group filter   : {args.group or 'ALL'}")
    print(f"[INFO] Full headers   : {args.keep_full_header}")
    print(f"[INFO] Normalize hdrs : {not args.keep_full_header}")
    print(f"[INFO] No merge       : {args.no_merge}")
    print(f"[INFO] Debug          : {args.debug}")

    if args.no_merge:
        batches = group_csv_files_for_no_merge(root, csv_files)
    else:
        batches = {"combined": csv_files}

    batch_results = []
    for batch_name, batch_files in batches.items():
        batch_outdir = outdir / batch_name if args.no_merge else outdir
        batch_results.append(
            process_csv_batch(
                batch_name=batch_name,
                csv_files=batch_files,
                batch_outdir=batch_outdir,
                args=args,
                metrics=metrics,
            )
        )

    total_processed = sum(result["processed"] for result in batch_results)
    total_skipped = sum(result["skipped"] for result in batch_results)
    total_errors = sum(result["errors"] for result in batch_results)
    total_written = sum(len(result["written"]) for result in batch_results)

    print("\n[RUN SUMMARY]")
    print(f"Batches         : {len(batch_results)}")
    print(f"Processed files : {total_processed}")
    print(f"Skipped files   : {total_skipped}")
    print(f"Errored files   : {total_errors}")
    print(f"Output CSV files: {total_written}")

    for result in batch_results:
        if result["visualizer_path"]:
            print_server_hints(result["outdir"])

    if metrics:
        print_run_metrics(metrics.finalize())


if __name__ == "__main__":
    main()
