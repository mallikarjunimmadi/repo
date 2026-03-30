#!/usr/bin/env python3
"""
json_to_csv_report.py

Generic JSON -> CSV report generator.

Outputs supported:
1. Combined summary CSV
2. Combined detailed CSV
3. Separate detailed CSV per section (with --separate-csv)

Features:
- --list-sections
- --sections supports:
    * space-separated values
    * comma-separated values
    * mixed usage
- section names with spaces are supported if quoted in shell
- output filenames include timestamp by default
- naming behavior for combined files:
    * no sections       -> <prefix>_all_<kind>_<timestamp>.csv
    * one section       -> <prefix>_<section>_<kind>_<timestamp>.csv
    * many sections     -> <prefix>_filters_<kind>_<timestamp>.csv
- naming behavior for separate files:
    * <prefix>_<section>_<timestamp>.csv
- --no-timestamp
- --separate-csv
- --explode-all
    * recursively explodes all list fields into rows
    * duplicates non-list fields across exploded rows

Examples:
    python3 json_to_csv_report.py --input input.json
    python3 json_to_csv_report.py --input input.json --list-sections
    python3 json_to_csv_report.py --input input.json --sections Alert
    python3 json_to_csv_report.py --input input.json --sections Alert,ActionGroupConfig
    python3 json_to_csv_report.py --input input.json --sections "Virtual Service"
    python3 json_to_csv_report.py --input input.json --sections Alert --explode-all
    python3 json_to_csv_report.py --input input.json --sections Alert --explode-all --separate-csv
"""

from __future__ import annotations

import argparse
import csv
import itertools
import json
import os
import re
import sys
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple


def eprint(msg: str) -> None:
    print(msg, file=sys.stderr)


def safe_str(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, (dict, list)):
        return json.dumps(value, ensure_ascii=False, sort_keys=True)
    return str(value)


def load_json(path: str) -> Any:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def get_scan_timestamp() -> str:
    return datetime.now().isoformat(timespec="seconds")


def get_file_timestamp() -> str:
    return datetime.now().strftime("%Y%m%d_%H%M%S")


def sanitize_for_filename(value: str) -> str:
    value = value.strip()
    value = re.sub(r"[^\w.-]+", "_", value)
    value = re.sub(r"_+", "_", value)
    value = value.strip("._")
    return value or "section"


def normalize_sections(sections: Optional[List[str]]) -> Optional[List[str]]:
    """
    Accept:
      --sections A B
      --sections A,B
      --sections "A, B"
      --sections "Virtual Service" Alert
      --sections "Virtual Service,Alert"
    """
    if not sections:
        return None

    normalized: List[str] = []

    for item in sections:
        if item is None:
            continue
        item = item.strip()
        if not item:
            continue

        parts = item.split(",")
        for part in parts:
            part = part.strip()
            if part:
                normalized.append(part)

    seen = set()
    result: List[str] = []
    for section in normalized:
        if section not in seen:
            seen.add(section)
            result.append(section)

    return result or None


def derive_prefix(input_path: str, custom_prefix: Optional[str]) -> str:
    if custom_prefix:
        return custom_prefix
    return os.path.splitext(os.path.basename(input_path))[0]


def get_available_sections(data: Any) -> List[str]:
    if isinstance(data, dict):
        return sorted(data.keys())
    return ["__root__"]


def validate_requested_sections(data: Any, selected_sections: Optional[List[str]]) -> List[str]:
    if not selected_sections:
        return []

    if not isinstance(data, dict):
        return selected_sections[:]

    available = set(data.keys())
    return [s for s in selected_sections if s not in available]


def filter_sections(data: Any, selected_sections: Optional[List[str]]) -> Any:
    if not selected_sections:
        return data

    if not isinstance(data, dict):
        raise ValueError(
            "Section filtering is supported only when the JSON root is an object/dictionary."
        )

    requested = set(selected_sections)
    return {k: v for k, v in data.items() if k in requested}


def get_combined_label(selected_sections: Optional[List[str]]) -> str:
    if not selected_sections:
        return "all"
    if len(selected_sections) == 1:
        return sanitize_for_filename(selected_sections[0])
    return "filters"


def build_output_paths(
    outdir: str,
    prefix: str,
    selected_sections: Optional[List[str]],
    no_timestamp: bool,
) -> Tuple[str, str]:
    label = get_combined_label(selected_sections)
    ts = "" if no_timestamp else f"_{get_file_timestamp()}"

    summary_name = f"{prefix}_{label}_summary{ts}.csv"
    detailed_name = f"{prefix}_{label}_detailed{ts}.csv"

    return (
        os.path.join(outdir, summary_name),
        os.path.join(outdir, detailed_name),
    )


def build_section_csv_path(
    outdir: str,
    prefix: str,
    section: str,
    no_timestamp: bool,
) -> str:
    ts = "" if no_timestamp else f"_{get_file_timestamp()}"
    section_clean = sanitize_for_filename(section)
    return os.path.join(outdir, f"{prefix}_{section_clean}{ts}.csv")


def flatten_simple_dict(obj: Dict[str, Any], parent_key: str = "", sep: str = ".") -> Dict[str, Any]:
    """
    Flatten only dict paths.
    Preserve lists as-is; caller decides whether to stringify or explode them.
    """
    items: Dict[str, Any] = {}

    for k, v in obj.items():
        new_key = f"{parent_key}{sep}{k}" if parent_key else str(k)

        if isinstance(v, dict):
            items.update(flatten_simple_dict(v, new_key, sep=sep))
        else:
            items[new_key] = v

    return items


def explode_record(record: Any, parent_key: str = "") -> List[Dict[str, Any]]:
    """
    Recursively explode all lists into rows.
    Dicts become dot-notation fields.
    Scalars remain as scalar fields.

    Behavior:
    - dict => merge children
    - scalar => one field
    - list of scalars/dicts/lists => each item contributes rows
    - multiple lists => cartesian product
    """
    if isinstance(record, dict):
        partial_rows: List[Dict[str, Any]] = [{}]

        for key, value in record.items():
            field_name = f"{parent_key}.{key}" if parent_key else key
            child_rows = explode_record(value, field_name)

            new_rows: List[Dict[str, Any]] = []
            for left in partial_rows:
                for right in child_rows:
                    merged = dict(left)
                    merged.update(right)
                    new_rows.append(merged)

            partial_rows = new_rows

        return partial_rows

    if isinstance(record, list):
        if not record:
            # Empty list contributes a blank value to preserve row
            if parent_key:
                return [{parent_key: ""}]
            return [{"value": ""}]

        list_rows: List[Dict[str, Any]] = []
        for item in record:
            item_rows = explode_record(item, parent_key)
            list_rows.extend(item_rows)

        return list_rows

    if parent_key:
        return [{parent_key: record}]
    return [{"value": record}]


def build_summary_rows(data: Any, input_file: str) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    scan_ts = get_scan_timestamp()
    input_base = os.path.basename(input_file)

    if isinstance(data, dict):
        for section, value in data.items():
            if isinstance(value, list):
                row_count = len(value)
                value_type = "list"
            elif isinstance(value, dict):
                row_count = len(value)
                value_type = "dict"
            else:
                row_count = 1 if value is not None else 0
                value_type = type(value).__name__

            rows.append(
                {
                    "input_file": input_base,
                    "section": section,
                    "value_type": value_type,
                    "record_count": row_count,
                    "scan_timestamp": scan_ts,
                }
            )
    elif isinstance(data, list):
        rows.append(
            {
                "input_file": input_base,
                "section": "__root__",
                "value_type": "list",
                "record_count": len(data),
                "scan_timestamp": scan_ts,
            }
        )
    else:
        rows.append(
            {
                "input_file": input_base,
                "section": "__root__",
                "value_type": type(data).__name__,
                "record_count": 1 if data is not None else 0,
                "scan_timestamp": scan_ts,
            }
        )

    return rows


def build_non_exploded_rows(data: Any, input_file: str) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    scan_ts = get_scan_timestamp()
    input_base = os.path.basename(input_file)

    if isinstance(data, dict):
        for section, value in data.items():
            if isinstance(value, list):
                if not value:
                    rows.append(
                        {
                            "input_file": input_base,
                            "section": section,
                            "record_index": "",
                            "record_type": "empty_list",
                            "scan_timestamp": scan_ts,
                        }
                    )
                    continue

                for idx, item in enumerate(value, start=1):
                    base = {
                        "input_file": input_base,
                        "section": section,
                        "record_index": idx,
                        "record_type": type(item).__name__,
                        "scan_timestamp": scan_ts,
                    }

                    if isinstance(item, dict):
                        flat = flatten_simple_dict(item)
                        row: Dict[str, Any] = {}
                        row.update(base)
                        for k, v in flat.items():
                            row[k] = safe_str(v)
                        rows.append(row)
                    else:
                        row = dict(base)
                        row["value"] = safe_str(item)
                        rows.append(row)

            elif isinstance(value, dict):
                base = {
                    "input_file": input_base,
                    "section": section,
                    "record_index": 1,
                    "record_type": "dict",
                    "scan_timestamp": scan_ts,
                }
                flat = flatten_simple_dict(value)
                row: Dict[str, Any] = {}
                row.update(base)
                for k, v in flat.items():
                    row[k] = safe_str(v)
                rows.append(row)

            else:
                rows.append(
                    {
                        "input_file": input_base,
                        "section": section,
                        "record_index": 1,
                        "record_type": type(value).__name__,
                        "value": safe_str(value),
                        "scan_timestamp": scan_ts,
                    }
                )

    elif isinstance(data, list):
        if not data:
            rows.append(
                {
                    "input_file": input_base,
                    "section": "__root__",
                    "record_index": "",
                    "record_type": "empty_list",
                    "scan_timestamp": scan_ts,
                }
            )
        else:
            for idx, item in enumerate(data, start=1):
                base = {
                    "input_file": input_base,
                    "section": "__root__",
                    "record_index": idx,
                    "record_type": type(item).__name__,
                    "scan_timestamp": scan_ts,
                }

                if isinstance(item, dict):
                    flat = flatten_simple_dict(item)
                    row: Dict[str, Any] = {}
                    row.update(base)
                    for k, v in flat.items():
                        row[k] = safe_str(v)
                    rows.append(row)
                else:
                    row = dict(base)
                    row["value"] = safe_str(item)
                    rows.append(row)

    else:
        rows.append(
            {
                "input_file": input_base,
                "section": "__root__",
                "record_index": 1,
                "record_type": type(data).__name__,
                "value": safe_str(data),
                "scan_timestamp": scan_ts,
            }
        )

    return rows


def build_exploded_rows(data: Any, input_file: str) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    scan_ts = get_scan_timestamp()
    input_base = os.path.basename(input_file)

    if isinstance(data, dict):
        for section, value in data.items():
            if isinstance(value, list):
                if not value:
                    rows.append(
                        {
                            "input_file": input_base,
                            "section": section,
                            "record_index": "",
                            "record_type": "empty_list",
                            "scan_timestamp": scan_ts,
                        }
                    )
                    continue

                for idx, item in enumerate(value, start=1):
                    base = {
                        "input_file": input_base,
                        "section": section,
                        "record_index": idx,
                        "record_type": type(item).__name__,
                        "scan_timestamp": scan_ts,
                    }

                    exploded = explode_record(item)
                    if not exploded:
                        rows.append(dict(base))
                        continue

                    for part in exploded:
                        row = dict(base)
                        for k, v in part.items():
                            row[k] = safe_str(v)
                        rows.append(row)

            elif isinstance(value, dict):
                base = {
                    "input_file": input_base,
                    "section": section,
                    "record_index": 1,
                    "record_type": "dict",
                    "scan_timestamp": scan_ts,
                }
                exploded = explode_record(value)
                if not exploded:
                    rows.append(dict(base))
                else:
                    for part in exploded:
                        row = dict(base)
                        for k, v in part.items():
                            row[k] = safe_str(v)
                        rows.append(row)

            else:
                rows.append(
                    {
                        "input_file": input_base,
                        "section": section,
                        "record_index": 1,
                        "record_type": type(value).__name__,
                        "value": safe_str(value),
                        "scan_timestamp": scan_ts,
                    }
                )

    elif isinstance(data, list):
        if not data:
            rows.append(
                {
                    "input_file": input_base,
                    "section": "__root__",
                    "record_index": "",
                    "record_type": "empty_list",
                    "scan_timestamp": scan_ts,
                }
            )
        else:
            for idx, item in enumerate(data, start=1):
                base = {
                    "input_file": input_base,
                    "section": "__root__",
                    "record_index": idx,
                    "record_type": type(item).__name__,
                    "scan_timestamp": scan_ts,
                }

                exploded = explode_record(item)
                if not exploded:
                    rows.append(dict(base))
                else:
                    for part in exploded:
                        row = dict(base)
                        for k, v in part.items():
                            row[k] = safe_str(v)
                        rows.append(row)

    else:
        rows.append(
            {
                "input_file": input_base,
                "section": "__root__",
                "record_index": 1,
                "record_type": type(data).__name__,
                "value": safe_str(data),
                "scan_timestamp": scan_ts,
            }
        )

    return rows


def collect_all_columns(rows: List[Dict[str, Any]]) -> List[str]:
    if not rows:
        return ["message"]

    seen = set()
    columns: List[str] = []

    preferred_first = [
        "input_file",
        "section",
        "record_index",
        "record_type",
        "scan_timestamp",
        "value",
    ]

    for col in preferred_first:
        if any(col in row for row in rows):
            columns.append(col)
            seen.add(col)

    remaining = sorted({k for row in rows for k in row.keys()} - seen)
    columns.extend(remaining)
    return columns


def write_csv(path: str, rows: List[Dict[str, Any]]) -> None:
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)

    if not rows:
        with open(path, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(["message"])
            writer.writerow(["no data"])
        return

    fieldnames = collect_all_columns(rows)

    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=fieldnames,
            extrasaction="ignore",
            quoting=csv.QUOTE_MINIMAL,
        )
        writer.writeheader()
        for row in rows:
            clean_row = {k: safe_str(v) for k, v in row.items()}
            writer.writerow(clean_row)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Generate summary and detailed CSV reports from a JSON file."
    )
    parser.add_argument(
        "--input",
        required=True,
        help="Path to input JSON file",
    )
    parser.add_argument(
        "--outdir",
        default=".",
        help="Output directory for generated CSV files (default: current directory)",
    )
    parser.add_argument(
        "--prefix",
        default=None,
        help="Output file prefix (default: input filename without extension)",
    )
    parser.add_argument(
        "--list-sections",
        action="store_true",
        help="List all available top-level sections and exit",
    )
    parser.add_argument(
        "--sections",
        nargs="*",
        help="Sections to include (supports space-separated, comma-separated, or mixed values)",
    )
    parser.add_argument(
        "--no-timestamp",
        action="store_true",
        help="Do not append timestamp to output filenames",
    )
    parser.add_argument(
        "--separate-csv",
        action="store_true",
        help="Generate one detailed CSV per section instead of a combined detailed CSV",
    )
    parser.add_argument(
        "--explode-all",
        action="store_true",
        help="Recursively explode all list fields into multiple rows",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    args.sections = normalize_sections(args.sections)

    input_path = args.input
    outdir = args.outdir
    prefix = derive_prefix(input_path, args.prefix)

    if not os.path.isfile(input_path):
        eprint(f"[ERROR] Input file not found: {input_path}")
        return 1

    try:
        data = load_json(input_path)
    except json.JSONDecodeError as exc:
        eprint(f"[ERROR] Failed to parse JSON: {exc}")
        return 2
    except Exception as exc:
        eprint(f"[ERROR] Failed to read input file: {exc}")
        return 3

    available_sections = get_available_sections(data)

    if args.list_sections:
        print("[INFO] Available sections:")
        for sec in available_sections:
            print(sec)
        return 0

    invalid_sections = validate_requested_sections(data, args.sections)
    if invalid_sections:
        eprint("[ERROR] Invalid section name(s):")
        for sec in invalid_sections:
            eprint(f"  - {sec}")

        eprint("\n[INFO] Available sections:")
        for sec in available_sections:
            eprint(f"  - {sec}")

        eprint("\n[INFO] Notes:")
        eprint('  - If a section name contains spaces, quote it, e.g. --sections "Virtual Service"')
        eprint('  - You can also use comma-separated values, e.g. --sections "Virtual Service,Alert"')
        return 4

    try:
        filtered_data = filter_sections(data, args.sections)
    except ValueError as exc:
        eprint(f"[ERROR] {exc}")
        return 5

    summary_rows = build_summary_rows(filtered_data, input_path)

    if args.explode_all:
        detailed_rows = build_exploded_rows(filtered_data, input_path)
    else:
        detailed_rows = build_non_exploded_rows(filtered_data, input_path)

    try:
        if args.separate_csv:
            if not isinstance(filtered_data, dict):
                eprint("[ERROR] --separate-csv requires top-level JSON object/dictionary.")
                return 6

            print("[INFO] Generating separate CSV per section")
            if args.explode_all:
                print("[INFO] Explode mode: enabled")
            else:
                print("[INFO] Explode mode: disabled")

            total_files = 0
            total_rows = 0

            for section, value in filtered_data.items():
                section_data = {section: value}

                if args.explode_all:
                    section_rows = build_exploded_rows(section_data, input_path)
                else:
                    section_rows = build_non_exploded_rows(section_data, input_path)

                if not section_rows:
                    continue

                section_csv = build_section_csv_path(
                    outdir=outdir,
                    prefix=prefix,
                    section=section,
                    no_timestamp=args.no_timestamp,
                )

                write_csv(section_csv, section_rows)
                print(f"[OK] {section} -> {section_csv}")
                print(f"[INFO] Rows written for {section}: {len(section_rows)}")

                total_files += 1
                total_rows += len(section_rows)

            print(f"[INFO] Total section CSVs generated: {total_files}")
            print(f"[INFO] Total rows written: {total_rows}")

        else:
            summary_csv, detailed_csv = build_output_paths(
                outdir=outdir,
                prefix=prefix,
                selected_sections=args.sections,
                no_timestamp=args.no_timestamp,
            )

            write_csv(summary_csv, summary_rows)
            write_csv(detailed_csv, detailed_rows)

            print(f"[OK] Summary CSV : {summary_csv}")
            print(f"[OK] Detailed CSV: {detailed_csv}")
            print(f"[INFO] Summary rows : {len(summary_rows)}")
            print(f"[INFO] Detailed rows: {len(detailed_rows)}")
            print(f"[INFO] Explode mode : {'enabled' if args.explode_all else 'disabled'}")

        if args.sections:
            print(f"[INFO] Filtered sections: {', '.join(args.sections)}")
        else:
            print("[INFO] Filtered sections: all")

    except Exception as exc:
        eprint(f"[ERROR] Failed to write CSV output: {exc}")
        return 7

    return 0


if __name__ == "__main__":
    sys.exit(main())
