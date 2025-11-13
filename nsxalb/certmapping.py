#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
avi_vs_cert_report_exact.py
Create CSV of Virtual Service → Certificate (exact match only).

- Input cert list may be comma-separated, newline-separated, and quoted with ' or ".
- Matching is exact: a Virtual Service is included only if one of its
  ssl_key_and_certificate_refs ends with either:
      name=<cert>     OR     name=<urlencoded(cert)>

Usage:
  python avi_vs_cert_report_exact.py --config avi_config --input certs.txt --output report.csv
"""

import argparse
import csv
import json
import sys
from pathlib import Path
from typing import Dict, List, Tuple, Any, Set
from urllib.parse import quote

def parse_args():
    p = argparse.ArgumentParser(description="Generate VS-to-certificate report (exact match only).")
    p.add_argument("--config", required=True, help="Path to avi_config JSON file.")
    p.add_argument("--input", required=True, help="Path to certificate list (comma/newline separated, names quoted ok).")
    p.add_argument("--output", default="report.csv", help="Output CSV file path.")
    p.add_argument("--ignore-case", action="store_true", help="Enable case-insensitive exact match.")
    return p.parse_args()

def load_json(path: Path) -> Dict[str, Any]:
    try:
        with path.open("r", encoding="utf-8") as f:
            return json.load(f)
    except Exception as e:
        print(f"ERROR: Could not read JSON file {path}: {e}", file=sys.stderr)
        sys.exit(1)

def load_and_clean_certs(path: Path) -> List[str]:
    try:
        raw = path.read_text(encoding="utf-8")
    except Exception as e:
        print(f"ERROR: Could not read input file {path}: {e}", file=sys.stderr)
        sys.exit(1)

    cleaned: List[str] = []
    # Replace commas (and optional whitespace) with newlines, then split
    parts = raw.replace("\r", "").replace("\t", " ").split("\n")
    tokens: List[str] = []
    for line in parts:
        for token in line.split(","):
            t = token.strip()
            if not t:
                continue
            if (t.startswith("'") and t.endswith("'")) or (t.startswith('"') and t.endswith('"')):
                t = t[1:-1].strip()
            if t:
                tokens.append(t)

    seen: Set[str] = set()
    for t in tokens:
        if t not in seen:
            seen.add(t)
            cleaned.append(t)
    return cleaned

def iter_vs_refs(doc: Dict[str, Any]):
    vs_list = doc.get("VirtualService") or []
    for vs in vs_list:
        if not isinstance(vs, dict):
            continue
        name = vs.get("name")
        refs = vs.get("ssl_key_and_certificate_refs") or []
        if isinstance(refs, str):
            refs = [refs]
        if name:
            yield name, [str(r) for r in refs]

def matches_exact(ref: str, cert: str, ignore_case: bool) -> bool:
    """Return True if ref ends with name=<cert> or name=<urlencoded(cert)> (exact match)."""
    target1 = f"name={cert}"
    target2 = f"name={quote(cert, safe='')}"
    if ignore_case:
        ref = ref.lower()
        target1 = target1.lower()
        target2 = target2.lower()
    return ref.endswith(target1) or ref.endswith(target2)

def generate_report(doc: Dict[str, Any], certs: List[str], ignore_case: bool) -> List[Tuple[str, str]]:
    rows: List[Tuple[str, str]] = []
    for vs_name, refs in iter_vs_refs(doc):
        for cert in certs:
            if any(matches_exact(ref, cert, ignore_case) for ref in refs):
                rows.append((vs_name, cert))
    # De-duplicate (VS, Cert) pairs
    seen: Set[Tuple[str, str]] = set()
    dedup = []
    for r in rows:
        if r not in seen:
            seen.add(r)
            dedup.append(r)
    return dedup

def write_csv(path: Path, rows: List[Tuple[str, str]]):
    try:
        with path.open("w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(["Virtual Service", "Certificate"])
            writer.writerows(rows)
    except Exception as e:
        print(f"ERROR: Could not write to {path}: {e}", file=sys.stderr)
        sys.exit(1)

def main():
    args = parse_args()
    config_path = Path(args.config)
    input_path = Path(args.input)
    output_path = Path(args.output)

    if not config_path.exists():
        sys.exit(f"ERROR: Config file not found: {config_path}")
    if not input_path.exists():
        sys.exit(f"ERROR: Input file not found: {input_path}")

    certs = load_and_clean_certs(input_path)
    if not certs:
        print("WARNING: No valid cert names found in input file.", file=sys.stderr)

    doc = load_json(config_path)
    rows = generate_report(doc, certs, args.ignore_case)
    write_csv(output_path, rows)

    print(f"✅ Wrote {output_path} with {len(rows)} matching rows.")

if __name__ == "__main__":
    main()

