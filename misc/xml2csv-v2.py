#!/usr/bin/env python3

import argparse
import csv
from pathlib import Path
import xml.etree.ElementTree as ET
from collections import defaultdict

# remove namespace from tag
def strip_ns(tag):
    if "}" in tag:
        return tag.split("}", 1)[1]
    return tag


def flatten_xml(elem, prefix, out, counter):
    tag = strip_ns(elem.tag)

    base = f"{prefix}/{tag}" if prefix else tag

    key = (prefix, tag)
    idx = counter[key]
    counter[key] += 1

    path = f"{base}[{idx}]" if idx > 0 else base

    # attributes
    for k, v in elem.attrib.items():
        out[f"{path}/@{k}"] = v

    # text
    text = (elem.text or "").strip()
    if text:
        out[path] = text

    child_counter = defaultdict(int)

    for child in elem:
        flatten_xml(child, path, out, child_counter)


def parse_xml(file):
    tree = ET.parse(file)
    root = tree.getroot()

    data = {}
    counter = defaultdict(int)

    flatten_xml(root, "", data, counter)

    return data


def write_csv(rows, keys, outfile):
    outfile.parent.mkdir(parents=True, exist_ok=True)

    with open(outfile, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=["file", "ext"] + list(keys),
            extrasaction="ignore"
        )

        writer.writeheader()

        for r in rows:
            writer.writerow(r)


def write_single_file_csv(file, kv, outdir):

    # ensure directory exists
    outdir.mkdir(parents=True, exist_ok=True)

    outfile = outdir / f"{file.stem}.csv"

    with open(outfile, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)

        writer.writerow(["key", "value"])

        for k, v in sorted(kv.items()):
            writer.writerow([k, v])

def main():

    parser = argparse.ArgumentParser()

    parser.add_argument("--root", default=".")
    parser.add_argument("--ext", action="append")
    parser.add_argument("--outdir", default="csv_output")
    parser.add_argument("--recursive", action="store_true")

    args = parser.parse_args()

    root = Path(args.root)
    outdir = Path(args.outdir)

    extensions = args.ext if args.ext else ["xml", "vpf"]
    extensions = [e.lower().replace(".", "") for e in extensions]

    pattern = "**/*" if args.recursive else "*"

    files = []

    for f in root.glob(pattern):
        if f.is_file():
            ext = f.suffix.lower().replace(".", "")
            if ext in extensions:
                files.append(f)

    rows_all = []
    keys_all = set()

    rows_by_ext = defaultdict(list)
    keys_by_ext = defaultdict(set)

    for file in files:

        try:
            kv = parse_xml(file)
        except Exception as e:
            print(f"Skipping {file}: {e}")
            continue

        ext = file.suffix.lower().replace(".", "")

        row = {"file": file.name, "ext": ext}
        row.update(kv)

        rows_all.append(row)

        rows_by_ext[ext].append(row)

        for k in kv:
            keys_all.add(k)
            keys_by_ext[ext].add(k)

        # CSV per file
        write_single_file_csv(file, kv, outdir / "per_file")

    # consolidated CSV
    write_csv(
        rows_all,
        sorted(keys_all),
        outdir / "consolidated_all.csv"
    )

    # per extension CSV
    for ext in rows_by_ext:
        write_csv(
            rows_by_ext[ext],
            sorted(keys_by_ext[ext]),
            outdir / f"per_extension_{ext}.csv"
        )


if __name__ == "__main__":
    main()