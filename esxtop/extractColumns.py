#!/usr/bin/env python3
"""
Filter CSV columns:
- Always includes the first column
- Keeps columns whose headers contain the filter string(s) (case-insensitive)
- Preserves original column order
- Writes to <basename>_<timestamp>.csv
- Also saves ALL column headers to <basename>_headers.txt

Usage examples:
    python filter_columns.py --file metrics.csv --filter latency delay
    python filter_columns.py --file metrics.csv --filter latency --delimiter ';'
    python filter_columns.py               # prompts for file and filters
"""

import csv
import sys
import os
import argparse
import datetime

def main():
    parser = argparse.ArgumentParser(
        description="Filter CSV columns by header names containing search strings."
    )
    parser.add_argument("--file", "-f", help="Input CSV file")
    parser.add_argument("--filter", "-F", nargs="+",
                        help="One or more search strings for matching column headers")
    parser.add_argument("--delimiter", "-d", default=",",
                        help="CSV delimiter (default: ','). Example: ';' or $'\\t' for tab")

    args = parser.parse_args()

    # Prompt for file if not provided
    infile = args.file
    if not infile:
        infile = input("Enter input CSV filename: ").strip()

    if not os.path.isfile(infile):
        print(f"Error: File not found: {infile}", file=sys.stderr)
        sys.exit(2)

    # Prompt for filters if not provided
    if args.filter:
        search_terms = [s.lower() for s in args.filter]
    else:
        user_input = input("Enter search strings (comma-separated): ").strip()
        if not user_input:
            print("No search strings provided, exiting.")
            sys.exit(3)
        search_terms = [s.strip().lower() for s in user_input.split(",") if s.strip()]

    base, _ = os.path.splitext(os.path.basename(infile))
    ts = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
    outfile = f"{base}_{ts}.csv"
    headerfile = f"{base}_headers.txt"

    with open(infile, newline="", encoding="utf-8") as fin:
        reader = csv.reader(fin, delimiter=args.delimiter)
        headers = next(reader)

        # --- Save all headers to a text file ---
        with open(headerfile, "w", encoding="utf-8") as hf:
            for h in headers:
                hf.write(h + "\n")

        # --- Select columns (always first + matches) ---
        selected_idx = []
        for i, h in enumerate(headers):
            if i == 0 or any(term in h.lower() for term in search_terms):
                selected_idx.append(i)

        # --- Write filtered CSV ---
        with open(outfile, "w", newline="", encoding="utf-8") as fout:
            writer = csv.writer(fout, delimiter=args.delimiter)
            writer.writerow([headers[i] for i in selected_idx])
            for row in reader:
                writer.writerow([row[i] for i in selected_idx])

    print(f"Wrote filtered CSV: {outfile}")
    print(f"Wrote all headers : {headerfile}")

if __name__ == "__main__":
    main()
