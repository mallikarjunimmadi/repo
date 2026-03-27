# ESXTOP Offline Bundle v0.0.6.1

`esxtop-offline_v0.0.6.1.py` is an all-in-one offline workflow for ESXTOP CSV processing.

A single run can:

- scan ESXTOP CSV files from a root directory
- split and merge them into **one output CSV per host/group**
- keep column growth safe across multiple input files
- sort output rows by timestamp
- generate a metadata file for the viewer
- generate the HTML visualizer in the output folder
- print ready-to-use `python3 -m http.server` hints

## What gets created

By default, the script writes into `./output`.

Expected structure:

```text
output/
├── raw/
│   ├── <host>-<group>.csv
│   ├── <host>-<group>.csv
│   └── ...
├── esxtop-metadata.json
├── esxtop-visualizer_v0.0.8.html
└── tmp/              # only during processing, unless --keep-temp is used
```

If `--keep-temp` is **not** used, the temp folder is removed at the end.

## Main behavior

### Input discovery

- default root is the current directory: `--root .`
- default scan is **non-recursive**
- use `--recursive` to scan subdirectories

### Output behavior

- default output directory is `output`
- final merged group files go to `output/raw`
- metadata JSON goes to `output/esxtop-metadata.json`
- viewer HTML goes to `output/esxtop-visualizer_v0.0.8.html`

### Header behavior

Default behavior writes cleaned headers.

Use `--keep-full-header` when you want to preserve the original ESXTOP-style timestamp/header names exactly as they appeared in the source data.

### Resource metrics

Metrics are shown only when `--debug` is used.

### Temp processing model

The script uses temp-file merge + external sort, so it is much safer for large input sets than an in-memory merge.

## Requirements

### Required

- Python 3.x

### Optional but recommended

- `psutil`

Install:

```bash
python3 -m pip install psutil
```

This improves the debug metrics output.

## Basic syntax

```bash
python3 esxtop-offline_v0.0.6.1.py [OPTIONS]
```

## Command reference

### `--root <PATH>`
Root directory to scan for source CSV files.

Default:

```bash
--root .
```

Example:

```bash
python3 esxtop-offline_v0.0.6.1.py --root /data/esxtop
```

### `--outdir <PATH>`
Output directory root.

Default:

```bash
--outdir output
```

Example:

```bash
python3 esxtop-offline_v0.0.6.1.py --outdir /tmp/esxtop_output
```

### `--group "<GROUP NAME>"`
Process only one ESXTOP group.

Examples:

```bash
python3 esxtop-offline_v0.0.6.1.py --group "Physical Cpu"
python3 esxtop-offline_v0.0.6.1.py --group "Network Port"
python3 esxtop-offline_v0.0.6.1.py --group "Vcpu"
```

### `--delimiter <CHAR>`
CSV delimiter for input and output.

Default:

```bash
--delimiter ,
```

Example:

```bash
python3 esxtop-offline_v0.0.6.1.py --delimiter ","
```

### `--recursive`
Scan subdirectories recursively.

Example:

```bash
python3 esxtop-offline_v0.0.6.1.py --recursive
```

### `--keep-full-header`
Keep the original timestamp/header names exactly as-is.

Use this when downstream tools depend on the original ESXTOP column format.

Example:

```bash
python3 esxtop-offline_v0.0.6.1.py --keep-full-header
```

### `--keep-temp`
Keep temporary chunk/sorted files after completion.

Useful for troubleshooting or validation.

Example:

```bash
python3 esxtop-offline_v0.0.6.1.py --keep-temp
```

### `--debug`
Enable runtime metrics and debug statistics.

Example:

```bash
python3 esxtop-offline_v0.0.6.1.py --debug
```

## Default run

This is the simplest run:

```bash
python3 esxtop-offline_v0.0.6.1.py
```

What it does:

- scans `.` for `*.csv`
- does **not** recurse into subdirectories
- writes output into `./output`
- creates group CSVs in `./output/raw`
- creates `./output/esxtop-metadata.json`
- creates `./output/esxtop-visualizer_v0.0.8.html`
- prints web server hints

## Common command combinations

### 1. Current directory, non-recursive, default output

```bash
python3 esxtop-offline_v0.0.6.1.py
```

Best when all source CSV files are in the current folder.

### 2. Recursive scan from current directory

```bash
python3 esxtop-offline_v0.0.6.1.py --recursive
```

Best when source CSV files are spread across subfolders.

### 3. Scan another folder

```bash
python3 esxtop-offline_v0.0.6.1.py --root /path/to/esxtop
```

Best when the source data is elsewhere.

### 4. Scan another folder recursively

```bash
python3 esxtop-offline_v0.0.6.1.py --root /path/to/esxtop --recursive
```

Best for nested input directories.

### 5. Write to a different output folder

```bash
python3 esxtop-offline_v0.0.6.1.py --outdir /path/to/output
```

### 6. Restrict to a single group

```bash
python3 esxtop-offline_v0.0.6.1.py --group "Physical Cpu"
```

Best when you only want one group’s merged CSVs and metadata/viewer built from that filtered output set.

### 7. Restrict to a single group and recurse

```bash
python3 esxtop-offline_v0.0.6.1.py --group "Network Port" --recursive
```

### 8. Preserve original headers

```bash
python3 esxtop-offline_v0.0.6.1.py --keep-full-header
```

Best when downstream tools need the original timestamp/header names unchanged.

### 9. Preserve original headers and recurse

```bash
python3 esxtop-offline_v0.0.6.1.py --keep-full-header --recursive
```

### 10. Preserve original headers for a single group

```bash
python3 esxtop-offline_v0.0.6.1.py --group "Vcpu" --keep-full-header
```

### 11. Keep temp files

```bash
python3 esxtop-offline_v0.0.6.1.py --keep-temp
```

Useful when you want to inspect chunk/sorted intermediates.

### 12. Keep temp files and recurse

```bash
python3 esxtop-offline_v0.0.6.1.py --recursive --keep-temp
```

### 13. Enable debug metrics

```bash
python3 esxtop-offline_v0.0.6.1.py --debug
```

Useful for runtime/memory diagnostics.

### 14. Debug + recursive

```bash
python3 esxtop-offline_v0.0.6.1.py --recursive --debug
```

### 15. Debug + keep temp

```bash
python3 esxtop-offline_v0.0.6.1.py --keep-temp --debug
```

### 16. Single group + debug

```bash
python3 esxtop-offline_v0.0.6.1.py --group "Physical Disk Adapter" --debug
```

### 17. Full typical production-style run

```bash
python3 esxtop-offline_v0.0.6.1.py \
  --root /path/to/esxtop \
  --recursive \
  --outdir /path/to/output \
  --keep-full-header \
  --debug
```

## How options combine

All supported options can be combined.

General pattern:

```bash
python3 esxtop-offline_v0.0.6.1.py \
  [--root PATH] \
  [--outdir PATH] \
  [--group "GROUP"] \
  [--delimiter ","] \
  [--recursive] \
  [--keep-full-header] \
  [--keep-temp] \
  [--debug]
```

### Composition rules

- `--root` changes where input files are searched
- `--recursive` changes whether subdirectories are scanned
- `--group` filters the extraction to one group only
- `--outdir` changes where final outputs are written
- `--keep-full-header` changes header style only
- `--keep-temp` controls temp cleanup only
- `--debug` only affects metrics output
- `--delimiter` changes CSV read/write delimiter

These options are independent and may be used together.

## Example combinations by use case

### Merge everything under a tree and keep defaults

```bash
python3 esxtop-offline_v0.0.6.1.py --root /data/esxtop --recursive
```

### Create a clean viewer bundle for only Network Port

```bash
python3 esxtop-offline_v0.0.6.1.py \
  --root /data/esxtop \
  --recursive \
  --group "Network Port" \
  --outdir network_port_bundle
```

### Preserve exact headers for downstream tools

```bash
python3 esxtop-offline_v0.0.6.1.py \
  --root /data/esxtop \
  --recursive \
  --keep-full-header
```

### Troubleshoot with temp files and runtime stats

```bash
python3 esxtop-offline_v0.0.6.1.py \
  --root /data/esxtop \
  --recursive \
  --keep-temp \
  --debug
```

### Build a portable bundle in a dedicated output folder

```bash
python3 esxtop-offline_v0.0.6.1.py \
  --root /data/esxtop \
  --recursive \
  --outdir ./esxtop_bundle
```

## Output files explained

### `output/raw/*.csv`
Final merged and sorted CSV files, one per host/group.

### `output/esxtop-metadata.json`
Metadata consumed by the visualizer.

Contains host/group/instance/metric/file mapping derived from the generated CSV outputs.

### `output/esxtop-visualizer_v0.0.8.html`
Self-contained HTML viewer for the generated output and metadata.

### `output/tmp/`
Temporary processing area.

Removed automatically unless `--keep-temp` is used.

## Visualizer workflow

After script completion:

1. change to the output directory
2. start a local web server
3. open the visualizer in a browser

The script prints hints for this automatically.

### Auto-port example

```bash
cd "output" && python3 -m http.server <AUTO_PORT>
```

### Custom port example

```bash
cd "output" && python3 -m http.server 8080
```

Then open:

```text
http://localhost:<PORT>/esxtop-visualizer_v0.0.8.html
```

## Typical end-to-end workflow

### Step 1: run the bundle generator

```bash
python3 esxtop-offline_v0.0.6.1.py --root /path/to/source --recursive
```

### Step 2: start the web server

```bash
cd output
python3 -m http.server 8000
```

### Step 3: open the viewer

```text
http://localhost:8000/esxtop-visualizer_v0.0.8.html
```

## Notes on viewer behavior

The bundled viewer supports:

- host filter
- group filter
- instance filter
- metric filter
- searchable multi-select dropdowns
- optional CSV upload fallback
- legend show/hide
- dark/light theme

If browser file-access restrictions prevent automatic CSV reads, run the web server from inside the output folder.

## Debug output

When `--debug` is used, runtime metrics include:

- wall time
- CPU time
- process CPU percent
- system CPU percent
- process RSS current
- process RSS peak
- system memory snapshot

`psutil` improves the quality of this output.

## Troubleshooting

### No CSV files found

Check:

- `--root` path is correct
- you used `--recursive` when needed
- source files really end with `.csv`

### Viewer opens but chart is empty

Check:

- a group is selected
- at least one instance or metric is selected
- you are serving the output directory with `python3 -m http.server`
- metadata and CSV files are in the output folder produced by the script

### Downstream tool rejects headers

Run with:

```bash
python3 esxtop-offline_v0.0.6.1.py --keep-full-header
```

### Need intermediate temp files for troubleshooting

Run with:

```bash
python3 esxtop-offline_v0.0.6.1.py --keep-temp
```

## Quick command cheat sheet

```bash
# simplest run
python3 esxtop-offline_v0.0.6.1.py

# recursive scan
python3 esxtop-offline_v0.0.6.1.py --recursive

# custom root
python3 esxtop-offline_v0.0.6.1.py --root /data/esxtop

# custom output
python3 esxtop-offline_v0.0.6.1.py --outdir /tmp/esxtop_output

# only one group
python3 esxtop-offline_v0.0.6.1.py --group "Physical Cpu"

# preserve exact headers
python3 esxtop-offline_v0.0.6.1.py --keep-full-header

# keep temp files
python3 esxtop-offline_v0.0.6.1.py --keep-temp

# show debug metrics
python3 esxtop-offline_v0.0.6.1.py --debug

# everything together
python3 esxtop-offline_v0.0.6.1.py --root /data/esxtop --recursive --outdir /tmp/out --group "Network Port" --keep-full-header --keep-temp --debug
```

## Version notes

This README is written for:

- `esxtop-offline_v0.0.6.1.py`
- bundled metadata generation based on `esxtop-metadata_v0.0.4` logic
- bundled viewer based on `esxtop-visualizer_v0.0.8`
