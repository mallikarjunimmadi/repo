# OSW Ping Analyzer v0.0.5

`osw_ping_analyzer_v0.0.5.py` analyzes OSWatcher private-network ping logs and generates CSV reports for ping latency breaches and latency buckets.

## What It Does

- Searches for directories named `oswprvtnet` under the selected root path.
- Processes `.dat` files by default.
- Parses OSWatcher `PING_PRIVATE` headers, `PING ... from ...` lines, and reply lines containing `time=<latency> ms`.
- Flags latency values greater than `--threshold`.
- Calculates breach `event_time` using:

```text
event_time = file_start_time + (((host_index - 1) * pings_per_host + ping_in_host) * interval)
```

- Writes the detailed ping analysis CSV sorted by `event_time` in ascending order.

## Outputs

Each run creates three timestamped CSV files:

- `ping_analysis_<timestamp>.csv`: detailed threshold breaches, sorted by `event_time` ascending.
- `ping_summary_<timestamp>.csv`: breach summary grouped by `file`, `src_ip`, `dst_ip`, and `bytes`.
- `ping_buckets_<timestamp>.csv`: latency bucket counts from all ping samples, not just breaches.

## Requirements

- Python 3
- No third-party Python packages are required.

## Examples

Show help:

```bash
python3 osw_ping_analyzer_v0.0.5.py --help
```

Show script version:

```bash
python3 osw_ping_analyzer_v0.0.5.py --version
```

Analyze from the current directory using defaults:

```bash
python3 osw_ping_analyzer_v0.0.5.py
```

Analyze a specific OSWatcher root directory:

```bash
python3 osw_ping_analyzer_v0.0.5.py --root /path/to/oswatcher/archive
```

Analyze one `.dat` file directly:

```bash
python3 osw_ping_analyzer_v0.0.5.py --root /path/to/oswprvtnet/private_ping.dat
```

Write reports and log to a dedicated output directory:

```bash
python3 osw_ping_analyzer_v0.0.5.py --root /path/to/oswatcher/archive --outdir ./reports --log ./reports/osw_ping_analyzer.log
```

Use a different latency threshold:

```bash
python3 osw_ping_analyzer_v0.0.5.py --root /path/to/oswatcher/archive --threshold 50
```

Change ping timing assumptions for `event_time` calculation:

```bash
python3 osw_ping_analyzer_v0.0.5.py --root /path/to/oswatcher/archive --pings-per-host 10 --interval 1
```

Include multiple file extensions:

```bash
python3 osw_ping_analyzer_v0.0.5.py --root /path/to/oswatcher/archive --extensions .dat,.txt
```

Customize latency bucket edges:

```bash
python3 osw_ping_analyzer_v0.0.5.py --root /path/to/oswatcher/archive --bucket-edges 1,5,10,20,50,100,200,500
```

Enable debug logging:

```bash
python3 osw_ping_analyzer_v0.0.5.py --root /path/to/oswatcher/archive --debug
```

## Options

- `--root`: Base directory or single file to analyze. Default: current directory.
- `--target-dir`: Directory name to process when walking a root directory. Default: `oswprvtnet`.
- `--extensions`: Comma-separated file extensions to process. Default: `.dat`.
- `--threshold`: Latency threshold in milliseconds. Default: `20.0`.
- `--pings-per-host`: Assumed number of pings per remote host. Default: `10`.
- `--interval`: Seconds between pings. Default: `1`.
- `--bucket-edges`: Comma-separated latency bucket edges in milliseconds. Default: `1,5,10,20,50,100,200`.
- `--outdir`: Output directory for generated CSV reports. Default: current directory.
- `--log`: Log file path. Default: `osw_ping_analyzer.log`.
- `--debug`: Enable debug logging.
- `--version`: Print the script version and exit.

## Notes

- Timestamp parsing uses Python `datetime.strptime` with `%Z`. Common timezone names such as `IST` may depend on the operating system locale/timezone support.
- Bucket ranges use strict inequalities. Values exactly equal to a bucket edge are not counted in middle buckets.
