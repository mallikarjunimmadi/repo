# PCAP Report Generator

The PCAP report script builds per-stream reports from a `.pcap` or `.pcapng` file using `tshark`.

It generates:
- `CSV` for spreadsheet-style analysis
- `JSON` for downstream automation
- main `HTML` report for interactive stream browsing
- separate graphs `HTML` report for offline time-series analysis

The current script supports:
- `TCP` and `UDP` stream aggregation
- `IPv4` and `IPv6`
- optional Wireshark display filters
- optional minimum stream duration filtering
- interactive main report with filtering, sorting, chips, and IP-pair summary
- offline interactive graphs with drag-to-zoom and reset
- stream classifications for TCP, TLS, RTT, retransmissions, and UDP burstiness

## Requirements

- Python `3.9+` recommended
- `tshark` installed and available in `PATH`

Check `tshark`:

```bash
tshark -v
```

If `tshark` is not found on macOS and Wireshark is installed:

```bash
sudo ln -s /Applications/Wireshark.app/Contents/MacOS/tshark /usr/local/bin/tshark
```

## Usage

Basic run:

```bash
python3 <script_name>.py -r capture.pcapng
```

Write outputs to custom paths:

```bash
python3 <script_name>.py \
  -r capture.pcapng \
  -o capture_report.csv \
  --out-json capture_report.json \
  --out-html capture_report.html \
  --out-graphs-html capture_graphs.html
```

Filter to HTTPS traffic only:

```bash
python3 <script_name>.py -r capture.pcapng -Y 'tcp.port == 443'
```

Keep only streams lasting at least 60 seconds:

```bash
python3 <script_name>.py -r capture.pcapng --min-duration 60
```

Write timestamps in UTC:

```bash
python3 <script_name>.py -r capture.pcapng --utc
```

## CLI Options

```text
-r, --read READ                Input pcap/pcapng file
--utc                          Output timestamps in UTC
-Y, --display-filter FILTER    Optional Wireshark display filter
--min-duration SECONDS         Only include streams with duration >= this value
-o, --out-csv PATH             Output CSV path
--out-json PATH                Output JSON path
--out-html PATH                Output HTML path for the main report
--out-graphs-html PATH         Output HTML path for offline interactive graphs
```

If output paths are not provided, the script creates:

```text
<pcap_basename>_report.csv
<pcap_basename>_report.json
<pcap_basename>_report.html
<pcap_basename>_graphs.html
```

If a target file already exists, the script appends `_1`, `_2`, and so on to avoid overwriting it.

## Console Output

The script prints immediate progress logs while it runs, followed by a run summary.

Progress logs include:
- current local timestamp
- analysis stage such as TCP, UDP, TLS, finalization, and file writes

Run summary includes:
- pcap file name and path
- pcap size
- run start time
- run end time
- total runtime
- capture start time
- capture end time
- capture duration
- time mode
- display filter
- min-duration filter
- stream, packet, and byte totals
- classification counts
- output file paths

## Generated Outputs

## CSV

The CSV contains one row per stream with fields such as:

- protocol
- stream ID
- source/destination IP and port
- first/last frame
- first/last timestamp
- duration
- packet count
- byte count
- TCP flag counters
- retransmission counters
- RTT-related metrics
- classification booleans

## JSON

The JSON contains the same per-stream data as the CSV in machine-friendly form.

## Main HTML Report

The main report is designed for local use over `file://` and includes:

- cleaner report header with:
  - report title
  - first packet timestamp
  - last packet timestamp
  - top-right min-duration control
- failure/category chips for fast navigation
- sortable columns
- per-column filters
- virtualized row rendering for large datasets
- IP pair summary table
- colored row highlighting for key categories
- footer with script version and author

The main report currently supports chips/filters for:

- Connection refused
- Client abort
- Connection failed
- Retransmissions
- Retrans Heavy
- Zero Window
- Window Full
- Long Idle
- HS Incomplete
- High RTT
- Spiky RTT
- TLS SH Missing
- High PPS UDP
- TLS handshake failed

## Graphs HTML Report

The graphs report is separate from the main report and is also designed for local `file://` use.

It includes:

- full-width chart layout
- drag-to-zoom on charts
- double-click to reset zoom
- reset zoom button
- current visible window label
- interactive series chips with unique colors
- styling aligned with the main HTML report
- footer with script version and author

Available graph series include:

- Packets/sec
- Connections/sec
- Connection Refused/sec
- Client Aborts/sec
- Connection Failures/sec
- TLS Handshake Failures/sec
- Retransmissions/sec
- TCP Retransmission Heavy/sec
- Zero Window/sec
- Window Full/sec
- Long Idle Streams/sec
- Handshake Incomplete/sec
- High RTT/sec
- Spiky RTT/sec
- TLS ServerHello Missing/sec
- High PPS UDP/sec

## Detection Notes

The script includes practical heuristics for rapid triage.

Core connection/TLS logic:

- `conn_refused_syn_rst`
  SYN followed by reset without successful handshake completion.

- `client_abort_after_synack`
  SYN and SYN-ACK observed, then the client sends a reset.

- `conn_failed_ackretrans_rst`
  SYN-ACK retransmission pattern where the handshake never completes.

- `tls_handshake_failed`
  TLS handshake appears not to progress to useful application data.

Additional classifications:

- `has_retransmissions`
  Stream contains packets flagged by `tcp.analysis.retransmission`.

- `retransmission_heavy`
  Stream has more than 2 retransmission packets.

- `zero_window`
  Receiver advertises zero window.

- `window_full`
  Receiver window becomes full.

- `long_idle_stream`
  Stream has a large inter-packet gap.

- `handshake_incomplete`
  Handshake starts but does not progress into a fuller session pattern.

- `high_rtt`
  Stream contains elevated ACK RTT.

- `spiky_rtt`
  RTT spread varies significantly across samples.

- `tls_serverhello_missing`
  TLS ClientHello observed without matching ServerHello.

- `high_pps_udp`
  UDP stream shows elevated packets-per-second behavior.

These are heuristics, not protocol-forensic guarantees. Validate critical findings in Wireshark when needed.

## Notes

- The script performs multiple `tshark` passes over the input file.
- Large pcaps may still take noticeable time.
- The main HTML is optimized for stream-level browsing.
- The graphs HTML is optimized for time-series exploration.

## Quick Start

```bash
python3 <script_name>.py -r sample.pcapng
```

Then open:

- the main report HTML to inspect and filter streams
- the graphs HTML to explore packet, connection, and classification trends over time
