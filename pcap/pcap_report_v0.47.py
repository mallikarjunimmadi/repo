#!/usr/bin/env python3
import argparse
import csv
import datetime as dt
import html
import json
import os
import subprocess
import re
import sys
import time
from dataclasses import dataclass
from typing import Dict, Iterator, Optional, Tuple, List

TCP_RETRANS_HEAVY_THRESHOLD = 2
LONG_IDLE_STREAM_SEC_THRESHOLD = 2.0
HIGH_RTT_SEC_THRESHOLD = 0.01
SPIKY_RTT_SPREAD_SEC_THRESHOLD = 0.05
HIGH_PPS_UDP_THRESHOLD = 100.0
SCRIPT_VERSION = "v0.44"


def unique_name(path: str) -> str:
    """Return a non-existing filename by appending _1, _2, ..."""
    if not os.path.exists(path):
        return path
    root, ext = os.path.splitext(path)
    i = 1
    while True:
        candidate = f"{root}_{i}{ext}"
        if not os.path.exists(candidate):
            return candidate
        i += 1


@dataclass
class StreamAgg:
    proto: str                 # "TCP" / "UDP"
    stream_id: int
    first_epoch: float
    last_epoch: float
    first_frame: int
    last_frame: int
    pkts: int
    bytes_total: int
    src_ip: str
    dst_ip: str
    src_port: str
    dst_port: str

    # TCP-only diagnostics (0 for UDP)
    syn_pkts: int = 0
    rst_pkts: int = 0
    rst_no_ack_pkts: int = 0
    ack_pkts: int = 0
    ack_only_pkts: int = 0
    synack_pkts: int = 0
    fin_pkts: int = 0
    other_flag_pkts: int = 0
    retrans_pkts: int = 0
    zero_window_pkts: int = 0
    window_full_pkts: int = 0

    # TLS/SSL diagnostics (TCP only)
    tls_clienthello_pkts: int = 0
    tls_serverhello_pkts: int = 0
    tls_alert_pkts: int = 0
    tls_appdata_pkts: int = 0
    tls_first_alert_frame: int = 0
    tls_first_appdata_frame: int = 0
    tls_first_serverhello_frame: int = 0
    tls_handshake_failed: bool = False  # computed at end

    conn_refused_syn_rst: bool = False  # computed at end
    client_abort_after_synack: bool = False  # computed at end
    conn_failed_ackretrans_rst: bool = False  # computed at end
    has_retransmissions: bool = False  # computed at end
    retransmission_heavy: bool = False  # computed at end
    zero_window_stream: bool = False  # computed at end
    window_full_stream: bool = False  # computed at end
    long_idle_stream: bool = False  # computed at end
    handshake_incomplete: bool = False  # computed at end
    high_rtt: bool = False  # computed at end
    spiky_rtt: bool = False  # computed at end
    tls_serverhello_missing: bool = False  # computed at end
    high_pps_udp: bool = False  # computed at end

    # Event timing hints for time-series graphs
    first_syn_epoch: float = 0.0
    first_synack_epoch: float = 0.0
    second_synack_epoch: float = 0.0
    first_rst_epoch: float = 0.0
    first_rst_no_ack_epoch: float = 0.0
    first_retrans_epoch: float = 0.0
    first_zero_window_epoch: float = 0.0
    first_window_full_epoch: float = 0.0
    first_long_idle_epoch: float = 0.0
    first_high_rtt_epoch: float = 0.0
    tls_first_clienthello_epoch: float = 0.0
    tls_first_serverhello_epoch: float = 0.0
    tls_first_alert_epoch: float = 0.0
    tls_first_appdata_epoch: float = 0.0
    ack_rtt_samples: int = 0
    ack_rtt_min_sec: float = 0.0
    ack_rtt_max_sec: float = 0.0
    max_interpacket_gap_sec: float = 0.0


def epoch_to_iso(epoch: float, utc: bool) -> str:
    if utc:
        return dt.datetime.fromtimestamp(epoch, tz=dt.timezone.utc).isoformat()
    return dt.datetime.fromtimestamp(epoch).isoformat()


def format_elapsed(seconds: float) -> str:
    total_ms = int(round(max(seconds, 0.0) * 1000))
    hours, rem_ms = divmod(total_ms, 3600 * 1000)
    minutes, rem_ms = divmod(rem_ms, 60 * 1000)
    secs, millis = divmod(rem_ms, 1000)
    if hours:
        return f"{hours:02d}:{minutes:02d}:{secs:02d}.{millis:03d}"
    return f"{minutes:02d}:{secs:02d}.{millis:03d}"


def progress_log(message: str) -> None:
    now = dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"[{now}] {message}", flush=True)


def summarize_rows(rows: List[StreamAgg]) -> dict:
    summary = {
        "tcp_streams": 0,
        "udp_streams": 0,
        "total_packets": 0,
        "total_bytes": 0,
        "capture_start_epoch": None,
        "capture_end_epoch": None,
        "conn_refused": 0,
        "client_abort": 0,
        "conn_failed": 0,
        "tls_failed": 0,
        "retrans_streams": 0,
        "retrans_heavy_streams": 0,
        "zero_window_streams": 0,
        "window_full_streams": 0,
        "long_idle_streams": 0,
        "handshake_incomplete_streams": 0,
        "high_rtt_streams": 0,
        "spiky_rtt_streams": 0,
        "tls_serverhello_missing_streams": 0,
        "high_pps_udp_streams": 0,
    }

    for st in rows:
        if st.proto == "TCP":
            summary["tcp_streams"] += 1
        elif st.proto == "UDP":
            summary["udp_streams"] += 1

        summary["total_packets"] += st.pkts
        summary["total_bytes"] += st.bytes_total

        if st.pkts > 0:
            start_epoch = summary["capture_start_epoch"]
            end_epoch = summary["capture_end_epoch"]
            if start_epoch is None or st.first_epoch < start_epoch:
                summary["capture_start_epoch"] = st.first_epoch
            if end_epoch is None or st.last_epoch > end_epoch:
                summary["capture_end_epoch"] = st.last_epoch

        if st.conn_refused_syn_rst:
            summary["conn_refused"] += 1
        if st.client_abort_after_synack:
            summary["client_abort"] += 1
        if st.conn_failed_ackretrans_rst:
            summary["conn_failed"] += 1
        if st.tls_handshake_failed:
            summary["tls_failed"] += 1
        if st.has_retransmissions:
            summary["retrans_streams"] += 1
        if st.retransmission_heavy:
            summary["retrans_heavy_streams"] += 1
        if st.zero_window_stream:
            summary["zero_window_streams"] += 1
        if st.window_full_stream:
            summary["window_full_streams"] += 1
        if st.long_idle_stream:
            summary["long_idle_streams"] += 1
        if st.handshake_incomplete:
            summary["handshake_incomplete_streams"] += 1
        if st.high_rtt:
            summary["high_rtt_streams"] += 1
        if st.spiky_rtt:
            summary["spiky_rtt_streams"] += 1
        if st.tls_serverhello_missing:
            summary["tls_serverhello_missing_streams"] += 1
        if st.high_pps_udp:
            summary["high_pps_udp_streams"] += 1

    return summary


def _bucket_epoch(epoch: float) -> int:
    return int(epoch)


def _inc_bucket(buckets: Dict[int, int], epoch: float, amount: int = 1) -> None:
    buckets[_bucket_epoch(epoch)] = buckets.get(_bucket_epoch(epoch), 0) + amount


def _pick_event_epoch(st: StreamAgg, kind: str) -> float:
    if kind == "connections":
        return st.first_epoch
    if kind == "conn_refused":
        return st.first_rst_epoch or st.last_epoch or st.first_epoch
    if kind == "client_abort":
        return st.first_rst_no_ack_epoch or st.first_rst_epoch or st.last_epoch or st.first_epoch
    if kind == "conn_failed":
        return st.second_synack_epoch or st.last_epoch or st.first_synack_epoch or st.first_epoch
    if kind == "tls_failed":
        return (
            st.tls_first_alert_epoch
            or st.tls_first_serverhello_epoch
            or st.tls_first_clienthello_epoch
            or st.first_epoch
        )
    if kind == "retransmissions":
        return st.first_retrans_epoch or st.last_epoch or st.first_epoch
    if kind == "retransmission_heavy":
        return st.first_retrans_epoch or st.last_epoch or st.first_epoch
    if kind == "zero_window":
        return st.first_zero_window_epoch or st.last_epoch or st.first_epoch
    if kind == "window_full":
        return st.first_window_full_epoch or st.last_epoch or st.first_epoch
    if kind == "long_idle":
        return st.first_long_idle_epoch or st.last_epoch or st.first_epoch
    if kind == "handshake_incomplete":
        return st.first_epoch
    if kind == "high_rtt":
        return st.first_high_rtt_epoch or st.last_epoch or st.first_epoch
    if kind == "spiky_rtt":
        return st.first_high_rtt_epoch or st.last_epoch or st.first_epoch
    if kind == "tls_serverhello_missing":
        return st.tls_first_clienthello_epoch or st.first_epoch
    if kind == "high_pps_udp":
        return st.first_epoch
    return st.first_epoch


def build_timeseries(rows: List[StreamAgg], packet_buckets: Dict[int, int], utc: bool) -> dict:
    series_maps: Dict[str, Dict[int, int]] = {
        "packets_per_sec": dict(packet_buckets),
        "connections_per_sec": {},
        "conn_refused_per_sec": {},
        "client_aborts_per_sec": {},
        "conn_failures_per_sec": {},
        "tls_handshake_failures_per_sec": {},
        "retransmissions_per_sec": {},
        "retransmission_heavy_per_sec": {},
        "zero_window_per_sec": {},
        "window_full_per_sec": {},
        "long_idle_streams_per_sec": {},
        "handshake_incomplete_per_sec": {},
        "high_rtt_per_sec": {},
        "spiky_rtt_per_sec": {},
        "tls_serverhello_missing_per_sec": {},
        "high_pps_udp_per_sec": {},
    }

    for st in rows:
        if st.pkts > 0:
            _inc_bucket(series_maps["connections_per_sec"], _pick_event_epoch(st, "connections"))
        if st.conn_refused_syn_rst:
            _inc_bucket(series_maps["conn_refused_per_sec"], _pick_event_epoch(st, "conn_refused"))
        if st.client_abort_after_synack:
            _inc_bucket(series_maps["client_aborts_per_sec"], _pick_event_epoch(st, "client_abort"))
        if st.conn_failed_ackretrans_rst:
            _inc_bucket(series_maps["conn_failures_per_sec"], _pick_event_epoch(st, "conn_failed"))
        if st.tls_handshake_failed:
            _inc_bucket(series_maps["tls_handshake_failures_per_sec"], _pick_event_epoch(st, "tls_failed"))
        if st.has_retransmissions:
            _inc_bucket(series_maps["retransmissions_per_sec"], _pick_event_epoch(st, "retransmissions"))
        if st.retransmission_heavy:
            _inc_bucket(series_maps["retransmission_heavy_per_sec"], _pick_event_epoch(st, "retransmission_heavy"))
        if st.zero_window_stream:
            _inc_bucket(series_maps["zero_window_per_sec"], _pick_event_epoch(st, "zero_window"))
        if st.window_full_stream:
            _inc_bucket(series_maps["window_full_per_sec"], _pick_event_epoch(st, "window_full"))
        if st.long_idle_stream:
            _inc_bucket(series_maps["long_idle_streams_per_sec"], _pick_event_epoch(st, "long_idle"))
        if st.handshake_incomplete:
            _inc_bucket(series_maps["handshake_incomplete_per_sec"], _pick_event_epoch(st, "handshake_incomplete"))
        if st.high_rtt:
            _inc_bucket(series_maps["high_rtt_per_sec"], _pick_event_epoch(st, "high_rtt"))
        if st.spiky_rtt:
            _inc_bucket(series_maps["spiky_rtt_per_sec"], _pick_event_epoch(st, "spiky_rtt"))
        if st.tls_serverhello_missing:
            _inc_bucket(series_maps["tls_serverhello_missing_per_sec"], _pick_event_epoch(st, "tls_serverhello_missing"))
        if st.high_pps_udp:
            _inc_bucket(series_maps["high_pps_udp_per_sec"], _pick_event_epoch(st, "high_pps_udp"))

    all_buckets = set()
    for buckets in series_maps.values():
        all_buckets.update(buckets.keys())

    if not all_buckets:
        return {
            "bucket_size_sec": 1,
            "labels": [],
            "bucket_epochs": [],
            "series": [],
            "notes": [
                "Packets/sec reflects packet buckets from tshark output after any display filter.",
                "Stream-based failure series are bucketed by inferred event time when available.",
            ],
        }

    start_bucket = min(all_buckets)
    end_bucket = max(all_buckets)
    bucket_epochs = list(range(start_bucket, end_bucket + 1))
    labels = [epoch_to_iso(float(bucket), utc) for bucket in bucket_epochs]

    series_defs = [
        ("packets_per_sec", "Packets/sec", "#1565c0"),
        ("connections_per_sec", "Connections/sec", "#00897b"),
        ("conn_refused_per_sec", "Connection Refused/sec", "#d32f2f"),
        ("client_aborts_per_sec", "Client Aborts/sec", "#ef6c00"),
        ("conn_failures_per_sec", "Connection Failures/sec", "#6a1b9a"),
        ("tls_handshake_failures_per_sec", "TLS Handshake Failures/sec", "#5d4037"),
        ("retransmissions_per_sec", "Retransmissions/sec", "#c2185b"),
        ("retransmission_heavy_per_sec", "TCP Retransmission Heavy/sec", "#ad1457"),
        ("zero_window_per_sec", "Zero Window/sec", "#00838f"),
        ("window_full_per_sec", "Window Full/sec", "#3949ab"),
        ("long_idle_streams_per_sec", "Long Idle Streams/sec", "#7b1fa2"),
        ("handshake_incomplete_per_sec", "Handshake Incomplete/sec", "#f4511e"),
        ("high_rtt_per_sec", "High RTT/sec", "#2e7d32"),
        ("spiky_rtt_per_sec", "Spiky RTT/sec", "#558b2f"),
        ("tls_serverhello_missing_per_sec", "TLS ServerHello Missing/sec", "#6d4c41"),
        ("high_pps_udp_per_sec", "High PPS UDP/sec", "#0277bd"),
    ]

    series = []
    for key, label, color in series_defs:
        buckets = series_maps[key]
        values = [buckets.get(bucket, 0) for bucket in bucket_epochs]
        series.append({
            "key": key,
            "label": label,
            "color": color,
            "values": values,
            "total": sum(values),
            "peak": max(values) if values else 0,
        })

    return {
        "bucket_size_sec": 1,
        "labels": labels,
        "bucket_epochs": bucket_epochs,
        "series": series,
        "notes": [
            "Packets/sec reflects packet buckets from tshark output after any display filter.",
            "Stream-based failure series are bucketed by inferred event time when available.",
        ],
    }


def pick_ip(ipv4: str, ipv6: str) -> str:
    return ipv4 if ipv4 else (ipv6 if ipv6 else "")


def parse_flag01(s: str) -> int:
    """
    tshark may emit '1'/'0' OR 'True'/'False' depending on version/build.
    """
    if not s:
        return 0
    v = s.strip().lower()
    return 1 if v in ("1", "true", "yes") else 0

def run_tshark(
    pcap: str,
    proto: str,
    display_filter: Optional[str] = None,
) -> Iterator[str]:
    """
    Yields tab-separated lines, one per packet.
    Uses -n for speed (no name resolution).
    """
    proto_l = proto.lower()

    if proto_l == "tcp":
        stream_field = "tcp.stream"
        srcport_field = "tcp.srcport"
        dstport_field = "tcp.dstport"
        base_filter = "tcp"
        extra_fields = [
            "-e", "tcp.flags.syn",
            "-e", "tcp.flags.ack",
            "-e", "tcp.flags.reset",
            "-e", "tcp.flags.fin",
            "-e", "tcp.flags.push",
            "-e", "tcp.flags.urg",
            "-e", "tcp.analysis.retransmission",
            "-e", "tcp.analysis.zero_window",
            "-e", "tcp.analysis.window_full",
            "-e", "tcp.analysis.ack_rtt",
            "-e", "tcp.time_delta",
        ]
    elif proto_l == "udp":
        stream_field = "udp.stream"
        srcport_field = "udp.srcport"
        dstport_field = "udp.dstport"
        base_filter = "udp"
        extra_fields = ["-e", "udp.time_delta"]
    else:
        raise ValueError("proto must be tcp or udp")

    final_filter = f"({base_filter})" if not display_filter else f"({base_filter}) && ({display_filter})"

    cmd = [
        "tshark",
        "-o", "x11.tcp.port:",
        "-n",
        "-r", pcap,
        "-Y", final_filter,
        "-T", "fields",
        "-E", "separator=\t",
        "-E", "occurrence=f",
        "-e", stream_field,
        "-e", "frame.time_epoch",
        "-e", "frame.number",
        "-e", "frame.len",
        "-e", "ip.src",
        "-e", "ip.dst",
        "-e", "ipv6.src",
        "-e", "ipv6.dst",
        "-e", srcport_field,
        "-e", dstport_field,
        *extra_fields,
    ]

    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, check=True)
    except FileNotFoundError:
        print("ERROR: tshark not found in PATH. If Wireshark is installed, symlink it:", file=sys.stderr)
        print("  sudo ln -s /Applications/Wireshark.app/Contents/MacOS/tshark /usr/local/bin/tshark", file=sys.stderr)
        sys.exit(2)
    except subprocess.CalledProcessError as e:
        print("ERROR: tshark failed.", file=sys.stderr)
        if e.stderr:
            print(e.stderr.strip(), file=sys.stderr)
        sys.exit(2)

    for line in proc.stdout.splitlines():
        if line.strip():
            yield line


def ingest_proto(
    pcap: str,
    proto: str,
    aggs: Dict[Tuple[str, int], StreamAgg],
    display_filter: Optional[str],
    packet_buckets: Optional[Dict[int, int]] = None,
) -> None:
    is_tcp = (proto.lower() == "tcp")

    for line in run_tshark(pcap, proto, display_filter=display_filter):
        parts = line.split("\t")

        if is_tcp:
            # 10 base fields + 11 tcp fields = 21
            if len(parts) != 21:
                continue
            (sid_s, epoch_s, frame_s, flen_s, ip4s, ip4d, ip6s, ip6d, sport, dport,
             syn_s, ack_s, rst_s, fin_s, psh_s, urg_s, retrans_s, zero_window_s,
             window_full_s, ack_rtt_s, delta_s) = parts
        else:
            if len(parts) != 11:
                continue
            sid_s, epoch_s, frame_s, flen_s, ip4s, ip4d, ip6s, ip6d, sport, dport, delta_s = parts
            syn_s = ack_s = rst_s = fin_s = psh_s = urg_s = retrans_s = zero_window_s = window_full_s = ack_rtt_s = ""

        if not sid_s or not epoch_s or not frame_s:
            continue

        try:
            sid = int(sid_s)
            epoch = float(epoch_s)
            frame_no = int(frame_s)
        except ValueError:
            continue

        if packet_buckets is not None:
            _inc_bucket(packet_buckets, epoch)

        try:
            frame_len = int(flen_s) if flen_s else 0
        except ValueError:
            frame_len = 0
        try:
            stream_delta_sec = float(delta_s) if delta_s else 0.0
        except ValueError:
            stream_delta_sec = 0.0

        src_ip = pick_ip(ip4s, ip6s)
        dst_ip = pick_ip(ip4d, ip6d)

        key = (proto.upper(), sid)

        if key not in aggs:
            aggs[key] = StreamAgg(
                proto=proto.upper(),
                stream_id=sid,
                first_epoch=epoch,
                last_epoch=epoch,
                first_frame=frame_no,
                last_frame=frame_no,
                pkts=1,
                bytes_total=frame_len,
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=sport,
                dst_port=dport,
            )
        else:
            st = aggs[key]
            st.pkts += 1
            st.bytes_total += frame_len

            if epoch < st.first_epoch:
                st.first_epoch = epoch
            if epoch > st.last_epoch:
                st.last_epoch = epoch
            if frame_no < st.first_frame:
                st.first_frame = frame_no
            if frame_no > st.last_frame:
                st.last_frame = frame_no

            if not st.src_ip and src_ip:
                st.src_ip = src_ip
            if not st.dst_ip and dst_ip:
                st.dst_ip = dst_ip
            if not st.src_port and sport:
                st.src_port = sport
            if not st.dst_port and dport:
                st.dst_port = dport

        st = aggs[key]

        # TCP-only flag accounting
        if is_tcp:
            syn = parse_flag01(syn_s)
            ack = parse_flag01(ack_s)
            rst = parse_flag01(rst_s)
            fin = parse_flag01(fin_s)
            psh = parse_flag01(psh_s)
            urg = parse_flag01(urg_s)
            retrans = parse_flag01(retrans_s)
            zero_window = parse_flag01(zero_window_s)
            window_full = parse_flag01(window_full_s)
            try:
                ack_rtt_sec = float(ack_rtt_s) if ack_rtt_s else 0.0
            except ValueError:
                ack_rtt_sec = 0.0

            # counts
            if syn == 1 and ack == 1:
                st.synack_pkts += 1
                if st.first_synack_epoch == 0.0:
                    st.first_synack_epoch = epoch
                elif st.second_synack_epoch == 0.0:
                    st.second_synack_epoch = epoch
            if ack == 1:
                st.ack_pkts += 1
            if ack == 1 and syn == 0 and rst == 0 and fin == 0 and psh == 0 and urg == 0:
                st.ack_only_pkts += 1
            if syn == 1 and ack == 0 and rst == 0:
                st.syn_pkts += 1
                if st.first_syn_epoch == 0.0:
                    st.first_syn_epoch = epoch
            if rst == 1:
                st.rst_pkts += 1  # include RST,ACK too (common)
                if st.first_rst_epoch == 0.0:
                    st.first_rst_epoch = epoch
            if rst == 1 and ack == 0:
                st.rst_no_ack_pkts += 1  # client-side abort often appears as pure RST
                if st.first_rst_no_ack_epoch == 0.0:
                    st.first_rst_no_ack_epoch = epoch

            if fin == 1:
                st.fin_pkts += 1
            if retrans == 1:
                st.retrans_pkts += 1
                if st.first_retrans_epoch == 0.0:
                    st.first_retrans_epoch = epoch
            if zero_window == 1:
                st.zero_window_pkts += 1
                if st.first_zero_window_epoch == 0.0:
                    st.first_zero_window_epoch = epoch
            if window_full == 1:
                st.window_full_pkts += 1
                if st.first_window_full_epoch == 0.0:
                    st.first_window_full_epoch = epoch
            if ack_rtt_sec > 0.0:
                st.ack_rtt_samples += 1
                if st.ack_rtt_min_sec == 0.0 or ack_rtt_sec < st.ack_rtt_min_sec:
                    st.ack_rtt_min_sec = ack_rtt_sec
                if ack_rtt_sec > st.ack_rtt_max_sec:
                    st.ack_rtt_max_sec = ack_rtt_sec
                if ack_rtt_sec >= HIGH_RTT_SEC_THRESHOLD and st.first_high_rtt_epoch == 0.0:
                    st.first_high_rtt_epoch = epoch

            # classify "other" flags (allow SYN and RST packets; treat FIN/PSH/URG combos as other)
            is_pure_syn = (syn == 1 and ack == 0 and rst == 0 and fin == 0 and psh == 0 and urg == 0)

            # pure SYN-ACK (server handshake response)
            is_synack_packet = (syn == 1 and ack == 1 and rst == 0 and fin == 0 and psh == 0 and urg == 0)

            # allow RST with or without ACK; disallow RST mixed with SYN/FIN/PSH/URG
            is_rst_packet = (rst == 1 and syn == 0 and fin == 0 and psh == 0 and urg == 0)

            if not (is_pure_syn or is_synack_packet or is_rst_packet):
                st.other_flag_pkts += 1
        if stream_delta_sec > st.max_interpacket_gap_sec:
            st.max_interpacket_gap_sec = stream_delta_sec
            if stream_delta_sec >= LONG_IDLE_STREAM_SEC_THRESHOLD and st.first_long_idle_epoch == 0.0:
                st.first_long_idle_epoch = epoch


def finalize_tcp_flags(rows: List[StreamAgg]) -> None:
    """
    Failure classifications (TCP only):

    conn_refused_syn_rst:
      - SYN observed
      - RST observed
      - no SYN-ACK
      - no other TCP flag types beyond SYN/RST

    conn_failed_ackretrans_rst:
      - SYN observed
      - SYN-ACK observed
      - SYN-ACK retransmits inferred (synack_pkts >= 2)
      - RST may or may not be present
      - no other TCP flag types beyond SYN/SYN-ACK (and optional RST)

    client_abort_after_synack:
      - SYN observed
      - SYN-ACK observed
      - client abort inferred via pure RST (no ACK)
      - no other TCP flag types beyond SYN/SYN-ACK/RST

    Mutually exclusive enforcement (priority):
      1) conn_refused_syn_rst
      2) conn_failed_ackretrans_rst
      3) client_abort_after_synack
    """
    for st in rows:
        if st.proto != "TCP":
            st.conn_refused_syn_rst = False
            st.client_abort_after_synack = False
            st.conn_failed_ackretrans_rst = False
            st.has_retransmissions = False
            st.retransmission_heavy = False
            continue

        st.has_retransmissions = st.retrans_pkts > 0
        st.retransmission_heavy = st.retrans_pkts > TCP_RETRANS_HEAVY_THRESHOLD

        # Raw detections
        conn_refused = (
            st.syn_pkts >= 1 and
            st.rst_pkts >= 1 and
            st.synack_pkts == 0 and
            st.other_flag_pkts == 0
        )

        conn_failed = (
            st.syn_pkts >= 1 and
            st.synack_pkts >= 2 and   # SYN-ACK retransmits inferred
            st.fin_pkts == 0 and
            st.other_flag_pkts == 0
        )

        client_abort = (
            st.syn_pkts >= 1 and
            st.synack_pkts >= 1 and
            st.rst_no_ack_pkts >= 1 and
            st.other_flag_pkts == 0
        )

        # Mutually exclusive (priority)
        if conn_refused:
            st.conn_refused_syn_rst = True
            st.conn_failed_ackretrans_rst = False
            st.client_abort_after_synack = False
        elif conn_failed:
            st.conn_refused_syn_rst = False
            st.conn_failed_ackretrans_rst = True
            st.client_abort_after_synack = False
        elif client_abort:
            st.conn_refused_syn_rst = False
            st.conn_failed_ackretrans_rst = False
            st.client_abort_after_synack = True
        else:
            st.conn_refused_syn_rst = False
            st.conn_failed_ackretrans_rst = False
            st.client_abort_after_synack = False


def finalize_additional_categories(rows: List[StreamAgg]) -> None:
    for st in rows:
        duration_sec = max(0.0, st.last_epoch - st.first_epoch)
        avg_pps = (st.pkts / duration_sec) if duration_sec > 0 else float(st.pkts if st.pkts > 0 else 0)

        st.long_idle_stream = st.max_interpacket_gap_sec >= LONG_IDLE_STREAM_SEC_THRESHOLD
        st.high_pps_udp = (st.proto == "UDP" and avg_pps >= HIGH_PPS_UDP_THRESHOLD)

        if st.proto != "TCP":
            st.zero_window_stream = False
            st.window_full_stream = False
            st.handshake_incomplete = False
            st.high_rtt = False
            st.spiky_rtt = False
            st.tls_serverhello_missing = False
            continue

        st.zero_window_stream = st.zero_window_pkts > 0
        st.window_full_stream = st.window_full_pkts > 0
        st.high_rtt = st.ack_rtt_max_sec >= HIGH_RTT_SEC_THRESHOLD
        st.spiky_rtt = (
            st.ack_rtt_samples >= 3 and
            (st.ack_rtt_max_sec - st.ack_rtt_min_sec) >= SPIKY_RTT_SPREAD_SEC_THRESHOLD
        )
        st.tls_serverhello_missing = (
            st.tls_clienthello_pkts >= 1 and
            st.tls_serverhello_pkts == 0
        )

        # Generic incomplete handshake bucket, excluding streams already covered by more-specific failure buckets.
        st.handshake_incomplete = (
            st.syn_pkts >= 1 and
            not st.conn_refused_syn_rst and
            not st.client_abort_after_synack and
            not st.conn_failed_ackretrans_rst and
            st.ack_only_pkts == 0 and
            st.fin_pkts == 0 and
            st.other_flag_pkts == 0
        )


def to_row_dict(st: StreamAgg, utc: bool) -> dict:
    dur = st.last_epoch - st.first_epoch
    return {
        "protocol": st.proto,
        "stream_id": st.stream_id,
        "src_ip": st.src_ip,
        "src_port": st.src_port,
        "dst_ip": st.dst_ip,
        "dst_port": st.dst_port,
        "first_frame": st.first_frame,
        "last_frame": st.last_frame,
        "first_ts": epoch_to_iso(st.first_epoch, utc),
        "last_ts": epoch_to_iso(st.last_epoch, utc),
        "duration_sec": round(dur, 6),
        "packets": st.pkts,
        "bytes_total": st.bytes_total,

        # TCP flags (0 for UDP)
        "syn_pkts": st.syn_pkts,
        "rst_pkts": st.rst_pkts,
        "ack_pkts": st.ack_pkts,
        "ack_only_pkts": st.ack_only_pkts,
        "synack_pkts": st.synack_pkts,
        "retrans_pkts": st.retrans_pkts,
        "zero_window_pkts": st.zero_window_pkts,
        "window_full_pkts": st.window_full_pkts,
        "max_interpacket_gap_sec": round(st.max_interpacket_gap_sec, 6),
        "ack_rtt_samples": st.ack_rtt_samples,
        "ack_rtt_max_ms": round(st.ack_rtt_max_sec * 1000.0, 3),
        "ack_rtt_spread_ms": round(max(0.0, st.ack_rtt_max_sec - st.ack_rtt_min_sec) * 1000.0, 3),
        "avg_pps": round((st.pkts / dur) if dur > 0 else float(st.pkts if st.pkts > 0 else 0), 3),

        # Failure categories
        "conn_refused_syn_rst": bool(st.conn_refused_syn_rst),
        "client_abort_after_synack": bool(st.client_abort_after_synack),
        "conn_failed_ackretrans_rst": bool(st.conn_failed_ackretrans_rst),
        "has_retransmissions": bool(st.has_retransmissions),
        "retransmission_heavy": bool(st.retransmission_heavy),
        "zero_window_stream": bool(st.zero_window_stream),
        "window_full_stream": bool(st.window_full_stream),
        "long_idle_stream": bool(st.long_idle_stream),
        "handshake_incomplete": bool(st.handshake_incomplete),
        "high_rtt": bool(st.high_rtt),
        "spiky_rtt": bool(st.spiky_rtt),
        "tls_serverhello_missing": bool(st.tls_serverhello_missing),
        "high_pps_udp": bool(st.high_pps_udp),

        # TLS classification
        "tls_handshake_failed": bool(st.tls_handshake_failed),
    }

def finalize_tls_flags(rows: List[StreamAgg]) -> None:
    """
    TLS/SSL handshake failure (TCP only), designed to work across Tshark versions.

    We mark tls_handshake_failed when:
      - saw at least one TLS ClientHello
      - AND either:
          * never saw a ServerHello (likely handshake didn't progress), OR
          * saw TLS Alerts but never saw any TLS Application Data, OR
          * (if frame numbers are available) saw an alert before the first Application Data frame

    Rationale:
      - Valid TLS sessions may include (Encrypted) Alerts during connection close (e.g., close_notify).
        Those typically occur after application data, so we avoid flagging them.
      - Some environments don't expose frame.number/tls.* fields reliably; we fall back to counters.
    """
    for st in rows:
        if st.proto != "TCP":
            st.tls_handshake_failed = False
            continue

        if st.tls_clienthello_pkts < 1:
            st.tls_handshake_failed = False
            continue

        # If we have ordering info, use it; otherwise fall back to counters.
        alert_before_appdata = False
        if st.tls_first_alert_frame > 0 and st.tls_first_appdata_frame > 0:
            alert_before_appdata = st.tls_first_alert_frame < st.tls_first_appdata_frame

        st.tls_handshake_failed = (
            st.tls_serverhello_pkts == 0 or
            (st.tls_alert_pkts >= 1 and st.tls_appdata_pkts == 0) or
            alert_before_appdata
        )

def write_csv(out_csv: str, rows: List[StreamAgg], utc: bool) -> None:
    fieldnames = [
        "protocol", "stream_id",
        "src_ip", "src_port", "dst_ip", "dst_port",
        "first_frame", "last_frame",
        "first_ts", "last_ts",
        "duration_sec",
        "packets",
        "bytes_total",
        "syn_pkts", "rst_pkts", "ack_pkts", "ack_only_pkts", "synack_pkts", "retrans_pkts",
        "zero_window_pkts", "window_full_pkts", "max_interpacket_gap_sec",
        "ack_rtt_samples", "ack_rtt_max_ms", "ack_rtt_spread_ms", "avg_pps",
        "conn_refused_syn_rst",
        "client_abort_after_synack",
        "conn_failed_ackretrans_rst",
        "has_retransmissions",
        "retransmission_heavy",
        "zero_window_stream",
        "window_full_stream",
        "long_idle_stream",
        "handshake_incomplete",
        "high_rtt",
        "spiky_rtt",
        "tls_serverhello_missing",
        "high_pps_udp",
        "tls_handshake_failed",
    ]
    with open(out_csv, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader()
        for st in rows:
            d = to_row_dict(st, utc=utc)
            d["conn_refused_syn_rst"] = "TRUE" if d["conn_refused_syn_rst"] else "FALSE"
            d["client_abort_after_synack"] = "TRUE" if d["client_abort_after_synack"] else "FALSE"
            d["conn_failed_ackretrans_rst"] = "TRUE" if d["conn_failed_ackretrans_rst"] else "FALSE"
            d["has_retransmissions"] = "TRUE" if d["has_retransmissions"] else "FALSE"
            d["retransmission_heavy"] = "TRUE" if d["retransmission_heavy"] else "FALSE"
            d["zero_window_stream"] = "TRUE" if d["zero_window_stream"] else "FALSE"
            d["window_full_stream"] = "TRUE" if d["window_full_stream"] else "FALSE"
            d["long_idle_stream"] = "TRUE" if d["long_idle_stream"] else "FALSE"
            d["handshake_incomplete"] = "TRUE" if d["handshake_incomplete"] else "FALSE"
            d["high_rtt"] = "TRUE" if d["high_rtt"] else "FALSE"
            d["spiky_rtt"] = "TRUE" if d["spiky_rtt"] else "FALSE"
            d["tls_serverhello_missing"] = "TRUE" if d["tls_serverhello_missing"] else "FALSE"
            d["high_pps_udp"] = "TRUE" if d["high_pps_udp"] else "FALSE"
            d["tls_handshake_failed"] = "TRUE" if d.get("tls_handshake_failed") else "FALSE"
            w.writerow(d)


def write_json(out_json: str, rows: List[StreamAgg], utc: bool) -> None:
    data = [to_row_dict(st, utc=utc) for st in rows]
    with open(out_json, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False)




def _tshark_supported_fields() -> set:
    '''
    Returns a set of field names supported by the local tshark.
    Uses: tshark -G fields
    '''
    try:
        proc = subprocess.run(["tshark", "-G", "fields"], capture_output=True, text=True, check=True)
    except Exception:
        return set()
    out = set()
    for line in proc.stdout.splitlines():
        # Format: F<TAB>field.name<TAB>...
        if not line or not line.startswith("F	"):
            continue
        parts = line.split("	")
        if len(parts) >= 2:
            out.add(parts[1].strip())
    return out


def _pick_first(supported: set, candidates: List[str]) -> Optional[str]:
    for c in candidates:
        if c and c in supported:
            return c
    return None



def _tls_field_config() -> List[str]:
    """
    TLS field list for tshark across versions.

    We keep this intentionally small and version-tolerant.
    IMPORTANT: `_ws.col.info` vs `_ws.col.Info` differs across builds, so we do NOT
    hardcode it here; `run_tshark_tls()` will try both variants automatically.
    """
    supported = _tshark_supported_fields()

    fields = ["tcp.stream"]

    # Optional: frame number (helps ordering alert vs app-data)
    if "frame.number" in supported:
        fields.append("frame.number")
    if "frame.time_epoch" in supported:
        fields.append("frame.time_epoch")

    # Nice-to-have, not required
    if "tls.handshake.type" in supported:
        fields.append("tls.handshake.type")
    elif "ssl.handshake.type" in supported:
        fields.append("ssl.handshake.type")

    if "tls.record.content_type" in supported:
        fields.append("tls.record.content_type")
    elif "ssl.record.content_type" in supported:
        fields.append("ssl.record.content_type")

    # Optional alert message fields (do NOT require alert_level/alert_description)
    for cand in (
        "tls.alert_message", "ssl.alert_message",
        "tls.alert_message.desc", "ssl.alert_message.desc",
        "tls.alert_message.level", "ssl.alert_message.level",
    ):
        if cand in supported:
            fields.append(cand)
            break

    return fields


def _tls_display_filter(supported: set, display_filter: Optional[str]) -> Optional[str]:
    tls_terms = [
        field for field in (
            "tls.record.content_type",
            "ssl.record.content_type",
            "tls.handshake.type",
            "ssl.handshake.type",
        )
        if field in supported
    ]
    if not tls_terms:
        return display_filter

    base = "(" + " || ".join(tls_terms) + ")"
    return base if not display_filter else f"({display_filter}) && {base}"



def run_tshark_tls(pcap: str, display_filter: Optional[str]) -> Tuple[List[str], Iterator[str]]:
    """
    Returns (field_list, iterator over tshark output lines).

    Compatibility behavior:
      - Tries `_ws.col.info` first (works in many builds; you verified this works),
        then retries with `_ws.col.Info` if tshark complains about an invalid field.
      - Avoids fragile fields like tls.alert_level / tls.alert_description.
    """
    supported = _tshark_supported_fields()
    base_fields = _tls_field_config()

    # Display filter: build only from fields supported by this Tshark.
    final_filter = _tls_display_filter(supported, display_filter)

    def _run_with_info_field(info_field: str):
        tls_fields = list(base_fields)
        if info_field:
            tls_fields.append(info_field)

        cmd = [
            "tshark",
            "-o", "x11.tcp.port:",  # disable X11 TCP port preference (best-effort)
            "-r", pcap,
            "-T", "fields",
            "-E", "separator=\t",
            "-E", "occurrence=f",
        ]
        if final_filter:
            cmd.extend(["-Y", final_filter])
        for f in tls_fields:
            cmd.extend(["-e", f])

        return tls_fields, subprocess.run(cmd, capture_output=True, text=True, check=True)

    tried: List[str] = []
    last_err: Optional[subprocess.CalledProcessError] = None

    for info_field in ("_ws.col.info", "_ws.col.Info", ""):
        try:
            tls_fields, proc = _run_with_info_field(info_field)

            def _iter():
                for line in proc.stdout.splitlines():
                    if line.strip():
                        yield line

            return tls_fields, _iter()
        except FileNotFoundError:
            print("ERROR: tshark not found in PATH.", file=sys.stderr)
            sys.exit(2)
        except subprocess.CalledProcessError as e:
            tried.append(info_field or "<no info col>")
            last_err = e
            err = (e.stderr or "")
            # If the only issue is an invalid info column, retry with alternate info field
            if "Some fields aren't valid" in err and info_field:
                continue
            print("ERROR: tshark failed while parsing TLS.", file=sys.stderr)
            if e.stderr:
                print(e.stderr.strip(), file=sys.stderr)
            sys.exit(2)

    print("ERROR: tshark failed while parsing TLS (tried info fields: %s)." % ", ".join(tried), file=sys.stderr)
    if last_err and last_err.stderr:
        print(last_err.stderr.strip(), file=sys.stderr)
    sys.exit(2)


def ingest_tls(pcap: str, aggs: Dict[Tuple[str, int], StreamAgg], display_filter: Optional[str]) -> None:
    '''
    Populate TLS counters on existing TCP StreamAggs.
    Works across tshark versions by adapting field names.
    '''
    fields, it = run_tshark_tls(pcap, display_filter=display_filter)

    idx = {name: i for i, name in enumerate(fields)}

    frame_name = "frame.number" if "frame.number" in fields else None
    epoch_name = "frame.time_epoch" if "frame.time_epoch" in fields else None
    hs_name = next((n for n in fields if n in ("tls.handshake.type", "ssl.handshake.type")), None)
    ctype_name = next((n for n in fields if n in ("tls.record.content_type", "ssl.record.content_type")), None)
    alert_msg_name = next((n for n in fields if n.startswith("tls.alert_message") or n.startswith("ssl.alert_message") or n in ("tls.alert_message", "ssl.alert_message")), None)
    alert_level_name = next((n for n in fields if n in ("tls.alert_level", "ssl.alert_level", "tls.alert_message.level", "ssl.alert_message.level")), None)

    proto_name = "frame.protocols" if "frame.protocols" in fields else None
    info_name = "_ws.col.Info" if "_ws.col.Info" in fields else ("_ws.col.info" if "_ws.col.info" in fields else None)

    for line in it:
        parts = line.split("	")
        if not parts or not parts[0]:
            continue

        sid_s = parts[0]
        try:
            sid = int(sid_s)
        except ValueError:
            continue

        key = ("TCP", sid)
        st = aggs.get(key)
        if not st:
            st = StreamAgg(proto="TCP", stream_id=sid, first_epoch=0.0, last_epoch=0.0,
                           first_frame=0, last_frame=0, pkts=0, bytes_total=0,
                           src_ip="", dst_ip="", src_port="", dst_port="")
            aggs[key] = st

        frame_no = 0
        frame_epoch = 0.0
        if frame_name is not None and idx.get(frame_name) is not None:
            j = idx[frame_name]
            if j < len(parts):
                try:
                    frame_no = int(parts[j]) if parts[j] else 0
                except ValueError:
                    frame_no = 0
        if epoch_name is not None and idx.get(epoch_name) is not None:
            j = idx[epoch_name]
            if j < len(parts):
                try:
                    frame_epoch = float(parts[j]) if parts[j] else 0.0
                except ValueError:
                    frame_epoch = 0.0


        # Fallback inference via column info (for older tshark builds missing tls.* fields)
        proto_s = ""
        if proto_name is not None and idx.get(proto_name) is not None:
            j = idx[proto_name]
            if j < len(parts) and parts[j]:
                proto_s = parts[j]

        info_s = ""
        if info_name is not None and idx.get(info_name) is not None:
            j = idx[info_name]
            if j < len(parts) and parts[j]:
                info_s = parts[j]

        # Normalize Info column so we can reliably detect events across tshark versions
        info_l = info_s.lower().strip()
        # Strip common bracketed prefixes e.g. "[TCP ZeroWindow] , Encrypted Alert"
        info_l = re.sub(r"^\[[^\]]+\]\s*,?\s*", "", info_l)
        # Also strip any leading punctuation left behind
        info_l = info_l.lstrip(" ,")

        saw_clienthello = False
        saw_serverhello = False
        saw_appdata = False
        saw_alert = False

        # Infer key events from Info column (most reliable on mac/older builds)
        if "client hello" in info_l:
            saw_clienthello = True
        if "server hello" in info_l:
            saw_serverhello = True
        if "application data" in info_l:
            saw_appdata = True

        # Alerts (plain or encrypted). We treat "alert (" and "encrypted alert" as alerts.
        if info_l.startswith("alert") or "alert (" in info_l or "encrypted alert" in info_l:
            saw_alert = True

        # Content types: 22=handshake, 21=alert, 23=application_data
        if ctype_name is not None and idx.get(ctype_name) is not None:
            i = idx[ctype_name]
            if i < len(parts):
                ctype_s = parts[i]
                if ctype_s:
                    try:
                        ctype = int(ctype_s)
                    except ValueError:
                        ctype = None
                    if ctype == 23:
                        saw_appdata = True
                    if ctype == 21:
                        saw_alert = True

        # Handshake types can be comma-separated
        if hs_name is not None and idx.get(hs_name) is not None:
            i = idx[hs_name]
            if i < len(parts):
                hs_type_s = parts[i]
                if hs_type_s:
                    for tok in str(hs_type_s).split(","):
                        tok = tok.strip()
                        if not tok:
                            continue
                        if tok == "1":
                            saw_clienthello = True
                        elif tok == "2":
                            saw_serverhello = True

        alert_seen = False
        if alert_msg_name is not None and idx.get(alert_msg_name) is not None:
            i = idx[alert_msg_name]
            if i < len(parts) and parts[i].strip():
                alert_seen = True
        if not alert_seen and alert_level_name is not None and idx.get(alert_level_name) is not None:
            i = idx[alert_level_name]
            if i < len(parts) and parts[i].strip():
                alert_seen = True

        if alert_seen:
            saw_alert = True

        if saw_clienthello:
            st.tls_clienthello_pkts += 1
            if frame_epoch and st.tls_first_clienthello_epoch == 0.0:
                st.tls_first_clienthello_epoch = frame_epoch
        if saw_serverhello:
            st.tls_serverhello_pkts += 1
            if frame_no and (st.tls_first_serverhello_frame == 0 or frame_no < st.tls_first_serverhello_frame):
                st.tls_first_serverhello_frame = frame_no
            if frame_epoch and st.tls_first_serverhello_epoch == 0.0:
                st.tls_first_serverhello_epoch = frame_epoch
        if saw_appdata:
            st.tls_appdata_pkts += 1
            if frame_no and (st.tls_first_appdata_frame == 0 or frame_no < st.tls_first_appdata_frame):
                st.tls_first_appdata_frame = frame_no
            if frame_epoch and st.tls_first_appdata_epoch == 0.0:
                st.tls_first_appdata_epoch = frame_epoch
        if saw_alert:
            st.tls_alert_pkts += 1
            if frame_no and (st.tls_first_alert_frame == 0 or frame_no < st.tls_first_alert_frame):
                st.tls_first_alert_frame = frame_no
            if frame_epoch and st.tls_first_alert_epoch == 0.0:
                st.tls_first_alert_epoch = frame_epoch


def build_ip_pair_summary(rows: List[StreamAgg]) -> List[dict]:
    """
    Returns list of dicts: {src_ip, dst_ip, unique_streams}
    Unique stream key is protocol:stream_id to avoid TCP/UDP collisions.
    """
    pair_sets: Dict[Tuple[str, str], set] = {}
    for st in rows:
        s = st.src_ip or ""
        d = st.dst_ip or ""
        if not s or not d:
            continue
        k = (s, d)
        if k not in pair_sets:
            pair_sets[k] = set()
        pair_sets[k].add(f"{st.proto}:{st.stream_id}")
    out = [{"src_ip": k[0], "dst_ip": k[1], "unique_streams": len(v)} for k, v in pair_sets.items()]
    out.sort(key=lambda r: (-r["unique_streams"], r["src_ip"], r["dst_ip"]))
    return out

def write_virtual_html(
    out_html: str,
    json_filename: str,
    title: str,
    pair_summary: List[dict],
    first_packet_ts: str,
    last_packet_ts: str,
) -> None:
    # Inline JSON for file:// compatibility on macOS
    with open(json_filename, "r", encoding="utf-8") as f:
        json_text = f.read()

    pair_json_text = json.dumps(pair_summary, ensure_ascii=False)

    def esc(x: str) -> str:
        return html.escape(x if x is not None else "")
    html_doc = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width,initial-scale=1" />
<title>__TITLE__</title>
<style>
:root {{
--row-h: 28px;
--bg: #f6f7f3;
--panel: #fffdf8;
--panel-2: #ffffff;
--border: #d8ddd4;
--head: rgba(250,251,247,.98);
--text: #172016;
--muted: #617062;
--accent: #0f766e;
--shadow: 0 10px 30px rgba(22, 34, 23, 0.08);
--radius: 16px;
--mono: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace;
--sans: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
}}
body {{
font-family: var(--sans);
margin: 0;
padding: 16px;
color: var(--text);
background:
radial-gradient(circle at top left, rgba(15,118,110,.14), transparent 28%),
radial-gradient(circle at top right, rgba(21,101,192,.10), transparent 26%),
linear-gradient(180deg, #f9fbf7, var(--bg));
}}
.topbar {{
display: flex;
justify-content: space-between;
align-items: flex-start;
gap: 18px;
margin-bottom: 10px;
}}
.titleblock {{
display: flex;
flex-direction: column;
gap: 4px;
min-width: 0;
}}
h1 {{ font-size: 25px; margin: 0; font-weight: 600; line-height: 1.2; }}
.submeta {{
font-size: 12px;
color: var(--muted);
display: flex;
flex-wrap: wrap;
gap: 16px;
line-height: 1.35;
}}
.submeta .label {{
font-weight: 600;
color: #536252;
margin-right: 4px;
}}
.toolbar-right {{
display: flex;
align-items: flex-start;
justify-content: flex-end;
flex: 0 0 auto;
}}
.bar {{
display: flex; flex-wrap: wrap; gap: 10px; align-items: center;
margin: 10px 0 12px;
}}
input[type="number"] {{
padding: 9px 10px; font-size: 14px; border: 1px solid var(--border); border-radius: 10px;
width: 140px;
background: rgba(255,255,255,.92);
}}
label {{ font-size: 13px; color: var(--muted); display: inline-flex; gap: 6px; align-items: center; }}
.meta {{ font-size: 13px; color: var(--muted); margin-bottom: 8px; }}
.chip {{
--chip: var(--accent);
font-size: 12px; padding: 8px 12px; border: 1px solid color-mix(in srgb, var(--chip) 28%, var(--border));
border-radius: 999px; background: color-mix(in srgb, var(--chip) 10%, white); cursor: pointer; user-select: none;
box-shadow: 0 3px 12px rgba(24, 36, 25, .05);
transition: transform .15s ease, box-shadow .15s ease, border-color .15s ease, background .15s ease;
}}
.chip:hover {{ transform: translateY(-1px); box-shadow: 0 10px 18px rgba(24, 36, 25, .08); }}
.chip.on {{
border-color: var(--chip) !important;
background: color-mix(in srgb, var(--chip) 18%, white) !important;
color: color-mix(in srgb, var(--chip) 80%, #102217) !important;
box-shadow: 0 10px 18px color-mix(in srgb, var(--chip) 16%, transparent) !important;
}}
.chip[data-cat="conn-refused"] {{ --chip: #d32f2f; }}
.chip[data-cat="client-abort"] {{ --chip: #ef6c00; }}
.chip[data-cat="conn-failed"] {{ --chip: #6a1b9a; }}
.chip[data-cat="retrans"] {{ --chip: #c2185b; }}
.chip[data-cat="retrans-heavy"] {{ --chip: #ad1457; }}
.chip[data-cat="zero-window"] {{ --chip: #00838f; }}
.chip[data-cat="window-full"] {{ --chip: #3949ab; }}
.chip[data-cat="long-idle"] {{ --chip: #7b1fa2; }}
.chip[data-cat="hs-incomplete"] {{ --chip: #f4511e; }}
.chip[data-cat="high-rtt"] {{ --chip: #2e7d32; }}
.chip[data-cat="spiky-rtt"] {{ --chip: #558b2f; }}
.chip[data-cat="tls-sh-missing"] {{ --chip: #6d4c41; }}
.chip[data-cat="high-pps-udp"] {{ --chip: #0277bd; }}
.chip[data-cat="tls-fail"] {{ --chip: #5d4037; }}
.badge {{
display: inline-block;
margin-left: 8px;
padding: 1px 7px;
border-radius: 999px;
border: 1px solid color-mix(in srgb, var(--chip) 20%, var(--border));
background: rgba(255,255,255,.92);
font-family: var(--mono);
font-size: 12px;
color: var(--text);
vertical-align: middle;
}}

/* Row highlights by failure type */
.row-refused {{ background: #fff0f0; }}
.row-failed  {{ background: #eef3ff; }}
.row-abort   {{ background: #fff6e8; }}
.row-tlsfail {{ background: #f8f0ff; }}
.row-retrans {{ background: #fff1f8; }}

/* Tooltip on chips */
.chip[data-tip] {{ position: relative; }}
.chip[data-tip]:hover::after {{
content: attr(data-tip);
position: absolute;
left: 0;
top: calc(100% + 8px);
z-index: 50;
max-width: 520px;
padding: 8px 10px;
border: 1px solid var(--border);
background: #fff;
border-radius: 10px;
box-shadow: var(--shadow);
color: #222;
font-size: 12px;
line-height: 1.35;
white-space: normal;
}}


.grid {{
display: grid;
grid-template-columns: 70px 70px 220px 90px 220px 90px 95px 95px 230px 230px 120px 90px 110px 70px 70px 70px 85px 90px 95px 95px 120px 95px 110px 95px 150px 150px 150px 150px 130px 110px 110px 170px 190px 170px 140px 170px 140px 140px 140px;
min-width: 5300px;
column-gap: 10px;
align-items: center;
padding: 0 10px;
height: var(--row-h);
border-bottom: 1px solid var(--border);
font-size: 13px;
white-space: nowrap;
overflow: hidden;
text-overflow: ellipsis;
}}
.grid > div {{
min-width: 0;
overflow: hidden;
text-overflow: ellipsis;
white-space: nowrap;
}}
.head {{
position: sticky; top: 0; z-index: 10;
background: var(--head);
border-top: 1px solid var(--border);
border-bottom: 1px solid var(--border);
font-weight: 600;
cursor: pointer;
user-select: none;
}}
.head > div {{
line-height: 1.15;
}}
.filters {{
top: 28px; /* second sticky row */
font-weight: 400;
cursor: default;
}}
.filters input {{
width: 100%;
box-sizing: border-box;
padding: 6px 8px;
font-size: 12px;
border: 1px solid var(--border);
border-radius: 8px;
background: rgba(255,255,255,.92);
}}
#header, #filters {{ will-change: transform; }}

.num {{ text-align: right; font-variant-numeric: tabular-nums; font-family: var(--mono); }}
.ts {{ font-family: var(--mono); font-size: 12px; }}
.wrap {{
border: 1px solid var(--border);
border-radius: var(--radius);
overflow-x: auto;
overflow-y: hidden;
background: var(--panel);
box-shadow: var(--shadow);
}}
#viewport {{
height: 70vh;
overflow: auto;
position: relative;
background: var(--panel);
}}
#spacer {{ height: 0px; }}
#rows {{
position: absolute;
top: 0; left: 0; right: 0;
}}
.hint {{ font-size: 12px; color: var(--muted); margin-top: 8px; }}
.right {{ margin-left: auto; }}
button {{
border: 1px solid var(--border); background: var(--panel-2); padding: 8px 10px;
border-radius: 10px; cursor: pointer; font-size: 13px;
}}
@media (max-width: 980px) {{
  .topbar {{
    flex-direction: column;
    align-items: stretch;
  }}
  .toolbar-right {{
    justify-content: flex-start;
  }}
}}
</style>
</head>
<body>
<div class="topbar">
  <div class="titleblock">
    <h1>__TITLE__</h1>
    <div class="submeta">
      <div><span class="label">First Packet Timestamp:</span> __FIRST_PACKET_TS__</div>
      <div><span class="label">Last Packet Timestamp:</span> __LAST_PACKET_TS__</div>
    </div>
  </div>
  <div class="toolbar-right">
    <label>Min duration (sec)
    <input id="minDur" type="number" min="0" step="1" value="0" />
    </label>
  </div>
</div>

<div class="bar">
<div id="chipConnRefused" class="chip" data-cat="conn-refused" data-tip="Connection refused: client SYN gets an immediate RST (port closed / actively refused).">
Connection refused (SYN → RST) <span id="badgeConnRefused" class="badge">0</span>
</div>
<div id="chipClientAbort" class="chip" data-cat="client-abort" data-tip="Client abort: SYN and SYN-ACK observed, then client sends a pure RST (no ACK).">
Client abort (SYN-ACK → RST) <span id="badgeClientAbort" class="badge">0</span>
</div>
<div id="chipConnFailed" class="chip" data-cat="conn-failed" data-tip="Connection failed: SYN observed, SYN-ACK observed and retransmitted (synack>=2). RST may or may not appear; handshake never completes.">
Connection failed (SYN → SYN-ACK retransmits) <span id="badgeConnFailed" class="badge">0</span>
</div>
<div id="chipRetrans" class="chip" data-cat="retrans" data-tip="Retransmissions detected in the stream using tcp.analysis.retransmission.">
Retransmissions <span id="badgeRetrans" class="badge">0</span>
</div>
<div id="chipRetransHeavy" class="chip" data-cat="retrans-heavy" data-tip="TCP retransmission heavy: more than 2 retransmission packets in the stream.">
Retrans Heavy <span id="badgeRetransHeavy" class="badge">0</span>
</div>
<div id="chipZeroWindow" class="chip" data-cat="zero-window" data-tip="Receiver advertised zero window in the stream.">
Zero Window <span id="badgeZeroWindow" class="badge">0</span>
</div>
<div id="chipWindowFull" class="chip" data-cat="window-full" data-tip="Receiver window became full in the stream.">
Window Full <span id="badgeWindowFull" class="badge">0</span>
</div>
<div id="chipLongIdle" class="chip" data-cat="long-idle" data-tip="Long idle stream: max inter-packet gap is at least 30 seconds.">
Long Idle <span id="badgeLongIdle" class="badge">0</span>
</div>
<div id="chipHandshakeIncomplete" class="chip" data-cat="hs-incomplete" data-tip="Handshake incomplete: handshake started but did not progress into a fuller session pattern.">
HS Incomplete <span id="badgeHandshakeIncomplete" class="badge">0</span>
</div>
<div id="chipHighRtt" class="chip" data-cat="high-rtt" data-tip="High RTT: stream has ACK RTT at or above 200 ms.">
High RTT <span id="badgeHighRtt" class="badge">0</span>
</div>
<div id="chipSpikyRtt" class="chip" data-cat="spiky-rtt" data-tip="Spiky RTT: RTT spread is elevated across multiple RTT samples.">
Spiky RTT <span id="badgeSpikyRtt" class="badge">0</span>
</div>
<div id="chipTlsShMissing" class="chip" data-cat="tls-sh-missing" data-tip="TLS ClientHello seen but no TLS ServerHello observed.">
TLS SH Missing <span id="badgeTlsShMissing" class="badge">0</span>
</div>
<div id="chipHighPpsUdp" class="chip" data-cat="high-pps-udp" data-tip="High PPS UDP: average packets per second for the UDP stream is high.">
High PPS UDP <span id="badgeHighPpsUdp" class="badge">0</span>
</div>
<div id="chipTlsFail" class="chip" data-cat="tls-fail" data-tip="ClientHello seen but TLS handshake does not complete (no app data; alert or no ServerHello).">TLS handshake failed <span class="badge" id="badgeTlsFail">0</span></div>
</div>

<h2 style="font-size:15px;margin:14px 0 8px;">IP Pair Summary (unique streams)</h2>
<div class="wrap" style="margin-bottom:14px;">
<div style="padding:10px; display:flex; gap:10px; align-items:center; flex-wrap:wrap;">
<label style="margin:0;">Show top
<input id="pairTopN" type="number" min="10" step="10" value="200" style="width:110px;" />
</label>
<div class="meta">Sorted by <b id="pairSortBy">unique_streams</b> <b id="pairSortDir">↓</b>
&nbsp; | &nbsp; Showing <b id="pairShown">0</b> / <b id="pairTotal">0</b>
</div>
</div>
<div style="overflow:auto; max-height:35vh; border-top:1px solid var(--border);">
<table id="pairTable" style="width:100%; border-collapse:collapse; font-size:13px;">
<thead>
<tr style="background:var(--head); position:sticky; top:0; z-index:5; cursor:pointer;">
<th data-k="src_ip" style="text-align:left; padding:8px 10px; border-bottom:1px solid var(--border);">Source IP</th>
<th data-k="dst_ip" style="text-align:left; padding:8px 10px; border-bottom:1px solid var(--border);">Destination IP</th>
<th data-k="unique_streams" style="text-align:right; padding:8px 10px; border-bottom:1px solid var(--border);">Unique Streams</th>
</tr>
</thead>
<tbody></tbody>
</table>
</div>
</div>

<div class="meta" style="margin:10px 0 8px;">
Showing <b id="shown">0</b> / <b id="total">0</b>
&nbsp; | &nbsp; Sorted by <b id="sortBy">protocol</b> <b id="sortDir">↑</b>
</div>


<div class="wrap">
<div id="header" class="grid head" title="Click a column to sort">
<div data-k="protocol">Protocol</div>
<div class="num" data-k="stream_id">Stream</div>
<div data-k="src_ip">Source IP</div>
<div class="num" data-k="src_port">Src Port</div>
<div data-k="dst_ip">Destination IP</div>
<div class="num" data-k="dst_port">Dst Port</div>
<div class="num" data-k="first_frame">First Frme</div>
<div class="num" data-k="last_frame">Last Frme</div>
<div data-k="first_ts">First TS</div>
<div data-k="last_ts">Last TS</div>
<div class="num" data-k="duration_sec">Duration(s)</div>
<div class="num" data-k="packets">Pkts</div>
<div class="num" data-k="bytes_total">Bytes</div>
<div class="num" data-k="syn_pkts">SYN</div>
<div class="num" data-k="rst_pkts">RST</div>
<div class="num" data-k="ack_pkts">ACK</div>
<div class="num" data-k="synack_pkts">SYN-ACK</div>
<div class="num" data-k="retrans_pkts">Retrans</div>
<div class="num" data-k="zero_window_pkts">ZeroWin</div>
<div class="num" data-k="window_full_pkts">WinFull</div>
<div class="num" data-k="max_interpacket_gap_sec">Max Gap(s)</div>
<div class="num" data-k="ack_rtt_samples">RTT Samp</div>
<div class="num" data-k="ack_rtt_max_ms">RTT Max(ms)</div>
<div class="num" data-k="ack_rtt_spread_ms">RTT Spread(ms)</div>
<div class="num" data-k="avg_pps">Avg PPS</div>
<div data-k="conn_refused_syn_rst">Conn Refused</div>
<div data-k="client_abort_after_synack">Client Abort</div>
<div data-k="conn_failed_ackretrans_rst">Conn Failed</div>
<div data-k="has_retransmissions">Has Retrans</div>
<div data-k="retransmission_heavy">Retrans Heavy</div>
<div data-k="zero_window_stream">Zero Window</div>
<div data-k="window_full_stream">Window Full</div>
<div data-k="long_idle_stream">Long Idle</div>
<div data-k="handshake_incomplete">HS Incomplete</div>
<div data-k="high_rtt">High RTT</div>
<div data-k="spiky_rtt">Spiky RTT</div>
<div data-k="tls_serverhello_missing">TLS SH Missing</div>
<div data-k="high_pps_udp">High PPS UDP</div>
<div data-k="tls_handshake_failed">TLS Fail</div>
</div>

<div id="filters" class="grid head filters" title="Per-column filters: text=contains, numeric=exact or min..max">
<div><input data-f="protocol" placeholder="TCP/UDP" /></div>
<div><input data-f="stream_id" placeholder="1562 or 100..200" /></div>
<div><input data-f="src_ip" placeholder="contains" /></div>
<div><input data-f="src_port" placeholder="443 or 1..1024" /></div>
<div><input data-f="dst_ip" placeholder="contains" /></div>
<div><input data-f="dst_port" placeholder="8443" /></div>
<div><input data-f="first_frame" placeholder="min..max" /></div>
<div><input data-f="last_frame" placeholder="min..max" /></div>
<div><input data-f="first_ts" placeholder="contains" /></div>
<div><input data-f="last_ts" placeholder="contains" /></div>
<div><input data-f="duration_sec" placeholder="60.. or ..120" /></div>
<div><input data-f="packets" placeholder="1..10" /></div>
<div><input data-f="bytes_total" placeholder="min..max" /></div>
<div><input data-f="syn_pkts" placeholder="min..max" /></div>
<div><input data-f="rst_pkts" placeholder="min..max" /></div>
<div><input data-f="ack_pkts" placeholder="min..max" /></div>
<div><input data-f="synack_pkts" placeholder="min..max" /></div>
<div><input data-f="retrans_pkts" placeholder="min..max" /></div>
<div><input data-f="zero_window_pkts" placeholder="min..max" /></div>
<div><input data-f="window_full_pkts" placeholder="min..max" /></div>
<div><input data-f="max_interpacket_gap_sec" placeholder="min..max" /></div>
<div><input data-f="ack_rtt_samples" placeholder="min..max" /></div>
<div><input data-f="ack_rtt_max_ms" placeholder="min..max" /></div>
<div><input data-f="ack_rtt_spread_ms" placeholder="min..max" /></div>
<div><input data-f="avg_pps" placeholder="min..max" /></div>
<div><input data-f="conn_refused_syn_rst" placeholder="true/false" /></div>
<div><input data-f="client_abort_after_synack" placeholder="true/false" /></div>
<div><input data-f="conn_failed_ackretrans_rst" placeholder="true/false" /></div>
<div><input data-f="has_retransmissions" placeholder="true/false" /></div>
<div><input data-f="retransmission_heavy" placeholder="true/false" /></div>
<div><input data-f="zero_window_stream" placeholder="true/false" /></div>
<div><input data-f="window_full_stream" placeholder="true/false" /></div>
<div><input data-f="long_idle_stream" placeholder="true/false" /></div>
<div><input data-f="handshake_incomplete" placeholder="true/false" /></div>
<div><input data-f="high_rtt" placeholder="true/false" /></div>
<div><input data-f="spiky_rtt" placeholder="true/false" /></div>
<div><input data-f="tls_serverhello_missing" placeholder="true/false" /></div>
<div><input data-f="high_pps_udp" placeholder="true/false" /></div>
<div><input data-f="tls_handshake_failed" placeholder="true/false" /></div>
</div>

<div id="viewport">
<div id="spacer"></div>
<div id="rows"></div>
</div>
</div>

<div class="hint">
• Click headers to sort ascending/descending. <br/>
• Column filters: numeric supports <b>10..20</b>, <b>10..</b>, <b>..20</b>, or exact <b>1562</b>. Text is “contains”. <br/>
</div>

<div style="margin-top:16px; font-size:12px; color:var(--muted); text-align:right;">
Version __SCRIPT_VERSION__ | Developed By: Mallikarjun Immadi
</div>

<script id="data" type="application/json">__JSON_TEXT__</script>
<script id="pairSummary" type="application/json">__PAIR_JSON_TEXT__</script>

<script>
(() => {{
const data = JSON.parse(document.getElementById('data').textContent);
const pairSummary = JSON.parse(document.getElementById('pairSummary').textContent);

const minDurEl = document.getElementById('minDur');
const chipConnRefused = document.getElementById('chipConnRefused');
const chipClientAbort = document.getElementById('chipClientAbort');
const chipConnFailed = document.getElementById(\'chipConnFailed\');
const chipRetrans = document.getElementById('chipRetrans');
const chipRetransHeavy = document.getElementById('chipRetransHeavy');
const chipZeroWindow = document.getElementById('chipZeroWindow');
const chipWindowFull = document.getElementById('chipWindowFull');
const chipLongIdle = document.getElementById('chipLongIdle');
const chipHandshakeIncomplete = document.getElementById('chipHandshakeIncomplete');
const chipHighRtt = document.getElementById('chipHighRtt');
const chipSpikyRtt = document.getElementById('chipSpikyRtt');
const chipTlsShMissing = document.getElementById('chipTlsShMissing');
const chipHighPpsUdp = document.getElementById('chipHighPpsUdp');
const chipTlsFail = document.getElementById('chipTlsFail');
const badgeConnRefused = document.getElementById('badgeConnRefused');
const badgeClientAbort = document.getElementById('badgeClientAbort');
const badgeConnFailed = document.getElementById('badgeConnFailed');
const badgeRetrans = document.getElementById('badgeRetrans');
const badgeRetransHeavy = document.getElementById('badgeRetransHeavy');
const badgeZeroWindow = document.getElementById('badgeZeroWindow');
const badgeWindowFull = document.getElementById('badgeWindowFull');
const badgeLongIdle = document.getElementById('badgeLongIdle');
const badgeHandshakeIncomplete = document.getElementById('badgeHandshakeIncomplete');
const badgeHighRtt = document.getElementById('badgeHighRtt');
const badgeSpikyRtt = document.getElementById('badgeSpikyRtt');
const badgeTlsShMissing = document.getElementById('badgeTlsShMissing');
const badgeHighPpsUdp = document.getElementById('badgeHighPpsUdp');
const badgeTlsFail = document.getElementById('badgeTlsFail');

const totalEl = document.getElementById('total');
const shownEl = document.getElementById('shown');
const sortByEl = document.getElementById('sortBy');
const sortDirEl = document.getElementById('sortDir');

const viewport = document.getElementById('viewport');
const spacer = document.getElementById('spacer');
const rowsEl = document.getElementById('rows');
const header = document.getElementById('header');
const filters = document.getElementById('filters');
const filterInputs = Array.from(document.querySelectorAll('#filters input'));

totalEl.textContent = String(data.length);

function setBadges() {{
let cRef=0, cAbort=0, cFail=0, cRetrans=0, cRetransHeavy=0, cZeroWindow=0, cWindowFull=0, cLongIdle=0, cHsIncomplete=0, cHighRtt=0, cSpikyRtt=0, cTlsShMissing=0, cHighPpsUdp=0, cTls=0;
for (const r of data) {{
if (r.protocol === 'TCP' && r.conn_refused_syn_rst) cRef++;
if (r.protocol === 'TCP' && r.client_abort_after_synack) cAbort++;
if (r.protocol === 'TCP' && r.conn_failed_ackretrans_rst) cFail++;
if (r.protocol === 'TCP' && r.has_retransmissions) cRetrans++;
if (r.protocol === 'TCP' && r.retransmission_heavy) cRetransHeavy++;
if (r.protocol === 'TCP' && r.zero_window_stream) cZeroWindow++;
if (r.protocol === 'TCP' && r.window_full_stream) cWindowFull++;
if (r.long_idle_stream) cLongIdle++;
if (r.protocol === 'TCP' && r.handshake_incomplete) cHsIncomplete++;
if (r.protocol === 'TCP' && r.high_rtt) cHighRtt++;
if (r.protocol === 'TCP' && r.spiky_rtt) cSpikyRtt++;
if (r.protocol === 'TCP' && r.tls_serverhello_missing) cTlsShMissing++;
if (r.protocol === 'UDP' && r.high_pps_udp) cHighPpsUdp++;
if (r.protocol === 'TCP' && r.tls_handshake_failed) cTls++;
}}
if (badgeConnRefused) badgeConnRefused.textContent = String(cRef);
if (badgeClientAbort) badgeClientAbort.textContent = String(cAbort);
if (badgeConnFailed) badgeConnFailed.textContent = String(cFail);
if (badgeRetrans) badgeRetrans.textContent = String(cRetrans);
if (badgeRetransHeavy) badgeRetransHeavy.textContent = String(cRetransHeavy);
if (badgeZeroWindow) badgeZeroWindow.textContent = String(cZeroWindow);
if (badgeWindowFull) badgeWindowFull.textContent = String(cWindowFull);
if (badgeLongIdle) badgeLongIdle.textContent = String(cLongIdle);
if (badgeHandshakeIncomplete) badgeHandshakeIncomplete.textContent = String(cHsIncomplete);
if (badgeHighRtt) badgeHighRtt.textContent = String(cHighRtt);
if (badgeSpikyRtt) badgeSpikyRtt.textContent = String(cSpikyRtt);
if (badgeTlsShMissing) badgeTlsShMissing.textContent = String(cTlsShMissing);
if (badgeHighPpsUdp) badgeHighPpsUdp.textContent = String(cHighPpsUdp);
if (badgeTlsFail) badgeTlsFail.textContent = String(cTls);
}}

// --- IP Pair Summary table ---
const pairTopNEl = document.getElementById('pairTopN');
const pairSortByEl = document.getElementById('pairSortBy');
const pairSortDirEl = document.getElementById('pairSortDir');
const pairShownEl = document.getElementById('pairShown');
const pairTotalEl = document.getElementById('pairTotal');
const pairTable = document.getElementById('pairTable');
const pairTbody = pairTable ? pairTable.querySelector('tbody') : null;

let pairSortKey = 'unique_streams';
let pairSortAsc = false;

function sortPairs() {{
if (!pairSummary) return;
pairSummary.sort((a,b) => {{
const va = a[pairSortKey];
const vb = b[pairSortKey];
let c = 0;
if (pairSortKey === 'unique_streams') {{
const na = Number(va), nb = Number(vb);
c = (na === nb) ? 0 : (na < nb ? -1 : 1);
}} else {{
c = cmp(String(va), String(vb));
}}
return pairSortAsc ? c : -c;
}});
if (pairSortByEl) pairSortByEl.textContent = pairSortKey;
if (pairSortDirEl) pairSortDirEl.textContent = pairSortAsc ? '↑' : '↓';
}}

function renderPairs() {{
if (!pairTbody) return;
const topN = Math.max(0, Number(pairTopNEl.value || 0));
const limit = topN > 0 ? Math.min(topN, pairSummary.length) : pairSummary.length;

pairTbody.textContent = '';
const frag = document.createDocumentFragment();
for (let i=0; i<limit; i++) {{
const r = pairSummary[i];
const tr = document.createElement('tr');
tr.innerHTML = `
<td style="padding:6px 10px; border-bottom:1px solid var(--border);">${{escapeHtml(r.src_ip)}}</td>
<td style="padding:6px 10px; border-bottom:1px solid var(--border);">${{escapeHtml(r.dst_ip)}}</td>
<td style="padding:6px 10px; border-bottom:1px solid var(--border); text-align:right; font-family: var(--mono);">${{r.unique_streams}}</td>
`;
frag.appendChild(tr);
}}
pairTbody.appendChild(frag);

if (pairTotalEl) pairTotalEl.textContent = String(pairSummary.length);
if (pairShownEl) pairShownEl.textContent = String(limit);
}}


const ROW_H = parseInt(getComputedStyle(document.documentElement).getPropertyValue('--row-h'), 10) || 28;
const OVERSCAN = 10;

let sortKey = 'protocol';
let sortAsc = true;

let failureFilter = "none";

function setFailureFilter(mode) {{
// mode: "none" | "connRefused" | "clientAbort" | "connFailed" | "retrans" | "retransHeavy" | "zeroWindow" | "windowFull" | "longIdle" | "hsIncomplete" | "highRtt" | "spikyRtt" | "tlsShMissing" | "highPpsUdp" | "tlsFail"
failureFilter = mode;
chipConnRefused.classList.toggle("on", failureFilter === "connRefused");
chipClientAbort.classList.toggle("on", failureFilter === "clientAbort");
chipConnFailed.classList.toggle("on", failureFilter === "connFailed");
if (chipRetrans) chipRetrans.classList.toggle("on", failureFilter === "retrans");
if (chipRetransHeavy) chipRetransHeavy.classList.toggle("on", failureFilter === "retransHeavy");
if (chipZeroWindow) chipZeroWindow.classList.toggle("on", failureFilter === "zeroWindow");
if (chipWindowFull) chipWindowFull.classList.toggle("on", failureFilter === "windowFull");
if (chipLongIdle) chipLongIdle.classList.toggle("on", failureFilter === "longIdle");
if (chipHandshakeIncomplete) chipHandshakeIncomplete.classList.toggle("on", failureFilter === "hsIncomplete");
if (chipHighRtt) chipHighRtt.classList.toggle("on", failureFilter === "highRtt");
if (chipSpikyRtt) chipSpikyRtt.classList.toggle("on", failureFilter === "spikyRtt");
if (chipTlsShMissing) chipTlsShMissing.classList.toggle("on", failureFilter === "tlsShMissing");
if (chipHighPpsUdp) chipHighPpsUdp.classList.toggle("on", failureFilter === "highPpsUdp");
if (chipTlsFail) chipTlsFail.classList.toggle("on", failureFilter === "tlsFail");
viewport.scrollTop = 0;
applyFilters();
}}

let viewIdx = Array.from({{length: data.length}}, (_, i) => i);

function cmp(a, b) {{
if (a === b) return 0;
return a < b ? -1 : 1;
}}

function sortView() {{
const numKeys = new Set(['stream_id','first_frame','last_frame','duration_sec','packets','bytes_total','syn_pkts','rst_pkts','ack_pkts','synack_pkts','retrans_pkts','zero_window_pkts','window_full_pkts','max_interpacket_gap_sec','ack_rtt_samples','ack_rtt_max_ms','ack_rtt_spread_ms','avg_pps','src_port','dst_port']);
viewIdx.sort((ia, ib) => {{
const A = data[ia], B = data[ib];
const va = A[sortKey];
const vb = B[sortKey];

let c = 0;
if (numKeys.has(sortKey)) {{
const na = Number(va), nb = Number(vb);
c = (na === nb) ? 0 : (na < nb ? -1 : 1);
}} else {{
c = cmp(String(va), String(vb));
}}
return sortAsc ? c : -c;
}});
sortByEl.textContent = sortKey;
sortDirEl.textContent = sortAsc ? '↑' : '↓';
}}

function parseRange(s) {{
const t = (s || '').trim();
if (!t) return null;

if (t.includes('..')) {{
const [a, b] = t.split('..', 2).map(x => x.trim());
const min = a === '' ? null : Number(a);
const max = b === '' ? null : Number(b);
if ((min !== null && Number.isNaN(min)) || (max !== null && Number.isNaN(max))) return null;
return {{ type: 'range', min, max }};
}}

const n = Number(t);
if (!Number.isNaN(n)) return {{ type: 'exact', val: n }};

return {{ type: 'text', val: t.toLowerCase() }};
}}

function matchRange(val, spec) {{
const n = Number(val);
if (Number.isNaN(n)) return false;
if (spec.type === 'exact') return n === spec.val;
if (spec.type === 'range') {{
if (spec.min !== null && n < spec.min) return false;
if (spec.max !== null && n > spec.max) return false;
return true;
}}
return false;
}}

function matchText(val, spec) {{
return String(val ?? '').toLowerCase().includes(spec.val);
}}

function buildColumnFilters() {{
const out = [];
for (const inp of filterInputs) {{
const key = inp.getAttribute('data-f');
const spec = parseRange(inp.value);
if (!spec) continue;
out.push({{ key, spec }});
}}
return out;
}}

function resizeSpacer() {{
spacer.style.height = (viewIdx.length * ROW_H) + 'px';
}}

function escapeHtml(s) {{
return String(s)
.replaceAll('&','&amp;')
.replaceAll('<','&lt;')
.replaceAll('>','&gt;')
.replaceAll('"','&quot;')
.replaceAll("'","&#039;");
}}

function makeRow(r) {{
const div = document.createElement('div');
let rowCls = 'grid';
if (r.protocol === 'TCP') {{
// Color TLS failures as primary highlight
if (r.tls_handshake_failed) rowCls += ' row-tlsfail';
else if (r.has_retransmissions) rowCls += ' row-retrans';
else if (r.conn_refused_syn_rst) rowCls += ' row-refused';
else if (r.conn_failed_ackretrans_rst) rowCls += ' row-failed';
else if (r.client_abort_after_synack) rowCls += ' row-abort';
}}
div.className = rowCls;
div.innerHTML = `
<div>${{escapeHtml(r.protocol)}}</div>
<div class="num">${{r.stream_id}}</div>
<div>${{escapeHtml(r.src_ip)}}</div>
<div class="num">${{escapeHtml(String(r.src_port))}}</div>
<div>${{escapeHtml(r.dst_ip)}}</div>
<div class="num">${{escapeHtml(String(r.dst_port))}}</div>
<div class="num">${{r.first_frame}}</div>
<div class="num">${{r.last_frame}}</div>
<div class="ts">${{escapeHtml(r.first_ts)}}</div>
<div class="ts">${{escapeHtml(r.last_ts)}}</div>
<div class="num">${{Number(r.duration_sec).toFixed(6)}}</div>
<div class="num">${{r.packets}}</div>
<div class="num">${{r.bytes_total}}</div>
<div class="num">${{r.syn_pkts}}</div>
<div class="num">${{r.rst_pkts}}</div>
<div class="num">${{r.ack_pkts}}</div>
<div class="num">${{r.synack_pkts}}</div>
<div class="num">${{r.retrans_pkts}}</div>
<div class="num">${{r.zero_window_pkts}}</div>
<div class="num">${{r.window_full_pkts}}</div>
<div class="num">${{Number(r.max_interpacket_gap_sec).toFixed(6)}}</div>
<div class="num">${{r.ack_rtt_samples}}</div>
<div class="num">${{Number(r.ack_rtt_max_ms).toFixed(3)}}</div>
<div class="num">${{Number(r.ack_rtt_spread_ms).toFixed(3)}}</div>
<div class="num">${{Number(r.avg_pps).toFixed(3)}}</div>
<div>${{r.conn_refused_syn_rst ? 'TRUE' : 'FALSE'}}</div>
<div>${{r.client_abort_after_synack ? 'TRUE' : 'FALSE'}}</div>
<div>${{r.conn_failed_ackretrans_rst ? 'TRUE' : 'FALSE'}}</div>
<div>${{r.has_retransmissions ? 'TRUE' : 'FALSE'}}</div>
<div>${{r.retransmission_heavy ? 'TRUE' : 'FALSE'}}</div>
<div>${{r.zero_window_stream ? 'TRUE' : 'FALSE'}}</div>
<div>${{r.window_full_stream ? 'TRUE' : 'FALSE'}}</div>
<div>${{r.long_idle_stream ? 'TRUE' : 'FALSE'}}</div>
<div>${{r.handshake_incomplete ? 'TRUE' : 'FALSE'}}</div>
<div>${{r.high_rtt ? 'TRUE' : 'FALSE'}}</div>
<div>${{r.spiky_rtt ? 'TRUE' : 'FALSE'}}</div>
<div>${{r.tls_serverhello_missing ? 'TRUE' : 'FALSE'}}</div>
<div>${{r.high_pps_udp ? 'TRUE' : 'FALSE'}}</div>
<div>${{r.tls_handshake_failed ? 'TRUE' : 'FALSE'}}</div>
`;
return div;
}}

function render() {{
const scrollTop = viewport.scrollTop;
const h = viewport.clientHeight;

const start = Math.max(0, Math.floor(scrollTop / ROW_H) - OVERSCAN);
const end = Math.min(viewIdx.length, Math.ceil((scrollTop + h) / ROW_H) + OVERSCAN);

const topPx = start * ROW_H;
rowsEl.style.transform = `translateY(${{topPx}}px)`;

rowsEl.textContent = '';
const frag = document.createDocumentFragment();
for (let i = start; i < end; i++) {{
const idx = viewIdx[i];
frag.appendChild(makeRow(data[idx]));
}}
rowsEl.appendChild(frag);
}}

function syncHeaderX() {{
const x = viewport.scrollLeft || 0;
// Move header & filter rows opposite to the body scroll so columns stay aligned
header.style.transform = 'translateX(' + (-x) + 'px)';
filters.style.transform = 'translateX(' + (-x) + 'px)';
}}


let t = null;
function debounceApply() {{
if (t) clearTimeout(t);
t = setTimeout(applyFilters, 160);
}}

function applyFilters() {{
const minDur = Number(minDurEl.value || 0);
const colFilters = buildColumnFilters();

const out = [];
for (let i = 0; i < data.length; i++) {{
const r = data[i];

if (minDur > 0 && Number(r.duration_sec) < minDur) continue;

if (failureFilter === 'connRefused') {{
if (r.protocol !== 'TCP') continue;
if (!r.conn_refused_syn_rst) continue;
}} else if (failureFilter === 'clientAbort') {{
if (r.protocol !== 'TCP') continue;
if (!r.client_abort_after_synack) continue;
}} else if (failureFilter === 'connFailed') {{
if (r.protocol !== 'TCP') continue;
if (!r.conn_failed_ackretrans_rst) continue;
}} else if (failureFilter === 'retrans') {{
if (r.protocol !== 'TCP') continue;
if (!r.has_retransmissions) continue;
}} else if (failureFilter === 'retransHeavy') {{
if (r.protocol !== 'TCP') continue;
if (!r.retransmission_heavy) continue;
}} else if (failureFilter === 'zeroWindow') {{
if (r.protocol !== 'TCP') continue;
if (!r.zero_window_stream) continue;
}} else if (failureFilter === 'windowFull') {{
if (r.protocol !== 'TCP') continue;
if (!r.window_full_stream) continue;
}} else if (failureFilter === 'longIdle') {{
if (!r.long_idle_stream) continue;
}} else if (failureFilter === 'hsIncomplete') {{
if (r.protocol !== 'TCP') continue;
if (!r.handshake_incomplete) continue;
}} else if (failureFilter === 'highRtt') {{
if (r.protocol !== 'TCP') continue;
if (!r.high_rtt) continue;
}} else if (failureFilter === 'spikyRtt') {{
if (r.protocol !== 'TCP') continue;
if (!r.spiky_rtt) continue;
}} else if (failureFilter === 'tlsShMissing') {{
if (r.protocol !== 'TCP') continue;
if (!r.tls_serverhello_missing) continue;
}} else if (failureFilter === 'highPpsUdp') {{
if (r.protocol !== 'UDP') continue;
if (!r.high_pps_udp) continue;
}} else if (failureFilter === 'tlsFail') {{
if (r.protocol !== 'TCP') continue;
if (!r.tls_handshake_failed) continue;
}}

let ok = true;
for (const f of colFilters) {{
const v = r[f.key];

if (f.key === 'conn_refused_syn_rst' || f.key === 'client_abort_after_synack' || f.key === 'conn_failed_ackretrans_rst' || f.key === 'has_retransmissions' || f.key === 'retransmission_heavy' || f.key === 'zero_window_stream' || f.key === 'window_full_stream' || f.key === 'long_idle_stream' || f.key === 'handshake_incomplete' || f.key === 'high_rtt' || f.key === 'spiky_rtt' || f.key === 'tls_serverhello_missing' || f.key === 'high_pps_udp' || f.key === 'tls_handshake_failed') {{
const vv = String(!!v).toLowerCase();
if (f.spec.type === 'text') {{
if (!vv.includes(f.spec.val)) {{ ok = false; break; }}
}} else {{
// allow "1" or "0" as exact
const want = (f.spec.type === 'exact' && f.spec.val === 1) ? 'true' :
(f.spec.type === 'exact' && f.spec.val === 0) ? 'false' : null;
if (want && vv !== want) {{ ok = false; break; }}
}}
continue;
}}

if (f.spec.type === 'text') {{
if (!matchText(v, f.spec)) {{ ok = false; break; }}
}} else {{
if (!matchRange(v, f.spec)) {{ ok = false; break; }}
}}
}}
if (!ok) continue;

out.push(i);
}}

viewIdx = out;
sortView();
resizeSpacer();
render();
shownEl.textContent = String(viewIdx.length);
}}

// listeners
minDurEl.addEventListener('input', debounceApply);
filterInputs.forEach(inp => inp.addEventListener('input', debounceApply));

if (pairTopNEl) pairTopNEl.addEventListener('input', () => {{ renderPairs(); }});

if (pairTable) {{
pairTable.querySelectorAll('th[data-k]').forEach(th => {{
th.addEventListener('click', () => {{
const k = th.getAttribute('data-k');
if (!k) return;
if (pairSortKey === k) {{
pairSortAsc = !pairSortAsc;
}} else {{
pairSortKey = k;
// default: counts descending, strings ascending
pairSortAsc = (k !== 'unique_streams');
}}
sortPairs();
renderPairs();
}});
}});
}}

chipConnRefused.addEventListener('click', () => {{
// mutually exclusive toggle
setFailureFilter(failureFilter === 'connRefused' ? 'none' : 'connRefused');
}});

chipClientAbort.addEventListener('click', () => {{
// mutually exclusive toggle
setFailureFilter(failureFilter === 'clientAbort' ? 'none' : 'clientAbort');
}});

chipConnFailed.addEventListener('click', () => {{
// mutually exclusive toggle
setFailureFilter(failureFilter === 'connFailed' ? 'none' : 'connFailed');
}});

if (chipRetrans) {{
  chipRetrans.addEventListener('click', () => {{
    setFailureFilter(failureFilter === 'retrans' ? 'none' : 'retrans');
  }});
}}

if (chipRetransHeavy) {{
  chipRetransHeavy.addEventListener('click', () => {{
    setFailureFilter(failureFilter === 'retransHeavy' ? 'none' : 'retransHeavy');
  }});
}}

if (chipZeroWindow) {{
  chipZeroWindow.addEventListener('click', () => {{
    setFailureFilter(failureFilter === 'zeroWindow' ? 'none' : 'zeroWindow');
  }});
}}

if (chipWindowFull) {{
  chipWindowFull.addEventListener('click', () => {{
    setFailureFilter(failureFilter === 'windowFull' ? 'none' : 'windowFull');
  }});
}}

if (chipLongIdle) {{
  chipLongIdle.addEventListener('click', () => {{
    setFailureFilter(failureFilter === 'longIdle' ? 'none' : 'longIdle');
  }});
}}

if (chipHandshakeIncomplete) {{
  chipHandshakeIncomplete.addEventListener('click', () => {{
    setFailureFilter(failureFilter === 'hsIncomplete' ? 'none' : 'hsIncomplete');
  }});
}}

if (chipHighRtt) {{
  chipHighRtt.addEventListener('click', () => {{
    setFailureFilter(failureFilter === 'highRtt' ? 'none' : 'highRtt');
  }});
}}

if (chipSpikyRtt) {{
  chipSpikyRtt.addEventListener('click', () => {{
    setFailureFilter(failureFilter === 'spikyRtt' ? 'none' : 'spikyRtt');
  }});
}}

if (chipTlsShMissing) {{
  chipTlsShMissing.addEventListener('click', () => {{
    setFailureFilter(failureFilter === 'tlsShMissing' ? 'none' : 'tlsShMissing');
  }});
}}

if (chipHighPpsUdp) {{
  chipHighPpsUdp.addEventListener('click', () => {{
    setFailureFilter(failureFilter === 'highPpsUdp' ? 'none' : 'highPpsUdp');
  }});
}}

if (chipTlsFail) {{
  chipTlsFail.addEventListener('click', () => {{
    // mutually exclusive toggle
    setFailureFilter(failureFilter === 'tlsFail' ? 'none' : 'tlsFail');
  }});
}}

viewport.addEventListener('scroll', () => {{
syncHeaderX();
render();
}});

header.querySelectorAll('[data-k]').forEach(el => {{
el.addEventListener('click', () => {{
const k = el.getAttribute('data-k');
if (!k) return;
if (sortKey === k) {{
sortAsc = !sortAsc;
}} else {{
sortKey = k;
sortAsc = true;
}}
sortView();
render();
}});
}});

// init
setBadges();
sortPairs();
renderPairs();

sortView();
resizeSpacer();
shownEl.textContent = String(viewIdx.length);
syncHeaderX();
render();
}})();
</script>
</body>
</html>
"""
    html_doc = html_doc.replace('{{', '{').replace('}}', '}')
    html_doc = html_doc.replace('__TITLE__', esc(title))
    html_doc = html_doc.replace('__FIRST_PACKET_TS__', esc(first_packet_ts))
    html_doc = html_doc.replace('__LAST_PACKET_TS__', esc(last_packet_ts))
    html_doc = html_doc.replace('__SCRIPT_VERSION__', esc(SCRIPT_VERSION))
    html_doc = html_doc.replace('__JSON_TEXT__', json_text)
    html_doc = html_doc.replace('__PAIR_JSON_TEXT__', pair_json_text)
    # Fix template literal expressions that were previously escaped for f-strings: ${{x}} -> ${x}
    html_doc = re.sub(r"\$\{\{(.*?)\}\}", r"${\1}", html_doc)
    with open(out_html, "w", encoding="utf-8") as f:
        f.write(html_doc)


def write_graph_html(out_html: str, title: str, timeseries: dict, summary: dict, utc: bool, graph_source_note: str) -> None:
    page_data = {
        "title": title,
        "timeseries": timeseries,
        "summary": summary,
        "utc": utc,
        "graph_source_note": graph_source_note,
    }
    data_json = json.dumps(page_data, ensure_ascii=False)

    html_doc = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width,initial-scale=1" />
<title>__TITLE__</title>
<style>
:root {
--bg: #f6f7f3;
--panel: #fffdf8;
--panel-2: #ffffff;
--border: #d8ddd4;
--text: #172016;
--muted: #617062;
--accent: #0f766e;
--shadow: 0 10px 30px rgba(22, 34, 23, 0.08);
--radius: 16px;
--mono: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace;
--sans: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
}
* { box-sizing: border-box; }
body {
margin: 0;
font-family: var(--sans);
background:
radial-gradient(circle at top left, rgba(15,118,110,.14), transparent 28%),
radial-gradient(circle at top right, rgba(21,101,192,.10), transparent 26%),
linear-gradient(180deg, #f9fbf7, var(--bg));
color: var(--text);
}
.page {
width: 100%;
max-width: none;
margin: 0;
padding: 24px 18px 28px;
}
h1 {
margin: 0 0 8px;
font-size: 28px;
font-weight: 600;
}
.sub {
color: var(--muted);
margin-bottom: 18px;
}
.panel {
background: var(--panel);
border: 1px solid var(--border);
border-radius: var(--radius);
box-shadow: var(--shadow);
}
.eyebrow {
font-size: 12px;
letter-spacing: .04em;
text-transform: uppercase;
color: var(--muted);
margin-bottom: 8px;
}
.bar {
display: flex;
flex-wrap: wrap;
gap: 10px;
align-items: center;
margin: 10px 0 18px;
}
.chip {
--chip: var(--accent);
display: inline-flex;
align-items: center;
gap: 8px;
font-size: 13px;
font-weight: 500;
padding: 8px 12px;
border: 1px solid color-mix(in srgb, var(--chip) 28%, var(--border));
border-radius: 999px;
background: color-mix(in srgb, var(--chip) 10%, white);
color: color-mix(in srgb, var(--chip) 80%, #102217);
cursor: pointer;
user-select: none;
box-shadow: 0 3px 12px rgba(24, 36, 25, .05);
transition: transform .15s ease, box-shadow .15s ease, border-color .15s ease, background .15s ease, opacity .15s ease;
}
.chip:hover {
transform: translateY(-1px);
box-shadow: 0 10px 18px rgba(24, 36, 25, .08);
}
.chip.off {
opacity: .48;
background: rgba(247,248,244,.88);
box-shadow: none;
}
.badge {
display: inline-flex;
align-items: center;
justify-content: center;
min-width: 22px;
padding: 1px 8px;
border-radius: 999px;
border: 1px solid color-mix(in srgb, var(--chip) 20%, var(--border));
background: rgba(255,255,255,.92);
font-family: var(--mono);
font-size: 12px;
color: var(--text);
}
.chip[data-cat="metric-streams"] { --chip: #0f766e; }
.chip[data-cat="metric-tcp"] { --chip: #00897b; }
.chip[data-cat="metric-udp"] { --chip: #0277bd; }
.chip[data-cat="metric-packets"] { --chip: #1565c0; }
.chip[data-cat="metric-bytes"] { --chip: #6d4c41; }
.controls {
padding: 18px;
margin-bottom: 18px;
background:
linear-gradient(180deg, rgba(255,255,255,.92), rgba(248,250,246,.96));
}
.window-row {
display: flex;
gap: 12px;
align-items: center;
justify-content: flex-end;
flex-wrap: wrap;
margin: 0 0 18px;
}
.control-row {
display: flex;
gap: 16px;
align-items: center;
justify-content: space-between;
flex-wrap: wrap;
margin-bottom: 12px;
}
.control-row:last-child { margin-bottom: 0; }
.toolbar-copy {
display: flex;
flex-direction: column;
gap: 6px;
max-width: 820px;
}
.toolbar-title {
font-size: 15px;
font-weight: 600;
color: var(--text);
}
.toolbar-help {
font-size: 13px;
color: var(--muted);
}
button {
border: 1px solid var(--border);
background: var(--panel-2);
padding: 8px 10px;
border-radius: 10px;
cursor: pointer;
font-size: 13px;
font-weight: 500;
color: var(--text);
transition: box-shadow .15s ease, border-color .15s ease, background .15s ease;
box-shadow: 0 2px 8px rgba(24, 36, 25, .03);
}
button:hover {
border-color: rgba(15,118,110,.4);
background: rgba(255,255,255,.96);
box-shadow: 0 6px 14px rgba(24, 36, 25, .06);
}
.legend {
display: flex;
flex-wrap: wrap;
gap: 10px;
}
.legend-item {
font-size: 13px;
}
.legend-text {
display: inline-flex;
align-items: baseline;
gap: 8px;
}
.legend-total {
font-size: 12px;
color: var(--muted);
}
.swatch {
width: 12px;
height: 12px;
border-radius: 999px;
display: inline-block;
box-shadow: 0 0 0 3px rgba(255,255,255,.85);
}
.charts {
display: grid;
grid-template-columns: 1fr;
gap: 16px;
}
.chart-card {
padding: 16px;
position: relative;
background: var(--panel);
border: 1px solid var(--border);
border-radius: var(--radius);
box-shadow: var(--shadow);
}
.chart-head {
display: flex;
justify-content: space-between;
gap: 12px;
align-items: baseline;
margin-bottom: 10px;
}
.chart-title {
font-size: 18px;
font-weight: 600;
}
.chart-meta {
font-size: 13px;
color: var(--muted);
}
.chart-shell {
position: relative;
}
svg {
width: 100%;
height: 250px;
display: block;
background: linear-gradient(180deg, rgba(255,255,255,.9), rgba(249,251,247,.95));
border-radius: 12px;
border: 1px solid rgba(216,221,212,.8);
}
.chart-interaction {
display: flex;
justify-content: space-between;
gap: 12px;
margin-top: 10px;
font-size: 12px;
color: var(--muted);
}
.chart-interaction strong {
color: var(--text);
}
.tooltip {
position: absolute;
display: none;
pointer-events: none;
z-index: 5;
padding: 8px 10px;
border: 1px solid var(--border);
border-radius: 12px;
background: rgba(255,255,255,.98);
box-shadow: var(--shadow);
font-size: 12px;
line-height: 1.4;
min-width: 180px;
}
.notes {
margin-top: 18px;
padding: 16px;
}
.notes ul {
margin: 8px 0 0 18px;
padding: 0;
}
.mono {
font-family: var(--mono);
}
.window-pill {
display: inline-flex;
align-items: center;
gap: 8px;
padding: 8px 12px;
border-radius: 10px;
border: 1px solid rgba(15,118,110,.18);
background: rgba(15,118,110,.07);
font-size: 13px;
font-weight: 500;
color: #145e58;
}
@media (max-width: 700px) {
  .page { padding: 16px; }
  h1 { font-size: 24px; }
  .control-row { align-items: flex-start; }
  .window-row { justify-content: flex-start; }
  .chart-interaction { flex-direction: column; }
}
</style>
</head>
<body>
<div class="page">
  <h1>__TITLE__</h1>
  <div class="sub">Offline interactive time-series view for packet volume, connections, and failure classifications.</div>

  <div id="summaryBar" class="bar"></div>

  <div class="window-row">
    <div id="windowLabel" class="window-pill"></div>
    <button id="resetZoom" type="button">Reset zoom</button>
  </div>

  <div class="panel controls">
    <div class="control-row">
      <div class="toolbar-copy">
        <div class="toolbar-title">Interactive Timeline</div>
        <div class="toolbar-help">Drag across any chart to zoom into a time range. Double-click a chart or use reset to return to the full window.</div>
      </div>
    </div>
    <div id="legend" class="legend"></div>
  </div>

  <div id="charts" class="charts"></div>

  <div class="panel notes">
    <div class="eyebrow">Notes</div>
    <div id="sourceNote"></div>
    <ul id="notesList"></ul>
  </div>

  <div style="margin-top:16px; font-size:12px; color:var(--muted); text-align:right;">
    Version __SCRIPT_VERSION__ | Developed By: Mallikarjun Immadi
  </div>
</div>

<script id="graphData" type="application/json">__DATA_JSON__</script>
<script>
(() => {
const payload = JSON.parse(document.getElementById('graphData').textContent);
const ts = payload.timeseries || {};
const labels = ts.labels || [];
const series = (ts.series || []).map((s) => ({ ...s, visible: true }));
const summary = payload.summary || {};

const chartsEl = document.getElementById('charts');
const legendEl = document.getElementById('legend');
const windowLabel = document.getElementById('windowLabel');
const resetZoom = document.getElementById('resetZoom');
const summaryBar = document.getElementById('summaryBar');
const notesList = document.getElementById('notesList');
const sourceNote = document.getElementById('sourceNote');

const fmtInt = new Intl.NumberFormat();
const maxIdx = Math.max(0, labels.length - 1);
let viewStartIdx = 0;
let viewEndIdx = maxIdx;

function safeLabel(i) {
  if (i < 0 || i >= labels.length) return 'n/a';
  return labels[i];
}

function buildSummaryCards() {
  const items = [
    ['Streams', fmtInt.format((summary.tcp_streams || 0) + (summary.udp_streams || 0)), 'metric-streams'],
    ['TCP Streams', fmtInt.format(summary.tcp_streams || 0), 'metric-tcp'],
    ['UDP Streams', fmtInt.format(summary.udp_streams || 0), 'metric-udp'],
    ['Packets', fmtInt.format(summary.total_packets || 0), 'metric-packets'],
    ['Bytes', fmtInt.format(summary.total_bytes || 0), 'metric-bytes'],
  ];
  summaryBar.innerHTML = items.map(([k, v, cat]) => `
    <div class="chip" data-cat="${cat}">
      <span>${k}</span>
      <span class="badge">${v}</span>
    </div>`).join('');
}

function buildLegend() {
  legendEl.innerHTML = '';
  series.forEach((s) => {
    const item = document.createElement('button');
    item.type = 'button';
    item.className = `legend-item chip${s.visible ? '' : ' off'}`;
    item.style.setProperty('--chip', s.color);
    item.innerHTML = `
      <span class="swatch" style="background:${s.color}"></span>
      <span class="legend-text">
        <span>${s.label}</span>
        <span class="badge">${fmtInt.format(s.total)}</span>
      </span>
    `;
    item.addEventListener('click', () => {
      s.visible = !s.visible;
      buildLegend();
      renderAll();
    });
    legendEl.appendChild(item);
  });
}

function sliceValues(values, startIdx, endIdx) {
  return values.slice(startIdx, endIdx + 1);
}

function makePath(values, width, height, pad) {
  const usableW = width - pad.l - pad.r;
  const usableH = height - pad.t - pad.b;
  const maxY = Math.max(1, ...values);
  const stepX = values.length > 1 ? usableW / (values.length - 1) : 0;
  const points = values.map((v, i) => {
    const x = pad.l + (stepX * i);
    const y = pad.t + usableH - ((v / maxY) * usableH);
    return [x, y];
  });
  const path = points.map((p, i) => `${i === 0 ? 'M' : 'L'}${p[0].toFixed(2)},${p[1].toFixed(2)}`).join(' ');
  return { path, points, maxY, usableW, usableH };
}

function renderChart(container, s, startIdx, endIdx) {
  const width = Math.max(1280, Math.floor(container.clientWidth) - 32);
  const height = 250;
  const pad = { l: 58, r: 18, t: 16, b: 40 };
  const values = sliceValues(s.values, startIdx, endIdx);
  const labelSlice = labels.slice(startIdx, endIdx + 1);
  const { path, points, maxY } = makePath(values, width, height, pad);
  const tickCount = Math.min(5, Math.max(2, values.length));
  const tickStep = values.length <= 1 ? 1 : Math.max(1, Math.floor((values.length - 1) / (tickCount - 1)));
  const yTicks = [0, maxY / 2, maxY].map((v) => Math.round(v * 100) / 100);

  const tickLines = yTicks.map((tick) => {
    const y = pad.t + (height - pad.t - pad.b) - ((tick / Math.max(1, maxY)) * (height - pad.t - pad.b));
    return `
      <line x1="${pad.l}" y1="${y}" x2="${width - pad.r}" y2="${y}" stroke="rgba(116,136,118,.18)" stroke-dasharray="3 5"></line>
      <text x="${pad.l - 8}" y="${y + 4}" text-anchor="end" font-size="11" fill="#617062">${tick}</text>
    `;
  }).join('');

  let xTicks = '';
  for (let i = 0; i < values.length; i += tickStep) {
    const point = points[i];
    if (!point) continue;
    const label = labelSlice[i] || '';
    xTicks += `
      <line x1="${point[0]}" y1="${height - pad.b}" x2="${point[0]}" y2="${height - pad.b + 6}" stroke="rgba(116,136,118,.5)"></line>
      <text x="${point[0]}" y="${height - 8}" text-anchor="middle" font-size="11" fill="#617062">${label.slice(11, 19)}</text>
    `;
  }

  const chartId = `chart_${s.key}`;
  container.innerHTML = `
    <div class="chart-head">
      <div>
        <div class="chart-title">${s.label}</div>
        <div class="chart-meta">Total ${fmtInt.format(s.total)} | Peak ${fmtInt.format(s.peak)}</div>
      </div>
      <div class="chart-meta">Visible buckets: ${fmtInt.format(values.length)}</div>
    </div>
    <div class="chart-shell">
      <svg viewBox="0 0 ${width} ${height}" data-key="${s.key}" id="${chartId}">
        <defs>
          <linearGradient id="${chartId}_fill" x1="0" x2="0" y1="0" y2="1">
            <stop offset="0%" stop-color="${s.color}" stop-opacity="0.22"></stop>
            <stop offset="100%" stop-color="${s.color}" stop-opacity="0.02"></stop>
          </linearGradient>
        </defs>
        <rect x="${pad.l}" y="${pad.t}" width="${width - pad.l - pad.r}" height="${height - pad.t - pad.b}" rx="10" fill="transparent"></rect>
        ${tickLines}
        ${xTicks}
        <line x1="${pad.l}" y1="${height - pad.b}" x2="${width - pad.r}" y2="${height - pad.b}" stroke="rgba(80,92,81,.7)"></line>
        <line x1="${pad.l}" y1="${pad.t}" x2="${pad.l}" y2="${height - pad.b}" stroke="rgba(80,92,81,.7)"></line>
        <path d="${path} L ${points.length ? points[points.length - 1][0] : pad.l},${height - pad.b} L ${points.length ? points[0][0] : pad.l},${height - pad.b} Z" fill="url(#${chartId}_fill)" stroke="none"></path>
        <path d="${path}" fill="none" stroke="${s.color}" stroke-width="3" stroke-linejoin="round" stroke-linecap="round"></path>
        <line id="${chartId}_guide" x1="${pad.l}" y1="${pad.t}" x2="${pad.l}" y2="${height - pad.b}" stroke="${s.color}" stroke-width="1.5" stroke-dasharray="4 5" opacity="0"></line>
        <circle id="${chartId}_dot" cx="${pad.l}" cy="${height - pad.b}" r="4.5" fill="${s.color}" opacity="0"></circle>
        <rect id="${chartId}_zoom" x="${pad.l}" y="${pad.t}" width="0" height="${height - pad.t - pad.b}" fill="${s.color}" fill-opacity="0.14" stroke="${s.color}" stroke-opacity="0.55" stroke-width="1" rx="8" opacity="0"></rect>
      </svg>
      <div class="tooltip" id="${chartId}_tooltip"></div>
    </div>
    <div class="chart-interaction">
      <div><strong>Hover</strong> for values and timestamps</div>
      <div><strong>Drag</strong> horizontally to zoom this time window</div>
    </div>
  `;

  const svg = container.querySelector('svg');
  const tooltip = container.querySelector('.tooltip');
  const guide = container.querySelector(`#${chartId}_guide`);
  const dot = container.querySelector(`#${chartId}_dot`);
  const zoomBox = container.querySelector(`#${chartId}_zoom`);
  let dragStartX = null;

  function svgMetrics() {
    const rect = svg.getBoundingClientRect();
    const scale = Math.min(rect.width / width, rect.height / height);
    const renderedWidth = width * scale;
    const renderedHeight = height * scale;
    const offsetX = (rect.width - renderedWidth) / 2;
    const offsetY = (rect.height - renderedHeight) / 2;
    return { rect, scale, renderedWidth, renderedHeight, offsetX, offsetY };
  }

  function clientXToViewX(clientX) {
    const { rect, renderedWidth, offsetX } = svgMetrics();
    const xInRendered = clientX - rect.left - offsetX;
    return (xInRendered / Math.max(1, renderedWidth)) * width;
  }

  function viewPointToScreen(pointX, pointY) {
    const { rect, scale, offsetX, offsetY } = svgMetrics();
    return {
      left: offsetX + (pointX * scale),
      top: offsetY + (pointY * scale),
      rect,
    };
  }

  function clampX(x) {
    return Math.max(pad.l, Math.min(width - pad.r, x));
  }

  function indexFromX(x) {
    const usableW = width - pad.l - pad.r;
    const ratio = usableW > 0 ? (clampX(x) - pad.l) / usableW : 0;
    return Math.max(0, Math.min(points.length - 1, Math.round(ratio * Math.max(0, points.length - 1))));
  }

  svg.addEventListener('mousemove', (ev) => {
    if (!points.length) return;
    const clampedX = clampX(clientXToViewX(ev.clientX));
    const idx = indexFromX(clampedX);
    const point = points[idx];
    if (!point) return;
    const absoluteIdx = startIdx + idx;
    const value = values[idx] || 0;
    guide.setAttribute('x1', point[0]);
    guide.setAttribute('x2', point[0]);
    guide.setAttribute('opacity', '1');
    dot.setAttribute('cx', point[0]);
    dot.setAttribute('cy', point[1]);
    dot.setAttribute('opacity', '1');
    const screenPoint = viewPointToScreen(point[0], point[1]);
    tooltip.style.display = 'block';
    tooltip.style.left = Math.min(screenPoint.rect.width - 190, screenPoint.left + 12) + 'px';
    tooltip.style.top = Math.max(8, screenPoint.top - 12) + 'px';
    tooltip.innerHTML = `
      <div><strong>${s.label}</strong></div>
      <div>${safeLabel(absoluteIdx)}</div>
      <div>Value: <span class="mono">${fmtInt.format(value)}</span></div>
      <div>Bucket: <span class="mono">${absoluteIdx}</span></div>
    `;

    if (dragStartX !== null) {
      const left = Math.min(dragStartX, clampedX);
      const right = Math.max(dragStartX, clampedX);
      zoomBox.setAttribute('x', left);
      zoomBox.setAttribute('width', Math.max(1, right - left));
      zoomBox.setAttribute('opacity', '1');
    }
  });

  svg.addEventListener('mouseleave', () => {
    tooltip.style.display = 'none';
    guide.setAttribute('opacity', '0');
    dot.setAttribute('opacity', '0');
    if (dragStartX === null) {
      zoomBox.setAttribute('opacity', '0');
    }
  });

  svg.addEventListener('mousedown', (ev) => {
    if (!points.length) return;
    dragStartX = clampX(clientXToViewX(ev.clientX));
    zoomBox.setAttribute('x', dragStartX);
    zoomBox.setAttribute('width', '1');
    zoomBox.setAttribute('opacity', '1');
  });

  svg.addEventListener('mouseup', (ev) => {
    if (dragStartX === null || !points.length) return;
    const dragEndX = clampX(clientXToViewX(ev.clientX));
    const startPointIdx = indexFromX(dragStartX);
    const endPointIdx = indexFromX(dragEndX);
    zoomBox.setAttribute('opacity', '0');
    dragStartX = null;
    if (Math.abs(endPointIdx - startPointIdx) < 2) return;
    const nextStart = startIdx + Math.min(startPointIdx, endPointIdx);
    const nextEnd = startIdx + Math.max(startPointIdx, endPointIdx);
    viewStartIdx = nextStart;
    viewEndIdx = nextEnd;
    renderAll();
  });

  svg.addEventListener('dblclick', () => {
    viewStartIdx = 0;
    viewEndIdx = maxIdx;
    renderAll();
  });
}

function renderAll() {
  let startIdx = Math.min(viewStartIdx, maxIdx);
  let endIdx = Math.min(viewEndIdx, maxIdx);
  if (startIdx > endIdx) {
    const t = startIdx;
    startIdx = endIdx;
    endIdx = t;
  }

  windowLabel.textContent = labels.length
    ? `Window ${safeLabel(startIdx)} to ${safeLabel(endIdx)}`
    : 'Window: no data';

  chartsEl.innerHTML = '';
  series.forEach((s) => {
    if (!s.visible) return;
    const card = document.createElement('div');
    card.className = 'panel chart-card';
    chartsEl.appendChild(card);
    renderChart(card, s, startIdx, endIdx);
  });

  if (!chartsEl.children.length) {
    chartsEl.innerHTML = '<div class="panel chart-card"><div class="chart-title">No series selected</div></div>';
  }
}

function init() {
  buildSummaryCards();
  buildLegend();
  sourceNote.textContent = payload.graph_source_note || '';
  (ts.notes || []).forEach((note) => {
    const li = document.createElement('li');
    li.textContent = note;
    notesList.appendChild(li);
  });

  resetZoom.addEventListener('click', () => {
    viewStartIdx = 0;
    viewEndIdx = maxIdx;
    renderAll();
  });

  window.addEventListener('resize', () => {
    renderAll();
  });

  renderAll();
}

init();
})();
</script>
</body>
</html>
"""
    html_doc = html_doc.replace("__TITLE__", html.escape(title))
    html_doc = html_doc.replace("__SCRIPT_VERSION__", html.escape(SCRIPT_VERSION))
    html_doc = html_doc.replace("__DATA_JSON__", data_json)
    with open(out_html, "w", encoding="utf-8") as f:
        f.write(html_doc)


def main():
    run_started_at = dt.datetime.now()
    run_started_perf = time.perf_counter()
    ap = argparse.ArgumentParser(
        description="PCAP per-stream report (TCP/UDP, IPv4/IPv6): CSV + JSON + low-RAM virtual HTML with per-column filters."
    )
    ap.add_argument("-r", "--read", required=True, help="Input pcap/pcapng file")
    ap.add_argument("--utc", action="store_true", help="Output timestamps in UTC (default local time)")
    ap.add_argument("-Y", "--display-filter", default=None, help="Optional Wireshark display filter, e.g. 'tcp.port==443'")
    ap.add_argument("--min-duration", type=float, default=0.0,
                    help="Only include streams with duration >= this many seconds (generation-time filter)")
    ap.add_argument("-o", "--out-csv", default=None, help="Output CSV path")
    ap.add_argument("--out-json", default=None, help="Output JSON path")
    ap.add_argument("--out-html", default=None, help="Output HTML path (virtualized)")
    ap.add_argument("--out-graphs-html", default=None, help="Output HTML path for offline interactive graphs")

    args = ap.parse_args()

    pcap = args.read
    if not os.path.exists(pcap):
        print(f"ERROR: File not found: {pcap}", file=sys.stderr)
        sys.exit(2)

    progress_log(f"Started analysis for {os.path.basename(pcap)}")
    progress_log(f"Input path: {os.path.abspath(pcap)}")
    progress_log(f"Display filter: {args.display_filter or '<none>'}")

    aggs: Dict[Tuple[str, int], StreamAgg] = {}
    packet_buckets: Dict[int, int] = {}
    progress_log("Parsing TCP streams...")
    ingest_proto(pcap, "tcp", aggs, display_filter=args.display_filter, packet_buckets=packet_buckets)
    progress_log(f"TCP parse complete. Streams seen so far: {len(aggs):,}")
    progress_log("Parsing UDP streams...")
    ingest_proto(pcap, "udp", aggs, display_filter=args.display_filter, packet_buckets=packet_buckets)
    progress_log(f"UDP parse complete. Streams seen so far: {len(aggs):,}")

    progress_log("Parsing TLS metadata...")
    ingest_tls(pcap, aggs, display_filter=args.display_filter)
    progress_log("TLS parse complete.")

    rows = list(aggs.values())
    rows.sort(key=lambda s: (s.proto, s.stream_id))

    progress_log(f"Finalizing classifications across {len(rows):,} streams...")
    finalize_tcp_flags(rows)
    finalize_tls_flags(rows)
    finalize_additional_categories(rows)
    progress_log("Classification complete.")

    prefilter_summary = summarize_rows(rows)
    progress_log(
        f"Pre-filter summary: {prefilter_summary['tcp_streams'] + prefilter_summary['udp_streams']:,} streams, {prefilter_summary['total_packets']:,} packets"
    )

    if args.min_duration > 0:
        progress_log(f"Applying min-duration filter: {args.min_duration} sec")
        rows = [st for st in rows if (st.last_epoch - st.first_epoch) >= args.min_duration]
        progress_log(f"Post-filter stream count: {len(rows):,}")

    final_summary = summarize_rows(rows)
    pcap_base = os.path.splitext(os.path.basename(pcap))[0]

    csv_out = unique_name(args.out_csv or f"{pcap_base}_report.csv")
    json_out = unique_name(args.out_json or f"{pcap_base}_report.json")
    html_out = unique_name(args.out_html or f"{pcap_base}_report.html")
    graphs_html_out = unique_name(args.out_graphs_html or f"{pcap_base}_graphs.html")

    progress_log(f"Writing CSV: {csv_out}")
    write_csv(csv_out, rows, utc=args.utc)
    progress_log(f"Writing JSON: {json_out}")
    write_json(json_out, rows, utc=args.utc)

    title = f"PCAP Report: {os.path.basename(pcap)}"
    pair_summary = build_ip_pair_summary(rows)
    capture_start_epoch = prefilter_summary["capture_start_epoch"]
    capture_end_epoch = prefilter_summary["capture_end_epoch"]
    first_packet_ts = epoch_to_iso(capture_start_epoch, args.utc) if capture_start_epoch is not None else "n/a"
    last_packet_ts = epoch_to_iso(capture_end_epoch, args.utc) if capture_end_epoch is not None else "n/a"
    progress_log(f"Writing main HTML report: {html_out}")
    write_virtual_html(
        html_out,
        json_out,
        title=title,
        pair_summary=pair_summary,
        first_packet_ts=first_packet_ts,
        last_packet_ts=last_packet_ts,
    )
    progress_log("Building time-series data...")
    timeseries = build_timeseries(rows, packet_buckets, utc=args.utc)
    graph_source_note = (
        "Packet volume is graphed from per-packet buckets after any display filter. "
        "Connection and failure graphs are bucketed from stream-level inferred event times."
    )
    progress_log(f"Writing graphs HTML: {graphs_html_out}")
    write_graph_html(
        graphs_html_out,
        title=f"PCAP Graphs: {os.path.basename(pcap)}",
        timeseries=timeseries,
        summary=final_summary,
        utc=args.utc,
        graph_source_note=graph_source_note,
    )
    progress_log("All outputs generated.")

    run_ended_at = dt.datetime.now()
    run_seconds = time.perf_counter() - run_started_perf

    capture_duration = 0.0
    if capture_start_epoch is not None and capture_end_epoch is not None:
        capture_duration = max(0.0, capture_end_epoch - capture_start_epoch)

    print("Run Summary")
    print(f"  PCAP file           : {os.path.basename(pcap)}")
    print(f"  PCAP path           : {os.path.abspath(pcap)}")
    print(f"  PCAP size           : {os.path.getsize(pcap):,} bytes")
    print(f"  Run start time      : {run_started_at.isoformat()}")
    print(f"  Run end time        : {run_ended_at.isoformat()}")
    print(f"  Run time            : {format_elapsed(run_seconds)}")
    if capture_start_epoch is not None and capture_end_epoch is not None:
        print(f"  Capture start time  : {epoch_to_iso(capture_start_epoch, args.utc)}")
        print(f"  Capture end time    : {epoch_to_iso(capture_end_epoch, args.utc)}")
        print(f"  Capture duration    : {format_elapsed(capture_duration)}")
    else:
        print("  Capture start time  : n/a")
        print("  Capture end time    : n/a")
        print("  Capture duration    : n/a")
    print(f"  Time mode           : {'UTC' if args.utc else 'Local'}")
    print(f"  Display filter      : {args.display_filter or '<none>'}")
    print(f"  Min duration filter : {args.min_duration}")
    print(f"  Streams found       : {prefilter_summary['tcp_streams'] + prefilter_summary['udp_streams']:,}")
    print(f"  TCP streams         : {prefilter_summary['tcp_streams']:,}")
    print(f"  UDP streams         : {prefilter_summary['udp_streams']:,}")
    print(f"  Packets tallied     : {prefilter_summary['total_packets']:,}")
    print(f"  Bytes tallied       : {prefilter_summary['total_bytes']:,}")
    print(f"  Conn refused        : {prefilter_summary['conn_refused']:,}")
    print(f"  Client abort        : {prefilter_summary['client_abort']:,}")
    print(f"  Conn failed         : {prefilter_summary['conn_failed']:,}")
    print(f"  Retrans streams     : {prefilter_summary['retrans_streams']:,}")
    print(f"  Retrans heavy       : {prefilter_summary['retrans_heavy_streams']:,}")
    print(f"  Zero window         : {prefilter_summary['zero_window_streams']:,}")
    print(f"  Window full         : {prefilter_summary['window_full_streams']:,}")
    print(f"  Long idle streams   : {prefilter_summary['long_idle_streams']:,}")
    print(f"  HS incomplete       : {prefilter_summary['handshake_incomplete_streams']:,}")
    print(f"  High RTT            : {prefilter_summary['high_rtt_streams']:,}")
    print(f"  Spiky RTT           : {prefilter_summary['spiky_rtt_streams']:,}")
    print(f"  TLS SH missing      : {prefilter_summary['tls_serverhello_missing_streams']:,}")
    print(f"  High PPS UDP        : {prefilter_summary['high_pps_udp_streams']:,}")
    print(f"  TLS handshake failed: {prefilter_summary['tls_failed']:,}")
    if args.min_duration > 0:
        print(f"  Streams written     : {final_summary['tcp_streams'] + final_summary['udp_streams']:,} (after min-duration filter)")
    print(f"Wrote {len(rows)} streams to:")
    print(f"  CSV : {csv_out}")
    print(f"  JSON: {json_out}")
    print(f"  HTML: {html_out}")
    print(f"  Graphs HTML: {graphs_html_out}")


if __name__ == "__main__":
    main()
