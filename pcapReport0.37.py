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
from dataclasses import dataclass
from typing import Dict, Iterator, Optional, Tuple, List


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


def epoch_to_iso(epoch: float, utc: bool) -> str:
    if utc:
        return dt.datetime.fromtimestamp(epoch, tz=dt.timezone.utc).isoformat()
    return dt.datetime.fromtimestamp(epoch).isoformat()


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
        ]
    elif proto_l == "udp":
        stream_field = "udp.stream"
        srcport_field = "udp.srcport"
        dstport_field = "udp.dstport"
        base_filter = "udp"
        extra_fields = []
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
) -> None:
    is_tcp = (proto.lower() == "tcp")

    for line in run_tshark(pcap, proto, display_filter=display_filter):
        parts = line.split("\t")

        if is_tcp:
            # 10 base fields + 6 tcp flag fields = 16
            if len(parts) != 16:
                continue
            (sid_s, epoch_s, frame_s, flen_s, ip4s, ip4d, ip6s, ip6d, sport, dport,
             syn_s, ack_s, rst_s, fin_s, psh_s, urg_s) = parts
        else:
            if len(parts) != 10:
                continue
            sid_s, epoch_s, frame_s, flen_s, ip4s, ip4d, ip6s, ip6d, sport, dport = parts
            syn_s = ack_s = rst_s = fin_s = psh_s = urg_s = ""

        if not sid_s or not epoch_s or not frame_s:
            continue

        try:
            sid = int(sid_s)
            epoch = float(epoch_s)
            frame_no = int(frame_s)
        except ValueError:
            continue

        try:
            frame_len = int(flen_s) if flen_s else 0
        except ValueError:
            frame_len = 0

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

        # TCP-only flag accounting
        if is_tcp:
            st = aggs[key]
            syn = parse_flag01(syn_s)
            ack = parse_flag01(ack_s)
            rst = parse_flag01(rst_s)
            fin = parse_flag01(fin_s)
            psh = parse_flag01(psh_s)
            urg = parse_flag01(urg_s)

            # counts
            if syn == 1 and ack == 1:
                st.synack_pkts += 1
            if ack == 1:
                st.ack_pkts += 1
            if ack == 1 and syn == 0 and rst == 0 and fin == 0 and psh == 0 and urg == 0:
                st.ack_only_pkts += 1
            if syn == 1 and ack == 0 and rst == 0:
                st.syn_pkts += 1
            if rst == 1:
                st.rst_pkts += 1  # include RST,ACK too (common)
            if rst == 1 and ack == 0:
                st.rst_no_ack_pkts += 1  # client-side abort often appears as pure RST

            if fin == 1:
                st.fin_pkts += 1

            # classify "other" flags (allow SYN and RST packets; treat FIN/PSH/URG combos as other)
            is_pure_syn = (syn == 1 and ack == 0 and rst == 0 and fin == 0 and psh == 0 and urg == 0)

            # pure SYN-ACK (server handshake response)
            is_synack_packet = (syn == 1 and ack == 1 and rst == 0 and fin == 0 and psh == 0 and urg == 0)

            # allow RST with or without ACK; disallow RST mixed with SYN/FIN/PSH/URG
            is_rst_packet = (rst == 1 and syn == 0 and fin == 0 and psh == 0 and urg == 0)

            if not (is_pure_syn or is_synack_packet or is_rst_packet):
                st.other_flag_pkts += 1


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
            continue

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
        "synack_pkts": st.synack_pkts,

        # Failure categories
        "conn_refused_syn_rst": bool(st.conn_refused_syn_rst),
        "client_abort_after_synack": bool(st.client_abort_after_synack),
        "conn_failed_ackretrans_rst": bool(st.conn_failed_ackretrans_rst),

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
        "syn_pkts", "rst_pkts", "ack_pkts", "ack_only_pkts", "synack_pkts",
        "conn_refused_syn_rst",
        "client_abort_after_synack",
        "conn_failed_ackretrans_rst",
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



def run_tshark_tls(pcap: str, display_filter: Optional[str]) -> Tuple[List[str], Iterator[str]]:
    """
    Returns (field_list, iterator over tshark output lines).

    Compatibility behavior:
      - Tries `_ws.col.info` first (works in many builds; you verified this works),
        then retries with `_ws.col.Info` if tshark complains about an invalid field.
      - Avoids fragile fields like tls.alert_level / tls.alert_description.
    """
    base_fields = _tls_field_config()

    # Display filter: field-presence based (portable across builds)
    base = "(tls.record.content_type || ssl.record.content_type || tls.handshake.type || ssl.handshake.type)"
    final_filter = base if not display_filter else f"({display_filter}) && {base}"

    def _run_with_info_field(info_field: str):
        tls_fields = list(base_fields)
        if info_field:
            tls_fields.append(info_field)

        cmd = [
            "tshark",
            "-o", "x11.tcp.port:",  # disable X11 TCP port preference (best-effort)
            "-r", pcap,
            "-Y", final_filter,
            "-T", "fields",
            "-E", "separator=\t",
            "-E", "occurrence=f",
        ]
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
        if frame_name is not None and idx.get(frame_name) is not None:
            j = idx[frame_name]
            if j < len(parts):
                try:
                    frame_no = int(parts[j]) if parts[j] else 0
                except ValueError:
                    frame_no = 0


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

        # Infer key events from Info column (most reliable on mac/older builds)
        if "client hello" in info_l:
            st.tls_clienthello_pkts += 1
        if "server hello" in info_l:
            st.tls_serverhello_pkts += 1
            if frame_no and (st.tls_first_serverhello_frame == 0 or frame_no < st.tls_first_serverhello_frame):
                st.tls_first_serverhello_frame = frame_no
        if "application data" in info_l:
            st.tls_appdata_pkts += 1
            if frame_no and (st.tls_first_appdata_frame == 0 or frame_no < st.tls_first_appdata_frame):
                st.tls_first_appdata_frame = frame_no

        # Alerts (plain or encrypted). We treat "alert (" and "encrypted alert" as alerts.
        if info_l.startswith("alert") or "alert (" in info_l or "encrypted alert" in info_l:
            st.tls_alert_pkts += 1
            if frame_no and (st.tls_first_alert_frame == 0 or frame_no < st.tls_first_alert_frame):
                st.tls_first_alert_frame = frame_no

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
                        st.tls_appdata_pkts += 1
                        if frame_no and (st.tls_first_appdata_frame == 0 or frame_no < st.tls_first_appdata_frame):
                            st.tls_first_appdata_frame = frame_no
                    if ctype == 21:
                        st.tls_alert_pkts += 1
                        if frame_no and (st.tls_first_alert_frame == 0 or frame_no < st.tls_first_alert_frame):
                            st.tls_first_alert_frame = frame_no

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
                            st.tls_clienthello_pkts += 1
                        elif tok == "2":
                            st.tls_serverhello_pkts += 1
                            if frame_no and (st.tls_first_serverhello_frame == 0 or frame_no < st.tls_first_serverhello_frame):
                                st.tls_first_serverhello_frame = frame_no
                            if frame_no and (st.tls_first_serverhello_frame == 0 or frame_no < st.tls_first_serverhello_frame):
                                st.tls_first_serverhello_frame = frame_no

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
            # Some tshark versions don't expose record.content_type; count an alert if we didn't already.
            if st.tls_first_alert_frame == 0 and frame_no:
                st.tls_first_alert_frame = frame_no
            if st.tls_alert_pkts == 0:
                st.tls_alert_pkts = 1


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

def write_virtual_html(out_html: str, json_filename: str, title: str, pair_summary: List[dict]) -> None:
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
--border: #ddd;
--bg: #fff;
--head: #f7f7f7;
--text: #111;
--muted: #666;
--mono: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace;
--sans: -apple-system, system-ui, Segoe UI, Roboto, Arial, sans-serif;
}}
body {{ font-family: var(--sans); margin: 16px; color: var(--text); background: var(--bg); }}
h1 {{ font-size: 18px; margin: 0 0 10px; }}
.bar {{
display: flex; flex-wrap: wrap; gap: 10px; align-items: center;
margin: 10px 0 12px;
}}
input[type="number"] {{
padding: 9px 10px; font-size: 14px; border: 1px solid var(--border); border-radius: 8px;
width: 140px;
}}
label {{ font-size: 13px; color: var(--muted); display: inline-flex; gap: 6px; align-items: center; }}
.meta {{ font-size: 13px; color: var(--muted); margin-bottom: 8px; }}
.chip {{
font-size: 12px; padding: 6px 10px; border: 1px solid var(--border);
border-radius: 999px; background: #fafafa; cursor: pointer; user-select: none;
}}
.chip.on {{ border-color: #2e7d32 !important; background: #e8f5e9 !important; color: #1b5e20 !important; }}
.badge {{
display: inline-block;
margin-left: 8px;
padding: 1px 7px;
border-radius: 999px;
border: 1px solid var(--border);
background: #fff;
font-family: var(--mono);
font-size: 12px;
color: #333;
vertical-align: middle;
}}

/* Row highlights by failure type */
.row-refused {{ background: #fff0f0; }}
.row-failed  {{ background: #f0f6ff; }}
.row-abort   {{ background: #fff8e6; }}

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
box-shadow: 0 10px 30px rgba(0,0,0,.08);
color: #222;
font-size: 12px;
line-height: 1.35;
white-space: normal;
}}


.grid {{
display: grid;
grid-template-columns: 70px 70px 220px 90px 220px 90px 95px 95px 230px 230px 120px 90px 110px 70px 70px 70px 85px 170px 190px 170px 140px 170px;
min-width: 2100px;
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
.head {{
position: sticky; top: 0; z-index: 10;
background: var(--head);
border-top: 1px solid var(--border);
border-bottom: 1px solid var(--border);
font-weight: 600;
cursor: pointer;
user-select: none;
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
background: #fff;
}}
#header, #filters {{ will-change: transform; }}

.num {{ text-align: right; font-variant-numeric: tabular-nums; font-family: var(--mono); }}
.ts {{ font-family: var(--mono); font-size: 12px; }}
.wrap {{
border: 1px solid var(--border);
border-radius: 12px;
overflow-x: auto;
overflow-y: hidden;
}}
#viewport {{
height: 70vh;
overflow: auto;
position: relative;
background: #fff;
}}
#spacer {{ height: 0px; }}
#rows {{
position: absolute;
top: 0; left: 0; right: 0;
}}
.hint {{ font-size: 12px; color: var(--muted); margin-top: 8px; }}
.right {{ margin-left: auto; }}
button {{
border: 1px solid var(--border); background: #fff; padding: 8px 10px;
border-radius: 10px; cursor: pointer; font-size: 13px;
}}
</style>
</head>
<body>
<h1>__TITLE__</h1>

<div class="bar">
<label>Min duration (sec)
<input id="minDur" type="number" min="0" step="1" value="0" />
</label>

<div id="chipConnRefused" class="chip" data-tip="Connection refused: client SYN gets an immediate RST (port closed / actively refused).">
Connection refused (SYN → RST) <span id="badgeConnRefused" class="badge">0</span>
</div>
<div id="chipClientAbort" class="chip" data-tip="Client abort: SYN and SYN-ACK observed, then client sends a pure RST (no ACK).">
Client abort (SYN-ACK → RST) <span id="badgeClientAbort" class="badge">0</span>
</div>
<div id="chipConnFailed" class="chip" data-tip="Connection failed: SYN observed, SYN-ACK observed and retransmitted (synack>=2). RST may or may not appear; handshake never completes.">
Connection failed (SYN → SYN-ACK retransmits) <span id="badgeConnFailed" class="badge">0</span>
</div>
    <div id="chipTlsFail" class="chip" data-tip="ClientHello seen but TLS handshake does not complete (no app data; alert or no ServerHello).">TLS handshake failed <span class="badge" id="badgeTlsFail">0</span></div>
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
<div data-k="conn_refused_syn_rst">Conn Refused</div>
<div data-k="client_abort_after_synack">Client Abort</div>
<div data-k="conn_failed_ackretrans_rst">Conn Failed</div>
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
<div><input data-f="conn_refused_syn_rst" placeholder="true/false" /></div>
<div><input data-f="client_abort_after_synack" placeholder="true/false" /></div>
<div><input data-f="conn_failed_ackretrans_rst" placeholder="true/false" /></div>
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
const badgeConnRefused = document.getElementById('badgeConnRefused');
const badgeClientAbort = document.getElementById('badgeClientAbort');
const badgeConnFailed = document.getElementById('badgeConnFailed');

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
let cRef=0, cAbort=0, cFail=0, cTls=0;
for (const r of data) {{
if (r.protocol === 'TCP' && r.conn_refused_syn_rst) cRef++;
if (r.protocol === 'TCP' && r.client_abort_after_synack) cAbort++;
if (r.protocol === 'TCP' && r.conn_failed_ackretrans_rst) cFail++;
if (r.protocol === 'TCP' && r.tls_handshake_failed) cTls++;
}}
if (badgeConnRefused) badgeConnRefused.textContent = String(cRef);
if (badgeClientAbort) badgeClientAbort.textContent = String(cAbort);
if (badgeConnFailed) badgeConnFailed.textContent = String(cFail);
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
// mode: "none" | "connRefused" | "clientAbort" | "connFailed" | "tlsFail"
failureFilter = mode;
chipConnRefused.classList.toggle("on", failureFilter === "connRefused");
chipClientAbort.classList.toggle("on", failureFilter === "clientAbort");
chipConnFailed.classList.toggle("on", failureFilter === "connFailed");
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
const numKeys = new Set(['stream_id','first_frame','last_frame','duration_sec','packets','bytes_total','syn_pkts','rst_pkts','ack_pkts','synack_pkts','src_port','dst_port']);
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
if (r.conn_refused_syn_rst) rowCls += ' row-refused';
else if (r.conn_failed_ackretrans_rst) rowCls += ' row-failed';
else if (r.client_abort_after_synack) rowCls += ' row-abort';
else if (r.tls_handshake_failed) rowCls += ' row-tlsfail';
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
<div>${{r.conn_refused_syn_rst ? 'TRUE' : 'FALSE'}}</div>
<div>${{r.client_abort_after_synack ? 'TRUE' : 'FALSE'}}</div>
<div>${{r.conn_failed_ackretrans_rst ? 'TRUE' : 'FALSE'}}</div>
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
}} else if (failureFilter === 'tlsFail') {{
if (r.protocol !== 'TCP') continue;
if (!r.tls_handshake_failed) continue;
}}

let ok = true;
for (const f of colFilters) {{
const v = r[f.key];

if (f.key === 'conn_refused_syn_rst' || f.key === 'client_abort_after_synack' || f.key === 'conn_failed_ackretrans_rst' || f.key === 'tls_handshake_failed') {{
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
    html_doc = html_doc.replace('__JSON_TEXT__', json_text)
    html_doc = html_doc.replace('__PAIR_JSON_TEXT__', pair_json_text)
    # Fix template literal expressions that were previously escaped for f-strings: ${{x}} -> ${x}
    html_doc = re.sub(r"\$\{\{(.*?)\}\}", r"${\1}", html_doc)
    with open(out_html, "w", encoding="utf-8") as f:
        f.write(html_doc)


def main():
    ap = argparse.ArgumentParser(
        description="PCAP per-stream report (TCP/UDP, IPv4/IPv6): CSV + JSON + low-RAM virtual HTML with per-column filters."
    )
    ap.add_argument("-r", "--read", required=True, help="Input pcap/pcapng file")
    ap.add_argument("--utc", action="store_true", help="Output timestamps in UTC (default local time)")
    ap.add_argument("-Y", "--display-filter", default=None, help="Optional Wireshark display filter, e.g. 'tcp.port==443'")
    ap.add_argument("--min-duration", type=float, default=0.0,
                    help="Only include streams with duration >= this many seconds (generation-time filter)")
    ap.add_argument("-o", "--out-csv", default="pcap_report.csv", help="Output CSV path")
    ap.add_argument("--out-json", default="pcap_report.json", help="Output JSON path")
    ap.add_argument("--out-html", default="pcap_report.html", help="Output HTML path (virtualized)")

    args = ap.parse_args()

    pcap = args.read
    if not os.path.exists(pcap):
        print(f"ERROR: File not found: {pcap}", file=sys.stderr)
        sys.exit(2)

    aggs: Dict[Tuple[str, int], StreamAgg] = {}
    ingest_proto(pcap, "tcp", aggs, display_filter=args.display_filter)
    ingest_proto(pcap, "udp", aggs, display_filter=args.display_filter)

    ingest_tls(pcap, aggs, display_filter=args.display_filter)

    rows = list(aggs.values())
    rows.sort(key=lambda s: (s.proto, s.stream_id))

    finalize_tcp_flags(rows)

    finalize_tls_flags(rows)

    if args.min_duration > 0:
        rows = [st for st in rows if (st.last_epoch - st.first_epoch) >= args.min_duration]

    pcap_base = os.path.splitext(os.path.basename(pcap))[0]

    csv_out  = unique_name(f"{pcap_base}_report.csv")
    json_out = unique_name(f"{pcap_base}_report.json")
    html_out = unique_name(f"{pcap_base}_report.html")

    write_csv(csv_out, rows, utc=args.utc)
    write_json(json_out, rows, utc=args.utc)

    title = f"PCAP Report: {os.path.basename(pcap)}"
    pair_summary = build_ip_pair_summary(rows)
    write_virtual_html(html_out, json_out, title=title, pair_summary=pair_summary)

    print(f"Wrote {len(rows)} streams to:")
    print(f"  CSV : {csv_out}")
    print(f"  JSON: {json_out}")
    print(f"  HTML: {html_out}")


if __name__ == "__main__":
    main()