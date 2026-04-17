awk -v thr=20 -v pph=10 -v interval=1 '
function to_epoch(ts,   cmd, out) {
    cmd = "date -j -f \"%a %b %d %H:%M:%S %Z %Y\" \"" ts "\" +%s"
    cmd | getline out
    close(cmd)
    return out
}

function from_epoch(e,   cmd, out) {
    cmd = "date -r " e " \"+%Y-%m-%d %H:%M:%S\""
    cmd | getline out
    close(cmd)
    return out
}

/^PING_PRIVATE/ {
    header = $0
    split($0, a, "===")
    ts = a[2]
    gsub(/^[[:space:]]+|[[:space:]]+$/, "", ts)

    start_epoch = to_epoch(ts)

    host_idx = 0
    ping_in_host = 0
    next
}

/^PING[[:space:]]+[0-9]+\./ {
    host_idx++
    ping_in_host = 0

    split($0, f, " ")
    cur_host = f[2]
    next
}

/bytes from/ {
    split($0, t, "time=")
    if (t[2] == "") next

    val = t[2]
    sub(/[[:space:]].*$/, "", val)

    ping_in_host++

    offset = ((host_idx - 1) * pph + ping_in_host) * interval

    if ((val + 0) > thr) {
        event_epoch = start_epoch + offset
        event_time = from_epoch(event_epoch)

        print header
        print "REL_TS=" event_time " OFFSET=" offset "s HOST=" cur_host " PING#=" ping_in_host " LAT=" val " ms"
        print $0
        print ""
    }
}
' *.dat
