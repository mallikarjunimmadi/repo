#!/usr/bin/env python3

import sys
from datetime import datetime, timezone, timedelta

def detect_and_convert(input_val):
    """
    Detects the time unit and converts to IST from epoch.
    """
    try:
        val = int(str(input_val).strip())

        # Infer the time unit based on magnitude
        if val > 1e17:
            # Likely nanoseconds
            epoch_sec = val / 1_000_000_000
            unit = "nanoseconds"
        elif val > 1e12:
            # Milliseconds
            epoch_sec = val / 1_000
            unit = "milliseconds"
        elif val > 1e10:
            # Seconds (future)
            epoch_sec = val
            unit = "seconds"
        elif val > 60*60*24*365:
            # Seconds (realistic range for ~50+ years)
            epoch_sec = val
            unit = "seconds"
        elif val > 60*60:
            # Likely minutes or hours, but assume minutes
            epoch_sec = val * 60
            unit = "minutes"
        elif val > 0:
            # Small numbers: assume hours
            epoch_sec = val * 3600
            unit = "hours"
        else:
            return f"{input_val} → [ERROR] Value too small or invalid"

        # Convert to IST
        dt_utc = datetime.fromtimestamp(epoch_sec, tz=timezone.utc)
        ist_offset = timedelta(hours=5, minutes=30)
        dt_ist = dt_utc.astimezone(timezone(ist_offset))
        time_str = dt_ist.strftime('%Y-%m-%d %H:%M:%S IST')
        return f"{input_val} ({unit}) → {time_str}"

    except Exception as e:
        return f"{input_val} → [ERROR] Invalid input: {e}"

def main():
    if len(sys.argv) > 1:
        for arg in sys.argv[1:]:
            print(detect_and_convert(arg))
    else:
        print("Enter values (epoch in seconds/ms/ns or minutes/hours since epoch). Ctrl+C to exit.")
        try:
            while True:
                user_input = input("time> ").strip()
                if user_input:
                    print(detect_and_convert(user_input))
        except KeyboardInterrupt:
            print("\n[INFO] Exiting.")

if __name__ == "__main__":
    main()
