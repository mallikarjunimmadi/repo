#!/usr/bin/env python3

import os
import sys
import subprocess
import logging
from logging.handlers import RotatingFileHandler
from pathlib import Path
import argparse
import datetime

# ==============================
# CONFIG
# ==============================
LOG_FILE = "/tmp/extract_icmp.log"
LOG_SIZE = 20 * 1024 * 1024
LOG_BACKUPS = 3

SUPPORTED_EXT = [".pcap", ".pcapng"]

# ==============================
# LOGGING SETUP
# ==============================
def setup_logging(debug=False):
    logger = logging.getLogger()
    logger.setLevel(logging.DEBUG if debug else logging.INFO)

    formatter = logging.Formatter(
        "%(asctime)s | %(levelname)s | %(message)s"
    )

    # File handler
    fh = RotatingFileHandler(LOG_FILE, maxBytes=LOG_SIZE, backupCount=LOG_BACKUPS)
    fh.setFormatter(formatter)
    fh.setLevel(logging.DEBUG)

    # Console handler
    ch = logging.StreamHandler()
    ch.setFormatter(formatter)
    ch.setLevel(logging.DEBUG if debug else logging.INFO)

    logger.addHandler(fh)
    logger.addHandler(ch)


# ==============================
# CHECK TSHARK
# ==============================
def check_tshark():
    try:
        subprocess.run(["tshark", "-v"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except FileNotFoundError:
        logging.error("tshark not found. Install Wireshark CLI tools.")
        sys.exit(1)


# ==============================
# FIND PCAP FILES
# ==============================
def find_pcaps(root_dir):
    pcaps = []
    for path in Path(root_dir).rglob("*"):
        if path.is_file() and path.suffix.lower() in SUPPORTED_EXT:
            pcaps.append(path)
    return pcaps


# ==============================
# PROCESS FILE
# ==============================
def process_pcap(pcap_path, root_dir):
    try:
        output_file = Path(root_dir) / f"{pcap_path.stem}-icmp.pcap"

        logging.info(f"[PROCESS] {pcap_path}")

        cmd = [
            "tshark",
            "-r", str(pcap_path),
            "-Y", "icmp",
            "-w", str(output_file)
        ]

        result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

        if result.returncode != 0:
            logging.error(f"[FAILED] {pcap_path} | {result.stderr.decode()}")
            return

        logging.info(f"[SUCCESS] Output: {output_file}")

    except Exception as e:
        logging.exception(f"[ERROR] {pcap_path} -> {e}")


# ==============================
# MAIN
# ==============================
def main():
    parser = argparse.ArgumentParser(
        description="Extract ICMP packets from all PCAPs recursively"
    )

    parser.add_argument(
        "--root",
        required=True,
        help="Root directory containing PCAP files"
    )

    parser.add_argument(
        "--debug",
        action="store_true",
        help="Enable debug logging"
    )

    args = parser.parse_args()

    root_dir = Path(args.root).resolve()

    if not root_dir.exists():
        print("Root directory does not exist")
        sys.exit(1)

    setup_logging(args.debug)
    check_tshark()

    logging.info(f"Starting ICMP extraction from: {root_dir}")

    pcaps = find_pcaps(root_dir)

    logging.info(f"Found {len(pcaps)} pcap files")

    if not pcaps:
        logging.warning("No PCAP files found")
        return

    for pcap in pcaps:
        process_pcap(pcap, root_dir)

    logging.info("Completed processing")


# ==============================
# ENTRY
# ==============================
if __name__ == "__main__":
    main()
