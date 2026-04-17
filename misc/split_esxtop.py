#!/usr/bin/env python3
import os
import sys
import time
import gzip
import shutil
import argparse
import logging
from pathlib import Path
from logging.handlers import RotatingFileHandler

# =========================
# HARD-CODED LOG LOCATION
# =========================
LOG_DIR = "/tools_logs/csv_splitter"
LOG_FILE = os.path.join(LOG_DIR, "splitter.log")
MAX_LOG_MB = 20
BACKUP_COUNT = 5

# =========================
# HARD-CODED ARCHIVE BEHAVIOR
# =========================
# If ARCHIVE_DIR is None, gz is created next to original file.
ARCHIVE_DIR = None  # e.g. "/tools_data/esxtop/archive_originals"
GZIP_LEVEL = 6      # 1 (fast) .. 9 (best). 6 is a good balance.

# If True: after gzip succeeds, remove original CSV (recommended to save space)
REMOVE_ORIGINAL_AFTER_GZIP = True

# =========================
# LOGGING SETUP
# =========================
def setup_logger():
    Path(LOG_DIR).mkdir(parents=True, exist_ok=True)

    logger = logging.getLogger("CSV_SPLITTER")
    logger.setLevel(logging.INFO)
    logger.propagate = False

    if logger.handlers:
        return logger

    fmt = logging.Formatter(
        "[%(asctime)s] [%(levelname)s] [PID=%(process)d] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
    )

    file_handler = RotatingFileHandler(
        LOG_FILE,
        maxBytes=MAX_LOG_MB * 1024 * 1024,
        backupCount=BACKUP_COUNT
    )
    file_handler.setFormatter(fmt)

    console_handler = logging.StreamHandler()
    console_handler.setFormatter(fmt)

    logger.addHandler(file_handler)
    logger.addHandler(console_handler)
    return logger

log = setup_logger()

# =========================
# PROMPT
# =========================
def prompt_once():
    try:
        return input("Enter CSV file path/name to split (blank = split ALL *.csv in directory): ").strip()
    except EOFError:
        return ""

# =========================
# GZIP ORIGINAL
# =========================
def gzip_original(csv_path: Path) -> Path:
    """
    Compress csv_path to .gz. Returns gz path on success.
    """
    csv_path = csv_path.resolve()
    if ARCHIVE_DIR:
        outdir = Path(ARCHIVE_DIR).resolve()
        outdir.mkdir(parents=True, exist_ok=True)
        gz_path = outdir / (csv_path.name + ".gz")
    else:
        gz_path = csv_path.with_name(csv_path.name + ".gz")

    tmp_gz = gz_path.with_suffix(gz_path.suffix + ".tmp")  # safe temp target

    log.info(f"Gzipping original: {csv_path} -> {gz_path}")

    # Stream copy + compress
    with csv_path.open("rb") as f_in, gzip.open(tmp_gz, "wb", compresslevel=GZIP_LEVEL) as f_out:
        shutil.copyfileobj(f_in, f_out, length=1024 * 1024)  # 1MB buffer

    # Atomic replace
    tmp_gz.replace(gz_path)

    log.info(f"Gzip complete: {gz_path} (size={gz_path.stat().st_size} bytes)")
    return gz_path

# =========================
# SPLIT FUNCTION
# =========================
def split_one_file(csv_path: Path, lines_per_part: int, outdir: Path, suffix_width: int = 2):
    start = time.time()
    base = csv_path.stem
    outdir.mkdir(parents=True, exist_ok=True)

    log.info(f"==== Splitting File: {csv_path} ====")
    log.info(f"Output Directory: {outdir}")
    log.info(f"Lines per part (data lines): {lines_per_part}")

    total_data_lines = 0
    part_num = 0

    with csv_path.open("r", encoding="utf-8", errors="replace", newline="") as f:
        header = f.readline()
        if not header:
            log.warning(f"Empty file skipped: {csv_path}")
            return

        while True:
            chunk = []
            for _ in range(lines_per_part):
                line = f.readline()
                if not line:
                    break
                chunk.append(line)

            if not chunk:
                break

            part_num += 1
            total_data_lines += len(chunk)

            suffix = str(part_num).zfill(suffix_width)
            out_file = outdir / f"{base}_part{suffix}.csv"

            with out_file.open("w", encoding="utf-8", newline="") as out:
                out.write(header)
                out.writelines(chunk)

            log.info(f"Created part: {out_file.name} | Data lines: {len(chunk)}")

    duration = time.time() - start
    log.info(
        f"Split done: {csv_path.name} | Parts={part_num} | Data lines={total_data_lines} | Time={duration:.2f}s"
    )

    if part_num == 0:
        log.warning(f"No parts created for {csv_path}. Skipping gzip.")
        return

    # gzip original (instead of deletion)
    gz_path = gzip_original(csv_path)

    if REMOVE_ORIGINAL_AFTER_GZIP:
        try:
            csv_path.unlink()
            log.info(f"Removed original CSV after gzip: {csv_path}")
        except Exception as e:
            log.warning(f"Could not remove original CSV {csv_path}: {e}")

# =========================
# MAIN
# =========================
def main():
    parser = argparse.ArgumentParser(description="CSV Splitter with detailed logs + gzip original")
    parser.add_argument("--file", help="CSV file path/name to split")
    parser.add_argument("--dir", default=".", help="Directory to scan if file is blank (default: current dir)")
    parser.add_argument("--outdir", help="Output directory for parts (default: same dir as input file)")
    parser.add_argument("--lines-per-part", type=int, default=50, help="Data lines per part (header added automatically)")
    parser.add_argument("--suffix-width", type=int, default=2, help="Zero padding for part numbers (2 => part01)")
    args = parser.parse_args()

    log.info("========== CSV SPLITTER START ==========")
    log.info(f"Log file: {LOG_FILE}")
    log.info(f"Archive mode: {'ARCHIVE_DIR=' + ARCHIVE_DIR if ARCHIVE_DIR else 'gzip next to original'}")
    log.info(f"Remove original after gzip: {REMOVE_ORIGINAL_AFTER_GZIP}")

    scan_dir = Path(args.dir).resolve()
    if not scan_dir.is_dir():
        log.error(f"Directory not found: {scan_dir}")
        sys.exit(2)

    file_arg = args.file
    if file_arg is None:
        file_arg = prompt_once()

    # Targets
    targets = []
    if not file_arg.strip():
        targets = sorted(p for p in scan_dir.glob("*.csv") if p.is_file())
        log.info(f"Mode: ALL | Found {len(targets)} *.csv files in {scan_dir}")
    else:
        p = Path(file_arg)
        if p.is_file():
            targets = [p.resolve()]
        else:
            cand = (scan_dir / file_arg)
            if cand.is_file():
                targets = [cand.resolve()]
            else:
                log.error(f"File not found: {file_arg} (also checked: {cand})")
                sys.exit(2)

    if not targets:
        log.warning("No CSV files found to process.")
        return

    for csv_file in targets:
        try:
            outdir = Path(args.outdir).resolve() if args.outdir else csv_file.parent.resolve()
            split_one_file(csv_file, args.lines_per_part, outdir, args.suffix_width)
        except Exception as e:
            log.exception(f"Error processing {csv_file}: {e}")

    log.info("========== CSV SPLITTER FINISHED ==========")

if __name__ == "__main__":
    main()
