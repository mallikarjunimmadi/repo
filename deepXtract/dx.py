#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
deep_extract.py — Recursively extract archives into "<file>_extracted" dirs.

• Supports: .zip, .tar, .tar.gz, .tgz, .tar.bz2, .tbz2, .tar.xz, .txz, .gz, .bz2, .xz, .7z
  (Optional via tools: .rar via unrar/7z, .zst via zstd)
• Safe extraction (ZipSlip protection), skips links inside tars
• Recurses up to depth N (default 3)
• Creates "<archive>_extracted"; if exists, appends timestamp "_YYYYMMDD-HHMMSS"
• Loads defaults from INI config; CLI overrides config
• Logs detailed output to console + rotating master log with hostname, user, PID
• Failure log in CWD, keeps FULL HISTORY, with rich troubleshooting info and strict ownership/permissions
"""

from __future__ import annotations
import argparse, configparser, os, sys, shutil, stat, subprocess, tarfile, zipfile, bz2, gzip, lzma
import logging
from logging.handlers import RotatingFileHandler
from datetime import datetime
from pathlib import Path
from typing import Iterable, List, Optional, Tuple
import socket, getpass, pwd, grp

# --------------------------- Logging setup ---------------------------

class HostUserFilter(logging.Filter):
    """Inject hostname and user into log records."""
    def __init__(self, hostname: str, user: str):
        super().__init__()
        self.hostname = hostname
        self.user = user
    def filter(self, record: logging.LogRecord) -> bool:
        record.hostname = self.hostname
        record.user = self.user
        return True

def setup_master_logger(log_file: Optional[str], verbose: bool, quiet: bool) -> logging.Logger:
    """
    Configure console + optional rotating file logging for detailed/master logs.
    Format: time host user pid level msg
    """
    logger = logging.getLogger("deep_extract")
    logger.propagate = False
    logger.setLevel(logging.DEBUG)

    # Remove old handlers if re-invoked
    for h in list(logger.handlers):
        logger.removeHandler(h)

    level_console = logging.WARNING if quiet else (logging.DEBUG if verbose else logging.INFO)
    fmt = "%(asctime)s %(hostname)s %(user)s [pid=%(process)d] [%(levelname)s] %(message)s"
    datefmt = "%Y-%m-%d %H:%M:%S"

    host = socket.gethostname()
    user = getpass.getuser()
    common_filter = HostUserFilter(host, user)

    # Console handler
    ch = logging.StreamHandler(sys.stdout)
    ch.setLevel(level_console)
    ch.setFormatter(logging.Formatter(fmt, datefmt=datefmt))
    ch.addFilter(common_filter)
    logger.addHandler(ch)

    # File handler (optional rotating)
    if log_file:
        log_dir = Path(log_file).parent
        log_dir.mkdir(parents=True, exist_ok=True)
        fh = RotatingFileHandler(log_file, maxBytes=5 * 1024 * 1024, backupCount=5)
        fh.setLevel(logging.DEBUG if verbose else logging.INFO)
        fh.setFormatter(logging.Formatter(fmt, datefmt=datefmt))
        fh.addFilter(common_filter)
        logger.addHandler(fh)

    return logger

def _apply_fail_log_ownership_perms(path: Path, user: Optional[str], group: Optional[str], master_log: logging.Logger):
    """
    Apply ownership and restrictive permissions to the failure log.
    - chown(user:group) if provided and permitted
    - chmod 0640 on file
    Notes:
      • Requires sufficient privileges to chown.
      • Deletion protection ultimately depends on the parent directory perms.
    """
    try:
        # Permissions first (in case current owner still writing)
        path.chmod(0o640)
    except Exception as e:
        master_log.warning(f"Could not chmod 0640 on failure log {path}: {e}")

    try:
        # Only try chown if both provided
        if user or group:
            uid = pwd.getpwnam(user).pw_uid if user else -1
            gid = grp.getgrnam(group).gr_gid if group else -1
            os.chown(path, uid if uid != -1 else -1, gid if gid != -1 else -1)
    except KeyError as e:
        master_log.warning(f"Invalid user/group for failure log {path}: {e}")
    except PermissionError as e:
        master_log.warning(f"Insufficient permissions to chown failure log {path}: {e}")
    except Exception as e:
        master_log.warning(f"Could not chown failure log {path}: {e}")

def setup_failure_logger(name_in_cwd: str,
                         owner_user: Optional[str],
                         owner_group: Optional[str],
                         master_log: logging.Logger) -> logging.Logger:
    """
    Create a dedicated failure-only logger that writes to CWD/<name> in APPEND mode.
    Keeps full history. Adds timestamp/host/user/pid to each line.
    """
    fail_path = Path.cwd() / name_in_cwd
    fail_path.parent.mkdir(parents=True, exist_ok=True)

    flog = logging.getLogger("deep_extract_fail")
    flog.propagate = False
    flog.setLevel(logging.INFO)

    # Clear old handlers if any
    for h in list(flog.handlers):
        flog.removeHandler(h)

    # Append mode, not truncating
    fh = logging.FileHandler(fail_path, mode="a", encoding="utf-8")
    fmt = "%(asctime)s %(hostname)s %(user)s [pid=%(process)d] [FAILED] %(message)s"
    datefmt = "%Y-%m-%d %H:%M:%S"

    host = socket.gethostname()
    user = getpass.getuser()
    fh.setFormatter(logging.Formatter(fmt, datefmt=datefmt))
    fh.addFilter(HostUserFilter(host, user))
    flog.addHandler(fh)

    # Apply ownership + restrictive perms
    _apply_fail_log_ownership_perms(fail_path, owner_user, owner_group, master_log)
    return flog

# Lightweight facade used by the rest of the code
class Log:
    def __init__(self, logger: logging.Logger, fail_logger: Optional[logging.Logger] = None):
        self._lg = logger
        self._fail = fail_logger
    def info(self, msg: str):  self._lg.info(msg)
    def warn(self, msg: str):  self._lg.warning(msg)
    def error(self, msg: str): self._lg.error(msg)
    def debug(self, msg: str): self._lg.debug(msg)

    def fail(self, *, archive_path: Path, detected_type: Optional[str],
             depth_left: int, reason: str, extra: Optional[str] = None):
        """
        Record a rich failure line in the failure-only log.
        Format (single-line): path | type=<...> | depth=<n> | reason=<...> | extra=<...>
        """
        if self._fail:
            parts = [
                str(archive_path),
                f"type={detected_type or 'unknown'}",
                f"depth={depth_left}",
                f"reason={reason}",
            ]
            if extra:
                parts.append(f"extra={extra}")
            self._fail.info(" | ".join(parts))

# --------------------------- Utilities ---------------------------

def which(cmd: str) -> Optional[str]:
    return shutil.which(cmd)

def ensure_unique_dir(p: Path) -> Path:
    """Use '<name>_extracted' if free; otherwise add a timestamp suffix."""
    if not p.exists():
        return p
    ts = datetime.now().strftime("%Y%m%d-%H%M%S")
    return p.with_name(f"{p.name}_{ts}")

def is_within(base: Path, target: Path) -> bool:
    try:
        target.resolve().relative_to(base.resolve())
        return True
    except Exception:
        return False

def safe_extract_tar(tf: tarfile.TarFile, dest: Path, log: Log):
    dest.mkdir(parents=True, exist_ok=True)
    for member in tf.getmembers():
        member_path = dest / member.name
        if not is_within(dest, member_path):
            log.warn(f"Skipped unsafe path in tar: {member.name}")
            continue
        if member.islnk() or member.issym():
            log.warn(f"Skipping link in tar: {member.name}")
            continue
        tf.extract(member, path=dest)

def safe_extract_zip(zf: zipfile.ZipFile, dest: Path, log: Log):
    dest.mkdir(parents=True, exist_ok=True)
    for member in zf.infolist():
        outpath = dest / member.filename
        if not is_within(dest, outpath):
            log.warn(f"Skipped unsafe path in zip: {member.filename}")
            continue
        zf.extract(member, path=dest)

def read_first_bytes(p: Path, n: int = 8) -> bytes:
    try:
        with p.open("rb") as f:
            return f.read(n)
    except Exception:
        return b""

# --------------------------- Type detection ---------------------------

EXT_PATTERNS = [
    (".tar.gz", "tar.gz"), (".tgz", "tar.gz"), (".tar.bz2", "tar.bz2"),
    (".tbz2", "tar.bz2"), (".tar.xz", "tar.xz"), (".txz", "tar.xz"),
    (".zip", "zip"), (".tar", "tar"), (".7z", "7z"), (".rar", "rar"),
    (".gz", "gz"), (".bz2", "bz2"), (".xz", "xz"), (".zst", "zst")
]

def detect_type(p: Path) -> Optional[str]:
    name_lower = p.name.lower()
    for ext, typ in EXT_PATTERNS:
        if name_lower.endswith(ext):
            return typ
    sig = read_first_bytes(p, 6)
    if sig.startswith(b"PK\x03\x04"):
        return "zip"
    if sig.startswith(b"\x1f\x8b\x08"):
        return "gz"
    return None

# --------------------------- Extractors ---------------------------

def extract_tar_like(p: Path, dest: Path, mode: str, log: Log):
    log.debug(f"Extracting TAR ({mode}) -> {dest}")
    with tarfile.open(p, mode) as tf:
        safe_extract_tar(tf, dest, log)

def extract_zip(p: Path, dest: Path, log: Log):
    log.debug(f"Extracting ZIP -> {dest}")
    with zipfile.ZipFile(p) as zf:
        safe_extract_zip(zf, dest, log)

def decompress_single_file(p: Path, dest_dir: Path, alg: str, log: Log) -> Path:
    dest_dir.mkdir(parents=True, exist_ok=True)
    opener = {"gz": gzip.open, "bz2": bz2.open, "xz": lzma.open}[alg]
    drop = "." + alg
    out_name = p.name[:-len(drop)] if p.name.lower().endswith(drop) else p.stem
    out_path = dest_dir / out_name
    log.debug(f"Decompressing {alg.upper()} -> {out_path}")
    with opener(p, "rb") as src, open(out_path, "wb") as dst:
        shutil.copyfileobj(src, dst)
    return out_path

def extract_with_7z(p: Path, dest: Path, log: Log) -> Tuple[bool, Optional[str]]:
    exe = which("7z") or which("7za") or which("7zz")
    if not exe:
        return False, "7z not found"
    dest.mkdir(parents=True, exist_ok=True)
    cmd = [exe, "x", "-y", f"-o{str(dest)}", str(p)]
    log.debug(f"Using 7z: {' '.join(cmd)}")
    try:
        cp = subprocess.run(cmd, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        return True, None
    except subprocess.CalledProcessError as e:
        stderr = (e.stderr or b"").decode(errors="ignore").strip()
        return False, f"7z error rc={e.returncode} stderr={stderr}"
    except Exception as e:
        return False, f"7z failed: {e}"

def extract_with_unrar(p: Path, dest: Path, log: Log) -> Tuple[bool, Optional[str]]:
    exe = which("unrar")
    if not exe:
        return False, "unrar not found"
    dest.mkdir(parents=True, exist_ok=True)
    cmd = [exe, "x", "-o+", str(p), str(dest)]
    log.debug(f"Using unrar: {' '.join(cmd)}")
    try:
        cp = subprocess.run(cmd, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        return True, None
    except subprocess.CalledProcessError as e:
        stderr = (e.stderr or b"").decode(errors="ignore").strip()
        return False, f"unrar error rc={e.returncode} stderr={stderr}"
    except Exception as e:
        return False, f"unrar failed: {e}"

def extract_one(p: Path, depth_left: int, log: Log, dry_run: bool=False) -> Optional[Path]:
    typ = detect_type(p)
    if not typ:
        log.debug(f"Skipping non-archive: {p}")
        return None

    out_dir = ensure_unique_dir(p.with_name(f"{p.name}_extracted"))
    if dry_run:
        log.info(f"[DRY-RUN] Would extract {p.name} ({typ}) -> {out_dir}")
        return out_dir

    try:
        if typ == "zip":
            extract_zip(p, out_dir, log)
        elif typ == "tar":
            extract_tar_like(p, out_dir, "r:", log)
        elif typ == "tar.gz":
            extract_tar_like(p, out_dir, "r:gz", log)
        elif typ == "tar.bz2":
            extract_tar_like(p, out_dir, "r:bz2", log)
        elif typ == "tar.xz":
            extract_tar_like(p, out_dir, "r:xz", log)
        elif typ in ("gz", "bz2", "xz"):
            decompressed = decompress_single_file(p, out_dir, typ, log)
            log.info(f"Decompressed {p.name} -> {decompressed}")
        elif typ == "7z":
            ok, why = extract_with_7z(p, out_dir, log)
            if not ok:
                raise RuntimeError(why or "7z extraction failed")
        elif typ == "rar":
            ok, why = extract_with_unrar(p, out_dir, log)
            if not ok:
                # Try 7z as fallback
                ok2, why2 = extract_with_7z(p, out_dir, log)
                if not ok2:
                    raise RuntimeError(f"{why}; fallback: {why2}")
        elif typ == "zst":
            zstd = which("zstd")
            if not zstd:
                raise RuntimeError("zstd not found for .zst")
            out_file = out_dir / p.stem  # drop .zst
            out_dir.mkdir(parents=True, exist_ok=True)
            cmd = [zstd, "-d", "-f", "-o", str(out_file), str(p)]
            log.debug(f"Using zstd: {' '.join(cmd)}")
            try:
                subprocess.run(cmd, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            except subprocess.CalledProcessError as e:
                stderr = (e.stderr or b"").decode(errors="ignore").strip()
                raise RuntimeError(f"zstd error rc={e.returncode} stderr={stderr}") from e
        else:
            raise RuntimeError("Unsupported archive type")

        log.info(f"Extracted: {p} -> {out_dir}")
        return out_dir

    except Exception as e:
        # Build rich context for failure log
        reason = f"{type(e).__name__}: {e}"
        # Provide common extra hints for missing tools/types
        tool_state = []
        if typ in ("7z", "rar"):
            tool_state.append(f"7z={'yes' if which('7z') or which('7za') or which('7zz') else 'no'}")
            if typ == "rar":
                tool_state.append(f"unrar={'yes' if which('unrar') else 'no'}")
        if typ == "zst":
            tool_state.append(f"zstd={'yes' if which('zstd') else 'no'}")
        extra = ", ".join(tool_state) if tool_state else None

        log.fail(archive_path=p, detected_type=typ, depth_left=depth_left, reason=reason, extra=extra)
        log.error(f"Failed extracting {p}: {reason}")
        return None

# --------------------------- Recursion driver ---------------------------

ARCHIVE_EXTS = tuple(ext for ext, _ in EXT_PATTERNS)

def looks_like_archive(path: Path) -> bool:
    return any(path.name.lower().endswith(ext) for ext in ARCHIVE_EXTS)

def iter_files(root: Path) -> Iterable[Path]:
    if root.is_file():
        yield root
    else:
        for dirpath, _, filenames in os.walk(root):
            for fn in filenames:
                yield Path(dirpath) / fn

def recurse_extract(start: Path, max_depth: int, delete_archives: bool, log: Log, dry_run: bool):
    """
    Breadth-first recursive extraction up to 'max_depth'.
    Each nested extraction level decrements the depth counter.
    """
    seen: set[Path] = set()
    queue: List[Tuple[Path, int]] = [(start, max_depth)]

    while queue:
        path, depth_left = queue.pop(0)
        try:
            path = path.resolve()
        except Exception:
            pass
        if path in seen:
            continue
        seen.add(path)

        log.debug(f"Processing: {path} (depth_left={depth_left})")

        # If it's a directory, enqueue archives inside *only if* depth allows
        if path.is_dir():
            if depth_left <= 0:
                log.debug(f"Skipping deeper scan (depth=0) in {path}")
                continue
            for f in iter_files(path):
                if looks_like_archive(f):
                    queue.append((f, depth_left - 1))
            continue

        # Otherwise it's a file — try to extract it
        out_dir = extract_one(path, depth_left, log, dry_run=dry_run)
        if out_dir is None:
            continue

        if delete_archives and not dry_run:
            try:
                path.unlink()
                log.debug(f"Deleted archive: {path}")
            except Exception as e:
                log.warn(f"Could not delete {path}: {e}")

        # Only enqueue extracted dir if depth allows
        if depth_left > 1:
            for f in iter_files(out_dir):
                if looks_like_archive(f):
                    queue.append((f, depth_left - 1))

# --------------------------- Config + CLI ---------------------------

def load_config(config_path: Optional[Path]) -> dict:
    """Load defaults from INI config if provided; silent if missing."""
    out = {}
    if not config_path:
        return out
    parser = configparser.ConfigParser()
    if not config_path.exists():
        print(f"[WARN] Config file not found: {config_path}", file=sys.stderr)
        return out
    parser.read(config_path)
    if 'extract' not in parser:
        print(f"[WARN] No [extract] section in {config_path}", file=sys.stderr)
        return out
    s = parser['extract']
    out = {
        'log_file': s.get('log_file', '').strip(),
        'fail_log_name': (s.get('fail_log_name', 'extract.log').strip() or 'extract.log'),
        'fail_log_owner_user': s.get('fail_log_owner_user', '').strip() or None,
        'fail_log_owner_group': s.get('fail_log_owner_group', '').strip() or None,
        'depth': s.getint('depth', 3),
        'delete_archives': s.getboolean('delete_archives', False),
        'verbose': s.getboolean('verbose', False),
        'quiet': s.getboolean('quiet', False),
    }
    return out

def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Recursively extract archives into '<file>_extracted' directories.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    # Positional path defaults to CWD when omitted
    p.add_argument(
        "target", nargs="?", type=Path, default=Path.cwd(),
        help="File or directory to scan for archives (default: current directory)"
    )
    # Explicit flag overrides positional
    p.add_argument(
        "--path", type=Path,
        help="File or directory to scan for archives (overrides the positional 'target')"
    )

    p.add_argument("--config", type=Path, help="Path to config INI file")
    p.add_argument("--depth", type=int, help="Max nested extraction depth")
    p.add_argument("--delete-archives", action="store_true", help="Delete archives after extraction")
    p.add_argument("--dry-run", action="store_true", help="Show what would happen")
    p.add_argument("-v", "--verbose", action="store_true", help="Verbose logging")
    p.add_argument("-q", "--quiet", action="store_true", help="Minimal logging")
    p.add_argument("--log-file", help="Explicit master log file path (overrides config)")
    p.add_argument("--fail-log-name", help="Failure-only log file name in CWD (overrides config)")
    p.add_argument("--fail-log-owner-user", help="Owner user for failure log (overrides config)")
    p.add_argument("--fail-log-owner-group", help="Owner group for failure log (overrides config)")
    return p.parse_args(argv)

def check_tools(log: Log):
    tools = {
        "7z": which("7z") or which("7za") or which("7zz"),
        "unrar": which("unrar"),
        "zstd": which("zstd"),
    }
    log.info("=== Capability Check ===")
    log.info(f"7z    -> {'Found at ' + tools['7z'] if tools['7z'] else 'Not found (required for .7z and fallback for .rar)'}")
    log.info(f"unrar -> {'Found at ' + tools['unrar'] if tools['unrar'] else 'Not found (optional for .rar)'}")
    log.info(f"zstd  -> {'Found at ' + tools['zstd'] if tools['zstd'] else 'Not found (required for .zst)'}")
    log.info("========================")

def main(argv: Optional[List[str]] = None) -> int:
    args = parse_args(argv)
    cfg = load_config(args.config)

    # Merge config -> CLI overrides
    depth = args.depth if args.depth is not None else cfg.get('depth', 3)
    delete_archives = args.delete_archives or cfg.get('delete_archives', False)
    verbose = args.verbose or cfg.get('verbose', False)
    quiet = args.quiet or cfg.get('quiet', False)
    log_file = args.log_file or cfg.get('log_file', '')
    fail_log_name = (args.fail_log_name or cfg.get('fail_log_name') or 'extract.log').strip() or 'extract.log'
    fail_log_owner_user = args.fail_log_owner_user or cfg.get('fail_log_owner_user')
    fail_log_owner_group = args.fail_log_owner_group or cfg.get('fail_log_owner_group')

    # Master logger (detailed logs)
    master_logger = setup_master_logger(log_file if log_file else None, verbose, quiet)
    # Failure-only logger (append mode, full history)
    failure_logger = setup_failure_logger(fail_log_name, fail_log_owner_user, fail_log_owner_group, master_logger)
    log = Log(master_logger, failure_logger)

    if args.config:
        if cfg:
            log.info(f"Loaded config: {args.config}")
        else:
            log.warn(f"Config not applied (missing or invalid): {args.config}")

    # Choose start path: --path > positional > CWD (positional already defaults to CWD)
    start: Path = args.path if args.path else args.target
    if not start.exists():
        log.error(f"Path not found: {start}")
        return 2

    # One-line audit-friendly effective settings
    log.info(
        "EFFECTIVE SETTINGS | "
        f"path={start} | depth={depth} | delete_archives={delete_archives} | "
        f"dry_run={args.dry_run} | verbose={verbose} | quiet={quiet} | "
        f"log_file={(log_file if log_file else 'STDOUT-only')} | "
        f"fail_log={Path.cwd() / fail_log_name} | "
        f"fail_log_owner_user={fail_log_owner_user or '-'} | fail_log_owner_group={fail_log_owner_group or '-'}"
    )

    check_tools(log)
    log.info(f"Start: {start} | depth={depth} | delete={delete_archives} | dry-run={args.dry_run}")

    try:
        recurse_extract(start.resolve(), depth, delete_archives, log, args.dry_run)
        log.info("All done.")
        return 0
    except KeyboardInterrupt:
        log.warn("Interrupted by user.")
        return 130

if __name__ == "__main__":
    raise SystemExit(main())

