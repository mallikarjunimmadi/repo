#!/usr/bin/env python3

import os
import re
import sys
import time
import argparse
import configparser
import fnmatch
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Tuple, Set, Optional

# =========================
# ANSI COLOR CODES
# =========================
RESET = "\033[0m"
RED = "\033[31m"          # filename color
DARK_YELLOW = "\033[33m"  # match highlight

# =========================
# ABSOLUTE MATCH HELPERS
# =========================
_TOKEN_BOUNDARY = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_")

def _is_boundary_char(ch: Optional[str]) -> bool:
    """True if ch is None or not a token char; token chars are letters/digits/_."""
    return (ch is None) or (ch not in _TOKEN_BOUNDARY)

def _allowed_token_chars(term: str) -> bool:
    """Fast-path eligibility: typical tokens (names/IPs/MACs)."""
    allowed = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._:-_")
    return all(c in allowed for c in term)

def build_absolute_pattern(term: str) -> str:
    """Regex for absolute (not glued to letters/digits/_)."""
    return r'(?<![A-Za-z0-9_])' + re.escape(term) + r'(?![A-Za-z0-9_])'

def manual_abs_indices(text: str, term: str, case_sensitive: bool) -> List[Tuple[int,int]]:
    """
    Find all absolute matches (not glued to letters/digits/_) using manual scanning.
    Returns list of (start, end) indices. Much faster than regex for common tokens.
    """
    hay = text if case_sensitive else text.lower()
    ned = term if case_sensitive else term.lower()
    L, n = hay, len(ned)
    out = []
    i = 0
    while True:
        j = L.find(ned, i)
        if j == -1:
            break
        left  = L[j-1] if j-1 >= 0 else None
        right = L[j+n] if j+n < len(L) else None
        if _is_boundary_char(left) and _is_boundary_char(right):
            out.append((j, j+n))
        i = j + 1
    return out

# =========================
# HIGHLIGHTING
# =========================
def highlight_via_spans(line: str, spans: List[Tuple[int,int]], color_enabled: bool) -> str:
    if not color_enabled or not spans:
        return line
    spans = sorted(spans)
    out = []
    prev = 0
    for a,b in spans:
        out.append(line[prev:a])
        out.append(f"{DARK_YELLOW}{line[a:b]}{RESET}")
        prev = b
    out.append(line[prev:])
    return "".join(out)

def color_filename(path: str, color_enabled: bool) -> str:
    return f"{RED}{path}{RESET}" if color_enabled else path

# =========================
# CONFIG
# =========================
def load_config(config_path: str) -> dict:
    cfg = configparser.ConfigParser(inline_comment_prefixes=('#', ';'))
    read_files = cfg.read(config_path)
    if not read_files:
        raise FileNotFoundError(f"Config file not found: {config_path}")
    if "search" not in cfg:
        raise KeyError("Config file must contain a [search] section.")

    s = cfg["search"]
    return {
        "base_path": s.get("base_path"),
        "case_sensitive": s.getboolean("case_sensitive", fallback=True),
        "result_count": s.getint("result_count", fallback=5),
        "match_mode": s.get("match_mode", fallback="relative").strip().lower(),
        "file_extensions": [
            ext.strip().lower() for ext in s.get("file_extensions", fallback=".txt,.csv").split(",") if ext.strip()
        ],
        "threads": s.getint("threads", fallback=0),  # 0 ⇒ choose default later
        "two_pass": s.getboolean("two_pass", fallback=False),
        "include_glob": [p.strip() for p in s.get("include_glob", fallback="").split(",") if p.strip()],
        "exclude_glob": [p.strip() for p in s.get("exclude_glob", fallback="").split(",") if p.strip()],
        "no_color": s.getboolean("no_color", fallback=False),
        "no_file_name": s.getboolean("no_file_name", fallback=False),
    }

# =========================
# MODE HANDLING
# =========================
def normalize_mode(mode: str) -> str:
    if not mode:
        return "relative"
    m = mode.lower().strip()
    mapping = {
        "a": "auto", "auto": "auto",
        "abs": "absolute", "absolute": "absolute",
        "rel": "relative", "relative": "relative"
    }
    return mapping.get(m, "relative")

def detect_auto_mode(term: str) -> str:
    """
    Choose 'absolute' or 'relative' automatically based on the term.
    - IPv4: absolute
    - MAC (':' or '-' separated): absolute
    - Contains whitespace: relative
    - Token-like term (letters/digits/._:-_): absolute
    - Otherwise: relative
    """
    t = term.strip()
    if not t:
        return "relative"
    if any(c.isspace() for c in t):
        return "relative"

    # IPv4
    if re.match(r'^\d{1,3}(?:\.\d{1,3}){3}$', t):
        return "absolute"

    # MAC AA:BB:CC:DD:EE:FF or AA-BB-CC-DD-EE-FF
    if re.match(r'^[0-9A-Fa-f]{2}(?:[:-][0-9A-Fa-f]{2}){5}$', t):
        return "absolute"

    # Token-like (fast absolute)
    if _allowed_token_chars(t):
        return "absolute"

    return "relative"

# =========================
# MATCHING (FAST)
# =========================
class AbsMatcher:
    """
    Absolute matcher with two fast paths:
      - manual boundary scan for token-y terms (names/IPs/MACs)
      - precompiled regex fallback for other terms
    """
    def __init__(self, term: str, case_sensitive: bool):
        self.term = term
        self.case_sensitive = case_sensitive
        self.use_manual = _allowed_token_chars(term)
        flags = 0 if case_sensitive else re.IGNORECASE
        self.regex = None if self.use_manual else re.compile(build_absolute_pattern(term), flags)
        self.term_prefilter = term if case_sensitive else term.lower()

    def find_spans(self, line: str) -> List[Tuple[int,int]]:
        hay = line if self.case_sensitive else line.lower()
        if self.term_prefilter not in hay:
            return []
        if self.use_manual:
            return manual_abs_indices(line, self.term, self.case_sensitive)
        else:
            return [(m.start(), m.end()) for m in self.regex.finditer(line)]

def match_found_and_spans(line: str, term: str, case_sensitive: bool, match_mode: str,
                          abs_matcher: Optional[AbsMatcher]) -> Tuple[bool, List[Tuple[int,int]]]:
    text = line.rstrip("\n")
    if match_mode == "absolute":
        spans = abs_matcher.find_spans(text) if abs_matcher else []
        return (len(spans) > 0, spans)
    else:
        hay = text if case_sensitive else text.lower()
        ned = term if case_sensitive else term.lower()
        if ned in hay:
            spans = []
            i = 0
            n = len(ned)
            while True:
                j = hay.find(ned, i)
                if j == -1: break
                spans.append((j, j+n))
                i = j + 1
            return True, spans
        return False, []

# =========================
# FILE HELPERS
# =========================
def is_allowed_extension(file_path: str, allowed_ext: List[str]) -> bool:
    lower = file_path.lower()
    return any(lower.endswith(ext) for ext in allowed_ext)

def path_for_glob(p: str) -> str:
    return Path(p).as_posix()

def passes_globs(p: str, includes: List[str], excludes: List[str]) -> bool:
    posix = path_for_glob(p)
    if excludes and any(fnmatch.fnmatch(posix, pat) for pat in excludes):
        return False
    if includes:
        return any(fnmatch.fnmatch(posix, pat) for pat in includes)
    return True

def get_file_timestamp(file_path: str) -> float:
    try:
        return os.path.getmtime(file_path)
    except Exception:
        return 0.0

# =========================
# SEARCH CORE
# =========================
def search_in_file(file_path: str, search_term: str, case_sensitive: bool, match_mode: str
                   ) -> List[Tuple[float, str, int, str, List[Tuple[int,int]]]]:
    """
    Returns tuples: (mtime, path, lineno, line_text, highlight_spans)
    """
    matches: List[Tuple[float, str, int, str, List[Tuple[int,int]]]] = []
    ts = get_file_timestamp(file_path)
    abs_matcher = AbsMatcher(search_term, case_sensitive) if match_mode == "absolute" else None

    tried_alt = False
    try:
        with open(file_path, "r", encoding="utf-8", errors="strict") as f:
            for lineno, line in enumerate(f, 1):
                ok, spans = match_found_and_spans(line, search_term, case_sensitive, match_mode, abs_matcher)
                if ok:
                    matches.append((ts, file_path, lineno, line.rstrip(), spans))
    except UnicodeDecodeError:
        tried_alt = True
    except Exception as e:
        print(f"[ERROR] Failed to read {file_path}: {e}")
        return matches

    if tried_alt:
        try:
            with open(file_path, "r", encoding="latin-1", errors="ignore") as f:
                for lineno, line in enumerate(f, 1):
                    ok, spans = match_found_and_spans(line, search_term, case_sensitive, match_mode, abs_matcher)
                    if ok:
                        matches.append((ts, file_path, lineno, line.rstrip(), spans))
        except Exception as e:
            print(f"[ERROR] Failed to read {file_path}: {e}")

    return matches

def clamp_threads(n: int) -> int:
    return max(1, min(10, n))  # cap at 10

def default_threads() -> int:
    return clamp_threads(os.cpu_count() or 4)

def collect_files(base_path: str, allowed_ext: List[str], includes: List[str], excludes: List[str]) -> List[str]:
    files = []
    for root, _, names in os.walk(base_path):
        for name in names:
            p = os.path.join(root, name)
            if not is_allowed_extension(p, allowed_ext):
                continue
            if not passes_globs(p, includes, excludes):
                continue
            files.append(p)
    return files

def scan_files_parallel(files: List[str], search_term: str, case_sensitive: bool, match_mode: str, threads: int
                        ) -> List[Tuple[float, str, int, str, List[Tuple[int,int]]]]:
    all_matches: List[Tuple[float, str, int, str, List[Tuple[int,int]]]] = []
    if not files:
        return all_matches
    try:
        with ThreadPoolExecutor(max_workers=threads) as ex:
            futures = [ex.submit(search_in_file, f, search_term, case_sensitive, match_mode) for f in files]
            for fut in as_completed(futures):
                try:
                    all_matches.extend(fut.result())
                except Exception as e:
                    print(f"[ERROR] Worker failed: {e}")
    except KeyboardInterrupt:
        print("\n[WARN] Interrupted by user (Ctrl-C). Returning partial results collected so far...")
    return all_matches

def scan_until_n(files_sorted: List[str], n: int, search_term: str, case_sensitive: bool,
                 match_mode: str, threads: int, newest: bool = False
                 ) -> List[Tuple[float, str, int, str, List[Tuple[int,int]]]]:
    if not files_sorted or n <= 0:
        return []

    order = list(reversed(files_sorted)) if newest else files_sorted
    collected: List[Tuple[float, str, int, str, List[Tuple[int,int]]]] = []
    chunk_size = max(1, threads * 4)

    idx = 0
    total = len(order)
    try:
        with ThreadPoolExecutor(max_workers=threads) as ex:
            while idx < total and len(collected) < n:
                chunk = order[idx: idx + chunk_size]
                idx += len(chunk)
                futures = [ex.submit(search_in_file, f, search_term, case_sensitive, match_mode) for f in chunk]
                for fut in as_completed(futures):
                    try:
                        collected.extend(fut.result())
                    except Exception as e:
                        print(f"[ERROR] Worker failed: {e}")
    except KeyboardInterrupt:
        print("\n[WARN] Interrupted by user (Ctrl-C). Returning partial results collected so far...")

    collected.sort(key=lambda x: (x[0], x[1], x[2]))
    return (collected[-n:] if newest else collected[:n])

def two_pass_collect(files: List[str], result_count: int,
                     search_term: str, case_sensitive: bool, match_mode: str, threads: int
                     ) -> List[Tuple[float, str, int, str, List[Tuple[int,int]]]]:
    if not files or result_count <= 0:
        return []

    files_sorted = sorted(files, key=lambda p: (get_file_timestamp(p), p))

    first_n = scan_until_n(files_sorted, result_count, search_term, case_sensitive, match_mode, threads, newest=False)
    last_n  = scan_until_n(files_sorted, result_count, search_term, case_sensitive, match_mode, threads, newest=True)

    seen: Set[Tuple[str, int]] = set()
    merged: List[Tuple[float, str, int, str, List[Tuple[int,int]]]] = []
    for rec in first_n + last_n:
        key = (rec[1], rec[2])
        if key not in seen:
            seen.add(key)
            merged.append(rec)

    merged.sort(key=lambda x: (x[0], x[1], x[2]))
    return merged

# =========================
# CLI
# =========================
def parse_args():
    parser = argparse.ArgumentParser(
        description="🔍 Search strings in selected file types with config, two-pass option, parallel scan, and color highlights.",
        epilog="""
Examples:
  python3 search_string_configurable.py -c search_config.ini -s "error"
  python3 search_string_configurable.py -s "10.176.55.14" -p /logs -i -m auto -n 10 -t 8
  python3 search_string_configurable.py -s timeout -e .log,.txt --include-glob '*/prod/*' --exclude-glob '*/archive/*' --two-pass
""",
        formatter_class=argparse.RawTextHelpFormatter
    )

    parser.add_argument("-c", "--config", default="search_config.ini", help="Path to config file (default: search_config.ini)")
    parser.add_argument("-p", "--base-path", help="Base path to search")
    parser.add_argument("-s", "--search-term", required=True, help="String to search for (required)")
    parser.add_argument("-i", "--ignore-case", action="store_true", help="Ignore case (default is case-sensitive)")
    parser.add_argument("-m", "--match-mode", choices=["auto", "a", "absolute", "abs", "relative", "rel"],
                        help="Match mode: auto (a), absolute (abs), relative (rel)")
    parser.add_argument("-n", "--result-count", type=int, help="Number of matches to return from beginning and end")
    parser.add_argument("-e", "--file-extensions", help="Comma-separated extensions (e.g. .txt,.csv)")
    parser.add_argument("-t", "--threads", type=int, help="Number of worker threads (capped at 10)")
    parser.add_argument("--two-pass", action="store_true", help="Faster on huge trees: collect first N from oldest and last N from newest files early")
    parser.add_argument("--include-glob", help="Comma-separated glob patterns to include (match against full path)")
    parser.add_argument("--exclude-glob", help="Comma-separated glob patterns to exclude (match against full path)")
    parser.add_argument("--no-color", action="store_true", help="Disable color highlighting")
    parser.add_argument("--no-line-number", action="store_true", help="Do not show line numbers in output")
    parser.add_argument("--no-file-name", "-F", action="store_true", help="Do not show file names in output")
    return parser.parse_args()

# =========================
# MAIN
# =========================
def clamp_threads(n: int) -> int:
    return max(1, min(10, n))

def default_threads() -> int:
    return clamp_threads(os.cpu_count() or 4)

def format_duration(seconds: float) -> str:
    """Return human-readable HH:MM:SS.mmm."""
    hrs, rem = divmod(seconds, 3600)
    mins, secs = divmod(rem, 60)
    return f"{int(hrs):02d}:{int(mins):02d}:{secs:05.2f}"

def main():
    start = time.time()
    args = parse_args()

    # Load config (for defaults)
    try:
        cfg = load_config(args.config)
    except Exception as e:
        print(f"[ERROR] {e}")
        return

    base_path = args.base_path or cfg["base_path"]
    search_term = args.search_term
    case_sensitive = (not args.ignore_case) if args.ignore_case else cfg["case_sensitive"]

    # Normalize and resolve auto mode
    mode_in = normalize_mode(args.match_mode or cfg["match_mode"])
    resolved_mode = detect_auto_mode(search_term) if mode_in == "auto" else mode_in

    result_count = args.result_count or cfg["result_count"]

    file_extensions = [
        ext.strip().lower()
        for ext in (args.file_extensions or ",".join(cfg["file_extensions"])).split(",")
        if ext.strip()
    ]

    threads = args.threads if args.threads is not None else cfg["threads"]
    if not threads:
        threads = default_threads()
    threads = clamp_threads(threads)

    two_pass = args.two_pass or cfg["two_pass"]

    includes = (
        [p.strip() for p in args.include_glob.split(",")] if args.include_glob
        else cfg["include_glob"]
    )
    excludes = (
        [p.strip() for p in args.exclude_glob.split(",")] if args.exclude_glob
        else cfg["exclude_glob"]
    )

    color_enabled = sys.stdout.isatty() and not (args.no_color or cfg["no_color"])
    hide_file_name = args.no_file_name or cfg["no_file_name"]

    if not base_path:
        print("[ERROR] 'base_path' must be provided (config or CLI).")
        return

    files = collect_files(base_path, file_extensions, includes, excludes)
    scanned_files = len(files)

    print(f"[INFO] Searching for '{search_term}' in '{base_path}' "
          f"(case_sensitive={case_sensitive}, match_mode={resolved_mode}, threads={threads}, two_pass={two_pass})")
    print(f"[INFO] Candidate files: {scanned_files}")

    try:
        if two_pass:
            matches = two_pass_collect(files, result_count, search_term, case_sensitive, resolved_mode, threads)
        else:
            matches = scan_files_parallel(files, search_term, case_sensitive, resolved_mode, threads)
            matches.sort(key=lambda x: (x[0], x[1], x[2]))
            if len(matches) > result_count:
                matches = matches[:result_count] + matches[-result_count:]
    except KeyboardInterrupt:
        print("\n[WARN] Interrupted by user (Ctrl-C). Returning partial results...")
        pass

    total = len(matches)
    if total == 0:
        dur = time.time() - start
        print(f"[INFO] No matches found.")
        print(f"[INFO] Done in {dur:.2f}s ({format_duration(dur)}) | files scanned: {scanned_files} | matches printed: 0")
        return

    split = min(result_count, total)
    first_half = matches[:split]
    last_half = matches[-split:] if total > split else []

    def print_match(rec):
        _, file_path, lineno, line, spans = rec
        if not hide_file_name:
            print(f"  {color_filename(file_path, color_enabled)}")
        colored = highlight_via_spans(line, spans, color_enabled)
        if args.no_line_number:
            print(f"    {colored}")
        else:
            print(f"    Line {lineno} -> {colored}")

    if first_half:
        print(f"\n[+] First {len(first_half)} Matches:")
        for rec in first_half:
            print_match(rec)

    if last_half and total > split:
        print(f"\n[+] Last {len(last_half)} Matches:")
        for rec in last_half:
            print_match(rec)

    dur = time.time() - start
    print(f"\n[INFO] Done in {dur:.2f}s ({format_duration(dur)}) | files scanned: {scanned_files} | matches printed: {len(first_half) + len(last_half)}")

if __name__ == "__main__":
    main()
