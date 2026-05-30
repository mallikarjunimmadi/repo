#!/usr/bin/env python3

import argparse
import configparser
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
import fnmatch
import heapq
import os
import re
import shutil
import subprocess
import sys
import time
from dataclasses import dataclass
from typing import Dict, Iterable, Iterator, List, Optional, Sequence, Tuple

# =========================
# ANSI COLOR CODES
# =========================
RESET = "\033[0m"
RED = "\033[31m"
DARK_YELLOW = "\033[33m"

# =========================
# MATCH HELPERS
# =========================
TOKEN_BOUNDARY = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_")
ALLOWED_TOKEN_CHARS = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._:-_")
IPV4_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")
MAC_RE = re.compile(r"^[0-9A-Fa-f]{2}(?:[:-][0-9A-Fa-f]{2}){5}$")


@dataclass(frozen=True)
class FileEntry:
    path: str
    mtime: float


@dataclass(frozen=True)
class SearchContext:
    term: str
    term_cmp: str
    case_sensitive: bool
    match_mode: str
    abs_matcher: Optional["AbsMatcher"]


MatchRecord = Tuple[float, str, int, str, List[Tuple[int, int]]]
KeyedRecord = Tuple[Tuple[float, str, int], MatchRecord]


def _is_boundary_char(ch: Optional[str]) -> bool:
    return (ch is None) or (ch not in TOKEN_BOUNDARY)


def _allowed_token_chars(term: str) -> bool:
    return all(c in ALLOWED_TOKEN_CHARS for c in term)


def build_absolute_pattern(term: str) -> str:
    return r"(?<![A-Za-z0-9_])" + re.escape(term) + r"(?![A-Za-z0-9_])"


def build_absolute_ere_pattern(term: str) -> str:
    escaped = re.sub(r'([][(){}.^$*+?|\\-])', r'\\\1', term)
    return r'(^|[^[:alnum:]_])' + escaped + r'([^[:alnum:]_]|$)'


def manual_abs_indices(hay_cmp: str, term_cmp: str) -> List[Tuple[int, int]]:
    n = len(term_cmp)
    out: List[Tuple[int, int]] = []
    i = 0
    while True:
        j = hay_cmp.find(term_cmp, i)
        if j == -1:
            break
        left = hay_cmp[j - 1] if j - 1 >= 0 else None
        right = hay_cmp[j + n] if j + n < len(hay_cmp) else None
        if _is_boundary_char(left) and _is_boundary_char(right):
            out.append((j, j + n))
        i = j + 1
    return out


class AbsMatcher:
    def __init__(self, term: str, term_cmp: str, case_sensitive: bool):
        self.term = term
        self.term_cmp = term_cmp
        self.case_sensitive = case_sensitive
        self.use_manual = _allowed_token_chars(term)
        flags = 0 if case_sensitive else re.IGNORECASE
        self.regex = None if self.use_manual else re.compile(build_absolute_pattern(term), flags)

    def find_spans(self, line: str, line_cmp: str) -> List[Tuple[int, int]]:
        if self.term_cmp not in line_cmp:
            return []
        if self.use_manual:
            return manual_abs_indices(line_cmp, self.term_cmp)
        return [(m.start(), m.end()) for m in self.regex.finditer(line)]


def highlight_via_spans(line: str, spans: List[Tuple[int, int]], color_enabled: bool) -> str:
    if not color_enabled or not spans:
        return line
    out: List[str] = []
    prev = 0
    for start, end in spans:
        out.append(line[prev:start])
        out.append(f"{DARK_YELLOW}{line[start:end]}{RESET}")
        prev = end
    out.append(line[prev:])
    return "".join(out)


def color_filename(path: str, color_enabled: bool) -> str:
    return f"{RED}{path}{RESET}" if color_enabled else path


def load_config(config_path: str) -> dict:
    cfg = configparser.ConfigParser(inline_comment_prefixes=("#", ";"))
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
        "threads": s.getint("threads", fallback=0),
        "two_pass": s.getboolean("two_pass", fallback=False),
        "include_glob": [p.strip() for p in s.get("include_glob", fallback="").split(",") if p.strip()],
        "exclude_glob": [p.strip() for p in s.get("exclude_glob", fallback="").split(",") if p.strip()],
        "no_color": s.getboolean("no_color", fallback=False),
        "no_file_name": s.getboolean("no_file_name", fallback=False),
    }


def normalize_mode(mode: str) -> str:
    if not mode:
        return "relative"
    return {
        "a": "auto",
        "auto": "auto",
        "abs": "absolute",
        "absolute": "absolute",
        "rel": "relative",
        "relative": "relative",
    }.get(mode.lower().strip(), "relative")


def detect_auto_mode(term: str) -> str:
    stripped = term.strip()
    if not stripped:
        return "relative"
    if any(ch.isspace() for ch in stripped):
        return "relative"
    if IPV4_RE.match(stripped) or MAC_RE.match(stripped) or _allowed_token_chars(stripped):
        return "absolute"
    return "relative"


def clamp_threads(n: int) -> int:
    return max(1, min(10, n))


def default_threads() -> int:
    return clamp_threads(os.cpu_count() or 4)


def format_duration(seconds: float) -> str:
    hrs, rem = divmod(seconds, 3600)
    mins, secs = divmod(rem, 60)
    return f"{int(hrs):02d}:{int(mins):02d}:{secs:05.2f}"


def format_mtime(epoch_seconds: float) -> str:
    return datetime.fromtimestamp(epoch_seconds).strftime("%Y-%m-%d %H:%M:%S")


def normalize_glob_path(path: str) -> str:
    return path.replace(os.sep, "/")


def passes_globs(path: str, includes: Sequence[str], excludes: Sequence[str]) -> bool:
    posix_path = normalize_glob_path(path)
    if excludes and any(fnmatch.fnmatch(posix_path, pattern) for pattern in excludes):
        return False
    if includes:
        return any(fnmatch.fnmatch(posix_path, pattern) for pattern in includes)
    return True


def extension_matches(name: str, allowed_ext: Sequence[str]) -> bool:
    lower = name.lower()
    return any(lower.endswith(ext) for ext in allowed_ext)


def build_search_context(term: str, case_sensitive: bool, match_mode: str) -> SearchContext:
    term_cmp = term if case_sensitive else term.lower()
    abs_matcher = AbsMatcher(term, term_cmp, case_sensitive) if match_mode == "absolute" else None
    return SearchContext(
        term=term,
        term_cmp=term_cmp,
        case_sensitive=case_sensitive,
        match_mode=match_mode,
        abs_matcher=abs_matcher,
    )


def match_found_and_spans(line: str, ctx: SearchContext) -> List[Tuple[int, int]]:
    text = line.rstrip("\n")
    line_cmp = text if ctx.case_sensitive else text.lower()
    if ctx.match_mode == "absolute":
        return ctx.abs_matcher.find_spans(text, line_cmp) if ctx.abs_matcher else []
    if ctx.term_cmp not in line_cmp:
        return []
    spans: List[Tuple[int, int]] = []
    i = 0
    n = len(ctx.term_cmp)
    while True:
        j = line_cmp.find(ctx.term_cmp, i)
        if j == -1:
            break
        spans.append((j, j + n))
        i = j + 1
    return spans


def should_skip_dir(dir_path: str, excludes: Sequence[str]) -> bool:
    if not excludes:
        return False
    candidate = normalize_glob_path(dir_path.rstrip(os.sep)) + "/"
    return any(fnmatch.fnmatch(candidate, pattern) for pattern in excludes)


def collect_files(base_path: str, allowed_ext: Sequence[str], includes: Sequence[str], excludes: Sequence[str]) -> List[FileEntry]:
    entries: List[FileEntry] = []

    def walk_dir(current_dir: str) -> None:
        try:
            with os.scandir(current_dir) as it:
                for entry in it:
                    path = entry.path
                    if entry.is_dir(follow_symlinks=False):
                        if should_skip_dir(path, excludes):
                            continue
                        walk_dir(path)
                        continue
                    if not entry.is_file(follow_symlinks=False):
                        continue
                    if not extension_matches(entry.name, allowed_ext):
                        continue
                    if not passes_globs(path, includes, excludes):
                        continue
                    try:
                        mtime = entry.stat(follow_symlinks=False).st_mtime
                    except OSError:
                        mtime = 0.0
                    entries.append(FileEntry(path=path, mtime=mtime))
        except OSError as exc:
            print(f"[ERROR] Failed to read directory {current_dir}: {exc}")

    walk_dir(base_path)
    return entries


def build_rg_command(
    ctx: SearchContext,
    targets: Sequence[str],
    allowed_ext: Sequence[str],
    includes: Sequence[str],
    excludes: Sequence[str],
    threads: int,
) -> List[str]:
    cmd = [
        "rg",
        "--line-number",
        "--with-filename",
        "--color",
        "never",
        "--no-heading",
        "--threads",
        str(threads),
        "--glob-case-insensitive",
    ]
    for ext in allowed_ext:
        cmd.extend(["-g", f"*{ext}"])
    for pattern in includes:
        cmd.extend(["-g", pattern])
    for pattern in excludes:
        cmd.extend(["-g", f"!{pattern}"])
    if ctx.case_sensitive:
        cmd.append("--case-sensitive")
    else:
        cmd.append("--ignore-case")

    if ctx.match_mode == "absolute":
        cmd.extend(["--pcre2", build_absolute_pattern(ctx.term)])
    else:
        cmd.extend(["-F", ctx.term])

    cmd.extend(targets)
    return cmd


def build_grep_command(
    ctx: SearchContext,
    targets: Sequence[str],
) -> List[str]:
    cmd = ["grep", "-nH"]
    if not ctx.case_sensitive:
        cmd.append("-i")
    if ctx.match_mode == "absolute":
        cmd.extend(["-E", build_absolute_ere_pattern(ctx.term)])
    else:
        cmd.extend(["-F", ctx.term])
    cmd.extend(targets)
    return cmd


def build_ag_command(
    ctx: SearchContext,
    targets: Sequence[str],
) -> List[str]:
    cmd = ["ag", "--nocolor", "--nogroup", "--column", "--parallel"]
    if not ctx.case_sensitive:
        cmd.append("-i")
    if ctx.match_mode == "absolute":
        cmd.extend(["--literal", ctx.term])
        cmd.append("-w")
    else:
        cmd.extend(["--literal", ctx.term])
    cmd.extend(targets)
    return cmd


def parse_rg_line(raw_line: str) -> Optional[Tuple[str, int, str]]:
    try:
        file_path, lineno_text, line = raw_line.rstrip("\n").split(":", 2)
        return file_path, int(lineno_text), line
    except ValueError:
        return None


def search_entries_with_rg(
    entries: Sequence[FileEntry],
    ctx: SearchContext,
    allowed_ext: Sequence[str],
    includes: Sequence[str],
    excludes: Sequence[str],
    threads: int,
) -> Iterator[MatchRecord]:
    if not entries or not shutil.which("rg"):
        return

    mtimes: Dict[str, float] = {entry.path: entry.mtime for entry in entries}
    cmd = build_rg_command(ctx, [entry.path for entry in entries], allowed_ext, includes, excludes, threads)
    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
    except OSError:
        return

    assert proc.stdout is not None
    for raw_line in proc.stdout:
        parsed = parse_rg_line(raw_line)
        if not parsed:
            continue
        file_path, lineno, line = parsed
        mtime = mtimes.get(file_path)
        if mtime is None:
            continue
        spans = match_found_and_spans(line, ctx)
        if spans:
            yield (mtime, file_path, lineno, line.rstrip("\n"), spans)

    stderr_output = ""
    if proc.stderr is not None:
        stderr_output = proc.stderr.read()
    return_code = proc.wait()
    if return_code not in (0, 1):
        raise RuntimeError(stderr_output.strip() or f"ripgrep failed with exit code {return_code}")


def search_entries_with_grep(
    entries: Sequence[FileEntry],
    ctx: SearchContext,
) -> Iterator[MatchRecord]:
    if not entries or not shutil.which("grep"):
        return

    mtimes: Dict[str, float] = {entry.path: entry.mtime for entry in entries}
    cmd = build_grep_command(ctx, [entry.path for entry in entries])
    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
    except OSError:
        return

    assert proc.stdout is not None
    for raw_line in proc.stdout:
        parsed = parse_rg_line(raw_line)
        if not parsed:
            continue
        file_path, lineno, line = parsed
        mtime = mtimes.get(file_path)
        if mtime is None:
            continue
        spans = match_found_and_spans(line, ctx)
        if spans:
            yield (mtime, file_path, lineno, line.rstrip("\n"), spans)

    stderr_output = ""
    if proc.stderr is not None:
        stderr_output = proc.stderr.read()
    return_code = proc.wait()
    if return_code not in (0, 1):
        raise RuntimeError(stderr_output.strip() or f"grep failed with exit code {return_code}")


def parse_ag_line(raw_line: str) -> Optional[Tuple[str, int, str]]:
    try:
        file_path, lineno_text, _column_text, line = raw_line.rstrip("\n").split(":", 3)
        return file_path, int(lineno_text), line
    except ValueError:
        return None


def search_entries_with_ag(
    entries: Sequence[FileEntry],
    ctx: SearchContext,
) -> Iterator[MatchRecord]:
    if not entries or not shutil.which("ag"):
        return

    mtimes: Dict[str, float] = {entry.path: entry.mtime for entry in entries}
    cmd = build_ag_command(ctx, [entry.path for entry in entries])
    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
    except OSError:
        return

    assert proc.stdout is not None
    for raw_line in proc.stdout:
        parsed = parse_ag_line(raw_line)
        if not parsed:
            continue
        file_path, lineno, line = parsed
        mtime = mtimes.get(file_path)
        if mtime is None:
            continue
        spans = match_found_and_spans(line, ctx)
        if spans:
            yield (mtime, file_path, lineno, line.rstrip("\n"), spans)

    stderr_output = ""
    if proc.stderr is not None:
        stderr_output = proc.stderr.read()
    return_code = proc.wait()
    if return_code not in (0, 1):
        raise RuntimeError(stderr_output.strip() or f"ag failed with exit code {return_code}")


def search_in_file(entry: FileEntry, ctx: SearchContext) -> Iterator[MatchRecord]:
    try:
        with open(entry.path, "r", encoding="utf-8", errors="replace") as handle:
            for lineno, line in enumerate(handle, 1):
                spans = match_found_and_spans(line, ctx)
                if spans:
                    yield (entry.mtime, entry.path, lineno, line.rstrip("\n"), spans)
    except OSError as exc:
        print(f"[ERROR] Failed to read {entry.path}: {exc}")


def search_batch(entries: Sequence[FileEntry], ctx: SearchContext) -> List[MatchRecord]:
    matches: List[MatchRecord] = []
    for entry in entries:
        matches.extend(search_in_file(entry, ctx))
    return matches


def batch_entries(entries: Sequence[FileEntry], batch_size: int) -> Iterator[Sequence[FileEntry]]:
    for idx in range(0, len(entries), batch_size):
        yield entries[idx:idx + batch_size]


def search_entries_python(entries: Sequence[FileEntry], ctx: SearchContext, threads: int) -> Iterator[MatchRecord]:
    if threads <= 1 or len(entries) <= 1:
        for entry in entries:
            yield from search_in_file(entry, ctx)
        return

    batch_size = max(16, min(256, len(entries) // threads or 16))
    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = [executor.submit(search_batch, batch, ctx) for batch in batch_entries(entries, batch_size)]
        for future in as_completed(futures):
            for rec in future.result():
                yield rec


def scan_until_n(
    entries_sorted: Sequence[FileEntry],
    result_count: int,
    ctx: SearchContext,
    allowed_ext: Sequence[str],
    includes: Sequence[str],
    excludes: Sequence[str],
    threads: int,
    engine: str,
    newest: bool = False,
) -> List[MatchRecord]:
    if not entries_sorted or result_count <= 0:
        return []

    order = list(reversed(entries_sorted)) if newest else list(entries_sorted)
    chunk_size = max(1, threads * 4)
    collected: List[MatchRecord] = []

    for chunk in batch_entries(order, chunk_size):
        if engine == "ripgrep":
            chunk_iter = search_entries_with_rg(chunk, ctx, allowed_ext, includes, excludes, threads)
        elif engine == "ag":
            chunk_iter = search_entries_with_ag(chunk, ctx)
        elif engine == "grep":
            chunk_iter = search_entries_with_grep(chunk, ctx)
        else:
            chunk_iter = search_entries_python(chunk, ctx, threads)
        collected.extend(chunk_iter)
        if len(collected) >= result_count:
            break

    collected.sort(key=key_for_record)
    return collected[-result_count:] if newest else collected[:result_count]


def two_pass_collect(
    entries: Sequence[FileEntry],
    result_count: int,
    ctx: SearchContext,
    allowed_ext: Sequence[str],
    includes: Sequence[str],
    excludes: Sequence[str],
    threads: int,
    engine: str,
) -> List[MatchRecord]:
    if not entries or result_count <= 0:
        return []

    entries_sorted = sorted(entries, key=lambda entry: (entry.mtime, entry.path))
    first_n = scan_until_n(entries_sorted, result_count, ctx, allowed_ext, includes, excludes, threads, engine, newest=False)
    last_n = scan_until_n(entries_sorted, result_count, ctx, allowed_ext, includes, excludes, threads, engine, newest=True)

    merged: List[MatchRecord] = []
    seen = set()
    for rec in first_n + last_n:
        dedupe_key = (rec[1], rec[2])
        if dedupe_key not in seen:
            seen.add(dedupe_key)
            merged.append(rec)
    merged.sort(key=key_for_record)
    return merged


def key_for_record(rec: MatchRecord) -> Tuple[float, str, int]:
    return (rec[0], rec[1], rec[2])


def collect_first_last(matches: Iterable[MatchRecord], result_count: int) -> List[MatchRecord]:
    if result_count <= 0:
        return []

    first_records: List[MatchRecord] = []
    last_heap: List[Tuple[Tuple[float, str, int], MatchRecord]] = []

    for rec in matches:
        key = key_for_record(rec)
        if len(first_records) < result_count:
            first_records.append(rec)
        else:
            worst_index = max(range(len(first_records)), key=lambda idx: key_for_record(first_records[idx]))
            if key < key_for_record(first_records[worst_index]):
                first_records[worst_index] = rec
        if len(last_heap) < result_count:
            heapq.heappush(last_heap, (key, rec))
        elif key > last_heap[0][0]:
            heapq.heapreplace(last_heap, (key, rec))

    if not first_records and not last_heap:
        return []

    merged: List[MatchRecord] = []
    seen = set()
    for rec in sorted(first_records, key=key_for_record):
        dedupe_key = (rec[1], rec[2])
        if dedupe_key not in seen:
            seen.add(dedupe_key)
            merged.append(rec)

    for _, rec in sorted(last_heap, key=lambda item: item[0]):
        dedupe_key = (rec[1], rec[2])
        if dedupe_key not in seen:
            seen.add(dedupe_key)
            merged.append(rec)

    return merged


def print_match(rec: MatchRecord, color_enabled: bool, hide_file_name: bool, hide_line_number: bool) -> None:
    mtime, file_path, lineno, line, spans = rec
    if not hide_file_name:
        print(f"  {color_filename(file_path, color_enabled)}  [mtime: {format_mtime(mtime)}]")
    colored = highlight_via_spans(line, spans, color_enabled)
    if hide_line_number:
        print(f"    {colored}")
    else:
        print(f"    Line {lineno} -> {colored}")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Search strings in selected file types with config, auto/absolute matching, and fast scanning.",
        epilog="""
Help:
  If --help or -h is provided, the script prints this help text and exits.
  Other flags are ignored when help is requested.

Performance:
  adsearch prefers ripgrep (rg), then ag, then grep, then the built-in Python engine.
  Use --engine to force a backend for benchmarking or compatibility.

Install ripgrep:
  macOS (Homebrew):  brew install ripgrep
  Ubuntu/Debian:     sudo apt-get update && sudo apt-get install -y ripgrep
  RHEL/CentOS:       sudo dnf install ripgrep
  Windows (winget):  winget install BurntSushi.ripgrep.MSVC

Examples:
  python3 adsearch_v0.0.3.py --help
  python3 adsearch_v0.0.3.py -c search_config.ini -s "error"
  python3 adsearch_v0.0.3.py -s "10.176.55.14" -p /logs -i -m auto -n 10 -t 8
  python3 adsearch_v0.0.3.py -s timeout -e .log,.txt --include-glob '*/prod/*' --exclude-glob '*/archive/*' --two-pass
  python3 adsearch_v0.0.3.py -s error --engine python
""",
        formatter_class=argparse.RawTextHelpFormatter,
    )
    parser.add_argument("-c", "--config", default="search_config.ini", help="Path to config file (default: search_config.ini)")
    parser.add_argument("-p", "--base-path", help="Base path to search")
    parser.add_argument("-s", "--search-term", help="String to search for (required unless --help is used)")
    parser.add_argument("-i", "--ignore-case", action="store_true", help="Ignore case (default is case-sensitive)")
    parser.add_argument(
        "-m",
        "--match-mode",
        choices=["auto", "a", "absolute", "abs", "relative", "rel"],
        help="Match mode: auto (a), absolute (abs), relative (rel)",
    )
    parser.add_argument("-n", "--result-count", type=int, help="Number of matches to return from beginning and end")
    parser.add_argument("-e", "--file-extensions", help="Comma-separated extensions (e.g. .txt,.csv)")
    parser.add_argument("-t", "--threads", type=int, help="Number of worker threads (capped at 10)")
    parser.add_argument("--engine", choices=["auto", "rg", "ag", "grep", "python"], default="auto",
                        help="Force search backend: auto, rg, ag, grep, or python")
    parser.add_argument("--two-pass", action="store_true", help="Preserved for CLI compatibility")
    parser.add_argument("--include-glob", help="Comma-separated glob patterns to include (match against full path)")
    parser.add_argument("--exclude-glob", help="Comma-separated glob patterns to exclude (match against full path)")
    parser.add_argument("--no-color", action="store_true", help="Disable color highlighting")
    parser.add_argument("--no-line-number", action="store_true", help="Do not show line numbers in output")
    parser.add_argument("--no-file-name", "-F", action="store_true", help="Do not show file names in output")
    return parser


def parse_args() -> argparse.Namespace:
    parser = build_parser()
    args = parser.parse_args()
    if not args.search_term:
        parser.error("the following arguments are required: -s/--search-term")
    return args


def main() -> None:
    start = time.time()
    args = parse_args()

    try:
        cfg = load_config(args.config)
    except Exception as exc:
        print(f"[ERROR] {exc}")
        return

    base_path = args.base_path or cfg["base_path"]
    search_term = args.search_term
    case_sensitive = (not args.ignore_case) if args.ignore_case else cfg["case_sensitive"]
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
    includes = [p.strip() for p in args.include_glob.split(",") if p.strip()] if args.include_glob else cfg["include_glob"]
    excludes = [p.strip() for p in args.exclude_glob.split(",") if p.strip()] if args.exclude_glob else cfg["exclude_glob"]
    color_enabled = sys.stdout.isatty() and not (args.no_color or cfg["no_color"])
    hide_file_name = args.no_file_name or cfg["no_file_name"]

    if not base_path:
        print("[ERROR] 'base_path' must be provided (config or CLI).")
        return
    if not os.path.isdir(base_path):
        print(f"[ERROR] Base path does not exist or is not a directory: {base_path}")
        return

    ctx = build_search_context(search_term, case_sensitive, resolved_mode)
    entries = collect_files(base_path, file_extensions, includes, excludes)
    scanned_files = len(entries)
    if args.engine == "rg":
        engine = "ripgrep"
    elif args.engine == "ag":
        engine = "ag"
    elif args.engine == "grep":
        engine = "grep"
    elif args.engine == "python":
        engine = "python"
    else:
        if shutil.which("rg"):
            engine = "ripgrep"
        elif shutil.which("ag"):
            engine = "ag"
        elif shutil.which("grep"):
            engine = "grep"
        else:
            engine = "python"

    print(
        f"[INFO] Searching for '{search_term}' in '{base_path}' "
        f"(case_sensitive={case_sensitive}, match_mode={resolved_mode}, threads={threads}, two_pass={two_pass})"
    )
    print(f"[INFO] Candidate files: {scanned_files} | engine: {engine}")

    try:
        if two_pass:
            matches = two_pass_collect(entries, result_count, ctx, file_extensions, includes, excludes, threads, engine)
        else:
            if engine == "ripgrep":
                match_iter = search_entries_with_rg(entries, ctx, file_extensions, includes, excludes, threads)
            elif engine == "ag":
                match_iter = search_entries_with_ag(entries, ctx)
            elif engine == "grep":
                match_iter = search_entries_with_grep(entries, ctx)
            else:
                match_iter = search_entries_python(entries, ctx, threads)
            matches = collect_first_last(match_iter, result_count)
    except KeyboardInterrupt:
        print("\n[WARN] Interrupted by user (Ctrl-C). Returning partial results...")
        return
    except Exception as exc:
        print(f"[ERROR] Search failed: {exc}")
        return

    total = len(matches)
    if total == 0:
        dur = time.time() - start
        print("[INFO] No matches found.")
        print(f"[INFO] Done in {dur:.2f}s ({format_duration(dur)}) | files scanned: {scanned_files} | matches printed: 0")
        return

    split = min(result_count, total)
    first_half = matches[:split]
    last_half = matches[-split:] if total > split else []
    first_match_time = format_mtime(first_half[0][0]) if first_half else "n/a"
    last_match_time = format_mtime(last_half[-1][0]) if last_half else first_match_time

    if first_half:
        print(f"\n[+] First {len(first_half)} Matches (earliest file mtime: {first_match_time}):")
        for rec in first_half:
            print_match(rec, color_enabled, hide_file_name, args.no_line_number)

    if last_half and total > split:
        print(f"\n[+] Last {len(last_half)} Matches (latest file mtime: {last_match_time}):")
        for rec in last_half:
            print_match(rec, color_enabled, hide_file_name, args.no_line_number)

    dur = time.time() - start
    print(
        f"\n[INFO] Done in {dur:.2f}s ({format_duration(dur)})"
        f" | first match mtime: {first_match_time}"
        f" | last match mtime: {last_match_time}"
        f" | files scanned: {scanned_files}"
        f" | matches printed: {len(first_half) + len(last_half)}"
    )


if __name__ == "__main__":
    main()
