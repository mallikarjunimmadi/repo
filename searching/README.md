# adsearch

`adsearch_v0.0.3.py` is the current Python version of the search script for scanning large file trees while preserving the existing CLI behavior.

It supports:
- config-driven defaults from `search_config.ini`
- `auto`, `absolute`, and `relative` matching
- include and exclude glob filters
- extension filtering
- case-sensitive and case-insensitive search
- first and last `N` result output
- optional colored highlighting
- automatic backend selection: `ripgrep` -> `ag` -> `grep` -> Python
- explicit backend override with `--engine`

The Python version prefers native search tools when available and falls back to the built-in Python engine for compatibility.

## Requirements

- Python 3.9+ recommended
- `ripgrep` strongly recommended for best performance

Backend selection in `auto` mode is:
- `ripgrep` (`rg`)
- `The Silver Searcher` (`ag`)
- `grep`
- built-in Python engine

If external tools are not installed or are unsuitable for a given environment, you can force Python mode with `--engine python`.

## Install ripgrep

### macOS

```bash
brew install ripgrep
```

### Ubuntu / Debian

```bash
sudo apt-get update
sudo apt-get install -y ripgrep
```

### RHEL / CentOS / Fedora

```bash
sudo dnf install ripgrep
```

### Windows

```powershell
winget install BurntSushi.ripgrep.MSVC
```

## Usage

```bash
python3 adsearch_v0.0.3.py -c search_config.ini -s "error"
```

Common examples:

```bash
python3 adsearch_v0.0.3.py --help
python3 adsearch_v0.0.3.py -s "10.10.10.100" -p /logs -i -m auto -n 10 -t 8
python3 adsearch_v0.0.3.py -s timeout -e .log,.txt --include-glob '*/prod/*' --exclude-glob '*/archive/*'
python3 adsearch_v0.0.3.py -s error --engine python
python3 adsearch_v0.0.3.py -s error --engine ag
```

## Backend Choice

Use `--engine` to force a backend:

```bash
python3 adsearch_v0.0.3.py -s error --engine auto
python3 adsearch_v0.0.3.py -s error --engine rg
python3 adsearch_v0.0.3.py -s error --engine ag
python3 adsearch_v0.0.3.py -s error --engine grep
python3 adsearch_v0.0.3.py -s error --engine python
```

This is useful when benchmarking or when some files contain unusual bytes/encodings that external tools may handle differently.

## Help Behavior

If `--help` or `-h` is provided, the script prints help and exits immediately. Other flags are ignored in that case.

## Notes

- The `--two-pass` flag is still accepted for compatibility with the older script.
- In `v0.0.3`, performance improvements come mainly from bounded result collection, cached metadata, faster directory traversal, backend auto-selection, and a stronger threaded Python fallback.

## Change History

- `v0.0.1`: introduced the redesigned Python search flow, `ripgrep` integration, bounded first/last result collection, cached file metadata, and timestamped output.
- `v0.0.2`: added `grep` as an additional backend between `ripgrep` and pure Python fallback.
- `v0.0.3`: added `ag` support and the `--engine` flag to force `auto`, `rg`, `ag`, `grep`, or `python`.
