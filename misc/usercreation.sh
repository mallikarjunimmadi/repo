#!/usr/bin/env bash
set -euo pipefail

# ------------------------------------------------------------
# bulk_create_users.sh
# - Create users from CSV
# - Prompt once (silent) for default password
# - Add to secondary group
# - Custom home base directory
# - Controlled behavior for existing users' home via flag
# - Dry-run mode
# - Summary + meaningful exit codes
#
# CSV format (header optional):
#   username,full_name
#   jdoe,John Doe
#
# Usage:
#   sudo ./bulk_create_users.sh users.csv
#   sudo ./bulk_create_users.sh users.csv --dry-run
#   sudo ./bulk_create_users.sh users.csv --change-existing-home
# ------------------------------------------------------------

# ----------------------------
# Defaults (edit as needed)
# ----------------------------
SECONDARY_GROUP="tools_users"
HOME_BASE="/tools_home"
SHELL_PATH="/bin/bash"
CREATE_HOME=true
FORCE_CHANGE_ON_FIRST_LOGIN=true

# Controlled behavior:
# If true and user exists, update home path and move contents (-m).
CHANGE_EXISTING_HOME=false

# Dry-run (no changes)
DRY_RUN=false

LOG_FILE="./bulk_user_create_$(date +%Y%m%d_%H%M%S).log"

# ----------------------------
# Helpers
# ----------------------------
log() { echo "[$(date '+%F %T')] $*" | tee -a "$LOG_FILE"; }
die() { log "ERROR: $*"; exit 2; }

require_root() { [[ "$(id -u)" -eq 0 ]] || die "Run as root (sudo)."; }

trim() {
  local s="${1:-}"
  s="${s#"${s%%[![:space:]]*}"}"
  s="${s%"${s##*[![:space:]]}"}"
  printf "%s" "$s"
}

run_cmd() {
  # Run a command or print it in dry-run
  if [[ "$DRY_RUN" == true ]]; then
    log "DRYRUN: $*"
    return 0
  fi
  "$@"
}

prompt_password_once() {
  local p1 p2
  while true; do
    read -r -s -p "Enter default password for ALL users: " p1; echo
    read -r -s -p "Confirm default password: " p2; echo
    [[ -n "$p1" ]] || { echo "Password cannot be empty."; continue; }
    [[ "$p1" == "$p2" ]] || { echo "Passwords do not match. Try again."; continue; }
    DEFAULT_PASSWORD="$p1"
    break
  done
  unset p1 p2
}

usage() {
  cat <<EOF
Usage:
  sudo $0 <csv_file> [--dry-run] [--change-existing-home] [--no-force-change]

Options:
  --dry-run              Log actions but do not make changes
  --change-existing-home If user exists, set home to ${HOME_BASE}/<user> and MOVE existing home contents (-m)
  --no-force-change      Do not force password change on first login

Notes:
  CSV (header optional): username,full_name
EOF
}

# ----------------------------
# Args
# ----------------------------
if [[ "${1:-}" == "-h" || "${1:-}" == "--help" || "${#}" -eq 0 ]]; then
  usage
  exit 0
fi

CSV_FILE="$1"; shift || true

while [[ "${1:-}" != "" ]]; do
  case "$1" in
    --dry-run) DRY_RUN=true ;;
    --change-existing-home) CHANGE_EXISTING_HOME=true ;;
    --no-force-change) FORCE_CHANGE_ON_FIRST_LOGIN=false ;;
    *)
      echo "Unknown option: $1"
      usage
      exit 2
      ;;
  esac
  shift || true
done

# ----------------------------
# Main
# ----------------------------
require_root
[[ -f "$CSV_FILE" ]] || die "CSV file not found: $CSV_FILE"

log "Starting bulk user creation"
log "CSV_FILE=$CSV_FILE"
log "SECONDARY_GROUP=$SECONDARY_GROUP"
log "HOME_BASE=$HOME_BASE SHELL=$SHELL_PATH CREATE_HOME=$CREATE_HOME"
log "CHANGE_EXISTING_HOME=$CHANGE_EXISTING_HOME FORCE_CHANGE_ON_FIRST_LOGIN=$FORCE_CHANGE_ON_FIRST_LOGIN DRY_RUN=$DRY_RUN"
log "LOG_FILE=$LOG_FILE"

# Prompt password once unless dry-run
DEFAULT_PASSWORD=""
if [[ "$DRY_RUN" == true ]]; then
  log "DRYRUN: Skipping password prompt (no changes will be made)"
else
  prompt_password_once
fi

# Ensure HOME_BASE exists
if [[ ! -d "$HOME_BASE" ]]; then
  run_cmd mkdir -p "$HOME_BASE"
  log "Ensured HOME_BASE directory exists: $HOME_BASE"
else
  log "HOME_BASE exists: $HOME_BASE"
fi

# Ensure group exists
if getent group "$SECONDARY_GROUP" >/dev/null 2>&1; then
  log "Group exists: $SECONDARY_GROUP"
else
  log "Group missing, will create: $SECONDARY_GROUP"
  run_cmd groupadd "$SECONDARY_GROUP"
fi

# Header detection
first_line="$(head -n 1 "$CSV_FILE" | tr -d '\r')"
first_col="$(echo "$first_line" | awk -F',' '{print $1}')"
skip_header=false
if [[ "$(trim "$first_col")" == "username" ]]; then
  skip_header=true
  log "Detected CSV header: $(trim "$first_line")"
fi

# Summary counters
total=0
created=0
existed=0
updated_home=0
moved_home=0
home_created=0
group_added=0
password_set=0
forced_change=0
skipped_invalid=0
skipped_empty=0
failures=0

# Track per-user errors without killing the whole run
set +e

line_no=0
while IFS=',' read -r username full_name _rest; do
  line_no=$((line_no + 1))
  [[ "$skip_header" == true && "$line_no" -eq 1 ]] && continue

  username="$(trim "${username:-}")"
  full_name="$(trim "${full_name:-}")"

  # Skip empty/comment lines
  if [[ -z "$username" || "$username" =~ ^# ]]; then
    skipped_empty=$((skipped_empty + 1))
    continue
  fi

  # Basic username validation
  if ! [[ "$username" =~ ^[a-z_][a-z0-9_-]{0,31}$ ]]; then
    log "WARN: Skipping invalid username '$username' (line $line_no)"
    skipped_invalid=$((skipped_invalid + 1))
    continue
  fi

  total=$((total + 1))
  home_dir="${HOME_BASE}/${username}"

  # Create or handle existing user
  if id "$username" >/dev/null 2>&1; then
    existed=$((existed + 1))

    current_home="$(getent passwd "$username" | cut -d: -f6)"
    current_shell="$(getent passwd "$username" | cut -d: -f7)"
    log "User exists: $username | current_home='$current_home' current_shell='$current_shell'"

    if [[ "$CHANGE_EXISTING_HOME" == true ]]; then
      # If current home differs, update and MOVE (-m)
      if [[ "$current_home" != "$home_dir" ]]; then
        log "Updating home for existing user $username -> '$home_dir' (will MOVE contents with -m)"
        run_cmd usermod -d "$home_dir" -m "$username"
        rc=$?
        if [[ $rc -ne 0 ]]; then
          log "ERROR: usermod (move home) failed for $username (rc=$rc)"
          failures=$((failures + 1))
          continue
        fi
        updated_home=$((updated_home + 1))
        moved_home=$((moved_home + 1))
      else
        log "Home already set as desired for $username: '$home_dir' (no change)"
      fi

      # Optionally ensure shell as well (kept conservative: only if different)
      if [[ "$current_shell" != "$SHELL_PATH" ]]; then
        log "Updating shell for existing user $username -> '$SHELL_PATH'"
        run_cmd usermod -s "$SHELL_PATH" "$username"
        rc=$?
        if [[ $rc -ne 0 ]]; then
          log "ERROR: usermod (shell) failed for $username (rc=$rc)"
          failures=$((failures + 1))
          continue
        fi
      fi
    else
      # Safe mode: do NOT change passwd profile fields; just ensure current home dir exists
      if [[ ! -d "$current_home" ]]; then
        log "Creating missing current home for existing user $username: '$current_home'"
        run_cmd mkdir -p "$current_home"
        rc=$?
        if [[ $rc -ne 0 ]]; then
          log "ERROR: mkdir failed for $username home '$current_home' (rc=$rc)"
          failures=$((failures + 1))
          continue
        fi
        run_cmd chown "$username:$username" "$current_home"
        run_cmd chmod 700 "$current_home"
        home_created=$((home_created + 1))
      fi
    fi

  else
    # Create new user
    log "Creating user: $username | full_name='${full_name}' | home='$home_dir'"
    useradd_args=(-s "$SHELL_PATH" -c "$full_name" -d "$home_dir")
    if [[ "$CREATE_HOME" == true ]]; then
      useradd_args+=(-m)
    fi

    run_cmd useradd "${useradd_args[@]}" "$username"
    rc=$?
    if [[ $rc -ne 0 ]]; then
      log "ERROR: useradd failed for $username (rc=$rc)"
      failures=$((failures + 1))
      continue
    fi

    created=$((created + 1))
  fi

  # Add to secondary group (always)
  log "Adding $username to group $SECONDARY_GROUP"
  run_cmd usermod -aG "$SECONDARY_GROUP" "$username"
  rc=$?
  if [[ $rc -ne 0 ]]; then
    log "ERROR: usermod -aG failed for $username (rc=$rc)"
    failures=$((failures + 1))
    continue
  fi
  group_added=$((group_added + 1))

  # Set password (skip in dry-run)
  if [[ "$DRY_RUN" == true ]]; then
    log "DRYRUN: Would set password for $username"
  else
    echo "${username}:${DEFAULT_PASSWORD}" | chpasswd
    rc=$?
    if [[ $rc -ne 0 ]]; then
      log "ERROR: chpasswd failed for $username (rc=$rc)"
      failures=$((failures + 1))
      continue
    fi
    password_set=$((password_set + 1))
    log "Password set for $username"
  fi

  # Force password change on next login (optional)
  if [[ "$FORCE_CHANGE_ON_FIRST_LOGIN" == true ]]; then
    if [[ "$DRY_RUN" == true ]]; then
      log "DRYRUN: Would force password change on first login for $username"
    else
      chage -d 0 "$username"
      rc=$?
      if [[ $rc -ne 0 ]]; then
        log "ERROR: chage failed for $username (rc=$rc)"
        failures=$((failures + 1))
        continue
      fi
      forced_change=$((forced_change + 1))
      log "Password change forced on first login for $username"
    fi
  fi

  # Ensure permissions on desired home_dir for new users or when we moved it
  # (Safe: only if the directory exists)
  if [[ -d "$home_dir" ]]; then
    run_cmd chown -R "$username:$username" "$home_dir"
    run_cmd chmod 700 "$home_dir"
  fi

done < <(tr -d '\r' < "$CSV_FILE")

set -e

# Best-effort cleanup
unset DEFAULT_PASSWORD || true

# Summary
log "-------------------- SUMMARY --------------------"
log "Processed rows (valid users): $total"
log "Created users:               $created"
log "Existing users:              $existed"
log "Existing home updated:       $updated_home"
log "Existing home moved (-m):    $moved_home"
log "Home dirs created (existing):$home_created"
log "Group adds attempted:        $group_added"
log "Passwords set:               $password_set"
log "Forced pw change:            $forced_change"
log "Skipped empty/comment lines: $skipped_empty"
log "Skipped invalid usernames:   $skipped_invalid"
log "Failures:                    $failures"
log "-------------------------------------------------"

# Exit codes:
# 0 = success, no failures
# 1 = partial success (some failures)
# 2 = usage/config error already handled via die/usage
if [[ $failures -gt 0 ]]; then
  log "Completed with failures. Exit code: 1"
  exit 1
fi

log "Completed successfully. Exit code: 0"
exit 0
